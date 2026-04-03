//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package datapath

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	inspectionConfig "github.com/cilium/cilium/enterprise/pkg/inspection/config"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/time"
)

const (
	minReconfigureInterval = 500 * time.Millisecond
	deviceWaitTimeout      = 3 * time.Second
)

var (
	ensureInspectionDeviceFn = ensureInspectionDevice
	removeInspectionDeviceFn = removeInspectionDevice
)

type manager struct {
	logger           *slog.Logger
	cfg              inspectionConfig.Config
	db               *statedb.DB
	deviceTable      statedb.Table[*tables.Device]
	endpointManager  endpointmanager.EndpointManager
	deviceConfigured chan struct{}
	deviceIfIndex    int
}

type managerIn struct {
	cell.In

	Logger *slog.Logger

	JobGroup         job.Group
	InspectionConfig inspectionConfig.Config
	Fence            regeneration.Fence
	DB               *statedb.DB
	DeviceTable      statedb.Table[*tables.Device]
	EndpointManager  endpointmanager.EndpointManager
}

func registerManager(in managerIn) {
	m := &manager{
		logger:           in.Logger,
		cfg:              in.InspectionConfig,
		db:               in.DB,
		deviceTable:      in.DeviceTable,
		endpointManager:  in.EndpointManager,
		deviceConfigured: make(chan struct{}),
	}

	if in.InspectionConfig.Enabled {
		in.JobGroup.Add(job.OneShot("inspection-datapath-manager", m.run, job.WithShutdown()))
		in.Fence.Add("inspection-device", func(ctx context.Context) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-m.deviceConfigured:
				return nil
			}
		})
		return
	}

	in.JobGroup.Add(job.OneShot("inspection-datapath-disable", m.disableDatapath,
		job.WithRetry(3, &job.ExponentialBackoff{Min: 10 * time.Second, Max: 1 * time.Minute}),
	))
}

func (m *manager) run(ctx context.Context, health cell.Health) error {
	limiter := rate.NewLimiter(minReconfigureInterval, 1)
	defer limiter.Stop()

	var retryChan <-chan time.Time

	for {
		deviceWatch, err := m.configureDatapath(ctx)
		if err != nil {
			m.logger.Error("Inspection datapath configuration failed", logfields.Error, err)
			health.Degraded("Inspection datapath configuration failed", err)
			retryChan = time.After(minReconfigureInterval)
		} else {
			health.OK(fmt.Sprintf("Inspection interface %q present", inspectionConfig.InterfaceName))
			retryChan = nil
		}

		select {
		case <-deviceWatch:
		case <-retryChan:
		case <-ctx.Done():
			return nil
		}

		if err := limiter.Wait(ctx); err != nil {
			return err
		}
	}
}

func (m *manager) configureDatapath(ctx context.Context) (<-chan struct{}, error) {
	ifIndex, err := ensureInspectionDeviceFn(inspectionConfig.InterfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to setup inspection device: %w", err)
	}

	deviceWatch, err := m.waitForDevice(ctx, ifIndex)
	if err != nil {
		return nil, fmt.Errorf("failed waiting for inspection device: %w", err)
	}

	if m.deviceIfIndex == 0 {
		close(m.deviceConfigured)
	}
	if m.deviceIfIndex > 0 && m.deviceIfIndex != ifIndex {
		m.logger.Info(
			"Inspection interface changed, regenerating endpoints",
			logfields.Interface, inspectionConfig.InterfaceName,
			logfields.Old, m.deviceIfIndex,
			logfields.New, ifIndex,
		)
		m.endpointManager.RegenerateAllEndpoints(&regeneration.ExternalRegenerationMetadata{
			Reason:            "Inspection interface changed",
			Message:           fmt.Sprintf("Inspection interface %q changed", inspectionConfig.InterfaceName),
			RegenerationLevel: regeneration.RegenerateWithDatapath,
			ParentContext:     ctx,
		}).Wait()
	}
	m.deviceIfIndex = ifIndex

	return deviceWatch, nil
}

func (m *manager) disableDatapath(ctx context.Context, health cell.Health) error {
	err := removeInspectionDeviceFn(inspectionConfig.InterfaceName)
	if err != nil {
		err = fmt.Errorf("failed to remove inspection device: %w", err)
		m.logger.Warn("Inspection datapath cleanup failed", logfields.Error, err)
		health.Degraded("Inspection datapath cleanup failed", err)
		return err
	}
	health.OK("Inspection datapath disabled")
	return nil
}

func (m *manager) waitForDevice(ctx context.Context, deviceIndex int) (<-chan struct{}, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, deviceWaitTimeout)
	defer cancel()

	for {
		_, _, watch, found := m.deviceTable.GetWatch(m.db.ReadTxn(), tables.DeviceIDIndex.Query(deviceIndex))
		if found {
			return watch, nil
		}

		select {
		case <-timeoutCtx.Done():
			return nil, timeoutCtx.Err()
		case <-watch:
		}
	}
}
