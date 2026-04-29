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
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	inspectionConfig "github.com/cilium/cilium/enterprise/pkg/inspection/config"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/endpointmanager"
)

type fakeHealth struct {
	okCount       atomic.Int32
	degradedCount atomic.Int32
}

func (h *fakeHealth) OK(string)                   { h.okCount.Add(1) }
func (h *fakeHealth) Stopped(string)              {}
func (h *fakeHealth) Degraded(string, error)      { h.degradedCount.Add(1) }
func (h *fakeHealth) NewScope(string) cell.Health { return h }
func (h *fakeHealth) Close()                      {}

type fakeEndpointManager struct {
	endpointmanager.EndpointManager
	regenCalls atomic.Int32
}

func (f *fakeEndpointManager) RegenerateAllEndpoints(_ *regeneration.ExternalRegenerationMetadata) *sync.WaitGroup {
	f.regenCalls.Add(1)
	return &sync.WaitGroup{}
}

type fakeJobGroup struct {
	jobs atomic.Int32
}

func (f *fakeJobGroup) Add(jobs ...job.Job) {
	f.jobs.Add(int32(len(jobs)))
}

func (f *fakeJobGroup) Scoped(string) job.ScopedGroup {
	return fakeScopedJobGroup{group: f}
}

type fakeScopedJobGroup struct {
	group *fakeJobGroup
}

func (f fakeScopedJobGroup) Add(jobs ...job.Job) {
	f.group.Add(jobs...)
}

type fakeFence struct {
	waitFuncs map[string]func(context.Context) error
}

func (f *fakeFence) Add(name string, waitFn func(context.Context) error) {
	if f.waitFuncs == nil {
		f.waitFuncs = map[string]func(context.Context) error{}
	}
	f.waitFuncs[name] = waitFn
}

func (f *fakeFence) Wait(context.Context) error {
	return nil
}

func newTestManager(t *testing.T, cfg inspectionConfig.Config) (*manager, *statedb.DB, statedb.RWTable[*tables.Device], *fakeEndpointManager) {
	db := statedb.New()
	devices, err := tables.NewDeviceTable(db)
	require.NoError(t, err)

	endpointManager := &fakeEndpointManager{}
	return &manager{
		logger:           hivetest.Logger(t),
		cfg:              cfg,
		db:               db,
		deviceTable:      devices,
		endpointManager:  endpointManager,
		deviceConfigured: make(chan struct{}),
	}, db, devices, endpointManager
}

func TestRegisterManagerEnabledAddsFenceAndRunJob(t *testing.T) {
	db := statedb.New()
	devices, err := tables.NewDeviceTable(db)
	require.NoError(t, err)

	jobs := &fakeJobGroup{}
	fence := &fakeFence{}
	registerManager(managerIn{
		Logger:           hivetest.Logger(t),
		JobGroup:         jobs,
		InspectionConfig: inspectionConfig.Config{Enabled: true},
		Fence:            fence,
		DB:               db,
		DeviceTable:      devices,
		EndpointManager:  &fakeEndpointManager{},
	})

	require.Equal(t, int32(1), jobs.jobs.Load())
	require.Contains(t, fence.waitFuncs, "inspection-device")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, fence.waitFuncs["inspection-device"](ctx), context.Canceled)
}

func TestRegisterManagerDisabledAddsCleanupJobOnly(t *testing.T) {
	jobs := &fakeJobGroup{}
	fence := &fakeFence{}
	registerManager(managerIn{
		Logger:           hivetest.Logger(t),
		JobGroup:         jobs,
		InspectionConfig: inspectionConfig.Config{},
		Fence:            fence,
	})

	require.Equal(t, int32(1), jobs.jobs.Load())
	require.Empty(t, fence.waitFuncs)
}

func TestRunConfiguresDatapathAndExitsOnContextCancel(t *testing.T) {
	m, db, devices, _ := newTestManager(t, inspectionConfig.Config{
		Enabled: true,
	})

	txn := db.WriteTxn(devices)
	_, _, err := devices.Insert(txn, &tables.Device{Index: 17, Name: inspectionConfig.InterfaceName})
	require.NoError(t, err)
	txn.Commit()

	origEnsure := ensureInspectionDeviceFn
	t.Cleanup(func() { ensureInspectionDeviceFn = origEnsure })
	ensureInspectionDeviceFn = func(device string) (int, error) {
		require.Equal(t, inspectionConfig.InterfaceName, device)
		return 17, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	health := &fakeHealth{}
	require.NoError(t, m.run(ctx, health))
	require.Equal(t, int32(1), health.okCount.Load())
	require.Equal(t, int32(0), health.degradedCount.Load())
}

func TestRunReportsConfigurationFailure(t *testing.T) {
	m, _, _, _ := newTestManager(t, inspectionConfig.Config{
		Enabled: true,
	})

	origEnsure := ensureInspectionDeviceFn
	t.Cleanup(func() { ensureInspectionDeviceFn = origEnsure })
	ensureInspectionDeviceFn = func(string) (int, error) {
		return 0, fmt.Errorf("setup failed")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	health := &fakeHealth{}
	require.NoError(t, m.run(ctx, health))
	require.Equal(t, int32(0), health.okCount.Load())
	require.Equal(t, int32(1), health.degradedCount.Load())
}

func TestConfigureDatapathInitialSetup(t *testing.T) {
	m, db, devices, endpointManager := newTestManager(t, inspectionConfig.Config{
		Enabled: true,
	})

	txn := db.WriteTxn(devices)
	_, _, err := devices.Insert(txn, &tables.Device{Index: 17, Name: inspectionConfig.InterfaceName})
	require.NoError(t, err)
	txn.Commit()

	origEnsure := ensureInspectionDeviceFn
	t.Cleanup(func() { ensureInspectionDeviceFn = origEnsure })

	var setupCalls atomic.Int32
	ensureInspectionDeviceFn = func(device string) (int, error) {
		setupCalls.Add(1)
		require.Equal(t, inspectionConfig.InterfaceName, device)
		return 17, nil
	}

	watch, err := m.configureDatapath(t.Context())
	require.NoError(t, err)
	require.NotNil(t, watch)
	require.Equal(t, int32(1), setupCalls.Load())
	require.Equal(t, int32(0), endpointManager.regenCalls.Load())

	select {
	case <-m.deviceConfigured:
	default:
		t.Fatal("deviceConfigured was not closed")
	}
}

func TestConfigureDatapathRegeneratesOnIfindexChange(t *testing.T) {
	m, db, devices, endpointManager := newTestManager(t, inspectionConfig.Config{
		Enabled: true,
	})
	m.deviceIfIndex = 17
	close(m.deviceConfigured)

	txn := db.WriteTxn(devices)
	_, _, err := devices.Insert(txn, &tables.Device{Index: 21, Name: inspectionConfig.InterfaceName})
	require.NoError(t, err)
	txn.Commit()

	origEnsure := ensureInspectionDeviceFn
	t.Cleanup(func() { ensureInspectionDeviceFn = origEnsure })
	ensureInspectionDeviceFn = func(device string) (int, error) {
		require.Equal(t, inspectionConfig.InterfaceName, device)
		return 21, nil
	}

	_, err = m.configureDatapath(t.Context())
	require.NoError(t, err)
	require.Equal(t, int32(1), endpointManager.regenCalls.Load())
	require.Equal(t, 21, m.deviceIfIndex)
}

func TestConfigureDatapathReturnsSetupError(t *testing.T) {
	m, _, _, _ := newTestManager(t, inspectionConfig.Config{
		Enabled: true,
	})

	origEnsure := ensureInspectionDeviceFn
	t.Cleanup(func() { ensureInspectionDeviceFn = origEnsure })
	ensureInspectionDeviceFn = func(device string) (int, error) {
		require.Equal(t, inspectionConfig.InterfaceName, device)
		return 0, fmt.Errorf("setup failed")
	}

	_, err := m.configureDatapath(t.Context())
	require.ErrorContains(t, err, "failed to setup inspection device")

	select {
	case <-m.deviceConfigured:
		t.Fatal("deviceConfigured should stay open when setup fails")
	default:
	}
}

func TestConfigureDatapathReturnsWaitError(t *testing.T) {
	m, _, _, _ := newTestManager(t, inspectionConfig.Config{
		Enabled: true,
	})

	origEnsure := ensureInspectionDeviceFn
	t.Cleanup(func() { ensureInspectionDeviceFn = origEnsure })
	ensureInspectionDeviceFn = func(device string) (int, error) {
		require.Equal(t, inspectionConfig.InterfaceName, device)
		return 17, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := m.configureDatapath(ctx)
	require.ErrorContains(t, err, "failed waiting for inspection device")

	select {
	case <-m.deviceConfigured:
		t.Fatal("deviceConfigured should stay open when wait fails")
	default:
	}
}

func TestDisableDatapath(t *testing.T) {
	m, _, _, _ := newTestManager(t, inspectionConfig.Config{
		Enabled: false,
	})

	origRemove := removeInspectionDeviceFn
	t.Cleanup(func() { removeInspectionDeviceFn = origRemove })

	var removeCalls atomic.Int32
	removeInspectionDeviceFn = func(device string) error {
		removeCalls.Add(1)
		require.Equal(t, inspectionConfig.InterfaceName, device)
		return nil
	}

	health := &fakeHealth{}
	err := m.disableDatapath(context.Background(), health)
	require.NoError(t, err)
	require.Equal(t, int32(1), removeCalls.Load())
	require.Equal(t, int32(1), health.okCount.Load())
}

func TestDisableDatapathReturnsRemoveError(t *testing.T) {
	m, _, _, _ := newTestManager(t, inspectionConfig.Config{
		Enabled: false,
	})

	origRemove := removeInspectionDeviceFn
	t.Cleanup(func() { removeInspectionDeviceFn = origRemove })
	removeInspectionDeviceFn = func(device string) error {
		require.Equal(t, inspectionConfig.InterfaceName, device)
		return fmt.Errorf("remove failed")
	}

	health := &fakeHealth{}
	err := m.disableDatapath(context.Background(), health)
	require.ErrorContains(t, err, "failed to remove inspection device")
	require.Equal(t, int32(1), health.degradedCount.Load())
	require.Equal(t, int32(0), health.okCount.Load())
}

func TestWaitForDeviceReturnsCanceledContext(t *testing.T) {
	m, _, _, _ := newTestManager(t, inspectionConfig.Config{
		Enabled: true,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	watch, err := m.waitForDevice(ctx, 17)
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, watch)
}

func TestEnsureInspectionDeviceRejectsEmptyName(t *testing.T) {
	ifIndex, err := ensureInspectionDevice("")
	require.ErrorContains(t, err, "inspection device name is empty")
	require.Zero(t, ifIndex)
}

func TestRemoveInspectionDeviceIgnoresEmptyName(t *testing.T) {
	require.NoError(t, removeInspectionDevice(""))
}
