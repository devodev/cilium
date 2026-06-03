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
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	evpnConfig "github.com/cilium/cilium/enterprise/pkg/evpn/config"
	privnetConfig "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/pkg/datapath/config"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	endpointTypes "github.com/cilium/cilium/pkg/endpoint/types"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeManager "github.com/cilium/cilium/pkg/node/manager"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/time"
)

const (
	// minReconfigureInterval is the time to wait before re-running datapath configuration.
	minReconfigureInterval = 10 * time.Second

	// deviceWaitTimeout is the time to wait for a newly created device to appear in the device table.
	deviceWaitTimeout = 3 * time.Second
)

var (
	setupEvpnVxlanDeviceFn  = setupEvpnVxlanDevice
	removeEvpnVxlanDeviceFn = removeEvpnVxlanDevice
	replaceEvpnDatapathFn   = replaceEvpnDatapath
	cleanupEvpnDatapathFn   = cleanupEvpnDatapath
)

// manager is responsible for managing EVPN VXLAN device and loading eBPF datapath programs to it.
type manager struct {
	log    *slog.Logger
	sysctl sysctl.Sysctl

	evpnConfig    evpnConfig.Config
	privnetConfig privnetConfig.Config

	orchestrator    endpointTypes.Orchestrator
	endpointManager endpointmanager.EndpointManager
	nodeConfig      atomic.Pointer[config.Config]

	db      *statedb.DB
	devices statedb.Table[*tables.Device]

	nodeConfigTrigger     chan struct{}
	vxlanDeviceConfigured chan struct{}
	vxlanIfIndex          int

	sourceIPs            evpnConfig.SourceIPs
	sourceIPsInitialized chan struct{}
	sourceIPsObserved    bool
}

type managerIn struct {
	cell.In

	Logger   *slog.Logger
	JobGroup job.Group
	Sysctl   sysctl.Sysctl

	EVPNConfig    evpnConfig.Config
	PrivnetConfig privnetConfig.Config

	Orchestrator       endpointTypes.Orchestrator
	EndpointManager    endpointmanager.EndpointManager
	Fence              regeneration.Fence
	NodeConfigNotifier *nodeManager.NodeConfigNotifier

	DB      *statedb.DB
	Devices statedb.Table[*tables.Device]
}

func registerManager(in managerIn) error {
	m := &manager{
		log:                   in.Logger,
		sysctl:                in.Sysctl,
		evpnConfig:            in.EVPNConfig,
		privnetConfig:         in.PrivnetConfig,
		orchestrator:          in.Orchestrator,
		endpointManager:       in.EndpointManager,
		db:                    in.DB,
		devices:               in.Devices,
		nodeConfigTrigger:     make(chan struct{}, 1),
		vxlanDeviceConfigured: make(chan struct{}),
		sourceIPsInitialized:  make(chan struct{}),
	}

	if in.EVPNConfig.Enabled && in.PrivnetConfig.Enabled {
		// Register for LocalNodeConfiguration changes.
		// NodeConfigurationChanged() is called whenever loader (re-)configures
		// the base datapath configuration - at the end of loader.Reinitialize().
		in.NodeConfigNotifier.Subscribe(m)
		// If SourceInterface is configured, watch it end trigger endpoint regeneration upon effective
		// source IP change to ensure source IPs in LXC config are up-to-date.
		if in.EVPNConfig.SourceInterface != "" {
			in.JobGroup.Add(job.OneShot("source-interface-watcher", m.runSourceInterfaceWatcher, job.WithShutdown()))
		}
		// Run the manager.
		in.JobGroup.Add(job.OneShot("datapath-manager", m.run))
	} else {
		// EVPN disabled - just perform the cleanup
		in.JobGroup.Add(job.OneShot("datapath-disable", m.disableDatapath,
			job.WithRetry(3, &job.ExponentialBackoff{Min: 10 * time.Second, Max: 1 * time.Minute})),
		)
		return nil
	}

	// Block endpoint regeneration until we first configure the EVPN vxlan device
	in.Fence.Add("evpn-vxlan-device", func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-m.vxlanDeviceConfigured:
			return nil
		}
	})

	return nil
}

func (m *manager) NodeConfigurationChanged(cfg config.Config) error {
	cfgCopy := cfg
	m.nodeConfig.Store(&cfgCopy)
	select {
	case m.nodeConfigTrigger <- struct{}{}:
	default:
	}
	return nil
}

func (m *manager) run(ctx context.Context, health cell.Health) error {
	// Wait for the Orchestrator to signal that the datapath is initialised for the first time.
	select {
	case <-m.orchestrator.DatapathInitialized():
	case <-ctx.Done():
		return nil
	}

	// Wait for the initial nodeConfigTrigger to ensure the nodeConfig is populated
	// and loader.Reinitialize() has been executed for the first time.
	select {
	case <-m.nodeConfigTrigger:
	case <-ctx.Done():
		return nil
	}

	// Wait for source IP initialization as we only trigger endpoint regeneration upon follow-up source IP changes.
	if m.evpnConfig.SourceInterface != "" {
		select {
		case <-m.sourceIPsInitialized:
		case <-ctx.Done():
			return nil
		}
	}

	limiter := rate.NewLimiter(minReconfigureInterval, 1)
	var retryChan <-chan time.Time

	for {
		deviceWatch, err := m.configureDatapath(ctx)
		if err != nil {
			m.log.Error("EVPN datapath configuration failed", logfields.Error, err)
			health.Degraded("EVPN datapath configuration failed", err)
			retryChan = time.After(minReconfigureInterval) // upon failure retry with rate-limiting
		} else {
			m.log.Debug("EVPN datapath configured")
			health.OK("EVPN datapath configured")
			retryChan = nil
		}

		// Re-configure if: nodeConfig changes upon loader.Reinitialize(), vxlan device changes, or the retry timeout expires.
		select {
		case <-m.nodeConfigTrigger:
		case <-deviceWatch:
		case <-retryChan:
		case <-ctx.Done():
			return nil
		}

		// Limit the rate at which we re-configure the datapath.
		if err := limiter.Wait(ctx); err != nil {
			return err
		}
	}
}

func (m *manager) configureDatapath(ctx context.Context) (<-chan struct{}, error) {
	lnc := m.nodeConfig.Load()
	if lnc == nil {
		return nil, fmt.Errorf("BUG: LocalNodeConfiguration is nil")
	}

	ifIndex, err := setupEvpnVxlanDeviceFn(m.log, m.sysctl, m.evpnConfig.VxlanDevice, m.evpnConfig.VxlanPort, lnc.DeviceMTU)
	if err != nil {
		return nil, fmt.Errorf("failed to setup EVPN VXLAN device: %w", err)
	}

	deviceWatch, err := m.waitForDevice(ctx, ifIndex)
	if err != nil {
		return nil, fmt.Errorf("failed waiting for EVPN VXLAN device: %w", err)
	}

	if err := replaceEvpnDatapathFn(ctx, m.log, lnc, m.evpnConfig, m.privnetConfig); err != nil {
		return nil, fmt.Errorf("failed loading EVPN datapath programs: %w", err)
	}

	if m.vxlanIfIndex == 0 {
		close(m.vxlanDeviceConfigured)
	}
	if m.vxlanIfIndex > 0 && m.vxlanIfIndex != ifIndex {
		// VXLAN device ifindex and MAC changed, need to regenerate the endpoints to pull the new config
		m.endpointManager.RegenerateAllEndpoints(&regeneration.ExternalRegenerationMetadata{
			Reason:            "EVPN VXLAN device changed",
			RegenerationLevel: regeneration.RegenerateWithDatapath,
		}).Wait()
	}
	m.vxlanIfIndex = ifIndex

	return deviceWatch, nil
}

func (m *manager) disableDatapath(ctx context.Context, health cell.Health) error {
	var resErr error
	if err := cleanupEvpnDatapathFn(m.evpnConfig.VxlanDevice); err != nil {
		resErr = fmt.Errorf("failed to cleanup EVPN datapath: %w", err)
	}
	if err := removeEvpnVxlanDeviceFn(m.evpnConfig.VxlanDevice); err != nil {
		resErr = errors.Join(resErr, fmt.Errorf("failed to remove EVPN VXLAN device: %w", err))
	}
	if resErr != nil {
		m.log.Warn("Errors by disabling EVPN datapath", logfields.Error, resErr)
		health.Degraded("Errors by disabling EVPN datapath", resErr)
		return resErr
	}
	health.OK("EVPN datapath disabled")
	return nil
}

// waitForDevice waits for the specified device name to appear on the devices table
// and returns a watch channel which is closed upon device changes.
func (m *manager) waitForDevice(ctx context.Context, deviceIndex int) (<-chan struct{}, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, deviceWaitTimeout)
	defer cancel()
	for {
		txn := m.db.ReadTxn()
		_, _, watch, found := m.devices.GetWatch(txn, tables.DeviceIDIndex.Query(deviceIndex))
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

func (m *manager) runSourceInterfaceWatcher(ctx context.Context, health cell.Health) error {
	select {
	case <-m.orchestrator.DatapathInitialized():
	case <-ctx.Done():
		return nil
	}
	_, devicesInitialized := m.devices.Initialized(m.db.ReadTxn())
	select {
	case <-devicesInitialized:
	case <-ctx.Done():
		return nil
	}
	for {
		sourceWatch := m.reconcileSourceIPs(ctx, health)
		select {
		case <-sourceWatch:
		case <-ctx.Done():
			return nil
		}
	}
}

func (m *manager) reconcileSourceIPs(ctx context.Context, health cell.Health) <-chan struct{} {
	sourceIPs, watch := m.resolveSourceIPs(health)
	if !m.sourceIPsObserved {
		m.sourceIPs = sourceIPs
		m.sourceIPsObserved = true
		close(m.sourceIPsInitialized)
		return watch
	}
	if m.sourceIPs != sourceIPs {
		m.log.Info(
			"EVPN source IP changed, regenerating endpoints",
			logfields.Interface, m.evpnConfig.SourceInterface,
			logfields.Old, m.sourceIPs,
			logfields.New, sourceIPs,
		)
		m.sourceIPs = sourceIPs
		m.endpointManager.RegenerateAllEndpoints(&regeneration.ExternalRegenerationMetadata{
			Reason:            regeneration.ReasonDeviceConfigurationChanged,
			Message:           fmt.Sprintf("EVPN source IP on interface %s changed", m.evpnConfig.SourceInterface),
			RegenerationLevel: regeneration.RegenerateWithDatapath,
			ParentContext:     ctx,
		}).Wait()
	}
	return watch
}

func (m *manager) resolveSourceIPs(health cell.Health) (evpnConfig.SourceIPs, <-chan struct{}) {
	dev, _, watch, found := m.devices.GetWatch(m.db.ReadTxn(), tables.DeviceNameIndex.Query(m.evpnConfig.SourceInterface))
	if !found {
		m.log.Warn("EVPN source interface not found",
			logfields.Interface, m.evpnConfig.SourceInterface,
		)
		health.Degraded(fmt.Sprintf("EVPN source interface %s not found", m.evpnConfig.SourceInterface), errors.New("interface not found"))
		return evpnConfig.SourceIPs{}, watch
	}
	sourceIPs, err := evpnConfig.SourceIPsFromDevice(dev)
	if err != nil {
		m.log.Warn("Failed to resolve EVPN source IPs from source interface",
			logfields.Interface, m.evpnConfig.SourceInterface,
			logfields.Error, err,
		)
		health.Degraded(fmt.Sprintf("Failed to resolve EVPN source IPs on interface %s", m.evpnConfig.SourceInterface), err)
		return evpnConfig.SourceIPs{}, watch
	}
	health.OK("EVPN source IPs resolved successfully")
	return sourceIPs, watch
}
