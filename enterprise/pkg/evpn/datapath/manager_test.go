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
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	evpnConfig "github.com/cilium/cilium/enterprise/pkg/evpn/config"
	privnetConfig "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/config"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/loader"
	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	endpointTypes "github.com/cilium/cilium/pkg/endpoint/types"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

const (
	testDeviceName = "cilium_evpn_tst"
	testVXLANPort  = uint16(4789)
	testDeviceMTU  = 1500
)

type fakeOrchestrator struct {
	initCh chan struct{}
}

func (f *fakeOrchestrator) Reinitialize(ctx context.Context) error {
	return nil
}

func (f *fakeOrchestrator) DatapathInitialized() <-chan struct{} {
	return f.initCh
}

func (f *fakeOrchestrator) ReloadDatapath(ctx context.Context, ep endpointTypes.Endpoint, stats *metrics.SpanStat) (string, error) {
	return "", nil
}

func (f *fakeOrchestrator) EndpointHash(cfg endpointTypes.Config) (string, error) {
	return "", nil
}

func (f *fakeOrchestrator) WriteEndpointConfig(w io.Writer, cfg endpointTypes.Config) error {
	return nil
}

func (f *fakeOrchestrator) Unload(ep endpointTypes.Endpoint) {}

type fakeHealth struct {
	okCount       atomic.Int32
	degradedCount atomic.Int32
}

func (h *fakeHealth) OK(status string) {
	h.okCount.Add(1)
}

func (h *fakeHealth) Stopped(reason string) {}

func (h *fakeHealth) Degraded(reason string, err error) {
	h.degradedCount.Add(1)
}

func (h *fakeHealth) NewScope(name string) cell.Health {
	return h
}

func (h *fakeHealth) Close() {}

type nopSysctl struct{}

func (n nopSysctl) Disable(name []string) error             { return nil }
func (n nopSysctl) Enable(name []string) error              { return nil }
func (n nopSysctl) Write(name []string, val string) error   { return nil }
func (n nopSysctl) WriteInt(name []string, val int64) error { return nil }
func (n nopSysctl) ApplySettings([]tables.Sysctl) error     { return nil }
func (n nopSysctl) Read(name []string) (string, error)      { return "", nil }
func (n nopSysctl) ReadInt(name []string) (int64, error)    { return 0, nil }

type fakeEndpointManager struct {
	endpointmanager.EndpointManager
	regenCalls atomic.Int32
}

func (f *fakeEndpointManager) RegenerateAllEndpoints(_ *regeneration.ExternalRegenerationMetadata) *sync.WaitGroup {
	f.regenCalls.Add(1)
	return &sync.WaitGroup{}
}

func newTestManager(t *testing.T, cfg evpnConfig.Config) (*manager, *statedb.DB, statedb.RWTable[*tables.Device]) {
	db := statedb.New()
	devices, err := tables.NewDeviceTable(db)
	require.NoError(t, err)

	orch := &fakeOrchestrator{initCh: make(chan struct{})}
	close(orch.initCh)

	m := &manager{
		log:                   hivetest.Logger(t),
		sysctl:                nopSysctl{},
		db:                    db,
		devices:               devices,
		evpnConfig:            cfg,
		nodeConfigTrigger:     make(chan struct{}, 1),
		vxlanDeviceConfigured: make(chan struct{}),
		endpointManager:       &fakeEndpointManager{},
		orchestrator:          orch,
	}
	return m, db, devices
}

func TestManagerRunEnabled(t *testing.T) {
	cfg := evpnConfig.Config{
		CommonConfig: evpnConfig.CommonConfig{Enabled: true},
		VxlanDevice:  testDeviceName,
		VxlanPort:    testVXLANPort,
	}
	m, db, devices := newTestManager(t, cfg)
	lnc := config.Config{DeviceMTU: testDeviceMTU}
	m.NodeConfigurationChanged(lnc)

	txn := db.WriteTxn(devices)
	_, _, err := devices.Insert(txn, &tables.Device{Index: 1, Name: testDeviceName})
	require.NoError(t, err)
	txn.Commit()

	origSetup := setupEvpnVxlanDeviceFn
	origReplace := replaceEvpnDatapathFn
	t.Cleanup(func() {
		setupEvpnVxlanDeviceFn = origSetup
		replaceEvpnDatapathFn = origReplace
	})

	var setupCalled atomic.Bool
	var replaceCalled atomic.Bool
	configured := make(chan struct{})

	setupEvpnVxlanDeviceFn = func(logger *slog.Logger, sys sysctl.Sysctl, device string, port uint16, mtu int) (int, error) {
		setupCalled.Store(true)
		require.Equal(t, testDeviceName, device)
		require.Equal(t, testVXLANPort, port)
		require.Equal(t, testDeviceMTU, mtu)
		return 1, nil
	}

	replaceEvpnDatapathFn = func(ctx context.Context, logger *slog.Logger, lnc *config.Config, evpnCfg evpnConfig.Config, privnetCfg privnetConfig.Config) error {
		replaceCalled.Store(true)
		require.Equal(t, testDeviceName, evpnCfg.VxlanDevice)
		require.Equal(t, testDeviceMTU, lnc.DeviceMTU)
		close(configured)
		return nil
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	health := &fakeHealth{}
	done := make(chan error, 1)
	go func() {
		done <- m.run(ctx, health)
	}()

	select {
	case <-configured:
		cancel()
	case <-t.Context().Done():
		t.Fatal("timed out waiting for EVPN datapath configuration")
	}

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-t.Context().Done():
		t.Fatal("timed out waiting for manager run to finish")
	}

	require.True(t, setupCalled.Load())
	require.True(t, replaceCalled.Load())
	require.Equal(t, int32(1), health.okCount.Load())
}

func TestManagerRunDisabled(t *testing.T) {
	cfg := evpnConfig.Config{
		CommonConfig: evpnConfig.CommonConfig{Enabled: false},
		VxlanDevice:  testDeviceName,
	}
	m, _, _ := newTestManager(t, cfg)

	origRemove := removeEvpnVxlanDeviceFn
	origCleanup := cleanupEvpnDatapathFn
	t.Cleanup(func() {
		removeEvpnVxlanDeviceFn = origRemove
		cleanupEvpnDatapathFn = origCleanup
	})

	var removeCalled atomic.Value
	var cleanupCalled atomic.Bool

	removeEvpnVxlanDeviceFn = func(device string) error {
		removeCalled.Store(device)
		return nil
	}
	cleanupEvpnDatapathFn = func(device string) error {
		require.Equal(t, testDeviceName, device)
		cleanupCalled.Store(true)
		return nil
	}

	health := &fakeHealth{}
	err := m.disableDatapath(t.Context(), health)

	require.NoError(t, err)
	require.Equal(t, testDeviceName, removeCalled.Load())
	require.True(t, cleanupCalled.Load())
	require.Equal(t, int32(1), health.okCount.Load())
}

func TestPrivilegedManagerDeviceRecreateAndCleanup(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		var (
			bpffsDeviceDir = ""
			bpffsLinksDir  = ""
			callsMapPath   = filepath.Join(bpf.TCGlobalsPath(), evpnCallsMap)
		)

		cfg := evpnConfig.Config{
			CommonConfig: evpnConfig.CommonConfig{Enabled: true},
			VxlanDevice:  testDeviceName,
			VxlanPort:    testVXLANPort,
		}
		m, db, devices := newTestManager(t, cfg)

		// setup test "setupEvpnVxlanDevice" and "replaceEvpnDatapath" functions
		origSetup := setupEvpnVxlanDeviceFn
		setupEvpnVxlanDeviceFn = func(logger *slog.Logger, sys sysctl.Sysctl, device string, port uint16, mtu int) (int, error) {
			// call the real setupEvpnVxlanDevice and insert the device index into statedb
			ifIndex, err := setupEvpnVxlanDevice(logger, sys, device, port, mtu)
			if err != nil {
				return 0, err
			}
			link, err := safenetlink.LinkByName(device)
			if err != nil {
				return 0, err
			}
			txn := db.WriteTxn(devices)
			_, _, err = devices.Insert(txn, &tables.Device{Index: link.Attrs().Index, Name: device})
			txn.Commit()
			if err != nil {
				return 0, err
			}
			return ifIndex, nil
		}
		origReplace := replaceEvpnDatapathFn
		replaceEvpnDatapathFn = func(ctx context.Context, logger *slog.Logger, cfgIn *config.Config, evpnCfg evpnConfig.Config, privnetCfg privnetConfig.Config) error {
			// create mock bpffs links dir and calls map pins
			link, err := safenetlink.LinkByName(evpnCfg.VxlanDevice)
			if err != nil {
				return err
			}
			bpffsLinksDir = loader.BPFFSDeviceLinksDir(bpf.CiliumPath(), link)
			bpffsDeviceDir = filepath.Dir(bpffsLinksDir)
			if err := os.MkdirAll(bpffsLinksDir, 0755); err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Join(bpffsLinksDir, "dummy"), 0755); err != nil {
				return err
			}
			return os.MkdirAll(callsMapPath, 0755)
		}
		t.Cleanup(func() {
			setupEvpnVxlanDeviceFn = origSetup
			replaceEvpnDatapathFn = origReplace
		})

		lnc := config.Config{DeviceMTU: testDeviceMTU}
		m.NodeConfigurationChanged(lnc)

		prevIfIdx := 0
		for i := range 3 {
			if i > 0 {
				// use different vxlan port test device recreate
				m.evpnConfig.VxlanPort = 4790
			}
			if i > 1 {
				// use different vxlan port to test change with no recreate
				lnc := config.Config{DeviceMTU: 1400}
				m.NodeConfigurationChanged(lnc)
			}

			_, err := m.configureDatapath(t.Context())
			require.NoError(t, err)

			// ensure device exists
			link, err := safenetlink.LinkByName(testDeviceName)
			require.NoError(t, err)

			// ensure bpffs links and calls map pins exist
			require.NoError(t, err)
			_, err = os.Stat(bpffsLinksDir)
			require.NoError(t, err)
			_, err = os.Stat(callsMapPath)
			require.NoError(t, err)

			if i == 1 {
				// ensure device index changed after port changed
				require.NotEqual(t, prevIfIdx, link.Attrs().Index)
			} else if i > 1 {
				// ensure device index has not changed after MTU changed
				require.Equal(t, prevIfIdx, link.Attrs().Index)
			}
			prevIfIdx = link.Attrs().Index
		}
		epMgr, ok := m.endpointManager.(*fakeEndpointManager)
		require.True(t, ok)
		require.Equal(t, int32(1), epMgr.regenCalls.Load())

		// disable datapath
		health := &fakeHealth{}
		require.NoError(t, m.disableDatapath(t.Context(), health))
		require.Equal(t, int32(1), health.okCount.Load())

		// ensure device is deleted
		_, err := safenetlink.LinkByName(testDeviceName)
		require.ErrorAs(t, err, &netlink.LinkNotFoundError{})

		// ensure bpffs links and calls map pins are cleared
		_, err = os.Stat(bpffsLinksDir)
		require.ErrorIs(t, err, os.ErrNotExist)
		_, err = os.Stat(callsMapPath)
		require.ErrorIs(t, err, os.ErrNotExist)

		require.NoError(t, os.RemoveAll(bpffsDeviceDir))
		return nil
	})
}
