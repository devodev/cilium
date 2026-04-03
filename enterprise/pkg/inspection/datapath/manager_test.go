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
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
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
