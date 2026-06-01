// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilerv2

import (
	"context"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/fake"
	enterpriseTypes "github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/bgp/gobgp"
	"github.com/cilium/cilium/pkg/bgp/manager/instance"
	"github.com/cilium/cilium/pkg/bgp/manager/reconciler"
	"github.com/cilium/cilium/pkg/bgp/manager/store"
	"github.com/cilium/cilium/pkg/bgp/types"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/option"
)

type checks struct {
	holdTimer         bool
	connectRetryTimer bool
	keepaliveTimer    bool
	grRestartTime     bool
}

var (
	peerData1 = PeerData{
		Peer: &v1.IsovalentBGPNodePeer{
			Name:        "peer-1",
			PeerAddress: ptr.To[string]("192.168.0.1"),
			PeerASN:     ptr.To[int64](64124),
			PeerConfigRef: &v1.PeerConfigReference{
				Name: "peer-config",
			},
		},
		Config: &v1.IsovalentBGPPeerConfigSpec{
			Transport: &v2.CiliumBGPTransport{
				PeerPort: ptr.To[int32](v2.DefaultBGPPeerPort),
			},
		},
	}

	peerData2 = PeerData{
		Peer: &v1.IsovalentBGPNodePeer{
			Name:        "peer-2",
			PeerAddress: ptr.To[string]("192.168.0.2"),
			PeerASN:     ptr.To[int64](64124),
			PeerConfigRef: &v1.PeerConfigReference{
				Name: "peer-config",
			},
		},
		Config: &v1.IsovalentBGPPeerConfigSpec{
			Transport: &v2.CiliumBGPTransport{
				PeerPort: ptr.To[int32](v2.DefaultBGPPeerPort),
			},
		},
	}

	peer2UpdatedASN = func() PeerData {
		peer2Copy := PeerData{
			Peer:     peerData2.Peer.DeepCopy(),
			Config:   peerData2.Config.DeepCopy(),
			Password: peerData2.Password,
		}

		peer2Copy.Peer.PeerASN = ptr.To[int64](64125)
		return peer2Copy
	}()

	peer2UpdatedTimers = func() PeerData {
		peer2Copy := PeerData{
			Peer:     peerData2.Peer.DeepCopy(),
			Config:   peerData2.Config.DeepCopy(),
			Password: peerData2.Password,
		}

		peer2Copy.Config.Timers = &v2.CiliumBGPTimers{
			ConnectRetryTimeSeconds: ptr.To[int32](3),
			HoldTimeSeconds:         ptr.To[int32](9),
			KeepAliveTimeSeconds:    ptr.To[int32](3),
		}

		return peer2Copy
	}()

	peer2UpdatedPorts = func() PeerData {
		peer2Copy := PeerData{
			Peer:     peerData2.Peer.DeepCopy(),
			Config:   peerData2.Config.DeepCopy(),
			Password: peerData2.Password,
		}

		peer2Copy.Config.Transport = &v2.CiliumBGPTransport{
			PeerPort: ptr.To[int32](1790),
		}

		return peer2Copy
	}()

	peer2UpdatedGR = func() PeerData {
		peer2Copy := PeerData{
			Peer:     peerData2.Peer.DeepCopy(),
			Config:   peerData2.Config.DeepCopy(),
			Password: peerData2.Password,
		}

		peer2Copy.Config.GracefulRestart = &v2.CiliumBGPNeighborGracefulRestart{
			Enabled:            true,
			RestartTimeSeconds: ptr.To[int32](3),
		}

		return peer2Copy
	}()

	peer2Pass = func() PeerData {
		peer2Copy := PeerData{
			Peer:     peerData2.Peer.DeepCopy(),
			Config:   peerData2.Config.DeepCopy(),
			Password: peerData2.Password,
		}

		peer2Copy.Config.AuthSecretRef = ptr.To[string]("a-secret")
		peer2Copy.Password = "a-password"

		return peer2Copy
	}()

	peer2UpdatePass = func() PeerData {
		peer2Copy := PeerData{
			Peer:     peerData2.Peer.DeepCopy(),
			Config:   peerData2.Config.DeepCopy(),
			Password: peerData2.Password,
		}

		peer2Copy.Config.AuthSecretRef = ptr.To[string]("a-secret")
		peer2Copy.Password = "b-password"

		return peer2Copy
	}()
)

// TestNeighborReconciler confirms the `neighborReconciler` function configures
// the desired BGP neighbors given a CiliumBGPVirtualRouter configuration.
func TestNeighborReconciler(t *testing.T) {
	req := require.New(t)
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

	table := []struct {
		name         string
		neighbors    []PeerData
		newNeighbors []PeerData
		secretStore  resource.Store[*slim_corev1.Secret]
		checks       checks
		err          error
	}{
		{
			name:         "no change",
			neighbors:    []PeerData{peerData1, peerData2},
			newNeighbors: []PeerData{peerData1, peerData2},
			err:          nil,
		},
		{
			name:         "add peers",
			neighbors:    []PeerData{peerData1},
			newNeighbors: []PeerData{peerData1, peerData2},
			err:          nil,
		},
		{
			name:         "remove peers",
			neighbors:    []PeerData{peerData1, peerData2},
			newNeighbors: []PeerData{peerData1},
			err:          nil,
		},
		{
			name:         "update config : ASN",
			neighbors:    []PeerData{peerData1, peerData2},
			newNeighbors: []PeerData{peerData1, peer2UpdatedASN},
			err:          nil,
		},
		{
			name:         "update config : timers",
			neighbors:    []PeerData{peerData1, peerData2},
			newNeighbors: []PeerData{peerData1, peer2UpdatedTimers},
			err:          nil,
		},
		{
			name:         "update config : ports",
			neighbors:    []PeerData{peerData1, peerData2},
			newNeighbors: []PeerData{peerData1, peer2UpdatedPorts},
			err:          nil,
		},
		{
			name:         "update config : graceful restart",
			neighbors:    []PeerData{peerData1, peerData2},
			newNeighbors: []PeerData{peerData1, peer2UpdatedGR},
			err:          nil,
		},
		{
			name:         "update config : password",
			neighbors:    []PeerData{peerData2},
			newNeighbors: []PeerData{peer2Pass},
			err:          nil,
		},
		{
			name:         "update config : password updated",
			neighbors:    []PeerData{peer2Pass},
			newNeighbors: []PeerData{peer2UpdatePass},
			err:          nil,
		},
		{
			name:         "update config : password removed",
			neighbors:    []PeerData{peer2Pass},
			newNeighbors: []PeerData{peerData2},
			err:          nil,
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			// our test BgpServer with our original router ID and local port
			srvParams := types.ServerParameters{
				Global: types.BGPGlobal{
					ASN:        64125,
					RouterID:   "127.0.0.1",
					ListenPort: -1,
				},
			}

			testInstance, err := instance.NewBGPInstance(context.Background(), gobgp.NewEnterpriseRouterProviderAsOSS(), logger, "test-instance", srvParams)
			req.NoError(err)

			t.Cleanup(func() {
				testInstance.Router.Stop(context.Background(), types.StopRequest{FullDestroy: true})
			})

			params, nodeConfig := setupNeighbors(logger, tt.neighbors)

			// setup initial neighbors
			neighborReconciler := NewNeighborReconciler(params).Reconciler
			neighborReconciler.Init(testInstance)
			defer neighborReconciler.Cleanup(testInstance)
			reconcileParams := reconciler.ReconcileParams{
				BGPInstance: testInstance,
				DesiredConfig: &v2.CiliumBGPNodeInstance{
					// Enterprise-specific logic. As the
					// NodeInstance is upgraded internally,
					// we only need to provide the name of
					// the NodeInstance.
					Name: nodeConfig.Name,
				},
			}
			err = neighborReconciler.Reconcile(context.Background(), reconcileParams)
			req.NoError(err)

			// validate neighbors
			validatePeers(req, tt.neighbors, getRunningPeers(req, testInstance), tt.checks)

			// update neighbors

			params, _ = setupNeighbors(logger, tt.newNeighbors)
			neighborReconciler.(*NeighborReconciler).PeerConfig = params.PeerConfig
			neighborReconciler.(*NeighborReconciler).SecretStore = params.SecretStore
			neighborReconciler.(*NeighborReconciler).upgrader = params.Upgrader
			reconcileParams = reconciler.ReconcileParams{
				BGPInstance: testInstance,
				DesiredConfig: &v2.CiliumBGPNodeInstance{
					// Enterprise-specific logic. As the
					// NodeInstance is upgraded internally,
					// we only need to provide the name of
					// the NodeInstance.
					Name: nodeConfig.Name,
				},
			}
			err = neighborReconciler.Reconcile(context.Background(), reconcileParams)
			req.NoError(err)

			// validate neighbors
			validatePeers(req, tt.newNeighbors, getRunningPeers(req, testInstance), tt.checks)
		})
	}
}

func TestNeighborReconciler_SourceInterfaceAddress(t *testing.T) {
	req := require.New(t)

	var (
		sourceInterfaceName   = "lo"
		sourceInterfaceV4Addr = "10.100.100.100"
		sourceInterfaceV6Addr = "fd00::aa:bb:100"

		peerV4 = PeerData{
			Peer: &v1.IsovalentBGPNodePeer{
				Name:        "peer-v4",
				PeerAddress: ptr.To[string]("192.168.0.1"),
				PeerASN:     ptr.To[int64](64124),
				PeerConfigRef: &v1.PeerConfigReference{
					Name: "peer-config",
				},
			},
			Config: &v1.IsovalentBGPPeerConfigSpec{
				Transport: &v2.CiliumBGPTransport{
					SourceInterface: &sourceInterfaceName,
				},
			},
		}
		peerV6 = PeerData{
			Peer: &v1.IsovalentBGPNodePeer{
				Name:        "peer-v6",
				PeerAddress: ptr.To[string]("fc00::100:1"),
				PeerASN:     ptr.To[int64](64124),
				PeerConfigRef: &v1.PeerConfigReference{
					Name: "peer-config",
				},
			},
			Config: &v1.IsovalentBGPPeerConfigSpec{
				Transport: &v2.CiliumBGPTransport{
					SourceInterface: &sourceInterfaceName,
				},
			},
		}
	)

	table := []struct {
		name                   string
		configuredNeighbors    []PeerData
		upsertDevices          []*tables.Device
		expectedNeighbors      []PeerData
		expectPeerLocalAddress map[string]string
		checks                 checks
	}{
		{
			name:                   "no device, no local address",
			configuredNeighbors:    []PeerData{peerV4, peerV6},
			expectedNeighbors:      []PeerData{},
			expectPeerLocalAddress: map[string]string{},
		},
		{
			name:                "add unrelated device, no local address",
			configuredNeighbors: []PeerData{peerV4, peerV6},
			upsertDevices: []*tables.Device{
				{
					Index: 1,
					Name:  "eth0",
					Addrs: []tables.DeviceAddress{
						{Addr: netip.MustParseAddr("10.0.0.1")},
						{Addr: netip.MustParseAddr("fc00::aa:bb:1")},
					},
				},
			},
			expectedNeighbors:      []PeerData{},
			expectPeerLocalAddress: map[string]string{},
		},
		{
			name:                "add device with IPv4 address only, IPv4 local address",
			configuredNeighbors: []PeerData{peerV4, peerV6},
			upsertDevices: []*tables.Device{
				{
					Index: 100,
					Name:  sourceInterfaceName,
					Addrs: []tables.DeviceAddress{
						{Addr: netip.MustParseAddr(sourceInterfaceV4Addr)},
					},
				},
			},
			expectedNeighbors: []PeerData{peerV4},
			expectPeerLocalAddress: map[string]string{
				peerV4.Peer.Name: sourceInterfaceV4Addr,
			},
		},
		{
			name:                "add IPv6 device address, IPv4 + IPv6 local address",
			configuredNeighbors: []PeerData{peerV4, peerV6},
			upsertDevices: []*tables.Device{
				{
					Index: 100,
					Name:  sourceInterfaceName,
					Addrs: []tables.DeviceAddress{
						{Addr: netip.MustParseAddr(sourceInterfaceV4Addr)},
						{Addr: netip.MustParseAddr(sourceInterfaceV6Addr)},
					},
				},
			},
			expectedNeighbors: []PeerData{peerV4, peerV6},
			expectPeerLocalAddress: map[string]string{
				peerV4.Peer.Name: sourceInterfaceV4Addr,
				peerV6.Peer.Name: sourceInterfaceV6Addr,
			},
		},
		{
			name:                "Remove usable device addresses, no local address",
			configuredNeighbors: []PeerData{peerV4, peerV6},
			upsertDevices: []*tables.Device{
				{
					Index: 100,
					Name:  sourceInterfaceName,
					Addrs: []tables.DeviceAddress{
						{Addr: netip.IPv4Unspecified()},          // IPv4 unspecified should be ignored
						{Addr: netip.MustParseAddr("127.0.0.1")}, // IPv4 loopback should be ignored
						{Addr: netip.MustParseAddr("224.0.0.1")}, // IPv4 multicast should be ignored
						{Addr: netip.IPv6Unspecified()},          // IPv6 unspecified should be ignored
						{Addr: netip.MustParseAddr("::1")},       // IPv6 loopback should be ignored
						{Addr: netip.MustParseAddr("ff00::1")},   // IPv6 multicast should be ignored
						{Addr: netip.MustParseAddr("fe80::1")},   // IPv6 link-local should be ignored
					},
				},
			},
			expectedNeighbors:      []PeerData{},
			expectPeerLocalAddress: map[string]string{},
		},
	}

	// initialize test statedb
	db := statedb.New()
	deviceTable, err := tables.NewDeviceTable(db)
	req.NoError(err)

	peerConfigStore := store.NewMockBGPCPResourceStore[*v1.IsovalentBGPPeerConfig]()

	neighborReconciler := NewNeighborReconciler(NeighborReconcilerIn{
		BGPConfig:    config.Config{Enabled: true, StatusReportEnabled: false},
		Logger:       hivetest.Logger(t),
		SecretStore:  nil,
		PeerConfig:   peerConfigStore,
		DaemonConfig: &option.DaemonConfig{},
		DB:           db,
		DeviceTable:  deviceTable,
	}).Reconciler.(*NeighborReconciler)

	// initialize test instance
	srvParams := types.ServerParameters{
		Global: types.BGPGlobal{
			ASN:        64125,
			RouterID:   "127.0.0.1",
			ListenPort: -1,
		},
	}
	testInstance, err := instance.NewBGPInstance(context.Background(), gobgp.NewEnterpriseRouterProviderAsOSS(), hivetest.Logger(t), "test-instance", srvParams)
	req.NoError(err)
	t.Cleanup(func() {
		testInstance.Router.Stop(context.Background(), types.StopRequest{FullDestroy: true})
	})
	neighborReconciler.Init(testInstance)
	defer neighborReconciler.Cleanup(testInstance)

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			// upsert devices in statedb
			if len(tt.upsertDevices) > 0 {
				wtxn := db.WriteTxn(deviceTable)
				for _, device := range tt.upsertDevices {
					_, _, err = deviceTable.Insert(wtxn, device)
					req.NoError(err)
				}
				wtxn.Commit()
			}

			// build desired node config
			nodeConfig := &v1.IsovalentBGPNodeInstance{
				Name: "bgp-node",
			}
			neighborReconciler.upgrader = newUpgraderMock(nodeConfig)
			for _, p := range tt.configuredNeighbors {
				obj := &v1.IsovalentBGPPeerConfig{
					ObjectMeta: metav1.ObjectMeta{
						Name: p.Peer.PeerConfigRef.Name,
					},
					Spec: *p.Config.DeepCopy(),
				}
				peerConfigStore.Upsert(obj)
				nodeConfig.Peers = append(nodeConfig.Peers, *p.Peer)
			}

			// run reconciliation
			reconcileParams := reconciler.ReconcileParams{
				BGPInstance: testInstance,
				DesiredConfig: &v2.CiliumBGPNodeInstance{
					// Enterprise-specific logic. As the
					// NodeInstance is upgraded internally,
					// we only need to provide the name of
					// the NodeInstance.
					Name: nodeConfig.Name,
				},
				CiliumNode: &v2.CiliumNode{
					ObjectMeta: metav1.ObjectMeta{
						Name: "bgp-node",
					},
				},
			}
			err = neighborReconciler.Reconcile(context.Background(), reconcileParams)
			req.NoError(err)

			// validate running peers
			validatePeers(req, tt.expectedNeighbors, getRunningPeers(req, testInstance), tt.checks)

			// validate local address used for peering
			runningMeta := neighborReconciler.getMetadata(&EnterpriseBGPInstance{Name: testInstance.Name})
			for expectPeer, expectAddr := range tt.expectPeerLocalAddress {
				req.NotNil(runningMeta.Peers[expectPeer], "peer %s is missing in the metadata", expectPeer)
				if expectAddr != "" {
					req.NotNil(runningMeta.Peers[expectPeer].Peer.LocalAddress, "LocalAddress is nil for the peer %s", expectPeer)
					req.Equal(expectAddr, *runningMeta.Peers[expectPeer].Peer.LocalAddress)
				} else {
					req.Nil(runningMeta.Peers[expectPeer].Peer.LocalAddress, "LocalAddress is expected to be for the peer %s", expectPeer)
				}
			}
		})
	}
}

func setupNeighbors(logger *slog.Logger, peers []PeerData) (NeighborReconcilerIn, *v1.IsovalentBGPNodeInstance) {
	// Desired BGP Node config
	nodeConfig := &v1.IsovalentBGPNodeInstance{
		Name: "bgp-node",
	}

	// setup fake store for peer config
	var objects []*v1.IsovalentBGPPeerConfig
	for _, p := range peers {
		obj := &v1.IsovalentBGPPeerConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name: p.Peer.PeerConfigRef.Name,
			},
			Spec: *p.Config.DeepCopy(),
		}
		objects = append(objects, obj)
		nodeConfig.Peers = append(nodeConfig.Peers, *p.Peer)
	}
	peerConfigStore := store.InitMockStore(objects)

	// setup secret store
	secrets := make(map[string][]byte)
	for _, p := range peers {
		if p.Config.AuthSecretRef != nil {
			secrets[*p.Config.AuthSecretRef] = []byte(p.Password)
		}
	}
	var secretObjs []*slim_corev1.Secret
	for _, s := range secrets {
		secretObjs = append(secretObjs, &slim_corev1.Secret{
			ObjectMeta: slim_metav1.ObjectMeta{
				Namespace: "bgp-secrets",
				Name:      "a-secret",
			},
			Data: map[string]slim_corev1.Bytes{"password": slim_corev1.Bytes(s)},
		})
	}
	secretStore := store.InitMockStore(secretObjs)

	return NeighborReconcilerIn{
		BGPConfig:   config.Config{Enabled: true, StatusReportEnabled: false},
		Logger:      logger,
		SecretStore: secretStore,
		PeerConfig:  peerConfigStore,
		DaemonConfig: &option.DaemonConfig{
			EnterpriseDaemonConfig: option.EnterpriseDaemonConfig{
				EnableEnterpriseBGPControlPlane: true,
			},
			BGPSecretsNamespace: "bgp-secrets",
		},

		// Enterprise-specific logic. Provide a mock upgrader.
		Upgrader: newUpgraderMock(nodeConfig),
	}, nodeConfig
}

func validatePeers(req *require.Assertions, expected, running []PeerData, checks checks) {
	req.Len(running, len(expected))

	for _, expPeer := range expected {
		found := false
		for _, runPeer := range running {
			req.NotNil(runPeer.Peer.PeerAddress)
			req.NotNil(runPeer.Peer.PeerASN)

			if *expPeer.Peer.PeerAddress == *runPeer.Peer.PeerAddress && *expPeer.Peer.PeerASN == *runPeer.Peer.PeerASN {
				found = true

				if checks.holdTimer {
					req.Equal(*expPeer.Config.Timers.HoldTimeSeconds, *runPeer.Config.Timers.HoldTimeSeconds)
				}

				if checks.connectRetryTimer {
					req.Equal(*expPeer.Config.Timers.ConnectRetryTimeSeconds, *runPeer.Config.Timers.ConnectRetryTimeSeconds)
				}

				if checks.keepaliveTimer {
					req.Equal(*expPeer.Config.Timers.KeepAliveTimeSeconds, *runPeer.Config.Timers.KeepAliveTimeSeconds)
				}

				if checks.grRestartTime {
					req.Equal(expPeer.Config.GracefulRestart.Enabled, runPeer.Config.GracefulRestart.Enabled)
					req.Equal(*expPeer.Config.GracefulRestart.RestartTimeSeconds, *runPeer.Config.GracefulRestart.RestartTimeSeconds)
				}

				if expPeer.Password != "" {
					req.NotEmpty(runPeer.Password)
				}

				break
			}
		}
		req.True(found)
	}
}

func getRunningPeers(req *require.Assertions, instance *instance.BGPInstance) []PeerData {
	getPeerResp, err := instance.Router.GetPeerStateLegacy(context.Background())
	req.NoError(err)

	var runningPeers []PeerData
	for _, peer := range getPeerResp.Peers {
		peerObj := &v1.IsovalentBGPNodePeer{
			PeerAddress: ptr.To[string](peer.PeerAddress),
			PeerASN:     ptr.To[int64](peer.PeerAsn),
		}

		peerConfObj := &v1.IsovalentBGPPeerConfigSpec{
			Transport: &v2.CiliumBGPTransport{
				PeerPort: ptr.To[int32](int32(peer.PeerPort)),
			},
			Timers: &v2.CiliumBGPTimers{
				ConnectRetryTimeSeconds: ptr.To[int32](int32(peer.ConnectRetryTimeSeconds)),
				HoldTimeSeconds:         ptr.To[int32](int32(peer.ConfiguredHoldTimeSeconds)),
				KeepAliveTimeSeconds:    ptr.To[int32](int32(peer.ConfiguredKeepAliveTimeSeconds)),
			},
			GracefulRestart: &v2.CiliumBGPNeighborGracefulRestart{
				Enabled:            peer.GracefulRestart.Enabled,
				RestartTimeSeconds: ptr.To[int32](int32(peer.GracefulRestart.RestartTimeSeconds)),
			},
			EBGPMultihop: ptr.To[int32](int32(peer.EbgpMultihopTTL)),
		}

		password := ""
		if peer.TCPPasswordEnabled {
			password = "something-is-set-dont-care-what"
		}

		runningPeers = append(runningPeers, PeerData{
			Peer:     peerObj,
			Config:   peerConfObj,
			Password: password,
		})
	}
	return runningPeers
}

func TestRouteReflectorPolicy(t *testing.T) {
	tests := []struct {
		name     string
		instance *v1.IsovalentBGPNodeInstance
		expected RoutePolicyMap
	}{
		{
			name:     "non-route-reflector",
			instance: &v1.IsovalentBGPNodeInstance{},
			expected: RoutePolicyMap{},
		},
		{
			name: "route-reflector no RR peer",
			instance: &v1.IsovalentBGPNodeInstance{
				RouteReflector: &v1.NodeRouteReflector{
					Role: v1.RouteReflectorRoleRouteReflector,
				},
			},
			expected: RoutePolicyMap{},
		},
		{
			name: "client no RR peer",
			instance: &v1.IsovalentBGPNodeInstance{
				RouteReflector: &v1.NodeRouteReflector{
					Role: v1.RouteReflectorRoleClient,
				},
			},
			expected: RoutePolicyMap{},
		},
		{
			name: "route-reflector to route-reflectors",
			instance: &v1.IsovalentBGPNodeInstance{
				RouteReflector: &v1.NodeRouteReflector{
					Role: v1.RouteReflectorRoleRouteReflector,
				},
				Peers: []v1.IsovalentBGPNodePeer{
					{
						PeerAddress: ptr.To("10.0.0.1"),
						RouteReflector: &v1.NodeRouteReflector{
							Role: v1.RouteReflectorRoleRouteReflector,
						},
					},
					{
						PeerAddress: ptr.To("10.0.0.2"),
						RouteReflector: &v1.NodeRouteReflector{
							Role: v1.RouteReflectorRoleRouteReflector,
						},
					},
				},
			},
			expected: RoutePolicyMap{
				"rr-rr-allow-all-imports-from-rr": &enterpriseTypes.ExtendedRoutePolicy{
					Name: "rr-rr-allow-all-imports-from-rr",
					Type: types.RoutePolicyTypeImport,
					Statements: []*enterpriseTypes.ExtendedRoutePolicyStatement{
						{
							Conditions: enterpriseTypes.ExtendedRoutePolicyConditions{
								RoutePolicyConditions: types.RoutePolicyConditions{
									MatchNeighbors: &types.RoutePolicyNeighborMatch{
										Type: types.RoutePolicyMatchAny,
										Neighbors: []netip.Addr{
											netip.MustParseAddr("10.0.0.1"),
											netip.MustParseAddr("10.0.0.2"),
										},
									},
								},
							},
							Actions: enterpriseTypes.ExtendedRoutePolicyActions{
								RoutePolicyActions: types.RoutePolicyActions{
									RouteAction: types.RoutePolicyActionAccept,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "route-reflector to clients",
			instance: &v1.IsovalentBGPNodeInstance{
				RouteReflector: &v1.NodeRouteReflector{
					Role: v1.RouteReflectorRoleRouteReflector,
				},
				Peers: []v1.IsovalentBGPNodePeer{
					{
						PeerAddress: ptr.To("10.0.0.1"),
						RouteReflector: &v1.NodeRouteReflector{
							Role: v1.RouteReflectorRoleClient,
						},
					},
					{
						PeerAddress: ptr.To("10.0.0.2"),
						RouteReflector: &v1.NodeRouteReflector{
							Role: v1.RouteReflectorRoleClient,
						},
					},
				},
			},
			expected: RoutePolicyMap{
				"rr-rr-allow-all-imports-from-clients": &enterpriseTypes.ExtendedRoutePolicy{
					Name: "rr-rr-allow-all-imports-from-clients",
					Type: types.RoutePolicyTypeImport,
					Statements: []*enterpriseTypes.ExtendedRoutePolicyStatement{
						{
							Conditions: enterpriseTypes.ExtendedRoutePolicyConditions{
								RoutePolicyConditions: types.RoutePolicyConditions{
									MatchNeighbors: &types.RoutePolicyNeighborMatch{
										Type: types.RoutePolicyMatchAny,
										Neighbors: []netip.Addr{
											netip.MustParseAddr("10.0.0.1"),
											netip.MustParseAddr("10.0.0.2"),
										},
									},
								},
							},
							Actions: enterpriseTypes.ExtendedRoutePolicyActions{
								RoutePolicyActions: types.RoutePolicyActions{
									RouteAction: types.RoutePolicyActionAccept,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "route-reflector to clients and route-reflectors",
			instance: &v1.IsovalentBGPNodeInstance{
				RouteReflector: &v1.NodeRouteReflector{
					Role: v1.RouteReflectorRoleRouteReflector,
				},
				Peers: []v1.IsovalentBGPNodePeer{
					{
						PeerAddress: ptr.To("10.0.0.1"),
						RouteReflector: &v1.NodeRouteReflector{
							Role: v1.RouteReflectorRoleClient,
						},
					},
					{
						PeerAddress: ptr.To("10.0.0.2"),
						RouteReflector: &v1.NodeRouteReflector{
							Role: v1.RouteReflectorRoleClient,
						},
					},
					{
						PeerAddress: ptr.To("10.0.0.3"),
						RouteReflector: &v1.NodeRouteReflector{
							Role: v1.RouteReflectorRoleRouteReflector,
						},
					},
					{
						PeerAddress: ptr.To("10.0.0.4"),
						RouteReflector: &v1.NodeRouteReflector{
							Role: v1.RouteReflectorRoleRouteReflector,
						},
					},
				},
			},
			expected: RoutePolicyMap{
				"rr-rr-allow-all-imports-from-clients": &enterpriseTypes.ExtendedRoutePolicy{
					Name: "rr-rr-allow-all-imports-from-clients",
					Type: types.RoutePolicyTypeImport,
					Statements: []*enterpriseTypes.ExtendedRoutePolicyStatement{
						{
							Conditions: enterpriseTypes.ExtendedRoutePolicyConditions{
								RoutePolicyConditions: types.RoutePolicyConditions{
									MatchNeighbors: &types.RoutePolicyNeighborMatch{
										Type: types.RoutePolicyMatchAny,
										Neighbors: []netip.Addr{
											netip.MustParseAddr("10.0.0.1"),
											netip.MustParseAddr("10.0.0.2"),
										},
									},
								},
							},
							Actions: enterpriseTypes.ExtendedRoutePolicyActions{
								RoutePolicyActions: types.RoutePolicyActions{
									RouteAction: types.RoutePolicyActionAccept,
								},
							},
						},
					},
				},
				"rr-rr-allow-all-imports-from-rr": &enterpriseTypes.ExtendedRoutePolicy{
					Name: "rr-rr-allow-all-imports-from-rr",
					Type: types.RoutePolicyTypeImport,
					Statements: []*enterpriseTypes.ExtendedRoutePolicyStatement{
						{
							Conditions: enterpriseTypes.ExtendedRoutePolicyConditions{
								RoutePolicyConditions: types.RoutePolicyConditions{
									MatchNeighbors: &types.RoutePolicyNeighborMatch{
										Type: types.RoutePolicyMatchAny,
										Neighbors: []netip.Addr{
											netip.MustParseAddr("10.0.0.3"),
											netip.MustParseAddr("10.0.0.4"),
										},
									},
								},
							},
							Actions: enterpriseTypes.ExtendedRoutePolicyActions{
								RoutePolicyActions: types.RoutePolicyActions{
									RouteAction: types.RoutePolicyActionAccept,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "client to route-reflectors",
			instance: &v1.IsovalentBGPNodeInstance{
				RouteReflector: &v1.NodeRouteReflector{
					Role: v1.RouteReflectorRoleClient,
				},
				Peers: []v1.IsovalentBGPNodePeer{
					{
						PeerAddress: ptr.To("10.0.0.1"),
						RouteReflector: &v1.NodeRouteReflector{
							Role: v1.RouteReflectorRoleRouteReflector,
						},
					},
					{
						PeerAddress: ptr.To("10.0.0.2"),
						RouteReflector: &v1.NodeRouteReflector{
							Role: v1.RouteReflectorRoleRouteReflector,
						},
					},
				},
			},
			expected: RoutePolicyMap{},
		},
		{
			name: "route-reflector to eBGP peer",
			instance: &v1.IsovalentBGPNodeInstance{
				LocalASN: ptr.To(int64(65000)),
				RouteReflector: &v1.NodeRouteReflector{
					Role: v1.RouteReflectorRoleRouteReflector,
				},
				Peers: []v1.IsovalentBGPNodePeer{
					{
						PeerAddress: ptr.To("10.0.0.1"),
						PeerASN:     ptr.To(int64(65000)),
						RouteReflector: &v1.NodeRouteReflector{
							Role: v1.RouteReflectorRoleClient,
						},
					},
					{
						PeerAddress: ptr.To("10.0.0.2"),
						PeerASN:     ptr.To(int64(65001)),
					},
				},
			},
			expected: RoutePolicyMap{
				"rr-rr-allow-all-imports-from-clients": &enterpriseTypes.ExtendedRoutePolicy{
					Name: "rr-rr-allow-all-imports-from-clients",
					Type: types.RoutePolicyTypeImport,
					Statements: []*enterpriseTypes.ExtendedRoutePolicyStatement{
						{
							Conditions: enterpriseTypes.ExtendedRoutePolicyConditions{
								RoutePolicyConditions: types.RoutePolicyConditions{
									MatchNeighbors: &types.RoutePolicyNeighborMatch{
										Type: types.RoutePolicyMatchAny,
										Neighbors: []netip.Addr{
											netip.MustParseAddr("10.0.0.1"),
										},
									},
								},
							},
							Actions: enterpriseTypes.ExtendedRoutePolicyActions{
								RoutePolicyActions: types.RoutePolicyActions{
									RouteAction: types.RoutePolicyActionAccept,
								},
							},
						},
					},
				},
				"rr-rr-allow-all-exports-to-non-rr-peers": &enterpriseTypes.ExtendedRoutePolicy{
					Name: "rr-rr-allow-all-exports-to-non-rr-peers",
					Type: types.RoutePolicyTypeExport,
					Statements: []*enterpriseTypes.ExtendedRoutePolicyStatement{
						{
							Conditions: enterpriseTypes.ExtendedRoutePolicyConditions{
								RoutePolicyConditions: types.RoutePolicyConditions{
									MatchNeighbors: &types.RoutePolicyNeighborMatch{
										Type: types.RoutePolicyMatchAny,
										Neighbors: []netip.Addr{
											netip.MustParseAddr("10.0.0.2"),
										},
									},
								},
							},
							Actions: enterpriseTypes.ExtendedRoutePolicyActions{
								RoutePolicyActions: types.RoutePolicyActions{
									RouteAction: types.RoutePolicyActionAccept,
									NextHop: &types.RoutePolicyActionNextHop{
										Unchanged: true,
									},
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getDesiredRouteReflectorPolicies(tt.instance)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestUserDefinedImportPolicy(t *testing.T) {
	policyV4 := &v1.IsovalentBGPPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "policy-v4",
		},
		Spec: v1.IsovalentBGPPolicySpec{
			Import: v1.BGPImportPolicy{
				Statements: []v1.BGPPolicyStatement{
					{
						Conditions: v1.BGPPolicyConditions{
							PrefixesV4: &v1.PrefixesV4Condition{
								MatchType: v1.BGPPolicyMatchTypeOr,
								Matches: []v1.PrefixV4Match{
									{
										Prefix: "10.0.0.0/24",
										MaxLen: ptr.To(uint8(16)),
										MinLen: ptr.To(uint8(8)),
									},
								},
							},
						},
						Actions: v1.BGPPolicyActions{
							RouteAction: v1.BGPRouteActionAccept,
						},
					},
				},
			},
		},
	}
	policyV6 := &v1.IsovalentBGPPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "policy-v6",
		},
		Spec: v1.IsovalentBGPPolicySpec{
			Import: v1.BGPImportPolicy{
				Statements: []v1.BGPPolicyStatement{
					{
						Conditions: v1.BGPPolicyConditions{
							PrefixesV6: &v1.PrefixesV6Condition{
								MatchType: v1.BGPPolicyMatchTypeOr,
								Matches: []v1.PrefixV6Match{
									{
										Prefix: "fd00::/64",
										MaxLen: ptr.To(uint8(32)),
										MinLen: ptr.To(uint8(16)),
									},
								},
							},
						},
						Actions: v1.BGPPolicyActions{
							RouteAction: v1.BGPRouteActionAccept,
						},
					},
				},
			},
		},
	}
	policyDual := &v1.IsovalentBGPPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "policy-dual",
		},
		Spec: v1.IsovalentBGPPolicySpec{
			Import: v1.BGPImportPolicy{
				Statements: []v1.BGPPolicyStatement{
					{
						Conditions: v1.BGPPolicyConditions{
							PrefixesV4: &v1.PrefixesV4Condition{
								MatchType: v1.BGPPolicyMatchTypeOr,
								Matches: []v1.PrefixV4Match{
									{
										Prefix: "10.0.0.0/24",
										MaxLen: ptr.To(uint8(16)),
										MinLen: ptr.To(uint8(8)),
									},
								},
							},
							PrefixesV6: &v1.PrefixesV6Condition{
								MatchType: v1.BGPPolicyMatchTypeOr,
								Matches: []v1.PrefixV6Match{
									{
										Prefix: "fd00::/64",
										MaxLen: ptr.To(uint8(32)),
										MinLen: ptr.To(uint8(16)),
									},
								},
							},
						},
						Actions: v1.BGPPolicyActions{
							RouteAction: v1.BGPRouteActionAccept,
						},
					},
				},
			},
		},
	}
	peerConfigV4Only := &v1.IsovalentBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "v4-only",
		},
		Spec: v1.IsovalentBGPPeerConfigSpec{
			Families: []v1.IsovalentBGPFamilyWithAdverts{
				{
					CiliumBGPFamily: v2.CiliumBGPFamily{
						Afi:  "ipv4",
						Safi: "unicast",
					},
					ImportPolicyRef: &v1.IsovalentBGPPolicyRef{
						Name: policyV4.Name,
					},
				},
			},
		},
	}
	peerConfigV6Only := &v1.IsovalentBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "v6-only",
		},
		Spec: v1.IsovalentBGPPeerConfigSpec{
			Families: []v1.IsovalentBGPFamilyWithAdverts{
				{
					CiliumBGPFamily: v2.CiliumBGPFamily{
						Afi:  "ipv6",
						Safi: "unicast",
					},
					ImportPolicyRef: &v1.IsovalentBGPPolicyRef{
						Name: policyV6.Name,
					},
				},
			},
		},
	}
	peerConfigDual := &v1.IsovalentBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "dual",
		},
		Spec: v1.IsovalentBGPPeerConfigSpec{
			Families: []v1.IsovalentBGPFamilyWithAdverts{
				{
					CiliumBGPFamily: v2.CiliumBGPFamily{
						Afi:  "ipv4",
						Safi: "unicast",
					},
					ImportPolicyRef: &v1.IsovalentBGPPolicyRef{
						Name: policyDual.Name,
					},
				},
				{
					CiliumBGPFamily: v2.CiliumBGPFamily{
						Afi:  "ipv6",
						Safi: "unicast",
					},
					ImportPolicyRef: &v1.IsovalentBGPPolicyRef{
						Name: policyDual.Name,
					},
				},
			},
		},
	}
	peerConfigOneFamily := &v1.IsovalentBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "one-of-family",
		},
		Spec: v1.IsovalentBGPPeerConfigSpec{
			Families: []v1.IsovalentBGPFamilyWithAdverts{
				{
					CiliumBGPFamily: v2.CiliumBGPFamily{
						Afi:  "ipv4",
						Safi: "unicast",
					},
					ImportPolicyRef: &v1.IsovalentBGPPolicyRef{
						Name: policyV4.Name,
					},
				},
				{
					CiliumBGPFamily: v2.CiliumBGPFamily{
						Afi:  "ipv4",
						Safi: "unicast",
					},
					ImportPolicyRef: nil,
				},
			},
		},
	}
	peerConfigNoRef := &v1.IsovalentBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "no-reference",
		},
		Spec: v1.IsovalentBGPPeerConfigSpec{
			Families: []v1.IsovalentBGPFamilyWithAdverts{
				{
					CiliumBGPFamily: v2.CiliumBGPFamily{
						Afi:  "ipv4",
						Safi: "unicast",
					},
					ImportPolicyRef: nil,
				},
			},
		},
	}
	implicitAllowAllCase0 := &v1.IsovalentBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "implicit-allow-all-case0",
		},
		Spec: v1.IsovalentBGPPeerConfigSpec{
			Families: []v1.IsovalentBGPFamilyWithAdverts{
				{
					CiliumBGPFamily: v2.CiliumBGPFamily{
						Afi:  "ipv4",
						Safi: "unicast",
					},
					// Attaching IPv6 matching policy to
					// IPv4 family produces empty prefix
					// matches.
					ImportPolicyRef: &v1.IsovalentBGPPolicyRef{
						Name: policyV6.Name,
					},
				},
			},
		},
	}

	tests := []struct {
		name             string
		peer             *v1.IsovalentBGPNodePeer
		expectedPolicies RoutePolicyMap
	}{
		{
			name: "v4 only",
			peer: &v1.IsovalentBGPNodePeer{
				Name:        "peer0",
				PeerAddress: ptr.To("10.0.0.1"),
				PeerConfigRef: &v1.PeerConfigReference{
					Name: peerConfigV4Only.Name,
				},
			},
			expectedPolicies: RoutePolicyMap{
				"import-user-defined-peer0-ipv4-unicast": &enterpriseTypes.ExtendedRoutePolicy{
					Name: "import-user-defined-peer0-ipv4-unicast",
					Type: types.RoutePolicyTypeImport,
					Statements: []*enterpriseTypes.ExtendedRoutePolicyStatement{
						{
							Conditions: enterpriseTypes.ExtendedRoutePolicyConditions{
								RoutePolicyConditions: types.RoutePolicyConditions{
									MatchNeighbors: &types.RoutePolicyNeighborMatch{
										Type:      types.RoutePolicyMatchAny,
										Neighbors: []netip.Addr{netip.MustParseAddr("10.0.0.1")},
									},
									MatchPrefixes: &types.RoutePolicyPrefixMatch{
										Type: types.RoutePolicyMatchAny,
										Prefixes: []types.RoutePolicyPrefix{
											{
												CIDR:         netip.MustParsePrefix("10.0.0.0/24"),
												PrefixLenMax: 16,
												PrefixLenMin: 8,
											},
										},
									},
									MatchFamilies: []types.Family{
										{
											Afi:  types.AfiIPv4,
											Safi: types.SafiUnicast,
										},
									},
								},
							},
							Actions: enterpriseTypes.ExtendedRoutePolicyActions{
								RoutePolicyActions: types.RoutePolicyActions{
									RouteAction: types.RoutePolicyActionAccept,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "v6 only",
			peer: &v1.IsovalentBGPNodePeer{
				Name:        "peer0",
				PeerAddress: ptr.To("2001:db8::1"),
				PeerConfigRef: &v1.PeerConfigReference{
					Name: peerConfigV6Only.Name,
				},
			},
			expectedPolicies: RoutePolicyMap{
				"import-user-defined-peer0-ipv6-unicast": &enterpriseTypes.ExtendedRoutePolicy{
					Name: "import-user-defined-peer0-ipv6-unicast",
					Type: types.RoutePolicyTypeImport,
					Statements: []*enterpriseTypes.ExtendedRoutePolicyStatement{
						{
							Conditions: enterpriseTypes.ExtendedRoutePolicyConditions{
								RoutePolicyConditions: types.RoutePolicyConditions{
									MatchNeighbors: &types.RoutePolicyNeighborMatch{
										Type:      types.RoutePolicyMatchAny,
										Neighbors: []netip.Addr{netip.MustParseAddr("2001:db8::1")},
									},
									MatchPrefixes: &types.RoutePolicyPrefixMatch{
										Type: types.RoutePolicyMatchAny,
										Prefixes: []types.RoutePolicyPrefix{
											{
												CIDR:         netip.MustParsePrefix("fd00::/64"),
												PrefixLenMax: 32,
												PrefixLenMin: 16,
											},
										},
									},
									MatchFamilies: []types.Family{
										{
											Afi:  types.AfiIPv6,
											Safi: types.SafiUnicast,
										},
									},
								},
							},
							Actions: enterpriseTypes.ExtendedRoutePolicyActions{
								RoutePolicyActions: types.RoutePolicyActions{
									RouteAction: types.RoutePolicyActionAccept,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "dual",
			peer: &v1.IsovalentBGPNodePeer{
				Name:        "peer0",
				PeerAddress: ptr.To("2001:db8::1"),
				PeerConfigRef: &v1.PeerConfigReference{
					Name: peerConfigDual.Name,
				},
			},
			expectedPolicies: RoutePolicyMap{
				"import-user-defined-peer0-ipv4-unicast": &enterpriseTypes.ExtendedRoutePolicy{
					Name: "import-user-defined-peer0-ipv4-unicast",
					Type: types.RoutePolicyTypeImport,
					Statements: []*enterpriseTypes.ExtendedRoutePolicyStatement{
						{
							Conditions: enterpriseTypes.ExtendedRoutePolicyConditions{
								RoutePolicyConditions: types.RoutePolicyConditions{
									MatchNeighbors: &types.RoutePolicyNeighborMatch{
										Type:      types.RoutePolicyMatchAny,
										Neighbors: []netip.Addr{netip.MustParseAddr("2001:db8::1")},
									},
									MatchPrefixes: &types.RoutePolicyPrefixMatch{
										Type: types.RoutePolicyMatchAny,
										Prefixes: []types.RoutePolicyPrefix{
											{
												CIDR:         netip.MustParsePrefix("10.0.0.0/24"),
												PrefixLenMax: 16,
												PrefixLenMin: 8,
											},
										},
									},
									MatchFamilies: []types.Family{
										{
											Afi:  types.AfiIPv4,
											Safi: types.SafiUnicast,
										},
									},
								},
							},
							Actions: enterpriseTypes.ExtendedRoutePolicyActions{
								RoutePolicyActions: types.RoutePolicyActions{
									RouteAction: types.RoutePolicyActionAccept,
								},
							},
						},
					},
				},
				"import-user-defined-peer0-ipv6-unicast": &enterpriseTypes.ExtendedRoutePolicy{
					Name: "import-user-defined-peer0-ipv6-unicast",
					Type: types.RoutePolicyTypeImport,
					Statements: []*enterpriseTypes.ExtendedRoutePolicyStatement{
						{
							Conditions: enterpriseTypes.ExtendedRoutePolicyConditions{
								RoutePolicyConditions: types.RoutePolicyConditions{
									MatchNeighbors: &types.RoutePolicyNeighborMatch{
										Type:      types.RoutePolicyMatchAny,
										Neighbors: []netip.Addr{netip.MustParseAddr("2001:db8::1")},
									},
									MatchPrefixes: &types.RoutePolicyPrefixMatch{
										Type: types.RoutePolicyMatchAny,
										Prefixes: []types.RoutePolicyPrefix{
											{
												CIDR:         netip.MustParsePrefix("fd00::/64"),
												PrefixLenMax: 32,
												PrefixLenMin: 16,
											},
										},
									},
									MatchFamilies: []types.Family{
										{
											Afi:  types.AfiIPv6,
											Safi: types.SafiUnicast,
										},
									},
								},
							},
							Actions: enterpriseTypes.ExtendedRoutePolicyActions{
								RoutePolicyActions: types.RoutePolicyActions{
									RouteAction: types.RoutePolicyActionAccept,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "one of family",
			peer: &v1.IsovalentBGPNodePeer{
				Name:        "peer0",
				PeerAddress: ptr.To("2001:db8::1"),
				PeerConfigRef: &v1.PeerConfigReference{
					Name: peerConfigOneFamily.Name,
				},
			},
			expectedPolicies: RoutePolicyMap{
				"import-user-defined-peer0-ipv4-unicast": &enterpriseTypes.ExtendedRoutePolicy{
					Name: "import-user-defined-peer0-ipv4-unicast",
					Type: types.RoutePolicyTypeImport,
					Statements: []*enterpriseTypes.ExtendedRoutePolicyStatement{
						{
							Conditions: enterpriseTypes.ExtendedRoutePolicyConditions{
								RoutePolicyConditions: types.RoutePolicyConditions{
									MatchNeighbors: &types.RoutePolicyNeighborMatch{
										Type:      types.RoutePolicyMatchAny,
										Neighbors: []netip.Addr{netip.MustParseAddr("2001:db8::1")},
									},
									MatchPrefixes: &types.RoutePolicyPrefixMatch{
										Type: types.RoutePolicyMatchAny,
										Prefixes: []types.RoutePolicyPrefix{
											{
												CIDR:         netip.MustParsePrefix("10.0.0.0/24"),
												PrefixLenMax: 16,
												PrefixLenMin: 8,
											},
										},
									},
									MatchFamilies: []types.Family{
										{
											Afi:  types.AfiIPv4,
											Safi: types.SafiUnicast,
										},
									},
								},
							},
							Actions: enterpriseTypes.ExtendedRoutePolicyActions{
								RoutePolicyActions: types.RoutePolicyActions{
									RouteAction: types.RoutePolicyActionAccept,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "route-reflector RR peer",
			peer: &v1.IsovalentBGPNodePeer{
				Name:        "peer0",
				PeerAddress: ptr.To("10.0.0.1"),
				PeerConfigRef: &v1.PeerConfigReference{
					Name: peerConfigV4Only.Name,
				},
				RouteReflector: &v1.NodeRouteReflector{
					Role: v1.RouteReflectorRoleRouteReflector,
				},
			},
			expectedPolicies: RoutePolicyMap{},
		},
		{
			name: "route-reflector client peer",
			peer: &v1.IsovalentBGPNodePeer{
				Name:        "peer0",
				PeerAddress: ptr.To("10.0.0.1"),
				PeerConfigRef: &v1.PeerConfigReference{
					Name: peerConfigV4Only.Name,
				},
				RouteReflector: &v1.NodeRouteReflector{
					Role: v1.RouteReflectorRoleClient,
				},
			},
			expectedPolicies: RoutePolicyMap{},
		},
		{
			name: "no peerAddress",
			peer: &v1.IsovalentBGPNodePeer{
				Name:        "peer0",
				PeerAddress: nil,
				PeerConfigRef: &v1.PeerConfigReference{
					Name: peerConfigV4Only.Name,
				},
			},
			expectedPolicies: RoutePolicyMap{},
		},
		{
			name: "no peerConfigRef",
			peer: &v1.IsovalentBGPNodePeer{
				Name:          "peer0",
				PeerAddress:   ptr.To("10.0.0.1"),
				PeerConfigRef: nil,
			},
			expectedPolicies: RoutePolicyMap{},
		},
		{
			name: "no importPolicyRef",
			peer: &v1.IsovalentBGPNodePeer{
				Name:        "peer0",
				PeerAddress: ptr.To("10.0.0.1"),
				PeerConfigRef: &v1.PeerConfigReference{
					Name: peerConfigNoRef.Name,
				},
			},
			expectedPolicies: RoutePolicyMap{},
		},
		{
			name: "implicit allow all case0",
			peer: &v1.IsovalentBGPNodePeer{
				Name:        "peer0",
				PeerAddress: ptr.To("10.0.0.1"),
				PeerConfigRef: &v1.PeerConfigReference{
					Name: implicitAllowAllCase0.Name,
				},
			},
			expectedPolicies: RoutePolicyMap{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// setup fake store for peer config
			peerConfigStore := store.InitMockStore([]*v1.IsovalentBGPPeerConfig{
				peerConfigV4Only,
				peerConfigV6Only,
				peerConfigDual,
				peerConfigOneFamily,
				peerConfigNoRef,
				implicitAllowAllCase0,
			})

			// setup fake store for policies
			policyStore := store.InitMockStore([]*v1.IsovalentBGPPolicy{
				policyV4,
				policyV6,
				policyDual,
			})

			reconcilerIn := NeighborReconcilerIn{
				Logger:           hivetest.Logger(t),
				BGPConfig:        config.Config{Enabled: true},
				EnterpriseConfig: Config{RouteImportEnabled: true},
				PeerConfig:       peerConfigStore,
				Policy:           policyStore,
			}

			instance := &v1.IsovalentBGPNodeInstance{
				Peers: []v1.IsovalentBGPNodePeer{*tt.peer},
			}

			reconciler := NewNeighborReconciler(reconcilerIn).Reconciler
			result := reconciler.(*NeighborReconciler).getDesiredUserDefinedImportPolicy(instance)
			require.Equal(t, tt.expectedPolicies, result)
		})
	}
}
func TestImportPolicyNotMutatedByDefaulting(t *testing.T) {
	logger := hivetest.Logger(t)

	instance0 := &v1.IsovalentBGPNodeInstance{
		Name:     "instance0",
		LocalASN: ptr.To(int64(65000)),
		Peers: []v1.IsovalentBGPNodePeer{
			{
				PeerAddress: ptr.To("10.0.0.1"),
				PeerASN:     ptr.To(int64(65001)),
				PeerConfigRef: &v1.PeerConfigReference{
					Name: "peer-config0",
				},
			},
		},
	}
	peerConfig0 := &v1.IsovalentBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "peer-config0",
		},
		Spec: v1.IsovalentBGPPeerConfigSpec{
			Families: []v1.IsovalentBGPFamilyWithAdverts{
				{
					CiliumBGPFamily: v2.CiliumBGPFamily{
						Afi:  "ipv4",
						Safi: "unicast",
					},
					ImportPolicyRef: &v1.IsovalentBGPPolicyRef{
						Name: "policy0",
					},
				},
			},
		},
	}
	policy0 := &v1.IsovalentBGPPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "policy0",
		},
		Spec: v1.IsovalentBGPPolicySpec{
			Import: v1.BGPImportPolicy{
				Statements: []v1.BGPPolicyStatement{
					{
						Conditions: v1.BGPPolicyConditions{
							PrefixesV4: &v1.PrefixesV4Condition{
								MatchType: v1.BGPPolicyMatchTypeOr,
								Matches: []v1.PrefixV4Match{
									{
										Prefix: "0.0.0.0/0",
										// omitting PrefixLenMin and PrefixLenMax intentionally, will be defaulted
									},
								},
							},
						},
						Actions: v1.BGPPolicyActions{
							RouteAction: v1.BGPRouteActionAccept,
						},
					},
				},
			},
		},
	}
	originalPolicy := policy0.DeepCopy()

	var (
		neighborReconciler reconciler.ConfigReconciler
		policyStore        store.BGPCPResourceStore[*v1.IsovalentBGPPolicy]
	)
	h := hive.New(
		cell.Provide(
			NewNeighborReconciler,
			tables.NewDeviceTable,
			statedb.RWTable[*tables.Device].ToTable,
			func() store.BGPCPResourceStore[*v1.IsovalentBGPPeerConfig] {
				return store.InitMockStore([]*v1.IsovalentBGPPeerConfig{peerConfig0})
			},
			func() store.BGPCPResourceStore[*v1.IsovalentBGPPolicy] {
				return store.InitMockStore([]*v1.IsovalentBGPPolicy{policy0})
			},
			func() store.BGPCPResourceStore[*slim_corev1.Secret] {
				return store.InitMockStore([]*slim_corev1.Secret{})
			},
			func() *option.DaemonConfig {
				return &option.DaemonConfig{
					EnableBGPControlPlane: true,
				}
			},
			func() paramUpgrader {
				return newUpgraderMock(instance0)
			},
		),
		cell.Config(config.DefaultConfig),
		cell.Config(defaultConfig),

		cell.Invoke(func(
			reconcilersIn struct {
				cell.In
				Reconcilers []reconciler.ConfigReconciler `group:"bgp-config-reconciler"`
			},
			_policyStore store.BGPCPResourceStore[*v1.IsovalentBGPPolicy],
		) {
			require.Len(t, reconcilersIn.Reconcilers, 1)
			neighborReconciler = reconcilersIn.Reconcilers[0]
			policyStore = _policyStore
		}),
	)
	hive.AddConfigOverride(h, func(c *config.Config) {
		c.Enabled = true
	})
	hive.AddConfigOverride(h, func(c *Config) {
		c.RouteImportEnabled = true
	})

	err := h.Populate(logger)
	require.NoError(t, err)

	t.Run("Before reconciliation", func(t *testing.T) {
		storedPolicy, exists, err := policyStore.GetByKey(resource.Key{Name: policy0.Name})
		require.NoError(t, err)
		require.True(t, exists)
		require.True(t, originalPolicy.DeepEqual(storedPolicy))
	})

	instance, err := instance.NewBGPInstance(
		t.Context(),
		fake.NewEnterpriseFakeRouterProviderAsOSS(),
		logger,
		instance0.Name,
		types.ServerParameters{},
	)
	require.NoError(t, err)

	err = neighborReconciler.Init(instance)
	require.NoError(t, err)

	err = neighborReconciler.Reconcile(context.Background(), reconciler.ReconcileParams{
		BGPInstance: instance,
		DesiredConfig: &v2.CiliumBGPNodeInstance{
			Name: instance0.Name,
		},
	})
	require.NoError(t, err)

	t.Run("After reconciliation", func(t *testing.T) {
		storedPolicy, exists, err := policyStore.GetByKey(resource.Key{Name: policy0.Name})
		require.NoError(t, err)
		require.True(t, exists)
		require.True(t, originalPolicy.DeepEqual(storedPolicy))
	})
}
