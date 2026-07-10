//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package egressgatewayha

import (
	"context"
	"log/slog"
	"maps"
	"net"
	"testing"

	hiveExt "github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	"github.com/cilium/statedb"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/sets"

	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/enterprise/pkg/egressgatewayha/healthcheck"
	enterpriseHealthConfig "github.com/cilium/cilium/enterprise/pkg/healthconfig"
	"github.com/cilium/cilium/enterprise/pkg/maps/egressmapha"
	"github.com/cilium/cilium/enterprise/pkg/tunnelip"
	operatorK8s "github.com/cilium/cilium/operator/k8s"
	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/bgp/agent/signaler"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/gneigh"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/healthconfig"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	k8sFake "github.com/cilium/cilium/pkg/k8s/client/testutils"
	k8sTables "github.com/cilium/cilium/pkg/k8s/tables"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/ctmap/gc"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/monitor/agent"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/testutils"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	"github.com/cilium/cilium/pkg/time"
)

func TestOperatorScripts(t *testing.T) {
	log := hivetest.Logger(t)
	ctx := t.Context()

	// Set the node name to be "localnode1" for all the tests.
	nodeTypes.SetName("localnode1")

	scripttest.Test(t,
		ctx,
		func(t testing.TB, args []string) *script.Engine {
			h := hive.New(
				OperatorCell,
				PolicyCell,
				k8sFake.FakeClientCell(),
				operatorK8s.ResourcesCell,
				cell.Provide(func() healthcheck.Healthchecker {
					return &mockHealthChecker{}
				}),
				cell.Provide(
					func() *operatorOption.OperatorConfig {
						return operatorOption.Config
					},
					func() *option.DaemonConfig {
						return &option.DaemonConfig{
							EnterpriseDaemonConfig: option.EnterpriseDaemonConfig{
								EnableIPv4EgressGatewayHA: true,
							},
							EnableBPFMasquerade:    true,
							EnableIPv4Masquerade:   true,
							IdentityAllocationMode: option.IdentityAllocationModeCRD,
							Debug:                  false,
						}
					},
				),

				cell.Invoke(func(*OperatorManager, hiveExt.ScriptCmds) {}),
			)

			flags := pflag.NewFlagSet("", pflag.ContinueOnError)
			h.RegisterFlags(flags)
			flags.Set(healthconfig.EnableHealthCheckingName, "false")
			flags.Set(enterpriseHealthConfig.EnableHealthServerName, "true")

			t.Cleanup(func() {
				assert.NoError(t, h.Stop(log, context.TODO()))
			})
			cmds, err := h.ScriptCommands(log)
			require.NoError(t, err, "ScriptCommands")
			maps.Insert(cmds, maps.All(script.DefaultCmds()))
			return &script.Engine{
				Cmds:          cmds,
				RetryInterval: 1500 * time.Millisecond,
			}
		}, []string{}, "testdata/operator_*.txtar")
}

func TestPrivilegedAgentScripts(t *testing.T) {
	testutils.PrivilegedTest(t)
	log := hivetest.Logger(t)
	ctx := t.Context()

	// Set the node name to be "localnode1" for all the tests.
	nodeTypes.SetName("localnode1")

	scripttest.Test(t,
		ctx,
		func(t testing.TB, args []string) *script.Engine {
			h := hive.New(
				k8sFake.FakeClientCell(),
				daemonk8s.ResourcesCell,
				k8sTables.NamespaceTableCell,
				agent.Cell,

				Cell,
				sysctl.Cell,
				tables.NodeAddressCell,

				// Note: We use the default local node store, and setup the node obj
				// using the mock node sync type.
				node.LocalNodeStoreCell,
				endpointmanager.Cell,
				cell.Provide(func(log *slog.Logger) *ipcache.IPCache {
					return ipcache.NewIPCache(&ipcache.Configuration{
						Logger: log,
					})
				}),
				cell.Provide(func() promise.Promise[endpointstate.Restorer] {
					resolver, promise := promise.New[endpointstate.Restorer]()
					resolver.Resolve(&fakeRestorer{})
					return promise
				}),
				gneigh.Cell,
				tunnel.Cell,

				testCell,

				PolicyCell,

				enterpriseHealthConfig.Cell,
				healthconfig.Cell,
				cell.Config(metrics.RegistryConfig{}),
				cell.Config(cmtypes.DefaultClusterInfo),
				cell.Config(tunnelip.Config{}),
				cell.Provide(
					metrics.NewRegistry,
					// LocalNodeSynchronizer syncs via apiserver, after the node is initialized, generally
					// using local stored config (if available) in daemon package.
					func() (*gc.GC, ctmap.GCRunner) {
						return &gc.GC{}, ctmap.NewFakeGCRunner()
					},
					func(tipConfig tunnelip.Config) node.LocalNodeSynchronizer {
						mock := &mockNodeSync{}
						if len(tipConfig.PreferredTunnelEndpointDevices) != 0 {
							mock.ciliumTunnelIP = "10.254.0.1"
						}
						return mock
					},
					func() *option.DaemonConfig {
						return &option.DaemonConfig{
							EnterpriseDaemonConfig: option.EnterpriseDaemonConfig{
								EnableIPv4EgressGatewayHA: true,
							},
							EnableIPv4:             true,
							EnableBPFMasquerade:    true,
							EnableIPv4Masquerade:   true,
							IdentityAllocationMode: option.IdentityAllocationModeCRD,
							Debug:                  false,
						}
					},

					func() cache.IdentityAllocator {
						m := testidentity.NewMockIdentityAllocator(nil)

						_, _, err := m.AllocateIdentity(context.TODO(),
							labels.NewLabelsFromSortedList("k8s:foo=bar"),
							false,
							30000,
						)
						assert.NoError(t, err)

						_, _, err = m.AllocateIdentity(context.TODO(),
							labels.NewLabelsFromSortedList("k8s:foo=bar2"),
							false,
							30001,
						)
						assert.NoError(t, err)

						return m
					},

					tables.NewDeviceTable,
					statedb.RWTable[*tables.Device].ToTable,
					// For NodeAddressCell
					tables.NewRouteTable,
					statedb.RWTable[*tables.Route].ToTable,

					func() *signaler.BGPCPSignaler {
						return signaler.NewBGPCPSignaler()
					},

					func() loadbalancer.Config {
						return loadbalancer.DefaultConfig
					},
					func() kpr.KPRConfig { return kpr.KPRConfig{} },
				),

				cell.Invoke(func(*Manager) {}),
			)

			flags := pflag.NewFlagSet("", pflag.ContinueOnError)
			h.RegisterFlags(flags)

			// Parse the shebang arguments in the script.
			require.NoError(t, flags.Parse(args), "flags.Parse")

			// Enterprise config overrides the OSS config.
			flags.Set(healthconfig.EnableHealthCheckingName, "false")
			flags.Set(enterpriseHealthConfig.EnableHealthServerName, "true")

			t.Cleanup(func() {
				assert.NoError(t, h.Stop(log, context.TODO()))
			})
			cmds, err := h.ScriptCommands(log)
			require.NoError(t, err, "ScriptCommands")
			maps.Insert(cmds, maps.All(script.DefaultCmds()))
			return &script.Engine{
				Cmds:          cmds,
				RetryInterval: 1500 * time.Millisecond,
			}
		}, []string{}, "testdata/agent_*.txtar")
}

var testCell = cell.Group(
	testCommandsCell,
	cell.Provide(
		func() egressmapha.PolicyConfig {
			return egressmapha.DefaultPolicyConfig
		},
		egressmapha.CreatePrivatePolicyMapV2,
		egressmapha.CreatePrivateCtMap,
	),
)

type mockHealthChecker struct {
	m map[string]healthcheck.NodeHealth
}

func (m *mockHealthChecker) UpdateNodeList(nodes map[string]nodeTypes.Node, healthy, active sets.Set[string]) {
}

func (m *mockHealthChecker) NodeHealth(nodeName string) healthcheck.NodeHealth {
	if nh, ok := m.m[nodeName]; ok {
		return nh
	}
	return healthcheck.NodeHealth{Reachable: true, AgentUp: true}
}

func (m *mockHealthChecker) Events() chan healthcheck.Event {
	ch := make(chan healthcheck.Event)
	return ch
}

type mockNodeSync struct {
	ciliumTunnelIP string
}

func (m *mockNodeSync) WaitForNodeInformation(ctx context.Context, store *node.LocalNodeStore) error {
	return nil
}

func (m *mockNodeSync) InitLocalNode(ctx context.Context, n *node.LocalNode) error {
	n.Node = nodeTypes.Node{
		Name: "localnode1",
		IPAddresses: []nodeTypes.Address{
			{Type: addressing.NodeInternalIP, IP: net.ParseIP("172.18.0.3")},
		},
	}
	if m.ciliumTunnelIP != "" {
		n.IPAddresses = append(n.IPAddresses, nodeTypes.Address{
			Type: addressing.NodeCiliumTunnelIP,
			IP:   net.ParseIP(m.ciliumTunnelIP),
		})
	}
	return nil
}

func (m *mockNodeSync) SyncLocalNode(context.Context, *node.LocalNodeStore) {
}

type fakeRestorer struct{}

func (r *fakeRestorer) Await(context.Context) (endpointstate.Restorer, error) {
	return r, nil
}

func (r *fakeRestorer) WaitForEndpointRestoreWithoutRegeneration(ctx context.Context) error {
	return nil
}

func (r *fakeRestorer) WaitForEndpointRestore(_ context.Context) error {
	return nil
}

func (r *fakeRestorer) WaitForInitialPolicy(_ context.Context) error {
	return nil
}
