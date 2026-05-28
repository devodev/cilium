// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package test

import (
	"context"
	"flag"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	"github.com/cilium/statedb"
	"github.com/spf13/afero"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/daemon/cmd/legacy"
	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	bfdtypes "github.com/cilium/cilium/enterprise/pkg/bfd/types"
	enterprisebgpv1 "github.com/cilium/cilium/enterprise/pkg/bgpv1"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/manager/reconcilerv2"
	"github.com/cilium/cilium/enterprise/pkg/egressgatewayha"
	evpnConfig "github.com/cilium/cilium/enterprise/pkg/evpn/config"
	evpnSecurityGroupTables "github.com/cilium/cilium/enterprise/pkg/evpn/securitygroups/tables"
	privnetConfig "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	privnetTables "github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/enterprise/pkg/rib"
	"github.com/cilium/cilium/enterprise/pkg/srv6/sidmanager"
	"github.com/cilium/cilium/enterprise/pkg/srv6/srv6manager"
	"github.com/cilium/cilium/pkg/bgp"
	"github.com/cilium/cilium/pkg/bgp/agent"
	"github.com/cilium/cilium/pkg/bgp/agent/signaler"
	"github.com/cilium/cilium/pkg/bgp/manager"
	osstest "github.com/cilium/cilium/pkg/bgp/test"
	"github.com/cilium/cilium/pkg/bgp/test/commands"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	routeReconciler "github.com/cilium/cilium/pkg/datapath/linux/route/reconciler"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	envoyCfg "github.com/cilium/cilium/pkg/envoy/config"
	ciliumhive "github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipam"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	k8sfake "github.com/cilium/cilium/pkg/k8s/client/testutils"
	k8sTables "github.com/cilium/cilium/pkg/k8s/tables"
	k8sTestutils "github.com/cilium/cilium/pkg/k8s/testutils"
	k8sVersion "github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/lbipamconfig"
	"github.com/cilium/cilium/pkg/loadbalancer"
	lbcell "github.com/cilium/cilium/pkg/loadbalancer/cell"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/maps/srv6map"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/nodeipamconfig"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/svcrouteconfig"
	"github.com/cilium/cilium/pkg/testutils"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
)

const (
	testTimeout = 60 * time.Second

	// test resource names
	testNodeName         = "test-node"
	testSecretsNamespace = "kube-system"
	testLink1Name        = "centbgptest1"
	testLink2Name        = "centbgptest2"

	// test arguments
	testPeeringIPsFlag               = "test-peering-ips"
	ipamFlag                         = "ipam"
	probeTCPMD5Flag                  = "probe-tcp-md5"
	enableNodeMaintenanceHelpersFlag = "enable-node-maintenance-helpers"
	enableNoEndpointsRoutableFlag    = "enable-no-service-endpoints-routable"
	enableEVPNSecurityGroupTagsFlag  = "enable-evpn-security-group-tags"
	defaultEVPNSecurityGroupIDFlag   = "evpn-default-security-group-id"
	kubeProxyReplacementFlag         = "kube-proxy-replacement"
)

// Global flag for disabling OSS BGP CPlane.
var disableOSSBGPControlPlane = flag.Bool("disable-oss-bgp-control-plane", false, "Disable OSS BGP Control Plane")

func TestPrivilegedScript(t *testing.T) {
	testutils.PrivilegedTest(t)
	slog.SetLogLoggerLevel(slog.LevelInfo) // used by test GoBGP instances
	k8sVersion.Force(k8sTestutils.DefaultVersion)

	types.SetName(testNodeName)

	// set test environment variables
	envVars := []string{"PATH=" + os.Getenv("PATH")}

	// setup test links
	envVars = setupTestLinks(t, envVars)

	setup := func(t testing.TB, args []string) *script.Engine {
		var (
			err        error
			lbWriter   *writer.Writer
			egwMgrMock *egwManagerMock
		)

		// parse the shebang arguments in the script
		flags := pflag.NewFlagSet("test-flags", pflag.ContinueOnError)
		peeringIPs := flags.StringSlice(testPeeringIPsFlag, nil, "List of IPs used for peering in the test")
		useIPAM := flags.String(ipamFlag, ipamOption.IPAMKubernetes, "IPAM used by the test")
		probeTCPMD5 := flags.Bool(probeTCPMD5Flag, false, "Probe if TCP_MD5SIG socket option is available")
		enableNodeMaintenanceHelpers := flags.Bool(enableNodeMaintenanceHelpersFlag, false, "Enable node maintenance helpers")
		enableNoEndpointsRoutable := flags.Bool(enableNoEndpointsRoutableFlag, true, "")
		enableEVPNSecurityGroupTags := flags.Bool(enableEVPNSecurityGroupTagsFlag, false, "Enable Security Group Tags in EVPN advertisements")
		defaultEVPNSecurityGroupID := flags.Uint16(defaultEVPNSecurityGroupIDFlag, 0, "Default Security Group ID used in EVPN advertisements")
		kubeProxyReplacement := flags.Bool(kubeProxyReplacementFlag, true, "Enable kube-proxy replacement")
		require.NoError(t, flags.Parse(args), "Error parsing test flags")

		if *probeTCPMD5 {
			available, err := osstest.TCPMD5SigAvailable()
			require.NoError(t, err)
			if !available {
				t.Skip("TCP_MD5SIG socket option is not available")
			}
		}

		h := ciliumhive.New(
			k8sfake.FakeClientCell(),
			daemonk8s.ResourcesCell,
			k8sTables.TablesCell,
			cell.Config(envoyCfg.SecretSyncConfig{}),
			metrics.Cell,
			lbcell.Cell,
			maglev.Cell,
			cell.Provide(source.NewSources),
			cell.Config(loadbalancer.TestConfig{}),
			cell.Provide(
				func(cfg loadbalancer.TestConfig) *loadbalancer.TestConfig { return &cfg }, // newLBMaps expects *TestConfig
			),
			cell.Config(cmtypes.DefaultClusterInfo),
			svcrouteconfig.Cell,

			lbipamconfig.Cell,
			nodeipamconfig.Cell,

			// OSS BGP cell
			bgp.Cell,

			// Enterprise cells
			enterprisebgpv1.Cell,
			sidmanager.SIDManagerCell,
			srv6manager.Cell,
			srv6map.Cell,
			rib.Cell,
			rib.NopDataPlaneCell,
			evpnConfig.Cell,
			privnetConfig.Cell,

			// Route Reconciler cell
			routeReconciler.Cell,

			// Enterprise BGP dependencies
			cell.Provide(
				tables.NewDeviceTable,
				tables.NewNeighborTable,
				tables.NewRouteTable,
				tables.NewNodeAddressTable,
				bfdtypes.NewBFDPeersTable,
				privnetTables.NewPrivateNetworksTable,
				privnetTables.NewLocalWorkloadsTable,
				evpnSecurityGroupTables.NewEndpointSecurityGroupTable,

				statedb.RWTable[*tables.Route].ToTable,
				statedb.RWTable[*tables.Device].ToTable,
				statedb.RWTable[*tables.Neighbor].ToTable,
				statedb.RWTable[tables.NodeAddress].ToTable,
				statedb.RWTable[*bfdtypes.BFDPeerStatus].ToTable,
				statedb.RWTable[privnetTables.PrivateNetwork].ToTable,
				statedb.RWTable[*privnetTables.LocalWorkload].ToTable,
				statedb.RWTable[evpnSecurityGroupTables.EndpointSecurityGroup].ToTable,
			),
			cell.Provide(func(sig *signaler.BGPCPSignaler) egressgatewayha.EgressIPsProvider {
				egwMgrMock = newEGWManagerMock(sig)
				return egwMgrMock
			}),

			// SRv6 dependencies
			cell.Provide(
				func() cache.IdentityAllocator {
					return testidentity.NewMockIdentityAllocator(nil)
				},
				func() legacy.DaemonInitialization {
					return legacy.DaemonInitialization{}
				},
				func() *ipam.IPAM {
					return &ipam.IPAM{}
				},
			),

			// OSS + CEE BGP DaemonConfig
			cell.Provide(func() *option.DaemonConfig {
				// BGP Manager uses the global variable option.Config so we need to set it there as well
				option.Config = &option.DaemonConfig{
					EnableBGPControlPlane:     !*disableOSSBGPControlPlane,
					BGPSecretsNamespace:       testSecretsNamespace,
					BGPRouterIDAllocationMode: option.BGPRouterIDAllocationModeDefault,
					IPAM:                      *useIPAM,
					EnableIPv4:                true,
					EnableIPv6:                true,
					EnterpriseDaemonConfig: option.EnterpriseDaemonConfig{
						EnableEnterpriseBGPControlPlane: true,
						EnableBFD:                       true,
						EnableIPv4EgressGatewayHA:       true,
					},
					StateDir: t.TempDir(),
				}
				return option.Config
			},
				func() kpr.KPRConfig {
					return kpr.KPRConfig{
						KubeProxyReplacement: *kubeProxyReplacement,
					}
				},
			),

			cell.Provide(
				tunnel.NewTestConfig,
				func() tunnel.EncapProtocol {
					return tunnel.VXLAN
				},
			),

			// Enterprise BFD config
			cell.Config(bfdtypes.BFDConfig{
				BFDEnabled: true,
			}),

			node.LocalNodeStoreTestCell,
			cell.Invoke(func() {
				types.SetName(testNodeName)
			}),
			cell.Provide(
				func() *egwManagerMock {
					return egwMgrMock
				},
				BGPTestScriptCmds,
			),
			cell.Invoke(func(m agent.BGPRouterManager) {
				m.(*manager.BGPRouterManager).DestroyRouterOnStop(true) // fully destroy GoBGP server on Stop()
			}),
			cell.Invoke(func(w *writer.Writer) {
				lbWriter = w
			}),
		)
		hive.AddConfigOverride(h, func(cfg *reconcilerv2.Config) {
			cfg.SvcHealthCheckingEnabled = true
			cfg.RouteImportEnabled = true
			if *enableNodeMaintenanceHelpers {
				cfg.MaintenanceGracefulShutdownEnabled = true
				cfg.MaintenanceWithdrawTime = 1 * time.Second
			}
		})
		hive.AddConfigOverride(h, func(cfg *config.Config) {
			// Disable enterprise BGP Control Plane when we are
			// testing OSS scripts.
			if strings.HasPrefix(t.Name(), "TestPrivilegedScript/ent-") {
				cfg.Enabled = true
			}
		})
		hive.AddConfigOverride(h, func(cfg *svcrouteconfig.RoutesConfig) {
			cfg.EnableNoServiceEndpointsRoutable = *enableNoEndpointsRoutable
		})
		hive.AddConfigOverride(h, func(cfg *evpnConfig.Config) {
			cfg.Enabled = true
			cfg.SecurityGroupTagsEnabled = *enableEVPNSecurityGroupTags
			cfg.DefaultSecurityGroupID = *defaultEVPNSecurityGroupID
		})
		hive.AddConfigOverride(h, func(cfg *privnetConfig.Flags) {
			cfg.Enabled = true
		})

		hiveLog := hivetest.Logger(t, hivetest.LogLevel(slog.LevelInfo))
		t.Cleanup(func() {
			assert.NoError(t, h.Stop(hiveLog, context.TODO()))
		})

		// setup test peering IPs
		setupTestPeeringIPs(t, *peeringIPs)

		// set up GoBGP command
		gobgpCmdCtx := commands.NewGoBGPCmdContext()
		t.Cleanup(gobgpCmdCtx.Cleanup)

		cmds, err := h.ScriptCommands(hiveLog)
		require.NoError(t, err, "ScriptCommands")
		maps.Insert(cmds, maps.All(script.DefaultCmds()))
		maps.Insert(cmds, maps.All(commands.GoBGPScriptCmds(gobgpCmdCtx)))
		maps.Insert(cmds, maps.All(CEEGoBGPScriptCmds(gobgpCmdCtx)))
		maps.Insert(cmds, maps.All(commands.SvcScriptCmds(lbWriter)))

		return &script.Engine{
			Cmds: cmds,
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	t.Cleanup(cancel)

	scripttest.Test(t,
		ctx,
		setup,
		envVars,
		"testdata/*.txtar")
}

func setupTestLinks(t *testing.T, envVars []string) []string {
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name:         testLink1Name,
			HardwareAddr: net.HardwareAddr{0xaa, 0x00, 0x00, 0x00, 0x00, 0x01},
		},
		PeerName:         testLink2Name,
		PeerHardwareAddr: net.HardwareAddr{0xaa, 0x00, 0x00, 0x00, 0x00, 0x02},
	}
	netlink.LinkDel(veth) // cleanup from potential interrupted test run
	err := netlink.LinkAdd(veth)
	require.NoError(t, err, "error by adding veth %s", testLink1Name)
	t.Cleanup(func() {
		// cleanup after test finishes
		netlink.LinkDel(veth)
	})

	veth1, err := safenetlink.LinkByName(testLink1Name)
	require.NoError(t, err)
	veth2, err := safenetlink.LinkByName(testLink2Name)
	require.NoError(t, err)

	// Assign IPv6 link-local addresses with EUI64 with fixed MAC address.
	// This makes the link-local addresses predictable and makes things a
	// lot easier.
	ctl := sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc")
	err = ctl.WriteInt([]string{"net", "ipv6", "conf", testLink1Name, "addr_gen_mode"}, 0)
	require.NoError(t, err)
	err = ctl.WriteInt([]string{"net", "ipv6", "conf", testLink2Name, "addr_gen_mode"}, 0)
	require.NoError(t, err)

	err = netlink.LinkSetUp(veth1)
	require.NoError(t, err)
	err = netlink.LinkSetUp(veth2)
	require.NoError(t, err)

	return envVars
}

func setupTestPeeringIPs(t testing.TB, peeringIPs []string) {
	l, err := safenetlink.LinkByName(testLink1Name)
	require.NoError(t, err)
	for _, ip := range peeringIPs {
		ipAddr, err := netip.ParseAddr(ip)
		require.NoError(t, err)
		bits := 32
		if ipAddr.Is6() {
			bits = 128
		}
		prefix := netip.PrefixFrom(ipAddr, bits)
		err = netlink.AddrAdd(l, createNetlinkAddr(prefix))
		if err != nil && os.IsExist(err) {
			t.Fatalf("Peering address %s is probably already used by another test", ip)
		}
		require.NoError(t, err)
	}
}

// createNetlinkAddr creates new netlink.Addr for the provided prefix
func createNetlinkAddr(prefix netip.Prefix) *netlink.Addr {
	pLen := 128
	if prefix.Addr().Is4() {
		pLen = 32
	}
	addr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   prefix.Addr().AsSlice(),
			Mask: net.CIDRMask(prefix.Bits(), pLen),
		},
	}
	if prefix.Addr().Is6() {
		addr.Flags = unix.IFA_F_NODAD // disable duplicate address detection so that we can use the address immediately
	}
	return addr
}
