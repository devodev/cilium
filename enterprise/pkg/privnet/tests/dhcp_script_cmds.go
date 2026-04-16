//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"

	uhive "github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/script"
	"github.com/cilium/statedb"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/mdlayher/socket"
	"github.com/spf13/pflag"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/enterprise/pkg/privnet/dhcp"
	"github.com/cilium/cilium/enterprise/pkg/privnet/grpc/client"
	grpcclient "github.com/cilium/cilium/enterprise/pkg/privnet/grpc/client"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	dptables "github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/time"
)

type dhcpTestConfig struct {
	StaticRelay bool `mapstructure:"privnet-test-dhcp-static-relay"`
}

func (def dhcpTestConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("privnet-test-dhcp-static-relay", def.StaticRelay, "Use a static DHCP relay in privnet script tests")
}

func dhcpScriptCmdsCell(t testing.TB) cell.Cell {
	return cell.Group(
		cell.Config(dhcpTestConfig{StaticRelay: true}),

		cell.Provide(
			func() (*dhcp.TestConfig, *netns.NetNS) {
				cfg := &dhcp.TestConfig{
					LeaseSweepInterval: 50 * time.Millisecond,
				}

				if testutils.IsPrivileged() {
					// Create a new network namespace for the privileged test cases.
					ns, err := netns.New()
					if err != nil {
						t.Fatalf("failed to create netns: %v", err)
					}
					t.Cleanup(func() {
						_ = ns.Close()
					})
					cfg.NetNS = ns
					return cfg, ns
				}
				return cfg, nil
			},
		),

		cell.DecorateAll(func(cfg dhcpTestConfig, relay dhcp.RelayFactory, connFactory grpcclient.ConnFactoryFn) dhcp.RelayFactory {
			if cfg.StaticRelay {
				return &dhcp.StaticRelayFactory{Relay: &dhcp.StaticRelay{
					ServerIP:   net.IPv4(192, 168, 100, 1),
					LeaseIP:    net.IPv4(192, 168, 100, 10),
					Lease:      5 * time.Minute,
					Renew:      2 * time.Minute,
					SubnetMask: net.IPv4(255, 255, 255, 255),
				}}
			}

			if grpcRelay, ok := relay.(*dhcp.GRPCRelayFactory); ok && grpcRelay.Factory == nil {
				grpcRelay.Factory = client.ConnFactoryFn(connFactory)
			}

			return relay
		}),
		cell.Provide(func(in struct {
			cell.In
			Log     *slog.Logger
			TestCfg *dhcp.TestConfig `optional:"true"`
		}) *dhcpScriptState {
			return newDHCPScriptState(in.Log, in.TestCfg)
		}),
		cell.Provide(func(state *dhcpScriptState, db *statedb.DB, workloads statedb.Table[*tables.LocalWorkload], leases statedb.Table[tables.DHCPLease], devices statedb.RWTable[*dptables.Device]) uhive.ScriptCmdsOut {
			state.attach(db, workloads, leases, devices)
			return uhive.NewScriptCmds(state.cmds())
		}),
		cell.Invoke(func(lc cell.Lifecycle, state *dhcpScriptState) {
			lc.Append(cell.Hook{
				OnStop: func(cell.HookContext) error {
					state.Close()
					return nil
				},
			})
		}),
	)
}

type dhcpScriptState struct {
	mu         lock.Mutex
	log        *slog.Logger
	links      []string
	servers    map[string]io.Closer
	transports map[string]*dhcpScriptTransport
	netnses    map[string]*netns.NetNS
	db         *statedb.DB
	work       statedb.RWTable[*tables.LocalWorkload]
	leases     statedb.Table[tables.DHCPLease]
	devices    statedb.RWTable[*dptables.Device]

	hostNetns *netns.NetNS
}

type dhcpScriptTransport struct {
	conn *socket.Conn
	sll  *unix.SockaddrLinklayer
}

func sourceMACForIfindex(ifindex int) net.HardwareAddr {
	return net.HardwareAddr{
		0x00,
		0x00,
		byte(ifindex >> 24),
		byte(ifindex >> 16),
		byte(ifindex >> 8),
		byte(ifindex),
	}
}

func newDHCPScriptState(log *slog.Logger, testCfg *dhcp.TestConfig) *dhcpScriptState {
	var hostNetns *netns.NetNS
	if testCfg != nil {
		hostNetns = testCfg.NetNS
	}
	return &dhcpScriptState{
		log:        log,
		servers:    make(map[string]io.Closer),
		transports: make(map[string]*dhcpScriptTransport),
		netnses:    make(map[string]*netns.NetNS),
		hostNetns:  hostNetns,
	}
}

func (s *dhcpScriptState) attach(db *statedb.DB, workloads statedb.Table[*tables.LocalWorkload], leases statedb.Table[tables.DHCPLease], devices statedb.RWTable[*dptables.Device]) {
	s.db = db
	s.work = workloads.(statedb.RWTable[*tables.LocalWorkload])
	s.leases = leases
	s.devices = devices
}

func (s *dhcpScriptState) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, srv := range s.servers {
		_ = srv.Close()
	}
	for _, transport := range s.transports {
		_ = transport.conn.Close()
	}
	for _, ns := range s.netnses {
		_ = ns.Close()
	}
	_ = s.withHostNetNS(func() error {
		for _, linkName := range s.links {
			link, err := safenetlink.LinkByName(linkName)
			if err == nil {
				_ = netlink.LinkDel(link)
			}
		}
		return nil
	})
	s.links = nil
	s.servers = map[string]io.Closer{}
	s.transports = map[string]*dhcpScriptTransport{}
	s.netnses = map[string]*netns.NetNS{}
	s.hostNetns = nil
}

func (s *dhcpScriptState) cmds() map[string]script.Cmd {
	return map[string]script.Cmd{
		"dhcp/veth-new":             s.cmdVethNew(),
		"dhcp/link-new":             s.cmdLinkNew(),
		"dhcp/server-start":         s.cmdDHCPServerStart(),
		"dhcp/set-endpoint-ifindex": s.cmdSetEndpointIfindex(),
		"dhcp/exchange":             s.cmdDHCPExchange(),
	}
}

func (s *dhcpScriptState) cmdVethNew() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "create a veth pair between the host and a netns",
			Args:    "host-iface netns-iface host-cidr netns-cidr",
		},
		func(_ *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 4 {
				return nil, fmt.Errorf("%w: expected host-iface, netns-iface, host-cidr, netns-cidr", script.ErrUsage)
			}
			nsName := strings.TrimSpace(args[0])
			if nsName == "" {
				return nil, fmt.Errorf("%w: invalid host-iface", script.ErrUsage)
			}
			peerNS, err := netns.New()
			if err != nil {
				return nil, err
			}
			s.mu.Lock()
			if existing := s.netnses[nsName]; existing != nil {
				s.mu.Unlock()
				_ = peerNS.Close()
				return nil, fmt.Errorf("network namespace %q already exists", nsName)
			}
			s.netnses[nsName] = peerNS
			s.mu.Unlock()

			hostAddr, err := netlink.ParseAddr(args[2])
			if err != nil {
				_ = peerNS.Close()
				return nil, fmt.Errorf("%w: invalid host cidr", script.ErrUsage)
			}
			nsAddr, err := netlink.ParseAddr(args[3])
			if err != nil {
				_ = peerNS.Close()
				return nil, fmt.Errorf("%w: invalid netns cidr", script.ErrUsage)
			}

			if err := s.withHostNetNS(func() error {
				veth := &netlink.Veth{
					LinkAttrs: netlink.LinkAttrs{
						Name: args[0],
					},
					PeerName: args[1],
				}
				if err := netlink.LinkAdd(veth); err != nil {
					return err
				}

				link, err := safenetlink.LinkByName(args[0])
				if err != nil {
					_ = netlink.LinkDel(veth)
					return err
				}
				if err := netlink.LinkSetHardwareAddr(link, macForName(args[0])); err != nil {
					_ = netlink.LinkDel(veth)
					return err
				}
				if err := netlink.AddrAdd(link, hostAddr); err != nil {
					_ = netlink.LinkDel(veth)
					return err
				}
				if err := netlink.LinkSetUp(link); err != nil {
					_ = netlink.LinkDel(veth)
					return err
				}

				peer, err := safenetlink.LinkByName(args[1])
				if err != nil {
					_ = netlink.LinkDel(link)
					return err
				}
				if err := netlink.LinkSetHardwareAddr(peer, macForName(args[1])); err != nil {
					_ = netlink.LinkDel(link)
					return err
				}
				if err := netlink.LinkSetNsFd(peer, peerNS.FD()); err != nil {
					_ = netlink.LinkDel(link)
					return err
				}

				if err := peerNS.Do(func() error {
					link, err := safenetlink.LinkByName(args[1])
					if err != nil {
						return err
					}
					if err := netlink.AddrAdd(link, nsAddr); err != nil {
						return err
					}
					return netlink.LinkSetUp(link)
				}); err != nil {
					_ = netlink.LinkDel(link)
					return err
				}

				return nil
			}); err != nil {
				s.mu.Lock()
				delete(s.netnses, nsName)
				s.mu.Unlock()
				_ = peerNS.Close()
				return nil, err
			}

			s.mu.Lock()
			s.links = append(s.links, args[0])
			s.mu.Unlock()

			return nil, nil
		},
	)
}

func (s *dhcpScriptState) cmdLinkNew() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "create a veth-backed DHCP test interface in the host netns",
			Args:    "name",
		},
		func(_ *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 1 {
				return nil, fmt.Errorf("%w: expected name", script.ErrUsage)
			}
			var transport *dhcpScriptTransport
			if err := s.withHostNetNS(func() error {
				peerName := peerNameFor(args[0])
				veth := &netlink.Veth{
					LinkAttrs: netlink.LinkAttrs{Name: args[0]},
					PeerName:  peerName,
				}
				if err := netlink.LinkAdd(veth); err != nil {
					return err
				}

				link, err := safenetlink.LinkByName(args[0])
				if err != nil {
					_ = netlink.LinkDel(veth)
					return err
				}
				peer, err := safenetlink.LinkByName(peerName)
				if err != nil {
					_ = netlink.LinkDel(link)
					return err
				}
				if err := netlink.LinkSetHardwareAddr(link, macForName(args[0])); err != nil {
					_ = netlink.LinkDel(link)
					return err
				}
				if err := netlink.LinkSetHardwareAddr(peer, macForName(peerName)); err != nil {
					_ = netlink.LinkDel(link)
					return err
				}
				if err := netlink.LinkSetUp(link); err != nil {
					_ = netlink.LinkDel(link)
					return err
				}
				if err := netlink.LinkSetUp(peer); err != nil {
					_ = netlink.LinkDel(link)
					return err
				}

				transportConn, err := openPacketSocket(peer.Attrs().Index)
				if err != nil {
					_ = netlink.LinkDel(link)
					return err
				}
				sendSLL := &unix.SockaddrLinklayer{
					Ifindex:  peer.Attrs().Index,
					Protocol: htons(unix.ETH_P_IP),
					Halen:    6,
				}
				copy(sendSLL.Addr[:], net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
				transport = &dhcpScriptTransport{
					conn: transportConn,
					sll:  sendSLL,
				}
				s.mu.Lock()
				s.transports[args[0]] = transport
				s.mu.Unlock()
				return nil
			}); err != nil {
				if transport != nil {
					_ = transport.conn.Close()
				}
				return nil, err
			}

			s.mu.Lock()
			s.links = append(s.links, args[0])
			s.mu.Unlock()

			return nil, nil
		},
	)
}

func (s *dhcpScriptState) cmdDHCPServerStart() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "start a DHCP server in a selected netns",
			Args:    "netns-name iface server-ip lease-ip",
		},
		func(_ *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 4 {
				return nil, fmt.Errorf("%w: expected netns-name, iface, server-ip, lease-ip", script.ErrUsage)
			}

			var targetNS *netns.NetNS
			switch strings.ToLower(strings.TrimSpace(args[0])) {
			case "host":
				targetNS = s.hostNetns
			case "root", "current":
				targetNS = nil
			default:
				s.mu.Lock()
				targetNS = s.netnses[args[0]]
				s.mu.Unlock()
				if targetNS == nil {
					return nil, fmt.Errorf("%w: invalid netns-name %q", script.ErrUsage, args[0])
				}
			}

			s.mu.Lock()
			if _, exists := s.servers[args[0]]; exists {
				s.mu.Unlock()
				return nil, fmt.Errorf("dhcp server already started for netns %q", args[0])
			}
			s.mu.Unlock()
			ifaceName := args[1]
			serverIP := net.ParseIP(args[2]).To4()
			if serverIP == nil {
				return nil, fmt.Errorf("%w: invalid server ip", script.ErrUsage)
			}
			leaseIP := net.ParseIP(args[3]).To4()
			if leaseIP == nil {
				return nil, fmt.Errorf("%w: invalid lease ip", script.ErrUsage)
			}

			if strings.Contains(ifaceName, "ucast") {
				var conn *net.UDPConn
				if err := s.runInNetNS(targetNS, func() error {
					c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: serverIP, Port: dhcpv4.ServerPort})
					if err != nil {
						return err
					}
					conn = c
					return nil
				}); err != nil {
					return nil, err
				}
				go func() {
					buf := make([]byte, 2048)
					for {
						n, addr, err := conn.ReadFromUDP(buf)
						if err != nil {
							return
						}
						msg, err := dhcpv4.FromBytes(buf[:n])
						if err != nil {
							continue
						}
						resp, err := dhcpv4.NewReplyFromRequest(msg)
						if err != nil {
							continue
						}
						resp.YourIPAddr = leaseIP
						resp.UpdateOption(dhcpv4.OptServerIdentifier(serverIP))
						switch msg.MessageType() {
						case dhcpv4.MessageTypeDiscover:
							resp.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeOffer))
						case dhcpv4.MessageTypeRequest:
							resp.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeAck))
						default:
							resp.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeAck))
						}
						_, _ = conn.WriteToUDP(resp.ToBytes(), addr)
					}
				}()

				s.mu.Lock()
				s.servers[args[0]] = conn
				s.mu.Unlock()

				return nil, nil
			}

			relay := &dhcp.StaticRelay{
				ServerIP:   serverIP,
				LeaseIP:    leaseIP,
				Lease:      5 * time.Minute,
				Renew:      2 * time.Minute,
				SubnetMask: net.IPv4(255, 255, 255, 255),
			}
			ifindex := 0
			if err := s.runInNetNS(targetNS, func() error {
				link, err := safenetlink.LinkByName(ifaceName)
				if err != nil {
					return err
				}
				attrs := link.Attrs()
				if attrs == nil || attrs.Index == 0 {
					return fmt.Errorf("invalid interface %q", ifaceName)
				}
				ifindex = attrs.Index
				return nil
			}); err != nil {
				return nil, err
			}
			var sourceIfindex int
			if err := s.withHostNetNS(func() error {
				link, err := safenetlink.LinkByName(args[0])
				if err != nil {
					return err
				}
				attrs := link.Attrs()
				if attrs == nil || attrs.Index == 0 {
					return fmt.Errorf("invalid interface %q", args[0])
				}
				sourceIfindex = attrs.Index
				return nil
			}); err != nil {
				return nil, err
			}
			handler := func(_ context.Context, _ cell.Health, _ uint16, req *dhcpv4.DHCPv4) (int, []*dhcpv4.DHCPv4, error) {
				if req == nil {
					return 0, nil, nil
				}
				resps, err := relay.Relay(context.Background(), 250*time.Millisecond, req)
				if err == nil {
					for _, resp := range resps {
						if resp == nil {
							continue
						}
						// Simulate the redirection to cilium_dhcp done by the bpf_host program. This is the actual
						// path for the response to the broadcast relay.
						if mirrorErr := s.injectResponseToCiliumDHCP(sourceIfindex, serverIP, resp); mirrorErr != nil {
							return 0, nil, mirrorErr
						}
					}
				}
				return ifindex, resps, err
			}
			srv, err := dhcp.NewServer(s.log, dhcp.DefaultConfig, targetNS, ifaceName, handler, nil)
			if err != nil {
				return nil, err
			}
			go func() {
				_ = srv.Serve(context.Background(), nil)
			}()

			s.mu.Lock()
			s.servers[args[0]] = srv
			s.mu.Unlock()

			return nil, nil
		},
	)
}

func (s *dhcpScriptState) injectResponseToCiliumDHCP(ifindex int, serverIP net.IP, resp *dhcpv4.DHCPv4) error {
	if resp == nil {
		return nil
	}

	s.mu.Lock()
	transport := s.transports["cilium_dhcp"]
	s.mu.Unlock()
	if transport == nil {
		return nil
	}

	frame, err := dhcp.BuildServerDHCPFrameForTest(
		resp.ToBytes(),
		sourceMACForIfindex(ifindex),
		net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		serverIP,
		net.IPv4bcast,
		dhcpv4.ServerPort,
		dhcpv4.ClientPort,
	)
	if err != nil {
		return err
	}

	return transport.conn.Sendto(context.Background(), frame, 0, transport.sll)
}

func (s *dhcpScriptState) cmdSetEndpointIfindex() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "set endpoint.json interface-index from interface name",
			Args:    "iface ep-req-json-file",
		},
		func(ss *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 2 {
				return nil, fmt.Errorf("%w: expected iface, ep-req-json-file", script.ErrUsage)
			}

			iface := strings.TrimSpace(args[0])
			if iface == "" {
				return nil, fmt.Errorf("%w: invalid iface", script.ErrUsage)
			}

			var ifindex int
			if err := s.withHostNetNS(func() error {
				link, err := safenetlink.LinkByName(iface)
				if err != nil {
					return err
				}
				attrs := link.Attrs()
				if attrs == nil || attrs.Index == 0 {
					return fmt.Errorf("invalid interface %q", iface)
				}
				ifindex = attrs.Index
				return nil
			}); err != nil {
				return nil, err
			}

			epr, err := parseEndpointJSON(ss, []string{args[1]})
			if err != nil {
				return nil, err
			}

			epr.InterfaceIndex = int64(ifindex)
			b, err := json.MarshalIndent(epr, "", "  ")
			if err != nil {
				return nil, err
			}
			if err := os.WriteFile(ss.Path(args[1]), append(b, '\n'), 0o644); err != nil {
				return nil, err
			}

			return nil, nil
		},
	)
}

func (s *dhcpScriptState) cmdDHCPExchange() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "perform a DHCP exchange in a netns",
			Args:    "endpoint-id",
		},
		func(ss *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 1 {
				return nil, fmt.Errorf("%w: expected endpoint-id", script.ErrUsage)
			}
			endpointID, err := strconv.ParseUint(args[0], 10, 16)
			if err != nil {
				return nil, err
			}
			txn := s.db.ReadTxn()
			lw, _, found := s.work.Get(txn, tables.LocalWorkloadsByID(uint16(endpointID)))
			if !found || lw == nil {
				return nil, fmt.Errorf("missing local workload for endpoint %d", endpointID)
			}
			hw, err := net.ParseMAC(lw.Interface.MAC)
			if err != nil {
				return nil, err
			}
			if len(hw) == 0 {
				return nil, fmt.Errorf("workload has no MAC address")
			}

			return nil, func() error {
				return s.withHostNetNS(func() error {
					s.mu.Lock()
					transport := s.transports["cilium_dhcp"]
					s.mu.Unlock()
					if transport == nil {
						return fmt.Errorf("dhcp transport cilium_dhcp not initialized")
					}

					req, err := dhcpv4.NewDiscovery(hw)
					if err != nil {
						return err
					}
					req.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeDiscover))

					srcMAC := net.HardwareAddr{0x00, 0x00, 0x00, 0x00, byte(endpointID >> 8), byte(endpointID)}
					dstMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
					frame, err := buildClientDHCPFrame(srcMAC, dstMAC, req.ToBytes())
					if err != nil {
						return err
					}
					if err := transport.conn.Sendto(context.Background(), frame, 0, transport.sll); err != nil {
						return err
					}

					offer, err := readDHCPFromTransport(transport, req.TransactionID, hw, time.Second)
					if err != nil {
						return err
					}
					if offer.MessageType() != dhcpv4.MessageTypeOffer {
						return fmt.Errorf("unexpected DHCP message type %s", offer.MessageType())
					}

					request, err := dhcpv4.NewRequestFromOffer(offer)
					if err != nil {
						return err
					}
					request.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeRequest))
					frame, err = buildClientDHCPFrame(srcMAC, dstMAC, request.ToBytes())
					if err != nil {
						return err
					}
					if err := transport.conn.Sendto(context.Background(), frame, 0, transport.sll); err != nil {
						return err
					}

					ack, err := readDHCPFromTransport(transport, request.TransactionID, hw, time.Second)
					if err != nil {
						return err
					}
					if ack.MessageType() != dhcpv4.MessageTypeAck {
						return fmt.Errorf("unexpected DHCP message type %s", ack.MessageType())
					}
					return nil
				})
			}()
		},
	)
}

func buildClientDHCPFrame(srcMAC net.HardwareAddr, dstMAC net.HardwareAddr, payload []byte) ([]byte, error) {
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.IPv4zero,
		DstIP:    net.IPv4bcast,
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(dhcpv4.ClientPort),
		DstPort: layers.UDPPort(dhcpv4.ServerPort),
	}
	if err := udp.SetNetworkLayerForChecksum(ip4); err != nil {
		return nil, err
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip4, udp, gopacket.Payload(payload)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func readDHCPFromTransport(transport *dhcpScriptTransport, xid dhcpv4.TransactionID, dstMAC net.HardwareAddr, timeout time.Duration) (*dhcpv4.DHCPv4, error) {
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 2048)
	for time.Now().Before(deadline) {
		if err := transport.conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
			return nil, err
		}
		n, _, err := transport.conn.Recvfrom(context.Background(), buf, 0)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return nil, err
		}
		packet := gopacket.NewPacket(buf[:n], layers.LayerTypeEthernet, gopacket.NoCopy)
		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if ethLayer == nil || ipLayer == nil || udpLayer == nil {
			continue
		}
		eth := ethLayer.(*layers.Ethernet)
		udp := udpLayer.(*layers.UDP)
		if udp.DstPort != dhcpv4.ClientPort {
			continue
		}
		if len(dstMAC) != 0 && !bytes.Equal(eth.DstMAC, dstMAC) {
			continue
		}
		msg, err := dhcpv4.FromBytes(udp.Payload)
		if err != nil {
			continue
		}
		if msg.TransactionID != xid {
			continue
		}
		return msg, nil
	}
	return nil, fmt.Errorf("timed out waiting for DHCP response")
}

func openPacketSocket(ifindex int) (*socket.Conn, error) {
	conn, err := socket.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_IP)), "privnet-dhcp-test", nil)
	if err != nil {
		return nil, err
	}
	if err := conn.Bind(&unix.SockaddrLinklayer{
		Ifindex:  ifindex,
		Protocol: htons(unix.ETH_P_IP),
	}); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func macForName(name string) net.HardwareAddr {
	h := fnv.New32a()
	_, _ = h.Write([]byte(name))
	sum := h.Sum32()
	return net.HardwareAddr{
		0x02, // locally administered unicast
		byte(sum >> 16),
		byte(sum >> 8),
		byte(sum),
		byte(sum >> 24),
		0x01,
	}
}

func peerNameFor(name string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(name))
	return fmt.Sprintf("dhcp%x", h.Sum32())
}

func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}

func (s *dhcpScriptState) withHostNetNS(fn func() error) error {
	if s.hostNetns == nil {
		return fn()
	}
	return s.hostNetns.Do(fn)
}

func (s *dhcpScriptState) runInNetNS(ns *netns.NetNS, fn func() error) error {
	if ns == nil {
		return fn()
	}
	return ns.Do(fn)
}
