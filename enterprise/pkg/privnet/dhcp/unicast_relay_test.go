// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package dhcp

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestUnicastRelayPrepareAppliesOption82(t *testing.T) {
	req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	require.NoError(t, err)
	req.UpdateOption(dhcpv4.OptRelayAgentInfo(
		dhcpv4.OptGeneric(dhcpv4.AgentCircuitIDSubOption, []byte("old-circuit")),
	))

	relay := &unicastRelay{
		option82: &v1alpha1.PrivateNetworkDHCPOption82Spec{
			CircuitID: "circuit-1",
			RemoteID:  "remote-1",
		},
	}
	out, err := relay.prepare(req, net.IPv4(192, 0, 2, 1))
	require.NoError(t, err)

	relayInfo := out.RelayAgentInfo()
	require.NotNil(t, relayInfo)
	require.Equal(t, []byte("circuit-1"), relayInfo.Options.Get(dhcpv4.AgentCircuitIDSubOption))
	require.Equal(t, []byte("remote-1"), relayInfo.Options.Get(dhcpv4.AgentRemoteIDSubOption))
	require.Equal(t, net.IPv4(192, 0, 2, 1).To4(), out.GatewayIPAddr.To4())
	require.Equal(t, uint8(1), out.HopCount)

	origRelayInfo := req.RelayAgentInfo()
	require.NotNil(t, origRelayInfo)
	require.Equal(t, []byte("old-circuit"), origRelayInfo.Options.Get(dhcpv4.AgentCircuitIDSubOption))
	require.Nil(t, origRelayInfo.Options.Get(dhcpv4.AgentRemoteIDSubOption))
}

func TestUnicastRelayPrepareSkipsEmptyOption82(t *testing.T) {
	req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	require.NoError(t, err)

	relay := &unicastRelay{
		option82: &v1alpha1.PrivateNetworkDHCPOption82Spec{},
	}
	out, err := relay.prepare(req, nil)
	require.NoError(t, err)
	require.Nil(t, out.RelayAgentInfo())
}

func TestPrivilegedUnicastRelaySendUnicastSetsGIAddrAndHop(t *testing.T) {
	testutils.PrivilegedTest(t)
	log := hivetest.Logger(t)

	relayNS, err := netns.New()
	require.NoError(t, err)
	defer relayNS.Close()

	serverNS, err := netns.New()
	require.NoError(t, err)
	defer serverNS.Close()

	relayIP := net.IPv4(192, 0, 2, 10)
	serverIP := net.IPv4(192, 0, 2, 20)

	setupUnicastRelayNamespaces(t, relayNS, serverNS, relayIP, serverIP)
	recvCh, stopServer := runSimpleDHCPServer(serverNS, serverIP, net.IPv4(192, 0, 2, 100))
	defer stopServer()

	relayFactory := &unicastRelayFactory{
		serverAddr: &net.UDPAddr{IP: serverIP, Port: dhcpv4.ServerPort},
		netns:      relayNS,
		log:        log,
	}
	relay, err := relayFactory.RelayFor(nil)
	require.NoError(t, err)
	require.NotNil(t, relay)
	req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	require.NoError(t, err)
	require.Equal(t, uint8(0), req.HopCount)

	require.Eventually(
		t,
		func() bool {
			_, err = relay.Relay(t.Context(), 50*time.Millisecond, req)
			if err != nil {
				t.Logf("Relay(): %s", err)
				return false
			}
			select {
			case info := <-recvCh:
				require.NotNil(t, info.msg)
				require.NotNil(t, info.addr)
				require.Equal(t, info.addr.IP.To4(), info.msg.GatewayIPAddr.To4())
				require.Equal(t, uint8(1), info.msg.HopCount)
				require.Equal(t, req.TransactionID, info.msg.TransactionID)
			case <-time.After(100 * time.Millisecond):
				return false
			}
			return true
		},
		2*time.Second,
		50*time.Millisecond,
	)
}

func TestPrivilegedUnicastRelaySendUnicastMaxHop(t *testing.T) {
	testutils.PrivilegedTest(t)
	log := hivetest.Logger(t)

	relayNS, err := netns.New()
	require.NoError(t, err)
	defer relayNS.Close()

	serverNS, err := netns.New()
	require.NoError(t, err)
	defer serverNS.Close()

	relayIP := net.IPv4(192, 0, 2, 30)
	serverIP := net.IPv4(192, 0, 2, 40)

	setupUnicastRelayNamespaces(t, relayNS, serverNS, relayIP, serverIP)
	recvCh, stopServer := runSimpleDHCPServer(serverNS, serverIP, net.IPv4(192, 0, 2, 101))
	defer stopServer()

	relayFactory := &unicastRelayFactory{
		serverAddr: &net.UDPAddr{IP: serverIP, Port: dhcpv4.ServerPort},
		netns:      relayNS,
		log:        log,
	}
	relay, err := relayFactory.RelayFor(nil)
	require.NoError(t, err)
	require.NotNil(t, relay)

	req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	require.NoError(t, err)
	req.HopCount = 255

	require.Eventually(
		t,
		func() bool {
			_, err = relay.Relay(t.Context(), 50*time.Millisecond, req)
			if err != nil {
				return false
			}
			select {
			case info := <-recvCh:
				require.NotNil(t, info.msg)
				require.Equal(t, uint8(255), info.msg.HopCount)
				require.Equal(t, req.TransactionID, info.msg.TransactionID)
			case <-time.After(50 * time.Millisecond):
				return false
			}
			return true

		},
		2*time.Second,
		50*time.Millisecond,
	)
}

func TestPrivilegedUnicastRelayRelayReturnsResponse(t *testing.T) {
	testutils.PrivilegedTest(t)

	relayNS, err := netns.New()
	require.NoError(t, err)
	defer relayNS.Close()

	serverNS, err := netns.New()
	require.NoError(t, err)
	defer serverNS.Close()

	relayIP := net.IPv4(192, 0, 2, 50)
	serverIP := net.IPv4(192, 0, 2, 60)

	setupUnicastRelayNamespaces(t, relayNS, serverNS, relayIP, serverIP)
	_, stopServer := runSimpleDHCPServer(serverNS, serverIP, net.IPv4(192, 0, 2, 100))
	defer stopServer()

	relayFactory := &unicastRelayFactory{
		serverAddr: &net.UDPAddr{IP: serverIP, Port: dhcpv4.ServerPort},
		log:        hivetest.Logger(t),
		netns:      relayNS,
	}
	relay, err := relayFactory.RelayFor(nil)
	require.NoError(t, err)
	require.NotNil(t, relay)
	req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01})
	require.NoError(t, err)

	require.Eventually(
		t,
		func() bool {
			resps, err := relay.Relay(t.Context(), 100*time.Millisecond, req)
			if err != nil || len(resps) != 1 {
				return false
			}
			resp := resps[0]
			require.NotNil(t, resp)
			require.Equal(t, dhcpv4.MessageTypeAck, resp.MessageType())
			return true
		},
		time.Second,
		50*time.Millisecond)
}

type recvInfo struct {
	msg  *dhcpv4.DHCPv4
	addr *net.UDPAddr
}

func setupUnicastRelayNamespaces(t *testing.T, relayNS, serverNS *netns.NetNS, relayIP, serverIP net.IP) {
	t.Helper()

	veth0, veth1 := setupVethPair(t, relayNS)
	veth0MAC := append(net.HardwareAddr(nil), veth0.Attrs().HardwareAddr...)
	veth1MAC := append(net.HardwareAddr(nil), veth1.Attrs().HardwareAddr...)

	require.NoError(t, relayNS.Do(func() error {
		link, err := safenetlink.LinkByName(veth1.Attrs().Name)
		if err != nil {
			return err
		}
		return netlink.LinkSetNsFd(link, serverNS.FD())
	}))

	require.NoError(t, relayNS.Do(func() error {
		link, err := safenetlink.LinkByName(veth0.Attrs().Name)
		if err != nil {
			return err
		}
		if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: &net.IPNet{IP: relayIP, Mask: net.CIDRMask(24, 32)}}); err != nil {
			return err
		}
		return netlink.NeighSet(&netlink.Neigh{
			LinkIndex:    link.Attrs().Index,
			IP:           serverIP,
			HardwareAddr: veth1MAC,
			State:        netlink.NUD_PERMANENT,
		})
	}))

	require.NoError(t, serverNS.Do(func() error {
		link, err := safenetlink.LinkByName(veth1.Attrs().Name)
		if err != nil {
			return err
		}
		if err := netlink.LinkSetUp(link); err != nil {
			return err
		}
		if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: &net.IPNet{IP: serverIP, Mask: net.CIDRMask(24, 32)}}); err != nil {
			return err
		}
		return netlink.NeighSet(&netlink.Neigh{
			LinkIndex:    link.Attrs().Index,
			IP:           relayIP,
			HardwareAddr: veth0MAC,
			State:        netlink.NUD_PERMANENT,
		})
	}))
}

func runSimpleDHCPServer(serverNS *netns.NetNS, serverIP, offeredIP net.IP) (<-chan recvInfo, func()) {
	recvCh := make(chan recvInfo, 1)
	stopCh := make(chan struct{})
	doneCh := make(chan struct{})

	go func() {
		defer close(doneCh)
		serverNS.Do(func() error {
			conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: serverIP, Port: dhcpv4.ServerPort})
			if err != nil {
				return err
			}
			defer conn.Close()

			buf := make([]byte, 2048)
			for {
				select {
				case <-stopCh:
					return nil
				default:
				}
				_ = conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
				n, addr, err := conn.ReadFromUDP(buf)
				if err != nil {
					var ne net.Error
					if errors.As(err, &ne) && ne.Timeout() {
						continue
					}
					return err
				}
				msg, err := dhcpv4.FromBytes(buf[:n])
				if err != nil {
					continue
				}
				select {
				case recvCh <- recvInfo{msg: msg, addr: addr}:
				default:
				}

				resp, err := dhcpv4.NewReplyFromRequest(msg)
				if err != nil {
					continue
				}
				resp.YourIPAddr = offeredIP
				resp.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeAck))
				_, err = conn.WriteToUDP(resp.ToBytes(), addr)
				if err != nil {
					return err
				}
			}
		})
	}()

	stop := func() {
		close(stopCh)
		<-doneCh
	}

	return recvCh, stop
}
