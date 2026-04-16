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
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/mdlayher/socket"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestPrivilegedDHCPServerInNetNS(t *testing.T) {
	testutils.PrivilegedTest(t)

	// Create a new network namespace for the test and add veth pair.
	// This simulates both the 'cilium_dhcp' and the 'lxc' device.
	ns, err := netns.New()
	require.NoError(t, err)
	defer ns.Close()
	veth0, veth1 := setupVethPair(t, ns)

	handler := func(_ context.Context, _ cell.Health, _ uint16, req *dhcpv4.DHCPv4) (int, []*dhcpv4.DHCPv4, error) {
		if req == nil {
			return 0, nil, nil
		}
		resp, err := dhcpv4.NewReplyFromRequest(req)
		if err != nil {
			return 0, nil, err
		}
		resp.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeOffer))
		resp.UpdateOption(dhcpv4.OptServerIdentifier(net.IPv4(192, 168, 250, 10)))
		resp.YourIPAddr = net.IPv4(192, 168, 250, 10)
		return veth0.Attrs().Index, []*dhcpv4.DHCPv4{resp}, nil
	}

	// Start the DHCP server on veth0
	srv, err := NewServer(hivetest.Logger(t), DefaultConfig, ns, veth0.Attrs().Name, handler, newReplyDispatcher())
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		srv.Close()
	})
	go func() {
		_ = srv.Serve(ctx, nil)
	}()

	require.NoError(t, ns.Do(func() error {
		// Open a raw socket for the DHCP exchange
		rawConn, err := socket.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_IP)), "dhcp-test", nil)
		if err != nil {
			return err
		}
		defer rawConn.Close()

		// Bind to veth1
		sll := &unix.SockaddrLinklayer{
			Ifindex:  veth1.Attrs().Index,
			Protocol: htons(unix.ETH_P_IP),
		}
		if err := rawConn.Bind(sll); err != nil {
			return err
		}

		sendSLL := &unix.SockaddrLinklayer{
			Ifindex:  veth1.Attrs().Index,
			Protocol: htons(unix.ETH_P_IP),
			Halen:    6,
		}
		copy(sendSLL.Addr[:], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})

		xid := uint32(0x12345678)
		chaddr := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
		req, err := buildDiscoverPacket(xid, chaddr)
		if err != nil {
			return err
		}
		frame, err := buildTestDHCPFrame(veth1.Attrs().HardwareAddr, req)
		if err != nil {
			return err
		}

		// As the server starts up asynchronously, try doing the DHCP exchange few times
		// until it succeeds.
		require.Eventually(
			t,
			func() bool {
				if err := rawConn.Sendto(t.Context(), frame, 0, sendSLL); err != nil {
					t.Logf("Sendto: %s", err)
					return false
				}
				buf := make([]byte, 2048)
				for {
					rawConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
					n, _, err := rawConn.Recvfrom(t.Context(), buf, 0)
					if err != nil {
						var ne net.Error
						if errors.As(err, &ne) && ne.Timeout() {
							break
						}
						t.Logf("Recvfrom: %s", err)
						return false
					}
					packet := gopacket.NewPacket(buf[:n], layers.LayerTypeEthernet, gopacket.NoCopy)
					ipLayer := packet.Layer(layers.LayerTypeIPv4)
					udpLayer := packet.Layer(layers.LayerTypeUDP)
					if ipLayer == nil || udpLayer == nil {
						continue
					}
					udp := udpLayer.(*layers.UDP)
					if udp.DstPort != dhcpv4.ClientPort {
						continue
					}
					if !isOffer(udp.Payload, xid) {
						continue
					}
					return true
				}
				return false
			},
			2*time.Second,
			50*time.Millisecond,
			"Timed out waiting for DHCP exchange to succeed",
		)
		return nil
	}))
}

func TestPrivilegedDHCPServerDispatchesRelayedResponse(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns, err := netns.New()
	require.NoError(t, err)
	defer ns.Close()

	veth0, veth1 := setupVethPair(t, ns)
	dispatcher := newReplyDispatcher()

	handler := func(_ context.Context, _ cell.Health, _ uint16, _ *dhcpv4.DHCPv4) (int, []*dhcpv4.DHCPv4, error) {
		return 0, nil, nil
	}

	srv, err := NewServer(hivetest.Logger(t), DefaultConfig, ns, veth0.Attrs().Name, handler, dispatcher)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		srv.Close()
	})
	go func() {
		_ = srv.Serve(ctx, nil)
	}()

	req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	require.NoError(t, err)

	resp, err := dhcpv4.NewReplyFromRequest(req)
	require.NoError(t, err)
	resp.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeOffer))
	resp.YourIPAddr = net.IPv4(192, 168, 250, 10)

	key, ok := newRelayKey(veth1.Attrs().Index, resp)
	require.True(t, ok)

	respCh := make(chan *dhcpv4.DHCPv4, 1)
	dispatcher.add(key, respCh)

	sendRequest := func() error {
		return ns.Do(func() error {
			rawConn, err := socket.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_IP)), "dhcp-relay-response-test", nil)
			if err != nil {
				return err
			}
			defer rawConn.Close()

			sendSLL := &unix.SockaddrLinklayer{
				Ifindex:  veth1.Attrs().Index,
				Protocol: htons(unix.ETH_P_IP),
				Halen:    6,
			}
			copy(sendSLL.Addr[:], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})

			frame, err := buildServerDHCPFrame(
				resp.ToBytes(),
				encodeRelayIfindexSourceMAC(veth1.Attrs().Index),
				net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
				net.IPv4(192, 168, 250, 1),
				net.IPv4bcast,
				dhcpv4.ServerPort,
				dhcpv4.ClientPort,
			)
			if err != nil {
				return err
			}
			return rawConn.Sendto(t.Context(), frame, 0, sendSLL)
		})
	}

	require.Eventually(t, func() bool {
		sendRequest()
		select {
		case got := <-respCh:
			return got != nil && got.TransactionID == resp.TransactionID
		default:
			return false
		}
	}, 2*time.Second, 50*time.Millisecond)
}

func buildDiscoverPacket(xid uint32, chaddr net.HardwareAddr) ([]byte, error) {
	req, err := dhcpv4.NewDiscovery(chaddr, dhcpv4.WithTransactionID(transactionIDFromUint32(xid)))
	if err != nil {
		return nil, err
	}
	return req.ToBytes(), nil
}

func buildTestDHCPFrame(srcMAC net.HardwareAddr, payload []byte) ([]byte, error) {
	dstMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
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

func isOffer(pkt []byte, xid uint32) bool {
	offer, err := dhcpv4.FromBytes(pkt)
	if err != nil {
		return false
	}
	if offer.TransactionID != transactionIDFromUint32(xid) {
		return false
	}
	return offer.MessageType() == dhcpv4.MessageTypeOffer
}

func transactionIDFromUint32(xid uint32) dhcpv4.TransactionID {
	var txid dhcpv4.TransactionID
	binary.BigEndian.PutUint32(txid[:], xid)
	return txid
}

func encodeRelayIfindexSourceMAC(ifindex int) net.HardwareAddr {
	mac := make(net.HardwareAddr, 6)
	binary.BigEndian.PutUint32(mac[2:], uint32(ifindex))
	return mac
}
