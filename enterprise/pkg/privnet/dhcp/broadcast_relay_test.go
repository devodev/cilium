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
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/mdlayher/socket"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestPrivilegedBroadcastRelay(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns, err := netns.New()
	require.NoError(t, err)
	defer ns.Close()

	veth0, veth1 := setupVethPair(t, ns)
	dispatcher := newReplyDispatcher()
	responderErr := make(chan error, 1)
	go func() {
		responderErr <- ns.Do(func() error {
			rawConn, err := socket.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_IP)), "dhcp-broadcast-relay-test", nil)
			if err != nil {
				return err
			}
			defer rawConn.Close()

			sll := &unix.SockaddrLinklayer{
				Ifindex:  veth1.Attrs().Index,
				Protocol: htons(unix.ETH_P_IP),
			}
			if err := rawConn.Bind(sll); err != nil {
				return err
			}

			buf := make([]byte, 2048)
			for {
				rawConn.SetReadDeadline(time.Now().Add(2 * time.Second))
				n, _, err := rawConn.Recvfrom(t.Context(), buf, 0)
				if err != nil {
					var netErr net.Error
					if errors.As(err, &netErr) && netErr.Timeout() {
						return errors.New("timed out waiting for relayed DHCP request")
					}
					return err
				}

				packet := gopacket.NewPacket(buf[:n], layers.LayerTypeEthernet, gopacket.NoCopy)
				udpLayer := packet.Layer(layers.LayerTypeUDP)
				if udpLayer == nil {
					continue
				}

				udp := udpLayer.(*layers.UDP)
				if udp.DstPort != dhcpv4.ServerPort {
					continue
				}

				req, err := dhcpv4.FromBytes(udp.Payload)
				if err != nil {
					return err
				}

				resp, err := dhcpv4.NewReplyFromRequest(req)
				if err != nil {
					return err
				}
				resp.YourIPAddr = net.IPv4(192, 168, 1, 10)
				resp.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeAck))

				resp2, err := dhcpv4.NewReplyFromRequest(req)
				if err != nil {
					return err
				}
				resp2.YourIPAddr = net.IPv4(192, 168, 1, 11)
				resp2.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeNak))

				dispatcher.dispatch(veth0.Attrs().Index, resp)
				dispatcher.dispatch(veth0.Attrs().Index, resp2)
				return nil
			}
		})
	}()

	// Test the broadcast relay against the dummy DHCP server by relaying the request to
	// it via veth0.
	relay := &broadcastRelay{
		ifname:    veth0.Attrs().Name,
		log:       hivetest.Logger(t),
		netns:     ns,
		responses: dispatcher,
	}
	require.NoError(t, err)
	require.NotNil(t, relay)

	hw := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	req, err := dhcpv4.NewDiscovery(hw)
	require.NoError(t, err)
	req.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeDiscover))

	require.Eventually(
		t,
		func() bool {
			resps, err := relay.Relay(t.Context(), 50*time.Millisecond, req)
			if err != nil {
				t.Logf("Relay(): %s", err)
				return false
			}
			if len(resps) != 2 {
				t.Logf("len(resps): %d", len(resps))
				return false
			}
			return true
		},
		time.Second,
		50*time.Millisecond,
	)

	require.NoError(t, <-responderErr)
}
