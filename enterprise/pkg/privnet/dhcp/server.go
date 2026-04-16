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
	"fmt"
	"log/slog"
	"net"
	"strconv"

	"github.com/cilium/hive/cell"
	"github.com/cilium/workerpool"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/mdlayher/socket"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.org/x/time/rate"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/time"
)

// Server implements a DHCP server that receives DHCP requests from the 'cilium_dhcp' interface
// (to which bpf_lxc redirects them), passes them to [Handler] and sends responses back to
// the lxc interfaces.
type Server struct {
	netns   *netns.NetNS
	conn    *socket.Conn
	handler Handler
	replies *replyDispatcher
	log     *slog.Logger
	cfg     Config
	ifindex int
	ifname  string
	ifmac   net.HardwareAddr
}

// Handler processes a DHCP request and returns the egress ifindex plus zero or more DHCP responses.
type Handler func(ctx context.Context, health cell.Health, endpointID uint16, req *dhcpv4.DHCPv4) (int, []*dhcpv4.DHCPv4, error)

func NewServer(log *slog.Logger, cfg Config, netns *netns.NetNS, ifname string, handler Handler, replies *replyDispatcher) (*Server, error) {
	if handler == nil {
		return nil, errors.New("handler not specified")
	}
	if ifname == "" {
		return nil, errors.New("interface name not specified")
	}

	logger := log.With(logfields.Interface, ifname)

	return &Server{
		netns:   netns,
		ifname:  ifname,
		handler: handler,
		replies: replies,
		log:     logger,
		cfg:     cfg,
	}, nil
}

func (s *Server) Close() error {
	return s.conn.Close()
}

const (
	// maxParallelWorkers sets the maximum number of background goroutines to use
	// for relaying DHCP requests.
	maxParallelWorkers = 32

	// minDefaultRequestInterval sets the minimum amount of time that must elapse
	// before an endpoint can make a request again. [Config.WaitTime] is used
	// instead if it is smaller than this.
	minDefaultRequestInterval = 100 * time.Millisecond

	// numEndpointTimestamps is the maximum number of endpoints we keep the
	// last request timestamp for. This is essentially the number of endpoints
	// we can effectively rate limit for at the same time.
	numEndpointTimestamps = 16
)

// requestRateLimiter keeps a fixed number of request timestamps per endpoint.
// This is designed to prevent abuse from a small number of endpoints while
// keeping memory usage static.
type requestRateLimiter struct {
	minInterval time.Duration
	entries     [numEndpointTimestamps]struct {
		endpointID uint16
		limiter    *rate.Limiter
	}
	pos int
}

func (r *requestRateLimiter) allow(id uint16) bool {
	for _, x := range r.entries {
		if x.endpointID == id {
			return x.limiter.Allow()
		}
	}
	r.entries[r.pos].limiter = rate.NewLimiter(rate.Every(r.minInterval), 3)
	r.entries[r.pos].endpointID = id
	r.pos++
	if r.pos >= len(r.entries) {
		r.pos = 0
	}
	return true
}

func (s *Server) Serve(ctx context.Context, health cell.Health) error {
	if err := s.setup(ctx); err != nil {
		return err
	}
	defer s.conn.Close()

	if health != nil {
		health.OK("Listening")
	}

	// Use a worker pool to process the requests in parallel.
	wp := workerpool.New(maxParallelWorkers)
	defer wp.Close()

	// Keep track of the last time a request was received from each endpoint
	// and drop requests that arrive too soon after the previous one. This makes
	// sure a single endpoint cannot spam DHCP requests and prevent others from
	// making progress.
	rateLimiter := requestRateLimiter{
		minInterval: min(minDefaultRequestInterval, s.cfg.WaitTime),
	}
	logLimiter := rate.NewLimiter(rate.Every(1*time.Second), 1)

	for {
		buf := make([]byte, 4096)
		n, from, err := s.conn.Recvfrom(ctx, buf, 0)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
				return nil
			}
			s.log.Error("Failed to read DHCP packet", logfields.Error, err)
			return err
		}

		sll, ok := from.(*unix.SockaddrLinklayer)
		if !ok || sll.Hatype != unix.ARPHRD_ETHER {
			continue
		}

		packet := gopacket.NewPacket(buf[:n], layers.LayerTypeEthernet, gopacket.NoCopy)
		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if ethLayer == nil || ipLayer == nil || udpLayer == nil {
			continue
		}
		eth := ethLayer.(*layers.Ethernet)
		ip4 := ipLayer.(*layers.IPv4)
		udp := udpLayer.(*layers.UDP)
		if udp.DstPort != dhcpv4.ServerPort && udp.DstPort != dhcpv4.ClientPort {
			continue
		}

		msg, err := dhcpv4.FromBytes(udp.Payload)
		if err != nil {
			s.log.Error("Failed to parse DHCP packet",
				logfields.Error, err,
				logfields.Peer, ip4.SrcIP)
			continue
		}

		if msg.OpCode == dhcpv4.OpcodeBootReply {
			relayIfindex, ok := decodeRelayIfindexSourceMAC(eth.SrcMAC)
			dispatched := ok && s.replies != nil && s.replies.dispatch(relayIfindex, msg)
			s.log.Debug("Received relayed DHCP response",
				logfields.Interface, relayIfindex,
				logfields.Type, msg.MessageType(),
				logfields.Xid, msg.TransactionID,
				logfields.Chaddr, msg.ClientHWAddr,
				logfields.Success, dispatched,
			)
			continue
		}

		if msg.OpCode != dhcpv4.OpcodeBootRequest {
			continue
		}

		endpointID := uint16(0)
		if len(eth.SrcMAC) >= 6 {
			endpointID = binary.BigEndian.Uint16(eth.SrcMAC[4:6])
		}

		if !rateLimiter.allow(endpointID) {
			if logLimiter.Allow() {
				s.log.Info("Dropping DHCP request due to rate limiting",
					logfields.EndpointID, endpointID,
				)
			}
			continue
		}

		s.log.Debug("Received DHCP packet",
			logfields.DstIP, ip4.DstIP,
			logfields.SrcIP, ip4.SrcIP,
			logfields.MACAddr, eth.SrcMAC,
			logfields.Type, msg.MessageType(),
			logfields.EndpointID, endpointID,
			logfields.Xid, msg.TransactionID,
			logfields.Chaddr, msg.ClientHWAddr,
			logfields.Giaddr, msg.GatewayIPAddr,
		)

		err = wp.Submit(strconv.FormatUint(uint64(endpointID), 10), func(ctx context.Context) error {
			ifindex, resps, err := s.handler(ctx, health, endpointID, msg)
			if err != nil || len(resps) == 0 {
				return nil
			}
			clientMAC := msg.ClientHWAddr
			if len(clientMAC) == 0 {
				clientMAC = eth.SrcMAC
			}
			srvAddr := &net.UDPAddr{IP: ip4.DstIP, Port: int(udp.SrcPort)}
			for _, resp := range resps {
				if resp != nil {
					if err := s.sendResponse(ctx, ifindex, clientMAC, ip4.DstIP, srvAddr, resp); err != nil {
						s.log.Error("Could not send response", logfields.Error, err)
					}
				}
			}
			return nil
		})
		if err != nil {
			s.log.Error("Failed to submit DHCP handler job", logfields.Error, err)
		}
	}
}

func (s *Server) setup(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	target := s.netns
	if target == nil {
		var err error
		target, err = netns.Current()
		if err != nil {
			return fmt.Errorf("open current netns: %w", err)
		}
		defer target.Close()
	}

	return target.Do(func() error {
		var err error
		var link netlink.Link
		// Wait until the device exists and is UP
		for ctx.Err() == nil {
			link, err = safenetlink.LinkByName(s.ifname)
			if err == nil && link.Attrs().Flags&net.FlagUp != 0 {
				break
			}
			select {
			case <-ctx.Done():
				err = ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
		if err != nil {
			return fmt.Errorf("lookup interface %q: %w", s.ifname, err)
		}
		attrs := link.Attrs()
		if attrs == nil || attrs.Index == 0 {
			return fmt.Errorf("invalid interface %q", s.ifname)
		}
		s.ifindex = attrs.Index
		s.ifmac = attrs.HardwareAddr

		s.conn, err = newRawSocket(s.ifindex)
		if err != nil {
			return fmt.Errorf("create raw socket: %w", err)
		}
		s.log.Debug("Listening",
			logfields.LinkIndex, s.ifindex,
			// slogloggercheck-to-string: use String() to pretty-print, otherwise shows raw array
			logfields.MACAddr, s.ifmac.String())
		return nil
	})
}

func (s *Server) sendResponse(ctx context.Context, ifindex int, dstMAC net.HardwareAddr, srcAddr net.IP, addr *net.UDPAddr, resp *dhcpv4.DHCPv4) error {
	var srcIP net.IP
	if !srcAddr.IsUnspecified() {
		srcIP = srcAddr
	}
	if srcIP == nil {
		srcIP = net.IPv4zero
	}

	ethDst := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	if len(dstMAC) != 0 {
		ethDst = dstMAC
	}

	dstIP := addr.IP
	if dstIP == nil || dstIP.IsUnspecified() {
		dstIP = net.IPv4bcast
	}
	dstPort := addr.Port
	if dstPort == 0 {
		dstPort = dhcpv4.ClientPort
	}

	frame, err := buildServerDHCPFrame(resp.ToBytes(), s.ifmac, ethDst, srcIP, dstIP, dhcpv4.ServerPort, dstPort)
	if err != nil {
		return err
	}

	sll := &unix.SockaddrLinklayer{
		Ifindex:  ifindex,
		Protocol: htons(unix.ETH_P_IP),
		Halen:    6,
	}
	copy(sll.Addr[:], ethDst)

	s.log.Debug("Sending DHCP response",
		logfields.Interface, ifindex,
		logfields.SrcIP, srcIP,
		logfields.DstIP, dstIP,
		logfields.DstPort, dstPort,
		logfields.MACAddr, ethDst,
		logfields.Type, resp.MessageType(),
		logfields.Xid, resp.TransactionID,
		logfields.Yiaddr, resp.YourIPAddr,
		logfields.Chaddr, resp.ClientHWAddr,
	)

	if err := s.conn.Sendto(ctx, frame, 0, sll); err != nil {
		return err
	}
	return nil
}

func newRawSocket(ifindex int) (*socket.Conn, error) {
	conn, err := socket.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)), "privnet-dhcp", nil)
	if err != nil {
		return nil, err
	}
	sll := &unix.SockaddrLinklayer{
		Ifindex:  ifindex,
		Pkttype:  unix.PACKET_HOST,
		Protocol: htons(unix.ETH_P_ALL),
	}
	if err := conn.Bind(sll); err != nil {
		_ = conn.Close()
		return nil, err
	}

	mreq := &unix.PacketMreq{
		Ifindex: int32(ifindex),
		Type:    unix.PACKET_MR_PROMISC,
	}
	if err := conn.SetsockoptPacketMreq(unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, mreq); err != nil {
		_ = conn.Close()
		return nil, err
	}

	return conn, nil
}

func buildServerDHCPFrame(payload []byte, srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort int) ([]byte, error) {
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
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
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

// BuildServerDHCPFrameForTest exposes the DHCP frame builder for privileged test helpers.
func BuildServerDHCPFrameForTest(payload []byte, srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort int) ([]byte, error) {
	return buildServerDHCPFrame(payload, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort)
}

func htons(n uint16) uint16 {
	return (n&0xff)<<8 | (n >> 8)
}
