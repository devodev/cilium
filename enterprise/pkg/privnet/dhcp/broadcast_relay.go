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
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/mdlayher/socket"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/time"
)

// broadcastRelay forwards DHCP requests using IPv4 broadcast. The replies
// are received via the 'cilium_dhcp' device which [Server] listens to and
// are passed to [broadcastRelay] via the [replyDispatcher].
type broadcastRelay struct {
	log       *slog.Logger
	netns     *netns.NetNS
	responses *replyDispatcher
	ifname    string
}

// Relay forwards the DHCP request and returns the first matching response.
func (r *broadcastRelay) Relay(ctx context.Context, waitTime time.Duration, req *dhcpv4.DHCPv4) ([]*dhcpv4.DHCPv4, error) {
	if req == nil {
		return nil, errors.New("dhcp request is nil")
	}

	if waitTime <= 0 {
		return nil, fmt.Errorf("wait time is required")
	}

	ifindex, ifmac, err := r.resolveInterface()
	if err != nil {
		return nil, err
	}

	key, ok := newRelayKey(ifindex, req)
	if !ok {
		return nil, errors.New("failed to build DHCP relay key")
	}
	respCh := make(chan *dhcpv4.DHCPv4, 16)
	r.responses.add(key, respCh)
	defer r.responses.remove(key, respCh)

	if req.MessageType() == dhcpv4.MessageTypeRequest &&
		req.ClientIPAddr != nil && !req.ClientIPAddr.IsUnspecified() {
		// Turn unicast renewals into a broadcast "init-reboot" request by filling the
		// "requested IP address" option and unsetting the client IP.
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(req.ClientIPAddr))(req)
		req.ClientIPAddr = nil
	}
	// Set broadcast bit to request responses via broadcast.
	req.SetBroadcast()

	r.log.Debug("Relaying DHCP request",
		logfields.Type, req.MessageType(),
		logfields.Xid, req.TransactionID,
		logfields.Chaddr, req.ClientHWAddr,
		logfields.Interface, r.ifname,
		logfields.Timeout, waitTime,
	)

	if err := r.send(ctx, ifindex, ifmac, req); err != nil {
		r.log.Info("Failed to send broadcast DHCP request", logfields.Error, err)
		return nil, fmt.Errorf("send broadcast request: %w", err)
	}

	timer := time.NewTimer(waitTime)
	defer timer.Stop()

	var responses []*dhcpv4.DHCPv4
	for {
		select {
		case <-ctx.Done():
			r.log.Debug("DHCP relay context done", logfields.Error, ctx.Err())
			return responses, ctx.Err()
		case <-timer.C:
			if len(responses) == 0 {
				r.log.Info("Timed out waiting for DHCP response")
				return nil, fmt.Errorf("timed out waiting for DHCP response")
			}
			r.log.Debug("Returning responses",
				logfields.Count, len(responses),
			)
			return responses, nil
		case resp := <-respCh:
			if resp == nil {
				r.log.Info("Received empty DHCP response")
				continue
			}
			r.log.Debug("Received DHCP response",
				logfields.Type, resp.MessageType(),
				logfields.Xid, resp.TransactionID,
				logfields.IPv4, resp.YourIPAddr,
				logfields.Interface, r.ifname,
			)
			responses = append(responses, resp)
		}
	}
}

func (r *broadcastRelay) prepare(req *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, error) {
	copyReq, err := dhcpv4.FromBytes(req.ToBytes())
	if err != nil {
		return nil, fmt.Errorf("copy dhcp request: %w", err)
	}
	copyReq.SetBroadcast()
	return copyReq, nil
}

func (r *broadcastRelay) resolveInterface() (ifindex int, ifmac net.HardwareAddr, err error) {
	err = r.withNetNS(func() error {
		link, err := safenetlink.LinkByName(r.ifname)
		if err != nil {
			return fmt.Errorf("lookup interface %q: %w", r.ifname, err)
		}
		attrs := link.Attrs()
		if attrs == nil || len(attrs.HardwareAddr) != 6 {
			return fmt.Errorf("interface %q has no hardware address", r.ifname)
		}
		if attrs.Flags&net.FlagUp == 0 || attrs.Flags&net.FlagRunning == 0 {
			return fmt.Errorf("interface %q is down", r.ifname)
		}

		ifindex = attrs.Index
		ifmac = attrs.HardwareAddr
		return nil
	})
	return
}

func (r *broadcastRelay) send(ctx context.Context, ifindex int, ifmac net.HardwareAddr, req *dhcpv4.DHCPv4) error {
	return r.withNetNS(func() error {
		prepared, err := r.prepare(req)
		if err != nil {
			return err
		}
		conn, err := newRelaySendSocket()
		if err != nil {
			return err
		}
		defer conn.Close()

		dstMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
		frame, err := buildServerDHCPFrame(
			prepared.ToBytes(),
			ifmac,
			dstMAC,
			net.IPv4zero,
			net.IPv4bcast,
			dhcpv4.ClientPort,
			dhcpv4.ServerPort,
		)
		if err != nil {
			return err
		}

		sll := &unix.SockaddrLinklayer{
			Ifindex:  ifindex,
			Protocol: htons(unix.ETH_P_IP),
			Halen:    6,
		}
		copy(sll.Addr[:], dstMAC)
		return conn.Sendto(ctx, frame, 0, sll)
	})
}

func (r *broadcastRelay) withNetNS(fn func() error) error {
	if r.netns == nil {
		return fn()
	}
	return r.netns.Do(fn)
}

func newRelaySendSocket() (*socket.Conn, error) {
	return socket.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_IP)), "privnet-dhcp-relay", nil)
}
