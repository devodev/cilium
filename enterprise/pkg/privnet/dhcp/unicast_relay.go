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

	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/time"
)

// unicastRelay forwards DHCP requests to a configured DHCP server via unicast
// using UDP source port 67.
type unicastRelay struct {
	serverAddr *net.UDPAddr
	option82   *v1alpha1.PrivateNetworkDHCPOption82Spec
	log        *slog.Logger
	netns      *netns.NetNS
}

// unicastRelayFactory returns a unicastRelay for each workload.
type unicastRelayFactory struct {
	serverAddr *net.UDPAddr
	option82   *v1alpha1.PrivateNetworkDHCPOption82Spec
	log        *slog.Logger
	netns      *netns.NetNS
}

// RelayFor implements RelayFactory.
func (f *unicastRelayFactory) RelayFor(*tables.LocalWorkload) (Relayer, error) {
	return &unicastRelay{
		serverAddr: f.serverAddr,
		option82:   f.option82,
		log:        f.log,
		netns:      f.netns,
	}, nil
}

// Relay forwards the DHCP request and returns responses received within waitTime.
func (r *unicastRelay) Relay(ctx context.Context, waitTime time.Duration, req *dhcpv4.DHCPv4) ([]*dhcpv4.DHCPv4, error) {
	if req == nil {
		return nil, errors.New("dhcp request is nil")
	}
	if waitTime <= 0 {
		return nil, fmt.Errorf("wait time is required")
	}

	conn, err := r.dialConn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	giaddr := net.IP(nil)
	if udpAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		giaddr = udpAddr.IP
	}

	sendReq, err := r.prepare(req, giaddr)
	if err != nil {
		return nil, err
	}

	if _, err := conn.Write(sendReq.ToBytes()); err != nil {
		r.log.Error("Failed to send unicast DHCP request", logfields.Error, err)
		return nil, fmt.Errorf("send unicast request: %w", err)
	}

	waitCtx, cancel := context.WithTimeout(ctx, waitTime)
	defer cancel()

	buf := make([]byte, 1500)
	for {
		select {
		case <-waitCtx.Done():
			if errors.Is(waitCtx.Err(), context.DeadlineExceeded) {
				r.log.Info("Timed out waiting for DHCP response")
				return nil, fmt.Errorf("timed out waiting for DHCP response")
			}
			return nil, waitCtx.Err()
		default:
			if err := conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
				return nil, err
			}
			n, err := conn.Read(buf)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					if _, err := conn.Write(sendReq.ToBytes()); err != nil {
						r.log.Error("Failed to resend unicast DHCP request", logfields.Error, err)
						return nil, fmt.Errorf("resend unicast request: %w", err)
					}
					continue
				}
				return nil, err
			}
			resp, err := dhcpv4.FromBytes(buf[:n])
			if err != nil {
				r.log.Info("Parse failure", logfields.Error, err)
				continue
			}
			// Ignore echoed requests and only accept server replies.
			if resp.OpCode != dhcpv4.OpcodeBootReply {
				continue
			}

			if resp.TransactionID != req.TransactionID {
				continue
			}
			return []*dhcpv4.DHCPv4{resp}, nil
		}
	}
}

func (r *unicastRelay) prepare(req *dhcpv4.DHCPv4, giaddr net.IP) (*dhcpv4.DHCPv4, error) {
	copyReq, err := dhcpv4.FromBytes(req.ToBytes())
	if err != nil {
		return nil, err
	}
	if copyReq.HopCount < 255 {
		copyReq.HopCount++
	}
	if giaddr != nil && !giaddr.IsUnspecified() {
		copyReq.GatewayIPAddr = giaddr
	}
	r.applyOption82(copyReq)
	return copyReq, nil
}

func (r *unicastRelay) applyOption82(req *dhcpv4.DHCPv4) {
	if req == nil || r.option82 == nil {
		return
	}

	opts := make([]dhcpv4.Option, 0, 2)
	if circuitID := r.option82.CircuitID; circuitID != "" {
		opts = append(opts, dhcpv4.OptGeneric(dhcpv4.AgentCircuitIDSubOption, []byte(circuitID)))
	}
	if remoteID := r.option82.RemoteID; remoteID != "" {
		opts = append(opts, dhcpv4.OptGeneric(dhcpv4.AgentRemoteIDSubOption, []byte(remoteID)))
	}
	if len(opts) == 0 {
		return
	}

	req.UpdateOption(dhcpv4.OptRelayAgentInfo(opts...))
}

func (r *unicastRelay) dialConn(ctx context.Context) (*net.UDPConn, error) {
	if r.serverAddr == nil || r.serverAddr.IP == nil {
		return nil, errors.New("server address is required for unicast relay")
	}
	dialer := net.Dialer{
		LocalAddr: &net.UDPAddr{Port: dhcpv4.ServerPort},
	}

	ns := r.netns
	if ns == nil {
		var err error
		ns, err = netns.Current()
		if err != nil {
			return nil, err
		}
		defer ns.Close()
	}

	var udpConn *net.UDPConn
	if err := ns.Do(func() error {
		conn, err := dialer.DialContext(ctx, "udp4", r.serverAddr.String())
		if err != nil {
			return fmt.Errorf("dial unicast relay socket to %s: %w", r.serverAddr, err)
		}
		c, ok := conn.(*net.UDPConn)
		if !ok {
			_ = conn.Close()
			return fmt.Errorf("unexpected conn type %T", conn)
		}
		udpConn = c
		return nil
	}); err != nil {
		return nil, err
	}
	return udpConn, nil
}
