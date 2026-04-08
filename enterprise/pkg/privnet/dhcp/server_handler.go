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
	"log/slog"
	"net"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/insomniacslk/dhcp/dhcpv4"

	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/time"
)

// RelayFactory provides a Relay for a specific workload.
type RelayFactory interface {
	RelayFor(*tables.LocalWorkload) (Relayer, error)
}

// Relayer forwards DHCP requests and returns a response packet.
type Relayer interface {
	// Relay DHCP request and return responses received within [waitTime]
	Relay(ctx context.Context, waitTime time.Duration, req *dhcpv4.DHCPv4) ([]*dhcpv4.DHCPv4, error)
}

// serverHandler relays DHCP requests and writes acquired leases to StateDB.
type serverHandler struct {
	relayFactory RelayFactory
	waitTime     time.Duration
	db           *statedb.DB
	workloads    statedb.RWTable[*tables.LocalWorkload]
	leases       statedb.Table[tables.DHCPLease]
	leaseWriter  *tables.DHCPLeaseWriter
	subnets      statedb.Table[tables.Subnet]
	log          *slog.Logger
	now          func() time.Time
}

// newServerHandler returns a DHCP handler that relays requests and persists leases.
func newServerHandler(log *slog.Logger, db *statedb.DB, workloads statedb.Table[*tables.LocalWorkload], leaseWriter *tables.DHCPLeaseWriter, subnets statedb.Table[tables.Subnet], relayFactory RelayFactory, waitTime time.Duration) *serverHandler {
	return &serverHandler{
		relayFactory: relayFactory,
		waitTime:     waitTime,
		db:           db,
		workloads:    workloads.(statedb.RWTable[*tables.LocalWorkload]),
		leases:       leaseWriter.Table(),
		leaseWriter:  leaseWriter,
		subnets:      subnets,
		log:          log,
		now:          time.Now,
	}
}

// serverHandler returns the handler function for DHCP server.
func (h *serverHandler) serverHandler() Handler {
	return func(ctx context.Context, health cell.Health, endpointID uint16, req *dhcpv4.DHCPv4) (int, []*dhcpv4.DHCPv4, error) {
		if h == nil || h.relayFactory == nil || req == nil || endpointID == 0 {
			return 0, nil, nil
		}
		txn := h.db.ReadTxn()

		lw, _, found := h.workloads.Get(txn, tables.LocalWorkloadsByID(endpointID))
		if !found || lw == nil {
			h.log.Debug("No local workload found", logfields.EndpointID, endpointID)
			return 0, nil, nil
		}

		if !tables.WorkloadUsesDHCP(txn, h.subnets, lw) {
			// FIXME: DHCP disabled, return response for the static IP. Requires that we enforce use
			// of managed-tap as with the bridge mode we'll fight with the KubeVirt DHCP server.
			h.log.Debug("DHCP disabled for workload, ignoring", logfields.EndpointID, endpointID)
			return 0, nil, nil
		}

		log := h.log.With(
			logfields.Interface, lw.LXC.IfIndex,
			logfields.EndpointID, lw.EndpointID,
			logfields.Network, lw.Interface.Network,
			logfields.PrivateNetworkSubnet, lw.Subnet,
		)

		ifindex := lw.LXC.IfIndex

		waitTime := h.waitTime

		relay, err := h.relayFactory.RelayFor(lw)
		if err != nil {
			h.log.Debug("Unable to construct relay", logfields.Error, err)
			return 0, nil, err
		}

		if relay == nil {
			// Relaying has been disabled with mode=none
			return 0, nil, nil
		}

		// If this is release/decline invalidate the lease and drop network IP.
		h.invalidateLeaseForRequest(endpointID, lw, req)

		log.Debug("Relaying DHCP request",
			logfields.Type, req.MessageType(),
			logfields.Xid, req.TransactionID,
			logfields.Chaddr, req.ClientHWAddr,
		)
		resps, err := relay.Relay(ctx, waitTime, req)
		if err != nil || len(resps) == 0 {
			log.Debug("Error relaying", logfields.Error, err)
			return ifindex, nil, err
		}
		out := make([]*dhcpv4.DHCPv4, 0, len(resps))
		for _, resp := range resps {
			if resp == nil {
				continue
			}
			if !h.offeredIPBelongsToWorkloadSubnet(lw, resp) {
				continue
			}
			if resp.MessageType() == dhcpv4.MessageTypeOffer || resp.MessageType() == dhcpv4.MessageTypeAck {
				resp, err = h.rewriteOffer(req, resp)
				if err != nil {
					continue
				}
			}
			log.Debug("DHCP response",
				logfields.Type, resp.MessageType(),
				logfields.Xid, resp.TransactionID,
				logfields.Yiaddr, resp.YourIPAddr,
			)
			h.recordLease(endpointID, req, resp)
			out = append(out, resp)
		}
		return ifindex, out, nil
	}
}

func resolveServerAddr(raw string) (*net.UDPAddr, error) {
	if raw == "" {
		return nil, errors.New("server address is required")
	}
	if _, _, err := net.SplitHostPort(raw); err != nil {
		if addr := net.ParseIP(raw); addr != nil {
			raw = net.JoinHostPort(raw, "67")
		}
	}
	return net.ResolveUDPAddr("udp4", raw)
}

func (h *serverHandler) offeredIPBelongsToWorkloadSubnet(lw *tables.LocalWorkload, resp *dhcpv4.DHCPv4) bool {
	if resp.MessageType() != dhcpv4.MessageTypeOffer && resp.MessageType() != dhcpv4.MessageTypeAck {
		return true
	}

	log := h.log.With(
		logfields.EndpointID, lw.EndpointID,
		logfields.Network, lw.Interface.Network,
		logfields.PrivateNetworkSubnet, lw.Subnet,
		logfields.Type, resp.MessageType(),
	)

	ip, ok := netip.AddrFromSlice(resp.YourIPAddr)
	if !ok {
		log.Warn("Ignoring DHCP response with invalid offered IPv4",
			logfields.IPv4, resp.YourIPAddr,
		)
		return false
	}
	ip = ip.Unmap()
	if !ip.Is4() {
		log.Warn("Ignoring DHCP response with non-IPv4 offer",
			logfields.IPv4, ip,
		)
		return false
	}

	network := tables.NetworkName(lw.Interface.Network)
	subnet, _, found := h.subnets.Get(h.db.ReadTxn(), tables.SubnetsByNetworkAndName(network, lw.Subnet))
	if !found || !subnet.CIDRv4.IsValid() {
		log.Warn("Ignoring DHCP response because workload subnet is not configured",
			logfields.IPv4, ip,
		)
		return false
	}

	if subnet.CIDRv4.Contains(ip) {
		return true
	}

	log.Warn("Ignoring DHCP response with offered IP outside workload subnet",
		logfields.IPv4, ip,
		logfields.CIDR, subnet.CIDRv4,
	)
	return false
}

var defaultGatewayAddress = net.IPv4(169, 254, 0, 1)

func (h *serverHandler) rewriteOffer(req, offer *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, error) {
	if req == nil || offer == nil {
		return nil, nil
	}
	resp, err := dhcpv4.NewReplyFromRequest(req)
	if err != nil {
		return nil, err
	}
	resp.UpdateOption(dhcpv4.OptMessageType(offer.MessageType()))
	resp.YourIPAddr = offer.YourIPAddr

	// Set the netmask to /32 and gateway to [defaultGatewayAddress]
	// and add a route for the default gateway.
	resp.UpdateOption(dhcpv4.OptSubnetMask(net.IPv4Mask(255, 255, 255, 255)))
	resp.UpdateOption(dhcpv4.OptRouter(defaultGatewayAddress))
	resp.UpdateOption(dhcpv4.OptClasslessStaticRoute(
		&dhcpv4.Route{
			Dest:   &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
			Router: defaultGatewayAddress,
		},
		&dhcpv4.Route{
			Dest:   &net.IPNet{IP: defaultGatewayAddress, Mask: net.CIDRMask(32, 32)},
			Router: net.IPv4zero,
		},
	))

	// Pass through a select set of options.

	if sid := offer.ServerIdentifier(); sid != nil {
		resp.UpdateOption(dhcpv4.OptServerIdentifier(sid))
	}

	if dns := offer.DNS(); len(dns) > 0 {
		resp.UpdateOption(dhcpv4.OptDNS(dns...))
	}
	if host := offer.HostName(); host != "" {
		resp.UpdateOption(dhcpv4.OptHostName(host))
	}
	if ntp := offer.NTPServers(); len(ntp) > 0 {
		resp.UpdateOption(dhcpv4.OptNTPServers(ntp...))
	}
	if domain := offer.DomainName(); domain != "" {
		resp.UpdateOption(dhcpv4.OptDomainName(domain))
	}
	if search := offer.DomainSearch(); search != nil {
		resp.UpdateOption(dhcpv4.OptDomainSearch(search))
	}
	if lt := offer.IPAddressLeaseTime(0); lt > 0 {
		resp.UpdateOption(dhcpv4.OptIPAddressLeaseTime(lt))
	}
	if rt := offer.IPAddressRenewalTime(0); rt > 0 {
		resp.UpdateOption(dhcpv4.OptRenewTimeValue(rt))
	}
	if rt := offer.IPAddressRebindingTime(0); rt > 0 {
		resp.UpdateOption(dhcpv4.OptRebindingTimeValue(rt))
	}

	return resp, nil
}

func (h *serverHandler) recordLease(endpointID uint16, req *dhcpv4.DHCPv4, resp *dhcpv4.DHCPv4) {
	switch resp.MessageType() {
	case dhcpv4.MessageTypeAck:
		h.recordLeaseAck(endpointID, req, resp)
	case dhcpv4.MessageTypeNak:
		macAddr := mac.MAC(req.ClientHWAddr)
		if len(macAddr) == 0 {
			macAddr = mac.MAC(resp.ClientHWAddr)
		}
		h.invalidateLease(endpointID, macAddr, netip.Addr{})
	}
}

func (h *serverHandler) recordLeaseAck(endpointID uint16, req *dhcpv4.DHCPv4, resp *dhcpv4.DHCPv4) {
	ip, ok := netip.AddrFromSlice(resp.YourIPAddr)
	if !ok {
		return
	}
	ip = ip.Unmap()

	macAddr := mac.MAC(req.ClientHWAddr)
	if len(macAddr) == 0 {
		macAddr = mac.MAC(resp.ClientHWAddr)
	}
	if len(macAddr) == 0 {
		return
	}

	serverID, _ := netip.AddrFromSlice(resp.ServerIdentifier())
	now := h.now()

	leaseTime := resp.IPAddressLeaseTime(0)
	renewTime := resp.IPAddressRenewalTime(0)
	if renewTime == 0 && leaseTime > 0 {
		renewTime = leaseTime / 2
	}

	expireAt := time.Time{}
	renewAt := time.Time{}
	if leaseTime > 0 {
		expireAt = now.Add(leaseTime)
	}
	if renewTime > 0 {
		renewAt = now.Add(renewTime)
	}

	wtxn := h.db.WriteTxn(h.leases, h.workloads)
	defer wtxn.Commit()
	lw, _, _ := h.workloads.Get(wtxn, tables.LocalWorkloadsByID(endpointID))
	if !tables.WorkloadUsesDHCP(wtxn, h.subnets, lw) {
		return
	}
	lease := tables.DHCPLease{
		Network:    tables.NetworkName(lw.Interface.Network),
		EndpointID: lw.EndpointID,
		MAC:        macAddr,
		IPv4:       ip,
		ServerID:   serverID,
		ObtainedAt: now,
		RenewAt:    renewAt,
		ExpireAt:   expireAt,
	}
	h.leaseWriter.Insert(wtxn, lease)
}

func (h *serverHandler) invalidateLeaseForRequest(endpointID uint16, lw *tables.LocalWorkload, req *dhcpv4.DHCPv4) {
	macAddr := mac.MAC(req.ClientHWAddr)
	if len(macAddr) == 0 {
		if parsedMAC, err := net.ParseMAC(lw.Interface.MAC); err == nil {
			macAddr = mac.MAC(parsedMAC)
		}
		if len(macAddr) == 0 {
			return
		}
	}

	switch req.MessageType() {
	case dhcpv4.MessageTypeRelease:
		releasedIP, _ := netip.AddrFromSlice(req.ClientIPAddr)
		h.invalidateLease(endpointID, macAddr, releasedIP.Unmap())
	case dhcpv4.MessageTypeDecline:
		declinedIP, _ := netip.AddrFromSlice(req.RequestedIPAddress())
		h.invalidateLease(endpointID, macAddr, declinedIP.Unmap())
	}
}

func (h *serverHandler) invalidateLease(endpointID uint16, macAddr mac.MAC, ipHint netip.Addr) {
	wtxn := h.db.WriteTxn(h.leases, h.workloads)
	defer wtxn.Commit()

	lw, _, _ := h.workloads.Get(wtxn, tables.LocalWorkloadsByID(endpointID))
	if !tables.WorkloadUsesDHCP(wtxn, h.subnets, lw) {
		return
	}

	lease, _, found := h.leases.Get(wtxn, tables.DHCPLeaseByNetworkMAC(tables.NetworkName(lw.Interface.Network), macAddr))
	if found && ipHint.IsValid() && lease.IPv4.IsValid() && lease.IPv4 != ipHint {
		return
	}
	if found {
		h.leaseWriter.Delete(wtxn, lease)
	}
}
