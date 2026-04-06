//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

//go:build linux

package egressipconf

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"net/netip"
	"os"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/vishvananda/netlink"
	"go4.org/netipx"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/enterprise/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/gneigh"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	egressIPLabel = "cilium-iegp"
)

func (ops *ops) Update(ctx context.Context, _ statedb.ReadTxn, _ statedb.Revision, entry *tables.EgressIPEntry) error {
	if !entry.Addr.IsValid() {
		return fmt.Errorf("egress IP %s is not valid", entry.Addr)
	}

	// For virtual IPs we currently don't need to take any action
	if entry.Interface == "" {
		return nil
	}

	iface, err := safenetlink.LinkByName(entry.Interface)
	if err != nil {
		return fmt.Errorf("failed to get device %s by name: %w", entry.Interface, err)
	}

	ops.logger.Debug("Adding address",
		logfields.Address, entry.Addr,
		logfields.Interface, entry.Interface)

	if err := netlink.AddrAdd(iface, addrForEgressIP(entry.Addr, egressIPLabel)); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("failed to add egress IP %s to interface %s: %w", entry.Addr, iface.Attrs().Name, err)
	}

	gneighIface, err := ops.gneighSender.InterfaceByIndex(iface.Attrs().Index)
	if err != nil {
		return fmt.Errorf("failed to get device %s by index: %w", entry.Interface, err)
	}

	err = ops.gneighSender.SendArp(gneighIface, entry.Addr, gneighIface.HardwareAddr())
	if err != nil {
		ops.logger.Warn("failed to send gratuitous arp reply",
			logfields.Address, entry.Addr,
			logfields.Interface, iface.Attrs().Name,
			logfields.LinkIndex, iface.Attrs().Index,
			logfields.Error, err)
	}

	return nil
}

func (ops *ops) Delete(ctx context.Context, _ statedb.ReadTxn, _ statedb.Revision, entry *tables.EgressIPEntry) error {
	// For virtual IPs we currently don't need to take any action
	if entry.Interface == "" {
		return nil
	}

	iface, err := safenetlink.LinkByName(entry.Interface)
	if err != nil {
		return fmt.Errorf("failed to get device %s by name: %w", entry.Interface, err)
	}

	ops.logger.Debug("Deleting address",
		logfields.Address, entry.Addr,
		logfields.Interface, entry.Interface)

	// For compatibility reasons don't require that the IP has our label.
	if err := netlink.AddrDel(iface, addrForEgressIP(entry.Addr, "")); err != nil && !errors.Is(err, unix.EADDRNOTAVAIL) {
		return fmt.Errorf("failed to delete egress IP %s to interface %s: %w", entry.Addr, iface.Attrs().Name, err)
	}

	return nil
}

func (ops *ops) Prune(ctx context.Context, txn statedb.ReadTxn, iter iter.Seq2[*tables.EgressIPEntry, statedb.Revision]) error {
	// prune addrs that are not part of the desired state (that is,
	// the stateDB current snapshot).
	// Also prune all routing setup left behind by an older installation.

	// There's currently no way to filter for specific labels, so we list all addresses:
	addrs, err := safenetlink.AddrList(nil, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("failed to list egress-gateway IPAM addresses: %w", err)
	}

	// build a map of in-use egressIP -> network interface:
	egressIPs := make(map[netip.Addr]string)
	for entry := range iter {
		egressIPs[entry.Addr] = entry.Interface
	}

	for _, a := range addrs {
		if a.Label != egressIPLabel {
			continue
		}

		addr, ok := netipx.FromStdIP(a.IP)
		if !ok {
			return fmt.Errorf("failed to convert netlink addr IP: %s", a.IP.String())
		}

		// Retain address when it's on the expected network interface:
		if ifName, ok := egressIPs[addr]; ok && ifName != "" {
			// TODO use Device table
			iface, err := safenetlink.LinkByName(ifName)
			if err != nil {
				return fmt.Errorf("failed to get device %s by name: %w", ifName, err)
			}

			if iface.Attrs().Index == a.LinkIndex {
				continue
			}
		}

		ops.logger.Debug("Pruning address",
			logfields.Address, addr,
			logfields.LinkIndex, a.LinkIndex)

		if err := netlink.AddrDel(nil, &a); err != nil {
			return fmt.Errorf("failed to delete egress IP %s: %w", addr, err)
		}
	}

	return nil
}

func newOps(logger *slog.Logger, gneighSender gneigh.Sender) *ops {
	return &ops{
		logger:       logger,
		gneighSender: gneighSender,
	}
}

type ops struct {
	logger       *slog.Logger
	gneighSender gneigh.Sender
}

var _ reconciler.Operations[*tables.EgressIPEntry] = &ops{}

func addrForEgressIP(addr netip.Addr, label string) *netlink.Addr {
	return &netlink.Addr{IPNet: netipx.AddrIPNet(addr), Label: label}
}
