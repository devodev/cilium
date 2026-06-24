// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package utils

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/bgp/agent/signaler"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/rate"
)

// SignalBGPUponTableEvents signals BGP control plane using the provided signaler upon all statedb table changes
func SignalBGPUponTableEvents[T any](ctx context.Context, db *statedb.DB, table statedb.Table[T], signaler *signaler.BGPCPSignaler, limiter *rate.Limiter) error {
	// wait for table initialization
	_, watch := table.Initialized(db.ReadTxn())
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-watch:
	}

	// emit initial signal
	signaler.Event(struct{}{})

	// watch for changes in the table
	_, watch = table.AllWatch(db.ReadTxn())

	for {
		select {
		case <-watch:
			// table changed, re-start the watch and emit reconciliation event
			_, watch = table.AllWatch(db.ReadTxn())
			signaler.Event(struct{}{})
		case <-ctx.Done():
			return ctx.Err()
		}
		// if rate-limiting is applied, wait if necessary
		if limiter != nil {
			if err := limiter.Wait(ctx); err != nil {
				return err
			}
		}
	}
}

// GetIPv6LinkLocalNeighborAddress attempts to find single neighbor with a link-local IPv6 address on the given interface
// in the provided device and neighbor tables. If found, returns its link-local address with zone.
// Expects single link-local IPv6 neighbor on the given interface - in case of multiple link-local neighbors, found returns false.
func GetIPv6LinkLocalNeighborAddress(deviceTable statedb.Table[*tables.Device], neighborTable statedb.Table[*tables.Neighbor], txn statedb.ReadTxn, ifName string) (neighborAddr string, found bool, err error) {
	device, _, found := deviceTable.Get(txn, tables.DeviceByName(ifName))
	if !found {
		// configured device not found on the node - return an error
		return "", false, fmt.Errorf("device %s not found", ifName)
	}

	// We need to skip our own link-local address, as it is populated into the neighbor table
	// when router advertisements for this interface are enabled on RADaemon.
	var localLLAddress netip.Addr
	for _, addr := range device.Addrs {
		if addr.Addr.Is6() && addr.Addr.IsLinkLocalUnicast() {
			localLLAddress = addr.Addr
			break
		}
	}

	// try to find single neighbor with a link-local IPv6 address
	neighbors := neighborTable.List(txn, tables.NeighborLinkIndex.Query(device.Index))
	cnt := 0
	addr := netip.Addr{}
	for neighbor := range neighbors {
		// NOTE: unfortunately, we can not rely on the NTF_ROUTER flag here, as the netlink library does not
		// deliver a neighbor update if flags on an existing neighbor entry change. Because of that, we may miss
		// the NTF_ROUTER flag if the neighbor entry was already existing before receiving a Router Advertisement.
		if neighbor.IPAddr.Is6() && neighbor.IPAddr.IsLinkLocalUnicast() && neighbor.IPAddr != localLLAddress && neighbor.State&tables.NUD_FAILED == 0 {
			addr = neighbor.IPAddr
			cnt++
		}
	}

	if cnt == 0 {
		// no valid link-local neighbor found
		return "", false, nil
	} else if cnt > 1 {
		// more than one link-local neighbor found, not supported - return an error
		return "", false, fmt.Errorf("found %d link-local neighbors, only one is supported", cnt)
	}

	// single neighbor with a link-local IPv6 address found
	return addr.WithZone(ifName).String(), true, nil
}
