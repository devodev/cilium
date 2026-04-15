//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package reconcilers

import (
	"context"
	"fmt"
	"iter"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"golang.org/x/time/rate"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/datapath/gneigh"
)

// GneighCell provides a reconciler which watches map entries and sends gratuitous ARP/ND packets
// for workload cluster endpoint entries. It is only active on the INB cluster acting as a bridge.
var GneighCell = cell.Group(
	cell.Provide(
		newGneighOps,
	),
	cell.Invoke(
		registerGneighReconciler,
	),
)

func registerGneighReconciler(in struct {
	cell.In

	Ops *GneighOps

	Lifecycle cell.Lifecycle
	Config    config.Config

	MapEntries       statedb.RWTable[*tables.MapEntry]
	ReconcilerParams reconciler.Params
}) (reconciler.Reconciler[*tables.MapEntry], error) {
	if !in.Config.IsLocallyConnected() {
		// Private networking is disabled or we are not a bridge, nothing to do.
		return nil, nil
	}

	in.Lifecycle.Append(
		cell.Hook{
			OnStop: func(hc cell.HookContext) error {
				for _, sender := range in.Ops.arpSenders {
					sender.Close()
				}

				for _, sender := range in.Ops.ndSenders {
					sender.Close()
				}

				return nil
			},
		},
	)
	return reconciler.Register(
		// params
		in.ReconcilerParams,
		// table
		in.MapEntries,
		// clone
		func(ne *tables.MapEntry) *tables.MapEntry {
			// We can do a shallow clone for the reconciler
			cpy := *ne
			return &cpy
		},
		// setStatus
		func(ne *tables.MapEntry, status reconciler.Status) *tables.MapEntry {
			ne.GneighStatus = status
			return ne
		},
		// getStatus
		func(ne *tables.MapEntry) reconciler.Status {
			return ne.GneighStatus
		},
		// ops
		in.Ops,
		// batchOps
		nil,
		// options
		reconciler.WithRefreshing(in.Config.BridgeGneighInterval, rate.NewLimiter(10, 1)),
		reconciler.WithName("gneigh"),
	)
}

type arpSender struct {
	gneigh.ArpSender
	gneigh.Interface
}

type ndSender struct {
	gneigh.NdSender
	gneigh.Interface
}

type GneighOps struct {
	sender gneigh.Sender

	// arpSenders are the gratuitous ARP senders per interface (indexed by ifindex).
	arpSenders map[int]*arpSender
	// ndSenders are the gratuitous ND senders per interface (indexed by ifindex).
	ndSenders map[int]*ndSender
}

func newGneighOps(sender gneigh.Sender) *GneighOps {
	return &GneighOps{
		sender: sender,

		arpSenders: make(map[int]*arpSender),
		ndSenders:  make(map[int]*ndSender),
	}
}

func (ops *GneighOps) Update(ctx context.Context, txn statedb.ReadTxn, rev statedb.Revision, me *tables.MapEntry) error {
	if !me.Routing.L2Announce {
		return nil
	}

	addr := me.Target.CIDR.Addr()
	if addr.Is4() {
		sender, err := ops.getArpSender(me.Routing.EgressIfIndex)
		if err != nil {
			return fmt.Errorf("failed to initialize ARP sender: %w", err)
		}

		if err := sender.Send(addr, sender.Interface.HardwareAddr()); err != nil {
			return fmt.Errorf("failed to send gratuitous ARP to %v: %w", addr, err)
		}
	} else {
		sender, err := ops.getNdSender(me.Routing.EgressIfIndex)
		if err != nil {
			return fmt.Errorf("failed to initialize ND sender: %w", err)
		}

		if err := sender.Send(addr, sender.Interface.HardwareAddr()); err != nil {
			return fmt.Errorf("failed to send gratuitous ND to %v: %w", addr, err)
		}
	}

	return nil
}

func (ops *GneighOps) Delete(_ context.Context, _ statedb.ReadTxn, _ statedb.Revision, me *tables.MapEntry) error {
	// Nothing to do
	return nil
}

// Prune closes and removes all ARP/ND senders whose interface is no longer referenced by any map
// entry.
func (ops *GneighOps) Prune(_ context.Context, txn statedb.ReadTxn, mes iter.Seq2[*tables.MapEntry, statedb.Revision]) error {
	interfaces := sets.Set[int]{}
	for me := range mes {
		if me.Routing.L2Announce {
			interfaces.Insert(me.Routing.EgressIfIndex)
		}
	}

	for ifindex, sender := range ops.arpSenders {
		if !interfaces.Has(ifindex) {
			sender.Close()
			delete(ops.arpSenders, ifindex)
		}
	}

	for ifindex, sender := range ops.ndSenders {
		if !interfaces.Has(ifindex) {
			sender.Close()
			delete(ops.ndSenders, ifindex)
		}
	}

	return nil
}

func (ops *GneighOps) getArpSender(ifindex int) (*arpSender, error) {
	if arpSender, ok := ops.arpSenders[ifindex]; ok {
		return arpSender, nil
	}

	iface, err := ops.sender.InterfaceByIndex(ifindex)
	if err != nil {
		return nil, err
	}

	sender, err := ops.sender.NewArpSender(iface)
	if err != nil {
		return nil, err
	}

	arpSender := &arpSender{sender, iface}
	ops.arpSenders[ifindex] = arpSender
	return arpSender, nil
}

func (ops *GneighOps) getNdSender(ifindex int) (*ndSender, error) {
	if ndSender, ok := ops.ndSenders[ifindex]; ok {
		return ndSender, nil
	}

	iface, err := ops.sender.InterfaceByIndex(ifindex)
	if err != nil {
		return nil, err
	}

	sender, err := ops.sender.NewNdSender(iface)
	if err != nil {
		return nil, err
	}

	ndSender := &ndSender{sender, iface}
	ops.ndSenders[ifindex] = ndSender
	return ndSender, nil
}
