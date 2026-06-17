//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package tests

import (
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/script"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"

	"github.com/cilium/cilium/enterprise/pkg/privnet/reconcilers"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/datapath/gneigh"
	dptables "github.com/cilium/cilium/pkg/datapath/tables"
)

func mockGneigh(t testing.TB) cell.Cell {
	t.Helper()

	return cell.Group(
		cell.ProvidePrivate(
			newFakeGneighSender,
			newGneighSentTable,
		),

		cell.Provide(
			func(fgs *fakeGneighSender) gneigh.Sender { return fgs },
			func(fgs *fakeGneighSender, gneighOps *reconcilers.GneighOps) hive.ScriptCmdsOut {
				return hive.NewScriptCmds(fgs.cmds(gneighOps))
			},
		),
	)
}

type gNeighType string

const (
	gNeighTypeARP gNeighType = "ARP"
	gNeighTypeND  gNeighType = "ND"
)

// gNeighSent tracks sent gratuitous ARP/ND packets for testing.
type gNeighSent struct {
	Type          gNeighType
	InterfaceName string
	MAC           net.HardwareAddr
	IP            netip.Addr
}

func (s gNeighSent) TableHeader() []string {
	return []string{"Type", "Interface", "MAC", "IP"}
}

func (s gNeighSent) TableRow() []string {
	return []string{
		string(s.Type),
		s.InterfaceName,
		s.MAC.String(),
		s.IP.String(),
	}
}

var _ statedb.TableWritable = gNeighSent{}

var (
	gneighSentIndex = statedb.Index[gNeighSent, netip.Addr]{
		Name: "ip",
		FromObject: func(obj gNeighSent) index.KeySet {
			return index.NewKeySet(index.NetIPAddr(obj.IP))
		},
		FromKey:    index.NetIPAddr,
		FromString: index.NetIPAddrString,
		Unique:     true,
	}
)

func newGneighSentTable(db *statedb.DB) (statedb.RWTable[gNeighSent], error) {
	return statedb.NewTable(
		db,
		"test-privnet-gneigh-sent",
		gneighSentIndex,
	)
}

type fakeSender struct {
	db   *statedb.DB
	sent statedb.RWTable[gNeighSent]

	typ   gNeighType
	iface gneigh.Interface
}

func newFakeSender(
	db *statedb.DB,
	sent statedb.RWTable[gNeighSent],
	typ gNeighType,
	iface gneigh.Interface,
) *fakeSender {
	return &fakeSender{
		db:    db,
		sent:  sent,
		typ:   typ,
		iface: iface,
	}
}

func (f *fakeSender) Send(addr netip.Addr, srcHW net.HardwareAddr) error {
	wtx := f.db.WriteTxn(f.sent)
	f.sent.Insert(wtx, gNeighSent{
		Type:          f.typ,
		InterfaceName: f.iface.Name(),
		MAC:           srcHW,
		IP:            addr,
	})
	wtx.Commit()
	return nil
}

func (f *fakeSender) Close() error {
	wtx := f.db.WriteTxn(f.sent)
	for sent := range f.sent.All(wtx) {
		if sent.Type == f.typ && sent.InterfaceName == f.iface.Name() {
			f.sent.Delete(wtx, sent)
		}
	}
	wtx.Commit()
	return nil

}

type fakeGneighSender struct {
	db         *statedb.DB
	sent       statedb.RWTable[gNeighSent]
	devs       statedb.Table[*dptables.Device]
	mapEntries statedb.Table[*tables.MapEntry]
}

func newFakeGneighSender(
	db *statedb.DB,
	sent statedb.RWTable[gNeighSent],
	devs statedb.Table[*dptables.Device],
	mapEntries statedb.Table[*tables.MapEntry],
) *fakeGneighSender {
	return &fakeGneighSender{
		db:         db,
		sent:       sent,
		devs:       devs,
		mapEntries: mapEntries,
	}
}

func (fgs *fakeGneighSender) SendArp(iface gneigh.Interface, ip netip.Addr, srcHW net.HardwareAddr) error {
	// Not used.
	return nil
}

func (fgs *fakeGneighSender) SendNd(iface gneigh.Interface, ip netip.Addr, srcHW net.HardwareAddr) error {
	// Not used.
	return nil
}

func (fgs *fakeGneighSender) NewArpSender(iface gneigh.Interface) (gneigh.ArpSender, error) {
	return newFakeSender(fgs.db, fgs.sent, gNeighTypeARP, iface), nil
}

func (fgs *fakeGneighSender) NewNdSender(iface gneigh.Interface) (gneigh.NdSender, error) {
	return newFakeSender(fgs.db, fgs.sent, gNeighTypeND, iface), nil
}

func (fgs *fakeGneighSender) InterfaceByIndex(idx int) (gneigh.Interface, error) {
	iface, _, found := fgs.devs.Get(fgs.db.ReadTxn(), dptables.DeviceByIndex(idx))
	if !found {
		return gneigh.Interface{}, fmt.Errorf("no interface for index %d", idx)
	}
	return gneigh.InterfaceFromNetInterface(&net.Interface{
		Index:        iface.Index,
		Name:         iface.Name,
		HardwareAddr: net.HardwareAddr(iface.HardwareAddr),
	}), nil
}

func (fgs *fakeGneighSender) cmds(ops *reconcilers.GneighOps) map[string]script.Cmd {
	return map[string]script.Cmd{
		"gneigh/prune": fgs.cmdGneighPrune(ops),
	}
}
func (fgs *fakeGneighSender) cmdGneighPrune(ops *reconcilers.GneighOps) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "prune sent gratuitous ARP/ND",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			txn := fgs.db.ReadTxn()
			iter := fgs.mapEntries.All(txn)
			ops.Prune(s.Context(), txn, iter)
			return nil, nil
		},
	)
}
