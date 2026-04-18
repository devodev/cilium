//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package vrf

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"

	"github.com/cilium/statedb"
	"github.com/vishvananda/netlink"

	dpTables "github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	epTypes "github.com/cilium/cilium/pkg/endpoint/types"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sTables "github.com/cilium/cilium/pkg/k8s/tables"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/node"
)

// newPodTable returns a writable pod statedb table for tests, registered
// against the provided db.
func newPodTable(db *statedb.DB) statedb.RWTable[k8sTables.LocalPod] {
	tbl, err := k8sTables.NewPodTable(db)
	if err != nil {
		panic(fmt.Sprintf("NewPodTable: %v", err))
	}
	return tbl
}

// newNamespaceTable returns a writable namespace statedb table for tests,
// registered against the provided db.
func newNamespaceTable(db *statedb.DB) statedb.RWTable[k8sTables.Namespace] {
	tbl, err := k8sTables.NewNamespaceTable(db)
	if err != nil {
		panic(fmt.Sprintf("NewNamespaceTable: %v", err))
	}
	return tbl
}

// newLocalNodeTable returns a writable local-node statedb table for tests.
func newLocalNodeTable(db *statedb.DB) statedb.RWTable[*node.LocalNode] {
	tbl, err := node.NewLocalNodeTable(db)
	if err != nil {
		panic(fmt.Sprintf("NewLocalNodeTable: %v", err))
	}
	return tbl
}

// newDeviceTable returns a writable device statedb table for tests.
func newDeviceTable(db *statedb.DB) statedb.RWTable[*dpTables.Device] {
	tbl, err := dpTables.NewDeviceTable(db)
	if err != nil {
		panic(fmt.Sprintf("NewDeviceTable: %v", err))
	}
	return tbl
}

// upsertPod writes a pod row to the table with the given namespace, name, and
// labels. It commits the write transaction.
func upsertPod(db *statedb.DB, tbl statedb.RWTable[k8sTables.LocalPod], namespace, name string, labels map[string]string) {
	wtxn := db.WriteTxn(tbl)
	defer wtxn.Commit()
	tbl.Insert(wtxn, k8sTables.LocalPod{
		Pod: &slim_corev1.Pod{
			ObjectMeta: slim_metav1.ObjectMeta{
				Namespace: namespace,
				Name:      name,
				Labels:    maps.Clone(labels),
			},
		},
	})
}

// upsertNamespace writes a namespace row with the given name and labels.
func upsertNamespace(db *statedb.DB, tbl statedb.RWTable[k8sTables.Namespace], name string, labels map[string]string) {
	wtxn := db.WriteTxn(tbl)
	defer wtxn.Commit()
	tbl.Insert(wtxn, k8sTables.Namespace{
		Name:   name,
		Labels: maps.Clone(labels),
	})
}

// putPod is a controller-scoped convenience wrapper around upsertPod that
// resolves the controller's read-only pod table back to its writable form.
func (c *controller) putPod(namespace, name string, labels map[string]string) {
	upsertPod(c.db, c.pods.(statedb.RWTable[k8sTables.LocalPod]), namespace, name, labels)
}

// putNamespace is the namespace-table analog of putPod.
func (c *controller) putNamespace(name string, labels map[string]string) {
	upsertNamespace(c.db, c.namespaces.(statedb.RWTable[k8sTables.Namespace]), name, labels)
}

func (c *controller) dumpLxc() map[netip.Addr]lxcmap.EndpointInfo {
	out, err := c.lxcMap.DumpToMap()
	if err != nil {
		panic(fmt.Sprintf("lxcMap.DumpToMap: %v", err))
	}
	return out
}

type fakeNetLink struct {
	links            map[string]netlink.Link
	masters          map[string]string
	linkDelErr       error
	linkSetMasterErr error
	linkSetAliasErr  error
}

func newFakeNetLink() *fakeNetLink {
	return &fakeNetLink{
		links:   map[string]netlink.Link{},
		masters: map[string]string{},
	}
}

func (f *fakeNetLink) addExisting(link netlink.Link) {
	f.links[link.Attrs().Name] = link
}

func (f *fakeNetLink) linkByName(name string) (netlink.Link, error) {
	link, ok := f.links[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", errLinkNotFound, name)
	}
	return link, nil
}

func (f *fakeNetLink) linkExists(name string) (bool, error) {
	_, ok := f.links[name]
	return ok, nil
}

func (f *fakeNetLink) linkList() ([]netlink.Link, error) {
	out := make([]netlink.Link, 0, len(f.links))
	for _, l := range f.links {
		out = append(out, l)
	}
	return out, nil
}

func (f *fakeNetLink) linkAdd(link netlink.Link) error {
	name := link.Attrs().Name
	if _, exists := f.links[name]; exists {
		return fmt.Errorf("link %q already exists", name)
	}
	f.links[name] = link
	return nil
}

func (f *fakeNetLink) linkDel(link netlink.Link) error {
	if f.linkDelErr != nil {
		return f.linkDelErr
	}
	name := link.Attrs().Name
	if _, exists := f.links[name]; !exists {
		return fmt.Errorf("%w: %s", errLinkNotFound, name)
	}
	delete(f.links, name)
	delete(f.masters, name)
	for child, master := range f.masters {
		if master == name {
			delete(f.masters, child)
		}
	}
	return nil
}

func (f *fakeNetLink) linkSetUp(link netlink.Link) error {
	return nil
}

func (f *fakeNetLink) linkSetAlias(link netlink.Link, alias string) error {
	if f.linkSetAliasErr != nil {
		return f.linkSetAliasErr
	}
	name := link.Attrs().Name
	stored, ok := f.links[name]
	if !ok {
		return fmt.Errorf("%w: %s", errLinkNotFound, name)
	}
	stored.Attrs().Alias = alias
	return nil
}

func (f *fakeNetLink) linkSetMaster(child, master netlink.Link) error {
	if f.linkSetMasterErr != nil {
		return f.linkSetMasterErr
	}
	f.masters[child.Attrs().Name] = master.Attrs().Name
	return nil
}

func (f *fakeNetLink) linkSetNoMaster(child netlink.Link) error {
	delete(f.masters, child.Attrs().Name)
	return nil
}

type fakeVRFMap struct {
	m         map[uint16]uint32
	upsertErr error
	deleteErr error
}

func newFakeVRFMap() *fakeVRFMap {
	return &fakeVRFMap{m: map[uint16]uint32{}}
}

func (f *fakeVRFMap) Get(k uint16) (uint32, error) {
	v, ok := f.m[k]
	if !ok {
		return 0, fmt.Errorf("vrf %d not found", k)
	}
	return v, nil
}

func (f *fakeVRFMap) Upsert(k uint16, v uint32) error {
	if f.upsertErr != nil {
		return f.upsertErr
	}
	f.m[k] = v
	return nil
}

func (f *fakeVRFMap) Delete(k uint16) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	delete(f.m, k)
	return nil
}

func (f *fakeVRFMap) List() (map[uint16]uint32, error) {
	return maps.Clone(f.m), nil
}

type statusCall struct {
	op        string
	entries   map[string]vrfStatusEntry
	conflicts map[string]string
}

type fakeStatusReporter struct {
	calls []statusCall
}

func newFakeStatusReporter() *fakeStatusReporter {
	return &fakeStatusReporter{}
}

func (f *fakeStatusReporter) init(_ context.Context) error {
	f.calls = append(f.calls, statusCall{op: "init"})
	return nil
}

func (f *fakeStatusReporter) setVRFStatuses(_ context.Context, batch *vrfStatusBatch) error {
	if batch == nil {
		return nil
	}
	f.calls = append(f.calls, statusCall{
		op:      "setVRFStatuses",
		entries: maps.Clone(batch.entries),
	})
	return nil
}

func (f *fakeStatusReporter) clearAllVRFStatuses(_ context.Context) error {
	f.calls = append(f.calls, statusCall{op: "clearAllVRFStatuses"})
	return nil
}

func (f *fakeStatusReporter) setMembershipConflicts(_ context.Context, conflicts map[string]string) error {
	f.calls = append(f.calls, statusCall{
		op:        "setMembershipConflicts",
		conflicts: maps.Clone(conflicts),
	})
	return nil
}

type fakeLxcMap struct {
	entries map[netip.Addr]lxcmap.EndpointInfo
}

func newFakeLxcMap() *fakeLxcMap {
	return &fakeLxcMap{entries: map[netip.Addr]lxcmap.EndpointInfo{}}
}

func (f *fakeLxcMap) setRTInfo(addr netip.Addr, rtInfo uint32) {
	if !addr.IsValid() {
		return
	}
	info := f.entries[addr]
	info.RTInfo = rtInfo
	f.entries[addr] = info
}

func (f *fakeLxcMap) WriteEndpoint(_ lxcmap.EndpointFrontend) error { return nil }
func (f *fakeLxcMap) SyncHostEntry(_ netip.Addr) (bool, error)      { return false, nil }
func (f *fakeLxcMap) DeleteEntry(addr netip.Addr) error {
	delete(f.entries, addr)
	return nil
}
func (f *fakeLxcMap) DeleteElement(_ *slog.Logger, _ lxcmap.EndpointFrontend) []error { return nil }
func (f *fakeLxcMap) Dump(_ map[string][]string) error                                { return nil }
func (f *fakeLxcMap) DumpToMap() (map[netip.Addr]lxcmap.EndpointInfo, error) {
	return maps.Clone(f.entries), nil
}

type fakeEndpoint struct {
	id            uint64
	namespace     string
	podName       string
	ipv4          netip.Addr
	ipv6          netip.Addr
	rtInfo        uint32
	rtInfoEnc     epTypes.RTInfoEncoding
	regenerations int
	regenFails    bool
	regenCoalesce bool
	lxc           *fakeLxcMap
}

func (f *fakeEndpoint) GetID() uint64                               { return f.id }
func (f *fakeEndpoint) GetK8sNamespace() string                     { return f.namespace }
func (f *fakeEndpoint) GetK8sPodName() string                       { return f.podName }
func (f *fakeEndpoint) GetRTInfo() (uint32, epTypes.RTInfoEncoding) { return f.rtInfo, f.rtInfoEnc }
func (f *fakeEndpoint) IPv4Address() netip.Addr {
	if f.ipv4.IsValid() {
		return f.ipv4
	}
	return netip.AddrFrom4([4]byte{10, 0, byte(f.id >> 8), byte(f.id)})
}
func (f *fakeEndpoint) IPv6Address() netip.Addr { return f.ipv6 }
func (f *fakeEndpoint) SetRTInfo(info uint32, t epTypes.RTInfoEncoding) {
	f.rtInfo = info
	f.rtInfoEnc = t
}
func (f *fakeEndpoint) ClearRTInfo() {
	f.rtInfo = 0
	f.rtInfoEnc = epTypes.RTInfoNone
}
func (f *fakeEndpoint) RegenerateIfAlive(_ *regeneration.ExternalRegenerationMetadata) <-chan bool {
	f.regenerations++
	ch := make(chan bool, 1)
	if f.regenCoalesce {
		close(ch)
		return ch
	}
	if f.regenFails {
		ch <- false
		close(ch)
		return ch
	}
	if f.lxc != nil {
		f.lxc.setRTInfo(f.IPv4Address(), f.rtInfo)
		f.lxc.setRTInfo(f.IPv6Address(), f.rtInfo)
	}
	ch <- true
	close(ch)
	return ch
}

type fakeEndpointSubscriber struct {
	endpoints []endpointInfo
}

func newFakeEndpointSubscriber(c *controller, endpoints ...*fakeEndpoint) *fakeEndpointSubscriber {
	lxc, _ := c.lxcMap.(*fakeLxcMap)
	infos := make([]endpointInfo, 0, len(endpoints))
	for _, ep := range endpoints {
		if lxc != nil {
			ep.lxc = lxc
		}
		infos = append(infos, ep)
	}
	return &fakeEndpointSubscriber{endpoints: infos}
}

func (f *fakeEndpointSubscriber) GetEndpoints() []endpointInfo {
	return f.endpoints
}
