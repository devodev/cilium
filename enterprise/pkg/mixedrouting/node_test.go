//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package mixedrouting

import (
	"fmt"
	"net"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

type op string

const (
	opUpsert = op("upsert")
	opDelete = op("delete")
)

type fakeNodeEntry struct {
	op   op
	node nodeTypes.Node
}

type fakeNodeDownstream struct {
	ops []fakeNodeEntry
}

func newFakeNodeDownstream() *fakeNodeDownstream {
	return &fakeNodeDownstream{}
}

func (fd *fakeNodeDownstream) clear() { fd.ops = nil }

func (fd *fakeNodeDownstream) NodeUpdated(node nodeTypes.Node) {
	fd.ops = append(fd.ops, fakeNodeEntry{opUpsert, node})
}

func (fd *fakeNodeDownstream) NodeDeleted(node nodeTypes.Node) {
	fd.ops = append(fd.ops, fakeNodeEntry{opDelete, node})
}

func (fd *fakeNodeDownstream) NodeSync() {}

type fakeEPMapper map[string]routingModeType

func newFakeEPMapper() fakeEPMapper                                     { return make(map[string]routingModeType) }
func (fem fakeEPMapper) setMapping(hostIP net.IP, mode routingModeType) { fem[hostIP.String()] = mode }
func (fem fakeEPMapper) unsetMapping(hostIP net.IP)                     { delete(fem, hostIP.String()) }

func toMapping(ips []string, mode routingModeType) fakeEPMapper {
	mapping := make(map[string]routingModeType)
	// Additionally include the NodeExternalIP
	for _, ip := range append(ips, "2001::beef") {
		mapping[ip] = mode
	}
	return mapping
}

func newNode(name string, modes routingModesType, internalIPs []string) *nodeTypes.Node {
	annotations := make(map[string]string)
	if len(modes) > 0 {
		annotations[SupportedRoutingModesKey] = modes.String()
	}

	addresses := []nodeTypes.Address{
		{Type: addressing.NodeCiliumInternalIP, IP: net.ParseIP("10.255.0.1")},
		{Type: addressing.NodeExternalIP, IP: net.ParseIP("2001::beef")},
	}

	for _, ip := range internalIPs {
		addresses = append(addresses, nodeTypes.Address{Type: addressing.NodeInternalIP, IP: net.ParseIP(ip)})
	}

	return &nodeTypes.Node{Name: name, Annotations: annotations, IPAddresses: addresses}
}

func TestNodeManager(t *testing.T) {
	fd := newFakeNodeDownstream()
	mgr := nodeManager{
		logger:     hivetest.Logger(t),
		modes:      routingModesType{routingModeNative, routingModeVXLAN},
		downstream: fd,
		epmapper:   newFakeEPMapper(),
	}

	ips1 := []string{"10.1.2.3", "fd00::1234"}
	ips2 := []string{"10.1.2.3", "fd00::6789"}

	no1 := *newNode("foo", []routingModeType{routingModeVXLAN}, ips1)
	no2 := *newNode("foo", []routingModeType{routingModeVXLAN}, ips2)
	no3 := *newNode("foo", []routingModeType{routingModeNative}, ips2)
	no4 := *newNode("foo", []routingModeType{routingModeNative}, ips1)

	mgr.NodeUpdated(no1)
	require.Len(t, fd.ops, 1, "Insertion should propagate to downstream")
	require.Equal(t, fakeNodeEntry{opUpsert, no1}, fd.ops[0], "Insertion should propagate to downstream")
	require.Equal(t, toMapping(ips1, routingModeVXLAN), mgr.epmapper.(fakeEPMapper), "endpoint mapping not configured correctly")
	fd.clear()

	mgr.NodeUpdated(no2)
	require.Len(t, fd.ops, 1, "Update should propagate to downstream")
	require.Equal(t, fakeNodeEntry{opUpsert, no2}, fd.ops[0], "Update should propagate to downstream")
	require.Equal(t, toMapping(ips2, routingModeVXLAN), mgr.epmapper.(fakeEPMapper), "endpoint mapping not configured correctly")
	fd.clear()

	mgr.NodeUpdated(no3)
	require.Len(t, fd.ops, 2, "Routing mode change should trigger deletion followed by insertion")
	require.Equal(t, fakeNodeEntry{opDelete, no2}, fd.ops[0], "Routing mode change should trigger deletion followed by insertion")
	require.Equal(t, fakeNodeEntry{opUpsert, no3}, fd.ops[1], "Routing mode change should trigger deletion followed by insertion")
	require.Equal(t, toMapping(ips2, routingModeNative), mgr.epmapper.(fakeEPMapper), "endpoint mapping not configured correctly")
	fd.clear()

	mgr.NodeUpdated(no4)
	require.Len(t, fd.ops, 1, "Update should propagate to downstream")
	require.Equal(t, fakeNodeEntry{opUpsert, no4}, fd.ops[0], "Update should propagate to downstream")
	require.Equal(t, toMapping(ips1, routingModeNative), mgr.epmapper.(fakeEPMapper), "endpoint mapping not configured correctly")
	fd.clear()

	mgr.NodeUpdated(no2)
	require.Len(t, fd.ops, 2, "Routing mode change should trigger deletion followed by insertion")
	require.Equal(t, fakeNodeEntry{opDelete, no4}, fd.ops[0], "Routing mode change should trigger deletion followed by insertion")
	require.Equal(t, fakeNodeEntry{opUpsert, no2}, fd.ops[1], "Routing mode change should trigger deletion followed by insertion")
	require.Equal(t, toMapping(ips2, routingModeVXLAN), mgr.epmapper.(fakeEPMapper), "endpoint mapping not configured correctly")
	fd.clear()

	mgr.NodeDeleted(no2)
	require.Len(t, fd.ops, 1, "Deletion should propagate to downstream")
	require.Equal(t, fakeNodeEntry{opDelete, no2}, fd.ops[0], "Deletion should propagate to downstream")
	require.Empty(t, mgr.epmapper.(fakeEPMapper), "endpoint mapping not reset correctly")
	fd.clear()
}

func TestNodeManagerNeedsEncapsulation(t *testing.T) {
	tests := []struct {
		local    routingModesType
		remote   routingModesType
		expected bool
	}{
		{
			local:    routingModesType{routingModeVXLAN, routingModeNative},
			expected: true,
		},
		{
			local:    routingModesType{routingModeNative},
			remote:   routingModesType{routingModeNative},
			expected: false,
		},
		{
			local:    routingModesType{routingModeNative, routingModeVXLAN},
			remote:   routingModesType{routingModeVXLAN},
			expected: true,
		},
		{
			local:    routingModesType{routingModeNative},
			remote:   routingModesType{routingModeGeneve, routingModeNative},
			expected: false,
		},
		{
			// No match is found. Although this is an error, we fallback to the
			// local primary mode, which is tunneling in this case.
			local:    routingModesType{routingModeGeneve},
			remote:   routingModesType{routingModeNative},
			expected: true,
		},
		{
			// Invalid routing mode. Although this is an error, we fallback to
			// the local primary mode, which is native in this case.
			local:    routingModesType{routingModeNative},
			remote:   routingModesType{"incorrect"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s|%s", tt.local, tt.remote), func(t *testing.T) {
			mgr := nodeManager{logger: hivetest.Logger(t), modes: tt.local}
			node := newNode("foo", tt.remote, nil)
			require.Equal(t, tt.expected, mgr.needsEncapsulation(node))
			require.Equal(t, tt.expected, mgr.ipsetFilter(node))
		})
	}
}
