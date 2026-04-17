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
	"context"
	"net/netip"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/enterprise/pkg/maps/extepspolicy"
	pnmaps "github.com/cilium/cilium/enterprise/pkg/maps/privnet"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/policymap"
)

func mockExtEPPolicyCell(t testing.TB) cell.Cell {
	t.Helper()

	return cell.Group(
		cell.Provide(
			newMockExtEpsPolicyWriter,
		),
	)
}

func newMockExtEpsPolicyWriter(m pnmaps.Map[*extepspolicy.KeyVal]) extepspolicy.Writer {
	return &mockExtEpsPolicyWriter{
		ops: m.Ops(),
	}
}

type mockExtEpsPolicyWriter struct {
	ops reconciler.Operations[*extepspolicy.KeyVal]
}

// Upsert registers a policy map for the given IP address.
func (m *mockExtEpsPolicyWriter) Upsert(ip netip.Addr, pm policymap.PolicyMap) error {
	// We rely on the fact that the injected fake reconciler operation ignores
	// the first three arguments passed to Update
	return m.ops.Update(context.Background(), nil, 0, &extepspolicy.KeyVal{
		Key: extepspolicy.Key{
			EndpointKey: bpf.NewEndpointKey(ip, 0),
		},
		Val: extepspolicy.Value{
			Fd: 0,
		},
	})
}

// Delete unregisters the policy map associated with the given IP address.
func (m *mockExtEpsPolicyWriter) Delete(ip netip.Addr) error {
	// We rely on the fact that the injected fake reconciler operation ignores
	// the first three arguments passed to Delete and ignores the value as well
	return m.ops.Delete(context.Background(), nil, 0, &extepspolicy.KeyVal{
		Key: extepspolicy.Key{
			EndpointKey: bpf.NewEndpointKey(ip, 0),
		},
	})
}

// MarkInitialized must be called when the initial set of entries has been written.
func (m *mockExtEpsPolicyWriter) MarkInitialized() {}
