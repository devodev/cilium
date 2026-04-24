// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package strictzone

import (
	"context"
	"iter"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"

	enterpriseannotation "github.com/cilium/cilium/enterprise/pkg/annotation"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
)

func TestSelectBackends(t *testing.T) {
	p := fixture(t)

	sel := newSelector(selectBackendsParams{
		Writer: p.Writer,
		Nodes:  p.Nodes,
	})

	testCases := []struct {
		name             string
		localZone        string
		annotations      map[string]string
		backends         []loadbalancer.Backend
		expectedBackends []string
	}{
		{
			name:      "strict same zone keeps only same-zone backends",
			localZone: "zone-a",
			annotations: map[string]string{
				enterpriseannotation.ServiceTrafficPolicyZone: enterpriseannotation.ServiceTrafficPolicyZoneRequireSameZone,
				"loadbalancer.isovalent.com/type":             "t1",
			},
			backends: []loadbalancer.Backend{
				backend("1.0.0.1", "zone-a", []string{"zone-a"}),
				backend("1.0.0.2", "zone-b", []string{"zone-b"}),
			},
			expectedBackends: []string{"1.0.0.1"},
		},
		{
			name:      "strict same zone skips backends without zone hints",
			localZone: "zone-a",
			annotations: map[string]string{
				enterpriseannotation.ServiceTrafficPolicyZone: enterpriseannotation.ServiceTrafficPolicyZoneRequireSameZone,
				"loadbalancer.isovalent.com/type":             "t1",
			},
			backends: []loadbalancer.Backend{
				backend("1.0.0.1", "zone-a", []string{"zone-a"}),
				backend("1.0.0.2", "zone-a", nil),
			},
			expectedBackends: []string{"1.0.0.1"},
		},
		{
			name:      "strict same zone returns empty when no same-zone backends remain",
			localZone: "zone-a",
			annotations: map[string]string{
				enterpriseannotation.ServiceTrafficPolicyZone: enterpriseannotation.ServiceTrafficPolicyZoneRequireSameZone,
				"loadbalancer.isovalent.com/type":             "t1",
			},
			backends: []loadbalancer.Backend{
				backend("1.0.0.1", "zone-b", []string{"zone-b"}),
				backend("1.0.0.2", "zone-a", nil),
			},
			expectedBackends: nil,
		},
		{
			name:      "non-annotated service is unchanged",
			localZone: "zone-a",
			annotations: map[string]string{
				"loadbalancer.isovalent.com/type": "t1",
			},
			backends: []loadbalancer.Backend{
				backend("1.0.0.1", "zone-a", []string{"zone-a"}),
				backend("1.0.0.2", "zone-b", []string{"zone-b"}),
			},
			expectedBackends: []string{"1.0.0.1", "1.0.0.2"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			p.LocalNodeStore.Update(func(ln *node.LocalNode) {
				ln.Labels[corev1.LabelTopologyZone] = tc.localZone
			})

			selected := sel.SelectBackends(
				p.DB.ReadTxn(),
				backendSeq(tc.backends...),
				service(tc.annotations),
				nil,
			)
			require.Equal(t, tc.expectedBackends, selectedBackendIPsFromSeq(selected))
		})
	}
}

func TestIsStrictSameZoneService(t *testing.T) {
	testCases := []struct {
		name     string
		svc      *loadbalancer.Service
		expected bool
	}{
		{
			name:     "nil service",
			svc:      nil,
			expected: false,
		},
		{
			name:     "missing annotations",
			svc:      &loadbalancer.Service{},
			expected: false,
		},
		{
			name: "missing strict-zone annotation",
			svc: &loadbalancer.Service{
				Annotations: map[string]string{
					"loadbalancer.isovalent.com/type": "t1",
				},
			},
			expected: false,
		},
		{
			name: "missing t1 type annotation",
			svc: &loadbalancer.Service{
				Annotations: map[string]string{
					enterpriseannotation.ServiceTrafficPolicyZone: enterpriseannotation.ServiceTrafficPolicyZoneRequireSameZone,
				},
			},
			expected: false,
		},
		{
			name: "strict same-zone t1 service",
			svc: &loadbalancer.Service{
				Annotations: map[string]string{
					enterpriseannotation.ServiceTrafficPolicyZone: enterpriseannotation.ServiceTrafficPolicyZoneRequireSameZone,
					"loadbalancer.isovalent.com/type":             "t1",
				},
			},
			expected: true,
		},
		{
			name: "strict same-zone t2 service",
			svc: &loadbalancer.Service{
				Annotations: map[string]string{
					enterpriseannotation.ServiceTrafficPolicyZone: enterpriseannotation.ServiceTrafficPolicyZoneRequireSameZone,
					"loadbalancer.isovalent.com/type":             "t2",
				},
			},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, isStrictSameZoneService(tc.svc))
		})
	}
}

type testParams struct {
	cell.In

	DB             *statedb.DB
	Writer         *writer.Writer
	LocalNodeStore *node.LocalNodeStore
	Nodes          statedb.Table[*node.LocalNode]

	FrontendTable statedb.Table[*loadbalancer.Frontend]
}

func fixture(t testing.TB) (p testParams) {
	log := hivetest.Logger(t, hivetest.LogLevel(slog.LevelError))

	h := hive.New(
		loadbalancer.ConfigCell,
		node.LocalNodeStoreTestCell,
		writer.Cell,
		Cell,
		cell.Provide(
			func() cmtypes.ClusterInfo { return cmtypes.ClusterInfo{} },
			func() *option.DaemonConfig { return &option.DaemonConfig{} },
			tables.NewNodeAddressTable,
			statedb.RWTable[tables.NodeAddress].ToTable,
			source.NewSources,
			func() kpr.KPRConfig { return kpr.KPRConfig{} },
		),
		cell.Invoke(func(p_ testParams) { p = p_ }),
	)

	require.NoError(t, h.Start(log, context.TODO()))
	t.Cleanup(func() {
		require.NoError(t, h.Stop(log, context.TODO()))
	})
	return p
}

func service(annotations map[string]string) *loadbalancer.Service {
	return &loadbalancer.Service{
		Name:        loadbalancer.NewServiceName("default", "svc"),
		Source:      source.Kubernetes,
		Annotations: annotations,
	}
}

func backend(ip, zone string, forZones []string) loadbalancer.Backend {
	addrCluster := cmtypes.AddrClusterFrom(netip.MustParseAddr(ip), 0)
	be := loadbalancer.Backend{
		Address: loadbalancer.NewL3n4Addr(loadbalancer.TCP, addrCluster, 8080, loadbalancer.ScopeExternal),
		State:   loadbalancer.BackendStateActive,
	}
	if zone != "" {
		be.Zone = &loadbalancer.BackendZone{Zone: zone, ForZones: forZones}
	}
	return be
}

func backendSeq(backends ...loadbalancer.Backend) iter.Seq2[*loadbalancer.Backend, statedb.Revision] {
	return func(yield func(*loadbalancer.Backend, statedb.Revision) bool) {
		for i := range backends {
			be := backends[i]
			if !yield(&be, 0) {
				return
			}
		}
	}
}

func selectedBackendIPsFromSeq(backends iter.Seq2[*loadbalancer.Backend, statedb.Revision]) []string {
	var ips []string
	for be := range backends {
		ips = append(ips, be.Address.AddrCluster().Addr().String())
	}
	return ips
}
