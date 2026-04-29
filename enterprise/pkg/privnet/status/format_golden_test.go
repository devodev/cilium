//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package status

import (
	"fmt"
	"net/netip"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/enterprise/pkg/privnet/types"
	"github.com/cilium/cilium/pkg/safeio"
)

func TestFormatGolden(t *testing.T) {

	for _, tc := range []struct {
		name   string
		golden string
		status NodeStatus
	}{
		{
			name:   "simple INB",
			golden: "simple",
			status: NodeStatus{
				Name:    "inb-0",
				Cluster: "inb-west",
				ConnectedClusters: []ConnectedCluster{
					{
						Name: "inb-west",
						NodeNames: []types.NodeName{
							"inb-0",
						},
					},
					{
						Name: "cluster-west",
						NodeNames: []types.NodeName{
							"worker-0",
							"worker-1",
							"worker-2",
						},
					},
					{
						Name: "cluster-east",
						NodeNames: []types.NodeName{
							"worker-0",
							"worker-1",
							"worker-2",
						},
					},
				},
				Enabled: true,
				Mode:    "bridge",
				Networks: []NetworkStatus{
					{
						Name: "blue",
						Routes: []Route{
							{
								Destination: netip.MustParsePrefix("0.0.0.0/0"),
								Gateway:     netip.MustParseAddr("192.168.1.1"),
							},
						},
						Subnets: []Subnet{
							{
								CIDRv4: netip.MustParsePrefix("192.168.1.1/24"),
							},
						},
						Endpoints: []EndpointStatus{
							{
								Name:    "ep0",
								Cluster: "cluster-west",
								Node:    "worker-0",
								IPv4:    netip.MustParseAddr("10.0.0.10"),
								NetIPv4: netip.MustParseAddr("192.168.1.10"),
								Active:  true,
							},
							{
								Name:    "ep1",
								Cluster: "cluster-west",
								Node:    "worker-1",
								IPv4:    netip.MustParseAddr("10.0.0.11"),
								NetIPv4: netip.MustParseAddr("192.168.1.11"),
								Active:  false,
							},
							{
								Name:    "ep2",
								Cluster: "cluster-west",
								Node:    "worker-2",
								IPv4:    netip.MustParseAddr("10.0.0.12"),
								NetIPv4: netip.MustParseAddr("192.168.1.12"),
								Active:  true,
							},
							{
								Name:    "ep2-east",
								Cluster: "cluster-east",
								Node:    "worker-2",
								IPv4:    netip.MustParseAddr("10.0.2.12"),
								NetIPv4: netip.MustParseAddr("192.168.1.52"),
								Active:  true,
							},
							{
								Name:     "extEp",
								Cluster:  "inb-west",
								Node:     "inb-0",
								IPv4:     netip.MustParseAddr("10.0.1.10"),
								NetIPv4:  netip.MustParseAddr("192.168.1.100"),
								External: true,
							},
						},
						INBStatus: INBStatus{
							Serving: true,
							Interfaces: []Interface{
								{
									Name:  "eth0",
									Index: 45,
								},
							},
							ActiveWorkloadNodes: []WorkloadNode{
								{
									Cluster: "cluster-west",
									Name:    "worker-0",
								},
								{
									Cluster: "cluster-west",
									Name:    "worker-1",
								},
								{
									Cluster: "cluster-east",
									Name:    "worker-2",
								},
							},
						},
					},
				},
			},
		},
		{
			name:   "simple worker",
			golden: "simple-worker",
			status: NodeStatus{
				Name:    "worker-0",
				Cluster: "cluster-west",
				ConnectedClusters: []ConnectedCluster{
					{
						Name: "inb-west",
						NodeNames: []types.NodeName{
							"inb-0",
						},
					},
					{
						Name: "inb-east",
						NodeNames: []types.NodeName{
							"inb-0",
							"inb-1",
						},
					},
					{
						Name: "cluster-east",
						NodeNames: []types.NodeName{
							"worker-0",
							"worker-1",
							"worker-2",
						},
					},
				},
				Enabled: true,
				Mode:    "default",
				Networks: []NetworkStatus{
					{
						Name: "blue",
						Routes: []Route{
							{
								Destination: netip.MustParsePrefix("0.0.0.0/0"),
								Gateway:     netip.MustParseAddr("192.168.1.1"),
							},
						},
						Subnets: []Subnet{
							{
								CIDRv4: netip.MustParsePrefix("192.168.1.1/24"),
							},
						},
						Endpoints: []EndpointStatus{
							{
								Name:    "ep0",
								Cluster: "cluster-west",
								Node:    "worker-0",
								IPv4:    netip.MustParseAddr("10.0.0.10"),
								NetIPv4: netip.MustParseAddr("192.168.1.10"),
								Active:  true,
							},
							{
								Name:    "ep1",
								Cluster: "cluster-west",
								Node:    "worker-1",
								IPv4:    netip.MustParseAddr("10.0.0.11"),
								NetIPv4: netip.MustParseAddr("192.168.1.11"),
								Active:  false,
							},
							{
								Name:    "ep2",
								Cluster: "cluster-west",
								Node:    "worker-2",
								IPv4:    netip.MustParseAddr("10.0.0.12"),
								NetIPv4: netip.MustParseAddr("192.168.1.12"),
								Active:  true,
							},
							{
								Name:    "ep2-east",
								Cluster: "cluster-east",
								Node:    "worker-2",
								IPv4:    netip.MustParseAddr("10.0.2.12"),
								NetIPv4: netip.MustParseAddr("192.168.1.52"),
								Active:  true,
							},
							{
								Name:     "extEp",
								Cluster:  "inb-west",
								Node:     "inb-0",
								IPv4:     netip.MustParseAddr("10.0.1.10"),
								NetIPv4:  netip.MustParseAddr("192.168.1.100"),
								External: true,
							},
							{
								Name:     "extEp2",
								Cluster:  "inb-east",
								Node:     "inb-1",
								IPv4:     netip.MustParseAddr("10.0.6.10"),
								NetIPv4:  netip.MustParseAddr("192.168.1.100"),
								External: true,
							},
						},
						WorkerStatus: WorkerStatus{
							ActiveINB: "inb-east/inb-0",
							ConnectedINBClusters: []INBCluster{
								{
									Name: "inb-east",
									INBs: []ConnectedINB{
										{
											Cluster: "inb-east",
											Name:    "inb-0",
											Healthy: true,
											Active:  true,
										},
										{
											Cluster: "inb-east",
											Name:    "inb-1",
											Healthy: true,
										},
									},
								},
								{
									Name: "inb-west",
									INBs: []ConnectedINB{
										{
											Cluster: "inb-west",
											Name:    "inb-0",
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:   "empty worker",
			golden: "empty-worker",
			status: NodeStatus{
				Name:    "worker-0",
				Cluster: "cluster-west",
				Enabled: true,
				Mode:    "default",
			},
		},
		{
			name:   "empty inb",
			golden: "empty-inb",
			status: NodeStatus{
				Name:    "inb-0",
				Cluster: "inb-west",
				Enabled: true,
				Mode:    "bridge",
			},
		},
		{
			name:   "connected INB",
			golden: "connected-inb",
			status: NodeStatus{
				Name:    "inb-0",
				Cluster: "inb-west",
				ConnectedClusters: []ConnectedCluster{
					{
						Name: "inb-west",
						NodeNames: []types.NodeName{
							"inb-0",
						},
					},
					{
						Name: "cluster-west",
						NodeNames: []types.NodeName{
							"worker-0",
							"worker-1",
							"worker-2",
						},
					},
					{
						Name: "cluster-east",
						NodeNames: []types.NodeName{
							"worker-0",
							"worker-1",
							"worker-2",
						},
					},
				},
				Enabled: true,
				Mode:    "bridge",
			},
		},
		{
			name:   "INB without workload cluster",
			golden: "disconnected-inb",
			status: NodeStatus{
				Name:    "inb-0",
				Cluster: "inb-west",
				ConnectedClusters: []ConnectedCluster{
					{
						Name: "inb-west",
						NodeNames: []types.NodeName{
							"inb-0",
						},
					},
				},
				Enabled: true,
				Mode:    "bridge",
				Networks: []NetworkStatus{
					{
						Name: "blue",
						Routes: []Route{
							{
								Destination: netip.MustParsePrefix("0.0.0.0/0"),
								Gateway:     netip.MustParseAddr("192.168.1.1"),
							},
						},
						Subnets: []Subnet{
							{
								CIDRv4: netip.MustParsePrefix("192.168.1.1/24"),
							},
						},
						Endpoints: []EndpointStatus{
							{
								Name:     "extEp",
								Cluster:  "inb-west",
								Node:     "inb-0",
								IPv4:     netip.MustParseAddr("10.0.1.10"),
								NetIPv4:  netip.MustParseAddr("192.168.1.100"),
								External: true,
							},
						},
						INBStatus: INBStatus{
							Serving: true,
							Interfaces: []Interface{
								{
									Name:  "eth0",
									Index: 45,
								},
							},
						},
					},
				},
			},
		},
		{
			name:   "worker without inb",
			golden: "worker-no-connected-inb",
			status: NodeStatus{
				Name:    "worker-0",
				Cluster: "cluster-west",
				ConnectedClusters: []ConnectedCluster{
					{
						Name: "cluster-east",
						NodeNames: []types.NodeName{
							"worker-0",
							"worker-1",
							"worker-2",
						},
					},
				},
				Enabled: true,
				Mode:    "default",
				Networks: []NetworkStatus{
					{
						Name: "blue",
						Routes: []Route{
							{
								Destination: netip.MustParsePrefix("0.0.0.0/0"),
								Gateway:     netip.MustParseAddr("192.168.1.1"),
							},
						},
						Subnets: []Subnet{
							{
								CIDRv4: netip.MustParsePrefix("192.168.1.1/24"),
							},
						},
						Endpoints: []EndpointStatus{
							{
								Name:    "ep0",
								Cluster: "cluster-west",
								Node:    "worker-0",
								IPv4:    netip.MustParseAddr("10.0.0.10"),
								NetIPv4: netip.MustParseAddr("192.168.1.10"),
								Active:  true,
							},
							{
								Name:    "ep1",
								Cluster: "cluster-west",
								Node:    "worker-1",
								IPv4:    netip.MustParseAddr("10.0.0.11"),
								NetIPv4: netip.MustParseAddr("192.168.1.11"),
								Active:  false,
							},
							{
								Name:    "ep2",
								Cluster: "cluster-west",
								Node:    "worker-2",
								IPv4:    netip.MustParseAddr("10.0.0.12"),
								NetIPv4: netip.MustParseAddr("192.168.1.12"),
								Active:  true,
							},
							{
								Name:    "ep2-east",
								Cluster: "cluster-east",
								Node:    "worker-2",
								IPv4:    netip.MustParseAddr("10.0.2.12"),
								NetIPv4: netip.MustParseAddr("192.168.1.52"),
								Active:  true,
							},
						},
						WorkerStatus: WorkerStatus{
							ConnectedINBClusters: []INBCluster{
								{
									Name: "inb-not-exists",
								},
							},
						},
					},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.status.Format()
			want := ""

			goldenFile, err := os.OpenFile(fmt.Sprintf("testdata/format_golden/%s.golden", tc.golden), os.O_RDWR|os.O_CREATE, 0644)
			require.NoError(t, err)
			defer goldenFile.Close()

			if *update {
				require.NoError(t, goldenFile.Truncate(0))
				_, err := goldenFile.WriteString(got)
				require.NoError(t, err)
				want = got
			} else {
				raw, err := safeio.ReadAllLimit(goldenFile, 10*safeio.KB)
				require.NoError(t, err)
				want = string(raw)
			}

			require.Equalf(t, want, got, "NOTE: If the change is expected, run 'go test -update .' in 'enterprise/pkg/privnet/status'")
		})
	}
}

func TestFormatGoldenCluster(t *testing.T) {
	for _, tc := range []struct {
		name   string
		golden string
		status ClusterStatus
	}{
		{
			name:   "simple cluster",
			golden: "cluster-simple",
			status: simpleClusterStatus,
		},
		{
			name:   "cluster with conflicts",
			golden: "cluster-conflicts",
			status: clusterStatusWithConflicts,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.status.Format(true)
			want := ""

			goldenFile, err := os.OpenFile(fmt.Sprintf("testdata/format_golden/%s.golden", tc.golden), os.O_RDWR|os.O_CREATE, 0644)
			require.NoError(t, err)
			defer goldenFile.Close()

			if *update {
				require.NoError(t, goldenFile.Truncate(0))
				_, err := goldenFile.WriteString(got)
				require.NoError(t, err)
				want = got
			} else {
				raw, err := safeio.ReadAllLimit(goldenFile, 10*safeio.KB)
				require.NoError(t, err)
				want = string(raw)
			}

			require.Equalf(t, want, got, "NOTE: If the change is expected, run 'go test -update .' in 'enterprise/pkg/privnet/status'")
		})
	}
}
