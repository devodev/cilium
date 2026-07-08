// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package t2servicehealth

import (
	"testing"

	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	"github.com/stretchr/testify/require"
	k8sTypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/enterprise/pkg/lb/envoyhealthcheck"
	"github.com/cilium/cilium/pkg/ciliumenvoyconfig"
	"github.com/cilium/cilium/pkg/envoy/xds"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/time"
)

func TestComputeServiceHealthRows(t *testing.T) {
	now := time.Now()

	cec := &ciliumenvoyconfig.CEC{
		Name:             k8sTypes.NamespacedName{Namespace: "default", Name: "test"},
		SelectsLocalNode: true,
		Spec:             &ciliumv2.CiliumEnvoyConfigSpec{},
		Resources: xds.Resources{
			Clusters: map[string]*envoy_config_cluster_v3.Cluster{
				"backend_cluster_backend-a": {Name: "backend_cluster_backend-a"},
				"backend_cluster_backend-b": {Name: "backend_cluster_backend-b"},
			},
		},
	}

	rows := computeServiceHealthRows([]*ciliumenvoyconfig.CEC{cec}, []*envoyhealthcheck.HealthCheck{
		{Cluster: "backend_cluster_backend-a", Interval: 10 * time.Second, UpdatedAt: now, Healthy: true},
		{Cluster: "backend_cluster_backend-a", Interval: 10 * time.Second, UpdatedAt: now, Healthy: false},
		{Cluster: "backend_cluster_backend-b", Interval: 10 * time.Second, UpdatedAt: now, Healthy: true},
	}, false, 50)

	key := serviceHealthKey{Service: loadbalancer.NewServiceName("default", "test")}
	row, found := rows[key]
	require.True(t, found)
	require.Equal(t, "default", row.Namespace)
	require.Equal(t, "test", row.Name)
	require.True(t, row.Healthy)
	require.Equal(t, 2, row.HealthyBackends)
	require.Equal(t, 3, row.TotalBackends)
	require.Equal(t, uint32(50), row.MinHealthyPct)
}

func TestComputeServiceHealthRowsFailsClosedWhenClusterHasNoEvents(t *testing.T) {
	now := time.Now()

	cec := &ciliumenvoyconfig.CEC{
		Name:             k8sTypes.NamespacedName{Namespace: "default", Name: "test"},
		SelectsLocalNode: true,
		Spec:             &ciliumv2.CiliumEnvoyConfigSpec{},
		Resources: xds.Resources{
			Clusters: map[string]*envoy_config_cluster_v3.Cluster{
				"backend_cluster_backend-a": {Name: "backend_cluster_backend-a"},
				"backend_cluster_backend-b": {Name: "backend_cluster_backend-b"},
			},
		},
	}

	rows := computeServiceHealthRows([]*ciliumenvoyconfig.CEC{cec}, []*envoyhealthcheck.HealthCheck{
		{Cluster: "backend_cluster_backend-a", Interval: 10 * time.Second, UpdatedAt: now, Healthy: true},
	}, false, 50)

	key := serviceHealthKey{Service: loadbalancer.NewServiceName("default", "test")}
	row, found := rows[key]
	require.True(t, found)
	require.False(t, row.Healthy)
}

func TestComputeServiceHealthRowsFailsClosedWhenNodeUnschedulable(t *testing.T) {
	now := time.Now()

	cec := &ciliumenvoyconfig.CEC{
		Name:             k8sTypes.NamespacedName{Namespace: "default", Name: "test"},
		SelectsLocalNode: true,
		Spec:             &ciliumv2.CiliumEnvoyConfigSpec{},
		Resources: xds.Resources{
			Clusters: map[string]*envoy_config_cluster_v3.Cluster{
				"backend_cluster_backend-a": {Name: "backend_cluster_backend-a"},
			},
		},
	}

	rows := computeServiceHealthRows([]*ciliumenvoyconfig.CEC{cec}, []*envoyhealthcheck.HealthCheck{
		{Cluster: "backend_cluster_backend-a", Interval: 10 * time.Second, UpdatedAt: now, Healthy: true},
	}, true, 50)

	key := serviceHealthKey{Service: loadbalancer.NewServiceName("default", "test")}
	row, found := rows[key]
	require.True(t, found)
	require.False(t, row.Healthy)
}
