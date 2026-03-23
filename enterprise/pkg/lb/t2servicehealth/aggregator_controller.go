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
	"context"
	"fmt"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	corev1 "k8s.io/api/core/v1"

	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/enterprise/pkg/lb/envoyhealthcheck"
	"github.com/cilium/cilium/pkg/ciliumenvoyconfig"
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

type aggregatorControllerParams struct {
	cell.In

	JobGroup              job.Group
	DB                    *statedb.DB
	EnvoyHealthCheckTable statedb.Table[*envoyhealthcheck.HealthCheck]
	ServiceHealthTable    statedb.RWTable[*serviceHealth]
	CECTable              statedb.Table[*ciliumenvoyconfig.CEC]
	LocalNodeResource     daemonk8s.LocalNodeResource
	Config                t2ServiceHealthConfig
}

func registerAggregatorController(params aggregatorControllerParams) {
	if !option.Config.EnableL7Proxy {
		return
	}

	controller := aggregatorController{aggregatorControllerParams: params}
	params.JobGroup.Add(job.OneShot("aggregator-controller", controller.run))
}

type aggregatorController struct {
	aggregatorControllerParams
}

func (a *aggregatorController) run(ctx context.Context, _ cell.Health) error {
	watchSet := statedb.NewWatchSet()

	for {
		watchSet.Clear()
		if err := a.reconcile(ctx, watchSet); err != nil {
			return err
		}

		if _, err := watchSet.Wait(ctx, time.Second); err != nil {
			return err
		}
	}
}

func (a *aggregatorController) reconcile(ctx context.Context, watchSet *statedb.WatchSet) error {
	rtxn := a.DB.ReadTxn()

	healthChecks, healthChecksWatch := a.EnvoyHealthCheckTable.AllWatch(rtxn)
	watchSet.Add(healthChecksWatch)

	cecs, cecsWatch := a.CECTable.AllWatch(rtxn)
	watchSet.Add(cecsWatch)

	nodeUnschedulable, err := a.localNodeUnschedulable(ctx)
	if err != nil {
		return fmt.Errorf("failed to determine local node schedulability: %w", err)
	}

	desired := computeServiceHealthRows(statedb.Collect(cecs), statedb.Collect(healthChecks), nodeUnschedulable, a.Config.MinHealthyBackendsPct)

	wtxn := a.DB.WriteTxn(a.ServiceHealthTable)
	defer wtxn.Commit()

	existing := map[serviceHealthKey]*serviceHealth{}
	for row := range a.ServiceHealthTable.All(wtxn) {
		existing[serviceHealthKey{
			Service: loadbalancer.NewServiceName(row.Namespace, row.Name),
		}] = row
	}

	for key, row := range desired {
		delete(existing, key)
		if _, _, err := a.ServiceHealthTable.Insert(wtxn, row); err != nil {
			wtxn.Abort()
			return fmt.Errorf("failed to upsert service health row: %w", err)
		}
	}

	for _, row := range existing {
		if _, _, err := a.ServiceHealthTable.Delete(wtxn, row); err != nil {
			wtxn.Abort()
			return fmt.Errorf("failed to delete stale service health row: %w", err)
		}
	}

	return nil
}

func (a *aggregatorController) localNodeUnschedulable(ctx context.Context) (bool, error) {
	store, err := a.LocalNodeResource.Store(ctx)
	if err != nil {
		return false, err
	}

	nodes := store.List()
	if len(nodes) == 0 || nodes[0] == nil {
		return false, nil
	}

	return nodeIsUnschedulable(nodes[0]), nil
}

func nodeIsUnschedulable(node *v1.Node) bool {
	for _, taint := range node.Spec.Taints {
		if taint.Key == corev1.TaintNodeUnschedulable && taint.Effect == v1.TaintEffectNoSchedule {
			return true
		}
	}
	return false
}

type clusterServiceMapping struct {
	Service loadbalancer.ServiceName
}

type clusterCounters struct {
	healthy int
	total   int
}

type serviceAggregate struct {
	service loadbalancer.ServiceName

	clusters        map[string]struct{}
	clusterCounters map[string]clusterCounters
	updatedAt       time.Time
	expiresAt       time.Time
}

func computeServiceHealthRows(cecs []*ciliumenvoyconfig.CEC, healthChecks []*envoyhealthcheck.HealthCheck, nodeUnschedulable bool, minHealthyPct uint32) map[serviceHealthKey]*serviceHealth {
	clusterMappings := collectClusterMappings(cecs)
	if len(clusterMappings) == 0 {
		return nil
	}

	serviceAggregates := map[serviceHealthKey]*serviceAggregate{}
	for clusterName, mapping := range clusterMappings {
		key := serviceHealthKey(mapping)
		agg, found := serviceAggregates[key]
		if !found {
			agg = &serviceAggregate{
				service:         mapping.Service,
				clusters:        map[string]struct{}{},
				clusterCounters: map[string]clusterCounters{},
			}
			serviceAggregates[key] = agg
		}

		agg.clusters[clusterName] = struct{}{}
	}

	for _, hc := range healthChecks {
		mapping, found := clusterMappings[hc.Cluster]
		if !found {
			continue
		}

		key := serviceHealthKey(mapping)
		agg := serviceAggregates[key]
		counters := agg.clusterCounters[hc.Cluster]
		counters.total++
		if hc.Healthy {
			counters.healthy++
		}
		agg.clusterCounters[hc.Cluster] = counters

		if agg.updatedAt.IsZero() || hc.UpdatedAt.After(agg.updatedAt) {
			agg.updatedAt = hc.UpdatedAt
		}

		expiresAt := hc.UpdatedAt.Add(hc.Interval + 5*time.Second)
		if agg.expiresAt.IsZero() || expiresAt.Before(agg.expiresAt) {
			agg.expiresAt = expiresAt
		}
	}

	rows := map[serviceHealthKey]*serviceHealth{}
	for key, agg := range serviceAggregates {
		healthy := true
		healthyBackends := 0
		totalBackends := 0

		for clusterName := range agg.clusters {
			counters, found := agg.clusterCounters[clusterName]
			if !found || counters.total == 0 {
				healthy = false
				continue
			}

			totalBackends += counters.total
			healthyBackends += counters.healthy

			if counters.healthy*100 < counters.total*int(minHealthyPct) {
				healthy = false
			}
		}

		rows[key] = &serviceHealth{
			Namespace:       agg.service.Namespace(),
			Name:            agg.service.Name(),
			Healthy:         healthy && !nodeUnschedulable,
			HealthyBackends: healthyBackends,
			TotalBackends:   totalBackends,
			MinHealthyPct:   minHealthyPct,
			UpdatedAt:       agg.updatedAt,
			ExpiresAt:       agg.expiresAt,
		}
	}

	return rows
}

func collectClusterMappings(cecs []*ciliumenvoyconfig.CEC) map[string]clusterServiceMapping {
	clusterMappings := map[string]clusterServiceMapping{}

	for _, cec := range cecs {
		if cec == nil || !cec.SelectsLocalNode || cec.Spec == nil {
			continue
		}

		serviceName := loadbalancer.NewServiceName(cec.Name.Namespace, cec.Name.Name)
		clusterNames := collectClusterNames(cec)
		if len(clusterNames) == 0 {
			continue
		}

		for clusterName := range clusterNames {
			clusterMappings[clusterName] = clusterServiceMapping{Service: serviceName}
		}
	}

	return clusterMappings
}

func collectClusterNames(cec *ciliumenvoyconfig.CEC) map[string]struct{} {
	clusterNames := map[string]struct{}{}
	for _, cluster := range cec.Resources.Clusters {
		if cluster == nil || cluster.Name == "" {
			continue
		}

		// filter out non-backend clusters (e.g. JWKS)
		name := cluster.Name
		if idx := strings.LastIndexByte(name, '/'); idx >= 0 {
			name = name[idx+1:]
		}
		if !strings.HasPrefix(name, "backend_cluster_") {
			continue
		}
		clusterNames[cluster.Name] = struct{}{}
	}
	return clusterNames
}
