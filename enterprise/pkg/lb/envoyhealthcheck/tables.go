// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package envoyhealthcheck

import (
	"slices"
	"strconv"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"k8s.io/apimachinery/pkg/util/duration"

	"github.com/cilium/cilium/pkg/time"
)

// HealthCheck defines the Envoy health check cluster and it's health status.
//
// The table is populated with the health check events received by the node local Envoy instance.
// https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/health_checking#health-check-event-logging
//
// Note that the fields of this object are exported so that we can JSON marshal
// it into sysdump.
type HealthCheck struct {
	Cluster string
	Backend string
	Type    string

	// Interval is the health check interval configured on the Envoy Cluster.
	// This information is fetched from the CEC table.
	Interval time.Duration

	// UpdatedAt is when the health check configuration was last updated at
	UpdatedAt time.Time

	// Healthy is true if the backend is considered Healthy.
	Healthy bool
}

// TableHeader implements statedb.TableWritable.
func (h *HealthCheck) TableHeader() []string {
	return []string{
		"Cluster",
		"Backend",
		"Type",
		"Interval",
		"Last Updated",
		"Healthy",
	}
}

// TableRow implements statedb.TableWritable.
func (h *HealthCheck) TableRow() []string {
	return []string{
		h.Cluster,
		h.Backend,
		h.Type,
		duration.HumanDuration(h.Interval),
		duration.HumanDuration(time.Since(h.UpdatedAt)),
		strconv.FormatBool(h.Healthy),
	}
}

var _ statedb.TableWritable = &HealthCheck{}

type healthCheckKey struct {
	Cluster string
	Backend string
	Type    string
}

func (k healthCheckKey) Key() index.Key {
	return slices.Concat([]byte(k.Cluster), []byte(k.Backend), []byte(k.Type))
}

const (
	healthCheckTableName = "envoy-healthchecks"
)

var healthCheckClusterBackendIndex = statedb.Index[*HealthCheck, healthCheckKey]{
	Name: "cluster-backend-type",
	FromObject: func(obj *HealthCheck) index.KeySet {
		return index.NewKeySet(healthCheckKey{obj.Cluster, obj.Backend, obj.Type}.Key())
	},
	FromKey: healthCheckKey.Key,
	Unique:  true,
}

func newHealthCheckTable(db *statedb.DB) (statedb.RWTable[*HealthCheck], error) {
	return statedb.NewTable(
		db,
		healthCheckTableName,
		healthCheckClusterBackendIndex,
	)
}
