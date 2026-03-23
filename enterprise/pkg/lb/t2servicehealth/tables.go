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
	"slices"
	"strconv"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"k8s.io/apimachinery/pkg/util/duration"

	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/time"
)

type serviceHealth struct {
	Namespace       string
	Name            string
	Healthy         bool
	HealthyBackends int
	TotalBackends   int
	MinHealthyPct   uint32
	UpdatedAt       time.Time
	ExpiresAt       time.Time
}

func (*serviceHealth) TableHeader() []string {
	return []string{
		"Namespace",
		"Name",
		"Healthy",
		"HealthyBackends",
		"TotalBackends",
		"MinHealthyPct",
		"Last Updated",
		"Expires In",
	}
}

func (s *serviceHealth) TableRow() []string {
	return []string{
		s.Namespace,
		s.Name,
		strconv.FormatBool(s.Healthy),
		strconv.Itoa(s.HealthyBackends),
		strconv.Itoa(s.TotalBackends),
		strconv.FormatUint(uint64(s.MinHealthyPct), 10),
		duration.HumanDuration(time.Since(s.UpdatedAt)),
		duration.HumanDuration(time.Until(s.ExpiresAt)),
	}
}

var _ statedb.TableWritable = &serviceHealth{}

type serviceHealthKey struct {
	Service loadbalancer.ServiceName
}

func (k serviceHealthKey) Key() index.Key {
	return slices.Clone(k.Service.Key())
}

const (
	serviceHealthTableName = "ilb-t2-service-health"
)

var (
	serviceHealthPrimaryIndex = statedb.Index[*serviceHealth, serviceHealthKey]{
		Name: "service",
		FromObject: func(obj *serviceHealth) index.KeySet {
			return index.NewKeySet(serviceHealthKey{
				Service: loadbalancer.NewServiceName(obj.Namespace, obj.Name),
			}.Key())
		},
		FromKey: serviceHealthKey.Key,
		Unique:  true,
	}
)

func newServiceHealthTable(db *statedb.DB) (statedb.RWTable[*serviceHealth], error) {
	return statedb.NewTable(
		db,
		serviceHealthTableName,
		serviceHealthPrimaryIndex,
	)
}

type remoteServiceHealth struct {
	TargetAddr string
	Namespace  string
	Name       string
	Healthy    bool
	ExpiresAt  time.Time
}

func (*remoteServiceHealth) TableHeader() []string {
	return []string{
		"TargetAddr",
		"Namespace",
		"Name",
		"Healthy",
		"Expires In",
	}
}

func (s *remoteServiceHealth) TableRow() []string {
	return []string{
		s.TargetAddr,
		s.Namespace,
		s.Name,
		strconv.FormatBool(s.Healthy),
		duration.HumanDuration(time.Until(s.ExpiresAt)),
	}
}

var _ statedb.TableWritable = &remoteServiceHealth{}

type remoteServiceHealthKey struct {
	TargetAddr string
	Service    loadbalancer.ServiceName
}

func (k remoteServiceHealthKey) Key() index.Key {
	return append(index.String(k.TargetAddr), serviceHealthKey{Service: k.Service}.Key()...)
}

type remoteServiceHealthTargetKey struct {
	TargetAddr string
}

func (k remoteServiceHealthTargetKey) Key() index.Key {
	return index.String(k.TargetAddr)
}

const remoteServiceHealthTableName = "ilb-t2-remote-service-health"

var (
	remoteServiceHealthPrimaryIndex = statedb.Index[*remoteServiceHealth, remoteServiceHealthKey]{
		Name: "target-service",
		FromObject: func(obj *remoteServiceHealth) index.KeySet {
			return index.NewKeySet(remoteServiceHealthKey{
				TargetAddr: obj.TargetAddr,
				Service:    loadbalancer.NewServiceName(obj.Namespace, obj.Name),
			}.Key())
		},
		FromKey: remoteServiceHealthKey.Key,
		Unique:  true,
	}
	remoteServiceHealthTargetIndex = statedb.Index[*remoteServiceHealth, remoteServiceHealthTargetKey]{
		Name: "target",
		FromObject: func(obj *remoteServiceHealth) index.KeySet {
			return index.NewKeySet(remoteServiceHealthTargetKey{TargetAddr: obj.TargetAddr}.Key())
		},
		FromKey: remoteServiceHealthTargetKey.Key,
		Unique:  false,
	}
)

func newRemoteServiceHealthTable(db *statedb.DB) (statedb.RWTable[*remoteServiceHealth], error) {
	return statedb.NewTable(
		db,
		remoteServiceHealthTableName,
		remoteServiceHealthPrimaryIndex,
		remoteServiceHealthTargetIndex,
	)
}
