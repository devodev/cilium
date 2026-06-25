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
	"iter"
	"log/slog"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	corev1 "k8s.io/api/core/v1"

	enterpriseannotation "github.com/cilium/cilium/enterprise/pkg/annotation"
	"github.com/cilium/cilium/pkg/clustermesh"
	pkgclustermesh "github.com/cilium/cilium/pkg/clustermesh"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/node"
)

type selectBackendsParams struct {
	cell.In

	Logger      *slog.Logger
	Writer      *writer.Writer
	Nodes       statedb.Table[*node.LocalNode]
	ClusterMesh *pkgclustermesh.ClusterMesh `optional:"true"`
}

func registerSelectBackends(p selectBackendsParams) {
	p.Writer.SetSelectBackendsFunc(newSelector(p).SelectBackends)
}

type selector struct {
	log                *slog.Logger
	writer             *writer.Writer
	nodes              statedb.Table[*node.LocalNode]
	clusterMeshEnabled bool
}

func newSelector(p selectBackendsParams) selector {
	return selector{
		log:                p.Logger,
		writer:             p.Writer,
		nodes:              p.Nodes,
		clusterMeshEnabled: p.ClusterMesh != nil,
	}
}

func (s selector) SelectBackends(txn statedb.ReadTxn, bes iter.Seq2[*loadbalancer.Backend, statedb.Revision], svc *loadbalancer.Service, fe *loadbalancer.Frontend) iter.Seq2[*loadbalancer.Backend, statedb.Revision] {
	selected := s.baseSelectBackends(txn, bes, svc, fe)
	if !isStrictSameZoneService(svc) {
		return selected
	}

	localZone, ok := s.localZone(txn)
	if !ok {
		return emptyBackends()
	}

	zonedSelected := filterBackendsWithZoneHints(selected)
	if !hasBackendForZone(zonedSelected, localZone) {
		return emptyBackends()
	}

	return filterBackendsForZone(zonedSelected, localZone)
}

func (s selector) baseSelectBackends(txn statedb.ReadTxn, bes iter.Seq2[*loadbalancer.Backend, statedb.Revision], svc *loadbalancer.Service, fe *loadbalancer.Frontend) iter.Seq2[*loadbalancer.Backend, statedb.Revision] {
	if !s.clusterMeshEnabled {
		return s.writer.DefaultSelectBackends(txn, bes, svc, fe)
	}

	return clustermesh.NewClusterMeshSelectBackends(s.writer, s.log).SelectBackends(txn, bes, svc, fe)
}

func (s selector) localZone(txn statedb.ReadTxn) (string, bool) {
	if localNode, _, found := s.nodes.Get(txn, node.LocalNodeQuery); found {
		if zone := localNode.Labels[corev1.LabelTopologyZone]; zone != "" {
			return zone, true
		}
	}
	return "", false
}

func emptyBackends() iter.Seq2[*loadbalancer.Backend, statedb.Revision] {
	return func(func(*loadbalancer.Backend, statedb.Revision) bool) {}
}

func filterBackendsWithZoneHints(backends iter.Seq2[*loadbalancer.Backend, statedb.Revision]) iter.Seq2[*loadbalancer.Backend, statedb.Revision] {
	return func(yield func(*loadbalancer.Backend, statedb.Revision) bool) {
		for be, rev := range backends {
			if be.Zone == nil || len(be.Zone.ForZones) == 0 {
				continue
			}
			if !yield(be, rev) {
				return
			}
		}
	}
}

func hasBackendForZone(backends iter.Seq2[*loadbalancer.Backend, statedb.Revision], localZone string) bool {
	for be := range backends {
		if slices.Contains(be.Zone.ForZones, localZone) {
			return true
		}
	}
	return false
}

func filterBackendsForZone(backends iter.Seq2[*loadbalancer.Backend, statedb.Revision], localZone string) iter.Seq2[*loadbalancer.Backend, statedb.Revision] {
	return func(yield func(*loadbalancer.Backend, statedb.Revision) bool) {
		for be, rev := range backends {
			if !slices.Contains(be.Zone.ForZones, localZone) {
				continue
			}
			if !yield(be, rev) {
				return
			}
		}
	}
}

func isStrictSameZoneService(svc *loadbalancer.Service) bool {
	if svc == nil || svc.Annotations == nil {
		return false
	}

	return svc.Annotations[enterpriseannotation.ServiceTrafficPolicyZone] == enterpriseannotation.ServiceTrafficPolicyZoneRequireSameZone &&
		svc.Annotations["loadbalancer.isovalent.com/type"] == "t1"
}
