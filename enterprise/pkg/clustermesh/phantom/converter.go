//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package phantom

import (
	"strings"

	enterprise_annotation "github.com/cilium/cilium/enterprise/pkg/annotation"
	"github.com/cilium/cilium/operator/watchers"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/clustermesh/store"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_discovery_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
)

func decorateClusterServiceConverter(conv watchers.ClusterServiceConverter) watchers.ClusterServiceConverter {
	return &phantomServiceConverter{conv}
}

type phantomServiceConverter struct {
	orig watchers.ClusterServiceConverter
}

// Convert implements watchers.ClusterServiceConverter.
// Mutates the service in order to make the service
// reachable in remote clusters, if it is marked to be of type phantom.
func (c *phantomServiceConverter) Convert(svc *slim_corev1.Service, getEndpointSlices func(namespace string, name string) []*slim_discovery_v1.EndpointSlice) (out *store.ClusterService, toUpsert bool, err error) {
	if !getAnnotationPhantom(svc) {
		return c.orig.Convert(svc, getEndpointSlices)
	}

	svc = svc.DeepCopy()
	svc.Annotations[annotation.SharedService] = "true"
	svc.Annotations[annotation.GlobalService] = "true"

	// Replace ClusterIPs with the LoadBalancer IPs
	svc.Spec.ClusterIP = ""
	svc.Spec.ClusterIPs = make([]string, 0, len(svc.Status.LoadBalancer.Ingress))
	for _, entry := range svc.Status.LoadBalancer.Ingress {
		if entry.IP != "" {
			svc.Spec.ClusterIPs = append(svc.Spec.ClusterIPs, entry.IP)
		}
	}
	if len(svc.Spec.ClusterIPs) > 0 {
		svc.Spec.ClusterIP = svc.Spec.ClusterIPs[0]
	} else {
		return c.orig.ForDeletion(svc), false, nil
	}

	out, toUpsert, err = c.orig.Convert(svc, getEndpointSlices)
	if err == nil {
		out.IncludeExternal = false
	}

	return
}

// ForDeletion implements watchers.ClusterServiceConverter.
func (c *phantomServiceConverter) ForDeletion(svc *slim_corev1.Service) (out *store.ClusterService) {
	return c.orig.ForDeletion(svc)
}

var _ watchers.ClusterServiceConverter = &phantomServiceConverter{}

func getAnnotationPhantom(svc *slim_corev1.Service) bool {
	// Cannot be a phantom service if it's already declared as global, or it is not of type LB.
	if annotation.GetAnnotationIncludeExternal(svc) || svc.Spec.Type != slim_corev1.ServiceTypeLoadBalancer {
		return false
	}

	if value, ok := annotation.Get(svc, enterprise_annotation.PhantomServiceKey); ok {
		return strings.ToLower(value) == "true"
	}

	return false
}
