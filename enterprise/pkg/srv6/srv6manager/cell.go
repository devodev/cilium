//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package srv6manager

import (
	"net/netip"

	"github.com/cilium/hive/cell"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/ipam"
	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/option"
)

var Cell = cell.Module(
	"srv6-manager",
	"SRv6 DataPath Manager",

	cell.ProvidePrivate(
		// Decouple IP allocator from IPAM implementation for tests
		newIPAllocator,
	),

	// The Controller which is the entry point of the module
	cell.Provide(
		NewSRv6Manager,
		newIsovalentVRFResource,
	),

	cell.ProvidePrivate(
		newIsovalentSRv6EgressPolicyResource,
	),

	// Force instantiation of SRv6Manager and override DaemonConfig
	cell.Invoke(func(m *Manager, dc *option.DaemonConfig) {
		if m != nil {
			// Override DaemonConfig to enforce attaching BPF program to
			// native devices. This is required for SRv6 decapsulation
			// handling.
			dc.ForceDeviceRequired = true
		}
	}),
)

func newIsovalentVRFResource(lc cell.Lifecycle, dc *option.DaemonConfig, cs client.Clientset, mp workqueue.MetricsProvider, opts ...func(*metav1.ListOptions)) (resource.Resource[*iso_v1alpha1.IsovalentVRF], error) {
	if !cs.IsEnabled() || !dc.EnableSRv6 {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*iso_v1alpha1.IsovalentVRFList](cs.IsovalentV1alpha1().IsovalentVRFs()),
		opts...,
	)
	return resource.New[*iso_v1alpha1.IsovalentVRF](lc, lw, mp, resource.WithMetric("IsovalentVRFResource")), nil
}

func newIsovalentSRv6EgressPolicyResource(lc cell.Lifecycle, dc *option.DaemonConfig, cs client.Clientset, mp workqueue.MetricsProvider, opts ...func(*metav1.ListOptions)) (resource.Resource[*iso_v1alpha1.IsovalentSRv6EgressPolicy], error) {
	if !cs.IsEnabled() || !dc.EnableSRv6 {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*iso_v1alpha1.IsovalentSRv6EgressPolicyList](cs.IsovalentV1alpha1().IsovalentSRv6EgressPolicies()),
		opts...,
	)
	return resource.New[*iso_v1alpha1.IsovalentSRv6EgressPolicy](lc, lw, mp, resource.WithMetric("IsovalentSRv6EgressPolicyResource")), nil
}

func newIPAllocator(ipam *ipam.IPAM) sidIPAllocator {
	return &sidIPAMWrapper{
		ipam: ipam,
	}
}

const (
	ownerName = "srv6-manager"
)

type sidIPAMWrapper struct {
	ipam *ipam.IPAM
}

// AllocateNext implements sidIPAllocator.
func (s *sidIPAMWrapper) AllocateNext() (*ipam.AllocationResult, error) {
	_, ipv6Result, err := s.ipam.AllocateNext("ipv6", ownerName, "")
	return ipv6Result, err
}

// Release implements sidIPAllocator.
func (s *sidIPAMWrapper) Release(ip netip.Addr) error {
	return s.ipam.ReleaseIP(ip, "")
}

type sidIPAllocator interface {
	// Release releases a previously allocated IP or fails
	Release(ip netip.Addr) error

	// AllocateNext allocates the next available IP or fails if no more IPs
	// are available
	AllocateNext() (*ipam.AllocationResult, error)
}
