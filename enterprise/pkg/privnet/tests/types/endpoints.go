//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package types

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"math"
	"net/netip"
	"slices"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/enterprise/pkg/privnet/endpoints"
	"github.com/cilium/cilium/enterprise/pkg/privnet/observers"
	epTypes "github.com/cilium/cilium/pkg/endpoint/types"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/maps/policymap"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	ciliumTypes "github.com/cilium/cilium/pkg/types"
)

// FakeEndpointEventObserver implements endpoints.EndpointEventObserver
type FakeEndpointEventObserver = observers.Generic[endpoints.EndpointID, endpoints.EndpointEventKind]

func NewFakeEndpointEventObserver() *FakeEndpointEventObserver {
	return observers.NewGeneric[endpoints.EndpointID, endpoints.EndpointEventKind]()
}

type FakeEP struct {
	mu lock.Mutex

	ID      uint16
	IfName  string
	IfIndex int

	IPv4 netip.Addr
	IPv6 netip.Addr
	MAC  mac.MAC

	PodName   string
	Namespace string

	Properties map[string]any
	Labels     labels.Labels
}

var _ endpoints.Endpoint = &FakeEP{}

// MarshalJSON the fake endpoint as an EndpointChangeRequest to match the format
// used by epm-create.
func (f *FakeEP) MarshalJSON() ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return json.Marshal(
		models.EndpointChangeRequest{
			ID:             int64(f.ID),
			InterfaceName:  f.IfName,
			InterfaceIndex: int64(f.IfIndex),
			K8sPodName:     f.PodName,
			K8sNamespace:   f.Namespace,
			Properties:     f.Properties,
			Addressing: &models.AddressPair{
				IPv4: f.GetIPv4Address(),
				IPv6: f.GetIPv6Address(),
			},
			Mac:    f.MAC.String(),
			Labels: f.Labels.GetPrintableModel(),
		},
	)
}

// GetPod implements [endpoints.Endpoint].
func (f *FakeEP) GetPod() *slim_corev1.Pod {
	return &slim_corev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      f.PodName,
			Namespace: f.Namespace,
			Labels:    f.Labels.K8sStringMap(),
		},
		Spec: slim_corev1.PodSpec{
			NodeName: nodeTypes.GetName(),
		},
	}
}

// GetID16 implements endpoints.Endpoint.
func (f *FakeEP) GetID16() uint16 {
	return f.ID
}

// HostInterface implements endpoints.Endpoint.
func (f *FakeEP) HostInterface() string {
	return f.IfName
}

// GetIfIndex implements endpoints.Endpoint.
func (f *FakeEP) GetIfIndex() int {
	return f.IfIndex
}

// IPv4Address implements endpoints.Endpoint.
func (f *FakeEP) IPv4Address() netip.Addr {
	return f.IPv4
}

// GetIPv4Address implements endpoints.Endpoint.
func (f *FakeEP) GetIPv4Address() string {
	if f.IPv4.IsValid() {
		return f.IPv4.String()
	}
	return ""
}

// IPv6Address implements endpoints.Endpoint.
func (f *FakeEP) IPv6Address() netip.Addr {
	return f.IPv6
}

// GetIPv6Address implements endpoints.Endpoint.
func (f *FakeEP) GetIPv6Address() string {
	if f.IPv6.IsValid() {
		return f.IPv6.String()
	}
	return ""
}

// GetK8sCEPName implements endpoints.Endpoint.
func (f *FakeEP) GetK8sCEPName() string {
	if cepName, ok := f.Properties[epTypes.PropertyCEPName]; ok {
		return cepName.(string)
	}
	return f.PodName
}

// GetK8sNamespaceAndCEPName implements endpoints.Endpoint.
func (f *FakeEP) GetK8sNamespaceAndCEPName() string {
	return fmt.Sprintf("%s/%s", f.Namespace, f.GetK8sCEPName())
}

// GetK8sNamespaceAndPodName implements endpoints.Endpoint.
func (f *FakeEP) GetK8sNamespaceAndPodName() string {
	return fmt.Sprintf("%s/%s", f.Namespace, f.PodName)
}

// SetK8sMetadata implements endpoints.Endpoint.
func (f *FakeEP) SetK8sMetadata(_ ciliumTypes.NamedPortMap) {
	// no-op
}

// GetPropertyValue implements endpoints.Endpoint.
func (f *FakeEP) GetPropertyValue(key string) any {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Properties == nil {
		return nil
	}
	return f.Properties[key]
}

// SetPropertyValue implements endpoints.Endpoint.
func (f *FakeEP) SetPropertyValue(key string, value any) any {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Properties == nil {
		f.Properties = map[string]any{}
	}
	f.Properties[key] = value
	return value
}

// IsProperty implements endpoints.Endpoint.
func (f *FakeEP) IsProperty(key string) bool {
	value, ok := f.GetPropertyValue(key).(bool)
	return ok && value
}

// LXCMac implements endpoints.Endpoint.
func (f *FakeEP) LXCMac() mac.MAC {
	return f.MAC
}

// SyncEndpointHeaderFile implements endpoints.Endpoint.
func (f *FakeEP) SyncEndpointHeaderFile() {}

// UpdateLabels implements endpoints.Endpoint.
func (f *FakeEP) UpdateLabels(ctx context.Context, sourceFilter string, identityLabels, infoLabels labels.Labels, blocking bool) (regenTriggered bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.Labels.RemoveFromSource(sourceFilter)
	f.Labels.MergeLabels(identityLabels)

	return false
}

// GetPolicyMap implements endpoints.Endpoint.
func (f *FakeEP) GetPolicyMap() (policymap.PolicyMap, error) {
	return nil, nil
}

// FakeEPM implements endpoints.Endpoint{Creator,Getter,Remover}
type FakeEPM struct {
	mu   lock.Mutex
	eps  []*FakeEP
	subs []endpoints.EndpointSubscriber

	observer *FakeEndpointEventObserver
}

func NewFakeEPM(observer *FakeEndpointEventObserver) *FakeEPM {
	return &FakeEPM{
		subs: []endpoints.EndpointSubscriber{},
		eps:  []*FakeEP{},

		observer: observer,
	}
}

// CreateEndpoint implements endpoints.EndpointCreator.
func (f *FakeEPM) createEndpoint(epTemplate *models.EndpointChangeRequest, restored bool) (endpoints.Endpoint, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var err error
	ep := FakeEP{
		ID:         uint16(epTemplate.ID),
		IfName:     epTemplate.InterfaceName,
		IfIndex:    int(epTemplate.InterfaceIndex),
		PodName:    epTemplate.K8sPodName,
		Namespace:  epTemplate.K8sNamespace,
		Properties: epTemplate.Properties,
		Labels:     labels.NewLabelsFromModel(epTemplate.Labels),
	}
	if epTemplate.Addressing.IPv4 != "" {
		ep.IPv4, err = netip.ParseAddr(epTemplate.Addressing.IPv4)
		if err != nil {
			return nil, err
		}
	}
	if epTemplate.Addressing.IPv6 != "" {
		ep.IPv6, err = netip.ParseAddr(epTemplate.Addressing.IPv6)
		if err != nil {
			return nil, err
		}
	}
	if epTemplate.Mac != "" {
		ep.MAC, err = mac.ParseMAC(epTemplate.Mac)
		if err != nil {
			return nil, err
		}
	}
	if ep.ID == 0 {
		// Allocate a new endpoint ID
		epID := uint16(0)
	allocateNextID:
		for {
			epID++
			if epID == math.MaxUint16 {
				return nil, fmt.Errorf("no available endpoint IDs")
			}
			for _, other := range f.eps {
				if other.ID == epID {
					continue allocateNextID
				}
			}
			break
		}
		ep.ID = epID
	}

	// Check no duplicates with endpoint ID or CEP name exist
	for _, other := range f.eps {
		if other.ID == ep.ID {
			return nil, fmt.Errorf("endpoint id %d already exists", ep.ID)
		}
		if other.GetK8sNamespaceAndCEPName() == ep.GetK8sNamespaceAndCEPName() {
			return nil, fmt.Errorf("endpoint with CEP %s already exists", ep.GetK8sNamespaceAndCEPName())
		}
	}

	f.eps = append(f.eps, &ep)
	f.observer.Queue(endpoints.EndpointCreate, endpoints.EndpointID(ep.ID))
	for _, sub := range f.subs {
		if restored {
			sub.EndpointRestored(&ep)
		} else {
			sub.EndpointCreated(&ep)
		}
	}
	f.observer.Queue(endpoints.EndpointRegenSuccess, endpoints.EndpointID(ep.ID))
	return &ep, nil
}

// CreateEndpoint implements endpoints.EndpointCreator.
func (f *FakeEPM) CreateEndpoint(ctx context.Context, epTemplate *models.EndpointChangeRequest) (endpoints.Endpoint, error) {
	ep, err := f.createEndpoint(epTemplate, false)
	return ep, err
}

// RestoreEndpoint restores an endpoint
func (f *FakeEPM) RestoreEndpoint(ctx context.Context, epTemplate *models.EndpointChangeRequest) (endpoints.Endpoint, error) {
	ep, err := f.createEndpoint(epTemplate, true)
	return ep, err
}

// RemoveEndpoint implements endpoints.EndpointRemover.
func (f *FakeEPM) RemoveEndpoint(ep endpoints.Endpoint) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	numEndpoints := len(f.eps)
	f.eps = slices.DeleteFunc(f.eps, func(fakeEP *FakeEP) bool {
		return fakeEP.GetID16() == ep.GetID16()
	})
	if len(f.eps) == numEndpoints {
		return fmt.Errorf("endpoint %d was already deleted", ep.GetID16())
	}
	f.observer.Queue(endpoints.EndpointDelete, endpoints.EndpointID(ep.GetID16()))
	for _, sub := range f.subs {
		sub.EndpointDeleted(ep)
	}
	return nil
}

// GetEndpointsByPodName implements endpoints.EndpointGetter.
func (f *FakeEPM) GetEndpointsByPodName(nsname string) iter.Seq[endpoints.Endpoint] {
	f.mu.Lock()
	eps := slices.Clone(f.eps)
	f.mu.Unlock()
	return func(yield func(endpoints.Endpoint) bool) {
		for _, ep := range eps {
			if ep.GetK8sNamespaceAndPodName() == nsname {
				if !yield(ep) {
					return
				}
			}
		}
	}
}

// GetEndpoints implements endpoints.EndpointGetter.
func (f *FakeEPM) GetEndpoints() iter.Seq[endpoints.Endpoint] {
	f.mu.Lock()
	eps := slices.Clone(f.eps)
	f.mu.Unlock()
	return func(yield func(endpoints.Endpoint) bool) {
		for _, ep := range eps {
			if !yield(ep) {
				return
			}
		}
	}
}

// LookupID implements endpoints.EndpointGetter.
func (f *FakeEPM) LookupID(id uint16) (ep endpoints.Endpoint) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.eps {
		if f.eps[i].GetID16() == id {
			return f.eps[i]
		}
	}
	return nil
}

// LookupCEPName implements endpoints.EndpointGetter.
func (f *FakeEPM) LookupCEPName(nsname string) (ep endpoints.Endpoint) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.eps {
		if f.eps[i].GetK8sNamespaceAndCEPName() == nsname {
			return f.eps[i]
		}
	}
	return nil
}

// Subscribe implements endpoints.EndpointGetter.
func (f *FakeEPM) Subscribe(s endpoints.EndpointSubscriber) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.subs = append(f.subs, s)
}
