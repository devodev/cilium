//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package endpoints

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"net/netip"
	"strconv"

	"github.com/cilium/hive/cell"
	"github.com/cilium/stream"
	k8sTypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/enterprise/pkg/privnet/addressing"
	"github.com/cilium/cilium/enterprise/pkg/privnet/observers"
	"github.com/cilium/cilium/enterprise/pkg/privnet/types"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/ipam"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/time"
	ciliumTypes "github.com/cilium/cilium/pkg/types"
)

// EndpointGetter allows read operations on the endpoint manager.
// This is a custom interface to allow for slim mock implementations.
type EndpointGetter interface {
	Subscribe(s EndpointSubscriber)

	LookupID(id uint16) (ep Endpoint)
	LookupCEPName(nsname string) (ep Endpoint)

	GetEndpoints() iter.Seq[Endpoint]
	GetEndpointsByPodName(nsname string) iter.Seq[Endpoint]
}

// EndpointRemover allows the removal of endpoints on the endpoint manager.
// This is a custom interface to allow for slim mock implementations.
type EndpointRemover interface {
	RemoveEndpoint(ep Endpoint) error
}

// EndpointCreator allows the creation of endpoints on the endpoint manager.
// This is a custom interface to allow for slim mock implementations.
type EndpointCreator interface {
	CreateEndpoint(ctx context.Context, epTemplate *models.EndpointChangeRequest) (Endpoint, error)
}

// Endpoint provides a subset of endpoint methods.
// This is a custom interface to allow for slim mock implementations.
type Endpoint interface {
	GetID16() uint16

	GetPropertyValue(key string) any
	SetPropertyValue(key string, value any) any
	IsProperty(key string) bool
	GetPod() *slim_corev1.Pod

	LXCMac() mac.MAC
	IPv4Address() netip.Addr
	GetIPv4Address() string
	IPv6Address() netip.Addr
	GetIPv6Address() string

	HostInterface() string
	GetIfIndex() int

	GetK8sNamespaceAndCEPName() string
	GetK8sNamespaceAndPodName() string
	SetK8sMetadata(namedPorts ciliumTypes.NamedPortMap)

	SyncEndpointHeaderFile()

	GetPolicyMap() (policymap.PolicyMap, error)
	UpdateLabels(ctx context.Context, sourceFilter string, identityLabels, infoLabels labels.Labels, blocking bool) (regenTriggered bool)
}

// EndpointSubscriber is endpointmanager.Subscriber but using the slim interfaces
// defined in this package.
type EndpointSubscriber interface {
	EndpointCreated(ep Endpoint)
	EndpointDeleted(ep Endpoint)
	EndpointRestored(ep Endpoint)
}

// RestorationNotifier is endpointstate.RestorationNotifier but using the slim interfaces
// defined in this package
type RestorationNotifier interface {
	RestorationNotify(possible iter.Seq[Endpoint])
}

// RestorationNotifierOut is used to provide a slim RestorationNotifier
type RestorationNotifierOut struct {
	cell.Out

	Restorer RestorationNotifier `group:"privnet-endpoint-restoration-notifiers"`
}

// EndpointPropertyProvider allows access to the endpoint properties.
// This is a custom interface to allow for slim mock implementations.
type EndpointPropertyProvider interface {
	GetPropertyValue(key string) any
}

// EndpointProperties is a type proxy for accessing the properties of an endpoint.
type EndpointProperties struct {
	network string
	subnet  string
	ep      EndpointPropertyProvider
}

// ExtractEndpointProperties extracts the private network relevant endpoint properties.
// It returns (nil, false) if the given endpoint is not attached to a private network.
func ExtractEndpointProperties(ep EndpointPropertyProvider) (*EndpointProperties, bool) {
	network, ok := ep.GetPropertyValue(types.PropertyPrivNetNetwork).(string)
	if !ok || network == "" {
		return nil, false
	}

	subnet, _ := ep.GetPropertyValue(types.PropertyPrivNetSubnet).(string)

	return &EndpointProperties{
		network: network,
		subnet:  subnet,
		ep:      ep,
	}, true
}

// PrivateNetwork returns the name of the private network this endpoint is attached to
func (p *EndpointProperties) PrivateNetwork() string {
	return p.network
}

// PrivateSubnet returns the name of the private network subnet this endpoint is attached to.
func (p *EndpointProperties) PrivateSubnet() string {
	return p.subnet
}

// NetworkIPv4 returns the IPv4 address of the endpoint within the network.
func (p *EndpointProperties) NetworkIPv4() (netip.Addr, error) {
	addr, ok := p.ep.GetPropertyValue(types.PropertyPrivNetIPv4).(string)
	if !ok || addr == "" {
		return netip.Addr{}, nil
	}

	ipv4, err := netip.ParseAddr(addr)
	if err != nil {
		return netip.Addr{}, err
	} else if !ipv4.Is4() {
		return netip.Addr{}, fmt.Errorf("expected IPv4 address, got %s", addr)
	}

	return ipv4, nil
}

// NetworkIPv4UsesDHCP returns whether the endpoint was configured to obtain its
// IPv4 address via DHCP.
func (p *EndpointProperties) NetworkIPv4UsesDHCP() bool {
	usesDHCP, ok := p.ep.GetPropertyValue(types.PropertyPrivNetIPv4UsesDHCP).(bool)
	if !ok {
		// The property is missing which implies that the endpoint was created
		// before this property was added and thus we don't know whether or not
		// it used DHCP, thus lean on the safe side and allow it.
		return true
	}
	return usesDHCP
}

// NetworkIPv6 returns the IPv6 address of the endpoint within the network.
func (p *EndpointProperties) NetworkIPv6() (netip.Addr, error) {
	addr, ok := p.ep.GetPropertyValue(types.PropertyPrivNetIPv6).(string)
	if !ok || addr == "" {
		return netip.Addr{}, nil
	}

	ipv6, err := netip.ParseAddr(addr)
	if err != nil {
		return netip.Addr{}, err
	} else if !ipv6.Is6() {
		return netip.Addr{}, fmt.Errorf("expected IPv6 address, got %s", addr)
	}

	return ipv6, nil
}

// ActivatedAt returns the timestamp when the endpoint became active.
func (p *EndpointProperties) ActivatedAt() (time.Time, error) {
	datetime, ok := p.ep.GetPropertyValue(types.PropertyPrivNetActivatedAt).(string)
	if !ok {
		return time.Time{}, nil
	}

	return time.Parse(time.RFC3339Nano, datetime)
}

func (p *EndpointProperties) NICIndex() (uint8, error) {
	idxstr, ok := p.ep.GetPropertyValue(types.PropertyPrivNetNICIndex).(string)
	if !ok {
		// The property is missing which implies that the endpoint was created
		// before this property was added and thus we don't know its NIC index.
		// Lean on the safe side and treat it as primary.
		return 0, nil
	}

	idx, err := strconv.ParseUint(idxstr, 10, 8)
	if err != nil {
		return 0, fmt.Errorf("parsing NIC index property: %w", err)
	}

	if idx > addressing.MaxSecondaryInterfaces {
		return 0, fmt.Errorf("parsing NIC index property: at most %d secondary interfaces are supported", addressing.MaxSecondaryInterfaces)
	}

	return uint8(idx), nil
}

func (p *EndpointProperties) PreviousAddressing() ([]types.PreviousAddressing, error) {
	str, ok := p.ep.GetPropertyValue(types.PropertyPrivNetPrevAddressing).(string)
	if !ok {
		return nil, nil
	}

	var prevAddrs []types.PreviousAddressing
	err := json.Unmarshal([]byte(str), &prevAddrs)
	if err != nil {
		return nil, err
	}
	return prevAddrs, nil
}

// EndpointPropertyManager allows reconcilers to change dynamic privnet-specific
// endpoint properties and allows them to subscribe to changes to said properties.
type EndpointPropertyManager struct {
	subscribers []endpointPropertySubscriber
}

// newEndpointPropertyManager creates a new EndpointPropertyManager
func newEndpointPropertyManager() *EndpointPropertyManager {
	return &EndpointPropertyManager{
		subscribers: []endpointPropertySubscriber{},
	}
}

type endpointPropertySubscriber interface {
	EndpointPropertyChanged(string, Endpoint)
}

// Subscribe is used to subscribe to changes to endpoint activation done via this manager.
// Must only be called at Hive construction time.
func (e *EndpointPropertyManager) Subscribe(subscriber endpointPropertySubscriber) {
	e.subscribers = append(e.subscribers, subscriber)
}

// SetActivatedAt sets the activatedAt timestamp of an endpoint and informs the subscribers
func (e *EndpointPropertyManager) SetActivatedAt(ep Endpoint, time time.Time) {
	ep.SetPropertyValue(types.PropertyPrivNetActivatedAt, FormatActivatedAtProperty(time))
	ep.SyncEndpointHeaderFile() // ensure the new activatedAt timestamp is persisted on disk
	for _, subscriber := range e.subscribers {
		subscriber.EndpointPropertyChanged(types.PropertyPrivNetActivatedAt, ep)
	}
}

// SetPreviousAddressing sets the previous addressing for this endpoint
func (e *EndpointPropertyManager) SetPreviousAddressing(ep Endpoint, prevAddr []types.PreviousAddressing) {
	str, _ := json.Marshal(prevAddr)
	ep.SetPropertyValue(types.PropertyPrivNetPrevAddressing, string(str))
	ep.SyncEndpointHeaderFile()
	for _, subscriber := range e.subscribers {
		subscriber.EndpointPropertyChanged(types.PropertyPrivNetPrevAddressing, ep)
	}
}

// FormatActivatedAtProperty is a helper to be used to format the PropertyPrivNetActivatedAt property.
func FormatActivatedAtProperty(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

type EndpointEventKind string

const (
	// EndpointCreate is emitted when a new endpoint was created
	EndpointCreate EndpointEventKind = "endpoint-create"
	// EndpointDelete is emitted when an endpoint was deleted
	EndpointDelete EndpointEventKind = "endpoint-delete"
	// EndpointRegenSuccess is emitted when an endpoint has successfully regenerated
	EndpointRegenSuccess EndpointEventKind = "regenerate-success"
	// EndpointRegenFailure is emitted when an endpoint has failed to regenerate
	EndpointRegenFailure EndpointEventKind = "regenerate-failure"
	// EndpointInitRegenAllDone is emitted when the initial endpoint regeneration has
	// finished for all restored endpoints (emitted EndpointID is 0 for this event)
	EndpointInitRegenAllDone EndpointEventKind = "initial-regeneration-all-done"
)

type EndpointID uint16

type EndpointEventObserver stream.Observable[observers.Events[EndpointID, EndpointEventKind]]
type EndpointEvents = observers.Events[EndpointID, EndpointEventKind]

// IPAM provides a subset of the IPAM allocator
type IPAM interface {
	ReleaseIP(ip netip.Addr, poolDefault ipam.Pool) error
	AllocateIPWithoutSyncUpstream(ip netip.Addr, owner string, pool ipam.Pool) (*ipam.AllocationResult, error)
	AllocateNext(family, owner string, poolDefault ipam.Pool) (ipv4Result, ipv6Result *ipam.AllocationResult, err error)
}

// CEPOwner implements CEPOwnerInterface for. It is also serialized as JSON to disk, so the format needs to be stable.
type CEPOwner struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`

	Namespace string       `json:"namespace"`
	Name      string       `json:"name"`
	UID       k8sTypes.UID `json:"uid"`

	Labels map[string]string `json:"labels"`
	HostIP string            `json:"hostIP"`
}

var _ endpoint.CEPOwnerInterface = CEPOwner{}

func (c CEPOwner) IsNil() bool {
	return false
}

func (c CEPOwner) GetAPIVersion() string {
	return c.APIVersion
}

func (c CEPOwner) GetKind() string {
	return c.Kind
}

func (c CEPOwner) GetNamespace() string {
	return c.Namespace
}

func (c CEPOwner) GetName() string {
	return c.Name
}

func (c CEPOwner) GetLabels() map[string]string {
	return c.Labels
}

func (c CEPOwner) GetUID() k8sTypes.UID {
	return c.UID
}

func (c CEPOwner) GetHostIP() string {
	return c.HostIP
}
