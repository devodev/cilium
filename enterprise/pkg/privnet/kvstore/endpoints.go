//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package kvstore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"iter"
	"log/slog"
	"net/netip"
	"path"
	"slices"

	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/time"
)

// EndpointsPrefix is the kvstore prefix for the private network endpoints.
//
// WARNING - STABLE API: Changing the structure or values of this will
// break backwards compatibility
var EndpointsPrefix = path.Join(kvstore.BaseKeyPrefix, "state", "privneteps", "v1")

// Endpoint represents a single private network endpoint, for either IPv4 or IPv6.
type Endpoint struct {
	// ActivatedAt is the instant in time in which this entry was marked as active.
	ActivatedAt time.Time `json:"activatedAt,omitzero"`

	// Flags contains additional flags to characterize the entry.
	Flags Flags `json:"flags"`

	// IP is the endpoint IP from the pod network point of view.
	IP netip.Addr `json:"ip" validate:"required"`

	// The name identifying the target endpoint.
	Name string `json:"name" validate:"required,dns1123-subdomain"`

	// Network contains the identifiers from the private network point of view.
	Network Network `json:"network" validate:"required"`

	// The name of the node hosting the target endpoint. It is the name of
	// the Isovalent Network Bridge when operating in bridge mode.
	NodeName string `json:"nodeName" validate:"required,dns1123-subdomain"`

	// Source identifies the resource propagating the endpoint information.
	Source Source `json:"source" validate:"required"`

	// PreviousAddressing is an optional field containing the previous addressing information if available.
	PreviousAddressing []PreviousAddressing `json:"previousAddressing,omitempty"`
}

// Network contains the identifiers from the private network point of view.
type Network struct {
	// Name is the name of the target private network.
	Name string `json:"name" validate:"required,dns1123-subdomain"`

	// IP is the IP addresses of the endpoint.
	IP netip.Addr `json:"ip" validate:"required"`

	// MAC is the MAC address of the endpoint.
	MAC mac.MAC `json:"mac" validate:"required,len=6"`
}

// PreviousAddressing contains the previous endpoint IP if the endpoint migrated,
// which caused the endpoint IP to change.
type PreviousAddressing struct {
	// IP is the previous endpoint IP from the pod network point of view.
	IP netip.Addr `json:"ip" validate:"required"`

	// The instant in time when above address was last known to be valid.
	LastSeen time.Time `json:"lastSeen" validate:"required"`
}

// Equal returns whether two Network objects are identical.
func (n Network) Equal(other Network) bool {
	return n.Name == other.Name &&
		n.IP == other.IP &&
		bytes.Equal(n.MAC, other.MAC)
}

// Source identifies the resource propagating the endpoint information.
type Source struct {
	Cluster   string `json:"cluster" validate:"required,cluster-name"`
	Namespace string `json:"namespace" validate:"required,dns1123-label"`
	Name      string `json:"name" validate:"required,dns1123-subdomain"`
}

func (s Source) String() string {
	return s.Cluster + "/" + s.Namespace + "/" + s.Name
}

// Flags groups additional flags to characterize the endpoint entry.
type Flags struct {
	// External is set when the endpoint is external to the cluster, and the
	// advertising node provides access to it in bridge mode.
	External bool `json:"external"`
}

// GetKeyName returns the kvstore key to be used for the private network endpoint.
func (e *Endpoint) GetKeyName() string {
	// WARNING - STABLE API: Changing the structure of the key may break
	// backwards compatibility
	return path.Join(e.Source.Cluster, e.Network.Name, e.IP.String())
}

// Marshal returns the global service object as JSON byte slice
func (e *Endpoint) Marshal() ([]byte, error) {
	return json.Marshal(e)
}

// Unmarshal parses the JSON byte slice and updates the receiver
func (e *Endpoint) Unmarshal(key string, data []byte) error {
	var endpoint Endpoint

	if err := json.Unmarshal(data, &endpoint); err != nil {
		return err
	}

	if err := endpoint.validate(key); err != nil {
		return err
	}

	*e = endpoint
	return nil
}

// Equal returns whether two Endpoint objects are identical.
func (e *Endpoint) Equal(other *Endpoint) bool {
	if e == nil || other == nil {
		return e == other
	}

	return e.ActivatedAt.Equal(other.ActivatedAt) &&
		e.IP == other.IP && e.Name == other.Name &&
		e.Network.Equal(other.Network) && e.Source == other.Source &&
		e.NodeName == other.NodeName && e.Flags == other.Flags &&
		slices.Equal(e.PreviousAddressing, other.PreviousAddressing)
}

func (e *Endpoint) validate(key string) error {
	if err := validate.Struct(e); err != nil {
		return err
	}

	expected := path.Join(e.Network.Name, e.IP.String())
	if expected != key {
		return fmt.Errorf("endpoint does not match provided key: got %q, expected %q", key, expected)
	}

	return nil
}

var (
	unspecifiedIPv4String = netip.IPv4Unspecified().String()
	unspecifiedIPv6String = netip.IPv6Unspecified().String()
)

// EndpointsFromEndpointSliceEntry returns an iterator of Endpoint objects generated from the specific EndpointSlice.
func EndpointsFromEndpointSlice(logger *slog.Logger, clusterName string, slice *iso_v1alpha1.PrivateNetworkEndpointSlice) iter.Seq[*Endpoint] {
	return func(yield func(*Endpoint) bool) {
		for _, ep := range slice.Endpoints {
			newEndpoint := func(epAddr, netAddr string) (*Endpoint, error) {
				mac, err := mac.ParseMAC(ep.Interface.MAC)
				if err != nil {
					return nil, err
				}

				netAddrParsed, err := netip.ParseAddr(netAddr)
				if err != nil {
					return nil, err
				}

				epAddrParsed, err := netip.ParseAddr(epAddr)
				if err != nil {
					return nil, err
				}

				var prevAddressing []PreviousAddressing
				for _, prevAddr := range ep.Endpoint.PreviousAddressing {
					var prevAddrStr string
					if epAddrParsed.Is4() {
						prevAddrStr = prevAddr.IPv4
					} else if epAddrParsed.Is6() {
						prevAddrStr = prevAddr.IPv6
					}

					prevAddrParsed, err := netip.ParseAddr(prevAddrStr)
					if err != nil {
						return nil, err
					}
					prevAddressing = append(prevAddressing, PreviousAddressing{
						IP:       prevAddrParsed,
						LastSeen: prevAddr.LastSeen.UTC(),
					})
				}

				return &Endpoint{
					ActivatedAt: ep.ActivatedAt.Time.UTC(),

					Flags: Flags{
						External: ep.Flags.External,
					},

					IP:   epAddrParsed,
					Name: ep.Endpoint.Name,

					Network: Network{
						Name: ep.Interface.Network,
						IP:   netAddrParsed,
						MAC:  mac,
					},

					NodeName: slice.NodeName,

					Source: Source{
						Cluster:   clusterName,
						Namespace: slice.GetNamespace(),
						Name:      slice.GetName(),
					},

					PreviousAddressing: prevAddressing,
				}, nil
			}

			for _, pair := range []struct {
				epAddr, netAddr string
			}{
				{ep.Endpoint.Addressing.IPv4, ep.Interface.Addressing.IPv4},
				{ep.Endpoint.Addressing.IPv6, ep.Interface.Addressing.IPv6},
			} {
				if pair.epAddr == "" || pair.netAddr == "" ||
					pair.netAddr == unspecifiedIPv4String ||
					pair.netAddr == unspecifiedIPv6String {
					continue
				}

				endpoint, err := newEndpoint(pair.epAddr, pair.netAddr)
				if err != nil {
					logger.Warn(
						"Ignoring invalid PrivateNetworkEndpointSlice entry",
						logfields.Error, err,
						logfields.K8sNamespace, slice.Namespace,
						logfields.Name, slice.Name,
						logfields.Network, ep.Interface.Network,
					)
					continue
				}

				if !yield(endpoint) {
					return
				}
			}
		}
	}
}

// ValidatingEndpoint wraps an Endpoint to perform additional validations at
// unmarshal time.
type ValidatingEndpoint struct {
	Endpoint

	validators []endpointValidator
}

func (vn *ValidatingEndpoint) Unmarshal(key string, data []byte) error {
	if err := vn.Endpoint.Unmarshal(key, data); err != nil {
		return err
	}

	for _, validator := range vn.validators {
		if err := validator(key, &vn.Endpoint); err != nil {
			return err
		}
	}

	return nil
}

type endpointValidator func(key string, e *Endpoint) error

// EndpointClusterNameValidator returns a validator enforcing that the cluster field
// of the unmarshaled endpoint matches the provided one.
func EndpointClusterNameValidator(clusterName string) endpointValidator {
	return func(_ string, e *Endpoint) error {
		if e.Source.Cluster != clusterName {
			return fmt.Errorf("unexpected cluster name: got %q, expected %q", e.Source.Cluster, clusterName)
		}
		return nil
	}
}

// EndpointKeyCreator returns a store.KeyCreator for private network endpoints,
// configuring the specified extra validators.
func EndpointKeyCreator(validators ...endpointValidator) store.KeyCreator {
	return func() store.Key {
		return &ValidatingEndpoint{validators: validators}
	}
}
