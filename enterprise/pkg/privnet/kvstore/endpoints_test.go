//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package kvstore_test

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/enterprise/pkg/privnet/kvstore"
	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/mac"
)

func TestEndpointEqual(t *testing.T) {
	m, err := mac.ParseMAC("00:11:22:33:44:55")
	require.NoError(t, err, "mac.ParseMAC")

	ep := kvstore.Endpoint{
		ActivatedAt: time.Now().UTC(),
		IP:          netip.MustParseAddr("1.2.3.4"),
		Name:        "name",
		Network: kvstore.Network{
			Name: "blue",
			IP:   netip.MustParseAddr("5.6.7.8"),
			MAC:  m,
		},
		NodeName: "node",
		Source:   kvstore.Source{Cluster: "foo", Namespace: "bar", Name: "baz"},
	}

	tests := []struct {
		name   string
		a, b   *kvstore.Endpoint
		assert assert.BoolAssertionFunc
	}{
		{
			name:   "both nil",
			assert: assert.True,
		},
		{
			name:   "only a nil",
			b:      &kvstore.Endpoint{},
			assert: assert.False,
		},
		{
			name:   "only b nil",
			a:      &kvstore.Endpoint{},
			assert: assert.False,
		},
		{
			name:   "same endpoint",
			a:      ptr.To(ep),
			b:      ptr.To(ep),
			assert: assert.True,
		},
		{
			name: "different ActivatedAt",
			a:    &ep,
			b: func(cpy kvstore.Endpoint) *kvstore.Endpoint {
				cpy.ActivatedAt = cpy.ActivatedAt.Add(1 * time.Second)
				return &cpy
			}(ep),
			assert: assert.False,
		},
		{
			name: "different Flags",
			a:    &ep,
			b: func(cpy kvstore.Endpoint) *kvstore.Endpoint {
				cpy.Flags.External = true
				return &cpy
			}(ep),
			assert: assert.False,
		},
		{
			name: "different IP",
			a:    &ep,
			b: func(cpy kvstore.Endpoint) *kvstore.Endpoint {
				cpy.IP = netip.MustParseAddr("1.2.3.5")
				return &cpy
			}(ep),
			assert: assert.False,
		},
		{
			name: "different Network",
			a:    &ep,
			b: func(cpy kvstore.Endpoint) *kvstore.Endpoint {
				m, err := mac.ParseMAC("00:11:22:33:44:66")
				require.NoError(t, err, "mac.ParseMAC")
				cpy.Network.MAC = m
				return &cpy
			}(ep),
			assert: assert.False,
		},
		{
			name: "different NodeName",
			a:    &ep,
			b: func(cpy kvstore.Endpoint) *kvstore.Endpoint {
				cpy.NodeName = "other"
				return &cpy
			}(ep),
			assert: assert.False,
		},
		{
			name: "different source",
			a:    &ep,
			b: func(cpy kvstore.Endpoint) *kvstore.Endpoint {
				cpy.Source.Namespace = "other"
				return &cpy
			}(ep),
			assert: assert.False,
		},
		{
			name: "different previous addressing",
			a:    &ep,
			b: func(cpy kvstore.Endpoint) *kvstore.Endpoint {
				cpy.PreviousAddressing = []kvstore.PreviousAddressing{
					{IP: netip.MustParseAddr("1.2.3.4"), LastSeen: time.Now().UTC()},
				}
				return &cpy
			}(ep),
			assert: assert.False,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.assert(t, tt.a.Equal(tt.b))
		})
	}
}

func TestEndpointMarshalUnmarshal(t *testing.T) {
	m, err := mac.ParseMAC("00:11:22:33:44:55")
	require.NoError(t, err, "mac.ParseMAC")

	ep := kvstore.Endpoint{
		ActivatedAt: time.Now().UTC(),
		Flags:       kvstore.Flags{External: true},
		IP:          netip.MustParseAddr("1.2.3.4"),
		Name:        "name",
		Network: kvstore.Network{
			Name: "blue",
			IP:   netip.MustParseAddr("5.6.7.8"),
			MAC:  m,
		},
		NodeName: "node",
		Source:   kvstore.Source{Cluster: "foo", Namespace: "bar", Name: "baz"},
	}

	tests := []struct {
		name     string
		endpoint kvstore.Endpoint
		key      string
		cname    string
		errstr   string
	}{
		{
			name:     "valid endpoint (with activatedAt)",
			endpoint: ep,
			key:      "blue/1.2.3.4",
			cname:    "foo",
		},
		{
			name: "valid endpoint (without activatedAt)",
			endpoint: func() kvstore.Endpoint {
				cpy := ep
				cpy.ActivatedAt = time.Time{}
				return cpy
			}(),
			key:   "blue/1.2.3.4",
			cname: "foo",
		},
		{
			name:     "mismatching cluster name",
			endpoint: ep,
			key:      "blue/1.2.3.4",
			cname:    "other",
			errstr:   "unexpected cluster name: got \"foo\", expected \"other\"",
		},
		{
			name:     "mismatching key",
			endpoint: ep,
			key:      "green/1.2.3.4",
			cname:    "other",
			errstr:   "endpoint does not match provided key: got \"green/1.2.3.4\", expected \"blue/1.2.3.4\"",
		},
		{
			name: "missing IP address",
			endpoint: func() kvstore.Endpoint {
				cpy := ep
				cpy.IP = netip.Addr{}
				return cpy
			}(),
			key:    "blue/1.2.3.4",
			cname:  "foo",
			errstr: "Key: 'Endpoint.IP' Error:Field validation for 'IP' failed on the 'required' tag",
		},
		{
			name: "invalid endpoint name",
			endpoint: func() kvstore.Endpoint {
				cpy := ep
				cpy.Name = ".^."
				return cpy
			}(),
			key:    "blue/1.2.3.4",
			cname:  "foo",
			errstr: "Key: 'Endpoint.Name' Error:Field validation for 'Name' failed on the 'dns1123-subdomain' tag",
		},
		{
			name: "missing and invalid network information",
			endpoint: func() kvstore.Endpoint {
				cpy := ep
				cpy.Network.Name = "-_-"
				cpy.Network.IP = netip.Addr{}
				cpy.Network.MAC = mac.MAC{}
				return cpy
			}(),
			key:    "blue/1.2.3.4",
			cname:  "foo",
			errstr: "Key: 'Endpoint.Network.Name' Error:Field validation for 'Name' failed on the 'dns1123-subdomain' tag\nKey: 'Endpoint.Network.IP' Error:Field validation for 'IP' failed on the 'required' tag\nKey: 'Endpoint.Network.MAC' Error:Field validation for 'MAC' failed on the 'len' tag",
		},
		{
			name: "invalid node name",
			endpoint: func() kvstore.Endpoint {
				cpy := ep
				cpy.NodeName = "-_-"
				return cpy
			}(),
			key:    "blue/1.2.3.4",
			cname:  "foo",
			errstr: "Key: 'Endpoint.NodeName' Error:Field validation for 'NodeName' failed on the 'dns1123-subdomain' tag",
		},
		{
			name: "missing source information",
			endpoint: func() kvstore.Endpoint {
				cpy := ep
				cpy.Source = kvstore.Source{}
				return cpy
			}(),
			key:    "blue/1.2.3.4",
			cname:  "foo",
			errstr: "Key: 'Endpoint.Source' Error:Field validation for 'Source' failed on the 'required' tag",
		},
		{
			name: "invalid source information",
			endpoint: func() kvstore.Endpoint {
				cpy := ep
				cpy.Source = kvstore.Source{
					Cluster:   "in/valid",
					Namespace: "not-|valid",
					Name:      "wrong--",
				}
				return cpy
			}(),
			key:    "blue/1.2.3.4",
			cname:  "foo",
			errstr: "Key: 'Endpoint.Source.Cluster' Error:Field validation for 'Cluster' failed on the 'cluster-name' tag\nKey: 'Endpoint.Source.Namespace' Error:Field validation for 'Namespace' failed on the 'dns1123-label' tag\nKey: 'Endpoint.Source.Name' Error:Field validation for 'Name' failed on the 'dns1123-subdomain' tag",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.endpoint.Marshal()
			require.NoError(t, err, "endpoint.Marshal")

			got := kvstore.EndpointKeyCreator(kvstore.EndpointClusterNameValidator(tt.cname))()
			err = got.Unmarshal(tt.key, data)
			if tt.errstr != "" {
				require.EqualError(t, err, tt.errstr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.endpoint, got.(*kvstore.ValidatingEndpoint).Endpoint)
		})
	}
}

func TestEndpointsFromEndpointSlice(t *testing.T) {
	type (
		Addr = iso_v1alpha1.PrivateNetworkEndpointAddressing
		EP   = iso_v1alpha1.PrivateNetworkEndpointSliceEndpoint
		IF   = iso_v1alpha1.PrivateNetworkEndpointSliceInterface
		FL   = iso_v1alpha1.PrivateNetworkEndpointSliceFlags
		PA   = iso_v1alpha1.PrivateNetworkEndpointSlicePreviousAddressing
	)

	var (
		MPA = netip.MustParseAddr
		MPM = func(in string) mac.MAC {
			out, err := mac.ParseMAC(in)
			require.NoError(t, err, "ParseMAC")
			return out
		}

		now    = time.Now().UTC()
		source = kvstore.Source{
			Cluster:   "__cluster__",
			Namespace: "__namespace__",
			Name:      "__name__",
		}

		input = &iso_v1alpha1.PrivateNetworkEndpointSlice{
			ObjectMeta: metav1.ObjectMeta{Namespace: source.Namespace, Name: source.Name},
			Endpoints: []iso_v1alpha1.PrivateNetworkEndpointSliceEntry{
				{
					Endpoint:  EP{Name: "ipv4-only", Addressing: Addr{IPv4: "192.168.0.1"}},
					Interface: IF{Network: "net-1", Addressing: Addr{IPv4: "10.0.0.1"}, MAC: "00:11:22:33:44:55"},
				},
				{
					Endpoint:  EP{Name: "ipv6-only", Addressing: Addr{IPv6: "fc00::1"}},
					Interface: IF{Network: "net-2", Addressing: Addr{IPv6: "fd00::1"}, MAC: "00:11:22:33:44:66"},
					Flags:     FL{External: true},
				},
				{
					Endpoint:    EP{Name: "dual", Addressing: Addr{IPv4: "192.168.0.2", IPv6: "fc00::2"}},
					Interface:   IF{Network: "net-3", Addressing: Addr{IPv4: "10.0.0.2", IPv6: "fd00::2"}, MAC: "00:11:22:33:44:77"},
					ActivatedAt: metav1.MicroTime{Time: now},
				},
				{
					Endpoint:  EP{Name: "invalid-mac", Addressing: Addr{IPv4: "192.168.0.3"}},
					Interface: IF{Network: "net-4", Addressing: Addr{IPv4: "10.0.0.3"}, MAC: "__invalid__"},
				},
				{
					Endpoint:  EP{Name: "invalid-ips", Addressing: Addr{IPv4: "192.168.0.3", IPv6: "__invalid__"}},
					Interface: IF{Network: "net-5", Addressing: Addr{IPv6: "10.0.0.3"}, MAC: "00:11:22:33:44:88"},
				},
				{
					Endpoint: EP{
						Name:               "previous",
						Addressing:         Addr{IPv4: "192.168.0.4", IPv6: "fc00::4"},
						PreviousAddressing: []PA{{IPv4: "192.168.0.2", IPv6: "fc00::2", LastSeen: metav1.MicroTime{Time: now}}}},
					Interface: IF{Network: "net-3", Addressing: Addr{IPv4: "10.0.0.2", IPv6: "fd00::2"}, MAC: "00:11:22:33:44:77"},
				},
			},
			NodeName: "__node__",
		}

		expected = []*kvstore.Endpoint{
			{Source: source, Name: "ipv4-only", IP: MPA("192.168.0.1"), Network: kvstore.Network{Name: "net-1", IP: MPA("10.0.0.1"), MAC: MPM("00:11:22:33:44:55")}, NodeName: "__node__"},
			{Source: source, Name: "ipv6-only", IP: MPA("fc00::1"), Network: kvstore.Network{Name: "net-2", IP: MPA("fd00::1"), MAC: MPM("00:11:22:33:44:66")}, NodeName: "__node__", Flags: kvstore.Flags{External: true}},
			{Source: source, Name: "dual", IP: MPA("192.168.0.2"), Network: kvstore.Network{Name: "net-3", IP: MPA("10.0.0.2"), MAC: MPM("00:11:22:33:44:77")}, NodeName: "__node__", ActivatedAt: now},
			{Source: source, Name: "dual", IP: MPA("fc00::2"), Network: kvstore.Network{Name: "net-3", IP: MPA("fd00::2"), MAC: MPM("00:11:22:33:44:77")}, NodeName: "__node__", ActivatedAt: now},
			{Source: source, Name: "previous", IP: MPA("192.168.0.4"), Network: kvstore.Network{Name: "net-3", IP: MPA("10.0.0.2"), MAC: MPM("00:11:22:33:44:77")}, NodeName: "__node__", PreviousAddressing: []kvstore.PreviousAddressing{{IP: MPA("192.168.0.2"), LastSeen: now}}},
			{Source: source, Name: "previous", IP: MPA("fc00::4"), Network: kvstore.Network{Name: "net-3", IP: MPA("fd00::2"), MAC: MPM("00:11:22:33:44:77")}, NodeName: "__node__", PreviousAddressing: []kvstore.PreviousAddressing{{IP: MPA("fc00::2"), LastSeen: now}}},
		}

		actual = slices.Collect(kvstore.EndpointsFromEndpointSlice(hivetest.Logger(t), source.Cluster, input))
	)

	require.Equal(t, expected, actual)
}
