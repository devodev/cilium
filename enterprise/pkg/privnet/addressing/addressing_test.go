// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package addressing

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"testing/synctest"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/go-openapi/strfmt"
	multusv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	"github.com/stretchr/testify/assert"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/enterprise/api/v1/models"
	"github.com/cilium/cilium/enterprise/api/v1/server/restapi/network"
	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/enterprise/pkg/privnet/types"
	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_meta_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sTables "github.com/cilium/cilium/pkg/k8s/tables"
	"github.com/cilium/cilium/pkg/time"
)

func TestPrivNetAPI_GetPrivateNetworkAddressing(t *testing.T) {
	initPrivNetAPI := func(t *testing.T, cfg cfg, pod k8sTables.LocalPod) *PrivNetAPI {
		t.Helper()

		db := statedb.New()
		pods, err := k8sTables.NewPodTable(db)
		if err != nil {
			t.Fatalf("NewPodTable: %s", err)
		}

		wtxn := db.WriteTxn(pods)
		pods.Insert(wtxn, pod)
		wtxn.Commit()

		privNets, err := tables.NewPrivateNetworksTable(db)
		if err != nil {
			t.Fatalf("NewPrivateNetworksTable: %s", err)
		}
		subnets, err := tables.NewSubnetTable(db)
		if err != nil {
			t.Fatalf("NewPrivateNetworksTable: %s", err)
		}
		wtxn = db.WriteTxn(privNets, subnets)
		privNets.Insert(wtxn,
			tables.PrivateNetwork{
				Name: "green-network",
				ID:   1,
			})
		subnets.Insert(wtxn,
			tables.Subnet{
				SubnetSpec: tables.SubnetSpec{
					Network:   "green-network",
					NetworkID: 1,
					Name:      "subnet1",
					CIDRv4:    netip.MustParsePrefix("192.168.11.0/24"),
					CIDRv6:    netip.MustParsePrefix("fd10:0:150::/64"),
				},
				DHCP: iso_v1alpha1.PrivateNetworkSubnetDHCPSpec{
					Mode: iso_v1alpha1.PrivateNetworkDHCPModeBroadcast,
				},
			})
		subnets.Insert(wtxn,
			tables.Subnet{
				SubnetSpec: tables.SubnetSpec{
					Network:   "green-network",
					NetworkID: 1,
					Name:      "subnet2",
					CIDRv4:    netip.MustParsePrefix("192.168.52.0/24"),
					CIDRv6:    netip.MustParsePrefix("fd10:0:152::/64"),
				},
				DHCP: iso_v1alpha1.PrivateNetworkSubnetDHCPSpec{
					Mode: iso_v1alpha1.PrivateNetworkDHCPModeNone,
				},
			},
		)
		subnets.Insert(wtxn,
			tables.Subnet{
				SubnetSpec: tables.SubnetSpec{
					Network:   "green-network",
					NetworkID: 1,
					Name:      "subnet3",
					CIDRv4:    netip.MustParsePrefix("192.168.10.0/24"),
					CIDRv6:    netip.MustParsePrefix("fd10:0:140::/64"),
				},
			},
		)
		privNets.Insert(wtxn,
			tables.PrivateNetwork{
				Name: "blue-network",
				ID:   2,
			})
		subnets.Insert(wtxn,
			tables.Subnet{
				SubnetSpec: tables.SubnetSpec{
					Network:   "blue-network",
					NetworkID: 2,
					Name:      "subnet1",
					CIDRv4:    netip.MustParsePrefix("192.168.22.0/24"),
				},
			})

		wtxn.Commit()

		return &PrivNetAPI{
			db:              db,
			cfg:             cfg,
			log:             hivetest.Logger(t),
			pods:            pods,
			privateNetworks: privNets,
			subnets:         subnets,
		}
	}

	newPod := func(namespace, name, uid string, annotations map[string]string) k8sTables.LocalPod {
		return k8sTables.LocalPod{Pod: &slim_core_v1.Pod{
			ObjectMeta: slim_meta_v1.ObjectMeta{
				Namespace:   namespace,
				Name:        name,
				UID:         k8stypes.UID(uid),
				Annotations: annotations,
			},
		}}
	}

	cfgDefault := cfg{
		privateNetworkConfig: config.Config{
			Enabled: true,
			Mode:    config.ModeDefault,
		},
		enableIPv4: true,
		enableIPv6: true,
	}
	cfgPrivNetDisabled := cfg{
		privateNetworkConfig: config.Config{
			Enabled: false,
		},
	}
	cfgIPv4Only := cfg{
		privateNetworkConfig: config.Config{
			Enabled: true,
			Mode:    config.ModeDefault,
		},
		enableIPv4: true,
		enableIPv6: false,
	}
	cfgIPv6Only := cfg{
		privateNetworkConfig: config.Config{
			Enabled: true,
			Mode:    config.ModeDefault,
		},
		enableIPv4: false,
		enableIPv6: true,
	}

	activatedAtActive := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	activatedAtInactive := time.Time{}

	type override struct {
		network   *string
		subnet    *string
		namespace string
		name      string
		uid       string
		ifname    string
	}
	tests := []struct {
		name           string
		cfg            *cfg
		pod            k8sTables.LocalPod
		override       override
		wantAddressing *models.PrivateNetworkAddressing
		wantErr        string
	}{
		{
			name: "no network attachment annotation",
			cfg:  &cfgPrivNetDisabled,
			pod:  newPod("default", "client", "uid", nil),
		},
		{
			name: "no network attachment annotation",
			pod:  newPod("default", "client", "uid", nil),
		},
		{
			name: "valid network attachment annotation",
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "ipv4": "192.168.11.11", "ipv6": "fd10:0:150::11", "mac": "00:50:56:ad:11:02"}`,
				},
			),
			wantAddressing: &models.PrivateNetworkAddressing{
				ActivatedAt: strfmt.DateTime(activatedAtActive),
				Network:     "green-network",
				Subnet:      "subnet1",
				Address: &models.AddressPair{
					IPv4: "192.168.11.11",
					IPv6: "fd10:0:150::11",
				},
				Mac: "00:50:56:ad:11:02",
				Routes: []*models.NetworkAttachmentRoute{
					{Destination: "169.254.0.1/32"},
					{Destination: "0.0.0.0/0", Gateway: "169.254.0.1"},
					{Destination: "fe80::1/128"},
					{Destination: "::/0", Gateway: "fe80::1"},
				},
			},
		},
		{
			name: "valid inactive pod",
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation:         `{"network": "green-network", "ipv4": "192.168.11.13", "ipv6": "fd10:0:150::13", "mac": "00:69:af:ca:8e:34"}`,
					types.PrivateNetworkInactiveAnnotation: "true",
				},
			),
			wantAddressing: &models.PrivateNetworkAddressing{
				ActivatedAt: strfmt.DateTime(activatedAtInactive),
				Network:     "green-network",
				Subnet:      "subnet1",
				Address: &models.AddressPair{
					IPv4: "192.168.11.13",
					IPv6: "fd10:0:150::13",
				},
				Mac: "00:69:af:ca:8e:34",
				Routes: []*models.NetworkAttachmentRoute{
					{Destination: "169.254.0.1/32"},
					{Destination: "0.0.0.0/0", Gateway: "169.254.0.1"},
					{Destination: "fe80::1/128"},
					{Destination: "::/0", Gateway: "fe80::1"},
				},
			},
		},
		{
			name: "pod nonexistent",
			pod:  newPod("default", "client", "uid", nil),
		},
		{
			name: "pod nonexistent in namespace",
			pod:  newPod("default", "client", "uid", nil),
			override: override{
				name: "workload",
			},
			wantErr: "pod default/workload not found",
		},
		{
			name: "pod nonexistent in namespace",
			pod:  newPod("default", "client", "uid", nil),
			override: override{
				namespace: "tenant1",
			},
			wantErr: "pod tenant1/client not found",
		},
		{
			name: "pod UID not matching",
			pod:  newPod("default", "client", "uid", nil),
			override: override{
				uid: "some-other-uid",
			},
			wantErr: "UID does not match pod object in store",
		},
		{
			name: "network nonexistent",
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "nonexistent-network", "ipv4": "10.20.0.12", "ipv6": "fd20:0:150::12", "mac": "00:60:8c:b1:91:21"}`,
				},
			),
			wantErr: fmt.Sprintf(`invalid network "nonexistent-network" in %q annotation`, types.PrivateNetworkAnnotation),
		},
		{
			name: "invalid attachment annotation",
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network" "ipv4": "192.168.11.11" "mac": "00:50:56:ad:11:02"}`,
				},
			),
			wantErr: fmt.Sprintf(`invalid value in %q annotation`, types.PrivateNetworkAnnotation),
		},
		{
			name: "invalid inactive annotation",
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation:         `{"network": "blue-network", "ipv4": "10.10.0.14", "ipv6": "fd10:0:150::14", "mac": "00:69:af:ca:8e:34"}`,
					types.PrivateNetworkInactiveAnnotation: "foobar",
				},
			),
			wantErr: fmt.Sprintf(`invalid value in %q annotation`, types.PrivateNetworkInactiveAnnotation),
		},
		{
			name: "invalid IPv4",
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "ipv4": "fd10:0:150::15", "ipv6": "fd10:0:150::15", "mac": "00:df:a2:ca:8e:44"}`,
				},
			),
			wantErr: fmt.Sprintf(`invalid IPv4 address "fd10:0:150::15" in %q annotation`, types.PrivateNetworkAnnotation),
		},
		{
			name: "invalid IPv6",
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "ipv4": "192.168.11.16", "ipv6": "192.168.11.16", "mac": "00:a3:af:ca:8e:66"}`,
				},
			),
			wantErr: fmt.Sprintf(`invalid IPv6 address "192.168.11.16" in %q annotation`, types.PrivateNetworkAnnotation),
		},
		{
			name: "IPv4 not in prefixes",
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "ipv4": "10.10.0.17", "ipv6": "fd10:0:150::17", "mac": "00:69:af:ca:8e:34"}`,
				},
			),
			wantErr: "requested IP 10.10.0.17 not in range of",
		},
		{
			name: "IPv6 not in prefixes",
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "ipv4": "192.168.11.18", "ipv6": "face::bead", "mac": "00:a8:c0:01:2d:22"}`,
				},
			),
			wantErr: "requested IP face::bead not in range of",
		},
		{
			name: "requesting IPv6 from IPv4-only network",
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "blue-network", "ipv4": "192.168.22.11", "ipv6": "fd10:0:250::11", "mac": "00:a8:c0:01:2d:22"}`,
				},
			),
			wantErr: "requested IP fd10:0:250::11 not in range of",
		},
		{
			name: "requesting IPv4 in IPv6-only configuration",
			cfg:  &cfgIPv6Only,
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "ipv4": "192.168.11.11", "mac": "00:50:56:ad:11:02"}`,
				},
			),
			wantErr: fmt.Sprintf(`invalid IPv6 address "invalid IP" in %q annotation`, types.PrivateNetworkAnnotation),
		},
		{
			name: "requesting IPv6 in IPv4-only configuration",
			cfg:  &cfgIPv4Only,
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "ipv6": "fd10:0:150::11",  "mac": "00:50:56:ad:11:02"}`,
				},
			),
			wantErr: "subnet must be specified for DHCP",
		},
		{
			name: "requesting IPv4 and IPv6 in IPv6-only configuration",
			cfg:  &cfgIPv6Only,
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "ipv4": "192.168.11.11", "ipv6": "fd10:0:150::11", "mac": "00:50:56:ad:11:02"}`,
				},
			),
			wantAddressing: &models.PrivateNetworkAddressing{
				ActivatedAt: strfmt.DateTime(activatedAtActive),
				Network:     "green-network",
				Subnet:      "subnet1",
				Address: &models.AddressPair{
					IPv6: "fd10:0:150::11",
				},
				Mac: "00:50:56:ad:11:02",
				Routes: []*models.NetworkAttachmentRoute{
					{Destination: "fe80::1/128"},
					{Destination: "::/0", Gateway: "fe80::1"},
				},
			},
		},
		{
			name: "requesting IPv4 and IPv6 in IPv4-only configuration",
			cfg:  &cfgIPv4Only,
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "ipv4": "192.168.11.11", "ipv6": "fd10:0:150::11", "mac": "00:50:56:ad:11:02"}`,
				},
			),
			wantAddressing: &models.PrivateNetworkAddressing{
				ActivatedAt: strfmt.DateTime(activatedAtActive),
				Network:     "green-network",
				Subnet:      "subnet1",
				Address: &models.AddressPair{
					IPv4: "192.168.11.11",
				},
				Mac: "00:50:56:ad:11:02",
				Routes: []*models.NetworkAttachmentRoute{
					{Destination: "169.254.0.1/32"},
					{Destination: "0.0.0.0/0", Gateway: "169.254.0.1"},
				},
			},
		},
		{
			name: "IPv4 and IPv6 not in same subnet",
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "ipv4": "192.168.52.17", "ipv6": "fd10:0:150::17", "mac": "00:69:af:ca:8e:34"}`,
				},
			),
			wantErr: "requested IP fd10:0:150::17 not in range of",
		},
		{
			name: "network attachement in conflicting subnet",
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "ipv4": "192.168.10.11", "ipv6": "fd10:0:150::11", "mac": "00:50:56:ad:11:02"}`,
				},
			),
			wantErr: "requested IP fd10:0:150::11 not in range of the subnet of the IP 192.168.10.11",
		},
		{
			name:     "CNI configuration specifies network, but subnet is missing",
			override: override{network: ptr.To("green-network")},
			pod:      newPod("default", "client", "uid", nil),
			wantErr:  "both network and subnet must be set in CNI configuration if one is provided",
		},
		{
			name:     "CNI configuration specifies subnet, but network is missing",
			override: override{subnet: ptr.To("subnet1")},
			pod:      newPod("default", "client", "uid", nil),
			wantErr:  "both network and subnet must be set in CNI configuration if one is provided",
		},
		{
			name:     "CNI configuration specifies network, but private networks is disabled",
			cfg:      &cfgPrivNetDisabled,
			override: override{network: ptr.To("green-network"), subnet: ptr.To("subnet1")},
			pod:      newPod("default", "client", "uid", nil),
			wantErr:  "target network set in CNI configuration, but private networks is disabled",
		},
		{
			name:     "CNI configuration specifies network, but attachment is missing",
			override: override{network: ptr.To("green-network"), subnet: ptr.To("subnet1")},
			pod:      newPod("default", "client", "uid", nil),
			wantErr:  fmt.Sprintf(`target network set in CNI configuration, but %q annotation is missing on pod default/client`, types.PrivateNetworkAnnotation),
		},
		{
			name:     "CNI configuration specifies network, but attachment is missing (secondary interface)",
			override: override{network: ptr.To("green-network"), subnet: ptr.To("subnet1"), ifname: "net0"},
			pod:      newPod("default", "client", "uid", nil),
			wantErr:  fmt.Sprintf(`target network set in CNI configuration, but %q annotation is missing on pod default/client`, types.PrivateNetworkSecondaryAttachmentsAnnotation),
		},
		{
			name:     "mismatching CNI configuration and attachment network",
			override: override{network: ptr.To("blue-network"), subnet: ptr.To("subnet1")},
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "ipv4": "192.168.10.11", "ipv6": "fd10:0:150::11", "mac": "00:50:56:ad:11:02"}`,
				}),
			wantErr: fmt.Sprintf(`mismatching target network in CNI configuration ("blue-network") and %q annotation on pod default/client ("green-network")`, types.PrivateNetworkAnnotation),
		},
		{
			name:     "mismatching CNI configuration and target subnet network",
			override: override{network: ptr.To("green-network"), subnet: ptr.To("subnet2")},
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "ipv4": "192.168.11.11", "ipv6": "fd10:0:150::11", "mac": "00:50:56:ad:11:02"}`,
				}),
			wantErr: `requested IPs are not in range of the requested subnet ("subnet2")`,
		},
		{
			name:     "mismatching CNI configuration and attachment subnet",
			override: override{network: ptr.To("green-network"), subnet: ptr.To("subnet2")},
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "subnet": "subnet1", "ipv4": "192.168.11.11", "ipv6": "fd10:0:150::11", "mac": "00:50:56:ad:11:02"}`,
				}),
			wantErr: fmt.Sprintf(`mismatching target subnet in CNI configuration ("subnet2") and %q annotation on pod default/client ("subnet1")`, types.PrivateNetworkAnnotation),
		},
		{
			name: "attachment subnet used when requested IP is unspecified",
			cfg:  &cfgIPv4Only,
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "subnet": "subnet1", "ipv4": "0.0.0.0", "mac": "00:50:56:ad:11:02"}`,
				},
			),
			wantAddressing: &models.PrivateNetworkAddressing{
				ActivatedAt: strfmt.DateTime(activatedAtActive),
				Network:     "green-network",
				Subnet:      "subnet1",
				Address: &models.AddressPair{
					IPv4: "0.0.0.0",
				},
				Mac: "00:50:56:ad:11:02",
				Routes: []*models.NetworkAttachmentRoute{
					{Destination: "169.254.0.1/32"},
					{Destination: "0.0.0.0/0", Gateway: "169.254.0.1"},
				},
			},
		},
		{
			name: "attachment subnet used when requested IP is empty",
			cfg:  &cfgIPv4Only,
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "subnet": "subnet1", "mac": "00:50:56:ad:11:02"}`,
				},
			),
			wantAddressing: &models.PrivateNetworkAddressing{
				ActivatedAt: strfmt.DateTime(activatedAtActive),
				Network:     "green-network",
				Subnet:      "subnet1",
				Address: &models.AddressPair{
					IPv4: "0.0.0.0",
				},
				Mac: "00:50:56:ad:11:02",
				Routes: []*models.NetworkAttachmentRoute{
					{Destination: "169.254.0.1/32"},
					{Destination: "0.0.0.0/0", Gateway: "169.254.0.1"},
				},
			},
		},

		{
			name:     "requested subnet used when requested IP is unspecified",
			cfg:      &cfgIPv4Only,
			override: override{network: ptr.To("green-network"), subnet: ptr.To("subnet1")},
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "ipv4": "0.0.0.0", "mac": "00:50:56:ad:11:02"}`,
				},
			),
			wantAddressing: &models.PrivateNetworkAddressing{
				ActivatedAt: strfmt.DateTime(activatedAtActive),
				Network:     "green-network",
				Subnet:      "subnet1",
				Address: &models.AddressPair{
					IPv4: "0.0.0.0",
				},
				Mac: "00:50:56:ad:11:02",
				Routes: []*models.NetworkAttachmentRoute{
					{Destination: "169.254.0.1/32"},
					{Destination: "0.0.0.0/0", Gateway: "169.254.0.1"},
				},
			},
		},
		{
			name:     "requested subnet with DHCP mode none and unspecified IPv4",
			cfg:      &cfgIPv4Only,
			override: override{network: ptr.To("green-network"), subnet: ptr.To("subnet2")},
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "ipv4": "0.0.0.0", "mac": "00:50:56:ad:11:02"}`,
				},
			),
			wantErr: `subnet "subnet2" does not support DHCP`,
		},
		{
			name: "subnet is required when requested IP is unspecified",
			cfg:  &cfgIPv4Only,
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "ipv4": "0.0.0.0", "mac": "00:50:56:ad:11:02"}`,
				},
			),
			wantErr: "subnet must be specified for DHCP",
		},
		{
			name: "attachment subnet must exist when requested IP is unspecified",
			cfg:  &cfgIPv4Only,
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "subnet": "missing", "ipv4": "0.0.0.0", "mac": "00:50:56:ad:11:02"}`,
				},
			),
			wantErr: `invalid subnet "missing" for network "green-network"`,
		},
		{
			name:     "requested subnet must exist",
			cfg:      &cfgIPv4Only,
			override: override{network: ptr.To("green-network"), subnet: ptr.To("missing")},
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "ipv4": "0.0.0.0", "mac": "00:50:56:ad:11:02"}`,
				},
			),
			wantErr: `invalid subnet "missing" for network "green-network"`,
		},
		{
			name:     "valid network attachment annotation, matching CNI configuration",
			override: override{network: ptr.To("green-network"), subnet: ptr.To("subnet1")},
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "ipv4": "192.168.11.11", "ipv6": "fd10:0:150::11", "mac": "00:50:56:ad:11:02"}`,
				},
			),
			wantAddressing: &models.PrivateNetworkAddressing{
				ActivatedAt: strfmt.DateTime(activatedAtActive),
				Network:     "green-network",
				Subnet:      "subnet1",
				Address: &models.AddressPair{
					IPv4: "192.168.11.11",
					IPv6: "fd10:0:150::11",
				},
				Mac: "00:50:56:ad:11:02",
				Routes: []*models.NetworkAttachmentRoute{
					{Destination: "169.254.0.1/32"},
					{Destination: "0.0.0.0/0", Gateway: "169.254.0.1"},
					{Destination: "fe80::1/128"},
					{Destination: "::/0", Gateway: "fe80::1"},
				},
			},
		},
		{
			name:     "secondary network attachment, match on order",
			override: override{ifname: "net2"},
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "ipv4": "192.168.11.11", "ipv6": "fd10:0:150::11", "mac": "00:50:56:ad:11:02"}`,
					types.PrivateNetworkSecondaryAttachmentsAnnotation: `[
						{ "network": "green-network", "ipv4": "192.168.52.11", "ipv6": "fd10:0:152::11", "mac": "00:50:56:ad:11:03" },
						{ "network": "green-network", "ipv4": "192.168.10.11", "ipv6": "fd10:0:140::11", "mac": "00:50:56:ad:11:04" },
						{ "network": "blue-network", "ipv4": "192.168.22.11", "mac": "00:50:56:ad:11:05" }
					]`,
					multusv1.NetworkAttachmentAnnot: "foo,bar,baz",
				},
			),
			wantAddressing: &models.PrivateNetworkAddressing{
				ActivatedAt: strfmt.DateTime(activatedAtActive),
				Network:     "green-network",
				Subnet:      "subnet3",
				Address: &models.AddressPair{
					IPv4: "192.168.10.11",
					IPv6: "fd10:0:140::11",
				},
				Mac: "00:50:56:ad:11:04",
				Routes: []*models.NetworkAttachmentRoute{
					{Destination: "169.254.0.3/32"},
					{Destination: "192.168.10.0/24", Gateway: "169.254.0.3"},
					{Destination: "fe80::3/128"},
					{Destination: "fd10:0:140::/64", Gateway: "fe80::3"},
				},
			},
		},
		{
			name:     "secondary network attachment, match on order (with interface names)",
			override: override{ifname: "eth3"},
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "ipv4": "192.168.11.11", "ipv6": "fd10:0:150::11", "mac": "00:50:56:ad:11:02"}`,
					types.PrivateNetworkSecondaryAttachmentsAnnotation: `[
						{ "network": "green-network", "ipv4": "192.168.52.11", "ipv6": "fd10:0:152::11", "mac": "00:50:56:ad:11:03" },
						{ "network": "green-network", "ipv4": "192.168.10.11", "ipv6": "fd10:0:140::11", "mac": "00:50:56:ad:11:04" },
						{ "network": "blue-network", "ipv4": "192.168.22.11", "mac": "00:50:56:ad:11:05" }
					]`,
					multusv1.NetworkAttachmentAnnot: "foo@eth3,bar@eth2,baz",
				},
			),
			wantAddressing: &models.PrivateNetworkAddressing{
				ActivatedAt: strfmt.DateTime(activatedAtActive),
				Network:     "green-network",
				Subnet:      "subnet2",
				Address: &models.AddressPair{
					IPv4: "192.168.52.11",
					IPv6: "fd10:0:152::11",
				},
				Mac: "00:50:56:ad:11:03",
				Routes: []*models.NetworkAttachmentRoute{
					{Destination: "169.254.0.2/32"},
					{Destination: "192.168.52.0/24", Gateway: "169.254.0.2"},
					{Destination: "fe80::2/128"},
					{Destination: "fd10:0:152::/64", Gateway: "fe80::2"},
				},
			},
		},
		{
			name:     "secondary network attachment, match on order (missing Multus annotation)",
			override: override{ifname: "net3"},
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "ipv4": "192.168.11.11", "ipv6": "fd10:0:150::11", "mac": "00:50:56:ad:11:02"}`,
					types.PrivateNetworkSecondaryAttachmentsAnnotation: `[
						{ "network": "green-network", "ipv4": "192.168.52.11", "ipv6": "fd10:0:152::11", "mac": "00:50:56:ad:11:03" },
						{ "network": "green-network", "ipv4": "192.168.10.11", "ipv6": "fd10:0:140::11", "mac": "00:50:56:ad:11:04" }
					]`,
				},
			),
			wantErr: `unable to parse "k8s.v1.cni.cncf.io/networks" annotation: no kubernetes network found`,
		},
		{
			name:     "secondary network attachment, match on order (invalid Multus annotation)",
			override: override{ifname: "net3"},
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "ipv4": "192.168.11.11", "ipv6": "fd10:0:150::11", "mac": "00:50:56:ad:11:02"}`,
					types.PrivateNetworkSecondaryAttachmentsAnnotation: `[
						{ "network": "green-network", "ipv4": "192.168.52.11", "ipv6": "fd10:0:152::11", "mac": "00:50:56:ad:11:03" },
						{ "network": "green-network", "ipv4": "192.168.10.11", "ipv6": "fd10:0:140::11", "mac": "00:50:56:ad:11:04" }
					]`,
					multusv1.NetworkAttachmentAnnot: "foo^invalid",
				},
			),
			wantErr: `unable to parse "k8s.v1.cni.cncf.io/networks" annotation: parsePodNetworkAnnotation`,
		},
		{
			name:     "secondary network attachment, match on order (missing entry in Multus annotation)",
			override: override{ifname: "net3"},
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "ipv4": "192.168.11.11", "ipv6": "fd10:0:150::11", "mac": "00:50:56:ad:11:02"}`,
					types.PrivateNetworkSecondaryAttachmentsAnnotation: `[
						{ "network": "green-network", "ipv4": "192.168.52.11", "ipv6": "fd10:0:152::11", "mac": "00:50:56:ad:11:03" },
						{ "network": "green-network", "ipv4": "192.168.10.11", "ipv6": "fd10:0:140::11", "mac": "00:50:56:ad:11:04" }
					]`,
					multusv1.NetworkAttachmentAnnot: "foo,bar",
				},
			),
			wantErr: `no entry found for interface "net3" in "k8s.v1.cni.cncf.io/networks" annotation`,
		},
		{
			name:     "secondary network attachment, match on order (missing entry in our annotation)",
			override: override{ifname: "net2"},
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "ipv4": "192.168.11.11", "ipv6": "fd10:0:150::11", "mac": "00:50:56:ad:11:02"}`,
					types.PrivateNetworkSecondaryAttachmentsAnnotation: `[
						{ "network": "green-network", "ipv4": "192.168.52.11", "ipv6": "fd10:0:152::11", "mac": "00:50:56:ad:11:03" }
					]`,
					multusv1.NetworkAttachmentAnnot: "foo,bar",
				},
			),
			wantErr: `no network attachment found for interface "net2" in`,
		},
		{
			name:     "secondary network attachment, match on order (duplicate entry)",
			override: override{ifname: "eth4"},
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "ipv4": "192.168.11.11", "ipv6": "fd10:0:150::11", "mac": "00:50:56:ad:11:02"}`,
					types.PrivateNetworkSecondaryAttachmentsAnnotation: `[
						{ "network": "green-network", "ipv4": "192.168.52.11", "ipv6": "fd10:0:152::11", "mac": "00:50:56:ad:11:03" },
						{ "network": "green-network", "ipv4": "192.168.10.11", "ipv6": "fd10:0:140::11", "mac": "00:50:56:ad:11:04" }
					]`,
					multusv1.NetworkAttachmentAnnot: "foo@eth4,bar@eth4",
				},
			),
			wantErr: `duplicate entry found for interface "eth4" in`,
		},
		{
			name:     "secondary network attachment, match on implicit interface name",
			override: override{ifname: "net2"},
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "ipv4": "192.168.11.11", "ipv6": "fd10:0:150::11", "mac": "00:50:56:ad:11:02"}`,
					types.PrivateNetworkSecondaryAttachmentsAnnotation: `[
						{ "network": "green-network", "ipv4": "192.168.52.11", "ipv6": "fd10:0:152::11", "mac": "00:50:56:ad:11:03", "interface": "net1" },
						{ "network": "green-network", "ipv4": "192.168.10.11", "ipv6": "fd10:0:140::11", "mac": "00:50:56:ad:11:04", "interface": "net2" },
						{ "network": "blue-network", "ipv4": "192.168.22.11", "mac": "00:50:56:ad:11:05", "interface": "net3" }
					]`,
					multusv1.NetworkAttachmentAnnot: "foo,bar,baz",
				},
			),
			wantAddressing: &models.PrivateNetworkAddressing{
				ActivatedAt: strfmt.DateTime(activatedAtActive),
				Network:     "green-network",
				Subnet:      "subnet3",
				Address: &models.AddressPair{
					IPv4: "192.168.10.11",
					IPv6: "fd10:0:140::11",
				},
				Mac: "00:50:56:ad:11:04",
				Routes: []*models.NetworkAttachmentRoute{
					{Destination: "169.254.0.3/32"},
					{Destination: "192.168.10.0/24", Gateway: "169.254.0.3"},
					{Destination: "fe80::3/128"},
					{Destination: "fd10:0:140::/64", Gateway: "fe80::3"},
				},
			},
		},
		{
			name:     "secondary network attachment, match on explicit interface name",
			override: override{ifname: "eth4"},
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "ipv4": "192.168.11.11", "ipv6": "fd10:0:150::11", "mac": "00:50:56:ad:11:02"}`,
					types.PrivateNetworkSecondaryAttachmentsAnnotation: `[
						{ "network": "green-network", "ipv4": "192.168.52.11", "ipv6": "fd10:0:152::11", "mac": "00:50:56:ad:11:03", "interface": "eth4" },
						{ "network": "green-network", "ipv4": "192.168.10.11", "ipv6": "fd10:0:140::11", "mac": "00:50:56:ad:11:04", "interface": "eth3" },
						{ "network": "blue-network", "ipv4": "192.168.22.11", "mac": "00:50:56:ad:11:05", "interface": "eth2" }
					]`,
					multusv1.NetworkAttachmentAnnot: "foo@eth2,bar@eth3,baz@eth4",
				},
			),
			wantAddressing: &models.PrivateNetworkAddressing{
				ActivatedAt: strfmt.DateTime(activatedAtActive),
				Network:     "green-network",
				Subnet:      "subnet2",
				Address: &models.AddressPair{
					IPv4: "192.168.52.11",
					IPv6: "fd10:0:152::11",
				},
				Mac: "00:50:56:ad:11:03",
				Routes: []*models.NetworkAttachmentRoute{
					{Destination: "169.254.0.4/32"},
					{Destination: "192.168.52.0/24", Gateway: "169.254.0.4"},
					{Destination: "fe80::4/128"},
					{Destination: "fd10:0:152::/64", Gateway: "fe80::4"},
				},
			},
		},
		{
			name:     "secondary network attachment, match on kubevirt interface name",
			override: override{ifname: "pod50a73efd61d"},
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "ipv4": "192.168.11.11", "ipv6": "fd10:0:150::11", "mac": "00:50:56:ad:11:02"}`,
					types.PrivateNetworkSecondaryAttachmentsAnnotation: `[
						{ "network": "green-network", "ipv4": "192.168.52.11", "ipv6": "fd10:0:152::11", "mac": "00:50:56:ad:11:03", "interface": "green-1" },
						{ "network": "green-network", "ipv4": "192.168.10.11", "ipv6": "fd10:0:140::11", "mac": "00:50:56:ad:11:04", "interface": "green-2" }
					]`,
					multusv1.NetworkAttachmentAnnot: `[{ "name": "green-2", "interface": "pod4c1327ef942" }, { "name": "green-1", "interface": "pod50a73efd61d" }]`,
				},
			),
			wantAddressing: &models.PrivateNetworkAddressing{
				ActivatedAt: strfmt.DateTime(activatedAtActive),
				Network:     "green-network",
				Subnet:      "subnet2",
				Address: &models.AddressPair{
					IPv4: "192.168.52.11",
					IPv6: "fd10:0:152::11",
				},
				Mac: "00:50:56:ad:11:03",
				Routes: []*models.NetworkAttachmentRoute{
					{Destination: "169.254.0.3/32"},
					{Destination: "192.168.52.0/24", Gateway: "169.254.0.3"},
					{Destination: "fe80::3/128"},
					{Destination: "fd10:0:152::/64", Gateway: "fe80::3"},
				},
			},
		},
		{
			name:     "secondary network attachment, match on interface name (missing entry in our annotation)",
			override: override{ifname: "net2"},
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "ipv4": "192.168.11.11", "ipv6": "fd10:0:150::11", "mac": "00:50:56:ad:11:02"}`,
					types.PrivateNetworkSecondaryAttachmentsAnnotation: `[
						{ "network": "green-network", "ipv4": "192.168.52.11", "ipv6": "fd10:0:152::11", "mac": "00:50:56:ad:11:03", "interface": "net3" }
					]`,
					multusv1.NetworkAttachmentAnnot: "foo,bar",
				},
			),
			wantErr: `no network attachment found for interface "net2" in`,
		},
		{
			name:     "secondary network attachment, match on order (duplicate entry)",
			override: override{ifname: "eth4"},
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "ipv4": "192.168.11.11", "ipv6": "fd10:0:150::11", "mac": "00:50:56:ad:11:02"}`,
					types.PrivateNetworkSecondaryAttachmentsAnnotation: `[
						{ "network": "green-network", "ipv4": "192.168.52.11", "ipv6": "fd10:0:152::11", "mac": "00:50:56:ad:11:03", "interface": "eth4" },
						{ "network": "green-network", "ipv4": "192.168.10.11", "ipv6": "fd10:0:140::11", "mac": "00:50:56:ad:11:04", "interface": "eth4" }
					]`,
					multusv1.NetworkAttachmentAnnot: "foo,bar@eth4",
				},
			),
			wantErr: `duplicate network attachment found for interface "eth4" in`,
		},
		{
			name:     "secondary network attachment, primary in default network",
			override: override{ifname: "net2"},
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkSecondaryAttachmentsAnnotation: `[
						{ "network": "green-network", "ipv4": "192.168.52.11", "ipv6": "fd10:0:152::11", "mac": "00:50:56:ad:11:03" },
						{ "network": "green-network", "ipv4": "192.168.10.11", "ipv6": "fd10:0:140::11", "mac": "00:50:56:ad:11:04" },
						{ "network": "blue-network", "ipv4": "192.168.22.11", "mac": "00:50:56:ad:11:05" }
					]`,
					multusv1.NetworkAttachmentAnnot: "foo,bar,baz",
				},
			),
			wantAddressing: &models.PrivateNetworkAddressing{
				ActivatedAt: strfmt.DateTime(activatedAtActive),
				Network:     "green-network",
				Subnet:      "subnet3",
				Address: &models.AddressPair{
					IPv4: "192.168.10.11",
					IPv6: "fd10:0:140::11",
				},
				Mac: "00:50:56:ad:11:04",
				Routes: []*models.NetworkAttachmentRoute{
					{Destination: "169.254.0.3/32"},
					{Destination: "192.168.10.0/24", Gateway: "169.254.0.3"},
					{Destination: "fe80::3/128"},
					{Destination: "fd10:0:140::/64", Gateway: "fe80::3"},
				},
			},
		},
		{
			name:     "secondary network attachment, MAC omitted",
			override: override{ifname: "net1"},
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkSecondaryAttachmentsAnnotation: `[
						{ "network": "green-network", "ipv4": "192.168.10.11", "ipv6": "fd10:0:140::11" }
					]`,
					multusv1.NetworkAttachmentAnnot: "foo",
				},
			),
			wantAddressing: &models.PrivateNetworkAddressing{
				ActivatedAt: strfmt.DateTime(activatedAtActive),
				Network:     "green-network",
				Subnet:      "subnet3",
				Address: &models.AddressPair{
					IPv4: "192.168.10.11",
					IPv6: "fd10:0:140::11",
				},
				Routes: []*models.NetworkAttachmentRoute{
					{Destination: "169.254.0.2/32"},
					{Destination: "192.168.10.0/24", Gateway: "169.254.0.2"},
					{Destination: "fe80::2/128"},
					{Destination: "fd10:0:140::/64", Gateway: "fe80::2"},
				},
			},
		},
		{
			name:     "secondary network attachment, MAC from Multus annotation",
			override: override{ifname: "net1"},
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkSecondaryAttachmentsAnnotation: `[
						{ "network": "green-network", "ipv4": "192.168.10.11", "ipv6": "fd10:0:140::11" }
					]`,
					multusv1.NetworkAttachmentAnnot: `[{ "name": "foo", "mac": "00:50:56:ad:11:05" }]`,
				},
			),
			wantAddressing: &models.PrivateNetworkAddressing{
				ActivatedAt: strfmt.DateTime(activatedAtActive),
				Network:     "green-network",
				Subnet:      "subnet3",
				Address: &models.AddressPair{
					IPv4: "192.168.10.11",
					IPv6: "fd10:0:140::11",
				},
				Mac: "00:50:56:ad:11:05",
				Routes: []*models.NetworkAttachmentRoute{
					{Destination: "169.254.0.2/32"},
					{Destination: "192.168.10.0/24", Gateway: "169.254.0.2"},
					{Destination: "fe80::2/128"},
					{Destination: "fd10:0:140::/64", Gateway: "fe80::2"},
				},
			},
		},
		{
			name:     "secondary network attachment, MAC matching",
			override: override{ifname: "net1"},
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkSecondaryAttachmentsAnnotation: `[
						{ "network": "green-network", "ipv4": "192.168.10.11", "ipv6": "fd10:0:140::11", "mac": "00:50:56:ad:11:05" }
					]`,
					multusv1.NetworkAttachmentAnnot: `[{ "name": "foo", "mac": "00:50:56:ad:11:05" }]`,
				},
			),
			wantAddressing: &models.PrivateNetworkAddressing{
				ActivatedAt: strfmt.DateTime(activatedAtActive),
				Network:     "green-network",
				Subnet:      "subnet3",
				Address: &models.AddressPair{
					IPv4: "192.168.10.11",
					IPv6: "fd10:0:140::11",
				},
				Mac: "00:50:56:ad:11:05",
				Routes: []*models.NetworkAttachmentRoute{
					{Destination: "169.254.0.2/32"},
					{Destination: "192.168.10.0/24", Gateway: "169.254.0.2"},
					{Destination: "fe80::2/128"},
					{Destination: "fd10:0:140::/64", Gateway: "fe80::2"},
				},
			},
		},
		{
			name:     "secondary network attachment, MAC mismatching",
			override: override{ifname: "net1"},
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkSecondaryAttachmentsAnnotation: `[
						{ "network": "green-network", "ipv4": "192.168.10.11", "ipv6": "fd10:0:140::11", "mac": "00:50:56:ad:11:05" }
					]`,
					multusv1.NetworkAttachmentAnnot: `[{ "name": "foo", "mac": "00:50:56:ad:11:06" }]`,
				},
			),
			wantErr: `mismatching MAC request for interface "net1" in`,
		},
		{
			name:     "secondary network attachment, invalid MAC from Multus annotation",
			override: override{ifname: "net1"},
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkSecondaryAttachmentsAnnotation: `[
						{ "network": "green-network", "ipv4": "192.168.10.11", "ipv6": "fd10:0:140::11" }
					]`,
					multusv1.NetworkAttachmentAnnot: `[{ "name": "foo", "mac": "invalid" }]`,
				},
			),
			wantErr: `invalid MAC address request in "k8s.v1.cni.cncf.io/networks" annotation`,
		},
		{
			name:     "too many secondary interfaces, match by index",
			override: override{ifname: "net65"},
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkSecondaryAttachmentsAnnotation: fmt.Sprintf("[%s]", strings.Join(
						slices.Repeat([]string{`{ "network": "green-network", "ipv4": "192.168.10.11", "ipv6": "fd10:0:140::11" }`}, 65), ",")),
					multusv1.NetworkAttachmentAnnot: strings.Join(slices.Repeat([]string{"foo"}, 65), ","),
				},
			),
			wantErr: "at most 64 secondary interfaces are supported",
		},
		{
			name:     "too many secondary interfaces, match by name",
			override: override{ifname: "net65"},
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkSecondaryAttachmentsAnnotation: `[
						{ "network": "green-network", "ipv4": "192.168.10.11", "ipv6": "fd10:0:140::11", "interface": "net65" }
					]`,
					multusv1.NetworkAttachmentAnnot: strings.Join(slices.Repeat([]string{"foo"}, 65), ","),
				},
			),
			wantErr: "at most 64 secondary interfaces are supported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cfg := cmp.Or(tt.cfg, &cfgDefault)
				n := initPrivNetAPI(t, *cfg, tt.pod)

				// override requested pod attributes to test mismatches
				name := cmp.Or(tt.override.name, tt.pod.Name)
				namespace := cmp.Or(tt.override.namespace, tt.pod.Namespace)
				uid := cmp.Or(tt.override.uid, string(tt.pod.UID))
				addressing, err := n.GetPrivateNetworkAddressing(network.GetNetworkPrivateAddressingParams{
					Network:      tt.override.network,
					Subnet:       tt.override.subnet,
					PodName:      name,
					PodNamespace: namespace,
					PodUID:       uid,
					Ifname:       cmp.Or(tt.override.ifname, "eth0"),
				})
				if tt.wantErr != "" {
					assert.ErrorContains(t, err, tt.wantErr)
				} else {
					assert.NoError(t, err)
					assert.Equal(t, tt.wantAddressing, addressing)
				}
			})
		})
	}
}
