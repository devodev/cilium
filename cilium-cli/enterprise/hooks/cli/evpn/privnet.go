// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package evpn

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

const (
	// privnetPodAddrOffset is address offset used for allocating test privnet pod IP addresses.
	// Test will start allocating pod IPs on privnet subnet address + this offset.
	privnetPodAddrOffset = 10

	privnetNetworkNameLabel = "cni:com.isovalent.private-network.name"
)

// privnetInfo privnet information retrieved from the cluster.
type privnetInfo struct {
	Name        string
	VNI         uint32
	EVPNSubnets []*v1alpha1.SubnetSpec
}

// privnetPodConfig holds configuration for a test privnet pod.
type privnetPodConfig struct {
	name       string
	privnet    privnetInfo
	subnetName string
	ipv4       netip.Addr
	ipv6       netip.Addr
	mac        string
}

// networkAttachmentAnnotation is used to populate the value of the privnet network-attachment pod annotation.
type networkAttachmentAnnotation struct {
	Network string `json:"network"`
	Subnet  string `json:"subnet,omitempty"`
	IPv4    string `json:"ipv4,omitempty"`
	IPv6    string `json:"ipv6,omitempty"`
	MAC     string `json:"mac,omitempty"`
}

func (r *TestRun) retrieveEVPNPrivateNetworks(ctx context.Context) (map[string]privnetInfo, error) {
	list, err := r.client.EnterpriseCiliumClientset.IsovalentV1alpha1().ClusterwidePrivateNetworks().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("error listing ClusterwidePrivateNetworks: %w", err)
	}

	networks := make(map[string]privnetInfo, len(list.Items))
	for i := range list.Items {
		network := &list.Items[i]
		if network.Spec.VNI == nil {
			continue
		}
		evpnSubnets := evpnEnabledSubnets(network)
		if len(evpnSubnets) == 0 {
			continue
		}
		networks[network.Name] = privnetInfo{
			Name:        network.Name,
			VNI:         *network.Spec.VNI,
			EVPNSubnets: evpnSubnets,
		}
	}

	for name, privNet := range networks {
		fmt.Fprintf(r.out, "Found EVPN-enabled private network: name=%s VNI=%d\n", name, privNet.VNI)
	}
	return networks, nil
}

func evpnEnabledSubnets(network *v1alpha1.ClusterwidePrivateNetwork) []*v1alpha1.SubnetSpec {
	var res []*v1alpha1.SubnetSpec
	for _, subnet := range network.Spec.Subnets {
		for _, route := range subnet.Routes {
			if route.Gateway == v1alpha1.EVPNRoute {
				res = append(res, &subnet)
				break
			}
		}
	}
	return res
}

func buildPrivnetK8sPod(podConfig *privnetPodConfig, params TestParams, labels map[string]string) (*corev1.Pod, error) {
	attachment := networkAttachmentAnnotation{
		Network: podConfig.privnet.Name,
		Subnet:  podConfig.subnetName,
		MAC:     podConfig.mac,
	}
	if podConfig.ipv4.IsValid() {
		attachment.IPv4 = podConfig.ipv4.String()
	}
	if podConfig.ipv6.IsValid() {
		attachment.IPv6 = podConfig.ipv6.String()
	}
	rawAttachment, err := json.Marshal(attachment)
	if err != nil {
		return nil, fmt.Errorf("marshaling privnet attachment annotation: %w", err)
	}

	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podConfig.name,
			Namespace: params.TestNamespace,
			Labels:    labels,
			Annotations: map[string]string{
				"privnet.isovalent.com/network-attachment": string(rawAttachment),
			},
		},
		Spec: corev1.PodSpec{
			TerminationGracePeriodSeconds: ptr.To[int64](1),
			Containers: []corev1.Container{
				{
					Name:    evpnTestContainerName,
					Image:   params.CurlImage,
					Command: []string{"sh", "-c", "sleep infinity"},
				},
			},
		},
	}, nil
}

func getPrivnetTestPodConfig(privnet privnetInfo, nameSuffix string, ordinal uint32) (*privnetPodConfig, error) {
	subnet, err := selectEVPNSubnet(privnet)
	if err != nil {
		return nil, err
	}

	pod := &privnetPodConfig{
		privnet:    privnet,
		subnetName: subnet.Name,
		name:       fmt.Sprintf("%s-%s", privnet.Name, nameSuffix),
		mac:        generatePrivnetPodMAC(privnet.VNI, ordinal),
	}

	if subnet.CIDRv4 != "" {
		prefix, err := netip.ParsePrefix(string(subnet.CIDRv4))
		if err != nil {
			return nil, err
		}
		if pod.ipv4, err = getSubnetAddrOffset(prefix, privnetPodAddrOffset+ordinal); err != nil {
			return nil, fmt.Errorf("could not allocate pod IPv4 address for privnet %s / subnet %s: %w", privnet.Name, subnet.Name, err)
		}
	}
	if subnet.CIDRv6 != "" {
		prefix, err := netip.ParsePrefix(string(subnet.CIDRv6))
		if err != nil {
			return nil, err
		}
		if pod.ipv6, err = getSubnetAddrOffset(prefix, privnetPodAddrOffset+ordinal); err != nil {
			return nil, fmt.Errorf("could not allocate pod IPv6 address for privnet %s/ subnet %s: %w", privnet.Name, subnet.Name, err)
		}
	}
	return pod, nil
}

func selectEVPNSubnet(network privnetInfo) (*v1alpha1.SubnetSpec, error) {
	if len(network.EVPNSubnets) == 0 {
		return nil, fmt.Errorf("privnet %s has no EVPN-enabled subnet", network.Name)
	}

	var singleFamily *v1alpha1.SubnetSpec
	for _, subnet := range network.EVPNSubnets {
		if subnet.CIDRv4 != "" && subnet.CIDRv6 != "" {
			// prefer dual-stack subnet
			return subnet, nil
		} else if singleFamily == nil {
			// keep the first single stack subnet as the second preference
			singleFamily = subnet
		}
	}
	if singleFamily != nil {
		return singleFamily, nil
	}
	return nil, fmt.Errorf("privnet %s has no valid EVPN-enabled subnet", network.Name)
}

func generatePrivnetPodMAC(vni uint32, ordinal uint32) string {
	return net.HardwareAddr{
		0x02,
		byte((vni >> 8) & 0xff),
		byte(vni & 0xff),
		byte((ordinal >> 16) & 0xff),
		byte((ordinal >> 8) & 0xff),
		byte(ordinal & 0xff),
	}.String()
}

func getSubnetAddrOffset(prefix netip.Prefix, offset uint32) (netip.Addr, error) {
	if prefix.Addr().Is4() {
		raw := prefix.Addr().As4()
		base := binary.BigEndian.Uint32(raw[:])
		sum := base + uint32(offset)
		binary.BigEndian.PutUint32(raw[:], sum)
		addr := netip.AddrFrom4(raw)
		if !prefix.Contains(addr) {
			return netip.Addr{}, fmt.Errorf("invalid offset %d for prefix %v", offset, prefix)
		}
		return addr, nil
	}

	raw := prefix.Addr().As16()
	high := binary.BigEndian.Uint64(raw[:8])
	low := binary.BigEndian.Uint64(raw[8:])
	sum := low + uint64(offset)
	if sum < low {
		high++
	}
	binary.BigEndian.PutUint64(raw[:8], high)
	binary.BigEndian.PutUint64(raw[8:], sum)
	addr := netip.AddrFrom16(raw)
	if !prefix.Contains(addr) {
		return netip.Addr{}, fmt.Errorf("invalid offset %d for prefix %v", offset, prefix)
	}
	return addr, nil
}
