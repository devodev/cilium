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
	"bytes"
	"cmp"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	multusv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	multusutils "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/utils"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/enterprise/api/v1/models"
	"github.com/cilium/cilium/enterprise/api/v1/server/restapi/network"
	"github.com/cilium/cilium/enterprise/pkg/api"
	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/enterprise/pkg/privnet/types"
	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	k8sTables "github.com/cilium/cilium/pkg/k8s/tables"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

var Cell = cell.Group(
	cell.ProvidePrivate(newPrivNetAPI),
	cell.Provide(newPrivNetAPIHandler),
)

// MaxSecondaryInterfaces is the maximum number of supported secondary interfaces.
const MaxSecondaryInterfaces = 64

// vNICIndex represents the index of a vNIC. The zero index represents the primary
// interface, and subsequent ones correspond to secondary interfaces, computed based
// on the position of the corresponding entry in the Multus network attachment annotation.
type vNICIndex uint

// Primary returns whether the index corresponds to the primary interface.
func (idx vNICIndex) Primary() bool { return idx == 0 }

type apiParams struct {
	cell.In

	Lifecycle cell.Lifecycle
	Log       *slog.Logger

	DB                   *statedb.DB
	PrivateNetworkConfig config.Config
	DaemonConfig         *option.DaemonConfig
	Pods                 statedb.Table[k8sTables.LocalPod]
	PrivateNetworks      statedb.Table[tables.PrivateNetwork]
	Subnets              statedb.Table[tables.Subnet]
}

type cfg struct {
	privateNetworkConfig config.Config

	enableIPv4 bool
	enableIPv6 bool
}

type PrivNetAPI struct {
	db  *statedb.DB
	cfg cfg
	log *slog.Logger

	pods            statedb.Table[k8sTables.LocalPod]
	privateNetworks statedb.Table[tables.PrivateNetwork]
	subnets         statedb.Table[tables.Subnet]
}

func newPrivNetAPI(p apiParams) *PrivNetAPI {
	return &PrivNetAPI{
		db: p.DB,
		cfg: cfg{
			privateNetworkConfig: p.PrivateNetworkConfig,

			enableIPv4: p.DaemonConfig.EnableIPv4,
			enableIPv6: p.DaemonConfig.EnableIPv6,
		},
		log:             p.Log,
		pods:            p.Pods,
		privateNetworks: p.PrivateNetworks,
		subnets:         p.Subnets,
	}
}

func (n *PrivNetAPI) GetPrivateNetworkAddressing(p network.GetNetworkPrivateAddressingParams) (*models.PrivateNetworkAddressing, error) {
	if (p.Network == nil) != (p.Subnet == nil) {
		return nil, fmt.Errorf("both network and subnet must be set in CNI configuration if one is provided")
	}

	if !n.cfg.privateNetworkConfig.Enabled {
		if p.Network != nil {
			return nil, fmt.Errorf("target network set in CNI configuration, but private networks is disabled")
		}

		// Don't look at network attachment annotations if privnet is disabled, attach to
		// default network.
		return nil, nil
	}

	podNamespaceName := fmt.Sprintf("%s/%s", p.PodNamespace, p.PodName)

	txn := n.db.ReadTxn()
	pod, _, found := n.pods.Get(txn, k8sTables.PodByName(p.PodNamespace, p.PodName))
	if !found {
		return nil, fmt.Errorf("pod %s not found", podNamespaceName)
	} else if string(pod.UID) != p.PodUID {
		return nil, fmt.Errorf("pod %s UID does not match pod object in store (got %q, want %q)",
			podNamespaceName, pod.UID, p.PodUID)
	}

	var annotationFor = func(nicidx vNICIndex) string {
		if nicidx.Primary() {
			return types.PrivateNetworkAnnotation
		}
		return types.PrivateNetworkSecondaryAttachmentsAnnotation
	}

	attachment, nicidx, err := n.getAttachmentFor(pod, p.Ifname)
	if err != nil {
		return nil, err
	} else if attachment == nil {
		if p.Network != nil {
			return nil, fmt.Errorf("target network set in CNI configuration, but %q annotation is missing on pod %s",
				annotationFor(nicidx), podNamespaceName,
			)
		}

		// Annotation not found, attach to default network.
		return nil, nil
	}

	if p.Network != nil && *p.Network != attachment.Network {
		return nil, fmt.Errorf("mismatching target network in CNI configuration (%q) and %q annotation on pod %s (%q)",
			*p.Network, annotationFor(nicidx), podNamespaceName, attachment.Network,
		)
	}
	privnet, _, found := n.privateNetworks.Get(txn, tables.PrivateNetworkByName(tables.NetworkName(attachment.Network)))
	if !found {
		return nil, fmt.Errorf("invalid network %q in %q annotation on pod %s",
			attachment.Network, annotationFor(nicidx), podNamespaceName)
	}

	inactive, err := types.ExtractInactiveAnnotation(pod)
	if err != nil {
		return nil, fmt.Errorf("invalid value in %q annotation on pod %s/%s: %w",
			types.PrivateNetworkInactiveAnnotation, pod.Namespace, pod.Name, err)
	}

	if p.Subnet != nil && attachment.Subnet != "" && *p.Subnet != attachment.Subnet {
		return nil, fmt.Errorf("mismatching target subnet in CNI configuration (%q) and %q annotation on pod %s (%q)",
			*p.Subnet, annotationFor(nicidx), podNamespaceName, attachment.Subnet,
		)
	}
	requestedSubnet := tables.SubnetName(ptr.Deref(p.Subnet, attachment.Subnet))

	var ipv4, ipv6 netip.Addr

	if n.cfg.enableIPv4 && attachment.IPv4.IsValid() {
		if !attachment.IPv4.Is4() {
			return nil, fmt.Errorf("invalid IPv4 address %q in %q annotation on pod %s",
				attachment.IPv4, annotationFor(nicidx), podNamespaceName)
		}
		ipv4 = attachment.IPv4
	}

	if n.cfg.enableIPv6 && attachment.IPv6.IsValid() {
		if !attachment.IPv6.Is6() {
			return nil, fmt.Errorf("invalid IPv6 address %q in %q annotation on pod %s",
				attachment.IPv6, annotationFor(nicidx), podNamespaceName)
		}
		ipv6 = attachment.IPv6
	}

	switch {
	case !ipv6.IsValid() && !ipv4.IsValid() && requestedSubnet == "":
		// User did not provide any IP or subnet, or provided a IP of a family we don't support
		return nil, fmt.Errorf("no valid IP address or subnet in %q annotation on pod %s",
			annotationFor(nicidx), podNamespaceName)
	case ipv4.IsUnspecified() && requestedSubnet == "":
		// User explicitly requested to do DHCP with 0.0.0.0. Fail, regardless of IPv6.
		return nil, fmt.Errorf("subnet must be specified for DHCP")
	}

	subnet, err := n.subnetForIPs(txn, privnet.Name, requestedSubnet, ipv4, ipv6)
	if err != nil {
		return nil, err
	}

	if n.cfg.enableIPv4 && !attachment.IPv4.IsValid() &&
		subnet.DHCP.Mode != iso_v1alpha1.PrivateNetworkDHCPModeNone &&
		subnet.CIDRv4.IsValid() {
		// If the cluster supports IPv4, and the subnet support DHCP. If the user
		// didn't provide an IPv4, just do DHCP.
		ipv4 = netip.IPv4Unspecified()
	}

	activatedAt := time.Now().UTC()
	if inactive {
		activatedAt = time.Time{} // zero value means inactive
	}

	addressing := &models.PrivateNetworkAddressing{
		Address:     &models.AddressPair{},
		Mac:         attachment.MAC.String(),
		Network:     attachment.Network,
		Subnet:      string(subnet.Name),
		ActivatedAt: strfmt.DateTime(activatedAt),
		NicIndex:    new(int64(nicidx)),
	}

	if ipv4.IsValid() {
		addressing.Address.IPv4 = ipv4.String()
	}

	if ipv6.IsValid() {
		addressing.Address.IPv6 = ipv6.String()
	}

	n.addRoutes(addressing, nicidx, subnet)
	return addressing, nil
}

// getAttachmentFor returns the network attachment associated with the given interface of a pod, and
// the corresponding vNIC index, computed based on the position of the entry in the Multus network
// attachment annotation.
//
// For secondary interfaces, it additionally validates that the MAC address requested via the network
// attachment matches the one in the corresponding Multus annotation entry, if both are specified,
// and defaults to the latter if the former is not specified. This ensures that the MAC requested
// through the Interface stanza of a VirtualMachineInstance is always respected, even if not explicitly
// specified as part of the network attachment annotation. Yet, no validation check, nor defaulting, is
// possible for the primary interface (without actually retrieving the VirtualMachineInstance object),
// as the MAC address is not propagated as part of the pod object itself, and users are responsible for
// always specifying the desired MAC address also through the network attachment annotation, if they set
// a custom MAC address through the Interface stanza.
func (n *PrivNetAPI) getAttachmentFor(pod metav1.Object, ifname string) (*types.NetworkAttachment, vNICIndex, error) {
	// The attachment for the primary interface is always the first one.
	const primary = "eth0"
	if ifname == primary {
		attachment, err := types.ExtractNetworkAttachmentAnnotation(pod)
		return attachment, 0, err
	}

	attachments, err := types.ExtractNetworkSecondaryAttachmentsAnnotation(pod)
	if err != nil || len(attachments) == 0 {
		// Return the [vNICIndex] matching a secondary interface, so that it can
		// be used to propagate a better error message.
		return nil, 1, err
	}

	// Lookup the entry matching the given interface name inside the "k8s.v1.cni.cncf.io/networks" annotation.
	elems, err := multusutils.ParsePodNetworkAnnotation(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: pod.GetName(), Namespace: pod.GetNamespace(), Annotations: pod.GetAnnotations(),
	}})
	if err != nil {
		return nil, 0, fmt.Errorf("unable to parse %q annotation: %w", multusv1.NetworkAttachmentAnnot, err)
	}

	nicidx, duplicate, macreq := -1, false, mac.MAC(nil)
	for i, elem := range elems {
		// If no interface name is specified, Multus constructs it based on the position of the delegate.
		// https://github.com/k8snetworkplumbingwg/multus-cni/blob/39d6a8ffd2fb/pkg/multus/multus.go#L92-L105
		if ifname == cmp.Or(elem.InterfaceRequest, fmt.Sprintf("net%d", i+1)) {
			if elem.MacRequest != "" {
				macreq, err = mac.ParseMAC(elem.MacRequest)
				if err != nil {
					return nil, 0, fmt.Errorf("invalid MAC address request in %q annotation: %w", multusv1.NetworkAttachmentAnnot, err)
				}
			}

			duplicate, nicidx = nicidx != -1, i
		}
	}

	switch {
	case duplicate:
		return nil, 0, fmt.Errorf("duplicate entry found for interface %q in %q annotation", ifname, multusv1.NetworkAttachmentAnnot)
	case nicidx == -1:
		return nil, 0, fmt.Errorf("no entry found for interface %q in %q annotation", ifname, multusv1.NetworkAttachmentAnnot)
	case nicidx >= MaxSecondaryInterfaces:
		return nil, 0, fmt.Errorf("at most %d secondary interfaces are supported", MaxSecondaryInterfaces)
	}

	// If the attachments specify the interface name, we can rely on it to retrieve the matching one.
	var naidx = nicidx
	if attachments[0].Interface != "" {
		// Copied from the Kubevirt implementation of [GenerateHashedInterfaceName], to avoid introducing a dependency.
		// https://github.com/kubevirt/kubevirt/blob/1ac3f5208a1f/pkg/network/namescheme/networknamescheme.go#L80-L85
		var kubevirtHashedInterfaceName = func(networkName string) string {
			hash := sha256.New()
			_, _ = io.WriteString(hash, networkName)
			hashedName := fmt.Sprintf("%x", hash.Sum(nil))[:11]
			return fmt.Sprintf("%s%s", "pod", hashedName)
		}

		naidx = -1
		for i, na := range attachments {
			if ifname == na.Interface || ifname == kubevirtHashedInterfaceName(na.Interface) {
				duplicate, naidx = naidx != -1, i
			}
		}
	}

	switch {
	case duplicate:
		return nil, 0, fmt.Errorf("duplicate network attachment found for interface %q in %q annotation",
			ifname, types.PrivateNetworkSecondaryAttachmentsAnnotation)
	case naidx == -1 || naidx >= len(attachments):
		return nil, 0, fmt.Errorf("no network attachment found for interface %q in %q annotation",
			ifname, types.PrivateNetworkSecondaryAttachmentsAnnotation)
	default:
		var attachment = attachments[naidx]
		if len(attachment.MAC) == 0 {
			attachment.MAC = macreq
		}

		if len(macreq) != 0 && !bytes.Equal(attachment.MAC, macreq) {
			return nil, 0, fmt.Errorf("mismatching MAC request for interface %q in %q and %q annotations",
				ifname, types.PrivateNetworkSecondaryAttachmentsAnnotation, multusv1.NetworkAttachmentAnnot,
			)
		}

		// We return the index in the Multus annotation, rather than the one of the
		// attachment entry, so that it is future proof once we make attachments optional.
		return &attachment, vNICIndex(nicidx + 1), nil
	}
}

func (n *PrivNetAPI) subnetForIPs(txn statedb.ReadTxn, privnet tables.NetworkName, sname tables.SubnetName, ipv4, ipv6 netip.Addr) (tables.Subnet, error) {
	// Resolve subnet names based on the IPv4 and IPv6 addresses
	var subnetv4, subnetv6 tables.SubnetName
	if ipv4.IsValid() && !ipv4.IsUnspecified() {
		if sub, ok := tables.FindSubnetForIPs(n.subnets, txn, privnet, ipv4); ok {
			subnetv4 = sub.Name
		} else {
			return tables.Subnet{}, fmt.Errorf("requested IP %s not in range of defined subnets", ipv4)
		}
	}
	if ipv6.IsValid() {
		if sub, ok := tables.FindSubnetForIPs(n.subnets, txn, privnet, ipv6); ok {
			subnetv6 = sub.Name
		} else {
			return tables.Subnet{}, fmt.Errorf("requested IP %s not in range of defined subnets", ipv6)
		}
	}

	// Look up the subnet. We do this before the validation in order to fail first
	// on missing subnet for a less confusing error message.
	chosen := cmp.Or(sname, subnetv4, subnetv6)
	subnet, _, found := n.subnets.Get(txn, tables.SubnetsByNetworkAndName(privnet, chosen))
	if !found {
		return tables.Subnet{}, fmt.Errorf("invalid subnet %q for network %q", chosen, privnet)
	}

	// Validate consistency of the subnet selection.
	switch {
	case subnetv4 != "" && subnetv6 != "" && subnetv4 != subnetv6:
		return tables.Subnet{}, fmt.Errorf("requested IP %s not in range of the subnet of the IP %s", ipv6, ipv4)

	case sname != "" && (subnetv4 != "" && subnetv4 != sname || subnetv6 != "" && subnetv6 != sname):
		return tables.Subnet{}, fmt.Errorf("requested IPs are not in range of the requested subnet (%q)", sname)

	case ipv4.IsUnspecified() && (subnet.DHCP.Mode == iso_v1alpha1.PrivateNetworkDHCPModeNone || !subnet.CIDRv4.IsValid()):
		// User explicitly requested to do DHCP with 0.0.0.0.
		return tables.Subnet{}, fmt.Errorf("subnet %q does not support DHCP", subnet.Name)
	}

	return subnet, nil
}

// addRoutes adds the list of routes to be configured for a private networks enabled endpoint to the provided
// addressing. Specifically, for each IP family that is enabled and used by the addressing, we configure the
// following routes.
//
// * For the primary interface:
//   - A route towards a link local address -- $link_local_address via $iface
//   - A default route -- default via $link_local_address
//
// * For secondary interfaces:
//   - A route towards a link local address, similarly as for the primary one.
//     The link local address is generated based on vNIC index.
//   - A route for the subnet CIDR -- $subnet_cidr via $link_local_address.
//     This mimics the route that would be automatically created if we propagated
//     the actual subnet mask, rather than leveraging /32 and /128 addresses.
//
// We leverage a link local address as nexthop, rather than simply setting the default route
// via the egress interface, to avoid the need for a neighbor lookup for every destination IP.
func (n *PrivNetAPI) addRoutes(addressing *models.PrivateNetworkAddressing, idx vNICIndex, subnet tables.Subnet) {
	var pfx = func(def string, subnet netip.Prefix) string {
		if idx.Primary() {
			return def
		}

		return subnet.String()
	}

	if addressing.Address.IPv4 != "" {
		var gw = fmt.Sprintf("169.254.0.%d", idx+1)

		addressing.Routes = append(addressing.Routes,
			&models.NetworkAttachmentRoute{Destination: gw + "/32"},
			&models.NetworkAttachmentRoute{Destination: pfx("0.0.0.0/0", subnet.CIDRv4), Gateway: gw},
		)
	}

	if addressing.Address.IPv6 != "" {
		var gw = fmt.Sprintf("fe80::%x", idx+1)

		addressing.Routes = append(addressing.Routes,
			&models.NetworkAttachmentRoute{Destination: gw + "/128"},
			&models.NetworkAttachmentRoute{Destination: pfx("::/0", subnet.CIDRv6), Gateway: gw},
		)
	}
}

// newPrivNetAPIHandler returns a default handler for the /network/private/addressing API endpoint
func newPrivNetAPIHandler(n *PrivNetAPI) network.GetNetworkPrivateAddressingHandler {
	return api.NewHandler(func(p network.GetNetworkPrivateAddressingParams) middleware.Responder {
		addressing, err := n.GetPrivateNetworkAddressing(p)
		if err != nil {
			return network.NewGetNetworkPrivateAddressingFailure().WithPayload(models.Error(err.Error()))
		}

		return network.NewGetNetworkPrivateAddressingOK().WithPayload(&models.PrivateNetworkAddressingResponse{
			Addressing: addressing,
		})
	})
}
