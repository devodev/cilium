// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package bgp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer/yaml"
	yamlutil "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/cli-runtime/pkg/printers"
	"k8s.io/client-go/dynamic"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/cilium-cli/api"
	legacyv2alpha1 "github.com/cilium/cilium/cilium-cli/enterprise/hooks/cli/bgp/apis/cilium.io/v2alpha1"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	isovalentv1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

const (
	egwPolicySelectorType = "IsovalentEgressGatewayPolicy"

	bgpPeeringPolicyGroup      = "cilium.io"
	bgpPeeringPolicyVersion    = "v2alpha1"
	bgpPeeringPolicyKind       = "CiliumBGPPeeringPolicy"
	bgpPeeringPolicyPluralName = "ciliumbgppeeringpolicies"
)

var (
	errBGPv2MappingUnsupported = errors.New("mapping to BGPv2 not supported")

	bgpPeeringPolicyGroupVersionKind = schema.GroupVersionKind{
		Group:   bgpPeeringPolicyGroup,
		Version: bgpPeeringPolicyVersion,
		Kind:    bgpPeeringPolicyKind,
	}
	bgpPeeringPolicyGroupVersionResource = schema.GroupVersionResource{
		Group:    bgpPeeringPolicyGroup,
		Version:  bgpPeeringPolicyVersion,
		Resource: bgpPeeringPolicyPluralName,
	}
)

func NewCmdBGPRenderAPI() *cobra.Command {
	var inputFile, outputFile string

	cmd := &cobra.Command{
		Use:   "render-api",
		Short: "Render BGPv2 version of existing BGPv1 configuration",
		Long:  "This command prints BGPv2 version of existing BGPv1 configuration from a k8s cluster or an input YAML file",
		RunE: func(c *cobra.Command, _ []string) error {
			var buffer bytes.Buffer

			if inputFile == "" {
				err := renderBGPv2APIFromK8sClient(c.Context(), &buffer)
				if err != nil {
					return err
				}
			} else {
				err := renderBGPv2APIFromYamlFile(inputFile, &buffer)
				if err != nil {
					return err
				}
			}

			if outputFile == "" {
				_, err := fmt.Fprintf(c.OutOrStdout(), "%s\n", buffer.String())
				if err != nil {
					return fmt.Errorf("failed writing to stdout: %w", err)
				}
			} else {
				err := os.WriteFile(outputFile, buffer.Bytes(), 0644)
				if err != nil {
					return fmt.Errorf("failed writing to %s: %w", outputFile, err)
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&inputFile, "input", "i", "", "Input file. If not provided, input will be read from k8s cluster.")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file. If not provided, standard output will be used.")

	return cmd
}

// renderBGPv2APIFromK8sClient reads BGPv1 config from k8s client and outputs rendered BGPv2 config into the provided buffer.
func renderBGPv2APIFromK8sClient(ctx context.Context, buffer *bytes.Buffer) error {
	var printer printers.YAMLPrinter

	// We use unstructured client to retrieve CiliumBGPPeeringPolicies, as we need to support fields that
	// are not available in main-ce version of CiliumBGPPeeringPolicy (egressGatewayPolicySelector).

	k8sClient, _ := api.GetK8sClientContextValue(ctx)
	dynamicClient, err := dynamic.NewForConfig(k8sClient.Config)
	if err != nil {
		return fmt.Errorf("failed creating dynamic k8s client: %w", err)
	}

	unstructuredPolicies, err := dynamicClient.Resource(bgpPeeringPolicyGroupVersionResource).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed listing CiliumBGPPeeringPolicies: %w", err)
	}

	for _, unstructuredPolicy := range unstructuredPolicies.Items {
		err = renderUnstructuredBGPPeeringPolicy(&unstructuredPolicy, buffer, &printer)
		if err != nil {
			return fmt.Errorf("failed rendering CiliumBGPPeeringPolicy: %w", err)
		}
	}

	// list nodes to retrieve BGP annotations
	nodes, err := k8sClient.Clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed listing nodes: %w", err)
	}
	for _, node := range nodes.Items {
		err = renderBGPNodeAnnotations(&node, buffer, &printer)
		if err != nil {
			return fmt.Errorf("failed rendering BGP node annotations: %w", err)
		}
	}

	return nil
}

// renderBGPv2APIFromYamlFile reads BGPv1 config an input file and outputs rendered BGPv2 config into the provided buffer.
func renderBGPv2APIFromYamlFile(inputFile string, buffer *bytes.Buffer) error {
	var printer printers.YAMLPrinter

	yamlBytes, err := os.ReadFile(inputFile)
	if err != nil {
		fmt.Print(err)
	}

	decoder := yamlutil.NewYAMLOrJSONDecoder(bytes.NewReader(yamlBytes), 100)
	for {
		var rawObj runtime.RawExtension
		if err = decoder.Decode(&rawObj); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("failed decoding YAML: %w", err)
		}
		obj, gvk, err := yaml.NewDecodingSerializer(unstructured.UnstructuredJSONScheme).Decode(rawObj.Raw, nil, nil)
		if err != nil {
			return fmt.Errorf("failed deserializing YAML: %w", err)
		}
		unstructuredMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
		if err != nil {
			return fmt.Errorf("failed converting YAML to unstructured object: %w", err)
		}
		unstructuredObj := &unstructured.Unstructured{Object: unstructuredMap}

		if gvk != nil && *gvk == bgpPeeringPolicyGroupVersionKind {
			err = renderUnstructuredBGPPeeringPolicy(unstructuredObj, buffer, &printer)
			if err != nil {
				return fmt.Errorf("failed rendering CiliumBGPPeeringPolicy: %w", err)
			}
		}
		if gvk != nil && *gvk == corev1.SchemeGroupVersion.WithKind("Node") {
			node := corev1.Node{}
			err = runtime.DefaultUnstructuredConverter.FromUnstructured(unstructuredObj.Object, &node)
			if err != nil {
				return fmt.Errorf("failed converting node from unstructured: %w", err)
			}
			err = renderBGPNodeAnnotations(&node, buffer, &printer)
			if err != nil {
				return fmt.Errorf("failed rendering node annotations: %w", err)
			}
		}
	}

	return nil
}

// renderUnstructuredBGPPeeringPolicy renders BGPv1 configuration from an unstructured CiliumBGPPeeringPolicy object
// and outputs BGPv2 configuration into the provided buffer using the provided printer.
func renderUnstructuredBGPPeeringPolicy(bgpPeeringPolicy *unstructured.Unstructured, buffer *bytes.Buffer, printer *printers.YAMLPrinter) error {
	// parse EGW selectors from the unstructured object
	egwSelectors, err := parseUnstructuredBGPPeeringPolicy(bgpPeeringPolicy)
	if err != nil {
		return fmt.Errorf("failed parsing EGW policy selectors: %w", err)
	}

	// convert to structured CiliumBGPPeeringPolicy and render it in structured way
	policy := legacyv2alpha1.CiliumBGPPeeringPolicy{}
	err = runtime.DefaultUnstructuredConverter.FromUnstructured(bgpPeeringPolicy.Object, &policy)
	if err != nil {
		return fmt.Errorf("failed converting CiliumBGPPeeringPolicy from unstructured: %w", err)
	}
	return renderBGPPeeringPolicy(&policy, egwSelectors, buffer, printer)
}

// parseUnstructuredBGPPeeringPolicy parses unstructured CiliumBGPPeeringPolicy object
// and returns EGW policy selectors, if present.
func parseUnstructuredBGPPeeringPolicy(bgpPeeringPolicy *unstructured.Unstructured) (map[int64]*slimv1.LabelSelector, error) {
	egwSelectors := make(map[int64]*slimv1.LabelSelector)

	vrs, _, err := unstructured.NestedSlice(bgpPeeringPolicy.Object, "spec", "virtualRouters")
	if err != nil {
		return nil, fmt.Errorf("failed parsing virtualRouters in %s: %w", bgpPeeringPolicy.GetName(), err)
	}
	for _, vr := range vrs {
		vrMap := vr.(map[string]any)

		// check if mapSRv6VRFs is present & enabled - if yes, return the unsupported error
		mapSRv6VRFs, found, err := unstructured.NestedBool(vrMap, "mapSRv6VRFs")
		if err != nil {
			return nil, fmt.Errorf("failed parsing virtualRouters.mapSRv6VRFs in %s: %w", bgpPeeringPolicy.GetName(), err)
		}
		if found && mapSRv6VRFs {
			return nil, fmt.Errorf("%w: SRv6 configuration is not supported", errBGPv2MappingUnsupported)
		}

		// retrieve local ASN
		asn, found, err := unstructured.NestedInt64(vrMap, "localASN")
		if err != nil {
			return nil, fmt.Errorf("failed parsing virtualRouters.localASN in %s: %w", bgpPeeringPolicy.GetName(), err)
		}
		if !found {
			return nil, fmt.Errorf("localASN not found in %s: %w", bgpPeeringPolicy.GetName(), err)
		}

		// retrieve egressGatewayPolicySelector
		egwSelector, found, err := unstructured.NestedFieldNoCopy(vrMap, "egressGatewayPolicySelector")
		if err != nil {
			return nil, fmt.Errorf("failed parsing virtualRouters.egressGatewayPolicySelector in %s: %w", bgpPeeringPolicy.GetName(), err)
		}
		if found {
			ls := slimv1.LabelSelector{}
			err = runtime.DefaultUnstructuredConverter.FromUnstructured(egwSelector.(map[string]any), &ls)
			if err != nil {
				return nil, fmt.Errorf("failed converting EGW LabelSelector from unstructured in %s: %w", bgpPeeringPolicy.GetName(), err)
			}
			egwSelectors[asn] = &ls
		}
	}

	return egwSelectors, nil
}

// renderBGPPeeringPolicy renders BGPv1 configuration from the provided CiliumBGPPeeringPolicy object and EGW selectors
// and outputs BGPv2 configuration into the provided buffer using the provided printer.
func renderBGPPeeringPolicy(bgpPeeringPolicy *legacyv2alpha1.CiliumBGPPeeringPolicy, egwSelectors map[int64]*slimv1.LabelSelector, buffer *bytes.Buffer, printer *printers.YAMLPrinter) error {
	var k8sObjects []runtime.Object

	clusterConfig := &isovalentv1.IsovalentBGPClusterConfig{
		TypeMeta: metav1.TypeMeta{
			APIVersion: isovalentv1.SchemeGroupVersion.String(),
			Kind:       isovalentv1.IsovalentBGPClusterConfigKindDefinition,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: bgpPeeringPolicy.Name,
		},
		Spec: isovalentv1.IsovalentBGPClusterConfigSpec{
			NodeSelector: bgpPeeringPolicy.Spec.NodeSelector,
		},
	}

	for _, vr := range bgpPeeringPolicy.Spec.VirtualRouters {
		if len(vr.Neighbors) == 0 {
			continue // don't render VirtualRouters without any neighbors - below code counts with at least 1 neighbor
		}
		instance := isovalentv1.IsovalentBGPInstance{
			Name:     bgpInstanceName(vr.LocalASN),
			LocalASN: ptr.To(vr.LocalASN),
		}

		// In some cases we can use common BGP advertisement and peer config for all peers, otherwise they
		// need to be peer-specific. Common peer config can be used only in case that common advertisement is used.
		var (
			commonAdvertisement *isovalentv1.IsovalentBGPAdvertisement
			commonPeerConfig    *isovalentv1.IsovalentBGPPeerConfig
			err                 error
		)
		if useCommonBGPAdvertisement(&vr) {
			advertName := bgpPeerConfigOrAdvertisementName(bgpPeeringPolicy, vr.LocalASN, nil)
			commonAdvertisement, err = createBGPAdvertisement(advertName, vr, egwSelectors, vr.Neighbors[0].AdvertisedPathAttributes)
			if err != nil {
				return err
			}
			k8sObjects = append(k8sObjects, commonAdvertisement)
			if useCommonBGPPeerConfig(&vr) {
				peerConfName := bgpPeerConfigOrAdvertisementName(bgpPeeringPolicy, vr.LocalASN, nil)
				commonPeerConfig = createBGPPeerConfig(peerConfName, &vr.Neighbors[0], commonAdvertisement)
				k8sObjects = append(k8sObjects, commonPeerConfig)
			}
		}

		for _, neigh := range vr.Neighbors {
			peerPrefix, err := netip.ParsePrefix(neigh.PeerAddress)
			if err != nil {
				return fmt.Errorf("failed parsing peer address %s: %w", neigh.PeerAddress, err)
			}
			peerAddr := peerPrefix.Addr()

			var advertisement *isovalentv1.IsovalentBGPAdvertisement
			if commonAdvertisement != nil {
				advertisement = commonAdvertisement
			} else {
				advertName := bgpPeerConfigOrAdvertisementName(bgpPeeringPolicy, vr.LocalASN, &peerAddr)
				advertisement, err = createBGPAdvertisement(advertName, vr, egwSelectors, neigh.AdvertisedPathAttributes)
				if err != nil {
					return err
				}
				k8sObjects = append(k8sObjects, advertisement)
			}

			var peerConfig *isovalentv1.IsovalentBGPPeerConfig
			if commonPeerConfig != nil {
				peerConfig = commonPeerConfig
			} else {
				peerConfName := bgpPeerConfigOrAdvertisementName(bgpPeeringPolicy, vr.LocalASN, &peerAddr)
				peerConfig = createBGPPeerConfig(peerConfName, &neigh, advertisement)
				k8sObjects = append(k8sObjects, peerConfig)
			}

			instance.Peers = append(instance.Peers, isovalentv1.IsovalentBGPPeer{
				Name:        bgpPeerName(peerAddr),
				PeerAddress: ptr.To(peerPrefix.Addr().String()),
				PeerASN:     ptr.To(neigh.PeerASN),
				PeerConfigRef: &isovalentv1.PeerConfigReference{
					Name: peerConfig.Name,
				},
			})
		}
		clusterConfig.Spec.BGPInstances = append(clusterConfig.Spec.BGPInstances, instance)
	}
	k8sObjects = append(k8sObjects, clusterConfig)

	for _, obj := range k8sObjects {
		err := printer.PrintObj(obj, buffer)
		if err != nil {
			return fmt.Errorf("failed printing %s to YAML: %w", obj.GetObjectKind().GroupVersionKind().Kind, err)
		}
	}

	return nil
}

// useCommonBGPAdvertisement detects if common IsovalentBGPAdvertisement can be used for all neighbors
// within the provided CiliumBGPVirtualRouter.
func useCommonBGPAdvertisement(vr *legacyv2alpha1.CiliumBGPVirtualRouter) bool {
	// we can use common advertisement if all neighbors use the same advertised path attributes
	var prevNeighbor *legacyv2alpha1.CiliumBGPNeighbor
	for i, n := range vr.Neighbors {
		if prevNeighbor != nil {
			if len(n.AdvertisedPathAttributes) != len(prevNeighbor.AdvertisedPathAttributes) {
				return false
			}
			for idx, attribs := range n.AdvertisedPathAttributes {
				if !attribs.DeepEqual(&prevNeighbor.AdvertisedPathAttributes[idx]) {
					return false
				}
			}
		}
		prevNeighbor = &vr.Neighbors[i]
	}
	return true
}

// useCommonBGPPeerConfig detects if common IsovalentBGPPeerConfig can be used for all neighbors
// within the provided CiliumBGPVirtualRouter.
func useCommonBGPPeerConfig(vr *legacyv2alpha1.CiliumBGPVirtualRouter) bool {
	// we can use common peer config if all neighbors use the same peering configuration except for peer address and ASN
	var prevNeighbor *legacyv2alpha1.CiliumBGPNeighbor
	for _, n := range vr.Neighbors {
		// create normalized neighbor
		curNeighbor := n.DeepCopy()
		curNeighbor.PeerAddress = ""
		curNeighbor.PeerASN = 0
		if prevNeighbor != nil && !prevNeighbor.DeepEqual(curNeighbor) {
			return false
		}
		prevNeighbor = curNeighbor
	}
	return true
}

// createBGPAdvertisement creates a new IsovalentBGPAdvertisement with configuration retrieved from the input arguments.
func createBGPAdvertisement(name string, vr legacyv2alpha1.CiliumBGPVirtualRouter, egwSelectors map[int64]*slimv1.LabelSelector, pathAttributes []legacyv2alpha1.CiliumBGPPathAttributes) (*isovalentv1.IsovalentBGPAdvertisement, error) {
	var err error

	advertisement := &isovalentv1.IsovalentBGPAdvertisement{
		TypeMeta: metav1.TypeMeta{
			APIVersion: isovalentv1.SchemeGroupVersion.String(),
			Kind:       isovalentv1.IsovalentBGPAdvertisementKindDefinition,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"advertise": name,
			},
		},
	}
	if vr.ExportPodCIDR != nil && *vr.ExportPodCIDR {
		advertisement.Spec.Advertisements = append(advertisement.Spec.Advertisements, isovalentv1.BGPAdvertisement{
			AdvertisementType: isovalentv1.BGPPodCIDRAdvert,
		})
	}
	if vr.PodIPPoolSelector != nil {
		advertisement.Spec.Advertisements = append(advertisement.Spec.Advertisements, isovalentv1.BGPAdvertisement{
			AdvertisementType: isovalentv1.BGPCiliumPodIPPoolAdvert,
			Selector:          vr.PodIPPoolSelector,
		})
	}
	if vr.ServiceSelector != nil {
		svcAdvertisements := vr.ServiceAdvertisements
		if len(svcAdvertisements) == 0 {
			// default svc advertisement type is LoadBalancerIP
			svcAdvertisements = []legacyv2alpha1.BGPServiceAddressType{
				legacyv2alpha1.BGPLoadBalancerIPAddr,
			}
		}
		bgpAdvert := isovalentv1.BGPAdvertisement{
			AdvertisementType: isovalentv1.BGPServiceAdvert,
			Selector:          vr.ServiceSelector,
			Service:           &isovalentv1.BGPServiceOptions{},
		}
		for _, svcAdvert := range svcAdvertisements {
			bgpAdvert.Service.Addresses = append(bgpAdvert.Service.Addresses, ciliumv2.BGPServiceAddressType(svcAdvert))
		}
		advertisement.Spec.Advertisements = append(advertisement.Spec.Advertisements, bgpAdvert)
	}
	if egwSelector, exists := egwSelectors[vr.LocalASN]; exists {
		advertisement.Spec.Advertisements = append(advertisement.Spec.Advertisements, isovalentv1.BGPAdvertisement{
			AdvertisementType: isovalentv1.BGPEGWAdvert,
			Selector:          egwSelector,
		})
	}
	for idx, advert := range advertisement.Spec.Advertisements {
		advertisement.Spec.Advertisements[idx].Attributes, err = mapBGPPathAttributes(pathAttributes, &advert)
		if err != nil {
			return nil, err
		}
	}
	return advertisement, nil
}

// mapBGPPathAttributes maps provided BGPv1 CiliumBGPPathAttributes to BGPv2 BGPAttributes for the provided advertisement.
// May return an error, as some mappings are not supported.
func mapBGPPathAttributes(pathAttributes []legacyv2alpha1.CiliumBGPPathAttributes, advert *isovalentv1.BGPAdvertisement) (*isovalentv1.BGPAttributes, error) {
	var res *isovalentv1.BGPAttributes
	for _, attr := range pathAttributes {
		if attr.SelectorType == legacyv2alpha1.CiliumLoadBalancerIPPoolSelectorName {
			return nil, fmt.Errorf("%w: %s advertisedPathAttributes.selectorType can not be translated to BGPv2", errBGPv2MappingUnsupported, attr.SelectorType)
		}
		if attr.SelectorType == string(advert.AdvertisementType) ||
			(attr.SelectorType == egwPolicySelectorType && advert.AdvertisementType == isovalentv1.BGPEGWAdvert) {
			if attr.Selector != nil {
				if attr.SelectorType == legacyv2alpha1.PodCIDRSelectorName {
					return nil, fmt.Errorf("%w: %s advertisedPathAttributes.selectorType with non-nil selector can not be translated to BGPv2", errBGPv2MappingUnsupported, attr.SelectorType)
				}
				if attr.SelectorType == legacyv2alpha1.CiliumPodIPPoolSelectorName && !attr.Selector.DeepEqual(advert.Selector) {
					return nil, fmt.Errorf("%w: advertisedPathAttributes.selector of %s selectorType does not match with virtualRouters.podIPPoolSelector", errBGPv2MappingUnsupported, attr.SelectorType)
				}
				if attr.SelectorType == egwPolicySelectorType && !attr.Selector.DeepEqual(advert.Selector) {
					return nil, fmt.Errorf("%w: advertisedPathAttributes.selector of %s selectorType does not match with virtualRouters.egressGatewayPolicySelector", errBGPv2MappingUnsupported, attr.SelectorType)
				}
			}
			if res != nil {
				return nil, fmt.Errorf("%w: %s multiple advertisedPathAttributes with the same selectorType can not be translated to BGPv2", errBGPv2MappingUnsupported, attr.SelectorType)
			}
			res = &isovalentv1.BGPAttributes{
				Communities:     toV2Communities(attr.Communities),
				LocalPreference: attr.LocalPreference,
			}
		}
	}
	return res, nil
}

// createBGPPeerConfig creates a new IsovalentBGPPeerConfig with configuration retrieved from the input arguments.
func createBGPPeerConfig(name string, neigh *legacyv2alpha1.CiliumBGPNeighbor, advertisement *isovalentv1.IsovalentBGPAdvertisement) *isovalentv1.IsovalentBGPPeerConfig {
	peerConfig := &isovalentv1.IsovalentBGPPeerConfig{
		TypeMeta: metav1.TypeMeta{
			APIVersion: isovalentv1.SchemeGroupVersion.String(),
			Kind:       bgpPeeringPolicyKind,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: isovalentv1.IsovalentBGPPeerConfigSpec{
			AuthSecretRef: neigh.AuthSecretRef,
			EBGPMultihop:  neigh.EBGPMultihopTTL,
		},
	}
	if neigh.GracefulRestart != nil {
		peerConfig.Spec.GracefulRestart = &ciliumv2.CiliumBGPNeighborGracefulRestart{
			Enabled:            neigh.GracefulRestart.Enabled,
			RestartTimeSeconds: neigh.GracefulRestart.RestartTimeSeconds,
		}
	}
	if neigh.PeerPort != nil {
		peerConfig.Spec.Transport = &ciliumv2.CiliumBGPTransport{
			PeerPort: ptr.To(*neigh.PeerPort),
		}
	}
	if neigh.ConnectRetryTimeSeconds != nil || neigh.HoldTimeSeconds != nil || neigh.KeepAliveTimeSeconds != nil {
		peerConfig.Spec.Timers = &ciliumv2.CiliumBGPTimers{
			ConnectRetryTimeSeconds: neigh.ConnectRetryTimeSeconds,
			HoldTimeSeconds:         neigh.HoldTimeSeconds,
			KeepAliveTimeSeconds:    neigh.KeepAliveTimeSeconds,
		}
	}

	families := []legacyv2alpha1.CiliumBGPFamily{
		// default families if not specified in BGPPeeringPolicy
		{Afi: "ipv4", Safi: "unicast"},
		{Afi: "ipv6", Safi: "unicast"},
	}
	if len(neigh.Families) > 0 {
		families = neigh.Families
	}
	for _, family := range families {
		peerConfig.Spec.Families = append(peerConfig.Spec.Families,
			isovalentv1.IsovalentBGPFamilyWithAdverts{
				CiliumBGPFamily: ciliumv2.CiliumBGPFamily{
					Afi:  family.Afi,
					Safi: family.Safi,
				},
				Advertisements: &slimv1.LabelSelector{
					MatchLabels: advertisement.Labels,
				},
			})
	}
	return peerConfig
}

// renderBGPNodeAnnotations renders BGPv1 node annotations from the provided Node object
// and outputs BGPv2 configuration into the provided buffer using the provided printer.
func renderBGPNodeAnnotations(node *corev1.Node, buffer *bytes.Buffer, printer *printers.YAMLPrinter) error {
	annotationMap, err := NewAnnotationMap(node.Annotations)
	if err != nil {
		return fmt.Errorf("failed parsing node annotations: %w", err)
	}
	delete(annotationMap, 0) // ignore empty entry for ASN 0
	if len(annotationMap) == 0 {
		return nil // no overrides necessary
	}

	override := &isovalentv1.IsovalentBGPNodeConfigOverride{
		TypeMeta: metav1.TypeMeta{
			APIVersion: isovalentv1.SchemeGroupVersion.String(),
			Kind:       isovalentv1.IsovalentBGPNodeConfigOverrideKindDefinition,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: node.Name,
		},
	}

	for _, asn := range slices.Sorted(maps.Keys(annotationMap)) {
		instanceOverride := isovalentv1.IsovalentBGPNodeConfigInstanceOverride{
			Name: bgpInstanceName(asn),
		}
		if annotationMap[asn].RouterID != "" {
			instanceOverride.RouterID = ptr.To(annotationMap[asn].RouterID)
		}
		if annotationMap[asn].LocalPort != 0 {
			instanceOverride.LocalPort = ptr.To(annotationMap[asn].LocalPort)
		}
		override.Spec.BGPInstances = append(override.Spec.BGPInstances, instanceOverride)
	}

	err = printer.PrintObj(override, buffer)
	if err != nil {
		return fmt.Errorf("failed printing IsovalentBGPNodeConfigOverride to YAML: %w", err)
	}
	return nil
}

func bgpInstanceName(asn int64) string {
	return fmt.Sprintf("instance-%d", asn)
}
func bgpPeerName(peerAddress netip.Addr) string {
	return fmt.Sprintf("peer-%s", convertAddressForResourceName(peerAddress))
}

func bgpPeerConfigOrAdvertisementName(bgpp *legacyv2alpha1.CiliumBGPPeeringPolicy, asn int64, peerAddress *netip.Addr) string {
	if peerAddress != nil {
		if len(bgpp.Spec.VirtualRouters) > 1 {
			return fmt.Sprintf("%s-%d-peer-%s", bgpp.Name, asn, convertAddressForResourceName(*peerAddress))
		}
		return fmt.Sprintf("%s-peer-%s", bgpp.Name, convertAddressForResourceName(*peerAddress))
	}
	if len(bgpp.Spec.VirtualRouters) > 1 {
		return fmt.Sprintf("%s-%d", bgpp.Name, asn)
	}
	return bgpp.Name
}

func convertAddressForResourceName(addr netip.Addr) string {
	// CRD object name can not contain ":" characters, replace
	tmp := strings.ReplaceAll(addr.String(), "::", "-")
	return strings.ReplaceAll(tmp, ":", ".")
}

func toV2Communities(c *legacyv2alpha1.BGPCommunities) *ciliumv2.BGPCommunities {
	if c == nil {
		return nil
	}
	res := &ciliumv2.BGPCommunities{}
	for _, s := range c.Standard {
		res.Standard = append(res.Standard, ciliumv2.BGPStandardCommunity(s))
	}
	for _, w := range c.WellKnown {
		res.WellKnown = append(res.WellKnown, ciliumv2.BGPWellKnownCommunity(w))
	}
	for _, l := range c.Large {
		res.Large = append(res.Large, ciliumv2.BGPLargeCommunity(l))
	}
	return res
}
