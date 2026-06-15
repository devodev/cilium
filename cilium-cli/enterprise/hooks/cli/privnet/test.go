// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package privnet

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"text/template"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer/yaml"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	yamlutil "k8s.io/apimachinery/pkg/util/yaml"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium/cilium-cli/enterprise/hooks/cli/docker"
	enterpriseK8s "github.com/cilium/cilium/cilium-cli/enterprise/hooks/k8s"
	"github.com/cilium/cilium/cilium-cli/enterprise/hooks/utils"
	"github.com/cilium/cilium/cilium-cli/k8s"
	"github.com/cilium/cilium/cilium-cli/utils/features"
	"github.com/cilium/cilium/enterprise/pkg/privnet/types"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	cslices "github.com/cilium/cilium/pkg/slices"
)

var (
	//go:embed manifests/privatenetwork.yaml
	privateNetworkTemplate string

	//go:embed manifests/vm.yaml
	vmTemplate string

	//go:embed manifests/mock-vm.yaml
	mockVMTemplate string

	//go:embed manifests/vm-echo-script.py
	vmEchoScript string

	//go:embed manifests/nodeattachment.yaml
	nodeAttachmentTemplate string

	//go:embed manifests/configmap.yaml
	configMapTemplate string
)

const (
	NetworkA = "network-a"
	NetworkB = "network-b"
	NetworkC = "network-c"
	NetworkD = "network-d"
	NetworkE = "network-e"
	NetworkF = "network-f"

	EchoServerPort = 8000
)

const (
	echoServerConfigMapName = "echoserver-script"
	echoServerConfigMapKey  = "echoserver.py"
)

type NodeName string

type TestRun struct {
	params     Params
	client     *enterpriseK8s.EnterpriseClient
	inbClients []*enterpriseK8s.EnterpriseClient
	docker     *docker.Client
	log        *slog.Logger

	families       []features.IPFamily
	webhookEnabled bool
	webhookPlanID  k8stypes.UID

	ciliumPodsCluster map[NodeName]check.Pod
	ciliumPodsINBs    map[NodeName]check.Pod

	vms map[NetworkName]map[VMName]VM
	ext map[NetworkName]map[VMName]VM
	unk map[NetworkName]map[VMName]VM

	pod map[VMName]*corev1.Pod

	// indexed by context name
	policies map[string][]k8s.Object

	cancel context.CancelFunc
	failed bool
}

func NewTestRun(
	ctx context.Context,
	cancel context.CancelFunc,
	params Params,
	client *enterpriseK8s.EnterpriseClient,
	inbClients []*enterpriseK8s.EnterpriseClient,
) *TestRun {
	level := slog.LevelInfo
	if params.Debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	}))

	return &TestRun{
		params:     params,
		client:     client,
		inbClients: inbClients,
		log:        log,
		vms:        map[NetworkName]map[VMName]VM{},
		ext:        map[NetworkName]map[VMName]VM{},
		unk:        map[NetworkName]map[VMName]VM{},
		pod:        map[VMName]*corev1.Pod{},

		policies: map[string][]k8s.Object{},

		cancel: cancel,
		failed: false,
	}
}

func objectsFromYAML(yamlStr string) (out []k8s.Object, err error) {
	decoder := yamlutil.NewYAMLOrJSONDecoder(strings.NewReader(yamlStr), 100)

	for chunk := range strings.SplitSeq(yamlStr, "\n---") {
		if strings.TrimSpace(chunk) == "" {
			continue
		}

		var rawObj k8sruntime.RawExtension
		if err := decoder.Decode(&rawObj); err != nil {
			return nil, fmt.Errorf("failed decoding YAML: %w", err)
		}
		obj, _, err := yaml.NewDecodingSerializer(unstructured.UnstructuredJSONScheme).Decode(rawObj.Raw, nil, nil)
		if err != nil {
			return nil, fmt.Errorf("failed deserializing YAML: %w", err)
		}
		unstructuredMap, err := k8sruntime.DefaultUnstructuredConverter.ToUnstructured(obj)
		if err != nil {
			return nil, fmt.Errorf("failed converting YAML to unstructured object: %w", err)
		}

		out = append(out, &unstructured.Unstructured{Object: unstructuredMap})
	}

	return out, nil
}

// toK8sObjects converts a slice of specific k8s objects to a slice of generic k8s objects.
func toK8sObjects[T k8s.Object](objs []T) []k8s.Object {
	ret := make([]k8s.Object, 0, len(objs))
	for _, obj := range objs {
		ret = append(ret, obj)
	}
	return ret
}

// updateNetworkMap updates the target network map with the provided VMs,
// ensuring that inner maps are created as needed.
func updateNetworkMap(target map[NetworkName]map[VMName]VM, vms []VM) {
	for _, vm := range vms {
		inner := target[vm.NetName]
		if inner == nil {
			inner = make(map[VMName]VM)
			target[vm.NetName] = inner
		}
		inner[vm.UniqueName()] = vm
	}
}

func (t *TestRun) retrieveCiliumConfig(ctx context.Context) error {
	cm, err := t.client.GetConfigMap(ctx, t.params.CiliumNamespace, defaults.ConfigMapName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("unable to retrieve ConfigMap %q: %w", defaults.ConfigMapName, err)
	}

	if cm.Data["enable-ipv4"] == "true" {
		t.families = append(t.families, features.IPFamilyV4)
	}

	if cm.Data["enable-ipv6"] == "true" {
		t.families = append(t.families, features.IPFamilyV6)
	}

	if cm.Data["private-networks-webhook-enabled"] == "true" {
		t.webhookEnabled = true
	}

	return nil
}

func (t *TestRun) retrieveMTVConfig(ctx context.Context) error {
	if !t.webhookEnabled {
		return nil
	}
	plan := &unstructured.Unstructured{}
	plan.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "forklift.konveyor.io",
		Version: "v1beta1",
		Kind:    "Plan",
	})
	plan, err := t.client.GetGeneric(ctx, t.params.TestNamespace, t.params.ForkliftPlanName, plan)
	if err != nil {
		return err
	}

	t.webhookPlanID = plan.GetUID()
	return nil
}

func (t *TestRun) retrieveCiliumPods(ctx context.Context) error {
	list := func(client *k8s.Client) (iter.Seq2[NodeName, check.Pod], error) {
		pods, err := client.ListPods(ctx, t.params.CiliumNamespace, metav1.ListOptions{LabelSelector: t.params.AgentPodSelector})
		if err != nil {
			return nil, fmt.Errorf("listing pods: %w", err)
		}

		if len(pods.Items) == 0 {
			return nil, fmt.Errorf("no pod found in namespace %s matching selector %q", t.params.CiliumNamespace, t.params.AgentPodSelector)
		}

		return func(yield func(NodeName, check.Pod) bool) {
			for _, pod := range pods.Items {
				if !yield(NodeName(pod.Spec.NodeName), check.Pod{K8sClient: client, Pod: &pod}) {
					return
				}
			}
		}, nil
	}

	got, err := list(t.client.Client)
	if err != nil {
		return fmt.Errorf("retrieving Cilium pods in %s: %w", t.client.ClusterName(), err)
	}
	t.ciliumPodsCluster = maps.Collect(got)

	t.ciliumPodsINBs = make(map[NodeName]check.Pod)
	for _, client := range t.inbClients {
		got, err := list(client.Client)
		if err != nil {
			return fmt.Errorf("retrieving Cilium pods in %s: %w", client.ClusterName(), err)
		}
		maps.Insert(t.ciliumPodsINBs, got)
	}

	return nil
}

func (t *TestRun) allCiliumPods() iter.Seq2[NodeName, check.Pod] {
	return func(yield func(NodeName, check.Pod) bool) {
		for node, pod := range t.ciliumPodsCluster {
			if !yield(node, pod) {
				return
			}
		}
		for node, pod := range t.ciliumPodsINBs {
			if !yield(node, pod) {
				return
			}
		}
	}
}

func (t *TestRun) createNamespace(ctx context.Context, client *enterpriseK8s.EnterpriseClient) error {
	_, err := client.GetNamespace(ctx, t.params.TestNamespace, metav1.GetOptions{})
	if err != nil {
		t.log.Info(fmt.Sprintf("📜 Creating namespace %s in cluster %s", t.params.TestNamespace, client.ClusterName()))
		namespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: t.params.TestNamespace,
			},
		}
		_, err = client.CreateNamespace(ctx, namespace, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("failed creating namespace %s in cluster %s: %w", t.params.TestNamespace, client.ClusterName(), err)
		}
	} else {
		t.log.Info(fmt.Sprintf("📜 Namespace %s already exists in cluster %s", t.params.TestNamespace, client.ClusterName()))
	}
	return nil
}

func renderNetworkPolicy(tmpl string, params PolicyParams) ([]k8s.Object, error) {
	policyYaml, err := renderTemplate(tmpl, params)
	if err != nil {
		return nil, fmt.Errorf("failed to render IsovalentNetworkPolicy template: %w", err)
	}
	policyObjs, err := utils.ParseYAML[*isovalentv1alpha1.IsovalentNetworkPolicy](policyYaml)
	if err != nil || len(policyObjs) == 0 {
		return nil, fmt.Errorf("failed to deserializing manifest for IsovalentNetworkPolicy: %w", err)
	}

	return toK8sObjects(policyObjs), nil
}

type networkTemplateData struct {
	Network         NetworkName
	Prefixes        []Subnet
	INBClusterNames []string
	Routes          []Route
}

func (t *TestRun) renderClusterNetworkTopology(network NetworkName, ndata NetworkData) ([]k8s.Object, error) {
	var objs []k8s.Object

	data := networkTemplateData{
		Network:  network,
		Prefixes: ndata.Prefixes,
	}

	for _, inb := range ndata.INBs {
		data.INBClusterNames = append(data.INBClusterNames, inb.ClusterName)
	}

	if len(ndata.NodeAttachments) > 0 {
		attachmentData := attachmentTemplateData{
			Network:     network,
			Attachments: ndata.NodeAttachments,
		}
		attachmentYAML, err := renderTemplate(nodeAttachmentTemplate, attachmentData)
		if err != nil {
			return nil, fmt.Errorf("failed rendering template for node attachment %s: %w", network, err)
		}
		attachmentObjs, err := utils.ParseYAML[*isovalentv1alpha1.PrivateNetworkNodeAttachment](attachmentYAML)
		if err != nil || len(attachmentObjs) == 0 {
			return nil, fmt.Errorf("failed deserializing manifest for node attachment %s: %w", network, err)
		}
		objs = append(objs, toK8sObjects(attachmentObjs)...)
	}

	networkYAML, err := renderTemplate(privateNetworkTemplate, data)
	if err != nil {
		return nil, fmt.Errorf("failed rendering template for network %s: %w", network, err)
	}
	networkObjs, err := utils.ParseYAML[*isovalentv1alpha1.ClusterwidePrivateNetwork](networkYAML)
	if err != nil || len(networkObjs) == 0 {
		return nil, fmt.Errorf("failed deserializing manifest for network %s: %w", network, err)
	}

	return append(objs, toK8sObjects(networkObjs)...), nil
}

func (t *TestRun) renderClusterVMs(vms []DesiredVM) ([]k8s.Object, error) {
	var objs []k8s.Object

	for _, vm := range vms {
		if !vm.SupportsFamilies(t.families...) {
			// Skip VMs that only have unsupported IPs
			continue
		}

		type vmData struct {
			DesiredVM
			TestNamespace   string
			VMImage         string
			MockVMImage     string
			ScriptConfigMap string
			ServePort       int
			NeedsAnnotation bool
			PlanID          k8stypes.UID
		}
		data := vmData{
			DesiredVM:       vm,
			TestNamespace:   t.params.TestNamespace,
			VMImage:         t.params.VMImage,
			MockVMImage:     t.params.MockVMImage,
			ScriptConfigMap: echoServerConfigMapName,
			ServePort:       EchoServerPort,
			NeedsAnnotation: !t.webhookEnabled || vm.ID == "",
			PlanID:          t.webhookPlanID,
		}

		var tmpl = vmTemplate
		if data.Mock {
			tmpl = mockVMTemplate
		}

		vmYAML, err := renderTemplate(tmpl, data)
		if err != nil {
			return nil, fmt.Errorf("failed rendering template for VM %s: %w", vm.Name, err)
		}
		vmObjs, err := objectsFromYAML(vmYAML)
		if err != nil {
			return nil, fmt.Errorf("failed deserializing manifest for VM %s: %w", vm.Name, err)
		}

		objs = append(objs, vmObjs...)
	}

	return objs, nil
}

func (t *TestRun) renderConfigMap(name string, data map[string]string) ([]k8s.Object, error) {
	var params = struct {
		Name          string
		TestNamespace string
		Data          map[string]string
	}{
		Name:          name,
		TestNamespace: t.params.TestNamespace,
		Data:          data,
	}

	manifest, err := renderTemplate(configMapTemplate, params)
	if err != nil {
		return nil, fmt.Errorf("failed rendering template for ConfigMap %s: %w", name, err)
	}

	objs, err := objectsFromYAML(manifest)
	if err != nil {
		return nil, fmt.Errorf("failed deserializing manifest for ConfigMap %s: %w", name, err)
	}

	return objs, nil
}

type attachmentTemplateData struct {
	Network     NetworkName
	Attachments []NodeAttachment
}

func (t *TestRun) applyINBNetworkTopology(ctx context.Context, network NetworkName, ndata NetworkData) error {
	for _, inb := range ndata.INBs {
		data := networkTemplateData{
			Network:  network,
			Prefixes: ndata.Prefixes,
		}

		attachmentData := attachmentTemplateData{
			Network:     network,
			Attachments: inb.NodeAttachments,
		}

		networkYAML, err := renderTemplate(privateNetworkTemplate, data)
		if err != nil {
			return fmt.Errorf("failed rendering template for network %s: %w", network, err)
		}
		networkObjs, err := utils.ParseYAML[*isovalentv1alpha1.ClusterwidePrivateNetwork](networkYAML)
		if err != nil || len(networkObjs) == 0 {
			return fmt.Errorf("failed deserializing manifest for network %s: %w", network, err)
		}

		attachmentYAML, err := renderTemplate(nodeAttachmentTemplate, attachmentData)
		if err != nil {
			return fmt.Errorf("failed rendering template for node attachment %s: %w", network, err)
		}
		attachmentObjs, err := utils.ParseYAML[*isovalentv1alpha1.PrivateNetworkNodeAttachment](attachmentYAML)
		if err != nil || len(attachmentObjs) == 0 {
			return fmt.Errorf("failed deserializing manifest for node attachment %s: %w", network, err)
		}

		objs := append(toK8sObjects(networkObjs), toK8sObjects(attachmentObjs)...)
		for _, client := range t.inbClients {
			if client.ClusterName() == "kind-"+inb.ClusterName {
				if _, _, err := t.applyObjs(ctx, client, objs); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (t *TestRun) waitForVMToBeReady(ctx context.Context, namespace, name string) error {
	ctx, cancel := context.WithTimeout(ctx, check.LongTimeout)
	defer cancel()

	t.log.Info(fmt.Sprintf("⌛ Waiting for VM %s to become ready", name))
	for {
		vm := &unstructured.Unstructured{}
		vm.SetGroupVersionKind(schema.GroupVersionKind{
			Group: "kubevirt.io", Version: "v1", Kind: "VirtualMachine",
		})

		vm, err := t.client.GetGeneric(ctx, namespace, name, vm)
		if err != nil {
			// Do not retry the errors here, as deemed to be fatal.
			return fmt.Errorf("failed retrieving VM object: %w", err)
		}

		ready, _, err := unstructured.NestedBool(vm.UnstructuredContent(), "status", "ready")
		if err != nil {
			// Do not retry the errors here, as deemed to be fatal.
			return fmt.Errorf("failed checking VM readiness status: %w", err)
		}

		if ready {
			return nil
		}

		select {
		case <-ctx.Done():
			return errors.New("timed out waiting for VM to become ready")
		case <-time.After(check.PollInterval):
		}
	}
}

func (t *TestRun) waitForMockVMToBeReady(ctx context.Context, namespace, name string) error {
	ctx, cancel := context.WithTimeout(ctx, check.LongTimeout)
	defer cancel()

	t.log.Info(fmt.Sprintf("⌛ Waiting for mock VM %s to become ready", name))
	for {
		err := t.client.CheckDeploymentStatus(ctx, namespace, name)
		if err == nil {
			return nil
		}

		select {
		case <-ctx.Done():
			return errors.New("timed out waiting for mock VM to become ready")
		case <-time.After(check.PollInterval):
		}
	}
}

func (t *TestRun) waitForNAD(ctx context.Context, namespace string, name string) error {
	ctx, cancel := context.WithTimeout(ctx, check.ShortTimeout)
	defer cancel()

	t.log.Info(fmt.Sprintf("⌛ Waiting for NetworkAttachmentDefinition %s/%s to appear", namespace, name))
	for {
		nad := &unstructured.Unstructured{}
		nad.SetGroupVersionKind(schema.GroupVersionKind{
			Group: "k8s.cni.cncf.io", Version: "v1", Kind: "NetworkAttachmentDefinition",
		})

		_, err := t.client.GetGeneric(ctx, namespace, name, nad)
		if err == nil {
			return nil
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for NetworkAttachmentDefinition %s/%s to appear (last error: %w)",
				namespace, name, err)
		case <-time.After(check.PollInterval):
		}
	}
}

func (t *TestRun) retrieveExternalVMs(ctx context.Context, client *enterpriseK8s.EnterpriseClient) ([]VM, error) {
	imes, err := client.EnterpriseCiliumClientset.IsovalentV1alpha1().
		PrivateNetworkExternalEndpoints(t.params.TestNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing PrivateNetworkExternalEndpoints: %w", err)
	}

	vms := make([]VM, len(imes.Items))
	for i, ime := range imes.Items {
		addrs := ime.Spec.Interface.Addressing
		var ip4, ip6 netip.Addr
		var err error

		if addrs.IPv4 != "" {
			ip4, err = netip.ParseAddr(addrs.IPv4)
			if err != nil {
				return nil, fmt.Errorf("parsing IP address %q: %w", addrs.IPv4, err)
			}
		}

		if addrs.IPv6 != "" {
			ip6, err = netip.ParseAddr(addrs.IPv6)
			if err != nil {
				return nil, fmt.Errorf("parsing IP address %q: %w", addrs.IPv6, err)
			}
		}

		vms[i] = VM{
			Name:    VMName(ime.GetName()),
			NetName: NetworkName(ime.Spec.Interface.Network),
			NetIPv4: ip4,
			NetIPv6: ip6,
			NetMAC:  ime.Spec.Interface.MAC,
			Kind:    VMKindExtern,
		}
	}
	return vms, nil
}

func (t *TestRun) VM(network NetworkName, vmName VMName) VM {
	return t.vms[network][vmName]
}

func (t *TestRun) ExternalVM(network NetworkName, vmName VMName) VM {
	return t.ext[network][vmName]
}

func (t *TestRun) AllExternalVMs(network NetworkName) iter.Seq[VM] {
	return maps.Values(t.ext[network])
}

func (t *TestRun) UnknownVM(network NetworkName, vmName VMName) VM {
	return t.unk[network][vmName]
}

func (t *TestRun) AllUnknownVMs(network NetworkName) iter.Seq[VM] {
	return maps.Values(t.unk[network])
}

func (t *TestRun) VirtLauncherPodForVM(vm VM) *corev1.Pod {
	return t.pod[vm.Name]
}

func (t *TestRun) SetupAndValidate(ctx context.Context) (err error) {
	t.docker, err = docker.NewClient()
	if err != nil {
		return err
	}

	if err := t.retrieveCiliumConfig(ctx); err != nil {
		return fmt.Errorf("failed retrieving Cilium configuration: %w", err)
	}
	if err := t.retrieveMTVConfig(ctx); err != nil {
		return fmt.Errorf("failed retrieving MTV configuration: %w", err)
	}
	if err := t.retrieveCiliumPods(ctx); err != nil {
		return fmt.Errorf("failed retrieving Cilium pods: %w", err)
	}

	if err := t.createNamespace(ctx, t.client); err != nil {
		return err
	}

	var nets []k8s.Object
	for network, networkData := range networkTopology.Networks {
		objs, err := t.renderClusterNetworkTopology(network, networkData)
		if err != nil {
			return err
		}
		nets = slices.Concat(nets, objs)
	}

	cms, err := t.renderConfigMap(echoServerConfigMapName, map[string]string{echoServerConfigMapKey: vmEchoScript})
	if err != nil {
		return err
	}

	if _, _, err := t.applyObjs(ctx, t.client, slices.Concat(nets, cms)); err != nil {
		return err
	}

	var nads = sets.New[string]()
	for _, vm := range networkTopology.VMs {
		for _, iface := range vm.Interfaces {
			if iface.NAD != "" {
				nads.Insert(iface.NAD)
			}
		}
	}

	// Wait for the NetworkAttachmentDefinitions to be generated, before trying
	// to apply the VMs. Otherwise, the webhook would fail if the target NAD
	// does not exist yet.
	for nad := range nads {
		err := t.waitForNAD(ctx, t.params.TestNamespace, nad)
		if err != nil {
			return err
		}
	}

	vms, err := t.renderClusterVMs(networkTopology.VMs)
	if err != nil {
		return err
	}

	updateNetworkMap(t.vms, slices.Concat(
		cslices.Map(networkTopology.VMs, DesiredVM.ToVMs)...),
	)

	if _, _, err := t.applyObjs(ctx, t.client, vms); err != nil {
		return err
	}

	// update network definitions in inb clients and collect unknown endpoints
	for network, networkData := range networkTopology.Networks {
		err := t.applyINBNetworkTopology(ctx, network, networkData)
		if err != nil {
			return err
		}

		t.unk[network] = make(map[VMName]VM, len(networkData.Unknown))
		for _, vm := range networkData.Unknown {
			t.unk[network][vm.Name] = vm
		}
	}

	for _, vms := range t.vms {
		for vmName, vm := range vms {
			if vm.Kind == VMKindSecondary {
				continue
			}
			if !vm.SupportsFamilies(t.families...) {
				// Skip VMs that only have unsupported IPs
				continue
			}

			var wait = t.waitForVMToBeReady
			if vm.Mock {
				wait = t.waitForMockVMToBeReady
			}

			err := wait(ctx, t.params.TestNamespace, vmName.String())
			if err != nil {
				return fmt.Errorf("failed waiting for VM %s to become ready: %w", vmName, err)
			}

			t.pod[vmName], err = t.client.FindLauncherPodForVM(ctx, t.params.TestNamespace, vmName.String())
			if err != nil {
				return err
			}
		}
	}

	for _, client := range t.inbClients {
		if err := t.createNamespace(ctx, client); err != nil {
			return err
		}

		vms, err := t.retrieveExternalVMs(ctx, client)
		if err != nil {
			return fmt.Errorf("failed retrieving external VMs from cluster %s: %w", client.ClusterName(), err)
		}
		updateNetworkMap(t.ext, vms)
	}

	if len(t.inbClients) > 0 && len(t.ext) == 0 {
		return errors.New("INB clients specified, but no external VM found")
	}

	// Wait for INBs to become healthy
	for nodeName, agent := range t.ciliumPodsCluster {
		_, err := t.waitForINBs(ctx, agent, t.assertSteadyState())
		if err != nil {
			return fmt.Errorf("Failed to wait for INBs to become ready on node %q: %w", nodeName, err)
		}
	}

	return nil
}

func (t *TestRun) Run(
	ctx context.Context,
	scenario Scenario,
	expectations Expectation,
	overrideIPFamilies ...features.IPFamily,
) {
	if err := ctx.Err(); err != nil {
		// context done or cancelled due to previous scenario failure
		return
	}

	scenario.Run(ctx, expectations, overrideIPFamilies...)
	if scenario.Failed() && t.cancel != nil {
		t.log.Error(fmt.Sprintf("Scenario %s failed", scenario.Name()))
		t.cancel()
		t.cancel = nil
		t.failed = true
	}
}

func (t *TestRun) Failed() bool {
	return t.failed
}

func (t *TestRun) Cleanup(ctx context.Context) {
	inbSuccess := true
	for _, client := range t.inbClients {
		for _, obj := range t.policies[client.ContextName()] {
			if !t.cleanupObj(ctx, client, obj) {
				inbSuccess = false
			}
		}
	}
	clusterSuccess := true
	for _, obj := range t.policies[t.client.ContextName()] {
		if !t.cleanupObj(ctx, t.client, obj) {
			clusterSuccess = false
		}
	}
	// Reset the map, so that a subsequent call to Cleanup doesn't attempt
	// to remove the same policies again. Unless something went wrong in the
	// cleanup, in which case we keep the map content intact.
	if inbSuccess {
		for _, client := range t.inbClients {
			delete(t.policies, client.ContextName())
		}
	}
	if clusterSuccess {
		delete(t.policies, t.client.ContextName())
	}
}

func (t *TestRun) cleanupObj(ctx context.Context, client *enterpriseK8s.EnterpriseClient, obj k8s.Object) bool {
	kind := obj.GetObjectKind().GroupVersionKind().Kind
	name := obj.GetName()
	if obj.GetNamespace() != "" {
		name = obj.GetNamespace() + "/" + name
	}

	t.log.Info(fmt.Sprintf("📜 Removing %s %s", kind, name))
	err := client.DeleteGeneric(ctx, obj)
	if err != nil && !k8serrors.IsNotFound(err) {
		t.log.Warn(fmt.Sprintf("⚠️ Failed removing %s %s: %v", kind, name, err))
		return false
	}
	return true
}

var networks = []NetworkName{NetworkA, NetworkB, NetworkC, NetworkD}

func (t *TestRun) Networks() iter.Seq[NetworkName] {
	return slices.Values(networks)
}

func (t *TestRun) INBNodeNames() iter.Seq[NodeName] {
	return maps.Keys(t.ciliumPodsINBs)
}

// getCiliumPolicyRevision returns the current policy revision of a Cilium pod.
func getCiliumPolicyRevision(ctx context.Context, pod check.Pod) (int, error) {
	stdout, err := pod.K8sClient.ExecInPod(ctx, pod.Pod.Namespace, pod.Pod.Name,
		defaults.AgentContainerName, []string{"cilium-dbg", "policy", "get", "-o", "jsonpath='{.revision}'"})
	if err != nil {
		return 0, err
	}
	revision, err := strconv.Atoi(strings.Trim(stdout.String(), "'\n"))
	if err != nil {
		return 0, fmt.Errorf("revision %q is not valid: %w", stdout.String(), err)
	}
	return revision, nil
}

// waitCiliumPolicyRevision waits for a Cilium pod to reach at least a given policy revision.
func waitCiliumPolicyRevision(ctx context.Context, pod check.Pod, rev int, timeout time.Duration) error {
	timeoutStr := strconv.Itoa(int(timeout.Seconds()))
	_, err := pod.K8sClient.ExecInPod(ctx, pod.Pod.Namespace, pod.Pod.Name,
		defaults.AgentContainerName, []string{"cilium-dbg", "policy", "wait", strconv.Itoa(rev), "--max-wait-time", timeoutStr})
	return err
}

func (t *TestRun) applyPolicies(ctx context.Context, policies ...PolicyParams) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("previous test operation failed: %w", err)
	}

	clusterPolicies := []k8s.Object{}
	inbPolicies := []k8s.Object{}
	for _, params := range policies {
		manifest, err := policyManifests.ReadFile(filepath.Join(policyDir, params.Manifest))
		if err != nil {
			return err
		}
		policy, err := renderNetworkPolicy(string(manifest), params)
		if err != nil {
			return err
		}
		if params.ApplyOnINB {
			inbPolicies = append(inbPolicies, policy...)
		} else {
			clusterPolicies = append(clusterPolicies, policy...)
		}
	}

	policyRevisions := map[check.Pod]int{}
	for _, ciliumPod := range t.allCiliumPods() {
		rev, err := getCiliumPolicyRevision(ctx, ciliumPod)
		if err != nil {
			return fmt.Errorf("failed getting cilium policy revision: %w", err)
		}
		policyRevisions[ciliumPod] = rev
	}

	// Apply policies to INB clusters
	changedPolicies := map[string]int{}
	for _, client := range t.inbClients {
		changes, successful, err := t.applyObjs(ctx, client, inbPolicies)
		t.policies[client.ContextName()] = append(t.policies[client.ContextName()], successful...)
		if err != nil {
			return err
		}
		changedPolicies[client.ContextName()] = changes
	}

	// Apply policies to workload cluster
	changes, successful, err := t.applyObjs(ctx, t.client, clusterPolicies)
	t.policies[t.client.ContextName()] = append(t.policies[t.client.ContextName()], successful...)
	if err != nil {
		return err
	}
	changedPolicies[t.client.ContextName()] = changes

	for _, ciliumPod := range t.allCiliumPods() {
		expectedRev := policyRevisions[ciliumPod] + changedPolicies[ciliumPod.K8sClient.ContextName()]
		err := waitCiliumPolicyRevision(ctx, ciliumPod, expectedRev, 30*time.Second)
		if err != nil {
			return fmt.Errorf("failed waiting for cilium policy revision: %w", err)
		}
	}

	return nil
}

func (t *TestRun) ApplyPolicies(ctx context.Context, policies ...PolicyParams) {
	err := t.applyPolicies(ctx, policies...)
	if err != nil && t.cancel != nil {
		t.log.Error(fmt.Sprintf("Failed to apply network policies: %s", err))
		t.cancel()
		t.cancel = nil
		t.failed = true
	}
}

func (t *TestRun) applyObjs(ctx context.Context, client *enterpriseK8s.EnterpriseClient, toApply []k8s.Object) (changes int, successful []k8s.Object, err error) {
	for _, obj := range toApply {
		kind := obj.GetObjectKind().GroupVersionKind().Kind
		name := obj.GetName()
		if namespace := obj.GetNamespace(); namespace != "" {
			name = namespace + "/" + name
		}
		t.log.Info(fmt.Sprintf("📜 Applying %s %s on cluster %s", kind, name, client.ClusterName()))
		existing, err := client.GetGeneric(ctx, obj.GetNamespace(), obj.GetName(), obj)
		if err != nil && !k8serrors.IsNotFound(err) {
			return changes, successful, fmt.Errorf("failed to retrieve %s/%s: %w", obj.GetNamespace(), obj.GetName(), err)
		}

		applied, err := client.ApplyGeneric(ctx, obj)
		if err != nil {
			return changes, successful, fmt.Errorf("failed applying %s %s on cluster %s: %w", kind, name, client.ClusterName(), err)
		}

		if existing == nil || existing.GetGeneration() != applied.GetGeneration() {
			changes++
		}

		successful = append(successful, applied)
	}
	return changes, successful, nil
}

func (t *TestRun) vmExec(ctx context.Context, vm VM, cmd []string) (stdout, stderr string, err error) {
	if vm.Kind == VMKindExtern || vm.Kind == VMKindUnknown {
		return t.docker.ContainerExec(ctx, vm.Name.String(), cmd)
	}

	pod := t.VirtLauncherPodForVM(vm)
	if pod == nil {
		return "", "", fmt.Errorf("no launcher pod found for VM %s", vm.Name)
	}

	var bout, berr bytes.Buffer

	if vm.Mock {
		err = t.client.ExecInPodWithWriters(ctx, nil, pod.Namespace, pod.Name, "compute", cmd, &bout, &berr)
	} else {
		err = t.client.ExecInVMWithWriters(ctx, pod, cmd, &bout, &berr)
	}

	return bout.String(), berr.String(), err
}

func (t *TestRun) theFamilies(overrides ...features.IPFamily) iter.Seq[features.IPFamily] {
	if len(overrides) == 0 {
		return slices.Values(t.families)
	}

	return func(yield func(features.IPFamily) bool) {
		for _, fam := range overrides {
			if slices.Contains(t.families, fam) {
				if !yield(fam) {
					return
				}
			}
		}
	}
}

func renderTemplate(templ string, data any) (string, error) {
	t, err := template.New("template").Funcs(template.FuncMap{
		// Slightly adapted version of:
		// https://github.com/Masterminds/sprig/blob/8cb06fe3c8b0f1163c26b0a558669da72ee14656/strings.go#L109-L112
		"indent": func(spaces int, v string) string {
			pad := strings.Repeat(" ", spaces)
			return strings.ReplaceAll(v, "\n", "\n"+pad)
		},
		"formatPrimaryNetworkAttachment": func(ifaces []Interface) (string, error) {
			if len(ifaces) == 0 {
				return "", errors.New("no interface provided")
			}

			out, err := json.MarshalIndent(ifaces[0].ToNetworkAttachment(0), "", "  ")
			return string(out), err
		},
		"formatSecondaryNetworkAttachments": func(ifaces []Interface) (string, error) {
			if len(ifaces) <= 1 {
				return "", nil
			}

			var attachments = make([]types.NetworkAttachment, 0, len(ifaces)-1)
			for idx, iface := range ifaces[1:] {
				attachments = append(attachments, iface.ToNetworkAttachment(uint(idx+1)))
			}

			out, err := json.MarshalIndent(attachments, "", "  ")
			return string(out), err
		},
		"formatMultusNetworks": func(ifaces []Interface) (out string) {
			for idx, iface := range ifaces[1:] {
				out += fmt.Sprintf("%s@%s,", iface.NAD, iface.Name(uint(idx+1)))
			}

			return strings.TrimRight(out, ",")
		},
	}).Parse(templ)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}
