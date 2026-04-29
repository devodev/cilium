// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package tests

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/utils/wait"
	inspectionConfig "github.com/cilium/cilium/enterprise/pkg/inspection/config"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/time"
)

const (
	inspectionSnifferName          = "inspection-sniffer"
	inspectionSenderName           = "inspection-sender"
	InspectionSenderSelectedName   = "inspection-sender-selected"
	InspectionSenderSkippedName    = "inspection-sender-skipped"
	inspectionLabelKey             = "inspection"
	inspectionSnifferLabel         = "sniffer"
	inspectionSenderLabel          = "sender"
	InspectionScopeLabelKey        = "inspection-scope"
	InspectionSelectionLabelKey    = "inspection-selection"
	InspectionSelectionSelected    = "selected"
	InspectionSelectionSkipped     = "skipped"
	inspectionCaptureFile          = "/tmp/inspection_capture.pcap"
	inspectionProbePort            = 19876
	inspectionSnifferSettleTime    = 60 * time.Second
	inspectionEndpointReadyTimeout = 60 * time.Second
	inspectionTestTimeout          = 60 * time.Second
)

var (
	inspectionSnifferSelector = fmt.Sprintf("%s=%s", inspectionLabelKey, inspectionSnifferLabel)
	inspectionSenderSelector  = fmt.Sprintf("%s=%s", inspectionLabelKey, inspectionSenderLabel)
)

type InspectionWorkloadSelectors struct {
	SnifferSelector string
	SenderSelector  string
}

type PassiveInspectionPhase struct {
	Name                   string
	DeleteInspectionConfig bool
	EndpointSelector       *api.EndpointSelector
	SnifferSelector        string
	IncludedNamespace      string
	IncludedSelector       string
	IncludedTagPrefix      string
	ExcludedNamespace      string
	ExcludedSelector       string
	ExcludedTagPrefix      string
}

func InspectionSelectorsForScope(scope string) InspectionWorkloadSelectors {
	return InspectionWorkloadSelectors{
		SnifferSelector: InspectionScopedSelector(scope, inspectionSnifferSelector),
		SenderSelector:  InspectionScopedSelector(scope, inspectionSenderSelector),
	}
}

func InspectionScopedSelector(scope, selector string) string {
	if scope == "" {
		return selector
	}
	scopeSelector := fmt.Sprintf("%s=%s", InspectionScopeLabelKey, scope)
	if selector == "" {
		return scopeSelector
	}
	return fmt.Sprintf("%s,%s", selector, scopeSelector)
}

func InspectionScopeLabels(scope string) map[string]string {
	if scope == "" {
		return nil
	}
	return map[string]string{InspectionScopeLabelKey: scope}
}

func (s InspectionWorkloadSelectors) withDefaults() InspectionWorkloadSelectors {
	if s.SnifferSelector == "" {
		s.SnifferSelector = inspectionSnifferSelector
	}
	if s.SenderSelector == "" {
		s.SenderSelector = inspectionSenderSelector
	}
	return s
}

func PassiveInspectionVerification(selectors InspectionWorkloadSelectors) check.Scenario {
	return &passiveInspectionVerification{
		ScenarioBase: check.NewScenarioBase(),
		selectors:    selectors.withDefaults(),
	}
}

func PassiveInspectionExcludedNamespaceVerification(excludedNamespace string, selectors InspectionWorkloadSelectors) check.Scenario {
	return &passiveInspectionExcludedNamespaceVerification{
		ScenarioBase:      check.NewScenarioBase(),
		excludedNamespace: excludedNamespace,
		selectors:         selectors.withDefaults(),
	}
}

func PassiveInspectionSelectedPodsVerification(selectors InspectionWorkloadSelectors, includedSelector, excludedSelector string) check.Scenario {
	return &passiveInspectionSelectedPodsVerification{
		ScenarioBase:     check.NewScenarioBase(),
		selectors:        selectors.withDefaults(),
		includedSelector: includedSelector,
		excludedSelector: excludedSelector,
	}
}

func PassiveInspectionPhasedVerification(phases ...PassiveInspectionPhase) check.Scenario {
	return &passiveInspectionPhasedVerification{
		ScenarioBase: check.NewScenarioBase(),
		phases:       phases,
	}
}

type passiveInspectionVerification struct {
	check.ScenarioBase

	selectors InspectionWorkloadSelectors
}

type passiveInspectionPhasedVerification struct {
	check.ScenarioBase

	phases []PassiveInspectionPhase
}

type passiveInspectionExcludedNamespaceVerification struct {
	check.ScenarioBase

	excludedNamespace string
	selectors         InspectionWorkloadSelectors
}

type passiveInspectionSelectedPodsVerification struct {
	check.ScenarioBase

	selectors        InspectionWorkloadSelectors
	includedSelector string
	excludedSelector string
}

func (s *passiveInspectionVerification) Name() string {
	return "passive-inspection-verification"
}

func (s *passiveInspectionExcludedNamespaceVerification) Name() string {
	return "passive-inspection-excluded-namespace-verification"
}

func (s *passiveInspectionSelectedPodsVerification) Name() string {
	return "passive-inspection-selected-pods-verification"
}

func (s *passiveInspectionPhasedVerification) Name() string {
	return "passive-inspection-phased-verification"
}

func (s *passiveInspectionVerification) Run(ctx context.Context, t *check.Test) {
	t.Logf("Running passive inspection verification (interface: %s)", inspectionConfig.InterfaceName)
	defer t.Logf("Finished passive inspection verification")

	snifferPods, err := getInspectionPods(ctx, t, s.selectors.SnifferSelector)
	if err != nil {
		t.Fatalf("Failed to list sniffer pods: %v", err)
	}
	if len(snifferPods) == 0 {
		t.Fatalf("No sniffer pods found with selector %q", s.selectors.SnifferSelector)
	}
	t.Debugf("Found %d sniffer pod(s)", len(snifferPods))

	killCtx, cancel := context.WithCancel(ctx)
	defer func() {
		t.Debugf("Stopping tcpdump listeners")
		cancel()
	}()
	if err := startInspectionSniffers(ctx, killCtx, t, snifferPods, inspectionConfig.InterfaceName); err != nil {
		t.Fatalf("Failed to start sniffers: %v", err)
	}

	t.Debugf("Waiting for tcpdump to start on all sniffer pods...")
	if err := waitForSnifferReady(ctx, t, snifferPods); err != nil {
		t.Fatalf("Sniffers did not become ready: %v", err)
	}

	t.Debugf("Waiting for all Cilium endpoints to reach ready state...")
	if err := waitForInspectionEndpointsReady(ctx, t); err != nil {
		t.Fatalf("Cilium endpoints did not become ready: %v", err)
	}

	senderPods, err := getInspectionPods(ctx, t, s.selectors.SenderSelector)
	if err != nil {
		t.Fatalf("Failed to list sender pods: %v", err)
	}
	if len(senderPods) == 0 {
		t.Fatalf("No sender pods found with selector %q", s.selectors.SenderSelector)
	}
	t.Debugf("Found %d sender pod(s)", len(senderPods))

	probeTag, err := sendInspectionProbes(ctx, t, senderPods, "inspection-probe-")
	if err != nil {
		t.Fatalf("Failed to send inspection probes: %v", err)
	}
	t.Debugf("Sent probes with tag %q from %d sender pod(s)", probeTag, len(senderPods))

	t.Debugf("Waiting for mirrored packets to appear in capture files...")
	if err := waitForInspectionCaptureExpectations(ctx, t, snifferPods, inspectionCaptureFile, func() error {
		_, err := sendInspectionProbes(ctx, t, senderPods, probeTag)
		return err
	}, []string{probeTag}, nil); err != nil {
		t.Fatalf("Inspection mirror verification failed: %v", err)
	}

	t.Logf("✅ Passive inspection verified: mirrored packets captured on all nodes")
}

func (s *passiveInspectionExcludedNamespaceVerification) Run(ctx context.Context, t *check.Test) {
	t.Logf("Running passive inspection excluded-namespace verification (interface: %s, excluded namespace: %s)", inspectionConfig.InterfaceName, s.excludedNamespace)
	defer t.Logf("Finished passive inspection excluded-namespace verification")

	snifferPods, err := getInspectionPods(ctx, t, s.selectors.SnifferSelector)
	if err != nil {
		t.Fatalf("Failed to list sniffer pods: %v", err)
	}
	if len(snifferPods) == 0 {
		t.Fatalf("No sniffer pods found with selector %q", s.selectors.SnifferSelector)
	}

	killCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	if err := startInspectionSniffers(ctx, killCtx, t, snifferPods, inspectionConfig.InterfaceName); err != nil {
		t.Fatalf("Failed to start sniffers: %v", err)
	}
	if err := waitForSnifferReady(ctx, t, snifferPods); err != nil {
		t.Fatalf("Sniffers did not become ready: %v", err)
	}
	if err := waitForInspectionEndpointsReady(ctx, t); err != nil {
		t.Fatalf("Cilium endpoints did not become ready: %v", err)
	}

	includedSenderPods, err := getInspectionPods(ctx, t, s.selectors.SenderSelector)
	if err != nil {
		t.Fatalf("Failed to list included sender pods: %v", err)
	}
	if len(includedSenderPods) == 0 {
		t.Fatalf("No included sender pods found with selector %q", s.selectors.SenderSelector)
	}

	excludedSenderPods, err := getInspectionPodsInNamespace(ctx, t, s.excludedNamespace, s.selectors.SenderSelector)
	if err != nil {
		t.Fatalf("Failed to list excluded sender pods: %v", err)
	}
	if len(excludedSenderPods) == 0 {
		t.Fatalf("No excluded sender pods found in namespace %q with selector %q", s.excludedNamespace, s.selectors.SenderSelector)
	}

	includedTag, err := sendInspectionProbes(ctx, t, includedSenderPods, "inspection-include-")
	if err != nil {
		t.Fatalf("Failed to send included inspection probes: %v", err)
	}
	excludedTag, err := sendInspectionProbes(ctx, t, excludedSenderPods, "inspection-exclude-")
	if err != nil {
		t.Fatalf("Failed to send excluded inspection probes: %v", err)
	}

	if err := waitForInspectionCaptureExpectations(ctx, t, snifferPods, inspectionCaptureFile, func() error {
		if _, err := sendInspectionProbes(ctx, t, includedSenderPods, includedTag); err != nil {
			return err
		}
		if _, err := sendInspectionProbes(ctx, t, excludedSenderPods, excludedTag); err != nil {
			return err
		}
		return nil
	}, []string{includedTag}, []string{excludedTag}); err != nil {
		t.Fatalf("Inspection excluded-namespace verification failed: %v", err)
	}

	t.Logf("✅ Passive inspection exclusions verified: included namespaces are mirrored and excluded namespaces are skipped")
}

func (s *passiveInspectionSelectedPodsVerification) Run(ctx context.Context, t *check.Test) {
	t.Logf("Running passive inspection selected-pods verification (interface: %s, included selector: %s, excluded selector: %s)",
		inspectionConfig.InterfaceName, s.includedSelector, s.excludedSelector)
	defer t.Logf("Finished passive inspection selected-pods verification")

	snifferPods, err := getInspectionPods(ctx, t, s.selectors.SnifferSelector)
	if err != nil {
		t.Fatalf("Failed to list sniffer pods: %v", err)
	}
	if len(snifferPods) == 0 {
		t.Fatalf("No sniffer pods found with selector %q", s.selectors.SnifferSelector)
	}

	killCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	if err := startInspectionSniffers(ctx, killCtx, t, snifferPods, inspectionConfig.InterfaceName); err != nil {
		t.Fatalf("Failed to start sniffers: %v", err)
	}
	if err := waitForSnifferReady(ctx, t, snifferPods); err != nil {
		t.Fatalf("Sniffers did not become ready: %v", err)
	}
	if err := waitForInspectionEndpointsReady(ctx, t); err != nil {
		t.Fatalf("Cilium endpoints did not become ready: %v", err)
	}

	includedSenderPods, err := getInspectionPods(ctx, t, s.includedSelector)
	if err != nil {
		t.Fatalf("Failed to list included sender pods: %v", err)
	}
	if len(includedSenderPods) == 0 {
		t.Fatalf("No included sender pods found with selector %q", s.includedSelector)
	}

	excludedSenderPods, err := getInspectionPods(ctx, t, s.excludedSelector)
	if err != nil {
		t.Fatalf("Failed to list excluded sender pods: %v", err)
	}
	if len(excludedSenderPods) == 0 {
		t.Fatalf("No excluded sender pods found with selector %q", s.excludedSelector)
	}

	includedTag, err := sendInspectionProbes(ctx, t, includedSenderPods, "inspection-pod-include-")
	if err != nil {
		t.Fatalf("Failed to send included inspection probes: %v", err)
	}
	excludedTag, err := sendInspectionProbes(ctx, t, excludedSenderPods, "inspection-pod-exclude-")
	if err != nil {
		t.Fatalf("Failed to send excluded inspection probes: %v", err)
	}

	if err := waitForInspectionCaptureExpectations(ctx, t, snifferPods, inspectionCaptureFile, func() error {
		if _, err := sendInspectionProbes(ctx, t, includedSenderPods, includedTag); err != nil {
			return err
		}
		if _, err := sendInspectionProbes(ctx, t, excludedSenderPods, excludedTag); err != nil {
			return err
		}
		return nil
	}, []string{includedTag}, []string{excludedTag}); err != nil {
		t.Fatalf("Inspection selected-pods verification failed: %v", err)
	}

	t.Logf("✅ Passive inspection pod selection verified: selected pods are mirrored and non-selected pods are skipped")
}

func (s *passiveInspectionPhasedVerification) Run(ctx context.Context, t *check.Test) {
	t.Logf("Running phased passive inspection verification (interface: %s)", inspectionConfig.InterfaceName)
	defer t.Logf("Finished phased passive inspection verification")

	if err := preserveInspectionConfig(ctx, t); err != nil {
		t.Fatalf("Failed to preserve inspection config: %v", err)
	}

	for _, phase := range s.phases {
		t.Logf("Running passive inspection phase %q", phase.Name)
		if err := applyInspectionPhaseConfig(ctx, t, phase); err != nil {
			t.Fatalf("Failed to apply inspection config for phase %q: %v", phase.Name, err)
		}
		if err := waitForInspectionEndpointsReady(ctx, t); err != nil {
			t.Fatalf("Cilium endpoints did not become ready for phase %q: %v", phase.Name, err)
		}
		if err := runPassiveInspectionPhase(ctx, t, phase); err != nil {
			t.Fatalf("Passive inspection phase %q failed: %v", phase.Name, err)
		}
	}

	t.Logf("✅ Phased passive inspection verification completed")
}

func newInspectionConfig(endpointSelector *api.EndpointSelector) *isovalentv1alpha1.IsovalentInspectionConfig {
	return &isovalentv1alpha1.IsovalentInspectionConfig{
		TypeMeta: metav1.TypeMeta{
			Kind:       isovalentv1alpha1.IsovalentInspectionConfigKindDefinition,
			APIVersion: "isovalent.com/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: isovalentv1alpha1.InspectionConfigName,
		},
		Spec: isovalentv1alpha1.IsovalentInspectionConfigSpec{
			EndpointSelector: endpointSelector,
		},
	}
}

func preserveInspectionConfig(ctx context.Context, t *check.Test) error {
	originalByCluster := map[string]*isovalentv1alpha1.IsovalentInspectionConfig{}
	probe := newInspectionConfig(nil)

	for _, client := range t.Context().Clients() {
		current, err := client.GetGeneric(ctx, "", isovalentv1alpha1.InspectionConfigName, probe)
		if err != nil {
			if k8sErrors.IsNotFound(err) {
				continue
			}
			return fmt.Errorf("retrieving IsovalentInspectionConfig on %s: %w", client.ClusterName(), err)
		}
		original := &isovalentv1alpha1.IsovalentInspectionConfig{}
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(current.Object, original); err != nil {
			return fmt.Errorf("converting IsovalentInspectionConfig on %s: %w", client.ClusterName(), err)
		}
		originalByCluster[client.ClusterName()] = original
	}

	t.WithFinalizer(func(ctx context.Context) error {
		for _, client := range t.Context().Clients() {
			if original, ok := originalByCluster[client.ClusterName()]; ok {
				if _, err := client.ApplyGeneric(ctx, original); err != nil {
					return fmt.Errorf("restoring IsovalentInspectionConfig on %s: %w", client.ClusterName(), err)
				}
				continue
			}
			if err := client.DeleteGeneric(ctx, newInspectionConfig(nil)); err != nil && !k8sErrors.IsNotFound(err) {
				return fmt.Errorf("deleting IsovalentInspectionConfig on %s: %w", client.ClusterName(), err)
			}
		}
		return nil
	})

	return nil
}

func applyInspectionPhaseConfig(ctx context.Context, t *check.Test, phase PassiveInspectionPhase) error {
	for _, client := range t.Context().Clients() {
		if phase.DeleteInspectionConfig {
			if err := client.DeleteGeneric(ctx, newInspectionConfig(nil)); err != nil && !k8sErrors.IsNotFound(err) {
				return fmt.Errorf("deleting IsovalentInspectionConfig on %s: %w", client.ClusterName(), err)
			}
			continue
		}
		if _, err := client.ApplyGeneric(ctx, newInspectionConfig(phase.EndpointSelector)); err != nil {
			return fmt.Errorf("applying IsovalentInspectionConfig on %s: %w", client.ClusterName(), err)
		}
	}
	return nil
}

func runPassiveInspectionPhase(ctx context.Context, t *check.Test, phase PassiveInspectionPhase) error {
	if phase.SnifferSelector == "" {
		phase.SnifferSelector = inspectionSnifferSelector
	}
	if phase.IncludedNamespace == "" {
		phase.IncludedNamespace = t.Context().Params().TestNamespace
	}
	if phase.IncludedSelector == "" {
		phase.IncludedSelector = inspectionSenderSelector
	}
	if phase.IncludedTagPrefix == "" {
		phase.IncludedTagPrefix = fmt.Sprintf("inspection-%s-include-", phase.Name)
	}
	if phase.ExcludedNamespace == "" {
		phase.ExcludedNamespace = t.Context().Params().TestNamespace
	}
	if phase.ExcludedTagPrefix == "" {
		phase.ExcludedTagPrefix = fmt.Sprintf("inspection-%s-exclude-", phase.Name)
	}

	snifferPods, err := getInspectionPods(ctx, t, phase.SnifferSelector)
	if err != nil {
		return fmt.Errorf("listing sniffer pods: %w", err)
	}
	if len(snifferPods) == 0 {
		return fmt.Errorf("no sniffer pods found with selector %q", phase.SnifferSelector)
	}

	captureFile := fmt.Sprintf("/tmp/inspection_capture_%s.pcap", phase.Name)
	clearInspectionCaptureFile(ctx, t, snifferPods, captureFile)
	killCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	if err := startInspectionSniffersWithCaptureFile(ctx, killCtx, t, snifferPods, inspectionConfig.InterfaceName, captureFile); err != nil {
		return fmt.Errorf("starting sniffers: %w", err)
	}
	if err := waitForSnifferReadyWithCaptureFile(ctx, t, snifferPods, captureFile); err != nil {
		return fmt.Errorf("waiting for sniffers: %w", err)
	}

	includedSenderPods, err := getInspectionPodsInNamespace(ctx, t, phase.IncludedNamespace, phase.IncludedSelector)
	if err != nil {
		return fmt.Errorf("listing included sender pods: %w", err)
	}
	if len(includedSenderPods) == 0 {
		return fmt.Errorf("no included sender pods found in namespace %q with selector %q", phase.IncludedNamespace, phase.IncludedSelector)
	}

	var excludedSenderPods map[string]check.Pod
	if phase.ExcludedSelector != "" {
		excludedSenderPods, err = getInspectionPodsInNamespace(ctx, t, phase.ExcludedNamespace, phase.ExcludedSelector)
		if err != nil {
			return fmt.Errorf("listing excluded sender pods: %w", err)
		}
		if len(excludedSenderPods) == 0 {
			return fmt.Errorf("no excluded sender pods found in namespace %q with selector %q", phase.ExcludedNamespace, phase.ExcludedSelector)
		}
	}

	includedTag, err := sendInspectionProbes(ctx, t, includedSenderPods, phase.IncludedTagPrefix)
	if err != nil {
		return fmt.Errorf("sending included probes: %w", err)
	}

	var expectedAbsent []string
	if len(excludedSenderPods) > 0 {
		excludedTag, err := sendInspectionProbes(ctx, t, excludedSenderPods, phase.ExcludedTagPrefix)
		if err != nil {
			return fmt.Errorf("sending excluded probes: %w", err)
		}
		expectedAbsent = []string{excludedTag}
	}

	if err := waitForInspectionCaptureExpectations(ctx, t, snifferPods, captureFile, func() error {
		if _, err := sendInspectionProbes(ctx, t, includedSenderPods, includedTag); err != nil {
			return err
		}
		if len(excludedSenderPods) > 0 {
			if _, err := sendInspectionProbes(ctx, t, excludedSenderPods, phase.ExcludedTagPrefix); err != nil {
				return err
			}
		}
		return nil
	}, []string{includedTag}, expectedAbsent); err != nil {
		return err
	}

	return nil
}

func clearInspectionCaptureFile(ctx context.Context, t *check.Test, pods map[string]check.Pod, captureFile string) {
	for _, pod := range pods {
		if _, stderr, err := pod.K8sClient.ExecInPodWithStderr(ctx,
			pod.Pod.Namespace, pod.Pod.Name, "", []string{"rm", "-f", captureFile}); err != nil {
			t.Debugf("failed to clear capture file %s on pod %s (non-fatal): %v / stderr: %s",
				captureFile, pod.Name(), err, stderr.String())
		}
	}
}

func startInspectionSniffers(ctx, killCtx context.Context, t *check.Test, pods map[string]check.Pod, iface string) error {
	return startInspectionSniffersWithCaptureFile(ctx, killCtx, t, pods, iface, inspectionCaptureFile)
}

func startInspectionSniffersWithCaptureFile(ctx, killCtx context.Context, t *check.Test, pods map[string]check.Pod, iface, captureFile string) error {
	for _, pod := range pods {
		go func() {
			cmd := []string{
				"tcpdump", "-U",
				"-i", iface,
				"udp", "port", fmt.Sprintf("%d", inspectionProbePort),
				"-w", captureFile,
			}
			err := pod.K8sClient.ExecInPodWithWriters(ctx, killCtx,
				pod.Pod.Namespace, pod.Pod.Name, "", cmd, io.Discard, io.Discard)
			if err != nil {
				if killCtx.Err() != nil && errors.Is(killCtx.Err(), context.Canceled) {
					return // normal shutdown
				}
				t.Fatalf("tcpdump exited unexpectedly on sniffer pod %s: %v", pod.Name(), err)
			}
		}()
	}
	return nil
}

func waitForSnifferReady(ctx context.Context, t *check.Test, pods map[string]check.Pod) error {
	return waitForSnifferReadyWithCaptureFile(ctx, t, pods, inspectionCaptureFile)
}

func waitForSnifferReadyWithCaptureFile(ctx context.Context, t *check.Test, pods map[string]check.Pod, captureFile string) error {
	w := wait.NewObserver(ctx, wait.Parameters{Timeout: inspectionSnifferSettleTime})
	defer w.Cancel()

	for {
		allReady := true
		for _, pod := range pods {
			_, err := pod.K8sClient.ExecInPod(ctx,
				pod.Pod.Namespace, pod.Pod.Name, "",
				[]string{"ls", captureFile})
			if err != nil {
				allReady = false
				break
			}
		}
		if allReady {
			return nil
		}
		if err := w.Retry(fmt.Errorf("tcpdump not ready yet on all sniffers")); err != nil {
			return err
		}
	}
}

func waitForInspectionEndpointsReady(ctx context.Context, t *check.Test) error {
	ct := t.Context()
	w := wait.NewObserver(ctx, wait.Parameters{Timeout: inspectionEndpointReadyTimeout})
	defer w.Cancel()

	for {
		allReady := true
		var notReadyMsg string

		for _, ciliumPod := range ct.CiliumPods() {
			endpoints, err := ciliumPod.K8sClient.CiliumDbgEndpoints(ctx,
				ciliumPod.Pod.Namespace, ciliumPod.Pod.Name)
			if err != nil {
				allReady = false
				notReadyMsg = fmt.Sprintf("cilium pod %s: failed to list endpoints: %v",
					ciliumPod.Name(), err)
				break
			}
			for _, ep := range endpoints {
				if ep.Status == nil || ep.Status.State == nil {
					continue
				}
				state := *ep.Status.State
				if state != models.EndpointStateReady &&
					state != models.EndpointStateDisconnecting &&
					state != models.EndpointStateDisconnected {
					allReady = false
					notReadyMsg = fmt.Sprintf(
						"cilium pod %s: endpoint %d is in state %q (not ready)",
						ciliumPod.Name(), ep.ID, state)
					break
				}
			}
			if !allReady {
				break
			}
		}

		if allReady {
			return nil
		}
		if err := w.Retry(fmt.Errorf("%s", notReadyMsg)); err != nil {
			return err
		}
	}
}

func sendInspectionProbes(ctx context.Context, t *check.Test, pods map[string]check.Pod, probeTagPrefix string) (string, error) {
	if probeTagPrefix == "" {
		probeTagPrefix = "inspection-probe-"
	}

	type podInfo struct {
		pod check.Pod
		ip  string
	}
	infos := make([]podInfo, 0, len(pods))
	for _, pod := range pods {
		infos = append(infos, podInfo{pod: pod, ip: pod.Pod.Status.PodIP})
	}

	for i, info := range infos {
		dstIP := infos[(i+1)%len(infos)].ip
		probeTag := fmt.Sprintf("%s%s", probeTagPrefix, info.pod.Pod.Name)

		cmd := []string{
			"sh", "-c",
			fmt.Sprintf(`echo '%s' | nc -u -w1 %s %d`,
				probeTag, dstIP, inspectionProbePort),
		}

		_, stderr, err := info.pod.K8sClient.ExecInPodWithStderr(ctx,
			info.pod.Pod.Namespace, info.pod.Pod.Name, "", cmd)
		if err != nil {
			t.Debugf("probe from %s to %s: nc exited with error (probe may still have been sent): %v / stderr: %s",
				info.pod.Name(), dstIP, err, stderr.String())
		} else {
			t.Debugf("Sent probe %q from pod %s (%s) to %s",
				probeTag, info.pod.Name(), info.pod.Pod.Status.PodIP, dstIP)
		}
	}

	return probeTagPrefix, nil
}

func waitForInspectionCaptureExpectations(ctx context.Context, t *check.Test, snifferPods map[string]check.Pod, captureFile string, resend func() error, expectedPresent []string, expectedAbsent []string) error {
	w := wait.NewObserver(ctx, wait.Parameters{Timeout: inspectionTestTimeout})
	defer w.Cancel()

	for {
		if err := validateInspectionCaptureExpectations(ctx, t, snifferPods, captureFile, expectedPresent, expectedAbsent); err != nil {
			if resend != nil {
				if sendErr := resend(); sendErr != nil {
					t.Debugf("Re-send probes failed (non-fatal): %v", sendErr)
				}
			}
			if err := w.Retry(err); err != nil {
				return fmt.Errorf("timed out waiting for captured packets: %w", err)
			}
			continue
		}
		return nil
	}
}

func validateInspectionCaptureExpectations(ctx context.Context, t *check.Test, snifferPods map[string]check.Pod, captureFile string, expectedPresent []string, expectedAbsent []string) error {
	for _, pod := range snifferPods {
		if sizeOut, _, _ := pod.K8sClient.ExecInPodWithStderr(ctx,
			pod.Pod.Namespace, pod.Pod.Name, "",
			[]string{"wc", "-c", captureFile}); sizeOut.Len() > 0 {
			t.Debugf("pod %s (node %s): pcap size: %s",
				pod.Name(), pod.Pod.Spec.NodeName, strings.TrimSpace(sizeOut.String()))
		}

		cmd := []string{"tcpdump", "-A", "-r", captureFile}
		stdout, stderr, _ := pod.K8sClient.ExecInPodWithStderr(ctx,
			pod.Pod.Namespace, pod.Pod.Name, "", cmd)

		if stderr.Len() > 0 {
			t.Debugf("pod %s: tcpdump stderr: %s", pod.Name(), strings.TrimSpace(stderr.String()))
		}

		for _, tag := range expectedPresent {
			if !strings.Contains(stdout.String(), tag) {
				return fmt.Errorf("pod %s (node %s): probe tag %q not yet found in capture",
					pod.Name(), pod.Pod.Spec.NodeName, tag)
			}
		}

		for _, tag := range expectedAbsent {
			if strings.Contains(stdout.String(), tag) {
				return fmt.Errorf("pod %s (node %s): excluded probe tag %q unexpectedly found in capture",
					pod.Name(), pod.Pod.Spec.NodeName, tag)
			}
		}

		t.Debugf("pod %s (node %s): capture matched expected inspection tags ✓", pod.Name(), pod.Pod.Spec.NodeName)
	}
	return nil
}

func getInspectionPods(ctx context.Context, t *check.Test, selector string) (map[string]check.Pod, error) {
	return getInspectionPodsInNamespace(ctx, t, t.Context().Params().TestNamespace, selector)
}

func getInspectionPodsInNamespace(ctx context.Context, t *check.Test, namespace, selector string) (map[string]check.Pod, error) {
	ct := t.Context()
	allPods := make(map[string]check.Pod)

	for _, client := range ct.Clients() {
		pods, err := client.ListPods(ctx, namespace,
			metav1.ListOptions{LabelSelector: selector})
		if err != nil {
			return nil, fmt.Errorf("failed to list pods with selector %q: %w", selector, err)
		}
		for i := range pods.Items {
			p := &pods.Items[i]
			key := fmt.Sprintf("%s/%s/%s", client.ClusterName(), namespace, p.Name)
			allPods[key] = check.Pod{
				K8sClient: client,
				Pod:       p.DeepCopy(),
			}
		}
	}
	return allPods, nil
}

func NewInspectionSnifferDaemonSet(namespace, name, image string, extraLabels map[string]string) *appsv1.DaemonSet {
	if name == "" {
		name = inspectionSnifferName
	}
	labels := map[string]string{
		inspectionLabelKey: inspectionSnifferLabel,
	}
	maps.Copy(labels, extraLabels)
	selectorLabels := map[string]string{
		"name": name,
		"kind": inspectionSnifferName,
	}

	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    maps.Clone(selectorLabels),
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: selectorLabels,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: func() map[string]string {
						l := maps.Clone(selectorLabels)
						maps.Copy(l, labels)
						return l
					}(),
				},
				Spec: corev1.PodSpec{
					HostNetwork:                   true,
					ServiceAccountName:            name,
					TerminationGracePeriodSeconds: ptr.To[int64](1),
					Containers: []corev1.Container{
						{
							Name:            name,
							Image:           image,
							ImagePullPolicy: corev1.PullIfNotPresent,
							Command:         []string{"sleep", "infinity"},
							SecurityContext: &corev1.SecurityContext{
								Capabilities: &corev1.Capabilities{
									Add: []corev1.Capability{"NET_ADMIN", "NET_RAW"},
								},
							},
							ReadinessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									Exec: &corev1.ExecAction{
										Command: []string{"sh", "-c", "which tcpdump"},
									},
								},
								InitialDelaySeconds: 1,
								PeriodSeconds:       3,
								FailureThreshold:    20,
							},
						},
					},
				},
			},
		},
	}
	return ds
}

func NewInspectionSenderDeployment(namespace, name, image string, extraLabels map[string]string) *appsv1.Deployment {
	if name == "" {
		name = inspectionSenderName
	}
	labels := map[string]string{
		inspectionLabelKey: inspectionSenderLabel,
	}
	maps.Copy(labels, extraLabels)

	selectorLabels := map[string]string{
		"name": name,
		"kind": inspectionSenderName,
	}

	replicas := int32(2)
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				"name": name,
				"kind": inspectionSenderName,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: selectorLabels,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: func() map[string]string {
						l := maps.Clone(selectorLabels)
						maps.Copy(l, labels)
						return l
					}(),
				},
				Spec: corev1.PodSpec{
					ServiceAccountName:            name,
					TerminationGracePeriodSeconds: ptr.To[int64](1),
					Affinity: &corev1.Affinity{
						PodAntiAffinity: &corev1.PodAntiAffinity{
							RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
								{
									LabelSelector: &metav1.LabelSelector{
										MatchLabels: selectorLabels,
									},
									TopologyKey: "kubernetes.io/hostname",
								},
							},
						},
					},
					Containers: []corev1.Container{
						{
							Name:            name,
							Image:           image,
							ImagePullPolicy: corev1.PullIfNotPresent,
							Command:         []string{"sleep", "infinity"},
							SecurityContext: &corev1.SecurityContext{
								Capabilities: &corev1.Capabilities{
									Add: []corev1.Capability{"NET_RAW"},
								},
							},
							ReadinessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									Exec: &corev1.ExecAction{
										Command: []string{"ip", "route"},
									},
								},
								InitialDelaySeconds: 1,
								PeriodSeconds:       3,
								FailureThreshold:    20,
							},
						},
					},
				},
			},
		},
	}
	return dep
}
