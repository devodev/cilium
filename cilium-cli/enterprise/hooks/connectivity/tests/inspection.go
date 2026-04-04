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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/utils/wait"
	inspectionConfig "github.com/cilium/cilium/enterprise/pkg/inspection/config"
	"github.com/cilium/cilium/pkg/time"
)

const (
	inspectionSnifferName          = "inspection-sniffer"
	inspectionSenderName           = "inspection-sender"
	inspectionLabelKey             = "inspection"
	inspectionSnifferLabel         = "sniffer"
	inspectionSenderLabel          = "sender"
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

func PassiveInspectionVerification() check.Scenario {
	return &passiveInspectionVerification{
		ScenarioBase: check.NewScenarioBase(),
	}
}

type passiveInspectionVerification struct {
	check.ScenarioBase
}

func (s *passiveInspectionVerification) Name() string {
	return "passive-inspection-verification"
}

func (s *passiveInspectionVerification) Run(ctx context.Context, t *check.Test) {
	t.Logf("Running passive inspection verification (interface: %s)", inspectionConfig.InterfaceName)
	defer t.Logf("Finished passive inspection verification")

	snifferPods, err := getInspectionPods(ctx, t, inspectionSnifferSelector)
	if err != nil {
		t.Fatalf("Failed to list sniffer pods: %v", err)
	}
	if len(snifferPods) == 0 {
		t.Fatalf("No sniffer pods found with selector %q", inspectionSnifferSelector)
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

	senderPods, err := getInspectionPods(ctx, t, inspectionSenderSelector)
	if err != nil {
		t.Fatalf("Failed to list sender pods: %v", err)
	}
	if len(senderPods) == 0 {
		t.Fatalf("No sender pods found with selector %q", inspectionSenderSelector)
	}
	t.Debugf("Found %d sender pod(s)", len(senderPods))

	probeTag, err := sendInspectionProbes(ctx, t, senderPods)
	if err != nil {
		t.Fatalf("Failed to send inspection probes: %v", err)
	}
	t.Debugf("Sent probes with tag %q from %d sender pod(s)", probeTag, len(senderPods))

	t.Debugf("Waiting for mirrored packets to appear in capture files...")
	if err := waitForInspectionCapture(ctx, t, snifferPods, senderPods, probeTag); err != nil {
		t.Fatalf("Inspection mirror verification failed: %v", err)
	}

	t.Logf("✅ Passive inspection verified: mirrored packets captured on all nodes")
}

func startInspectionSniffers(ctx, killCtx context.Context, t *check.Test, pods map[string]check.Pod, iface string) error {
	for _, pod := range pods {
		go func() {
			cmd := []string{
				"tcpdump", "-U",
				"-i", iface,
				"udp", "port", fmt.Sprintf("%d", inspectionProbePort),
				"-w", inspectionCaptureFile,
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
	w := wait.NewObserver(ctx, wait.Parameters{Timeout: inspectionSnifferSettleTime})
	defer w.Cancel()

	for {
		allReady := true
		for _, pod := range pods {
			_, err := pod.K8sClient.ExecInPod(ctx,
				pod.Pod.Namespace, pod.Pod.Name, "",
				[]string{"ls", inspectionCaptureFile})
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

func sendInspectionProbes(ctx context.Context, t *check.Test, pods map[string]check.Pod) (string, error) {
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
		probeTag := fmt.Sprintf("inspection-probe-%s", info.pod.Pod.Name)

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

	return "inspection-probe-", nil
}

func waitForInspectionCapture(ctx context.Context, t *check.Test, snifferPods map[string]check.Pod, senderPods map[string]check.Pod, probeTag string) error {
	w := wait.NewObserver(ctx, wait.Parameters{Timeout: inspectionTestTimeout})
	defer w.Cancel()

	for {
		if err := validateInspectionCaptures(ctx, t, snifferPods, probeTag); err != nil {
			if _, sendErr := sendInspectionProbes(ctx, t, senderPods); sendErr != nil {
				t.Debugf("Re-send probes failed (non-fatal): %v", sendErr)
			}
			if err := w.Retry(err); err != nil {
				return fmt.Errorf("timed out waiting for captured packets: %w", err)
			}
			continue
		}
		return nil
	}
}

func validateInspectionCaptures(ctx context.Context, t *check.Test, snifferPods map[string]check.Pod, probeTag string) error {
	for _, pod := range snifferPods {
		if sizeOut, _, _ := pod.K8sClient.ExecInPodWithStderr(ctx,
			pod.Pod.Namespace, pod.Pod.Name, "",
			[]string{"wc", "-c", inspectionCaptureFile}); sizeOut.Len() > 0 {
			t.Debugf("pod %s (node %s): pcap size: %s",
				pod.Name(), pod.Pod.Spec.NodeName, strings.TrimSpace(sizeOut.String()))
		}

		cmd := []string{"tcpdump", "-A", "-r", inspectionCaptureFile}
		stdout, stderr, _ := pod.K8sClient.ExecInPodWithStderr(ctx,
			pod.Pod.Namespace, pod.Pod.Name, "", cmd)

		if stderr.Len() > 0 {
			t.Debugf("pod %s: tcpdump stderr: %s", pod.Name(), strings.TrimSpace(stderr.String()))
		}

		if !strings.Contains(stdout.String(), probeTag) {
			return fmt.Errorf("pod %s (node %s): probe tag %q not yet found in capture",
				pod.Name(), pod.Pod.Spec.NodeName, probeTag)
		}

		t.Debugf("pod %s (node %s): probe tag found in capture ✓", pod.Name(), pod.Pod.Spec.NodeName)
	}
	return nil
}

func getInspectionPods(ctx context.Context, t *check.Test, selector string) (map[string]check.Pod, error) {
	ct := t.Context()
	allPods := make(map[string]check.Pod)

	for _, client := range ct.Clients() {
		pods, err := client.ListPods(ctx, ct.Params().TestNamespace,
			metav1.ListOptions{LabelSelector: selector})
		if err != nil {
			return nil, fmt.Errorf("failed to list pods with selector %q: %w", selector, err)
		}
		for i := range pods.Items {
			p := &pods.Items[i]
			allPods[p.Name] = check.Pod{
				K8sClient: client,
				Pod:       p.DeepCopy(),
			}
		}
	}
	return allPods, nil
}

func NewInspectionSnifferDaemonSet(namespace, image string) *appsv1.DaemonSet {
	labels := map[string]string{
		inspectionLabelKey: inspectionSnifferLabel,
	}

	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      inspectionSnifferName,
			Namespace: namespace,
			Labels: map[string]string{
				"name": inspectionSnifferName,
				"kind": inspectionSnifferName,
			},
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"name": inspectionSnifferName,
					"kind": inspectionSnifferName,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: func() map[string]string {
						l := map[string]string{
							"name": inspectionSnifferName,
							"kind": inspectionSnifferName,
						}
						maps.Copy(l, labels)
						return l
					}(),
				},
				Spec: corev1.PodSpec{
					HostNetwork:                   true,
					ServiceAccountName:            inspectionSnifferName,
					TerminationGracePeriodSeconds: ptr.To[int64](1),
					Containers: []corev1.Container{
						{
							Name:            inspectionSnifferName,
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

func NewInspectionSenderDeployment(namespace, image string) *appsv1.Deployment {
	labels := map[string]string{
		inspectionLabelKey: inspectionSenderLabel,
	}

	replicas := int32(2)
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      inspectionSenderName,
			Namespace: namespace,
			Labels: map[string]string{
				"name": inspectionSenderName,
				"kind": inspectionSenderName,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"name": inspectionSenderName,
					"kind": inspectionSenderName,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: func() map[string]string {
						l := map[string]string{
							"name": inspectionSenderName,
							"kind": inspectionSenderName,
						}
						maps.Copy(l, labels)
						return l
					}(),
				},
				Spec: corev1.PodSpec{
					ServiceAccountName:            inspectionSenderName,
					TerminationGracePeriodSeconds: ptr.To[int64](1),
					Affinity: &corev1.Affinity{
						PodAntiAffinity: &corev1.PodAntiAffinity{
							RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
								{
									LabelSelector: &metav1.LabelSelector{
										MatchLabels: labels,
									},
									TopologyKey: "kubernetes.io/hostname",
								},
							},
						},
					},
					Containers: []corev1.Container{
						{
							Name:            inspectionSenderName,
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
