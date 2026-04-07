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
	"fmt"
	"net/netip"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/cilium-cli/enterprise/hooks/k8s"
	slimlabels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
)

const (
	podStatusPollInterval = 2 * time.Second
	podReadyTimeout       = 5 * time.Minute
	podCleanupTimeout     = 30 * time.Second

	evpnTestLabelKey          = "app.kubernetes.io/part-of"
	evpnTestLabelValue        = "cilium-cli-evpn-test"
	evpnTestComponentLabelKey = "app.kubernetes.io/component"
	evpnTestContainerName     = "test"
)

func ensureNamespace(ctx context.Context, client *k8s.EnterpriseClient, namespace string) error {
	_, err := client.GetNamespace(ctx, namespace, metav1.GetOptions{})
	if err == nil {
		return nil
	}
	if !k8serrors.IsNotFound(err) {
		return fmt.Errorf("failed getting namespace %s: %w", namespace, err)
	}

	_, err = client.CreateNamespace(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespace,
			Labels: map[string]string{
				evpnTestLabelKey: evpnTestLabelValue,
			},
		},
	}, metav1.CreateOptions{})
	if err != nil && !k8serrors.IsAlreadyExists(err) {
		return fmt.Errorf("failed creating namespace %s: %w", namespace, err)
	}
	return nil
}

func waitForPodReady(ctx context.Context, client *k8s.EnterpriseClient, namespace, podName string) (*corev1.Pod, error) {
	var readyPod *corev1.Pod

	err := wait.PollUntilContextTimeout(ctx, podStatusPollInterval, podReadyTimeout, true, func(ctx context.Context) (bool, error) {
		pod, err := client.GetPod(ctx, namespace, podName, metav1.GetOptions{})
		if err != nil {
			return false, fmt.Errorf("error getting pod %s/%s: %w", namespace, podName, err)
		}
		switch pod.Status.Phase {
		case corev1.PodRunning:
			if isPodReady(pod) {
				readyPod = pod
				return true, nil
			}
		case corev1.PodFailed, corev1.PodSucceeded:
			return false, fmt.Errorf("pod %s/%s terminated (%s)", pod.Namespace, pod.Name, pod.Status.Phase)
		}
		return false, nil
	})
	if err != nil {
		return nil, err
	}

	return readyPod, nil
}

func isPodReady(pod *corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func cleanupPods(ctx context.Context, client *k8s.EnterpriseClient, namespace string, labels map[string]string) error {
	err := client.DeletePodCollection(ctx, namespace, metav1.DeleteOptions{
		GracePeriodSeconds: ptr.To[int64](1),
	}, metav1.ListOptions{
		LabelSelector: slimlabels.FormatLabels(labels),
	})
	if err != nil && !k8serrors.IsNotFound(err) {
		return fmt.Errorf("failed deleting pods: %w", err)
	}
	return wait.PollUntilContextTimeout(ctx, podStatusPollInterval, podCleanupTimeout, true, func(ctx context.Context) (bool, error) {
		pods, err := client.ListPods(ctx, namespace, metav1.ListOptions{
			LabelSelector: slimlabels.FormatLabels(labels),
		})
		if k8serrors.IsNotFound(err) {
			return true, nil
		}
		if err != nil {
			return false, fmt.Errorf("failed listing pods: %w", err)
		}
		return len(pods.Items) == 0, nil
	})
}

func pingFromPod(ctx context.Context, t *TestRun, pod *corev1.Pod, target netip.Addr) error {
	pingCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	cmd := []string{"ping", "-c", "3", "-W", "1", target.String()}

	fmt.Fprintf(t.out, "Pinging %s from pod %s/%s...\n", target, pod.Namespace, pod.Name)
	stdout, err := t.client.ExecInPod(pingCtx, pod.Namespace, pod.Name, evpnTestContainerName, cmd)
	if err != nil {
		return fmt.Errorf("ping %s from pod %s/%s failed: %w\n%s", target, pod.Namespace, pod.Name, err, stdout.String())
	}

	fmt.Fprintf(t.out, "Ping %s from pod %s/%s succeeded\n", target, pod.Namespace, pod.Name)
	return nil
}

func testPodLabels(testName string) map[string]string {
	return map[string]string{
		evpnTestLabelKey:          evpnTestLabelValue,
		evpnTestComponentLabelKey: testName,
	}
}
