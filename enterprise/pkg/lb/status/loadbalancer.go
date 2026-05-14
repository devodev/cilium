// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package status

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"

	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	ciliumClientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	ciliumMetav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/time"
)

// Parameters contains options for CLI
type Parameters struct {
	WaitDuration   time.Duration
	Output         string
	RelationOutput string

	CiliumNamespace  string
	ServiceNamespace string
	ServiceName      string
	ServiceVIP       string
	ServicePort      uint
	ServiceStatus    string

	Colors  bool
	Verbose bool
}

type execInPodFunc func(ctx context.Context, namespace, pod, container string, command []string) (bytes.Buffer, bytes.Buffer, error)

type LoadbalancerClient struct {
	params      Parameters
	client      execClient
	t1AgentPods []*Pod
	t2AgentPods []*Pod
	t1NodeZones map[string]string

	execInPodOverride execInPodFunc
}

type Pod struct {
	Name      string
	Namespace string
	NodeName  string
}

func NewLoadbalancerClient(k8sClient kubernetes.Interface, ciliumClient ciliumClientset.Interface, restConfig *rest.Config, params Parameters) *LoadbalancerClient {
	return &LoadbalancerClient{
		params: params,
		client: execClient{
			k8sClient:    k8sClient,
			ciliumClient: ciliumClient,
			restConfig:   restConfig,
		},
	}
}

func (s *LoadbalancerClient) execInPod(ctx context.Context, namespace, pod, container string, command []string) (bytes.Buffer, bytes.Buffer, error) {
	if s.execInPodOverride != nil {
		return s.execInPodOverride(ctx, namespace, pod, container, command)
	}

	return s.client.ExecInPod(ctx, namespace, pod, container, command)
}

func (s *LoadbalancerClient) InitNodeAgentPods(ctx context.Context) error {
	t1NodeZones, t2NodeZones, err := s.getLBNodes(ctx)
	if err != nil {
		return err
	}

	agentPods, err := s.client.k8sClient.CoreV1().Pods(s.params.CiliumNamespace).List(ctx, metav1.ListOptions{LabelSelector: "k8s-app=cilium"})
	if err != nil {
		return fmt.Errorf("failed to list agent pods: %w", err)
	}

	t1AgentPods := []*Pod{}
	t2AgentPods := []*Pod{}

	for _, ap := range agentPods.Items {
		if _, ok := t1NodeZones[ap.Spec.NodeName]; ok {
			t1AgentPods = append(t1AgentPods, &Pod{
				Name:      ap.Name,
				Namespace: ap.Namespace,
				NodeName:  ap.Spec.NodeName,
			})
		}

		if _, ok := t2NodeZones[ap.Spec.NodeName]; ok {
			t2AgentPods = append(t2AgentPods, &Pod{
				Name:      ap.Name,
				Namespace: ap.Namespace,
				NodeName:  ap.Spec.NodeName,
			})
		}
	}

	s.t1AgentPods = t1AgentPods
	s.t2AgentPods = t2AgentPods
	s.t1NodeZones = getOnlyZonedNodes(t1NodeZones)

	return nil
}

func (s *LoadbalancerClient) GetT1NodeAgentPods() []*Pod {
	return s.t1AgentPods
}

func (s *LoadbalancerClient) GetT2NodeAgentPods() []*Pod {
	return s.t2AgentPods
}

func (s *LoadbalancerClient) SetT1NodeAgentPods(pods []*Pod) {
	s.t1AgentPods = pods
}

func (s *LoadbalancerClient) SetT2NodeAgentPods(pods []*Pod) {
	s.t2AgentPods = pods
}

const (
	t1T2SelectorKey   = "service.cilium.io/node"
	t1OnlyLabel       = "t1"
	t1T2Label         = "t1-t2"
	t2OnlyLabel       = "t2"
	defaultT1Selector = t1T2SelectorKey + " in ( " + t1OnlyLabel + " , " + t1T2Label + " )"
	defaultT2Selector = t1T2SelectorKey + " in ( " + t2OnlyLabel + " , " + t1T2Label + " )"
)

func (s *LoadbalancerClient) getLBNodes(ctx context.Context) (map[string]string, map[string]string, error) {
	deployments, err := s.getLBDeployments(ctx)
	if err != nil {
		return nil, nil, err
	}

	t1Selectors := []string{defaultT1Selector}
	t2Selectors := []string{defaultT2Selector}
	for i := range deployments {
		ls := deployments[i].Spec.Nodes.LabelSelectors
		if ls == nil {
			continue
		}

		t1Selectors = append(t1Selectors, matchLabelsToLabelSelectors(ls.T1.MatchLabels)...)
		t1Selectors = append(t1Selectors, matchExpressionsToLabelSelectors(ls.T1.MatchExpressions)...)
		t2Selectors = append(t2Selectors, matchLabelsToLabelSelectors(ls.T2.MatchLabels)...)
		t2Selectors = append(t2Selectors, matchExpressionsToLabelSelectors(ls.T2.MatchExpressions)...)
	}

	t1Selectors = deduplicateSlice(t1Selectors)
	t2Selectors = deduplicateSlice(t2Selectors)

	var t1NameZone, t2NameZone map[string]string
	eg := errgroup.Group{}
	eg.Go(func() error {
		nameZone, err := s.getNodeZoneBySelector(ctx, t1Selectors)
		if err != nil {
			return err
		}
		t1NameZone = nameZone
		return nil
	})
	eg.Go(func() error {
		nameZone, err := s.getNodeZoneBySelector(ctx, t2Selectors)
		if err != nil {
			return err
		}
		t2NameZone = nameZone
		return nil
	})

	if err := eg.Wait(); err != nil {
		return nil, nil, err
	}
	return t1NameZone, t2NameZone, nil
}

func (s *LoadbalancerClient) getLBDeployments(ctx context.Context) ([]v1alpha1.LBDeployment, error) {
	namespaces, err := s.client.k8sClient.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	deployments := make([]v1alpha1.LBDeployment, 0)
	for _, ns := range namespaces.Items {
		items, err := s.client.ciliumClient.IsovalentV1alpha1().LBDeployments(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		deployments = append(deployments, items.Items...)
	}
	return deployments, nil
}

func (s *LoadbalancerClient) getNodeZoneBySelector(ctx context.Context, labelSelectors []string) (map[string]string, error) {
	nodeZone := make(map[string]string)
	for _, selector := range labelSelectors {
		nodes, err := s.client.k8sClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: selector})
		if err != nil {
			return nil, err
		}
		for _, node := range nodes.Items {
			nodeZone[node.Name] = node.Labels[corev1.LabelTopologyZone]
		}
	}
	return nodeZone, nil
}

func matchLabelsToLabelSelectors(labelValues map[string]ciliumMetav1.MatchLabelsValue) []string {
	if len(labelValues) == 0 {
		return []string{}
	}

	selectors := make([]string, 0, len(labelValues))
	for l, v := range labelValues {
		selectors = append(selectors, labelSelectorString(l, ciliumMetav1.LabelSelectorOpIn, v))
	}
	return selectors
}

func matchExpressionsToLabelSelectors(requirements []ciliumMetav1.LabelSelectorRequirement) []string {
	if len(requirements) == 0 {
		return []string{}
	}

	selectors := make([]string, 0, len(requirements))
	for _, r := range requirements {
		selectors = append(selectors, labelSelectorString(r.Key, r.Operator, r.Values...))
	}
	return selectors
}

func labelSelectorString(key string, operator ciliumMetav1.LabelSelectorOperator, values ...string) string {
	return fmt.Sprintf("%s %s ( %s )", key, strings.ToLower(string(operator)), strings.Join(values, " , "))
}

func getOnlyZonedNodes(nodeZone map[string]string) map[string]string {
	result := make(map[string]string)
	for node, zone := range nodeZone {
		if zone != "" {
			result[node] = zone
		}
	}
	return result
}

func deduplicateSlice(s []string) []string {
	slices.Sort(s)
	return slices.Compact(s)
}
