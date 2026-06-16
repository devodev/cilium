//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package ilb

import (
	"encoding/json"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	lbstatus "github.com/cilium/cilium/enterprise/pkg/lb/status"
)

// t2BackendStates returns how many T2->backend healthchecks are passing (active)
// versus failing (inactive) for each T2 node in total.
func (r *lbTestScenario) t2BackendStates(t2NodeList *corev1.NodeList) (active int, inactive int, err error) {
	podList, err := r.k8sCli.CoreV1().Pods(r.t.CiliumNamespace()).List(r.t.Context(), metav1.ListOptions{
		LabelSelector: ciliumAgentPodLabelSelector,
	})
	if err != nil {
		return 0, 0, fmt.Errorf("failed to list cilium agent pods: %w", err)
	}

	clusterPrefix := fmt.Sprintf("%s/lbfe-%s/", r.k8sNamespace, r.testName)

	for _, t2 := range t2NodeList.Items {
		podName := ciliumAgentPodNameForNode(podList, t2.Name)
		if podName == "" {
			return 0, 0, fmt.Errorf("failed to get cilium agent pod for node %s", t2.Name)
		}

		stdout, _, err := execIntoPod(r.t, r.k8sCli, r.t.CiliumNamespace(), podName, "cilium-agent", []string{"cilium-dbg", "envoy", "admin", "config"})
		if err != nil {
			return 0, 0, fmt.Errorf("failed to fetch envoy config on node %s: %w", t2.Name, err)
		}

		envoyConfig := lbstatus.EnvoyConfigModel{}
		if err := json.Unmarshal(stdout.Bytes(), &envoyConfig); err != nil {
			return 0, 0, fmt.Errorf("failed to unmarshal envoy config from %s: %w", podName, err)
		}

		for _, c := range envoyConfig.Configs {
			if c.Type != "type.googleapis.com/envoy.admin.v3.EndpointsConfigDump" {
				continue
			}
			for _, e := range c.DynamicEndpointConfigs {
				if !strings.HasPrefix(e.EndpointConfig.ClusterName, clusterPrefix) {
					continue
				}
				for _, ep := range e.EndpointConfig.Endpoints {
					for _, epc := range ep.LbEndpoints {
						if epc.HealthStatus == "HEALTHY" {
							active++
						} else {
							inactive++
						}
					}
				}
			}
		}
	}

	return active, inactive, nil
}
