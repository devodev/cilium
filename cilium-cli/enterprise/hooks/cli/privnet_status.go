// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/cilium-cli/api"
	"github.com/cilium/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium/cilium-cli/k8s"
	"github.com/cilium/cilium/cilium-cli/status"
	pnstatus "github.com/cilium/cilium/enterprise/pkg/privnet/status"
	"github.com/cilium/cilium/pkg/lock"
)

func GetPrivnetStatus(ctx context.Context, k8sClient *k8s.Client, namespace string) (pnstatus.ClusterStatus, error) {
	stat := pnstatus.ClusterStatus{}
	pods, err := k8sClient.ListPods(ctx, namespace, metav1.ListOptions{LabelSelector: defaults.AgentPodSelector})
	if err != nil {
		return stat, fmt.Errorf("failed to get cilium agent pods: %w", err)
	}

	var errs error
	var wg sync.WaitGroup
	var mu lock.Mutex

	// max number of concurrent go routines will be number of cilium agent pods
	wg.Add(len(pods.Items))

	// concurrently fetch status from each cilium pod
	for _, pod := range pods.Items {
		go func(ctx context.Context, pod corev1.Pod) {
			defer wg.Done()
			output, err := k8sClient.ExecInPod(ctx, pod.Namespace, pod.Name, "cilium-agent", []string{"cilium-dbg", "shell", "--", "privnet/status", "-o=json"})
			if err != nil {
				mu.Lock()
				errs = errors.Join(errs, fmt.Errorf("failed to collect node status for %q: %w", pod.Name, err))
				mu.Unlock()
				return
			}
			var status pnstatus.NodeStatus
			err = json.Unmarshal(output.Bytes(), &status)
			if err != nil {
				mu.Lock()
				errs = errors.Join(errs, fmt.Errorf("failed to parse node status for %q: %w", pod.Name, err))
				mu.Unlock()
				return
			}
			mu.Lock()
			stat.Nodes = append(stat.Nodes, status)
			mu.Unlock()
		}(ctx, pod)
	}

	wg.Wait()

	if len(stat.Nodes) > 0 {
		stat.Name = stat.Nodes[0].Cluster
	}

	return stat, errs
}

func newCmdPrivNetStatus() *cobra.Command {
	var namespace string
	var output string
	var colors bool

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Display Private Network status",
		Long:  "",
		RunE: func(c *cobra.Command, _ []string) error {
			namespace = ciliumNamespace(c)

			k8sClient, _ := api.GetK8sClientContextValue(c.Context())

			stat, errs := GetPrivnetStatus(c.Context(), k8sClient, namespace)

			switch output {
			case status.OutputJSON:
				out, err := json.MarshalIndent(stat, "", "  ")
				if err != nil {
					return err
				}
				_, err = c.OutOrStdout().Write(out)
				errs = errors.Join(errs, err)
			default:
				_, err := c.OutOrStdout().Write([]byte(stat.Format(colors)))
				errs = errors.Join(errs, err)
			}
			return errs
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", status.OutputSummary, "Output format. One of: json, summary")
	cmd.Flags().BoolVarP(&colors, "colors", "c", true, "Enable colors in 'summary' output")

	return cmd
}
