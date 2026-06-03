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
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cilium/workerpool"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/cilium-cli/api"
	"github.com/cilium/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium/cilium-cli/k8s"
	"github.com/cilium/cilium/cilium-cli/status"
	pnstatus "github.com/cilium/cilium/enterprise/pkg/privnet/status"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/slices"
)

func GetPrivnetStatus(ctx context.Context, k8sClient *k8s.Client, namespace string, workers uint) (pnstatus.ClusterStatus, error) {
	pods, err := k8sClient.ListPods(ctx, namespace, metav1.ListOptions{LabelSelector: defaults.AgentPodSelector})
	if err != nil {
		return pnstatus.ClusterStatus{}, fmt.Errorf("failed to get cilium agent pods: %w", err)
	}

	var (
		wp   = workerpool.NewWithContext(ctx, int(workers))
		stat pnstatus.ClusterStatus
		mu   lock.Mutex
	)

	defer func() { _ = wp.Close() }()

	// concurrently fetch status from each cilium pod
	for _, pod := range pods.Items {
		if err = wp.Submit(pod.Name, func(ctx context.Context) error {
			output, err := k8sClient.ExecInPod(ctx, pod.Namespace, pod.Name, "cilium-agent", []string{"cilium-dbg", "shell", "--", "privnet/status", "-o=json"})
			if err != nil {
				return fmt.Errorf("failed to collect node status for %q: %w", pod.Name, err)
			}

			var status pnstatus.NodeStatus
			err = json.Unmarshal(output.Bytes(), &status)
			if err != nil {
				return fmt.Errorf("failed to parse node status for %q: %w", pod.Name, err)
			}

			mu.Lock()
			stat.Nodes = append(stat.Nodes, status)
			mu.Unlock()

			return nil
		}); err != nil {
			return stat, fmt.Errorf("failed to collect status: %w", err)
		}
	}

	tasks, err := wp.Drain()
	if err != nil {
		return stat, fmt.Errorf("failed to collect status: %w", err)
	}

	if len(stat.Nodes) > 0 {
		stat.Name = stat.Nodes[0].Cluster
	}

	return stat, errors.Join(slices.Map(tasks, func(t workerpool.Task) error { return t.Err() })...)
}

func newCmdPrivNetStatus() *cobra.Command {
	const defaultWorkers = 8

	var namespace string
	var output string
	var colors bool
	var workers uint

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Display Private Network status",
		Long:  "",
		RunE: func(c *cobra.Command, _ []string) error {
			namespace = ciliumNamespace(c)

			k8sClient, _ := api.GetK8sClientContextValue(c.Context())

			stat, errs := GetPrivnetStatus(c.Context(), k8sClient, namespace, cmp.Or(workers, defaultWorkers))

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
	cmd.Flags().UintVar(&workers, "workers", defaultWorkers, "The number of workers used to collect the status")

	return cmd
}
