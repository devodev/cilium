// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package status

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
)

// getHealthcheckT2 gets HealthCheck state from Envoy Config from all T2 cilium agent pods.
func (s *LoadbalancerClient) getHealthcheckT2(ctx context.Context) (map[string]*EnvoyConfigModel, error) {
	res, err := s.fetchEnvoyConfigConcurrently(ctx)
	if err != nil {
		if len(res) == 0 {
			// no results retrieved - just return the error
			return nil, err
		}
		// print the errors, but continue with printing results
		fmt.Fprintf(os.Stderr, "Errors by retrieving services: %v\n\n", err)
	}

	return res, nil
}

func (s *LoadbalancerClient) fetchEnvoyConfigConcurrently(ctx context.Context) (map[string]*EnvoyConfigModel, error) {
	allFetchedData := make(map[string]*EnvoyConfigModel)

	// res contains data returned from cilium pod
	type res struct {
		nodeName string
		data     *EnvoyConfigModel
		err      error
	}
	resCh := make(chan res)

	var wg sync.WaitGroup

	// max number of concurrent go routines will be number of cilium agent pods
	wg.Add(len(s.t2AgentPods))

	// compute the command for fetching the envoy config from a cilium pod
	fetchCmd := []string{"cilium-dbg", "envoy", "admin", "config"}

	// concurrently fetch envoy config from each T1 cilium pod
	for _, pod := range s.t2AgentPods {
		go func(ctx context.Context, pod *Pod) {
			defer wg.Done()

			envoyConfig, err := s.fetchEnvoyConfigFromPod(ctx, fetchCmd, pod)
			resCh <- res{
				nodeName: pod.NodeName,
				data:     envoyConfig,
				err:      err,
			}
		}(ctx, pod)
	}

	// close resCh when data from all nodes is collected
	go func() {
		wg.Wait()
		close(resCh)
	}()

	// read from the channel till it is closed.
	// on error, store error and continue to next node.
	var err error
	for fetchedData := range resCh {
		if fetchedData.err != nil {
			err = errors.Join(err, fetchedData.err)
		} else {
			allFetchedData[fetchedData.nodeName] = fetchedData.data
		}
	}

	return allFetchedData, err
}

func (s *LoadbalancerClient) fetchEnvoyConfigFromPod(ctx context.Context, fetchCmd []string, pod *Pod) (*EnvoyConfigModel, error) {
	output, errOutput, err := s.execInPod(ctx, pod.Namespace, pod.Name, "cilium-agent", fetchCmd)
	if err != nil {
		var errStr string
		if errOutput.String() != "" {
			errStr = strings.TrimSpace(errOutput.String())
		} else {
			errStr = err.Error()
		}
		return nil, fmt.Errorf("failed to fetch envoy config from %s: (%s)", pod.Name, errStr)
	}

	envoyConfig := EnvoyConfigModel{}

	err = json.Unmarshal(output.Bytes(), &envoyConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal envoy config from %s: %w", pod.Name, err)
	}

	return &envoyConfig, nil
}
