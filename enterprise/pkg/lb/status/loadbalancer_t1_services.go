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

	"github.com/cilium/cilium/api/v1/models"
)

// getHealthcheckT1 gets HealthCheck state from LB VIP services from all T1 cilium agent pods.
func (s *LoadbalancerClient) getHealthcheckT1(ctx context.Context) (map[string][]*models.Service, error) {
	res, err := s.fetchServiceStatusConcurrently(ctx)
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

func (s *LoadbalancerClient) fetchServiceStatusConcurrently(ctx context.Context) (map[string][]*models.Service, error) {
	allFetchedData := make(map[string][]*models.Service)

	// res contains data returned from cilium pod
	type res struct {
		nodeName string
		data     []*models.Service
		err      error
	}
	resCh := make(chan res)

	var wg sync.WaitGroup

	// max number of concurrent go routines will be number of cilium agent pods
	wg.Add(len(s.t1AgentPods))

	// compute the command for fetching the services from a cilium pod
	fetchCmd := []string{"cilium-dbg", "service", "list"}
	fetchCmd = append(fetchCmd, "-o", "json")

	// concurrently fetch services from each T1 cilium pod
	for _, pod := range s.t1AgentPods {
		go func(ctx context.Context, pod *Pod) {
			defer wg.Done()

			services, err := s.fetchServiceStatusFromPod(ctx, fetchCmd, pod)
			resCh <- res{
				nodeName: pod.NodeName,
				data:     services,
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

func (s *LoadbalancerClient) fetchServiceStatusFromPod(ctx context.Context, fetchCmd []string, pod *Pod) ([]*models.Service, error) {
	output, errOutput, err := s.execInPod(ctx, pod.Namespace, pod.Name, "cilium-agent", fetchCmd)
	if err != nil {
		var errStr string
		if errOutput.String() != "" {
			errStr = strings.TrimSpace(errOutput.String())
		} else {
			errStr = err.Error()
		}
		return nil, fmt.Errorf("failed to fetch service status from %s: (%s)", pod.Name, errStr)
	}

	services := make([]*models.Service, 0)

	err = json.Unmarshal(output.Bytes(), &services)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal service status from %s: %w", pod.Name, err)
	}

	return services, nil
}
