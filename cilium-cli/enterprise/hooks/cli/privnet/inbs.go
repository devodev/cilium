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
	"errors"
	"fmt"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type inbs struct {
	active    NodeName
	standby   []NodeName
	unhealthy []NodeName
}

type activeINBs map[NetworkName]NodeName

func (t *TestRun) getINBs(
	ctx context.Context, agent check.Pod, validate func(NetworkName, NodeName, inbs) error,
) (activeINBs, error) {
	stdout, err := agent.K8sClient.ExecInPod(ctx, agent.Pod.Namespace, agent.Pod.Name, defaults.AgentContainerName,
		[]string{"cilium-dbg", "shell", "--", "db/show", "privnet-inbs", "--format=yaml"},
	)

	if err != nil {
		return nil, fmt.Errorf("retrieving INBs: %w", err)
	}

	var (
		summary = make(map[NetworkName]inbs)
		active  = make(activeINBs)
	)

	for item := range bytes.SplitSeq(stdout.Bytes(), []byte("\n---")) {
		var inb tables.INB

		err = yaml.Unmarshal(item, &inb)
		if err != nil {
			return nil, fmt.Errorf("parsing INBs: %w", err)
		}

		var (
			network = NetworkName(inb.Network)
			node    = NodeName(inb.Node.Name)
			state   = summary[network]
		)

		switch inb.Role {
		case tables.INBRoleActive:
			state.active = node
			active[network] = node
		case tables.INBRoleStandby:
			state.standby = append(state.standby, node)
		case tables.INBRoleNone:
			state.unhealthy = append(state.unhealthy, node)
		}

		summary[network] = state
	}

	for network := range t.Networks() {
		if err := validate(network, NodeName(agent.NodeName()), summary[network]); err != nil {
			return nil, fmt.Errorf("validating INBs: %w", err)
		}
	}

	return active, nil
}

func (t *TestRun) waitForINBs(
	ctx context.Context, agent check.Pod, validate func(NetworkName, NodeName, inbs) error,
) (activeINBs, error) {
	ctx, cancel := context.WithTimeout(ctx, check.ShortTimeout)
	defer cancel()

	t.log.Info(fmt.Sprintf("⌛ Waiting for INBs to converge on node %s", agent.NodeName()))

	var lastErr error
	for {
		active, err := t.getINBs(ctx, agent, validate)
		if err == nil {
			return active, nil
		}

		lastErr = err
		t.log.Debug("INB check failed, retrying",
			logfields.Error, err,
			logfields.Node, agent.NodeName(),
			logfields.Interval, check.PollInterval,
		)

		select {
		case <-time.After(check.PollInterval):
		case <-ctx.Done():
			return nil, fmt.Errorf("timeout out waiting for INBs to converge: %w", lastErr)
		}
	}
}

func (t *TestRun) assertSteadyState() func(NetworkName, NodeName, inbs) error {
	return func(network NetworkName, node NodeName, state inbs) error {
		switch {
		case state.active == "":
			return errors.New("no active INB")
		case len(state.standby) != t.expectedStandby(network):
			return fmt.Errorf("got %d standby INBs, %d expected", len(state.standby), t.expectedStandby(network))
		case len(state.unhealthy) != 0:
			return fmt.Errorf("got %d unhealthy INBs, 0 expected", len(state.unhealthy))

		default:
			t.log.Debug("INBs converged to steady state",
				logfields.Network, network,
				logfields.Node, node,
				logfields.Active, state.active,
			)
			return nil
		}
	}
}

func (t *TestRun) assertDegradedState(target NodeName, previous activeINBs) func(NetworkName, NodeName, inbs) error {
	return func(network NetworkName, node NodeName, state inbs) error {
		var (
			affected = target == previous[network]
			standby  = t.expectedStandby(network)
		)

		switch {
		case affected && state.active == previous[network]:
			return errors.New("active INB should have changed")
		case affected && standby == 0 && state.active != "":
			// There was no standby INBs, so we should have no active INB now.
			return errors.New("got active INB, none expected")
		case affected && standby > 0 && state.active == "":
			// There was at least one standby INB, so we should have an active INB now.
			return errors.New("no active INB")

		case !affected && state.active != previous[network]:
			return errors.New("active INB should not have changed")

		case len(state.standby) != max(standby-1, 0):
			return fmt.Errorf("got %d standby INBs, %d expected", len(state.standby), max(standby-1, 0))

		case (affected || standby > 0) && len(state.unhealthy) != 1:
			return fmt.Errorf("got %d unhealthy INBs, 1 expected", len(state.unhealthy))
		case (!affected && standby == 0) && len(state.unhealthy) != 0:
			return fmt.Errorf("got %d unhealthy INBs, 0 expected", len(state.unhealthy))

		default:
			t.log.Debug("INBs converged to degraded state",
				logfields.Network, network,
				logfields.Node, node,
				logfields.Active, state.active,
			)
			return nil
		}
	}
}

func (t *TestRun) expectedStandby(network NetworkName) int {
	// This is correct under the assumption that INB clusters have a single node.
	return max(len(networkTopology.Networks[network].INBs)-1, 0)
}
