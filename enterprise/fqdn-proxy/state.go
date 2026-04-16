//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	pb "github.com/cilium/cilium/enterprise/fqdn-proxy/api/v1/dnsproxy"
	"github.com/cilium/cilium/enterprise/pkg/fqdnha/tables"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/version"
)

var startTime = time.Now().Unix()

// onUpdateFn is a function that is called when an update is about to be committed
type onUpdateFn func(agent tables.AgentState, proxy tables.RemoteProxyState)

type stateManager struct {
	log    *slog.Logger
	client *fqdnAgentClient
	db     statedb.DB
	cfg    Config

	agentState statedb.RWTable[tables.AgentState]
	proxyState statedb.RWTable[tables.RemoteProxyState]

	// onUpdates is the list of functions that should be called
	// as part of a state update transaction
	onUpdates []onUpdateFn

	// state metrics
	metricProxyStatus metric.Gauge
	metricAgentStatus metric.Gauge
}

type stateManagerParams struct {
	cell.In

	Cfg    Config
	Log    *slog.Logger
	JG     job.Group
	Client *fqdnAgentClient

	DB               *statedb.DB
	RemoteProxyState statedb.RWTable[tables.RemoteProxyState]
	AgentState       statedb.RWTable[tables.AgentState]
}

func newStateManager(params stateManagerParams) (*stateManager, metricsOut) {
	sm := &stateManager{
		log:    params.Log.With(logfields.LogSubsys, "state-manager"),
		client: params.Client,
		cfg:    params.Cfg,

		db:         *params.DB,
		agentState: params.AgentState,
		proxyState: params.RemoteProxyState,
	}

	sm.metricProxyStatus = metric.NewGauge(metric.GaugeOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "proxy_status",
		Help:      "The current proxy status",
	})

	sm.metricAgentStatus = metric.NewGauge(metric.GaugeOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "agent_status",
		Help:      "The current agent status",
	})

	trig := job.NewTrigger()
	params.JG.Add(job.Timer("mark-proxy-live", sm.markLive, 0, job.WithTrigger(trig)))
	params.JG.Add(job.OneShot("sync-state", sm.syncState))
	sm.addOnUpdate(sm.triggerMarkLive(trig))

	return sm, metricsOut{Metrics: []metric.WithMetadata{
		sm.metricProxyStatus,
		sm.metricAgentStatus,
	}}
}

// addOnUpdate adds an on-update handler.
// This should only be called before the Hive is started.
func (sm *stateManager) addOnUpdate(fn onUpdateFn) {
	sm.onUpdates = append(sm.onUpdates, fn)
}

func (sm *stateManager) setAgentState(msg *pb.AgentState, offline bool) {
	var state tables.AgentState
	if msg != nil {
		state = tables.AgentStateFromMessage(msg)
	}
	if offline {
		state.Status = pb.AgentStatus_AS_UNSPECIFIED
	}
	wtxn := sm.db.WriteTxn(sm.agentState, sm.proxyState)
	defer wtxn.Abort()
	if _, _, err := sm.agentState.Insert(wtxn, state); err != nil {
		sm.log.Error("BUG: failed to update agent state", logfields.Error, err)
		return
	}
	sm.log.Info("remote agent changed state", logfields.State, msg)
	sm.onUpdate(wtxn)
	wtxn.Commit()

	// set status metric
	sm.metricAgentStatus.Set(float64(state.Status))
}

// onUpdate calls the set of update functions during a write transaction.
//
// This needs to be synchronous as we need to update our BPF references in lock-step
// with state changes, otherwise in-flight dns requests may be lost.
// Thus, we can't use the traditional statedb reconcilers.
func (sm *stateManager) onUpdate(wtxn statedb.WriteTxn) {
	if len(sm.onUpdates) == 0 {
		return
	}
	var agent tables.AgentState
	var proxy tables.RemoteProxyState

	agent, _, _ = sm.agentState.Get(wtxn, tables.AgentStateIndex.Query(""))
	proxy, _, _ = sm.proxyState.Get(wtxn, tables.RemoteProxyStateIndex.Query(""))

	for _, fn := range sm.onUpdates {
		fn(agent, proxy)
	}
}

// GetCurrentProxyState returns the currently existing state of the remote proxy.
func (sm *stateManager) GetCurrentProxyState() tables.RemoteProxyState {
	var state tables.RemoteProxyState
	var found bool
	state, _, found = sm.proxyState.Get(sm.db.ReadTxn(), tables.RemoteProxyStateIndex.Query(""))
	if found {
		return state
	}
	state.Status = pb.RemoteProxyStatus_RPS_UNSPECIFIED
	return state
}

// UpdateProxyState records a change in proxy state.
// If `from“ is not UNSPEC, then this will only set the state to `to` if
// already in state `from`.
func (sm *stateManager) UpdateProxyState(from, to pb.RemoteProxyStatus) {
	wtxn := sm.db.WriteTxn(sm.proxyState, sm.agentState)
	defer wtxn.Abort()

	sm.updateProxyState(wtxn, from, to)
}

// updateProxyState generates and commits the proxy state update.
func (sm *stateManager) updateProxyState(wtxn statedb.WriteTxn, from, to pb.RemoteProxyStatus) {
	// Check existing state.
	existing := pb.RemoteProxyStatus_RPS_UNSPECIFIED
	if old, _, found := sm.proxyState.Get(wtxn, tables.RemoteProxyStateIndex.Query("")); found {
		existing = old.Status
	}

	// If we are already at this state, nothing to do.
	if existing == to {
		return
	}

	// If from is not UNSPEC and existing does not match from, reject this transition
	if from != pb.RemoteProxyStatus_RPS_UNSPECIFIED && from != existing {
		sm.log.Info("Skipped proxy state transition",
			logfields.From, from,
			logfields.To, to,
			logfields.State, existing)
		return
	}

	state := tables.RemoteProxyState{
		Status:            to,
		Version:           version.GetCiliumVersion().Version,
		StartTime:         startTime,
		EnableOfflineMode: sm.cfg.EnableOfflineMode,
	}

	if _, _, err := sm.proxyState.Insert(wtxn, state); err != nil {
		sm.log.Error("BUG: failed to update proxy state", logfields.Error, err)
		return
	}
	sm.log.Info("proxy changed state", logfields.State, to)
	sm.onUpdate(wtxn)
	wtxn.Commit()
	sm.metricProxyStatus.Set(float64(to))
}

// triggerMarkLive triggers (separately) the markLive job
// if we have finally reached the proxy state "WAITING_FOR_AGENT_LIVE"
// and agent state LIVE
func (sm *stateManager) triggerMarkLive(trig job.Trigger) onUpdateFn {
	return func(agent tables.AgentState, proxy tables.RemoteProxyState) {
		if agent.Status == pb.AgentStatus_AS_LIVE && proxy.Status == pb.RemoteProxyStatus_RPS_WAITING_FOR_AGENT_LIVE {
			trig.Trigger()
		}
	}
}

// markLive transitions the proxy from WAITING_FOR_AGENT_LIVE to LIVE when the agent
// itself transitions to LIVE.
// These transitions can occur in any order, so we must react to them independently.
func (sm *stateManager) markLive(ctx context.Context) error {
	wtxn := sm.db.WriteTxn(sm.proxyState, sm.agentState)
	defer wtxn.Abort()

	agent, _, _ := sm.agentState.Get(wtxn, tables.AgentStateIndex.Query(""))
	proxy, _, _ := sm.proxyState.Get(wtxn, tables.RemoteProxyStateIndex.Query(""))

	if agent.Status == pb.AgentStatus_AS_LIVE && proxy.Status == pb.RemoteProxyStatus_RPS_WAITING_FOR_AGENT_LIVE {
		sm.updateProxyState(wtxn, pb.RemoteProxyStatus_RPS_WAITING_FOR_AGENT_LIVE, pb.RemoteProxyStatus_RPS_LIVE)
	}

	return nil
}

func (sm *stateManager) syncState(ctx context.Context, _ cell.Health) error {
	// initialize states
	sm.setAgentState(nil, true)
	sm.UpdateProxyState(pb.RemoteProxyStatus_RPS_UNSPECIFIED, pb.RemoteProxyStatus_RPS_LIVE)

	var nextLog time.Time

	for {
		err := sm.trySyncState(ctx)
		if ctx.Err() != nil {
			break
		}

		// backoff for up to 1 second, or 5 minutes if agent version is old.
		// immediately retry if gRPC connection state changes.
		retryInterval := time.Second
		if isUnimplementedError(err) {
			// older agent version, every 5 minutes, retry subscription
			retryInterval = 5 * time.Minute
		} else {
			now := time.Now()
			if now.After(nextLog) { // silence needless logs.
				sm.log.Info("error synchronizing state with agent", logfields.Error, err)
				nextLog = now.Add(30 * time.Second)
			}
		}
		sctx, cancel := context.WithTimeout(ctx, retryInterval)
		sm.client.WaitMaybeReconnected(sctx)
		cancel()
	}

	return ctx.Err()
}

func (sm *stateManager) trySyncState(ctx context.Context) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(context.Canceled)

	stream, err := sm.client.SubscribeState(ctx)
	if err != nil {
		return fmt.Errorf("SubscribState() failed: %w", err)
	}

	// Launch a goroutine to consume agent states
	go func() {
		var err error
		var agentState *pb.AgentState
		for ctx.Err() == nil {
			agentState, err = stream.Recv()
			if err != nil {
				break
			}
			sm.setAgentState(agentState, false)
		}
		sm.setAgentState(agentState, true)
		cancel(err)
	}()

	// get list/watch of proxy state changes
	wtx := sm.db.WriteTxn(sm.proxyState)
	changeStream, err := sm.proxyState.Changes(wtx)
	wtx.Commit()
	if err != nil {
		sm.log.Error("BUG: failed to watch for proxy state changes", logfields.Error, err)
		return err
	}

	// Forward them to the agent until it fails or we shut down
	for {
		changes, watch := changeStream.Next(sm.db.ReadTxn())
		for change := range changes {
			if err := stream.Send(change.Object.ToMessage()); err != nil {
				sm.log.Info("SubscribeState(): failed to send proxy state change to agent")
				cancel(err)
				return err
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-stream.Context().Done():
			return nil
		case <-watch:
		}
	}
}
