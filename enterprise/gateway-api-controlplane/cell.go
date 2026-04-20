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
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/hive/shell"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/gops"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/pprof"
)

var (
	GatewayAPIControlplane = cell.Module(
		"gateway-api-controlplane",
		"Gateway API controlplane",

		cell.Config(defaultConfig),

		gops.Cell(defaults.EnableGops, defaultGopsPort),
		pprof.Cell(pprofConfig),
		shell.ServerCell(shellSockPath),
		cell.Provide(newMetricsRegistry),

		cell.Provide(newXDSSnapshotStateTable),
		cell.ProvidePrivate(statedb.RWTable[*XDSSnapshotState].ToTable),

		cell.ProvidePrivate(newXDSServer),
		cell.ProvidePrivate(func(server *xdsServer) XDSResourceMutator { return server }),

		cell.ProvidePrivate(newControllerRuntimeManager),

		cell.Invoke(registerMetricsServer),
		cell.Invoke(registerHealthServer),
		cell.Invoke(registerXDSServer),
		cell.Invoke(registerGatewayController),
	)

	Hive = hive.New(
		GatewayAPIControlplane,
	)
)

type healthServerParams struct {
	cell.In

	Lifecycle cell.Lifecycle
	JobGroup  job.Group
	Health    cell.Health
	Logger    *slog.Logger
	Config    Config
}

func registerHealthServer(params healthServerParams) {
	httpServer := healthServer{
		logger:      params.Logger,
		bindAddress: params.Config.HealthBindAddress,
	}

	params.JobGroup.Add(job.OneShot("health-server", httpServer.Serve, job.WithShutdown()))

	params.Lifecycle.Append(cell.Hook{
		OnStop: func(cell.HookContext) error {
			httpServer.Stop()
			return nil
		},
	})
}

type xdsServerParams struct {
	cell.In

	Lifecycle cell.Lifecycle
	JobGroup  job.Group
	XDSServer *xdsServer
}

func registerXDSServer(params xdsServerParams) {
	params.JobGroup.Add(job.OneShot("xds-server", params.XDSServer.Serve, job.WithShutdown()))

	params.Lifecycle.Append(cell.Hook{
		OnStop: func(cell.HookContext) error {
			params.XDSServer.Stop()
			return nil
		},
	})
}
