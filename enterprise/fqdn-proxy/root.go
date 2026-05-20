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

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/hive/shell"

	"github.com/cilium/cilium/enterprise/pkg/fqdnha/tables"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/gops"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/pprof"
)

var (
	FQDNProxy = cell.Module(
		"fqdnha-proxy",
		"Cilium FQDN-HA Proxy",

		cell.Config(defaultConfig),

		cell.Provide(newAgentClient),
		cell.Provide(newNotifier),
		cell.Provide(newRulesWatcher),
		cell.Provide(newBPFIPCache),
		cell.Provide(newRemoteNameManager),

		cell.Provide(tables.NewAgentStateTable, tables.NewRemoteProxyStateTable),
		cell.Provide(newStateManager),
		cell.Invoke(func(_ *stateManager) {}),

		gops.Cell(defaults.EnableGops, DefaultGopsPort),
		pprof.Cell(pprofConfig),
		cell.Invoke(runDNSProxy),

		// Cilium DNSProxy debug shell.
		shellCommandsCell,
		shell.ServerCell(shellSockPath),
	)

	Hive = hive.New(
		FQDNProxy,
		Metrics,
	)
)

func runDNSProxy(jg job.Group, params runParams) {
	jg.Add(job.OneShot("fqdnha-proxy", func(ctx context.Context, health cell.Health) error {
		return run(ctx, health, params)
	}, job.WithShutdown()))
}
