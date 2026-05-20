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

	_ "github.com/cilium/cilium/enterprise/fips"
	"github.com/cilium/cilium/enterprise/pkg/fqdnha/config"

	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/fqdn/re"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/version"
)

type runParams struct {
	cell.In

	Cfg         Config
	Log         *slog.Logger
	Watcher     *rulesWatcher
	NameManager *remoteNameManager

	Client   *fqdnAgentClient
	Notifier *notifier
}

func run(ctx context.Context, health cell.Health, params runParams) error {
	log := params.Log.With(logfields.LogSubsys, "fqdn-proxy")

	log.Info("     _ _ _")
	log.Info(" ___|_| |_|_ _ _____")
	log.Info("|  _| | | | | |     |")
	log.Info("|___|_|_|_|___|_|_|_|")
	log.Info("Cilium DNS Proxy", logfields.Version, version.Version)

	log.Info("loaded config options", logfields.Config, params.Cfg)
	cfg := params.Cfg

	log.Info("starting cilium dns proxy server")

	re.Resize(log, cfg.FQDNRegexCompileLRUSize)

	dnsProxyConfig := dnsproxy.DNSProxyConfig{
		Logger:                 log.WithGroup("dns-proxy"),
		Address:                "",
		IPv4:                   cfg.EnableIPV4,
		IPv6:                   cfg.EnableIPV6,
		EnableDNSCompression:   cfg.EnableDNSCompression,
		MaxRestoreDNSIPs:       0,
		ConcurrencyLimit:       int(cfg.ConcurrencyLimit),
		ConcurrencyGracePeriod: cfg.ConcurrencyGracePeriod,
		RejectReply:            cfg.ToFQDNSRejectResponseCode,
	}

	proxy := dnsproxy.NewDNSProxy(
		dnsProxyConfig,
		params.NameManager,
		params.Notifier.NotifyOnDNSMsg,
	)

	// wait for first L7 rules
	gotRules := params.Watcher.waitForRules(proxy)
	log.Info("Waiting for agent to provide endpoint configurations...")
	select {
	case <-gotRules:
	case <-ctx.Done():
		return ctx.Err()
	}
	time.Sleep(2 * time.Second) // grace period to get all endpoints from the agent

	log.Info("Got endpoint configurations, opening sockets.")
	err := proxy.Listen(config.DNSProxyPort) // use hard-coded port, must be same as agent
	if err != nil {
		return fmt.Errorf("failed to start DNS proxy: %w", err)
	}
	log.Info("started dns proxy")
	health.OK("started dns proxy")

	<-ctx.Done()
	log.Info("Shutting proxy down...")
	proxy.Cleanup()

	return nil
}
