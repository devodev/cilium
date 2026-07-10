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
	"path/filepath"

	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/pprof"
	"github.com/cilium/cilium/pkg/time"
)

var (
	// Path to UNIX socket DNS Proxy listens on.
	// This is different from the default cilium shell.sock as dnsproxy shares runtime
	// directory(/var/run/cilium) with cilium-agent.
	shellSockPath = filepath.Join(defaults.RuntimePath, "dnsproxy-shell.sock")
)

type Config struct {
	Debug                         bool              `mapstructure:"debug"`
	EnableOfflineMode             bool              `mapstructure:"tofqdns-enable-offline-mode"`
	EnableIPV6                    bool              `mapstructure:"enable-ipv6"`
	EnableIPV4                    bool              `mapstructure:"enable-ipv4"`
	EnableDNSCompression          bool              `mapstructure:"tofqdns-enable-dns-compression"`
	ExposePrometheusMetrics       bool              `mapstructure:"expose-metrics"`
	PrometheusPort                uint16            `mapstructure:"prometheus-port"`
	DNSNotificationSendWorkers    uint              `mapstructure:"dns-notification-retry-workers"`
	DNSNotificationChannelSize    uint              `mapstructure:"dns-notification-channel-size"`
	ConcurrencyLimit              uint              `mapstructure:"concurrency-limit"`
	ConcurrencyGracePeriod        time.Duration     `mapstructure:"concurrency-processing-grace-period"`
	FQDNRegexCompileLRUSize       uint              `mapstructure:"fqdn-regex-compile-lru-size"`
	ToFQDNSRejectResponseCode     string            `mapstructure:"tofqdns-dns-reject-response-code"`
	DNSProxyEnableTransparentMode bool              `mapstructure:"dnsproxy-enable-transparent-mode"`
	DNSProxySocketLingerTimeout   uint              `mapstructure:"dnsproxy-socket-linger-timeout"`
	LogDriver                     []string          `mapstructure:"log-driver"`
	LogOpt                        map[string]string `mapstructure:"log-opt"`
}

// IsDualStack returns whether both IPv4 and IPv6 are enabled.
func (cfg Config) IsDualStack() bool {
	return cfg.EnableIPV4 && cfg.EnableIPV6
}

var defaultConfig = Config{
	Debug:                         false,
	EnableOfflineMode:             false,
	EnableIPV4:                    true,
	EnableIPV6:                    true,
	EnableDNSCompression:          true,
	ExposePrometheusMetrics:       false,
	PrometheusPort:                9967,
	DNSNotificationSendWorkers:    128,
	DNSNotificationChannelSize:    16384,
	ConcurrencyLimit:              0,
	ConcurrencyGracePeriod:        0,
	FQDNRegexCompileLRUSize:       1024,
	ToFQDNSRejectResponseCode:     "refused",
	DNSProxyEnableTransparentMode: false,
	DNSProxySocketLingerTimeout:   defaults.DNSProxySocketLingerTimeout,
	LogDriver:                     []string{},
	LogOpt:                        map[string]string{},
}

const DefaultGopsPort = 8910

var pprofConfig = pprof.Config{
	Pprof:                     false,
	PprofAddress:              "localhost",
	PprofPort:                 8920,
	PprofMutexProfileFraction: 0,
	PprofBlockProfileRate:     0,
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("debug", def.Debug, "Enable debugging mode")
	flags.Bool("tofqdns-enable-offline-mode", def.EnableOfflineMode, "DNS Proxy will use the Cilium agent's bpf maps directly rather than getting information from the agent's dns proxy service.")
	flags.Bool("enable-ipv6", def.EnableIPV6, "")
	flags.Bool("enable-ipv4", def.EnableIPV4, "")
	flags.Bool("tofqdns-enable-dns-compression", def.EnableDNSCompression, "Allow the DNS proxy to compress responses to endpoints that are larger than 512 Bytes or the EDNS0 option, if present")
	flags.Bool("expose-metrics", def.ExposePrometheusMetrics, "")
	flags.Uint16("prometheus-port", def.PrometheusPort, "")
	flags.Uint("dns-notification-retry-workers", def.DNSNotificationSendWorkers, "")
	flags.Uint("dns-notification-channel-size", def.DNSNotificationChannelSize, "This is the number of DNS messages that will generate a notification in Cilium Agent after it restarts. All DNS messages above this limit will be handled by proxy, but not generate notification after Cilium Agent restarts.")
	flags.Uint("concurrency-limit", def.ConcurrencyLimit, "concurrency limit for dns proxy (0 for infinite)")
	flags.Duration("concurrency-processing-grace-period", def.ConcurrencyGracePeriod, "Grace time to wait when DNS proxy concurrent limit has been reached during DNS message processing")
	flags.Uint("fqdn-regex-compile-lru-size", def.FQDNRegexCompileLRUSize, "Size of the FQDN regex compilation LRU. Useful for heavy but repeated DNS L7 rules with MatchName or MatchPattern")
	flags.String("tofqdns-dns-reject-response-code", def.ToFQDNSRejectResponseCode, "DNS response code for rejecting DNS requests, available options are '[nameError refused]' (default \"refused\")")
	flags.Bool("dnsproxy-enable-transparent-mode", def.DNSProxyEnableTransparentMode, "Enable DNS proxy transparent mode")
	flags.Uint("dnsproxy-socket-linger-timeout", def.DNSProxySocketLingerTimeout, "Timeout (in seconds) when closing the connection between the DNS proxy and the upstream server."+
		"If set to 0, the connection is closed immediately (with TCP RST). If set to -1, the connection is closed asynchronously in the background")
	flags.StringSlice("log-driver", def.LogDriver, "Logging endpoints to use (example: syslog)")
	flags.StringToString("log-opt", def.LogOpt, `Log driver options for the dnsproxy, `+
		`configmap example for syslog driver: {"syslog.level":"info","syslog.facility":"local5","syslog.tag":"cilium-dnsproxy"}`)
}
