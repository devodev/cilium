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
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"strings"

	flag "github.com/spf13/pflag"

	"github.com/cilium/cilium/tools/testowners/codeowners"
)

var (
	ignore = "@isovalent/void"

	// defaultOwners maps code owner teams from OSS into Enterprise.
	// The key of the map is a team in the Cilium organization on GitHub,
	// used in the CODEOWNERS file in the cilium/cilium main branch. The
	// value in the map is the corresponding team that owns the same code
	// in the Enterprise tree.
	//
	// If some areas do not directly map, or there are no tests that run in
	// Enterprise for files owned by the OSS team, then those teams can be
	// mapped to the "ignore" team declared above.
	defaultOwners = map[string]string{
		"@cilium/alibabacloud":       "@isovalent/infrastructure",
		"@cilium/api":                ignore,
		"@cilium/aws":                "@isovalent/infrastructure",
		"@cilium/azure":              "@isovalent/infrastructure",
		"@cilium/build":              ignore,
		"@cilium/cilium-maintainers": ignore,
		"@cilium/ci-structure":       ignore,
		"@cilium/cli":                "@isovalent/ci-structure",
		"@cilium/community":          ignore,
		"@cilium/committers":         ignore,
		"@cilium/contributing":       ignore,
		"@cilium/docker":             ignore,
		"@cilium/docs-structure":     ignore,
		"@cilium/egress-gateway":     "@isovalent/egress-gateway",
		"@cilium/endpoint":           "@isovalent/policy-identity-networking",
		"@cilium/envoy":              "@isovalent/service-mesh",
		"@cilium/fqdn":               "@isovalent/dns-proxy",
		"@cilium/github-sec":         ignore,
		"@cilium/gke":                "@isovalent/infrastructure",
		"@cilium/helm":               ignore,
		"@cilium/hubble-metrics":     "@isovalent/hubble",
		"@cilium/ipcache":            "@isovalent/policy-identity-networking",
		"@cilium/ipsec":              "@isovalent/encryption",
		"@cilium/kvstore":            ignore,
		"@cilium/loader":             "@isovalent/networking-framework",
		"@cilium/metrics":            ignore,
		"@cilium/operator":           ignore,
		"@cilium/proxy":              "@isovalent/service-mesh",
		"@cilium/release-managers":   ignore,
		"@cilium/security":           ignore,
		"@cilium/sig-agent":          "@isovalent/cni",
		"@cilium/sig-bgp":            "@isovalent/traffic-engineering",
		"@cilium/sig-clustermesh":    "@isovalent/clustermesh",
		"@cilium/sig-datapath":       "@isovalent/cni",
		"@cilium/sig-encryption":     "@isovalent/encryption",
		"@cilium/sig-foundations":    "@isovalent/ci-structure",
		"@cilium/sig-hubble":         "@isovalent/hubble",
		"@cilium/sig-hubble-api":     "@isovalent/hubble-api",
		"@cilium/sig-ipam":           "@isovalent/networking-framework",
		"@cilium/sig-k8s":            "@isovalent/sig-k8s",
		"@cilium/sig-lb":             "@isovalent/isovalent-loadbalancer",
		"@cilium/sig-policy":         "@isovalent/policy-identity-networking",
		"@cilium/sig-scalability":    "@isovalent/scalability-performance",
		"@cilium/sig-servicemesh":    "@isovalent/service-mesh",
		"@cilium/vendor":             ignore,
		"@cilium/wireguard":          "@isovalent/encryption",
		"@cilium/ztunnel":            "@isovalent/encryption",
	}

	// teams is a map of all of all teams in the Isovalent GitHub
	// organization which are also present in the CODEOWNERS file.
	//
	// If you are extending the CODEOWNERS file to add a new team, please
	// add an entry into this map corresponding to that new team.
	teams = map[string]struct{}{
		"@isovalent/backporters":                {},
		"@isovalent/cilium-agent":               {},
		"@isovalent/cilium-datapath":            {},
		"@isovalent/ci-structure":               {},
		"@isovalent/cli":                        {},
		"@isovalent/clustermesh":                {},
		"@isovalent/cni":                        {},
		"@isovalent/core-structure":             {},
		"@isovalent/dns-proxy":                  {},
		"@isovalent/egress-gateway":             {},
		"@isovalent/encryption":                 {},
		"@isovalent/helm":                       {},
		"@isovalent/hubble":                     {},
		"@isovalent/hubble-rbac":                {},
		"@isovalent/hubble-api":                 {},
		"@isovalent/ignore-k8s-crd":             {},
		"@isovalent/infrastructure":             {},
		"@isovalent/isovalent-loadbalancer":     {},
		"@isovalent/metrics":                    {},
		"@isovalent/networking-framework":       {},
		"@isovalent/openshift":                  {},
		"@isovalent/policy-identity-networking": {},
		"@isovalent/private-networking":         {},
		"@isovalent/qa":                         {},
		"@isovalent/release-managers":           {},
		"@isovalent/scalability-performance":    {},
		"@isovalent/security":                   {},
		"@isovalent/service-mesh":               {},
		"@isovalent/sig-defence":                {},
		"@isovalent/sig-k8s":                    {},
		"@isovalent/timescape":                  {},
		"@isovalent/traffic-engineering":        {},
		"@isovalent/void":                       {},
	}
)

type mapper struct {
	codeOwnerToEnterprise map[string]string
	targetTeams           map[string]struct{}
}

func newMapper(teamMapping map[string]string, teams map[string]struct{}) mapper {
	return mapper{
		codeOwnerToEnterprise: teamMapping,
		targetTeams:           teams,
	}
}

type testOwner interface {
	String() string
}

func (m *mapper) targetOwner(owner testOwner) (string, error) {
	o := owner.String()
	if o == "@isovalent/core-structure" ||
		o == "@isovalent/backporters" ||
		o == "@isovalent/release-managers" {
		// These catch-all groups have rights for general maintenance
		// purposes, so should be excluded from test ownership.
		return ignore, nil
	}

	newOwner, ok := m.codeOwnerToEnterprise[o]
	if ok {
		return newOwner, nil
	}
	if _, ok := m.targetTeams[o]; ok {
		return o, nil
	}
	return "", fmt.Errorf("mapping code owner %q: No team found in internal mapping", o)
}

var (
	CodeOwners []string
)

func init() {
	flag.StringSliceVar(&CodeOwners, "code-owners", []string{}, "Use the code owners defined in these files for --log-code-owners")
}

func main() {
	var exitCode int

	flag.Parse()

	owners, err := codeowners.Load(CodeOwners)
	if err != nil {
		slog.Error("Cannot load codeowners", slog.Any("error", err.Error()))
		os.Exit(1)
	}
	rules := owners.Ruleset
	mapper := newMapper(defaultOwners, teams)

	out := bufio.NewWriter(os.Stdout)

	for _, r := range rules {
		owners := make([]string, 0, len(r.Owners))

		if len(r.Owners) == 0 {
			slog.Info("No code owners assigned for pattern", slog.Any("path", r.RawPattern()))
		}
		for _, o := range r.Owners {
			newOwner, err := mapper.targetOwner(o)
			if err != nil {
				slog.Error("Failed to find owner", slog.Any("path", r.RawPattern()), slog.Any("error", err))
				exitCode = 1
			}
			if newOwner != ignore {
				owners = append(owners, newOwner)
			}
		}

		if len(owners) == 0 {
			continue
		}
		fmt.Fprintf(out, "%s %s\n", r.RawPattern(), strings.Join(owners, " "))
	}

	out.Flush()
	os.Exit(exitCode)
}
