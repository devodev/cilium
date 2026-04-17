// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package commands

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/cilium/hive/script"
	"github.com/spf13/pflag"
	"go.yaml.in/yaml/v3"

	"github.com/cilium/cilium/enterprise/pkg/bgpv1/agent"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	ossTypes "github.com/cilium/cilium/pkg/bgp/types"
)

const (
	instanceFlag      = "instance"
	instanceFlagShort = "i"
)

func BGPPRoutePolicies(bgpMgr agent.EnterpriseBGPRouterManager) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "List BGP route policies on Cilium",
			Flags: func(fs *pflag.FlagSet) {
				fs.StringP(instanceFlag, instanceFlagShort, "", "Name of a Cilium router instance. Lists policies of all instances if omitted.")
				AddOutFileFlag(fs)
				AddFormatFlag(fs)
			},
			Detail: []string{
				"Lists route policies configured in Cilium BGP Control Plane.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			instance, err := s.Flags.GetString(instanceFlag)
			if err != nil {
				return nil, err
			}
			format, err := s.Flags.GetString(formatFlag)
			if err != nil {
				return nil, err
			}
			return func(*script.State) (stdout, stderr string, err error) {
				policies, err := bgpMgr.GetRoutePoliciesExtended(s.Context(), instance)
				if err != nil {
					return "", "", err
				}

				w, buf, f, err := GetCmdWriter(s)
				if err != nil {
					return "", "", err
				}
				if f != nil {
					defer f.Close()
				}

				switch format {
				case "table":
					tw := GetCmdTabWriter(w)
					if err != nil {
						return "", "", err
					}
					PrintBGPRoutePoliciesTable(tw, policies)
				case "json":
					out, err := json.MarshalIndent(policies, "", "  ")
					if err != nil {
						return "", "", fmt.Errorf("json marshal failed: %w", err)
					}
					if _, err := w.Write(out); err != nil {
						return "", "", err
					}
				case "yaml":
					out, err := yaml.Marshal(policies)
					if err != nil {
						return "", "", fmt.Errorf("yaml marshal failed: %w", err)
					}
					if _, err := w.Write(out); err != nil {
						return "", "", err
					}
				default:
					return "", "", fmt.Errorf("unsupported format: %s", format)
				}
				return buf.String(), "", err
			}, nil
		},
	)
}

// PrintBGPRoutePoliciesTable prints table of provided BGP route policies in the provided tab writer.
func PrintBGPRoutePoliciesTable(w *tabwriter.Writer, instancePolicies map[string][]*types.ExtendedRoutePolicy) {
	fmt.Fprintln(w, "Instance\tPolicy Name\tType\tMatch Peers\tMatch Families\tMatch Prefixes (Min..Max Len)\tMatch Communities\tRIB Action\tPath Actions")

	instances := slices.Collect(maps.Keys(instancePolicies))
	slices.Sort(instances)

	for _, instance := range instances {
		policies := instancePolicies[instance]
		sort.Slice(policies, func(i, j int) bool {
			return policies[i].Name < policies[j].Name
		})
		for _, policy := range policies {
			fmt.Fprintf(w, "%s\t", instance)
			fmt.Fprintf(w, "%s\t", policy.Name)
			fmt.Fprintf(w, "%s\t", formatPolicyType(policy.Type))

			for i, stmt := range policy.Statements {
				if i > 0 {
					fmt.Fprint(w, strings.Repeat("\t", 3))
				}
				fmt.Fprintf(w, "%s\t", formatMatchNeighbors(stmt.Conditions.MatchNeighbors))
				fmt.Fprintf(w, "%s\t", formatFamilies(stmt.Conditions.MatchFamilies))
				fmt.Fprintf(w, "%s\t", formatMatchPrefixes(stmt.Conditions.MatchPrefixes))
				fmt.Fprintf(w, "%s\t", strings.Join([]string{
					formatMatchCommunities(stmt.Conditions.MatchCommunities, ""),
					formatMatchCommunities(stmt.Conditions.MatchLargeCommunities, "Large: "),
				}, " "))
				fmt.Fprintf(w, "%s\t", formatRouteActionType(stmt.Actions.RouteAction))
				fmt.Fprintf(w, "%s\n", formatPathActions(stmt.Actions.RoutePolicyActions))
			}
			if len(policy.Statements) == 0 {
				fmt.Fprintf(w, "\n")
			}
		}
	}
	w.Flush()
}

func formatPolicyType(t ossTypes.RoutePolicyType) string {
	if t == ossTypes.RoutePolicyTypeImport {
		return "import"
	}
	return "export"
}

func formatMatchNeighbors(match *ossTypes.RoutePolicyNeighborMatch) string {
	if match == nil || len(match.Neighbors) == 0 {
		return ""
	}
	neighborsStr := formatIPAddrArray(match.Neighbors)
	if len(match.Neighbors) > 1 {
		return fmt.Sprintf("(%s) %s", match.Type, neighborsStr)
	}
	return neighborsStr
}

func formatFamilies(families []ossTypes.Family) string {
	var res []string
	for _, f := range families {
		res = append(res, fmt.Sprintf("%s/%s", f.Afi, f.Safi))
	}
	return formatStringArray(res)
}

func formatMatchPrefixes(match *ossTypes.RoutePolicyPrefixMatch) string {
	if match == nil || len(match.Prefixes) == 0 {
		return ""
	}
	var prefixes []string
	for _, p := range match.Prefixes {
		prefixes = append(prefixes, fmt.Sprintf("%s (%d..%d)", p.CIDR, p.PrefixLenMin, p.PrefixLenMax))
	}
	prefixesStr := formatStringArray(prefixes)
	if len(prefixes) > 1 || match.Type == ossTypes.RoutePolicyMatchInvert {
		return fmt.Sprintf("(%s) %s", match.Type, prefixesStr)
	}
	return prefixesStr
}

func formatMatchCommunities(match *types.RoutePolicyCommunityMatch, prefix string) string {
	if match == nil || len(match.Communities) == 0 {
		return ""
	}
	commStr := formatStringArray(match.Communities)
	if len(match.Communities) > 1 || match.Type == ossTypes.RoutePolicyMatchInvert {
		return prefix + fmt.Sprintf("(%s) %s", match.Type, commStr)
	}
	return prefix + commStr
}

func formatRouteActionType(a ossTypes.RoutePolicyAction) string {
	switch a {
	case ossTypes.RoutePolicyActionAccept:
		return "accept"
	case ossTypes.RoutePolicyActionReject:
		return "reject"
	default:
		return ""
	}
}

func formatPathActions(a ossTypes.RoutePolicyActions) string {
	var res []string
	if len(a.AddCommunities) > 0 {
		res = append(res, fmt.Sprintf("AddCommunities: %v", a.AddCommunities))
	}
	if len(a.AddLargeCommunities) > 0 {
		res = append(res, fmt.Sprintf("AddLargeCommunities: %v", a.AddLargeCommunities))
	}
	if a.SetLocalPreference != nil {
		res = append(res, fmt.Sprintf("SetLocalPreference: %d", *a.SetLocalPreference))
	}
	if a.NextHop != nil {
		res = append(res, fmt.Sprintf("NextHop: %s", formatNextHop(a.NextHop)))
	}
	return formatStringArray(res)
}

func formatNextHop(nh *ossTypes.RoutePolicyActionNextHop) string {
	return fmt.Sprintf("Self=%t, Unchanged=%t", nh.Self, nh.Unchanged)
}

func formatIPAddrArray(arr []netip.Addr) string {
	if len(arr) == 1 {
		return arr[0].String()
	}
	res := strings.Builder{}
	for _, ip := range arr {
		res.WriteString("{" + ip.String() + "}" + "} ")
	}
	return strings.TrimSpace(res.String())
}

func formatStringArray(arr []string) string {
	if len(arr) == 1 {
		return arr[0]
	}
	res := strings.Builder{}
	for _, str := range arr {
		res.WriteString("{" + str + "} ")
	}
	return strings.TrimSpace(res.String())
}
