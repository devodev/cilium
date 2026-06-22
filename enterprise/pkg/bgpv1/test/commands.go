// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package test

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/cilium/hive"
	"github.com/cilium/hive/script"
	gobgpapi "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/spf13/pflag"
	k8stypes "k8s.io/apimachinery/pkg/types"

	ceeCommands "github.com/cilium/cilium/enterprise/pkg/bgpv1/commands"
	"github.com/cilium/cilium/pkg/bgp/api"
	"github.com/cilium/cilium/pkg/bgp/gobgp"
	"github.com/cilium/cilium/pkg/bgp/test/commands"
	"github.com/cilium/cilium/pkg/bgp/types"
	client "github.com/cilium/cilium/pkg/k8s/client/testutils"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
)

const (
	communitiesFlag      = "communities"
	communitiesFlagShort = "c"
)

// BGPTestScriptCmds are special purpose script commands for BGP Control Plane tests.
func BGPTestScriptCmds(clientSet *client.FakeClientset, writer *writer.Writer, egwMgr *egwManagerMock) hive.ScriptCmdsOut {
	return hive.NewScriptCmds(map[string]script.Cmd{
		"bgptest/upsert-egw-policy":  UpsertEGWPolicyCommand(egwMgr),
		"bgptest/set-backend-health": SetBackendHealthCommand(writer),
	})
}

// UpsertEGWPolicyCommand upserts mocked Egress Gateway Policy data for the test.
func UpsertEGWPolicyCommand(egwMgr *egwManagerMock) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Upsert Egress Gateway Policy data in the test",
			Args:    "name labels egress-ips",
			Detail: []string{
				"Update/insert mock Egress Gateway Policy data in the test.",
				"",
				"'name' is the name of the EGW policy.",
				"'labels' is a set of key=value labels of the policy separated by colon, e.g. 'key1=value1,key2=value2'.",
				"'egress-ips' is list of IP addresses used as egress IPs by the policy.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) < 3 {
				return nil, fmt.Errorf("invalid command format, should be: 'bgptest/upsert-egw-policy name labels egress-ips'")
			}
			labels := make(map[string]string)
			for label := range strings.SplitSeq(args[1], ",") {
				parts := strings.Split(label, "=")
				if len(parts) != 2 {
					return nil, fmt.Errorf("invalid label format: '%s'", label)
				}
				labels[parts[0]] = parts[1]
			}
			egressIPs := make([]netip.Addr, 0)
			for ip := range strings.SplitSeq(args[2], ",") {
				if ip == "" {
					continue
				}
				ipAddr, err := netip.ParseAddr(ip)
				if err != nil {
					return nil, fmt.Errorf("invalid egw IP address: %s", ip)
				}
				egressIPs = append(egressIPs, ipAddr)
			}
			policy := mockEGWPolicy{
				id:        k8stypes.NamespacedName{Name: args[0]},
				labels:    labels,
				egressIPs: egressIPs,
			}
			s.Logf("Upserting EGW Policy: %s (labels: %v, IPs: %v)", policy.id.Name, policy.labels, policy.egressIPs)
			egwMgr.updateMockPolicy(policy)
			return nil, nil
		},
	)
}

func SetBackendHealthCommand(writer *writer.Writer) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Set the number of healthy backends for given frontend",
			Args:    "frontend-addr backend-count",
			Detail: []string{
				"Look up the frontend and iterate over its backends setting the first",
				"<backend-count> as healthy and rest as unhealthy.",
				"",
				"'frontend-addr' is the  frontend address of the service in the L3n4Addr format, e.g. '172.16.1.1:80/TCP'.",
				"'backend-count' is the number of healthy backends that should be reported by the mock service health check manager.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			var addr lb.L3n4Addr
			err := addr.ParseFromString(args[0])
			if err != nil {
				return nil, fmt.Errorf("invalid frontend address: %s", args[0])
			}
			backendCount, err := strconv.Atoi(args[1])
			if err != nil {
				return nil, fmt.Errorf("invalid backend count: %s", args[1])
			}

			txn := writer.WriteTxn()

			fe, _, found := writer.Frontends().Get(txn, lb.FrontendByAddress(addr))
			if !found {
				return nil, fmt.Errorf("frontend %s not found", addr.StringWithProtocol())
			}

			for be := range fe.Backends {
				writer.UpdateBackendHealth(txn, fe.ServiceName, be.Address, backendCount > 0)
				backendCount--
			}

			txn.Commit()
			return nil, nil
		},
	)
}

// CEEGoBGPScriptCmds are cee-specific GoBGP commands
func CEEGoBGPScriptCmds(cmdCtx *commands.GoBGPCmdContext) map[string]script.Cmd {
	return map[string]script.Cmd{
		"gobgp/add-route":    AddRoute(cmdCtx),
		"gobgp/delete-route": DeleteRoute(cmdCtx),
		"gobgp/routes":       GoBGPRoutesCmd(cmdCtx),
	}
}

func nextParam(s string) (string, int, error) {
	var param string

	if !strings.HasPrefix(s, "[") {
		return "", 0, fmt.Errorf("expected parameter to be enclosed in '[]', got: %s", s)
	}

	foundEnd := false
	for _, r := range s[1:] {
		if r == ']' {
			foundEnd = true
			break
		}
		param = param + string(r)
	}

	if !foundEnd {
		return "", 0, fmt.Errorf("expected parameter to be enclosed in '[]', got: %s", s)
	}

	return param, len(param) + 2, nil
}

// parseEVPNRT5Prefix parses the EVPN RT5 prefix
// [RD][ESI][ETag][Prefix][GWIP][VNI] and returns it as a
// bgp.AddrPrefixInterface.
func parseEVPNRT5Prefix(s string) (*bgp.EVPNNLRI, error) {
	param, n, err := nextParam(s)
	if err != nil {
		return nil, fmt.Errorf("failed to extract RD string: %w", err)
	}

	rd, err := bgp.ParseRouteDistinguisher(param)
	if err != nil {
		return nil, fmt.Errorf("invalid RD in EVPN prefix: %w", err)
	}

	sub := s[n:]
	param, n, err = nextParam(sub)
	if err != nil {
		return nil, fmt.Errorf("failed to extract ESI string: %w", err)
	}

	if param != "single-homed" {
		return nil, fmt.Errorf("unsupported ESI in EVPN prefix (must be 'single-homed'): %s", param)
	}

	esi, err := bgp.ParseEthernetSegmentIdentifier([]string{param})
	if err != nil {
		return nil, fmt.Errorf("invalid ESI in EVPN prefix: %w", err)
	}

	sub = sub[n:]
	param, n, err = nextParam(sub)
	if err != nil {
		return nil, fmt.Errorf("failed to extract ETag string: %w", err)
	}

	eTag, err := strconv.ParseUint(param, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid ETag in EVPN prefix: %w", err)
	}

	sub = sub[n:]
	param, n, err = nextParam(sub)
	if err != nil {
		return nil, fmt.Errorf("failed to extract Prefix string: %w", err)
	}

	prefix, err := netip.ParsePrefix(param)
	if err != nil {
		return nil, fmt.Errorf("invalid Prefix in EVPN prefix: %w", err)
	}

	sub = sub[n:]
	param, n, err = nextParam(sub)
	if err != nil {
		return nil, fmt.Errorf("failed to extract GatewayIP string: %w", err)
	}

	gwip, err := netip.ParseAddr(param)
	if err != nil {
		return nil, fmt.Errorf("invalid GatewayIP in EVPN prefix: %w", err)
	}

	sub = sub[n:]
	param, _, err = nextParam(sub)
	if err != nil {
		return nil, fmt.Errorf("failed to extract VNI string: %w", err)
	}

	vni, err := strconv.ParseUint(param, 10, 24)
	if err != nil {
		return nil, fmt.Errorf("invalid VNI in EVPN prefix: %w", err)
	}

	return bgp.NewEVPNIPPrefixRoute(
		rd,
		esi,
		uint32(eTag),
		uint8(prefix.Bits()),
		prefix.Addr(),
		gwip,
		uint32(vni),
	)
}

func parsePrefix(s string) (bgp.NLRI, error) {
	// First try to interpret as an IPv4 or IPv6 prefix
	if prefix, err := netip.ParsePrefix(s); err == nil {
		return bgp.NewIPAddrPrefix(prefix)
	}

	if strings.HasPrefix(s, "EVPN") {
		sub := s[4:]

		param, n, err := nextParam(sub)
		if err != nil {
			return nil, fmt.Errorf("failed to extract RD string: %w", err)
		}

		typ, err := strconv.ParseUint(param, 10, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid Route Type in EVPN prefix: %w", err)
		}
		if typ != 5 {
			return nil, fmt.Errorf("unsupported Route Type in EVPN prefix: %d", typ)
		}

		return parseEVPNRT5Prefix(sub[n:])
	}

	return nil, fmt.Errorf("invalid prefix format: %s", s)
}

// AddRoute adds a route to the GoBGP RIB.
func AddRoute(cmdCtx *commands.GoBGPCmdContext) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Adds a route to the GoBGP RIB",
			Args:    "prefix [nexthop] [llnexthop]",
			Flags: func(fs *pflag.FlagSet) {
				fs.StringP(
					commands.ServerNameFlag,
					commands.ServerNameFlagShort,
					"",
					"Name of the GoBGP server instance. Can be omitted if only one instance is active.",
				)
				fs.StringSliceP(
					communitiesFlag,
					communitiesFlagShort,
					nil,
					"BGP communities (standard / large / extended) to be associated with the route. Multiple comma-separated values are accepted.",
				)
			},
			Detail: []string{
				"Adds a route to the GoBGP RIB.",
				"",
				"'Prefix' is one of the following formats:",
				"  - IPv4 prefix (e.g. 10.0.0.0/24)",
				"  - IPv6 prefix (e.g. 2001:db8::/32)",
				"  - EVPN RT5 prefix EVPN[5][RD][ESI][ETag][Prefix][GWIP][VNI]",
				"    - RD: Route Distinguisher in any format",
				"    - ESI: Ethernet Segment Identifier, only 'single-homed' is supported at this point",
				"    - ETag: Ethernet Tag ID, a 32-bit unsigned integer",
				"    - Prefix: IPv4 or IPv6 prefix",
				"    - GWIP: Gateway IP address for the prefix",
				"    - VNI: VXLAN Network Identifier, a 24-bit unsigned integer",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) < 1 {
				return nil, fmt.Errorf("invalid command format, should be: 'gobgp/add-route prefix [nexthop] [llnexthop]'")
			}
			if len(args) > 3 {
				return nil, fmt.Errorf("invalid command format, too many arguments: 'gobgp/add-route prefix [nexthop] [llnexthop]'")
			}

			nlri, err := parsePrefix(args[0])
			if err != nil {
				return nil, fmt.Errorf("invalid prefix: %s: %w", args[0], err)
			}

			var nexthop, llnexthop netip.Addr
			if len(args) >= 2 {
				nexthop, err = netip.ParseAddr(args[1])
				if err != nil {
					return nil, fmt.Errorf("invalid nexthop: %s", args[1])
				}
			}
			if len(args) >= 3 {
				llnexthop, err = netip.ParseAddr(args[2])
				if err != nil {
					return nil, fmt.Errorf("invalid link-local nexthop: %s", args[2])
				}
			}

			return func(*script.State) (stdout, stderr string, err error) {
				goBGPServer, err := commands.GetGoBGPServer(s, cmdCtx)
				if err != nil {
					return "", "", fmt.Errorf("failed to get GoBGP server: %w", err)
				}

				originAttr := bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP)

				var path *apiutil.Path
				switch {
				case len(args) == 1:
					p, err := defaultPathForNLRI(nlri)
					if err != nil {
						return "", "", fmt.Errorf("failed to create default path: %w", err)
					}
					path, err = gobgp.ToGoBGPPath(p)
					if err != nil {
						return "", "", fmt.Errorf("failed to convert default path to GoBGP path: %w", err)
					}
				case len(args) == 2:
					family, goBGPFamily, err := pathFamilyForNLRI(nlri)
					if err != nil {
						return "", "", err
					}
					if family.Afi == types.AfiIPv4 && nexthop.Is4() {
						// v4 prefix with v4 nexthop.
						// Use regular NEXTHOP
						// attribute.
						nextHopAttr, err := bgp.NewPathAttributeNextHop(nexthop)
						if err != nil {
							return "", "", fmt.Errorf("failed to create next-hop attribute: %w", err)
						}
						path, err = gobgp.ToGoBGPPath(&types.Path{
							Family: family,
							NLRI:   nlri,
							PathAttributes: []bgp.PathAttributeInterface{
								originAttr,
								nextHopAttr,
							},
						})
						if err != nil {
							return "", "", fmt.Errorf("failed to convert prefix and nexthop to GoBGP path: %w", err)
						}
					} else {
						// Other cases (v4 prefix with
						// v6 nexthop, v6 prefix with v6
						// nexthop) are encoded using
						// MP_REACH_NLRI attribute.
						mpReachNLRIAttr, err := bgp.NewPathAttributeMpReachNLRI(goBGPFamily, []bgp.PathNLRI{{NLRI: nlri}}, nexthop)
						if err != nil {
							return "", "", fmt.Errorf("failed to create MP_REACH_NLRI attribute: %w", err)
						}
						path, err = gobgp.ToGoBGPPath(&types.Path{
							Family: family,
							NLRI:   nlri,
							PathAttributes: []bgp.PathAttributeInterface{
								originAttr,
								mpReachNLRIAttr,
							},
						})
						if err != nil {
							return "", "", fmt.Errorf("failed to convert prefix and nexthop to GoBGP path: %w", err)
						}
					}
				case len(args) >= 3:
					family, goBGPFamily, err := pathFamilyForNLRI(nlri)
					if err != nil {
						return "", "", err
					}
					// Link-local nexthop is only usable
					// with MP_REACH_NLRI attribute.
					mpReachNLRIAttr, err := bgp.NewPathAttributeMpReachNLRI(goBGPFamily, []bgp.PathNLRI{{NLRI: nlri}}, nexthop, llnexthop)
					if err != nil {
						return "", "", fmt.Errorf("failed to create MP_REACH_NLRI attribute: %w", err)
					}
					path, err = gobgp.ToGoBGPPath(&types.Path{
						Family: family,
						NLRI:   nlri,
						PathAttributes: []bgp.PathAttributeInterface{
							originAttr,
							mpReachNLRIAttr,
						},
					})
					if err != nil {
						return "", "", fmt.Errorf("failed to convert prefix and nexthops to GoBGP path: %w", err)
					}
				}

				commValues, err := s.Flags.GetStringSlice(communitiesFlag)
				if err != nil {
					return "", "", err
				}
				var (
					communities         []uint32
					largeCommunities    []*bgp.LargeCommunity
					extendedCommunities []bgp.ExtendedCommunityInterface
				)
				for _, community := range commValues {
					// First check the extended community
					// prefixes.
					switch {
					case strings.HasPrefix(community, "rt:"):
						rt, err := bgp.ParseRouteTarget(community[3:])
						if err != nil {
							return "", "", fmt.Errorf("invalid RT format: %w", err)
						}
						extendedCommunities = append(extendedCommunities, rt)
						continue

					case strings.HasPrefix(community, "rtrmac:"):
						rtrmac := bgp.NewRoutersMacExtended(community[7:])
						if rtrmac == nil {
							return "", "", fmt.Errorf("invalid Router's MAC format: %s", community[7:])
						}
						extendedCommunities = append(extendedCommunities, rtrmac)
						continue

					case strings.HasPrefix(community, "encap:"):
						encap, err := bgp.ParseExtendedCommunity(bgp.EC_SUBTYPE_ENCAPSULATION, community[6:])
						if encap == nil {
							return "", "", fmt.Errorf("invalid Encap format: %w", err)
						}
						extendedCommunities = append(extendedCommunities, encap)
						continue
					}

					elems := strings.Split(community, ":")
					if len(elems) == 2 {
						fst, _ := strconv.ParseUint(elems[0], 10, 16)
						snd, _ := strconv.ParseUint(elems[1], 10, 16)
						communities = append(communities, uint32(fst<<16|snd))
					} else if len(elems) == 3 {
						fst, _ := strconv.ParseUint(elems[0], 10, 32)
						snd, _ := strconv.ParseUint(elems[1], 10, 32)
						trd, _ := strconv.ParseUint(elems[2], 10, 32)
						largeCommunities = append(largeCommunities, &bgp.LargeCommunity{ASN: uint32(fst), LocalData1: uint32(snd), LocalData2: uint32(trd)})
					} else {
						return "", "", fmt.Errorf("invalid communities value")
					}
				}
				if len(communities) > 0 || len(largeCommunities) > 0 || len(extendedCommunities) > 0 {
					var pathAttrs []bgp.PathAttributeInterface
					if len(communities) > 0 {
						pathAttrs = append(pathAttrs, bgp.NewPathAttributeCommunities(communities))
					}
					if len(largeCommunities) > 0 {
						pathAttrs = append(pathAttrs, bgp.NewPathAttributeLargeCommunities(largeCommunities))
					}
					if len(extendedCommunities) > 0 {
						pathAttrs = append(pathAttrs, bgp.NewPathAttributeExtendedCommunities(extendedCommunities))
					}
					path.Attrs = append(path.Attrs, pathAttrs...)
				}

				if _, err := goBGPServer.AddPath(
					apiutil.AddPathRequest{
						Paths: []*apiutil.Path{path},
					},
				); err != nil {
					return "", "", fmt.Errorf("failed to add path: %w", err)
				}

				return "Successfully added route: " + args[0], "", nil
			}, nil
		},
	)
}

// DeleteRoute deletes a route to the GoBGP RIB.
func DeleteRoute(cmdCtx *commands.GoBGPCmdContext) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Deletes a route to the GoBGP RIB",
			Args:    "prefix",
			Flags: func(fs *pflag.FlagSet) {
				fs.StringP(
					commands.ServerNameFlag,
					commands.ServerNameFlagShort,
					"",
					"Name of the GoBGP server instance. Can be omitted if only one instance is active.",
				)
			},
			Detail: []string{
				"Deletes a route to the GoBGP RIB.",
				"",
				"'Prefix' is IPv4 or IPv6 prefix.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) < 1 {
				return nil, fmt.Errorf("invalid command format, should be: 'gobgp/delete-route prefix nexthop'")
			}
			nlri, err := parsePrefix(args[0])
			if err != nil {
				return nil, fmt.Errorf("invalid prefix: %s: %w", args[0], err)
			}
			return func(*script.State) (stdout, stderr string, err error) {
				goBGPServer, err := commands.GetGoBGPServer(s, cmdCtx)
				if err != nil {
					return "", "", fmt.Errorf("failed to get GoBGP server: %w", err)
				}

				defaultPath, err := defaultPathForNLRI(nlri)
				if err != nil {
					return "", "", fmt.Errorf("failed to create default path: %w", err)
				}
				path, err := gobgp.ToGoBGPPath(defaultPath)
				if err != nil {
					return "", "", fmt.Errorf("failed to convert prefix to GoBGP path: %w", err)
				}

				if err := goBGPServer.DeletePath(
					apiutil.DeletePathRequest{
						Paths: []*apiutil.Path{path},
					},
				); err != nil {
					return "", "", fmt.Errorf("failed to delete path: %w", err)
				}

				return "Successfully deleted route: " + args[0], "", nil
			}, nil
		},
	)
}

func GoBGPRoutesCmd(cmdCtx *commands.GoBGPCmdContext) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "List routes on the GoBGP server",
			Args:    "[afi] [safi]",
			Flags: func(fs *pflag.FlagSet) {
				fs.StringP(commands.ServerNameFlag, commands.ServerNameFlagShort, "", "Name of the GoBGP server instance. Can be omitted if only one instance is active.")
				ceeCommands.AddOutFileFlag(fs)
			},
			Detail: []string{
				"List all routes in the global RIB on the GoBGP server",
				"",
				"'afi' is Address Family Indicator, defaults to 'ipv4'.",
				"'safi' is Subsequent Address Family Identifier, defaults to 'unicast'.",
				"If there are multiple server instances configured, the server-asn flag needs to be specified.",
			},
		},
		func(s *script.State, args ...string) (waitFunc script.WaitFunc, err error) {
			gobgpServer, err := commands.GetGoBGPServer(s, cmdCtx)
			if err != nil {
				return nil, err
			}
			return func(*script.State) (stdout, stderr string, err error) {
				w, buf, f, err := ceeCommands.GetCmdWriter(s)
				if err != nil {
					return "", "", err
				}
				tw := ceeCommands.GetCmdTabWriter(w)
				if f != nil {
					defer f.Close()
				}

				req := apiutil.ListPathRequest{
					TableType: gobgpapi.TableType_TABLE_TYPE_GLOBAL,
					Family:    bgp.NewFamily(bgp.AFI_IP, bgp.SAFI_UNICAST),
				}
				if len(args) > 0 && args[0] != "" {
					req.Family = bgp.NewFamily(uint16(types.ParseAfi(args[0])), req.Family.Safi())
				}
				if len(args) > 1 && args[1] != "" {
					req.Family = bgp.NewFamily(req.Family.Afi(), uint8(types.ParseSafi(args[1])))
				}
				type pathSet struct {
					prefix bgp.NLRI
					paths  []*apiutil.Path
				}
				var paths []pathSet
				err = gobgpServer.ListPath(req, func(prefix bgp.NLRI, listedPaths []*apiutil.Path) {
					paths = append(paths, pathSet{prefix: prefix, paths: listedPaths})
				})
				sort.Slice(paths, func(i, j int) bool {
					return paths[i].prefix.String() < paths[j].prefix.String()
				})

				printPathHeader(tw)
				for _, path := range paths {
					printPath(tw, path.prefix, path.paths)
				}
				tw.Flush()
				return buf.String(), "", err
			}, nil
		},
	)
}

func printPathHeader(w *tabwriter.Writer) {
	fmt.Fprintln(w, "Prefix\tNextHop\tAttrs")
}

func printPath(w *tabwriter.Writer, prefix bgp.NLRI, paths []*apiutil.Path) {
	aPaths, _ := gobgp.ToAgentPaths(paths)
	sort.Slice(aPaths, func(i, j int) bool {
		return fmt.Sprint(aPaths[i].PathAttributes) < fmt.Sprint(aPaths[j].PathAttributes)
	})
	for _, path := range aPaths {
		fmt.Fprintf(w, "%s\t%s\t%s\n", prefix.String(), api.NextHopFromPathAttributes(path.PathAttributes), ceeCommands.FormatPathAttributes(path.PathAttributes))
	}
}

func pathFamilyForNLRI(nlri bgp.NLRI) (types.Family, bgp.Family, error) {
	switch nlri := nlri.(type) {
	case *bgp.IPAddrPrefix:
		if nlri.Prefix.Addr().Is4() {
			return types.Family{Afi: types.AfiIPv4, Safi: types.SafiUnicast}, bgp.NewFamily(bgp.AFI_IP, bgp.SAFI_UNICAST), nil
		}
		return types.Family{Afi: types.AfiIPv6, Safi: types.SafiUnicast}, bgp.NewFamily(bgp.AFI_IP6, bgp.SAFI_UNICAST), nil
	case *bgp.EVPNNLRI:
		return types.Family{Afi: types.AfiL2VPN, Safi: types.SafiEvpn}, bgp.NewFamily(bgp.AFI_L2VPN, bgp.SAFI_EVPN), nil
	default:
		return types.Family{}, 0, fmt.Errorf("unsupported NLRI type: %T", nlri)
	}
}

func defaultPathForNLRI(nlri bgp.NLRI) (*types.Path, error) {
	family, goBGPFamily, err := pathFamilyForNLRI(nlri)
	if err != nil {
		return nil, err
	}
	originAttr := bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP)
	path := &types.Path{
		Family: family,
		NLRI:   nlri,
		PathAttributes: []bgp.PathAttributeInterface{
			originAttr,
		},
	}
	switch nlri := nlri.(type) {
	case *bgp.IPAddrPrefix:
		if nlri.Prefix.Addr().Is4() {
			nextHop, err := bgp.NewPathAttributeNextHop(netip.IPv4Unspecified())
			if err != nil {
				return nil, fmt.Errorf("failed to create IPv4 next-hop attribute: %w", err)
			}
			path.PathAttributes = append(path.PathAttributes, nextHop)
			return path, nil
		}

		mpReach, err := bgp.NewPathAttributeMpReachNLRI(goBGPFamily, []bgp.PathNLRI{{NLRI: nlri}}, netip.IPv6Unspecified())
		if err != nil {
			return nil, fmt.Errorf("failed to create IPv6 MP_REACH_NLRI attribute: %w", err)
		}
		path.PathAttributes = append(path.PathAttributes, mpReach)
		return path, nil
	case *bgp.EVPNNLRI:
		rt5 := nlri.RouteTypeData.(*bgp.EVPNIPPrefixRoute)
		nextHop := netip.IPv6Unspecified()
		if rt5.IPPrefix.Is4() {
			nextHop = netip.IPv4Unspecified()
		}
		mpReach, err := bgp.NewPathAttributeMpReachNLRI(goBGPFamily, []bgp.PathNLRI{{NLRI: nlri}}, nextHop)
		if err != nil {
			return nil, fmt.Errorf("failed to create EVPN MP_REACH_NLRI attribute: %w", err)
		}
		path.PathAttributes = append(path.PathAttributes, mpReach)
		return path, nil
	default:
		return nil, fmt.Errorf("unsupported NLRI type: %T", nlri)
	}
}
