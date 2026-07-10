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
	"io"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/cilium/hive/script"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/spf13/pflag"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/cilium/cilium/enterprise/pkg/bgpv1/agent"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/manager/reconcilerv2"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	ossAgent "github.com/cilium/cilium/pkg/bgp/agent"
	"github.com/cilium/cilium/pkg/bgp/api"
	ossTypes "github.com/cilium/cilium/pkg/bgp/types"
	"github.com/cilium/cilium/pkg/time"
)

func BGPRoutesCmd(bgpMgr agent.EnterpriseBGPRouterManager, errorPathStore *reconcilerv2.ErrorPathStore) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "List BGP routes on Cilium",
			Args:    "<table type> <afi> <safi>",
			Flags: func(fs *pflag.FlagSet) {
				AddOutFileFlag(fs)
				fs.StringP(formatFlag, formatFlagShort, "table", "Format to write in (table, table-json or json)")
				fs.Bool("no-age", false, "Do not show Age column for testing purpose")
				fs.BoolP("with-attrs", "a", false, "Show path attributes (excluding NEXT_HOP and MP_REACH_NLRI)")
			},
			Detail: []string{
				"List routes in the BGP Control Plane's RIBs",
				"",
				"table type: \"loc\" (loc-rib), \"in\" (adj-rib-in), or \"out\" (adj-rib-out).",
				"afi: Address Family Identifier (e.g. ipv4, ipv6).",
				"safi: Subsequent Address Family Identifier (e.g. unicast).",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) < 3 {
				return nil, fmt.Errorf("BGP routes command requires <table type> <afi> <safi>")
			}
			format, err := s.Flags.GetString(formatFlag)
			if err != nil {
				return nil, err
			}
			tableType, err := parseTableTypeArg(args[0])
			if err != nil {
				return nil, err
			}
			afi := ossTypes.ParseAfi(args[1])
			if afi == ossTypes.AfiUnknown {
				return nil, fmt.Errorf("unknown AFI %s", args[1])
			}
			safi := ossTypes.ParseSafi(args[2])
			if safi == ossTypes.SafiUnknown {
				return nil, fmt.Errorf("unknown SAFI %s", args[2])
			}
			routesReq := &agent.GetRoutesExtendedRequest{
				TableType: tableType,
				Family: ossTypes.Family{
					Afi:  afi,
					Safi: safi,
				},
			}
			peersReq := &ossAgent.GetPeersRequest{}

			return func(*script.State) (stdout, stderr string, err error) {
				noAge, err := s.Flags.GetBool("no-age")
				if err != nil {
					return "", "", err
				}

				printAttr, err := s.Flags.GetBool("with-attrs")
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

				routesRes, err := bgpMgr.GetRoutesExtended(s.Context(), routesReq)
				if err != nil {
					return "", "", err
				}

				peersRes, err := bgpMgr.GetPeers(s.Context(), peersReq)
				if err != nil {
					return "", "", err
				}

				peerMaps := make(map[string]map[netip.Addr]string)
				for _, instance := range peersRes.Instances {
					m := make(map[netip.Addr]string)
					peerMaps[instance.Name] = m
					for _, peer := range instance.Peers {
						m[peer.Address] = peer.Name
					}
				}

				isAdjRIB := tableType == ossTypes.TableTypeAdjRIBIn || tableType == ossTypes.TableTypeAdjRIBOut

				switch format {
				case "table":
					tw := GetCmdTabWriter(w)
					if err != nil {
						return "", "", err
					}
					PrintRoutes(tw, routesRes.Instances, peerMaps, errorPathStore, noAge, isAdjRIB, printAttr)
					tw.Flush()
				case "table-json":
					builder := strings.Builder{}
					PrintRoutes(&builder, routesRes.Instances, peerMaps, errorPathStore, noAge, isAdjRIB, printAttr)
					table := tableJSONfromString(builder.String())
					out, err := json.MarshalIndent(table, "", "  ")
					if err != nil {
						return "", "", fmt.Errorf("json marshal failed: %w", err)
					}
					if _, err := w.Write(out); err != nil {
						return "", "", err
					}
				case "json":
					out, err := json.MarshalIndent(routesRes, "", "  ")
					if err != nil {
						return "", "", fmt.Errorf("json marshal failed: %w", err)
					}
					if _, err := w.Write(out); err != nil {
						return "", "", err
					}
				default:
					return "", "", fmt.Errorf("unsupported format: %s", format)
				}

				return buf.String(), "", nil
			}, nil
		},
	)
}

func parseTableTypeArg(arg string) (ossTypes.TableType, error) {
	switch arg {
	case "loc":
		return ossTypes.TableTypeLocRIB, nil
	case "in":
		return ossTypes.TableTypeAdjRIBIn, nil
	case "out":
		return ossTypes.TableTypeAdjRIBOut, nil
	default:
		return ossTypes.TableTypeUnknown, fmt.Errorf("unknown table type %s", arg)
	}
}

func PrintRoutes(
	w io.Writer,
	instances []agent.InstanceRoutesExtended,
	peerMaps map[string]map[netip.Addr]string,
	errorPathStore *reconcilerv2.ErrorPathStore,
	noAge, isAdjRIB, printAttr bool,
) {
	type row struct {
		Instance string
		Peer     string
		Prefix   string
		NextHop  string
		Best     string
		Age      string
		Error    string
		Attrs    string
	}

	var rows []row
	for _, instance := range instances {
		for _, route := range instance.Routes {
			for _, path := range route.Paths {
				var (
					peerName string
					errStr   = "-"
				)
				if isAdjRIB {
					peerName = instance.NeighborName
				} else {
					peerName = "(unknown)"
					if !path.NeighborAddr.IsValid() {
						peerName = "(self)"
					}
					if peerMap, found := peerMaps[instance.InstanceName]; found {
						if name, found := peerMap[path.NeighborAddr]; found {
							peerName = name
						}
					}
					// Find the route import error
					// associated with this path if it
					// exists.
					errPath, found := errorPathStore.Get(
						instance.InstanceName,
						path.Family,
						reconcilerv2.ErrorPathKeyFromPath(path),
					)
					if found {
						// The error string is
						// lowercase. To make it more
						// readable, we convert it to
						// title case.
						errStr = cases.Title(language.English).String(errPath.Error.Error())
					}
				}
				r := row{
					Instance: instance.InstanceName,
					Peer:     peerName,
					Prefix:   route.Prefix,
					NextHop:  api.NextHopFromPathAttributes(path.PathAttributes),
					Best:     strconv.FormatBool(path.Best),
					Age:      path.Age().Truncate(time.Second).String(),
					Error:    errStr,
					Attrs:    FormatPathAttributes(path.PathAttributes),
				}
				if noAge {
					r.Age = "-"
				}
				rows = append(rows, r)
			}
		}
	}

	slices.SortFunc(rows, func(a, b row) int {
		c := strings.Compare(a.Instance, b.Instance)
		if c != 0 {
			return c
		}
		c = strings.Compare(a.Peer, b.Peer)
		if c != 0 {
			return c
		}
		return strings.Compare(a.Prefix, b.Prefix)
	})

	rows = slices.Insert(rows, 0, row{
		Instance: "Instance",
		Peer:     "Peer",
		Prefix:   "Prefix",
		NextHop:  "NextHop",
		Best:     "Best",
		Age:      "Age",
		Error:    "Error",
		Attrs:    "Attrs",
	})

	prevInstance := ""
	prevPeer := ""
	prevPrefix := ""
	for i, row := range rows {
		if i != 0 {
			if row.Instance == prevInstance {
				row.Instance = ""
			}
			if row.Instance == "" && row.Peer == prevPeer {
				row.Peer = ""
			}
			if row.Instance == "" && row.Peer == "" && row.Prefix == prevPrefix {
				row.Prefix = ""
			}
		}

		if isAdjRIB {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s", row.Instance, row.Peer, row.Prefix, row.NextHop, row.Age)
		} else {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s", row.Instance, row.Peer, row.Prefix, row.NextHop, row.Best, row.Age, row.Error)
		}

		if printAttr {
			fmt.Fprintf(w, "\t%s\n", row.Attrs)
		} else {
			fmt.Fprintf(w, "\n")
		}

		if row.Instance != "" {
			prevInstance = row.Instance
		}
		if row.Peer != "" {
			prevPeer = row.Peer
		}
		if row.Prefix != "" {
			prevPrefix = row.Prefix
		}
	}
}

// FormatPathAttributes should be used for formatting BGP Path Attributes in CEE commands
// as it decodes some implementation-specific path attributes into a format that is more
// human-friendly than the upstream GoBGP String() methods.
func FormatPathAttributes(pattrs []bgp.PathAttributeInterface) string {
	formatted := make([]string, 0, len(pattrs))
	for _, pa := range pattrs {
		switch a := pa.(type) {
		case *bgp.PathAttributeNextHop, *bgp.PathAttributeMpReachNLRI:
			// Skip NextHop and MpReachNLRI attributes as they are
			// already shown in a separate column.
		case *bgp.PathAttributeExtendedCommunities:
			formatted = append(formatted, formatExtendedCommunities(a))
		default:
			formatted = append(formatted, pa.String())
		}

	}
	return "[" + strings.Join(formatted, " ") + "]"
}

func formatExtendedCommunities(extComms *bgp.PathAttributeExtendedCommunities) string {
	formatted := make([]string, 0, len(extComms.Value))
	for _, extComm := range extComms.Value {
		switch ec := extComm.(type) {
		case *bgp.EncapExtended:
			formatted = append(formatted, formatEncapExtendedCommunity(ec))
		case *bgp.OpaqueExtended:
			formatted = append(formatted, formatOpaqueExtendedCommunity(ec))
		case *bgp.RouterMacExtended:
			formatted = append(formatted, formatRouterMacExtendedCommunity(ec))
		default:
			_, subType := extComm.GetTypes()
			if subType == bgp.EC_SUBTYPE_ROUTE_TARGET {
				formatted = append(formatted, formatRouteTargetExtendedCommunity(extComm))
			} else {
				formatted = append(formatted, extComm.String())
			}
		}
	}
	return "{Extcomms: [" + strings.Join(formatted, "], [") + "]}"
}

func formatEncapExtendedCommunity(e *bgp.EncapExtended) string {
	return fmt.Sprintf("Encap:%s", e.TunnelType.String())
}

func formatRouterMacExtendedCommunity(r *bgp.RouterMacExtended) string {
	return fmt.Sprintf("RouterMAC:%s", r.Mac)
}

func formatOpaqueExtendedCommunity(o *bgp.OpaqueExtended) string {
	if len(o.Value) == 0 {
		return o.String()
	}
	if types.IsGroupPolicyIDExtendedCommunity(o) {
		return formatGroupPolicyIDExtendedCommunity(o)
	}
	trans := "Transitive"
	if !o.IsTransitive {
		trans = "NonTransitive"
	}
	return fmt.Sprintf("Opaque%s:[subtype:%d][value:0x%x]", trans, o.Value[0], o.Value[1:])
}

func formatGroupPolicyIDExtendedCommunity(sgt *bgp.OpaqueExtended) string {
	return fmt.Sprintf("GroupPolicyID:%d", types.GetGroupPolicyIDFromExtendedCommunity(sgt))
}

func formatRouteTargetExtendedCommunity(rt bgp.ExtendedCommunityInterface) string {
	return fmt.Sprintf("RouteTarget:%s", rt.String())
}
