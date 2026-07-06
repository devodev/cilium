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
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/cilium/hive/script"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/enterprise/pkg/bgpv1/agent"
)

func BGPGlobalsCmd(bgpMgr agent.EnterpriseBGPRouterManager) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "List BGP global configuration",
			Flags: func(fs *pflag.FlagSet) {
				AddOutFileFlag(fs)
				AddFormatFlag(fs)
			},
			Detail: []string{
				"List global configuration of all BGP instances configured in BGP Control Plane.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			format, err := s.Flags.GetString(formatFlag)
			if err != nil {
				return nil, err
			}

			return func(*script.State) (stdout, stderr string, err error) {
				res, err := bgpMgr.GetGlobalsExtended(s.Context())
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
					PrintGlobalsTable(tw, res.Instances)
				case "json":
					out, err := json.MarshalIndent(res.Instances, "", "  ")
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

func PrintGlobalsTable(tw *tabwriter.Writer, instances []agent.InstanceGlobal) {
	type row struct {
		Instance   string
		ASN        string
		RouterID   string
		ListenPort string
		VRF        string
	}

	rows := make([]row, 0, len(instances)+1)
	for _, instance := range instances {
		rows = append(rows, row{
			Instance:   instance.Name,
			ASN:        strconv.FormatUint(uint64(instance.Global.ASN), 10),
			RouterID:   instance.Global.RouterID,
			ListenPort: formatListenPort(instance.Global.ListenPort),
			VRF:        formatVRFDevice(instance.Global.BindToDevice),
		})
	}

	slices.SortFunc(rows, func(a, b row) int {
		return strings.Compare(a.Instance, b.Instance)
	})

	rows = slices.Insert(rows, 0, row{
		Instance:   "Instance",
		ASN:        "ASN",
		RouterID:   "Router ID",
		ListenPort: "Listen Port",
		VRF:        "VRF",
	})

	for _, row := range rows {
		fmt.Fprintf(tw, "%s\n", strings.Join([]string{
			row.Instance,
			row.ASN,
			row.RouterID,
			row.ListenPort,
			row.VRF,
		}, "\t"))
	}
	tw.Flush()
}

func formatListenPort(port int32) string {
	if port == -1 {
		return "(disabled)"
	}
	return strconv.FormatInt(int64(port), 10)
}

// formatVRFDevice returns the VRF device the instance/peer is bound to, or
// "(default)" if it is not bound to any device.
func formatVRFDevice(device string) string {
	if device == "" {
		return "(default)"
	}
	return device
}
