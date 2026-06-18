// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package status

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"
)

const (
	padding     = 3
	minWidth    = 5
	paddingChar = ' '
)

const (
	ansiDefault = "\033[39m"
	ansiRed     = "\033[31m"
	ansiYellow  = "\033[33m"
	ansiBlue    = "\033[34m"
	ansiGreen   = "\033[32m"
	ansiMagenta = "\033[35m"
	ansiCyan    = "\033[36m"
	ansiBold    = "\033[1m"
	ansiReset   = "\033[0m"
)

const (
	RelationOutputNumbers    = "numbers"
	RelationOutputPercentage = "percentage"
)

type LoadbalancerStatusModel struct {
	Summary  LoadbalancerStatusModelSummary   `json:"summary,omitempty"`
	Services []LoadbalancerStatusModelService `json:"services,omitempty"`
}

type ansiPalette struct {
	Default string
	Red     string
	Yellow  string
	Blue    string
	Green   string
	Magenta string
	Cyan    string
	Bold    string
	Reset   string
}

func newANSIPalette(enabled bool) ansiPalette {
	if !enabled {
		return ansiPalette{}
	}

	return ansiPalette{
		Default: ansiDefault,
		Red:     ansiRed,
		Yellow:  ansiYellow,
		Blue:    ansiBlue,
		Green:   ansiGreen,
		Magenta: ansiMagenta,
		Cyan:    ansiCyan,
		Bold:    ansiBold,
		Reset:   ansiReset,
	}
}

func (lsm *LoadbalancerStatusModel) Output(out io.Writer, params Parameters) error {
	lsm.sort()

	if params.Output == "json" {
		jsonOutput, err := json.Marshal(lsm)
		if err != nil {
			return fmt.Errorf("failed to output JSON: %w", err)
		}

		fmt.Fprintln(out, string(jsonOutput))

		return nil
	}

	colors := newANSIPalette(params.Colors)

	if !params.Verbose {

		summaryTabWriter := tabwriter.NewWriter(out, minWidth, 0, padding, paddingChar, 0)

		fmt.Fprintln(out, "=========")
		fmt.Fprintln(out, "Summary")
		fmt.Fprintln(out, "=========")
		fmt.Fprintln(out, "")

		fmt.Fprintf(summaryTabWriter, "T1 Nodes:\t%d\n", lsm.Summary.NrOfT1Nodes)
		fmt.Fprintf(summaryTabWriter, "T2 Nodes:\t%d\n", lsm.Summary.NrOfT2Nodes)
		fmt.Fprintf(summaryTabWriter, "Services:\t%d\n", lsm.Summary.NrOfServices)
		fmt.Fprintf(summaryTabWriter, "VIPs:\t%d\n", lsm.Summary.NrOfVIPs)

		summaryTabWriter.Flush()

		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "=========")
		fmt.Fprintln(out, "Services")
		fmt.Fprintln(out, "=========")
		fmt.Fprintln(out, "")

	}

	tableTabWriter := tabwriter.NewWriter(out, minWidth, 0, padding, paddingChar, 0)
	fmt.Fprintf(tableTabWriter, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", "Namespace", "Name", colors.Default+"VIP"+colors.Reset, "Port", "Type", colors.Default+"D-Mode"+colors.Reset, colors.Default+"BGP Peers"+colors.Reset, colors.Default+"BGP Routes"+colors.Reset, colors.Default+"T1"+colors.Reset, colors.Default+"HC T1->[T2|B]"+colors.Reset, colors.Default+"T2"+colors.Reset, colors.Default+"HC T2->B"+colors.Reset, colors.Default+"Backendpools"+colors.Reset, colors.Default+"Status"+colors.Reset)
	fmt.Fprintf(tableTabWriter, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", "---------", "----", colors.Default+"---"+colors.Reset, "----", "----", colors.Default+"------"+colors.Reset, colors.Default+"---------"+colors.Reset, colors.Default+"----------"+colors.Reset, colors.Default+"--"+colors.Reset, colors.Default+"-------------"+colors.Reset, colors.Default+"--"+colors.Reset, colors.Default+"--------"+colors.Reset, colors.Default+"------------"+colors.Reset, colors.Default+"------"+colors.Reset)
	for _, f := range lsm.Services {
		fmt.Fprintf(tableTabWriter, "%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", f.Namespace, f.Name, statusText(f.VIP, colors), f.Port, f.Type,
			statusText(f.DeploymentMode, colors),
			printSimpleStatusCell(f.BGPPeerStatus.LoadbalancerStatusModelSimpleStatus, params.RelationOutput, colors),
			printSimpleStatusCell(f.BGPRouteStatus, params.RelationOutput, colors),
			printSimpleStatusCell(f.T1NodeStatus, params.RelationOutput, colors),
			printSimpleStatusCell(f.T1T2HCStatus.LoadbalancerStatusModelSimpleStatus, params.RelationOutput, colors),
			printSimpleStatusCell(f.T2NodeStatus, params.RelationOutput, colors),
			printSimpleStatusCell(f.T2BackendHCStatus.LoadbalancerStatusModelSimpleStatus, params.RelationOutput, colors),
			printGroupedStatusCell(f.BackendpoolStatus, params.RelationOutput, colors),
			renderOverallStatus(f.Status, colors))
	}

	tableTabWriter.Flush()

	if !params.Verbose {
		return nil
	}

	verboseTabWriter := tabwriter.NewWriter(out, minWidth, 0, padding, paddingChar, 0)

	fmt.Fprintln(out, "")

	fmt.Fprintln(verboseTabWriter, colors.Bold+"BGP Peers"+colors.Reset)
	fmt.Fprintln(verboseTabWriter, colors.Bold+"---------"+colors.Reset)
	for _, p := range lsm.Services[0].BGPPeerStatus.Peers {
		fmt.Fprintf(verboseTabWriter, "%s(%s)\n", p.Name, statusTextFromBool(p.IsHealthy, colors))
	}
	fmt.Fprintln(verboseTabWriter)

	fmt.Fprintln(verboseTabWriter, colors.Bold+"HC T1->[T2|B]"+colors.Reset)
	fmt.Fprintln(verboseTabWriter, colors.Bold+"-------------"+colors.Reset)
	hcByFrom := hcsByFrom(lsm.Services[0].T1T2HCStatus.HealthChecks)
	for _, from := range sortedHCFroms(hcByFrom) {
		hc := hcByFrom[from]
		fmt.Fprintf(verboseTabWriter, "%s:", from)
		for _, h := range hc {
			fmt.Fprintf(verboseTabWriter, "\t%s(%s)\n", h.Endpoint, statusTextFromBool(h.IsHealthy, colors))
		}
	}
	fmt.Fprintln(verboseTabWriter)

	fmt.Fprintln(verboseTabWriter, colors.Bold+"HC T2->B"+colors.Reset)
	fmt.Fprintln(verboseTabWriter, colors.Bold+"--------"+colors.Reset)
	hcByFrom = hcsByFrom(lsm.Services[0].T2BackendHCStatus.HealthChecks)
	for _, from := range sortedHCFroms(hcByFrom) {
		hc := hcByFrom[from]
		fmt.Fprintf(verboseTabWriter, "%s:", from)
		for _, h := range hc {
			fmt.Fprintf(verboseTabWriter, "\t%s(%s)\n", h.Endpoint, statusTextFromBool(h.IsHealthy, colors))
		}
	}
	fmt.Fprintln(verboseTabWriter)

	verboseTabWriter.Flush()

	return nil
}

type LoadbalancerStatusModelSummary struct {
	NrOfT1Nodes  int `json:"nrOfT1Nodes"`
	NrOfT2Nodes  int `json:"nrOfT2Nodes"`
	NrOfServices int `json:"nrOfServices"`
	NrOfVIPs     int `json:"nrOfVips"`
}

type LoadbalancerStatusModelService struct {
	Namespace         string                               `json:"namespace"`
	Name              string                               `json:"name"`
	VIP               string                               `json:"vip"`
	Port              uint                                 `json:"port"`
	Type              string                               `json:"type"`
	DeploymentMode    string                               `json:"deploymentMode"`
	BGPPeerStatus     BGPPeerStatus                        `json:"bgpPeerStatus"`
	BGPRouteStatus    LoadbalancerStatusModelSimpleStatus  `json:"bgpRouteStatus"`
	T1NodeStatus      LoadbalancerStatusModelSimpleStatus  `json:"t1NodeStatus"`
	T1T2HCStatus      HealthChecksStatus                   `json:"t1t2HealthcheckStatus"`
	T2NodeStatus      LoadbalancerStatusModelSimpleStatus  `json:"t2NodeStatus"`
	T2BackendHCStatus HealthChecksStatus                   `json:"t2BackendHealthcheckStatus"`
	BackendpoolStatus LoadbalancerStatusModelGroupedStatus `json:"backendpoolStatus"`
	Status            string                               `json:"status"`
}

type LoadbalancerStatusModelSimpleStatus struct {
	Status string `json:"status"`
	OK     int    `json:"ok"`
	Total  int    `json:"total"`
}

type BGPPeer struct {
	Name      string `json:"name"` // ip-asn
	IsHealthy bool   `json:"healthy"`
}

type BGPPeerStatus struct {
	LoadbalancerStatusModelSimpleStatus

	Peers []BGPPeer `json:"peers"`
}

type LoadbalancerStatusModelGroupedStatus struct {
	Status string                                `json:"status"`
	Groups []LoadbalancerStatusModelSimpleStatus `json:"groups"`
}

type HCStatus struct {
	From      string `json:"from"`
	Endpoint  string `json:"endpoint"`
	IsHealthy bool   `json:"healthy"`
}

type HealthChecksStatus struct {
	LoadbalancerStatusModelSimpleStatus

	HealthChecks []HCStatus `json:"endpoints"`
}

func (lsm *LoadbalancerStatusModel) sort() {
	slices.SortFunc(lsm.Services, func(a, b LoadbalancerStatusModelService) int {
		return cmp.Or(
			cmp.Compare(a.Namespace, b.Namespace),
			cmp.Compare(a.Name, b.Name),
			cmp.Compare(a.VIP, b.VIP),
			cmp.Compare(a.Port, b.Port),
		)
	})

	for i := range lsm.Services {
		svc := &lsm.Services[i]

		slices.SortFunc(svc.BGPPeerStatus.Peers, func(a, b BGPPeer) int {
			return cmp.Or(
				cmp.Compare(a.Name, b.Name),
				compareBool(a.IsHealthy, b.IsHealthy),
			)
		})
		slices.SortFunc(svc.T1T2HCStatus.HealthChecks, compareHCStatuses)
		slices.SortFunc(svc.T2BackendHCStatus.HealthChecks, compareHCStatuses)
		slices.SortFunc(svc.BackendpoolStatus.Groups, func(a, b LoadbalancerStatusModelSimpleStatus) int {
			return cmp.Or(
				cmp.Compare(a.Status, b.Status),
				cmp.Compare(a.OK, b.OK),
				cmp.Compare(a.Total, b.Total),
			)
		})
	}
}

func compareHCStatuses(a, b HCStatus) int {
	return cmp.Or(
		cmp.Compare(a.From, b.From),
		cmp.Compare(a.Endpoint, b.Endpoint),
		compareBool(a.IsHealthy, b.IsHealthy),
	)
}

func compareBool(a, b bool) int {
	switch {
	case a == b:
		return 0
	case !a:
		return -1
	default:
		return 1
	}
}

func printSimpleStatusCell(status LoadbalancerStatusModelSimpleStatus, rel string, colors ansiPalette) string {
	return fmt.Sprintf("%s %s", statusText(status.Status, colors), relationText(status.Status, status.OK, status.Total, rel))
}

func printGroupedStatusCell(status LoadbalancerStatusModelGroupedStatus, rel string, colors ansiPalette) string {
	statusString := strings.Builder{}

	for _, g := range status.Groups {
		statusString.WriteString(relationText(status.Status, g.OK, g.Total, rel))
	}

	return fmt.Sprintf("%s %s", statusText(status.Status, colors), statusString.String())
}

func renderOverallStatus(status string, colors ansiPalette) string {
	switch status {
	case "ONLINE":
		return colors.Green + status + colors.Reset
	case "OFFLINE":
		return colors.Red + status + colors.Reset
	default:
		return colors.Default + status + colors.Reset
	}
}

func statusText(statusText string, colors ansiPalette) string {
	switch statusText {
	case "OK":
		return colors.Green + "OK " + colors.Reset
	case "DEG":
		return colors.Yellow + "DEG" + colors.Reset
	case "N/A":
		return colors.Yellow + "N/A" + colors.Reset
	}

	return colors.Default + statusText + colors.Reset
}

func statusTextFromBool(ok bool, colors ansiPalette) string {
	if ok {
		return colors.Green + "OK" + colors.Reset
	}

	return colors.Yellow + "DEG" + colors.Reset
}

func relationText(status string, ok, total int, relationOutput string) string {
	if status == "N/A" || status == "" {
		return ""
	}

	if relationOutput == RelationOutputPercentage {
		if total == 0 {
			return "[0%]"
		}
		return fmt.Sprintf("[%d%%]", ok*100/total)
	}

	return fmt.Sprintf("[%d/%d]", ok, total)
}

func hcsByFrom(hcs []HCStatus) map[string][]HCStatus {
	hcByFrom := map[string][]HCStatus{}

	for _, hc := range hcs {
		if _, ok := hcByFrom[hc.From]; !ok {
			hcByFrom[hc.From] = []HCStatus{}
		}
		hcByFrom[hc.From] = append(hcByFrom[hc.From], hc)
	}

	return hcByFrom
}

func sortedHCFroms(hcByFrom map[string][]HCStatus) []string {
	froms := make([]string, 0, len(hcByFrom))
	for from := range hcByFrom {
		froms = append(froms, from)
	}
	slices.Sort(froms)
	return froms
}
