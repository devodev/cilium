//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package status

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
)

const (
	Red    = "\033[31m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Green  = "\033[32m"
	Cyan   = "\033[36m"
	Reset  = "\033[0m"
)

const (
	fmtHighliteColor = Cyan
	fmtOkColor       = Green
	fmtInfoColor     = Blue
	fmtWarnColor     = Yellow
	fmtErrColor      = Red
)

func fmtHghlt[T ~string](s T) string {
	return fmtHighliteColor + string(s) + Reset
}
func fmtOk[T ~string](s T) string {
	return fmtOkColor + string(s) + Reset
}
func fmtInfo[T ~string](s T) string {
	return fmtInfoColor + string(s) + Reset
}
func fmtWrn[T ~string](s T) string {
	return fmtWarnColor + string(s) + Reset
}
func fmtErr[T ~string](s T) string {
	return fmtErrColor + string(s) + Reset
}

func FmtReset[T ~string](s T) string {
	return strings.NewReplacer(
		fmtHighliteColor, "",
		fmtOkColor, "",
		fmtInfoColor, "",
		fmtWarnColor, "",
		fmtErrColor, "",
		Reset, "",
	).Replace(string(s))
}

func ansiLen[T ~string](s T) int {
	return len([]rune(FmtReset(s)))
}

func fmtIndent(s string, indent int) string {
	sb := strings.Builder{}
	for line := range strings.Lines(s) {
		sb.WriteString(fmtPad(indent) + line)
	}
	return sb.String()
}

func fmtIndentTitle(title, s string, indent int) string {
	sb := strings.Builder{}
	sb.WriteString(title)
	doIndent := indent - ansiLen(title)
	if doIndent < 2 {
		// The title is too long for the indent. Start on the second line
		doIndent = indent
		sb.WriteString("\n")
	}
	for line := range strings.Lines(s) {
		sb.WriteString(fmtPad(doIndent) + line)
		doIndent = indent
	}
	return sb.String()
}

func fmtPad(pad int) string {
	return strings.Repeat(" ", max(pad, 0))
}

func sortWithPin[E cmp.Ordered](pin E) func(E, E) int {
	return func(a, b E) int {
		switch {
		case a == pin:
			return -1
		case b == pin:
			return 1
		default:
			return cmp.Compare(a, b)
		}
	}
}

func fmtWrapLineItems(items []string, width int) string {
	if len(items) == 0 {
		return "\n"
	}

	sb := &strings.Builder{}

	sb.WriteString(items[0])
	curLineLen := ansiLen(items[0])

	// group items in lines
	for _, item := range items[1:] {
		if curLineLen+2+ansiLen(item) > width {
			// The item length + padding would exceed the max len
			// Start a new line and add the item
			sb.WriteString("\n")
			sb.WriteString(item)
			curLineLen = ansiLen(item)
			continue
		}
		sb.WriteString("  ")
		sb.WriteString(item)
		curLineLen += 2 + ansiLen(item)
	}
	sb.WriteString("\n")
	return sb.String()
}

func fmtWrapLineItemsTitle(title string, items []string, indent int, width int) string {
	return fmtIndentTitle(title, fmtWrapLineItems(items, width-indent), indent)
}

func fmtBar(left, mid, right string, width int) string {
	sb := &strings.Builder{}

	halfWidth := width / 2
	leftPad := max(halfWidth-ansiLen(left)-ansiLen(mid)/2, 1)
	rightPad := max(width-leftPad-ansiLen(left)-ansiLen(mid)-ansiLen(right), 1)

	sb.WriteString(left)
	sb.WriteString(fmtPad(leftPad))
	sb.WriteString(mid)
	sb.WriteString(fmtPad(rightPad))
	sb.WriteString(right)
	sb.WriteString("\n")

	return sb.String()
}

func (s NodeStatus) nodeStatus() string {

	switch {
	case slices.ContainsFunc(s.Networks, func(net NetworkStatus) bool {
		return len(net.Errors) > 0
	}):
		return "Status  " + fmtErr("DEGRADED")
	case s.Mode == config.ModeBridge && len(s.ConnectedClusters) < 2:
		return "Status  " + fmtWrn("NOT CONNECTED")
	case len(s.Networks) == 0:
		return "Status  " + fmtInfo("READY")
	default:
		return "Status  " + fmtOk("OK")
	}
}

func (s NetworkStatus) formatSubnets(width int) string {
	if len(s.Subnets) == 0 {
		return "Subnets    " + fmtErr("No subnets defined for network") + "\n"
	}
	subnetStr := []string{}
	for _, subnet := range s.Subnets {
		if subnet.CIDRv4.IsValid() {
			subnetStr = append(subnetStr, subnet.CIDRv4.String())
		}
		if subnet.CIDRv6.IsValid() {
			subnetStr = append(subnetStr, subnet.CIDRv6.String())
		}
	}
	return fmtWrapLineItemsTitle("Subnets", subnetStr, 10, width)
}
func (s NetworkStatus) formatRoutes(width int) string {
	if len(s.Routes) == 0 {
		return "Routes    " + fmtInfo("No routes defined for network") + "\n"
	}
	routesStr := []string{}
	for _, route := range s.Routes {
		routesStr = append(routesStr, fmt.Sprintf("%s via %s", route.Destination.String(), route.Gateway.String()))
	}
	return fmtWrapLineItemsTitle("Routes", routesStr, 10, width)
}
