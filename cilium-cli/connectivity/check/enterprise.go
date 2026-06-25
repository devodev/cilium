// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"fmt"
	"net"
	"strconv"

	"github.com/cilium/cilium/cilium-cli/utils/features"
)

func (ct *ConnectivityTest) CurlCommandParallelWithOutput(peer TestPeer, ipFam features.IPFamily, parallel int, opts ...string) []string {
	cmd := []string{
		"curl", "--silent", "--fail", "--show-error",
		"--parallel", "--parallel-immediate", "--parallel-max", fmt.Sprint(parallel),
	}

	if connectTimeout := ct.params.ConnectTimeout.Seconds(); connectTimeout > 0.0 {
		cmd = append(cmd, "--connect-timeout", strconv.FormatFloat(connectTimeout, 'f', -1, 64))
	}
	if requestTimeout := ct.params.RequestTimeout.Seconds(); requestTimeout > 0.0 {
		cmd = append(cmd, "--max-time", strconv.FormatFloat(requestTimeout, 'f', -1, 64))
	}

	cmd = append(cmd, opts...)
	url := fmt.Sprintf("%s://%s%s",
		peer.Scheme(),
		net.JoinHostPort(peer.Address(ipFam), fmt.Sprint(peer.Port())),
		peer.Path())

	for range parallel {
		cmd = append(cmd, url)
	}

	return cmd
}

// SetFRRPods records FRR pods deployed by enterprise connectivity hooks.
func (ct *ConnectivityTest) SetFRRPods(pods []Pod) {
	ct.frrPods = pods
}
