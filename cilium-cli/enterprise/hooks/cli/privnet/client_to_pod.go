// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package privnet

import (
	"context"
	"fmt"
	"net/netip"

	corev1 "k8s.io/api/core/v1"

	"github.com/cilium/cilium/cilium-cli/utils/features"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type clientToPod struct {
	scenario

	src VM
	dst *corev1.Pod
}

func NewClientToPod(t *TestRun, src VM, dst *corev1.Pod) Scenario {
	name := fmt.Sprintf("curl-%s-to-pod-%s", src.Name, dst.Name)
	return &clientToPod{
		scenario: scenario{t: t, name: name},
		src:      src,
		dst:      dst,
	}
}

func (s *clientToPod) Run(ctx context.Context, exp Expectation, overrideIPFamilies ...features.IPFamily) {
	for family := range s.t.theFamilies(overrideIPFamilies...) {
		s.run(ctx, exp, family)
	}
}

func (s *clientToPod) run(ctx context.Context, exp Expectation, family features.IPFamily) {
	var dstIP netip.Addr
	for _, podIP := range s.dst.Status.PodIPs {
		ip := netip.MustParseAddr(podIP.IP)
		if ip.Is6() && family == features.IPFamilyV6 {
			dstIP = ip
		} else if ip.Is4() && family == features.IPFamilyV4 {
			dstIP = ip
		}
	}

	s.t.log.Info(fmt.Sprintf("🧐 Executing curl %s (%v) %s %s (%s:%d)", s.src.DescName(), s.src.IP(family), exp, s.dst.GetName(), dstIP, EchoServerPort))
	stdout, stderr, err := s.t.vmExec(ctx, s.src, curlCmd(netip.AddrPortFrom(dstIP, EchoServerPort).String()))

	exitCode, ok := extractExitCode(err)
	if !ok {
		s.fail(family, "failed with unexpected exec error: %s", err)
		return
	} else if exitCode != exp.ExitStatus {
		s.t.log.Debug("curl output",
			logfields.Stdout, stdout,
			logfields.Stderr, stderr,
		)
		s.fail(family, "unexpected curl exit code. got %d want %d", exitCode, exp.ExitStatus)
	}
}
