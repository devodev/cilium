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

	"github.com/cilium/cilium/cilium-cli/utils/features"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type clientToWorld struct {
	scenario

	src VM
	dst string
}

func NewClientToWorld(t *TestRun, src VM, dst string) Scenario {
	name := fmt.Sprintf("curl-%s-to-world", src.Name)
	return &clientToWorld{
		scenario: scenario{t: t, name: name},
		src:      src,
		dst:      dst,
	}
}

func (s *clientToWorld) Run(ctx context.Context, exp Expectation, overrideIPFamilies ...features.IPFamily) {
	for family := range s.t.theFamilies(overrideIPFamilies...) {
		s.run(ctx, exp, family)
	}
}

func (s *clientToWorld) run(ctx context.Context, exp Expectation, family features.IPFamily) {
	s.t.log.Info(fmt.Sprintf("🧐 Executing curl %s (%v) %s %s", s.src.DescName(), s.src.IP(family), exp, s.dst))
	stdout, stderr, err := s.t.vmExec(ctx, s.src, curlCmd(s.dst))

	exitCode, ok := extractExitCode(err)
	if !ok {
		s.fail(features.IPFamilyAny, "failed with unexpected exec error: %s", err)
		return
	} else if exitCode != exp.ExitStatus {
		s.t.log.Debug("curl output",
			logfields.Stdout, stdout,
			logfields.Stderr, stderr,
		)
		s.fail(features.IPFamilyAny, "unexpected curl exit code. got %d want %d", exitCode, exp.ExitStatus)
	}
}
