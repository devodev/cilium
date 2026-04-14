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
)

type Expectation struct {
	ExitStatus int
}

var ExpectationOK = Expectation{
	ExitStatus: 0,
}

var ExpectationCurlTimeout = Expectation{
	ExitStatus: 28,
}

func (e Expectation) String() string {
	if e.ExitStatus != 0 {
		return "🚫"
	}
	return "➡️"
}

type options struct {
	network NetworkName
}

func renderOptions(opts ...opt) options {
	var options options

	for _, opt := range opts {
		opt(&options)
	}

	return options
}

type opt func(*options)

func WithNetworkOverride(network NetworkName) opt {
	return func(o *options) { o.network = network }
}

type Scenario interface {
	Name() string
	Run(ctx context.Context, exp Expectation, overrideIPFamilies ...features.IPFamily)
	Failed() bool
}

type scenario struct {
	t *TestRun

	name   string
	failed bool
}

func (s *scenario) Name() string {
	return s.name
}

func (s *scenario) Failed() bool {
	return s.failed
}

func (s *scenario) fail(family features.IPFamily, msg string, args ...any) {
	s.t.log.Error(fmt.Sprintf("Test scenario %q (%s) failed: %s", s.name, family, fmt.Sprintf(msg, args...)))
	s.failed = true
}
