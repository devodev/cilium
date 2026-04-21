//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package tests

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/enterprise/hooks/connectivity/deploy"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

func PodToPhantomService() check.Scenario {
	return &podToPhantomService{
		ScenarioBase: check.NewScenarioBase(),
	}
}

type podToPhantomService struct {
	check.ScenarioBase
}

func (s *podToPhantomService) Name() string {
	return "pod-to-phantom-service"
}

func (s *podToPhantomService) Run(ctx context.Context, t *check.Test) {
	var (
		i int

		ct  = t.Context()
		dst = deploy.MustGetEchoPodOtherNode(ct) // Used for flow validation
		idx = ct.Params().TestNamespaceIndex
	)

	for _, pod := range ct.ClientPods() {
		t.ForEachIPFamily(func(ipFam features.IPFamily) {
			target := check.HTTPEndpoint(fmt.Sprintf("phantom-service-%s", ipFam),
				"http://"+net.JoinHostPort(deploy.PhantomServiceAddress(ipFam, idx), strconv.FormatUint(deploy.PhantomServicePort, 10)))

			t.NewAction(s, fmt.Sprintf("curl-%s-%d", ipFam, i), &pod, target, ipFam).Run(func(a *check.Action) {
				a.ExecInPod(ctx, ct.CurlCommand(target, ipFam, true, nil))

				a.ValidateFlows(ctx, pod, a.GetEgressRequirements(check.FlowParameters{
					DNSRequired: false, AltDstIP: dst.Address(ipFam), AltDstPort: dst.Port()}))
				a.ValidateFlows(ctx, dst, a.GetIngressRequirements(check.FlowParameters{
					DNSRequired: false, AltDstIP: dst.Address(ipFam), AltDstPort: dst.Port()}))
			})
		})

		i++
	}
}
