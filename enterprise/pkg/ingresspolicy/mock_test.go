//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package ingresspolicy

import (
	"context"

	cilium "github.com/cilium/proxy/go/cilium/api"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/endpoint"
	"github.com/cilium/cilium/pkg/revert"
)

var _ envoy.XDSServer = &mockXDSServer{}

type mockXDSServer struct {
	nrOfDeletions int
	nrOfUpdates   int
	nrOfUpserts   int

	policies map[string]*policy.EndpointPolicy
}

func newMockXdsServer() *mockXDSServer {
	return &mockXDSServer{
		policies: map[string]*policy.EndpointPolicy{},
	}
}

func (r *mockXDSServer) Reset() {
	r.nrOfUpdates = 0
	r.nrOfUpserts = 0
	r.nrOfDeletions = 0
}

func (r *mockXDSServer) UpdateEnvoyResources(ctx context.Context, old xds.Resources, new xds.Resources, _ *completion.WaitGroup) error {
	r.nrOfUpdates++
	return nil
}

func (r *mockXDSServer) DeleteEnvoyResources(ctx context.Context, resources xds.Resources, _ *completion.WaitGroup) error {
	r.nrOfDeletions++
	return nil
}

func (r *mockXDSServer) UpsertEnvoyResources(ctx context.Context, resources xds.Resources, _ *completion.WaitGroup) error {
	r.nrOfUpserts++
	return nil
}

func (*mockXDSServer) AddListener(ctx context.Context, name string, kind policy.L7ParserType, port uint16, isIngress bool, mayUseOriginalSourceAddr bool, wg *completion.WaitGroup, cb func(err error)) error {
	panic("unimplemented")
}

func (*mockXDSServer) AddAdminListener(ctx context.Context, port uint16, wg *completion.WaitGroup) {
	panic("unimplemented")
}

func (*mockXDSServer) AddMetricsListener(ctx context.Context, port uint16, wg *completion.WaitGroup) {
	panic("unimplemented")
}

func (*mockXDSServer) GetNetworkPolicies(resourceNames []string) (map[string]*cilium.NetworkPolicy, error) {
	panic("unimplemented")
}

func (s *mockXDSServer) RemoveAllNetworkPolicies() {
	panic("unimplemented")
}

func (s *mockXDSServer) RemoveListener(ctx context.Context, name string, wg *completion.WaitGroup) xds.AckingResourceMutatorRevertFunc {
	panic("unimplemented")
}

func (s *mockXDSServer) RemoveNetworkPolicy(ctx context.Context, ep endpoint.EndpointInfoSource) {
	s.nrOfDeletions++
	delete(s.policies, ep.GetPolicyNames()[0])
}

func (s *mockXDSServer) UpdateNetworkPolicy(ctx context.Context, ep endpoint.EndpointUpdater, policy *policy.EndpointPolicy, wg *completion.WaitGroup) (error, revert.RevertFunc, revert.FinalizeFunc) {
	s.nrOfUpdates++
	s.policies[ep.GetPolicyNames()[0]] = policy
	return nil, func() error { return nil }, nil
}

func (*mockXDSServer) UseCurrentNetworkPolicy(ep endpoint.EndpointUpdater, policy *policy.EndpointPolicy, wg *completion.WaitGroup) {
	panic("unimplemented")
}

func (*mockXDSServer) GetPolicySecretSyncNamespace() string {
	panic("unimplemented")
}

func (*mockXDSServer) SetPolicySecretSyncNamespace(string) {
	panic("unimplemented")
}
