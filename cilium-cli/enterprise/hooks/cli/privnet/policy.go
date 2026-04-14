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
	"cmp"
	"embed"
	"net/netip"
)

//go:embed manifests/policies
var policyManifests embed.FS

const policyDir = "manifests/policies"

type PolicyParams struct {
	Manifest      string
	TestNamespace string

	SubjectName string
	Interface   string
	Network     string

	Port     uint16
	CIDRs    []string
	PeerName string

	ApplyOnINB bool
}

type PolicyOpt func(*PolicyParams)

func WithPolicyPort(port uint16) PolicyOpt {
	return func(p *PolicyParams) {
		p.Port = port
	}
}

func WithPolicyCIDRsForVM(vm VM) PolicyOpt {
	return func(p *PolicyParams) {
		p.CIDRs = append(p.CIDRs,
			netip.PrefixFrom(vm.NetIPv4, vm.NetIPv4.BitLen()).String(),
			netip.PrefixFrom(vm.NetIPv6, vm.NetIPv6.BitLen()).String(),
		)
	}
}

func WithPolicyPeer(vm VM) PolicyOpt {
	return func(p *PolicyParams) {
		p.PeerName = vm.Name.String()
	}
}

func (t *TestRun) PolicyFor(subject VM, manifest string, opts ...PolicyOpt) PolicyParams {
	p := PolicyParams{
		Manifest:      manifest,
		TestNamespace: t.params.TestNamespace,

		SubjectName: subject.Name.String(),
		Interface:   cmp.Or(subject.Interface, "any"),
		Network:     subject.NetName.String(),
	}
	if subject.Kind == VMKindExtern {
		p.ApplyOnINB = true
	}
	for _, opt := range opts {
		opt(&p)
	}
	return p
}
