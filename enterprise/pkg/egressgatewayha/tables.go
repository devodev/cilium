//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package egressgatewayha

import (
	"fmt"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"k8s.io/apimachinery/pkg/types"
)

var (
	AgentIndex = statedb.Index[AgentPolicyConfig, types.NamespacedName]{
		Name: "id",
		FromObject: func(s AgentPolicyConfig) index.KeySet {
			return index.NewKeySet(s.Key())
		},
		FromKey: func(key types.NamespacedName) index.Key {
			return index.Key(key.String())
		},
		FromString: index.FromString,
		Unique:     true,
	}
	// This is by matching endpoint IP.
	ByEndpointSourceIP = statedb.Index[AgentPolicyConfig, string]{
		Name: "source-ip",
		FromObject: func(s AgentPolicyConfig) index.KeySet {
			ks := []index.Key{}
			for _, ep := range s.matchedEndpoints {
				for _, ip := range ep.ips {
					ks = append(ks, index.Key(ip.String()))
				}
			}
			return index.NewKeySet(ks...)
		},
		FromKey: index.String,
	}
)

func (p AgentPolicyConfig) TableHeader() []string {
	return []string{"ID", "Endpoints", "Generation", "IsGateway", "Interface", "Ifindex", "EgressIPv4", "EgressIPv6", "Groups"}
}

func (p AgentPolicyConfig) TableRow() []string {
	eps := []string{}
	for _, ep := range p.matchedEndpoints {
		for _, ip := range ep.ips {
			eps = append(eps, ip.String())
		}
	}
	matched := fmt.Sprintf("%v", eps)
	ss := []string{}
	for _, status := range p.groupStatuses {
		gs := fmt.Sprintf("active=%v", status.activeGatewayIPs)
		if p.azAffinity != azAffinityDisabled {
			gs += fmt.Sprintf(",activeByAZ=%v", status.activeGatewayIPsByAZ)
		}
		gs += fmt.Sprintf(",healthy=%v", status.healthyGatewayIPs)
		if len(status.egressIPByGatewayIP) != 0 {
			gs += fmt.Sprintf(",byGateway=%v", status.egressIPByGatewayIP)
		}
		ss = append(ss, gs)
	}
	var (
		localNodeIsGateway   string
		ifaceName            string
		ifaceIndex           uint32
		egressIP4, egressIP6 string
	)

	if p.gatewayConfig != nil {
		localNodeIsGateway = fmt.Sprintf("%t", p.gatewayConfig.localNodeConfiguredAsGateway)
		ifaceName = p.gatewayConfig.ifaceName
		ifaceIndex = p.gatewayConfig.egressIfindex
		egressIP4 = p.gatewayConfig.egressIP4.String()
		egressIP6 = p.gatewayConfig.egressIP6.String()
	}
	return []string{
		strings.TrimPrefix(p.id.String(), "/"),
		matched,
		fmt.Sprintf("%d", p.generation),
		localNodeIsGateway,
		ifaceName,
		fmt.Sprintf("%d", ifaceIndex),
		egressIP4,
		egressIP6,
		fmt.Sprintf("%v", ss),
	}
}

func newAgentTables(db *statedb.DB) (statedb.RWTable[AgentPolicyConfig], error) {
	return statedb.NewTable(db, "policy-config", AgentIndex, ByEndpointSourceIP)
}
