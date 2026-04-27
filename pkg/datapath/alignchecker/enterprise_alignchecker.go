//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package alignchecker

import (
	"github.com/cilium/cilium/enterprise/pkg/maps/egressmapha"
	"github.com/cilium/cilium/enterprise/pkg/maps/encryptionpolicymap"
	"github.com/cilium/cilium/enterprise/pkg/maps/evpn"
	"github.com/cilium/cilium/enterprise/pkg/maps/extepspolicy"
	"github.com/cilium/cilium/enterprise/pkg/maps/privnet"
	vniMap "github.com/cilium/cilium/enterprise/pkg/maps/vni"
	"github.com/cilium/cilium/pkg/monitor"
)

func init() {
	for typ, str := range map[string][]any{
		"egress_gw_ha_ct_entry":        {egressmapha.EgressCtVal4{}},
		"egress_gw_ha_policy_key":      {egressmapha.EgressPolicyV2Key4{}},
		"egress_gw_ha_policy_entry_v2": {egressmapha.EgressPolicyV2Val4{}},
		"egress_gw_standalone_key":     {egressmapha.SEGWMapKey4{}},
		"egress_gw_standalone_entry":   {egressmapha.SEGWMapVal4{}},
		"endpoint_key":                 {extepspolicy.Key{}},
		"encryption_policy_key":        {encryptionpolicymap.EncryptionPolicyKey{}},
		"encryption_policy_entry":      {encryptionpolicymap.EncryptionPolicyVal{}},
		"privnet_fib_key":              {privnet.FIBKey{}},
		"privnet_fib_val":              {privnet.FIBVal{}},
		"privnet_pip_key":              {privnet.PIPKey{}},
		"privnet_pip_val":              {privnet.PIPVal{}},
		"privnet_device_key":           {privnet.DeviceKey{}},
		"privnet_device_val":           {privnet.DeviceVal{}},
		"privnet_subnet_key":           {privnet.SubnetKey{}},
		"privnet_subnet_val":           {privnet.SubnetVal{}},
		"privnet_cidr_identity_key":    {privnet.CIDRIdentityKey{}},
		"privnet_cidr_identity":        {privnet.CIDRIdentityVal{}},
		"privnet_arp_sender_key":       {privnet.ARPSenderKey{}},
		"privnet_arp_sender_val":       {privnet.ARPSenderVal{}},
		"vni_key":                      {vniMap.VNIKey{}},
		"vni_val":                      {vniMap.VNIVal{}},
		"evpn_fib_key":                 {evpn.FIBKey{}},
		"evpn_fib_val":                 {evpn.FIBVal{}},
	} {
		toCheck[typ] = append(toCheck[typ], str...)
	}

	toCheck["trace_notify"] = []any{monitor.EnterpriseTraceNotify{}}
	toCheck["drop_notify"] = []any{monitor.EnterpriseDropNotify{}}
	toCheck["policy_verdict_notify"] = []any{monitor.EnterprisePolicyVerdictNotify{}}

	for size, str := range map[string][]any{
		"__u32": {
			extepspolicy.Value{},
			privnet.CTMapsKey{},
			privnet.CTMapsValue{},
		},
	} {
		toCheckSizes[size] = append(toCheckSizes[size], str...)
	}
}
