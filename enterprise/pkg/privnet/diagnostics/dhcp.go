//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package diagnostics

import (
	"fmt"
	"slices"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	diagnostics "github.com/cilium/cilium/enterprise/pkg/diagnostics"
	pncfg "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/time"
)

const (
	subsys                         = "Private Networks"
	dhcpLeasePendingSecondsKey     = "privnet_dhcp_lease_pending_seconds"
	defaultDHCPLeasePendingSeconds = 60.0
)

func registerDHCPDiagnosticConditions(reg *diagnostics.Registry, params dhcpDiagnosticCheckerParams) error {
	checker := newDHCPDiagnosticChecker(params)
	return reg.Register(
		diagnostics.Condition{
			ID:          "privnet_dhcp_active_inb_missing",
			SubSystem:   subsys,
			Description: "DHCP-enabled private network subnets do not have a healthy active INB.",
			Evaluator:   checker.evalActiveINBMissing,
		},
		diagnostics.Condition{
			ID:          "privnet_dhcp_lease_pending",
			SubSystem:   subsys,
			Description: "DHCP-enabled local workloads have not acquired a lease within the expected time.",
			Evaluator:   checker.evalLeasePending,
		},
	)
}

type dhcpDiagnosticChecker struct {
	cfg       pncfg.Config
	db        *statedb.DB
	subnets   statedb.Table[tables.Subnet]
	workloads statedb.Table[*tables.LocalWorkload]
	leases    statedb.Table[tables.DHCPLease]
	inbs      statedb.Table[tables.INB]
}

type dhcpDiagnosticCheckerParams struct {
	cell.In

	Config    pncfg.Config
	DB        *statedb.DB
	Subnets   statedb.Table[tables.Subnet]
	Workloads statedb.Table[*tables.LocalWorkload]
	Leases    statedb.Table[tables.DHCPLease]
	INBs      statedb.Table[tables.INB]
}

func newDHCPDiagnosticChecker(in dhcpDiagnosticCheckerParams) *dhcpDiagnosticChecker {
	return &dhcpDiagnosticChecker{
		cfg:       in.Config,
		db:        in.DB,
		subnets:   in.Subnets,
		workloads: in.Workloads,
		leases:    in.Leases,
		inbs:      in.INBs,
	}
}

func (c *dhcpDiagnosticChecker) evalActiveINBMissing(_ diagnostics.Environment) (string, diagnostics.Severity) {
	if c.cfg.EnabledAsLocalAccess() {
		return "DHCP active INB diagnostics do not apply in local access mode", diagnostics.OK
	}

	txn := c.db.ReadTxn()

	if !tablesInitialized(txn, c.subnets, c.inbs) {
		return "Waiting for initialization", diagnostics.OK
	}

	var failures []string
	for subnet := range c.subnets.All(txn) {
		if subnet.DHCP.Mode == iso_v1alpha1.PrivateNetworkDHCPModeNone {
			continue
		}
		if c.hasUsableActiveINB(txn, subnet.Network) {
			continue
		}
		failures = append(failures,
			fmt.Sprintf("%s/%s (visible INBs: %s)", subnet.Network, subnet.Name, c.describeINBs(txn, subnet.Network)))
	}

	if len(failures) > 0 {
		slices.Sort(failures)
		return "Missing healthy active INB for DHCP-enabled subnets: " + strings.Join(failures, "; "), diagnostics.Major
	}

	return "Healthy active INB available for DHCP-enabled subnet(s)", diagnostics.OK
}

func (c *dhcpDiagnosticChecker) evalLeasePending(env diagnostics.Environment) (string, diagnostics.Severity) {
	txn := c.db.ReadTxn()

	if !tablesInitialized(txn, c.subnets, c.workloads) {
		return "Waiting for initialization", diagnostics.OK
	}
	now := env.Now()
	threshold := time.Duration(env.UserConstant(dhcpLeasePendingSecondsKey, defaultDHCPLeasePendingSeconds) * float64(time.Second))

	var pending []string
	checked := 0
	for lw := range c.workloads.All(txn) {
		if !lw.UsesDHCPv4 {
			continue
		}
		subnet, _, found := c.subnets.Get(txn, tables.SubnetsByNetworkAndName(tables.NetworkName(lw.Interface.Network), lw.Subnet))
		if !found || subnet.DHCP.Mode == iso_v1alpha1.PrivateNetworkDHCPModeNone {
			continue
		}
		checked++
		if lw.ActivatedAt.IsZero() || now.Sub(lw.ActivatedAt) < threshold {
			continue
		}
		if c.hasUsableLease(txn, lw, now) {
			continue
		}

		pending = append(pending, fmt.Sprintf("%s/%s endpoint %d pending %s",
			subnet.Network,
			subnet.Name,
			lw.EndpointID,
			now.Sub(lw.ActivatedAt).Round(time.Second),
		))
	}
	slices.Sort(pending)

	if len(pending) > 0 {
		return fmt.Sprintf("DHCP lease acquisition delayed beyond %s: %s", threshold.Round(time.Second), strings.Join(pending, "; ")), diagnostics.Minor
	}
	if checked == 0 {
		return "No DHCP-enabled local workloads", diagnostics.OK
	}
	return fmt.Sprintf("All DHCP-enabled local workloads acquired leases within %s", threshold.Round(time.Second)), diagnostics.OK
}

func tablesInitialized(txn statedb.ReadTxn, tbls ...statedb.TableMeta) bool {
	for _, tbl := range tbls {
		initialized, _ := tbl.Initialized(txn)
		if !initialized {
			return false
		}
	}
	return true
}

func (c *dhcpDiagnosticChecker) hasUsableActiveINB(txn statedb.ReadTxn, network tables.NetworkName) bool {
	for inb := range c.inbs.List(txn, tables.INBsByNetworkAndRole(network, tables.INBRoleActive)) {
		if inb.Health.Node == tables.INBNodeStateHealthy && inb.Health.Network == tables.INBNetworkStateConfirmed {
			return true
		}
	}
	return false
}

func (c *dhcpDiagnosticChecker) describeINBs(txn statedb.ReadTxn, network tables.NetworkName) string {
	items := slices.Sorted(statedb.ToSeq(statedb.Map(
		c.inbs.Prefix(txn, tables.INBsByNetwork(network)),
		func(inb tables.INB) string {
			return fmt.Sprintf("%s role=%s health=%s/%s",
				inb.Node.String(),
				inb.Role.String(),
				inb.Health.Node.String(),
				inb.Health.Network.String(),
			)
		})))
	if len(items) == 0 {
		return "none"
	}
	return strings.Join(items, ", ")
}

func (c *dhcpDiagnosticChecker) hasUsableLease(txn statedb.ReadTxn, lw *tables.LocalWorkload, now time.Time) bool {
	if lw.Interface.Addressing.IPv4 != "" && lw.Interface.Addressing.IPv4 != "0.0.0.0" {
		return true
	}

	macAddr, err := mac.ParseMAC(lw.Interface.MAC)
	if err != nil {
		return false
	}
	lease, _, found := c.leases.Get(txn, tables.DHCPLeaseByNetworkMAC(tables.NetworkName(lw.Interface.Network), macAddr))
	if found {
		return lease.ExpireAt.IsZero() || lease.ExpireAt.After(now)
	}
	return false
}
