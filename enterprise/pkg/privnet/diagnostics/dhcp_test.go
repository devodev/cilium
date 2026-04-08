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
	"net/netip"
	"testing"

	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	diagnostics "github.com/cilium/cilium/enterprise/pkg/diagnostics"
	pncfg "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/time"
)

func TestEvalActiveINBMissing(t *testing.T) {
	t.Run("healthy-active-inb", func(t *testing.T) {
		fixture := newDHCPDiagnosticsFixture(t, pncfg.Config{Enabled: true, Mode: pncfg.ModeBridge})
		fixture.insertSubnet(subnetWithDHCP("blue", "subnet-a", iso_v1alpha1.PrivateNetworkDHCPModeBroadcast))
		fixture.insertWorkload(localWorkload("blue", "subnet-a", 101))
		fixture.insertINB(inbForNetwork("blue", tables.INBRoleActive, tables.INBNodeStateHealthy, tables.INBNetworkStateConfirmed))

		msg, sev := fixture.checker.evalActiveINBMissing(&diagnostics.FakeEnvironment{})
		require.Equal(t, diagnostics.OK, sev)
		require.Contains(t, msg, "Healthy active INB available")
	})

	t.Run("missing-active-inb", func(t *testing.T) {
		fixture := newDHCPDiagnosticsFixture(t, pncfg.Config{Enabled: true, Mode: pncfg.ModeBridge})
		fixture.insertSubnet(subnetWithDHCP("blue", "subnet-a", iso_v1alpha1.PrivateNetworkDHCPModeBroadcast))
		fixture.insertWorkload(localWorkload("blue", "subnet-a", 101))

		msg, sev := fixture.checker.evalActiveINBMissing(&diagnostics.FakeEnvironment{})
		require.Equal(t, diagnostics.Major, sev)
		require.Contains(t, msg, "blue/subnet-a")
		require.Contains(t, msg, "visible INBs: none")
	})

	t.Run("active-inb-unhealthy", func(t *testing.T) {
		fixture := newDHCPDiagnosticsFixture(t, pncfg.Config{Enabled: true, Mode: pncfg.ModeBridge})
		fixture.insertSubnet(subnetWithDHCP("blue", "subnet-a", iso_v1alpha1.PrivateNetworkDHCPModeBroadcast))
		fixture.insertWorkload(localWorkload("blue", "subnet-a", 101))
		fixture.insertINB(inbForNetwork("blue", tables.INBRoleActive, tables.INBNodeStateUnhealthy, tables.INBNetworkStateUnknown))

		msg, sev := fixture.checker.evalActiveINBMissing(&diagnostics.FakeEnvironment{})
		require.Equal(t, diagnostics.Major, sev)
		require.Contains(t, msg, "role=Active health=Unhealthy/Unknown")
	})

	t.Run("local-access-does-not-require-inb", func(t *testing.T) {
		fixture := newDHCPDiagnosticsFixture(t, pncfg.Config{Enabled: true, Mode: pncfg.ModeLocalAccess})
		fixture.insertSubnet(subnetWithDHCP("blue", "subnet-a", iso_v1alpha1.PrivateNetworkDHCPModeBroadcast))
		fixture.insertWorkload(localWorkload("blue", "subnet-a", 101))

		msg, sev := fixture.checker.evalActiveINBMissing(&diagnostics.FakeEnvironment{})
		require.Equal(t, diagnostics.OK, sev)
		require.Contains(t, msg, "do not apply in local access mode")
	})

	t.Run("waiting-for-state-initialization", func(t *testing.T) {
		fixture := newDHCPDiagnosticsFixture(t, pncfg.Config{Enabled: true, Mode: pncfg.ModeBridge})
		registerInitializer(t, fixture.db, fixture.subnets, "subnets-initialized")
		registerInitializer(t, fixture.db, fixture.inbs, "inbs-initialized")

		msg, sev := fixture.checker.evalActiveINBMissing(&diagnostics.FakeEnvironment{})
		require.Equal(t, diagnostics.OK, sev)
		require.Contains(t, msg, "Waiting for initialization")
	})
}

func TestEvalLeasePending(t *testing.T) {
	now := time.Now()

	t.Run("below-threshold", func(t *testing.T) {
		fixture := newDHCPDiagnosticsFixture(t, pncfg.Config{})
		lw := localWorkload("blue", "subnet-a", 101)
		lw.ActivatedAt = now.Add(-30 * time.Second)
		fixture.insertSubnet(subnetWithDHCP("blue", "subnet-a", iso_v1alpha1.PrivateNetworkDHCPModeBroadcast))
		fixture.insertWorkload(lw)

		msg, sev := fixture.checker.evalLeasePending(&diagnostics.FakeEnvironment{FakeNow: now})
		require.Equal(t, diagnostics.OK, sev)
		require.Contains(t, msg, "acquired leases within 1m0s")
	})

	t.Run("pending-without-lease", func(t *testing.T) {
		fixture := newDHCPDiagnosticsFixture(t, pncfg.Config{})
		lw := localWorkload("blue", "subnet-a", 101)
		lw.ActivatedAt = now.Add(-2 * time.Minute)
		fixture.insertSubnet(subnetWithDHCP("blue", "subnet-a", iso_v1alpha1.PrivateNetworkDHCPModeBroadcast))
		fixture.insertWorkload(lw)

		msg, sev := fixture.checker.evalLeasePending(&diagnostics.FakeEnvironment{FakeNow: now})
		require.Equal(t, diagnostics.Minor, sev)
		require.Contains(t, msg, "blue/subnet-a endpoint 101 pending 2m0s")
	})

	t.Run("has-valid-lease", func(t *testing.T) {
		fixture := newDHCPDiagnosticsFixture(t, pncfg.Config{})
		lw := localWorkload("blue", "subnet-a", 101)
		lw.ActivatedAt = now.Add(-2 * time.Minute)
		fixture.insertSubnet(subnetWithDHCP("blue", "subnet-a", iso_v1alpha1.PrivateNetworkDHCPModeBroadcast))
		fixture.insertWorkload(lw)
		fixture.insertLease(leaseForWorkload("blue", lw, now.Add(5*time.Minute)))

		msg, sev := fixture.checker.evalLeasePending(&diagnostics.FakeEnvironment{FakeNow: now})
		require.Equal(t, diagnostics.OK, sev)
		require.Contains(t, msg, "acquired leases within 1m0s")
	})

	t.Run("non-dhcp-subnet", func(t *testing.T) {
		fixture := newDHCPDiagnosticsFixture(t, pncfg.Config{})
		lw := localWorkload("blue", "subnet-a", 101)
		lw.ActivatedAt = now.Add(-2 * time.Minute)
		fixture.insertSubnet(subnetWithDHCP("blue", "subnet-a", iso_v1alpha1.PrivateNetworkDHCPModeNone))
		fixture.insertWorkload(lw)

		msg, sev := fixture.checker.evalLeasePending(&diagnostics.FakeEnvironment{FakeNow: now})
		require.Equal(t, diagnostics.OK, sev)
		require.Contains(t, msg, "No DHCP-enabled local workloads")
	})

	t.Run("waiting-for-state-initialization", func(t *testing.T) {
		fixture := newDHCPDiagnosticsFixture(t, pncfg.Config{})
		registerInitializer(t, fixture.db, fixture.subnets, "subnets-initialized")
		registerInitializer(t, fixture.db, fixture.workloads, "local-workloads-initialized")

		msg, sev := fixture.checker.evalLeasePending(&diagnostics.FakeEnvironment{FakeNow: now})
		require.Equal(t, diagnostics.OK, sev)
		require.Contains(t, msg, "Waiting for initialization")
	})
}

type dhcpDiagnosticsFixture struct {
	db        *statedb.DB
	checker   *dhcpDiagnosticChecker
	subnets   statedb.RWTable[tables.Subnet]
	workloads statedb.RWTable[*tables.LocalWorkload]
	leases    statedb.RWTable[tables.DHCPLease]
	inbs      statedb.RWTable[tables.INB]
}

func newDHCPDiagnosticsFixture(t *testing.T, cfg pncfg.Config) dhcpDiagnosticsFixture {
	t.Helper()

	db := statedb.New()
	subnets, err := tables.NewSubnetTable(db)
	require.NoError(t, err)
	workload, err := tables.NewLocalWorkloadsTable(db)
	require.NoError(t, err)
	leases, err := tables.NewDHCPLeasesTable(db)
	require.NoError(t, err)
	inbs, err := tables.NewINBsTable(db)
	require.NoError(t, err)

	return dhcpDiagnosticsFixture{
		db: db,
		checker: newDHCPDiagnosticChecker(dhcpDiagnosticCheckerParams{
			Config:    cfg,
			DB:        db,
			Subnets:   subnets,
			Workloads: workload,
			Leases:    leases,
			INBs:      inbs,
		}),
		subnets:   subnets,
		workloads: workload,
		leases:    leases,
		inbs:      inbs,
	}
}

func (f dhcpDiagnosticsFixture) insertSubnet(subnet tables.Subnet) {
	wtxn := f.db.WriteTxn(f.subnets)
	f.subnets.Insert(wtxn, subnet)
	wtxn.Commit()
}

func (f dhcpDiagnosticsFixture) insertWorkload(lw *tables.LocalWorkload) {
	wtxn := f.db.WriteTxn(f.workloads)
	f.workloads.Insert(wtxn, lw)
	wtxn.Commit()
}

func (f dhcpDiagnosticsFixture) insertINB(inb tables.INB) {
	wtxn := f.db.WriteTxn(f.inbs)
	f.inbs.Insert(wtxn, inb)
	wtxn.Commit()
}

func (f dhcpDiagnosticsFixture) insertLease(lease tables.DHCPLease) {
	wtxn := f.db.WriteTxn(f.leases)
	f.leases.Insert(wtxn, lease)
	wtxn.Commit()
}

func registerInitializer[Obj any](t *testing.T, db *statedb.DB, table statedb.RWTable[Obj], name string) {
	t.Helper()

	wtxn := db.WriteTxn(table)
	table.RegisterInitializer(wtxn, name)
	wtxn.Commit()
}

func subnetWithDHCP(network tables.NetworkName, name tables.SubnetName, mode iso_v1alpha1.PrivateNetworkDHCPMode) tables.Subnet {
	subnet := tables.Subnet{
		SubnetSpec: tables.SubnetSpec{
			Network:       network,
			Name:          name,
			CIDRv4:        netip.MustParsePrefix("192.168.100.0/24"),
			EgressIfName:  "eth0",
			EgressIfIndex: 2,
		},
		DHCP: iso_v1alpha1.PrivateNetworkSubnetDHCPSpec{
			Mode: mode,
		},
	}
	if mode == iso_v1alpha1.PrivateNetworkDHCPModeRelay {
		subnet.DHCP.Relay = &iso_v1alpha1.PrivateNetworkDHCPRelaySpec{
			ServerAddress: "192.0.2.10:67",
		}
	}
	return subnet
}

func localWorkload(network tables.NetworkName, subnet tables.SubnetName, endpointID uint16) *tables.LocalWorkload {
	return &tables.LocalWorkload{
		EndpointID: endpointID,
		Subnet:     subnet,
		Interface: iso_v1alpha1.PrivateNetworkEndpointSliceInterface{
			Network: string(network),
			MAC:     "02:aa:bb:cc:dd:ee",
		},
		UsesDHCPv4: true,
	}
}

func leaseForWorkload(network tables.NetworkName, lw *tables.LocalWorkload, expireAt time.Time) tables.DHCPLease {
	hwAddr, err := mac.ParseMAC(lw.Interface.MAC)
	if err != nil {
		panic(err)
	}
	return tables.DHCPLease{
		Network:    network,
		EndpointID: lw.EndpointID,
		MAC:        hwAddr,
		ExpireAt:   expireAt,
	}
}

func inbForNetwork(network tables.NetworkName, role tables.INBRole, nodeState tables.INBNodeState, networkState tables.INBNetworkState) tables.INB {
	return tables.INB{
		Network: network,
		Node: tables.INBNode{
			Cluster: "cluster-a",
			Name:    "node-a",
			IP:      netip.MustParseAddr("192.0.2.10"),
		},
		Role: role,
		Health: tables.INBHealthState{
			Node:    nodeState,
			Network: networkState,
		},
	}
}
