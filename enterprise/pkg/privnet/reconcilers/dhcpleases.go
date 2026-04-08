// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilers

import (
	"context"
	"log/slog"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/enterprise/pkg/privnet/dhcp"
	"github.com/cilium/cilium/enterprise/pkg/privnet/endpoints"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/time"
)

var DhcpLeasesCell = cell.Invoke(newDhcpLeaseReconciler)

const leaseSweepInterval = time.Minute

// dhcpLeaseReconciler watches local workloads and manages DHCP leases.
type dhcpLeaseReconciler struct {
	log           *slog.Logger
	db            *statedb.DB
	workloads     statedb.RWTable[*tables.LocalWorkload]
	leases        statedb.Table[tables.DHCPLease]
	leaseWriter   *tables.DHCPLeaseWriter
	endpoints     endpoints.EndpointGetter
	subnets       statedb.Table[tables.Subnet]
	sweepInterval time.Duration
}

type dhcpLeaseReconcilerParams struct {
	cell.In

	Log         *slog.Logger
	JobGroup    job.Group
	DB          *statedb.DB
	Workloads   statedb.RWTable[*tables.LocalWorkload]
	LeaseWriter *tables.DHCPLeaseWriter
	Endpoints   endpoints.EndpointGetter
	Subnets     statedb.Table[tables.Subnet]
	TestCfg     *dhcp.TestConfig `optional:"true"`
}

// newDhcpLeaseReconciler constructs a DHCP lease manager.
func newDhcpLeaseReconciler(in dhcpLeaseReconcilerParams) *dhcpLeaseReconciler {
	sweepInterval := leaseSweepInterval
	if in.TestCfg != nil && in.TestCfg.LeaseSweepInterval > 0 {
		sweepInterval = in.TestCfg.LeaseSweepInterval
	}

	m := &dhcpLeaseReconciler{
		log:           in.Log,
		db:            in.DB,
		workloads:     in.Workloads,
		leases:        in.LeaseWriter.Table(),
		leaseWriter:   in.LeaseWriter,
		endpoints:     in.Endpoints,
		subnets:       in.Subnets,
		sweepInterval: sweepInterval,
	}
	if in.JobGroup != nil {
		in.JobGroup.Add(job.OneShot("dhcp-lease-reconciler", m.run))
	}
	return m
}

// run watches workloads and leases and projects them into the local workload table.
func (m *dhcpLeaseReconciler) run(ctx context.Context, _ cell.Health) error {
	// Wait for subnets to reconcile as we rely on them in [workloadUsesDHCP]
	_, watch := m.subnets.Initialized(m.db.ReadTxn())
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-watch:
	}

	wtxn := m.db.WriteTxn(m.workloads, m.leases)
	workloadIter, _ := m.workloads.Changes(wtxn)
	leaseIter, _ := m.leases.Changes(wtxn)
	wtxn.Commit()

	sweep := time.NewTicker(m.sweepInterval)
	defer sweep.Stop()

	for {
		watchset := statedb.NewWatchSet()

		wtxn := m.db.WriteTxn(m.leases, m.workloads)
		workloadChanges, workloadWatch := workloadIter.Next(wtxn)
		leaseChanges, leaseWatch := leaseIter.Next(wtxn)
		watchset.Add(workloadWatch, leaseWatch)

		for change := range workloadChanges {
			if lw := change.Object; lw != nil && tables.WorkloadUsesDHCP(wtxn, m.subnets, lw) {
				if change.Deleted {
					m.dropWorkloadLeases(wtxn, lw)
					continue
				}
				m.syncWorkloadLease(wtxn, lw)
			}
		}

		for change := range leaseChanges {
			if change.Deleted {
				m.clearWorkloadLease(wtxn, change.Object)
				continue
			}
			m.syncLease(wtxn, change.Object)
		}
		wtxn.Commit()

		select {
		case <-ctx.Done():
			return nil
		case <-sweep.C:
			m.handleExpiredLeases()
		default:
			_, err := watchset.Wait(ctx, SettleTime)
			if err != nil {
				return nil
			}
		}
	}
}

func (m *dhcpLeaseReconciler) syncWorkloadLease(wtxn statedb.WriteTxn, lw *tables.LocalWorkload) {
	macAddr, err := mac.ParseMAC(lw.Interface.MAC)
	if err != nil {
		return
	}

	lease, _, found := m.leases.Get(wtxn, tables.DHCPLeaseByNetworkMAC(tables.NetworkName(lw.Interface.Network), macAddr))
	if !found {
		return
	}

	if m.maybeRemoveExpiredLease(wtxn, lease) {
		return
	}

	m.updateLocalWorkloadIP(wtxn, lease.EndpointID, lease.IPv4.String())
}

func (m *dhcpLeaseReconciler) dropWorkloadLeases(wtxn statedb.WriteTxn, lw *tables.LocalWorkload) {
	mac, err := mac.ParseMAC(lw.Interface.MAC)
	if err != nil {
		return
	}
	for lease := range m.leases.List(wtxn, tables.DHCPLeaseByNetworkMAC(tables.NetworkName(lw.Interface.Network), mac)) {
		m.leaseWriter.Delete(wtxn, lease)
	}
}

func (m *dhcpLeaseReconciler) syncLease(wtxn statedb.WriteTxn, lease tables.DHCPLease) {
	if m.maybeRemoveExpiredLease(wtxn, lease) {
		return
	}
	m.updateLocalWorkloadIP(wtxn, lease.EndpointID, lease.IPv4.String())
}

func (m *dhcpLeaseReconciler) handleExpiredLeases() {
	wtxn := m.db.WriteTxn(m.leases, m.workloads)
	for lease := range m.leases.All(wtxn) {
		m.maybeRemoveExpiredLease(wtxn, lease)
	}
	wtxn.Commit()
}

func (m *dhcpLeaseReconciler) maybeRemoveExpiredLease(wtxn statedb.WriteTxn, lease tables.DHCPLease) (deleted bool) {
	if !lease.ExpireAt.IsZero() && time.Now().After(lease.ExpireAt) {
		m.log.Debug("Removing expired lease and releasing network IP",
			logfields.EndpointID, lease.EndpointID,
			logfields.IPv4, lease.IPv4,
			logfields.MACAddr, lease.MAC,
			logfields.Expiration, lease.ExpireAt,
		)
		m.updateLocalWorkloadIP(wtxn, lease.EndpointID, zeroAddrString)
		m.leaseWriter.Delete(wtxn, lease)
		return true
	}
	return false
}

var zeroAddrString = netip.IPv4Unspecified().String()

func (m *dhcpLeaseReconciler) clearWorkloadLease(wtxn statedb.WriteTxn, lease tables.DHCPLease) {
	m.updateLocalWorkloadIP(wtxn, lease.EndpointID, zeroAddrString)
}

func (m *dhcpLeaseReconciler) updateLocalWorkloadIP(
	wtxn statedb.WriteTxn,
	endpointID uint16,
	ipv4 string,
) {
	lw, _, found := m.workloads.Get(wtxn, tables.LocalWorkloadsByID(endpointID))
	if !found {
		return
	}
	if !tables.WorkloadUsesDHCP(wtxn, m.subnets, lw) {
		return
	}
	if lw.Interface.Addressing.IPv4 == ipv4 {
		return
	}

	updated := *lw
	updated.Interface.Addressing.IPv4 = ipv4
	m.workloads.Insert(wtxn, &updated)

	// Update the ipv4 property in the endpoint and persist. This ensures that updates to endpoint
	// that propagate to LocalWorkload won't overwrite the IP and that the IP is persisted to disk
	// and restored on restart.
	if ep := m.endpoints.LookupID(endpointID); ep != nil {
		if value, _ := ep.GetPropertyValue(endpoints.PropertyPrivNetIPv4).(string); value != ipv4 {
			ep.SetPropertyValue(endpoints.PropertyPrivNetIPv4, ipv4)
			ep.SyncEndpointHeaderFile()
		}
	}
}
