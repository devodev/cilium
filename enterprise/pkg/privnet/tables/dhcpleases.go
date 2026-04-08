// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package tables

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"path"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"

	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/wal"
)

// DHCPLease represents a DHCP lease for a private network endpoint.
type DHCPLease struct {
	// Network is the private network name.
	Network NetworkName

	// EndpointID is the Cilium's numeric identifier of the endpoint.
	EndpointID uint16

	// MAC is the endpoint interface MAC address.
	MAC mac.MAC

	// IPv4 is the leased IPv4 address.
	IPv4 netip.Addr

	// ServerID is the DHCP server IPv4 address, if provided.
	ServerID netip.Addr

	// ObtainedAt is the time the lease was acquired.
	ObtainedAt time.Time

	// RenewAt is the time the lease should be renewed.
	RenewAt time.Time

	// ExpireAt is the lease expiration time.
	ExpireAt time.Time
}

var _ statedb.TableWritable = DHCPLease{}

func (l DHCPLease) TableHeader() []string {
	return []string{"Network", "EndpointID", "MAC", "IPv4", "ServerID", "ObtainedAt", "RenewAt", "ExpireAt"}
}

func (l DHCPLease) TableRow() []string {
	showTime := func(t time.Time) string {
		if t.IsZero() {
			return "<unknown>"
		}
		return t.UTC().Format(time.RFC3339)
	}
	return []string{
		string(l.Network),
		fmt.Sprintf("%d", l.EndpointID),
		l.MAC.String(),
		l.IPv4.String(),
		l.ServerID.String(),
		showTime(l.ObtainedAt),
		showTime(l.RenewAt),
		showTime(l.ExpireAt),
	}
}

// DHCPLeaseKey is <network>|<mac>.
type DHCPLeaseKey string

func (key DHCPLeaseKey) Key() index.Key {
	return index.String(string(key))
}

func newDHCPLeaseKey(network NetworkName, macAddr mac.MAC) DHCPLeaseKey {
	return DHCPLeaseKey(string(network) + indexDelimiter + macAddr.String())
}

// DHCPLeaseByNetworkMAC queries leases by network and MAC.
func DHCPLeaseByNetworkMAC(network NetworkName, macAddr mac.MAC) statedb.Query[DHCPLease] {
	return leasePrimaryIndex.Query(newDHCPLeaseKey(network, macAddr))
}

var (
	leasePrimaryIndex = statedb.Index[DHCPLease, DHCPLeaseKey]{
		Name: "network-mac",
		FromObject: func(obj DHCPLease) index.KeySet {
			return index.NewKeySet(newDHCPLeaseKey(obj.Network, obj.MAC).Key())
		},
		FromKey:    DHCPLeaseKey.Key,
		FromString: index.FromString,
		Unique:     true,
	}
)

// NewDHCPLeasesTable returns a StateDB table for DHCP leases.
func NewDHCPLeasesTable(db *statedb.DB) (statedb.RWTable[DHCPLease], error) {
	return statedb.NewTable(
		db,
		"privnet-dhcp-leases",
		leasePrimaryIndex,
	)
}

var DHCPLeasesCell = cell.Provide(
	NewDHCPLeaseWriter,
)

const DHCPLeasesWALFile = "privnet-dhcp-leases.wal"

// DHCPLeaseWriter wraps the DHCP lease table with WAL-backed persistence.
type DHCPLeaseWriter struct {
	log       *slog.Logger
	db        *statedb.DB
	leases    statedb.RWTable[DHCPLease]
	walWriter *wal.Writer[dhcpLeaseWALEntry]

	// walCount is the number of WAL entries written for deciding when to compact
	// the log. Protected by the leases table lock.
	walCount int
}

type dhcpLeaseWALEntry struct {
	Deleted bool
	Lease   DHCPLease
}

func (e dhcpLeaseWALEntry) MarshalBinary() ([]byte, error) {
	return json.Marshal(e)
}

func NewDHCPLeaseWriter(log *slog.Logger, db *statedb.DB, cfg *option.DaemonConfig, lc cell.Lifecycle) (*DHCPLeaseWriter, statedb.Table[DHCPLease], error) {
	table, err := NewDHCPLeasesTable(db)
	if err != nil {
		return nil, nil, err
	}
	leases := &DHCPLeaseWriter{log: log, db: db, leases: table}
	walPath := path.Join(cfg.StateDir, DHCPLeasesWALFile)

	lc.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			if err := leases.restore(db, walPath); err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					log.Warn("Failed to restore DHCP leases WAL. DHCP lease state will not be restored",
						logfields.File, walPath,
						logfields.Error, err,
					)
				}
			}
			walWriter, err := wal.NewWriter[dhcpLeaseWALEntry](walPath)
			if err != nil {
				return err
			}
			leases.walWriter = walWriter

			// Immediately compact the existing log to keep it short.
			walWriter.Compact(func(yield func(dhcpLeaseWALEntry) bool) {
				for lease := range table.All(db.ReadTxn()) {
					if !yield(dhcpLeaseWALEntry{Lease: lease}) {
						break
					}
				}
			})

			return nil
		},
		OnStop: func(cell.HookContext) error {
			if leases.walWriter == nil {
				return nil
			}
			return leases.walWriter.Close()
		},
	})

	return leases, table, nil
}

func (l *DHCPLeaseWriter) Table() statedb.Table[DHCPLease] {
	return l.leases
}

func (l *DHCPLeaseWriter) Insert(wtxn statedb.WriteTxn, lease DHCPLease) (old DHCPLease, hadOld bool, err error) {
	defer l.writeWALEntry(wtxn, dhcpLeaseWALEntry{Lease: lease})
	return l.leases.Insert(wtxn, lease)
}

func (l *DHCPLeaseWriter) Delete(wtxn statedb.WriteTxn, lease DHCPLease) (oldObj DHCPLease, hadOld bool, err error) {
	oldObj, _, hadOld = l.leases.Get(wtxn, DHCPLeaseByNetworkMAC(lease.Network, lease.MAC))
	if !hadOld {
		return
	}
	defer l.writeWALEntry(wtxn, dhcpLeaseWALEntry{Deleted: true, Lease: oldObj})
	return l.leases.Delete(wtxn, lease)
}

func (l *DHCPLeaseWriter) restore(db *statedb.DB, walPath string) error {
	entries, err := wal.Read(walPath, func(data []byte) (dhcpLeaseWALEntry, error) {
		var entry dhcpLeaseWALEntry
		return entry, json.Unmarshal(data, &entry)
	})
	if err != nil {
		return err
	}

	wtxn := db.WriteTxn(l.leases)
	defer wtxn.Commit()

	for entry, err := range entries {
		if err != nil {
			return err
		}
		lease := entry.Lease
		if entry.Deleted {
			if _, _, err := l.leases.Delete(wtxn, lease); err != nil {
				return err
			}
		} else {
			if _, _, err := l.leases.Insert(wtxn, lease); err != nil {
				return err
			}
		}
	}
	l.log.Info("Restored DHCP leases from disk", logfields.Count, l.leases.NumObjects(wtxn))
	return nil
}

// dhcpWALCompactThreshold is the number of WAL entries before the WAL is compacted.
// The entries written during compaction are not counted towards this.
const dhcpWALCompactThreshold = 1000

// writeWALEntry to the write-ahead log. Must be called after Insert/Delete on the table
// for this to be able to compact.
func (l *DHCPLeaseWriter) writeWALEntry(wtxn statedb.WriteTxn, entry dhcpLeaseWALEntry) {
	if l.walCount >= dhcpWALCompactThreshold {
		l.walWriter.Compact(func(yield func(dhcpLeaseWALEntry) bool) {
			for lease := range l.leases.All(wtxn) {
				if !yield(dhcpLeaseWALEntry{Lease: lease}) {
					break
				}
			}
		})
		l.walCount = 0
	} else {
		l.walCount++
		if err := l.walWriter.Write(entry); err != nil {
			// Writing to the WAL is best-effort. If we can't append due to e.g. disk being full
			// we continue regardless. The impact of this is that we might not correctly expire a lease
			// on restart and keep using a network IP that in principle is no longer valid.
			l.log.Warn("Failed to append DHCP leases WAL entry. Lease expiry may not be correctly processed on restart.", logfields.Error, err)
		}
	}
}

// WorkloadUsesDHCP returns true if the workload has DHCP enabled and the associated subnet has
// DHCP relaying configured.
func WorkloadUsesDHCP(txn statedb.ReadTxn, subnets statedb.Table[Subnet], lw *LocalWorkload) bool {
	if lw == nil {
		return false
	}
	subnet, _, found := subnets.Get(txn, SubnetsByNetworkAndName(
		NetworkName(lw.Interface.Network),
		lw.Subnet,
	))
	return found && lw.UsesDHCPv4 &&
		subnet.DHCP.Mode != iso_v1alpha1.PrivateNetworkDHCPModeNone
}
