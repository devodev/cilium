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
	"net/netip"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"
)

// MigrationPIPRewrite represent an ongoing PIP rewrite task
type MigrationPIPRewrite struct {
	MapEntry MapEntryKey

	Endpoint Source

	OldPIP netip.Addr
	NewPIP netip.Addr

	Status reconciler.Status
}

var _ statedb.TableWritable = MigrationPIPRewrite{}

func (m MigrationPIPRewrite) TableHeader() []string {
	return []string{"Endpoint", "OldPIP", "NewPIP", "Status"}
}

func (m MigrationPIPRewrite) TableRow() []string {
	return []string{
		m.Endpoint.String(),
		m.OldPIP.String(),
		m.NewPIP.String(),
		m.Status.String(),
	}
}

func (m MigrationPIPRewrite) Clone() MigrationPIPRewrite   { return m }
func (m MigrationPIPRewrite) GetStatus() reconciler.Status { return m.Status }
func (m MigrationPIPRewrite) SetStatus(status reconciler.Status) MigrationPIPRewrite {
	m.Status = status
	return m
}

type MigrationPIPRewriteKey string

func (m MigrationPIPRewriteKey) Key() index.Key {
	return index.String(string(m))
}

func newMigrationPIPRewriteKey(entry MapEntryKey, oldPIP netip.Addr) MigrationPIPRewriteKey {
	return MigrationPIPRewriteKey(string(entry) + indexDelimiter + oldPIP.String())
}

func newMigrationPIPRewriteKeyFromEntry(entry MapEntryKey) MigrationPIPRewriteKey {
	return MigrationPIPRewriteKey(string(entry) + indexDelimiter)
}

var (
	migrationPIPRewritePrimaryIndex = statedb.Index[MigrationPIPRewrite, MigrationPIPRewriteKey]{
		Name: "key",
		FromObject: func(obj MigrationPIPRewrite) index.KeySet {
			return index.NewKeySet(newMigrationPIPRewriteKey(obj.MapEntry, obj.OldPIP).Key())
		},
		FromKey:    MigrationPIPRewriteKey.Key,
		FromString: index.FromString,
		Unique:     true,
	}
)

func MigrationPIPRewriteByMapEntry(entry MapEntryKey) statedb.Query[MigrationPIPRewrite] {
	return migrationPIPRewritePrimaryIndex.Query(newMigrationPIPRewriteKeyFromEntry(entry))
}

func NewMigrationPIPRewriteTable(db *statedb.DB) (statedb.RWTable[MigrationPIPRewrite], error) {
	return statedb.NewTable(
		db,
		"privnet-migration-pip-rewrite",
		migrationPIPRewritePrimaryIndex,
	)
}
