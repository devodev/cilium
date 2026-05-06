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
	"strconv"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"

	"github.com/cilium/cilium/pkg/time"
)

// MigrationKey is the stable identity of a migration session.
type MigrationKey struct {
	Cluster   ClusterName
	Namespace string
	PodName   string
}

func (k MigrationKey) String() string {
	return string(k.Cluster) + indexDelimiter +
		k.Namespace + indexDelimiter +
		k.PodName
}

func (k MigrationKey) Key() index.Key {
	return index.String(k.String())
}

type MigrationState string

const (
	// MigrationStateNew is the initial state when the migration has been created
	// from the local pod object.
	MigrationStateNew MigrationState = "New"

	// MigrationStateWaitDeps is set when dependencies (private networks, workloads)
	// were not yet present and the reconciler is waiting for them to appear before
	// proceeding.
	MigrationStateWaitDeps MigrationState = "WaitDeps"

	// MigrationStateStarted is set when the migration of data has started.
	MigrationStateStarted MigrationState = "Started"

	// MigrationStateFinishing is set when the VM has been resumed on the target
	// node and the final state has been requested, but not yet processed.
	MigrationStateFinishing MigrationState = "Finishing"

	// MigrationStateDone is set when the migration completed successfully.
	// Terminal state.
	MigrationStateDone MigrationState = "Done"

	// MigrationStateError is set when the migration failed. See [Migration.Error]
	// for details. Terminal state.
	MigrationStateError MigrationState = "Error"
)

// IsTerminal returns true if the state is a terminal state. Migrations that reach
// a terminal state are garbage collected after a wait period since last update is
// exceeded.
func (s MigrationState) IsTerminal() bool {
	return s == MigrationStateDone || s == MigrationStateError
}

// Migration tracks the state of a live migration of a KubeVirt virtual machine
// to facilitate transfer of state from old node to the new node.
//
// Migration is derived from the local pod table and then picked up by the
// migration reconciler.
type Migration struct {
	MigrationKey

	VMIName    string
	SourceNode NodeName
	TargetNode NodeName

	Resumed bool
	State   MigrationState
	Error   error

	CreatedAt time.Time
	UpdatedAt time.Time
}

var _ statedb.TableWritable = Migration{}

func (s Migration) TableHeader() []string {
	return []string{
		"Cluster",
		"Namespace",
		"PodName",
		"SourceNode",
		"TargetNode",
		"Resumed",
		"State",
		"Error",
		"CreatedAt",
		"UpdatedAt",
	}
}

func (s Migration) TableRow() []string {
	var error string
	if s.Error != nil {
		error = s.Error.Error()
	}
	return []string{
		string(s.Cluster),
		s.Namespace,
		s.PodName,
		string(s.SourceNode),
		string(s.TargetNode),
		strconv.FormatBool(s.Resumed),
		string(s.State),
		error,
		formatActivatedAt(s.CreatedAt),
		formatActivatedAt(s.UpdatedAt),
	}
}

func (s Migration) Equal(other Migration) bool {
	return s == other
}

func (s *Migration) BlocksActivation() bool {
	// Migration blocks activation of the endpoint until the VM
	// is resuming and we've either finished migration or are in
	// the process of finishing it.
	return s != nil &&
		!s.State.IsTerminal() &&
		s.State != MigrationStateFinishing
}

var (
	migrationPrimaryIndex = statedb.Index[Migration, MigrationKey]{
		Name: "key",
		FromObject: func(obj Migration) index.KeySet {
			return index.NewKeySet(obj.MigrationKey.Key())
		},
		FromKey:    MigrationKey.Key,
		FromString: index.FromString,
		Unique:     true,
	}

	MigrationByKey = migrationPrimaryIndex.Query
)

func NewMigrationsTable(db *statedb.DB) (statedb.RWTable[Migration], error) {
	return statedb.NewTable(
		db,
		"privnet-migrations",
		migrationPrimaryIndex,
	)
}
