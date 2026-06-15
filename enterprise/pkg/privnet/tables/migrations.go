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
	"slices"
	"strconv"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"

	"github.com/cilium/cilium/pkg/time"
)

// MigrationKey is the stable identity of a migration session.
type MigrationKey struct {
	Namespace string
	PodName   string
	MAC       string
}

func (k MigrationKey) String() string {
	return k.Namespace + indexDelimiter +
		k.PodName + indexDelimiter + k.MAC
}

func (k MigrationKey) Key() index.Key {
	return index.String(k.String())
}

type MigrationState string

const (
	// MigrationStateNew is the initial state when the migration has been created
	// from the local pod object.
	MigrationStateNew MigrationState = "New"

	// MigrationStateStarting is set when the migration of the data is being
	// started.
	MigrationStateStarting MigrationState = "Starting"

	// MigrationStateStarted is set when the migration of data has started.
	MigrationStateStarted MigrationState = "Started"

	// MigrationStateFinalizing is set when the VM has been resumed on the target
	// node and the final state has been requested, but not yet processed.
	MigrationStateFinalizing MigrationState = "Finalizing"

	// MigrationStateDone is set when the migration completed successfully.
	// Terminal state.
	MigrationStateDone MigrationState = "Done"

	// MigrationStateError is set when the migration failed. See [Migration.Error]
	// for details. Terminal state.
	MigrationStateError MigrationState = "Error"
)

var terminalMigrationStates = []MigrationState{
	MigrationStateDone,
	MigrationStateError,
}

// IsTerminal returns true if the state is a terminal state. Migrations that reach
// a terminal state are garbage collected after a wait period since last update is
// exceeded.
func (s MigrationState) IsTerminal() bool {
	return slices.Contains(terminalMigrationStates, s)
}

// Migration tracks the state of a live migration of a KubeVirt virtual machine
// to facilitate transfer of state from old node to the new node.
//
// Migration is derived from the local pod table and then picked up by the
// migration reconciler.
type Migration struct {
	MigrationKey

	// LocalWorkload is the local workload associated with this migration. This
	// is set when the migration object is created but it is not updated when it
	// changes.
	LocalWorkload *LocalWorkload

	// SourceNode is the node on which the VM used to run.
	SourceNode NodeName

	// Resumed is set to true when the VM has been resumed on the target node
	// and we can finalize the migration. This is derived from the KubeVirt node
	// name label which is set to the target node when the VM has been resumed.
	Resumed bool

	// State is the current state of the migration. If [Error] is set
	// we failed in this state and may be retrying.
	State MigrationState

	// Error if non-nil captures any error occurred while in [State].
	Error error

	// CreatedAt is the time at which this object was created.
	CreatedAt time.Time

	// UpdatedAt is the time at which this object was last updated.
	UpdatedAt time.Time
}

var _ statedb.TableWritable = Migration{}

func (s Migration) TableHeader() []string {
	return []string{
		"Namespace",
		"PodName",
		"MAC",
		"SourceNode",
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
		s.Namespace,
		s.PodName,
		s.MAC,
		string(s.SourceNode),
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
		s.State != MigrationStateFinalizing
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
