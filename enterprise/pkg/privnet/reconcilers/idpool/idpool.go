// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package idpool

import (
	"errors"
	"io/fs"
	"iter"
	"log/slog"
	"math/rand/v2"
	"path"

	jsoniter "github.com/json-iterator/go"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/wal"
)

// The null ID is always reserved
const IDReserved = 0

// IDPool handles the allocation of IDs for private networks.
type IDPool[N comparable, I ~uint16] struct {
	mu          lock.Mutex
	next, max   I
	allocations map[N]idAllocation[I]
	used        map[I]N

	log       *slog.Logger
	walWriter *wal.Writer[allocationWALEntry[N, I]]
}

type idAllocation[I ~uint16] struct {
	id I
	// restored is true for entries that have been restored from disk and have
	// not been acquired again.
	restored bool
}

// NewIDPool creates and returns a new ID pool with custom settings.
func NewIDPool[N comparable, I ~uint16](log *slog.Logger, first, max I) *IDPool[N, I] {
	return &IDPool[N, I]{
		log:  log,
		mu:   lock.Mutex{},
		next: first,
		max:  max,
		allocations: map[N]idAllocation[I]{
			*new(N): {
				id: IDReserved,
			},
		},
		used: map[I]N{
			IDReserved: *new(N),
		},
	}
}

// Randomize configures whether the network and subnet ID pools use a random initial
// value, to make sure that we don't incorrectly rely on the fact that the IDs
// are consistent across nodes. Randomization is enabled by default, and can be
// disabled for testing purposes, e.g., through an init function.
var Randomize = true

type NetworkIDPool = IDPool[tables.NetworkName, tables.NetworkID]

func NewPrivnetIDPool(log *slog.Logger, cfg *option.DaemonConfig, lc cell.Lifecycle) *NetworkIDPool {
	var first tables.NetworkID
	if Randomize {
		first = tables.NetworkID(rand.Uint64N(uint64(tables.NetworkIDMax)) + 1)
	}

	pool := NewIDPool[tables.NetworkName, tables.NetworkID](log, first, tables.NetworkIDMax)
	lc.Append(
		cell.Hook{
			OnStart: func(ctx cell.HookContext) error {
				filePath := path.Join(cfg.StateDir, PrivnetIDWALFile)

				err := pool.restore(filePath)
				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						log.Debug("No IDPool WAL found. " +
							"Local Network IDs will not be restored. This might be expected",
						)
					} else {
						log.Warn("Cannot read IDPool WAL."+
							"Local Network IDs will not be restored.",
							logfields.Error, err,
						)
					}
				}

				walw, err := wal.NewWriter[allocationWALEntry[tables.NetworkName, tables.NetworkID]](filePath)
				if err != nil {
					log.Warn("Failed to setup IDPool WAL writer."+
						"Local Network IDs will not be preserved.",
						logfields.Error, err,
					)
				}
				pool.walWriter = walw

				return nil
			},
		},
	)
	return pool
}

type SubnetIDPool = IDPool[tables.SubnetName, tables.SubnetID]

func NewSubnetIDPool(log *slog.Logger) *SubnetIDPool {
	var first tables.SubnetID
	if Randomize {
		first = tables.SubnetID(rand.Uint64N(uint64(tables.SubnetIDMax)) + 1)
	}

	return NewIDPool[tables.SubnetName, tables.SubnetID](log, first, tables.SubnetIDMax)
}

// Acquire returns a network ID for the provided network name. If a network ID
// was already allocated for the provided network name, the previously
// allocated ID will be returned. acquire will return an error if the ID pool
// was exhausted.
func (idp *IDPool[N, I]) Acquire(name N) (I, error) {
	idp.mu.Lock()
	defer idp.mu.Unlock()

	alloc, ok := idp.allocations[name]
	if ok {
		alloc.restored = false
		idp.allocations[name] = alloc
		return alloc.id, nil
	}

	if len(idp.used) == int(idp.max)+1 {
		return IDReserved, errors.New("ID pool exhausted")
	}

	advance := func(cur I) (next I) {
		return I((uint64(cur) + 1) % (uint64(idp.max) + 1))
	}

	cur := idp.next
	_, allocated := idp.used[cur]
	for allocated {
		cur = advance(cur)
		_, allocated = idp.used[cur]
	}

	idp.used[cur] = name
	idp.allocations[name] = idAllocation[I]{
		id: cur,
	}

	err := idp.walWrite(allocationWALEntry[N, I]{
		ID:   cur,
		Name: name,
	})
	if err != nil {
		idp.log.Warn("Failed to write IDPool WAL."+
			"Local Network IDs might not be preserved",
			logfields.Error, err,
		)
	}

	idp.next = advance(cur)

	return cur, nil
}

// Release will free the provided network ID if it was allocated before.
func (idp *IDPool[N, I]) Release(id I) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	// Cannot release the reserved network ID.
	if id != IDReserved {
		name := idp.used[id]
		delete(idp.allocations, name)
		delete(idp.used, id)

		err := idp.walCompact()
		if err != nil {
			idp.log.Warn("Failed to write IDPool WAL."+
				"Local Network IDs might not be preserved",
				logfields.Error, err,
			)
		}
	}
}

// Allocated returns the number of active allocations
func (idp *IDPool[N, I]) Allocated() int {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	return len(idp.allocations) - 1 // don't count the reserved ID as an allocation
}

// allocationWALEntry is the representation of a single alloction on disk
// STABLE API - make sure not to break backwards compatibility
type allocationWALEntry[N comparable, I ~uint16] struct {
	ID   I
	Name N
}

func (ae allocationWALEntry[N, I]) MarshalBinary() (data []byte, err error) {
	return jsoniter.Marshal(ae)
}

const PrivnetIDWALFile = "privnet-net-ids.wal"

func (idp *IDPool[N, I]) walWrite(e allocationWALEntry[N, I]) error {
	if idp.walWriter == nil {
		return nil
	}
	return idp.walWriter.Write(e)
}

func (idp *IDPool[N, I]) walCompact() error {
	if idp.walWriter == nil {
		return nil
	}
	return idp.walWriter.Compact(idp.allWALEntries())
}

func (idp *IDPool[N, I]) allWALEntries() iter.Seq[allocationWALEntry[N, I]] {
	return func(yield func(allocationWALEntry[N, I]) bool) {
		for name, alloc := range idp.allocations {
			if !yield(allocationWALEntry[N, I]{
				ID:   alloc.id,
				Name: name,
			}) {
				return
			}
		}
	}
}

// restores the checkpoint file content - clearing any in-memory state.
func (idp *IDPool[N, I]) restore(path string) error {
	allocations, err := wal.Read(path, func(data []byte) (allocationWALEntry[N, I], error) {
		var ae allocationWALEntry[N, I]
		err := jsoniter.Unmarshal(data, &ae)
		return ae, err
	})
	if err != nil {
		return err
	}

	for allocation, err := range allocations {
		if err != nil {
			return err
		}
		idp.allocations[allocation.Name] = idAllocation[I]{
			id:       allocation.ID,
			restored: allocation.ID != IDReserved,
		}
		idp.used[allocation.ID] = allocation.Name
	}

	return nil
}

// Initialized marks the IDPool as successfully restored and will free any IDs
// that have not been re-acquired. Should only be called once the IDPool has
// seen the "state of the world"
func (idp *IDPool[N, I]) Initialized() {
	idp.mu.Lock()
	defer idp.mu.Unlock()

	for net, allocation := range idp.allocations {
		if allocation.restored {
			delete(idp.allocations, net)
			delete(idp.used, allocation.id)
		}
	}
	err := idp.walCompact()
	if err != nil {
		idp.log.Warn("Failed to compact IDPool WAL."+
			"Local Network IDs might not be preserved",
			logfields.Error, err,
		)
	}
}
