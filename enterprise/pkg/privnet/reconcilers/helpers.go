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
	"iter"
	"slices"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/enterprise/pkg/privnet/endpoints"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/enterprise/pkg/privnet/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/time"
)

// SettleTime is the time reconcilers wait before proceeding with the actual
// reconciliation, to batch work.
const SettleTime = 50 * time.Millisecond

// EndpointActivationManager allows reconcilers to mark privnet-enabled
// endpoints as active or inactive and subscribe to changes to the
// active or inactive status of an endpoint
type EndpointActivationManager struct {
	subscribers []endpointActivationSubscriber
}

func newEndpointActivationManager() *EndpointActivationManager {
	return &EndpointActivationManager{
		subscribers: []endpointActivationSubscriber{},
	}
}

type endpointActivationSubscriber interface {
	EndpointActivationChanged(endpoints.Endpoint)
}

// Subscribe is used to subscribe to changes to endpoint activation done via this manager.
// Must only be called at construction time.
func (e *EndpointActivationManager) Subscribe(subscriber endpointActivationSubscriber) {
	e.subscribers = append(e.subscribers, subscriber)
}

// SetActivatedAt sets the activatedAt timestamp of an endpoint and informs the subscribers
func (e *EndpointActivationManager) SetActivatedAt(ep endpoints.Endpoint, time time.Time) {
	ep.SetPropertyValue(types.PropertyPrivNetActivatedAt, endpoints.FormatActivatedAtProperty(time))
	ep.SyncEndpointHeaderFile() // ensure the new activatedAt timestamp is persisted on disk
	for _, subscriber := range e.subscribers {
		subscriber.EndpointActivationChanged(ep)
	}
}

// watchesTracker tracks the associations between each watch channel and the
// associated list of objects. The same channel may be associated with multiple
// objects, in case they all map to the same watch channel.
type watchesTracker[T comparable] map[<-chan struct{}][]T

func newWatchesTracker[T comparable]() watchesTracker[T] {
	return make(watchesTracker[T])
}

// Register registers a watch channel to object association.
func (tracker watchesTracker[T]) Register(watch <-chan struct{}, obj T) {
	if !slices.Contains(tracker[watch], obj) {
		tracker[watch] = append(tracker[watch], obj)
	}
}

// Iter returns an iterator over all objects matching one of the closed channels.
func (tracker watchesTracker[T]) Iter(closed []<-chan struct{}) iter.Seq[T] {
	return func(yield func(T) bool) {
		for _, watch := range closed {
			objs, found := tracker[watch]

			// The watch channel is not in our cache. This is expected if closed
			// includes other channels as well, such as initialization ones.
			if !found {
				continue
			}

			delete(tracker, watch)
			for _, obj := range objs {
				if !yield(obj) {
					return
				}
			}
		}
	}
}

// PropertyTracker simplifies the tracking of objects observed via statedb.Table[T].Changes,
// to detect if a property of interest changed, and retrieve its previous value.
// Specifically, this is useful to allow triggering a downstream reconciliation
// based both on the previous and the current value, even if the property is not
// part of the primary key, and a change therefore happens in place.
type PropertyTracker[T any, K, V comparable] struct {
	m      map[K]V
	keyer  func(T) K
	valuer func(T) V
}

func NewPropertyTracker[T any, K, V comparable](keyer func(T) K, valuer func(T) V) *PropertyTracker[T, K, V] {
	return &PropertyTracker[T, K, V]{
		m:      make(map[K]V),
		keyer:  keyer,
		valuer: valuer,
	}
}

// Track updates the internal state according to the provided change, and returns
// the previous value associated with the given object, and whether the new value
// is different; changed is always false if no previous value existed.
func (tracker *PropertyTracker[T, K, V]) Track(change statedb.Change[T]) (prev V, changed bool) {
	var (
		key = tracker.keyer(change.Object)
		val = tracker.valuer(change.Object)
	)

	prev, ok := tracker.m[key]

	if change.Deleted {
		delete(tracker.m, key)
	} else {
		tracker.m[key] = val
	}

	return prev, ok && prev != val
}

// NewNodeAttachmentsNetworkTracker constructs a [PropertyTracker] to track the
// network associated with a given [tables.NodeAttachment] instance.
func NewNodeAttachmentsNetworkTracker() *PropertyTracker[*tables.NodeAttachment, tables.NodeAttachmentPrimaryKey, tables.NetworkName] {
	return NewPropertyTracker(
		(*tables.NodeAttachment).Key,
		func(na *tables.NodeAttachment) tables.NetworkName { return na.Network },
	)
}

func NewWaitUntilReconciledFn[T any](db *statedb.DB, tbl statedb.Table[T], getStatus func(T) reconciler.Status) hive.WaitFunc {
	return func(ctx context.Context) error {
		// Wait until the table has been initialized.
		_, initDone := tbl.Initialized(db.ReadTxn())
		select {
		case <-initDone:
		case <-ctx.Done():
			return ctx.Err()
		}

		// Wait until no entries are in pending state.
		// TODO: replace with [Reconciler.WaitUntilReconciled].
		for {
			entries, watch := tbl.AllWatch(db.ReadTxn())

			ready := true
			for entry := range entries {
				if getStatus(entry).Kind == reconciler.StatusKindPending {
					ready = false
					break
				}
			}

			if ready {
				return nil
			}

			// Poor man's rate limiting, just to avoid waking up for all changes.
			select {
			case <-time.After(SettleTime):
			case <-ctx.Done():
				return ctx.Err()
			}

			select {
			case <-watch:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}
