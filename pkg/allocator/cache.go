// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package allocator

import (
	"context"
	"log/slog"
	"sync"

	"github.com/cilium/stream"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

// backendOpTimeout is the time allowed for operations sent to backends in
// response to events such as create/modify/delete.
const backendOpTimeout = 10 * time.Second

// idMap provides mapping from ID to an AllocatorKey
type idMap map[idpool.ID]AllocatorKey

// keyMap provides mapping from AllocatorKey to ID
type keyMap map[string]idpool.ID

type cache struct {
	logger      *slog.Logger
	controllers *controller.Manager

	allocator *Allocator

	ctx    context.Context
	cancel context.CancelFunc

	// mutex protects all cache data structures
	mutex lock.RWMutex

	// cache is a local cache of all IDs allocated in the kvstore. It is
	// being maintained by watching for kvstore events and can thus lag
	// behind.
	cache idMap

	// keyCache shadows cache and allows access by key
	keyCache keyMap

	// nextCache is the cache is constantly being filled by startWatch(),
	// when startWatch has successfully performed the initial fill using
	// ListPrefix, the cache above will be pointed to nextCache. If the
	// startWatch() fails to perform the initial list, then the cache is
	// never pointed to nextCache. This guarantees that a valid cache is
	// kept at all times.
	nextCache idMap

	// nextKeyCache follows the same logic as nextCache but for keyCache
	nextKeyCache keyMap

	listDone waitChan

	// stopWatchWg is a wait group that gets conditions added when a
	// watcher is started with the conditions marked as done when the
	// watcher has exited
	stopWatchWg sync.WaitGroup

	changeSrc         stream.Observable[AllocatorChange]
	emitChange        func(AllocatorChange)
	completeChangeSrc func(error)
}

func newCache(a *Allocator) (c cache) {
	ctx, cancel := context.WithCancel(context.Background())
	c = cache{
		logger:      a.logger,
		allocator:   a,
		cache:       idMap{},
		keyCache:    keyMap{},
		ctx:         ctx,
		cancel:      cancel,
		controllers: controller.NewManager(),
	}
	c.changeSrc, c.emitChange, c.completeChangeSrc = stream.Multicast[AllocatorChange]()
	return
}

type waitChan chan struct{}

// CacheMutations are the operations given to a Backend's ListAndWatch command.
// They are called on changes to identities.
type CacheMutations interface {
	// OnListDone is called when the initial full-sync is complete.
	OnListDone()

	// OnUpsert is called when either a new key->ID mapping appears or an existing
	// one is modified. The latter case may occur e.g., when leases are updated,
	// and does not mean that the actual mapping had changed.
	OnUpsert(id idpool.ID, key AllocatorKey)

	// OnDelete is called when a key->ID mapping is removed. This may trigger
	// master-key protection, if enabled, where the local allocator will recreate
	// the key->ID association is recreated because the local node is still using
	// it.
	OnDelete(id idpool.ID, key AllocatorKey)
}

func (c *cache) sendEvent(typ AllocatorChangeKind, id idpool.ID, key AllocatorKey) {
	if events := c.allocator.events; events != nil {
		events <- AllocatorEvent{Typ: typ, ID: id, Key: key}
	}
}

func (c *cache) OnListDone() {
	c.mutex.Lock()
	// nextCache is valid, point the live cache to it
	c.cache = c.nextCache
	c.keyCache = c.nextKeyCache
	c.mutex.Unlock()

	c.logger.Debug("Initial list of identities received")

	// report that the list operation has
	// been completed and the allocator is
	// ready to use
	close(c.listDone)
}

func (c *cache) OnUpsert(id idpool.ID, key AllocatorKey) {
	for _, validator := range c.allocator.cacheValidators {
		if err := validator(AllocatorChangeUpsert, id, key); err != nil {
			c.logger.Warn(
				"Skipping event for invalid identity",
				logfields.Error, err,
				logfields.Identity, id,
				logfields.Event, AllocatorChangeUpsert,
			)
			return
		}
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	if k, ok := c.nextCache[id]; ok {
		delete(c.nextKeyCache, k.GetKey())
	}

	c.nextCache[id] = key
	if key != nil {
		c.nextKeyCache[key.GetKey()] = id
	}

	c.allocator.idPool.Remove(id)

	c.emitChange(AllocatorChange{Kind: AllocatorChangeUpsert, ID: id, Key: key})

	c.sendEvent(AllocatorChangeUpsert, id, key)
}

func (c *cache) OnDelete(id idpool.ID, key AllocatorKey) {
	for _, validator := range c.allocator.cacheValidators {
		if err := validator(AllocatorChangeDelete, id, key); err != nil {
			c.logger.Warn(
				"Skipping event for invalid identity",
				logfields.Error, err,
				logfields.Identity, id,
				logfields.Event, AllocatorChangeDelete,
			)
			return
		}
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.onDeleteLocked(id, key, true)
}

const syncIdentityControllerGroup = "sync-identity"

func syncControllerName(id idpool.ID) string {
	return syncIdentityControllerGroup + "-" + id.String()
}

// no max interval by default, exposed as a variable for testing.
var masterKeyRecreateMaxInterval = time.Duration(0)

var syncIdentityGroup = controller.NewGroup(syncIdentityControllerGroup)

// onDeleteLocked must be called while holding c.Mutex for writing
func (c *cache) onDeleteLocked(id idpool.ID, key AllocatorKey, recreateMissingLocalKeys bool) {
	a := c.allocator
	if a.enableMasterKeyProtection && recreateMissingLocalKeys {
		if value := a.localKeys.lookupID(id); value != nil {
			c.controllers.UpdateController(syncControllerName(id), controller.ControllerParams{
				Context:          context.Background(),
				MaxRetryInterval: masterKeyRecreateMaxInterval,
				Group:            syncIdentityGroup,
				DoFunc: func(ctx context.Context) error {
					c.mutex.Lock()
					defer c.mutex.Unlock()
					// For each attempt, check if this ciliumidentity is still a candidate for recreation.
					// It's possible that since the last iteration that this agent has legitimately deleted
					// the key, in which case we can stop trying to recreate it.
					if value := c.allocator.localKeys.lookupID(id); value == nil {
						return nil
					}

					ctx, cancel := context.WithTimeout(ctx, backendOpTimeout)
					defer cancel()

					// Each iteration will attempt to grab the key reference, if that succeeds
					// then this completes (i.e. the key exists).
					// Otherwise we will attempt to create the key, this process repeats until
					// the key is created.
					if err := a.backend.UpdateKey(ctx, id, value, true); err != nil {
						c.logger.Error(
							"OnDelete MasterKeyProtection update for key",
							logfields.Error, err,
							logfields.ID, id,
						)
						return err
					}
					c.logger.Info(
						"OnDelete MasterKeyProtection update succeeded",
						logfields.ID, id,
					)
					return nil
				},
			})

			return
		}
	}

	if k, ok := c.nextCache[id]; ok && k != nil {
		delete(c.nextKeyCache, k.GetKey())
	}

	delete(c.nextCache, id)
	a.idPool.Insert(id)

	c.emitChange(AllocatorChange{Kind: AllocatorChangeDelete, ID: id, Key: key})

	c.sendEvent(AllocatorChangeDelete, id, key)
}

// start requests a LIST operation from the kvstore and starts watching the
// prefix in a go subroutine.
func (c *cache) start() waitChan {
	c.listDone = make(waitChan)

	c.mutex.Lock()

	// start with a fresh nextCache
	c.nextCache = idMap{}
	c.nextKeyCache = keyMap{}
	c.mutex.Unlock()

	c.stopWatchWg.Add(1)

	go func() {
		c.allocator.backend.ListAndWatch(c.ctx, c)
		c.stopWatchWg.Done()
	}()

	return c.listDone
}

func (c *cache) stop() {
	c.cancel()
	c.stopWatchWg.Wait()
	// Drain/stop any remaining sync identity controllers.
	// Backend watch is now stopped, any running controllers attempting to
	// sync identities will complete and stop (possibly in a unresolved state).
	c.controllers.RemoveAllAndWait()
	c.completeChangeSrc(nil)
}

// drain emits a deletion event for all known IDs. It must be called after the
// cache has been stopped, to ensure that no new events can be received afterwards.
func (c *cache) drain() {
	// Make sure we wait until the watch loop has been properly stopped.
	c.stopWatchWg.Wait()

	c.mutex.Lock()
	for id, key := range c.nextCache {
		c.onDeleteLocked(id, key, false)
	}
	c.mutex.Unlock()
}

// drainIf emits a deletion event for all known IDs that are stale according to
// the isStale function. It must be called after the cache has been stopped, to
// ensure that no new events can be received afterwards.
func (c *cache) drainIf(isStale func(id idpool.ID) bool) {
	// Make sure we wait until the watch loop has been properly stopped, otherwise
	// new IDs might be added afterwards we complete the draining process.
	c.stopWatchWg.Wait()

	c.mutex.Lock()
	for id, key := range c.nextCache {
		if isStale(id) {
			c.onDeleteLocked(id, key, false)
			c.logger.Debug(
				"Stale identity deleted",
				logfields.ID, id,
				logfields.Key, key,
			)
		}
	}
	c.mutex.Unlock()
}

func (c *cache) get(key string) idpool.ID {
	c.mutex.RLock()
	if id, ok := c.keyCache[key]; ok {
		c.mutex.RUnlock()
		return id
	}
	c.mutex.RUnlock()

	return idpool.NoID
}

func (c *cache) getByID(id idpool.ID) AllocatorKey {
	c.mutex.RLock()
	if v, ok := c.cache[id]; ok {
		c.mutex.RUnlock()
		return v
	}
	c.mutex.RUnlock()

	return nil
}

func (c *cache) foreach(cb RangeFunc) {
	c.mutex.RLock()
	for k, v := range c.cache {
		cb(k, v)
	}
	c.mutex.RUnlock()
}

func (c *cache) insert(key AllocatorKey, val idpool.ID) {
	c.mutex.Lock()
	c.nextCache[val] = key
	c.nextKeyCache[key.GetKey()] = val
	c.mutex.Unlock()
}

func (c *cache) numEntries() int {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return len(c.nextCache)
}

type AllocatorChangeKind string

const (
	AllocatorChangeSync   AllocatorChangeKind = "sync"
	AllocatorChangeUpsert AllocatorChangeKind = "upsert"
	AllocatorChangeDelete AllocatorChangeKind = "delete"
)

type AllocatorChange struct {
	Kind AllocatorChangeKind
	ID   idpool.ID
	Key  AllocatorKey
}

// Observe the allocator changes. Conforms to stream.Observable.
// Replays the current state of the cache when subscribing.
func (c *cache) Observe(ctx context.Context, next func(AllocatorChange), complete func(error)) {
	// This short-lived go routine serves the purpose of replaying the current state of the cache before starting
	// to observe the actual source changeSrc. ChangeSrc is backed by a stream.FuncObservable, that will start its own
	// go routine. Therefore, the current go routine will stop and free the lock on the mutex after the registration.
	go func() {
		// Wait until initial listing has completed before
		// replaying the state.
		select {
		case <-c.listDone:
		case <-ctx.Done():
			complete(ctx.Err())
			return
		}

		c.mutex.RLock()
		defer c.mutex.RUnlock()

		for id, key := range c.cache {
			next(AllocatorChange{Kind: AllocatorChangeUpsert, ID: id, Key: key})
		}

		// Emit a sync event to inform the subscriber that it has received a consistent
		// initial state.
		next(AllocatorChange{Kind: AllocatorChangeSync})

		// And subscribe to new events. Since we held the read-lock there won't be any
		// missed or duplicate events.
		c.changeSrc.Observe(ctx, next, complete)
	}()

}
