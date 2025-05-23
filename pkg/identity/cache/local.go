// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cache

import (
	"context"
	"fmt"
	"log/slog"
	"maps"

	"github.com/cilium/stream"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type localIdentityCache struct {
	logger              *slog.Logger
	mutex               lock.RWMutex
	identitiesByID      map[identity.NumericIdentity]*identity.Identity
	identitiesByLabels  map[string]*identity.Identity
	nextNumericIdentity identity.NumericIdentity
	scope               identity.NumericIdentity
	minID               identity.NumericIdentity
	maxID               identity.NumericIdentity

	// withheldIdentities is a set of identities that should be considered unavailable for allocation,
	// but not yet allocated.
	// They are used during agent restart, where local identities are restored to prevent unnecessary
	// ID flapping on restart.
	//
	// If an old nID is passed to lookupOrCreate(), then it is allowed to use a withhend entry here. Otherwise
	// it must allocate a new ID not in this set.
	withheldIdentities map[identity.NumericIdentity]struct{}

	// Used to implement the stream.Observable interface.
	changeSource stream.Observable[IdentityChange]
	emitChange   func(IdentityChange)
}

func newLocalIdentityCache(logger *slog.Logger, scope, minID, maxID identity.NumericIdentity) *localIdentityCache {
	// There isn't a natural completion of this observable, so let's drop it.
	mcast, emit, _ := stream.Multicast[IdentityChange]()
	return &localIdentityCache{
		logger:              logger,
		identitiesByID:      map[identity.NumericIdentity]*identity.Identity{},
		identitiesByLabels:  map[string]*identity.Identity{},
		nextNumericIdentity: minID,
		scope:               scope,
		minID:               minID,
		maxID:               maxID,
		withheldIdentities:  map[identity.NumericIdentity]struct{}{},
		changeSource:        mcast,
		emitChange:          emit,
	}
}

func (l *localIdentityCache) bumpNextNumericIdentity() {
	if l.nextNumericIdentity == l.maxID {
		l.nextNumericIdentity = l.minID
	} else {
		l.nextNumericIdentity++
	}
}

// getNextFreeNumericIdentity returns the next available numeric identity or an error
// If idCandidate has the local scope and is available, it will be returned instead of
// searching for a new numeric identity.
// The l.mutex must be held
func (l *localIdentityCache) getNextFreeNumericIdentity(idCandidate identity.NumericIdentity) (identity.NumericIdentity, error) {
	// Try first with the given candidate
	if idCandidate.Scope() == l.scope {
		if _, taken := l.identitiesByID[idCandidate]; !taken {
			// let nextNumericIdentity be, allocated identities will be skipped anyway
			l.logger.Debug("Reallocated restored local identity", logfields.Identity, idCandidate)
			return idCandidate, nil
		} else {
			l.logger.Debug("Requested local identity not available to allocate", logfields.Identity, idCandidate)
		}
	}
	firstID := l.nextNumericIdentity
	for {
		idCandidate = l.nextNumericIdentity | l.scope
		_, taken := l.identitiesByID[idCandidate]
		_, withheld := l.withheldIdentities[idCandidate]
		if !taken && !withheld {
			l.bumpNextNumericIdentity()
			return idCandidate, nil
		}

		l.bumpNextNumericIdentity()
		if l.nextNumericIdentity == firstID {
			// Desperation: no local identities left (unlikely). If there are withheld
			// but not-taken identities, claim one of them.
			for withheldID := range l.withheldIdentities {
				if _, taken := l.identitiesByID[withheldID]; !taken {
					delete(l.withheldIdentities, withheldID)
					l.logger.Warn("Local identity allocator full; claiming first withheld identity. This may cause momentary policy drops", logfields.Identity, withheldID)
					return withheldID, nil
				}
			}

			return 0, fmt.Errorf("out of local identity space")
		}
	}
}

// lookupOrCreate searches for the existence of a local identity with the given
// labels. If it exists, the reference count is incremented and the identity is
// returned. If it does not exist, a new identity is created with a unique
// numeric identity. All identities returned by lookupOrCreate() must be
// released again via localIdentityCache.release().
// A possible previously used numeric identity for these labels can be passed
// in as the 'oldNID' parameter; identity.InvalidIdentity must be passed if no
// previous numeric identity exists. 'oldNID' will be reallocated if available.
func (l *localIdentityCache) lookupOrCreate(lbls labels.Labels, oldNID identity.NumericIdentity) (*identity.Identity, bool, error) {
	// Not converting to string saves an allocation, as byte key lookups into
	// string maps are optimized by the compiler, see
	// https://github.com/golang/go/issues/3512.
	repr := lbls.SortedList()

	l.mutex.Lock()
	defer l.mutex.Unlock()

	if id, ok := l.identitiesByLabels[string(repr)]; ok {
		id.ReferenceCount++
		return id, false, nil
	}

	numericIdentity, err := l.getNextFreeNumericIdentity(oldNID)
	if err != nil {
		return nil, false, err
	}

	id := &identity.Identity{
		ID:             numericIdentity,
		Labels:         lbls,
		LabelArray:     lbls.LabelArray(),
		ReferenceCount: 1,
	}

	l.identitiesByLabels[string(repr)] = id
	l.identitiesByID[numericIdentity] = id

	l.emitChange(IdentityChange{Kind: IdentityChangeUpsert, ID: numericIdentity, Labels: lbls})

	return id, true, nil
}

// release releases a local identity from the cache. true is returned when the
// last use of the identity has been released and the identity has been
// forgotten.
func (l *localIdentityCache) release(id *identity.Identity) bool {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if id, ok := l.identitiesByID[id.ID]; ok {
		switch {
		case id.ReferenceCount > 1:
			id.ReferenceCount--
			return false

		case id.ReferenceCount == 1:
			// Release is only attempted once, when the reference count is
			// hitting the last use
			delete(l.identitiesByLabels, string(id.Labels.SortedList()))
			delete(l.identitiesByID, id.ID)
			l.emitChange(IdentityChange{Kind: IdentityChangeDelete, ID: id.ID})

			return true
		}
	}

	return false
}

// withhold marks the nids as unavailable. Any out-of-scope identities are returned.
func (l *localIdentityCache) withhold(nids []identity.NumericIdentity) []identity.NumericIdentity {
	if len(nids) == 0 {
		return nil
	}

	unused := make([]identity.NumericIdentity, 0, len(nids))
	l.mutex.Lock()
	defer l.mutex.Unlock()
	for _, nid := range nids {
		if nid.Scope() != l.scope {
			unused = append(unused, nid)
			continue
		}
		l.withheldIdentities[nid] = struct{}{}
	}

	return unused
}

func (l *localIdentityCache) unwithhold(nids []identity.NumericIdentity) {
	if len(nids) == 0 {
		return
	}
	l.mutex.Lock()
	defer l.mutex.Unlock()
	for _, nid := range nids {
		if nid.Scope() != l.scope {
			continue
		}
		delete(l.withheldIdentities, nid)
	}
}

// lookup searches for a local identity matching the given labels and returns
// it. If found, the reference count is NOT incremented and thus release must
// NOT be called.
func (l *localIdentityCache) lookup(lbls labels.Labels) *identity.Identity {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	if id, ok := l.identitiesByLabels[string(lbls.SortedList())]; ok {
		return id
	}

	return nil
}

// lookupByID searches for a local identity matching the given ID and returns
// it. If found, the reference count is NOT incremented and thus release must
// NOT be called.
func (l *localIdentityCache) lookupByID(id identity.NumericIdentity) *identity.Identity {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	if id, ok := l.identitiesByID[id]; ok {
		return id
	}

	return nil
}

// GetIdentities returns all local identities
func (l *localIdentityCache) GetIdentities() map[identity.NumericIdentity]*identity.Identity {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return maps.Clone(l.identitiesByID)
}

func (l *localIdentityCache) checkpoint(dst []*identity.Identity) []*identity.Identity {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	for _, id := range l.identitiesByID {
		dst = append(dst, id)
	}
	return dst
}

func (l *localIdentityCache) size() int {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return len(l.identitiesByID)
}

// Implements stream.Observable. Replays initial state as a sequence of adds.
func (l *localIdentityCache) Observe(ctx context.Context, next func(IdentityChange), complete func(error)) {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	for nid, id := range l.identitiesByID {
		select {
		case <-ctx.Done():
			complete(ctx.Err())
			return
		default:
		}
		next(IdentityChange{Kind: IdentityChangeUpsert, ID: nid, Labels: id.Labels})
	}

	select {
	case <-ctx.Done():
		complete(ctx.Err())
		return
	default:
	}
	next(IdentityChange{Kind: IdentityChangeSync})

	l.changeSource.Observe(ctx, next, complete)
}
