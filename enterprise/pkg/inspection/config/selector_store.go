//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package config

import (
	"sync/atomic"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/policy"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
)

type selectorState struct {
	// selector is the compiled endpoint selector. A nil selector means
	// "wildcard": all endpoints are selected.
	selector       *policyTypes.LabelSelector
	cachedSelector policy.CachedSelector
	selectNone     bool
}

// SelectorStore keeps the resolved inspection selector separate from datapath
// endpoint snapshots. The reconciler owns selector updates and stamps the
// endpoint-local property consumed by datapath loading.
type SelectorStore struct {
	mu lock.RWMutex
	// selectorCache keeps selector -> numeric identity matches precomputed, so
	// datapath config generation can make a local Selects(identity) decision.
	selectorCache       *policy.SelectorCache
	selectorCacheUser   *selectorCacheUser
	activeSelectorState atomic.Pointer[selectorState]
}

func NewSelectorStore() *SelectorStore {
	return &SelectorStore{
		selectorCacheUser: &selectorCacheUser{},
	}
}

// SetSelector updates the active inspection selector. A nil selector means all
// endpoints are selected (wildcard).
func (s *SelectorStore) SetSelector(sel *policyTypes.LabelSelector) {
	if s == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var cachedSelector policy.CachedSelector
	if sel != nil && s.selectorCache != nil {
		cachedSelectors, _ := s.selectorCache.AddSelectors(s.selectorCacheUser, sel)
		if len(cachedSelectors) > 0 {
			cachedSelector = cachedSelectors[0]
		}
	}

	oldState := s.activeSelectorState.Load()
	s.activeSelectorState.Store(&selectorState{
		selector:       sel,
		cachedSelector: cachedSelector,
	})

	if oldState != nil && oldState.cachedSelector != nil &&
		oldState.cachedSelector != cachedSelector && s.selectorCache != nil {
		s.selectorCache.RemoveSelector(oldState.cachedSelector, s.selectorCacheUser)
	}
}

// SetSelectNone updates the active inspection selector to match no endpoints.
// This is used as a safe fallback when the configured selector cannot be
// sanitized and there is no previous valid selector to preserve.
func (s *SelectorStore) SetSelectNone() {
	if s == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	oldState := s.activeSelectorState.Load()
	s.activeSelectorState.Store(&selectorState{
		selectNone: true,
	})

	if oldState != nil && oldState.cachedSelector != nil && s.selectorCache != nil {
		s.selectorCache.RemoveSelector(oldState.cachedSelector, s.selectorCacheUser)
	}
}

// HasSelector returns whether the selector store has been initialized. Before
// the inspection config resource syncs, an uninitialized store is intentionally
// treated as non-authoritative.
func (s *SelectorStore) HasSelector() bool {
	return s != nil && s.activeSelectorState.Load() != nil
}

// DesiredEnabledForEndpoint evaluates the active inspection selector for the
// provided endpoint. The second return value indicates whether the result is
// authoritative.
func (s *SelectorStore) DesiredEnabledForEndpoint(ep SelectorEndpoint) (bool, bool) {
	if s == nil {
		return false, false
	}
	state := s.activeSelectorState.Load()
	if state == nil {
		return false, false
	}
	if state.selectNone {
		return false, true
	}
	if !ep.K8sNamespaceAndPodNameIsSet() {
		// Non-k8s endpoints (host, etc.) carry no pod/namespace labels and
		// therefore cannot match a label selector.
		return false, true
	}
	if state.selector == nil {
		return true, true
	}
	id, err := ep.GetSecurityIdentity()
	if err != nil || id == nil {
		return false, false
	}
	return policyTypes.Matches(state.selector, id.LabelArray), true
}

// DesiredEnabledForIdentityID evaluates the active inspection selector for a
// numeric security identity using the policy selector cache. The second return
// value indicates whether the result is authoritative.
func (s *SelectorStore) DesiredEnabledForIdentityID(id identity.NumericIdentity) (bool, bool) {
	if s == nil {
		return false, false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	state := s.activeSelectorState.Load()
	if state == nil {
		return false, false
	}
	if state.selectNone {
		return false, true
	}
	if state.selector == nil {
		return true, true
	}
	if state.cachedSelector == nil {
		return false, false
	}
	return state.cachedSelector.Selects(id), true
}
