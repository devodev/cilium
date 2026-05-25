// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package cache

import (
	"context"
	"slices"

	"github.com/jonboulle/clockwork"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"

	aggregationpb "github.com/cilium/cilium/enterprise/pkg/hubble/aggregation/api/aggregation"
	"github.com/cilium/cilium/enterprise/pkg/hubble/aggregation/internal/aggregation/types"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/time"
)

func (c *Cache) aggregateFlow(a *types.AggregatedFlow, f types.AggregatableFlow) (r *types.Result) {
	r = &types.Result{}
	var s *aggregationpb.DirectionStatistics

	if a.Stats.Reply == nil {
		a.Stats.Reply = &aggregationpb.DirectionStatistics{}
	}

	if a.Stats.Forward == nil {
		a.Stats.Forward = &aggregationpb.DirectionStatistics{}
	}

	if f.IsReply() {
		s = a.Stats.Reply
		if s.NumFlows == 0 {
			// This is the first flow observed with is_reply set to true.
			// Set the first_reply state change.
			r.StateChange |= aggregationpb.StateChange_first_reply
		}
	} else {
		s = a.Stats.Forward
	}

	s.LastActivity = timestamppb.New(c.clock.Now())
	s.NumFlows++

	if f.State().ACK {
		s.AckSeen = true
	}

	state := f.State()
	switch {
	case state.Error:
		if s.Errors == 0 {
			r.StateChange |= aggregationpb.StateChange_first_error
		} else {
			r.StateChange |= aggregationpb.StateChange_error
		}
		s.Errors++
	case state.CloseRequest:
		s.CloseRequests++
	case state.ConnectionRequest:
		s.ConnectionAttempts++
	}

	if c.conf.AggregateFunc != nil {
		c.conf.AggregateFunc(a, s, f, r)
	}

	if s.FirstActivity.GetSeconds() == 0 && s.FirstActivity.GetNanos() == 0 {
		s.FirstActivity = s.LastActivity
	}

	r.AggregatedFlow = a
	r.Reply = true
	return
}

// Cache is an aggregation cache used to store historic flows for
// identification of aggregation potential
type Cache struct {
	clock clockwork.Clock
	conf  Configuration

	// mutex protects the cache
	mutex lock.Mutex
	cache map[types.Hash][]*types.AggregatedFlow
	// shutdown channel is used to communicate that the GC goroutine stopped.
	shutdown chan struct{}
}

// Configuration is the configuration of an aggregation cache
type Configuration struct {
	CompareFunc   types.FlowCompareFunc
	HashFunc      types.FlowHashFunc
	AggregateFunc func(a *types.AggregatedFlow, s *aggregationpb.DirectionStatistics, f types.AggregatableFlow, r *types.Result)
	Expiration    time.Duration
	RenewTTL      bool
}

// NewCache returns a new aggregation cache
func NewCache(clock clockwork.Clock, conf Configuration) *Cache {
	if conf.Expiration == time.Duration(0) {
		conf.Expiration = time.Minute
	}

	c := &Cache{
		clock:    clock,
		conf:     conf,
		cache:    map[types.Hash][]*types.AggregatedFlow{},
		shutdown: make(chan struct{}, 1),
	}

	return c
}

func (c *Cache) StartGC(ctx context.Context) {
	for {
		select {
		case <-c.clock.After(c.conf.Expiration):
			c.mutex.Lock()
			now := c.clock.Now()
			for k, v := range c.cache {
				var valid []*types.AggregatedFlow
				for _, c := range v {
					if c.Expires.After(now) {
						valid = append(valid, c)
					}
				}
				if len(valid) > 0 {
					c.cache[k] = valid
				} else {
					delete(c.cache, k)
				}
			}
			c.mutex.Unlock()
		case <-ctx.Done():
			c.shutdown <- struct{}{}
			return
		}
	}
}

// Aggregate performs aggregation of a flow based on the existing cache content
func (c *Cache) Aggregate(f types.AggregatableFlow) *types.Result {
	var isNew bool

	expires := c.clock.Now().Add(c.conf.Expiration)
	hash := c.conf.HashFunc(f)

	c.mutex.Lock()
	defer c.mutex.Unlock()

	a := c.lookup(hash, f)
	if a == nil {
		if c.cache[hash] == nil {
			c.cache[hash] = []*types.AggregatedFlow{}
		}

		a = &types.AggregatedFlow{Expires: expires, FirstFlow: f}
		c.cache[hash] = append(c.cache[hash], a)
		isNew = true
	}

	if c.conf.RenewTTL {
		a.Expires = expires
	}
	result := c.aggregateFlow(a, f)
	if isNew {
		result.StateChange |= aggregationpb.StateChange_new
	}

	return result
}

// Lookup returns the aggregated flow if the flow passed into the Lookup
// function can be found in the cache
func (c *Cache) Lookup(f types.AggregatableFlow) *types.AggregatedFlow {
	hash := c.conf.HashFunc(f)
	c.mutex.Lock()
	defer c.mutex.Unlock()

	return c.lookup(hash, f)
}

func (c *Cache) lookup(hash types.Hash, f types.AggregatableFlow) *types.AggregatedFlow {
	now := c.clock.Now()

	if chain, ok := c.cache[hash]; ok {
		// Iterate over the chain backward. The order is important here in case the list
		// contains an expired flow that hasn't been evicted by the background goroutine.
		// The Aggregate function appends a new entry at the end of the list if there is
		// an expired flow in the list. If this function iterates over the list from the
		// beginning of the list, this function ends up marking all the subsequent flows
		// as new until the background goroutine evicts the expired flow. This is because
		// the lookup function returns nil as soon as it finds a matching flow that has
		// expired.
		for _, af := range slices.Backward(chain) {
			if c.conf.CompareFunc(af.FirstFlow, f) {
				if af.Expires.Before(now) {
					return nil
				}

				return af
			}
		}
	}

	return nil
}

// WaitForShutdown blocks until either the context is cancelled or the GC goroutine
// shuts down.
func (c *Cache) WaitForShutdown(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.shutdown:
		return nil
	}
}
