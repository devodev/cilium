//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package mixedrouting

import (
	"context"
	"log/slog"
	"net"

	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/bpf"
	dpipc "github.com/cilium/cilium/pkg/datapath/ipcache"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	ipcmap "github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

// epentry wraps the information associated with a given prefix.
type epEntry struct {
	hostIP   net.IP
	hostKey  uint8
	k8sMeta  *ipcache.K8sMetadata
	identity ipcache.Identity
}

type epBufferedEntry struct {
	*epEntry
	buffered time.Time
}

type prefixType = string
type hostIPType = string
type epState int

const (
	epStateUnknown epState = iota
	epStatePropagated
	epStateBuffered
)

// prefixCache caches all known prefixes, along with the associated information.
type prefixCache struct {
	propagated  map[prefixType]*epEntry
	buffered    map[prefixType]epBufferedEntry
	byHostIP    map[hostIPType]sets.Set[prefixType]
	bufepMetric metric.Gauge
}

func newPrefixCache(bufepMetric metric.Gauge) prefixCache {
	return prefixCache{
		propagated:  make(map[prefixType]*epEntry),
		buffered:    make(map[prefixType]epBufferedEntry),
		byHostIP:    make(map[hostIPType]sets.Set[prefixType]),
		bufepMetric: bufepMetric,
	}
}

// get returns the state and entry associated with a given prefix, if any.
func (pc *prefixCache) get(prefix prefixType) (state epState, entry *epEntry) {
	if entry, propagated := pc.propagated[prefix]; propagated {
		return epStatePropagated, entry
	}

	if entry, buffered := pc.buffered[prefix]; buffered {
		return epStateBuffered, entry.epEntry
	}

	return epStateUnknown, nil
}

// upsert stores a new prefix inside the cache. It returns the previous state
// and entry associated with that prefix, if any.
func (pc *prefixCache) upsert(prefix prefixType, entry *epEntry, state epState) (oldState epState, oldEntry *epEntry) {
	oldState, oldEntry = pc.get(prefix)

	switch {
	case state == epStatePropagated:
		pc.propagated[prefix] = entry
		if oldState == epStateBuffered {
			delete(pc.buffered, prefix)
		}
	case state == epStateBuffered:
		pc.buffered[prefix] = epBufferedEntry{entry, time.Now()}
		if oldState == epStatePropagated {
			delete(pc.propagated, prefix)
		}
	}

	if oldState == epStateUnknown || !oldEntry.hostIP.Equal(entry.hostIP) {
		pc.setHostIPMapping(prefix, entry.hostIP.String())
		if oldState != epStateUnknown {
			pc.unsetHostIPMapping(prefix, oldEntry.hostIP.String())
		}
	}

	pc.bufepMetric.Set(float64(len(pc.buffered)))
	return oldState, oldEntry
}

// delete removes a previously cached prefix, and returns its state.
func (pc *prefixCache) delete(prefix prefixType) (state epState) {
	state, entry := pc.get(prefix)

	switch state {
	case epStatePropagated:
		delete(pc.propagated, prefix)
	case epStateBuffered:
		delete(pc.buffered, prefix)
	}

	if state != epStateUnknown {
		pc.unsetHostIPMapping(prefix, entry.hostIP.String())
	}

	pc.bufepMetric.Set(float64(len(pc.buffered)))
	return state
}

// listByHostIP executes the callback function for all prefix entries matching
// the given hostIP.
func (pc *prefixCache) listByHostIP(hostIP hostIPType, cb func(prefix prefixType, entry *epEntry, state epState)) {
	for prefix := range pc.byHostIP[hostIP] {
		state, entry := pc.get(prefix)
		cb(prefix, entry, state)
	}
}

func (pc *prefixCache) setHostIPMapping(prefix prefixType, hostIP hostIPType) {
	mapping, ok := pc.byHostIP[hostIP]
	if !ok {
		mapping = sets.New[prefixType]()
		pc.byHostIP[hostIP] = mapping
	}

	mapping.Insert(prefix)
}

func (pc *prefixCache) unsetHostIPMapping(prefix prefixType, hostIP hostIPType) {
	if mapping, ok := pc.byHostIP[hostIP]; ok {
		mapping.Delete(prefix)
		if mapping.Len() == 0 {
			delete(pc.byHostIP, hostIP)
		}
	}
}

type endpointManager struct {
	logger *slog.Logger
	modes  routingModesType

	downstream ipcache.IPCacher
	mappings   lock.Map[hostIPType, routingModeType]

	// This mutex is leveraged to serialize all operations, and prevent out-of-order
	// processing issues. It does not introduce performance concerns, as that's
	// also done by the downstream ipcache implementation. In addition, we use
	// a lock.Map for the mappings to avoid risking circular locking, given that
	// an upsertion will synchronously execute the ipcache map wrapper.
	mu lock.Mutex

	prefixes prefixCache
}

// Upsert wraps the correspoding ipcache.IPCache method to observe endpoint upsertions
// and perform the appropriate operations to implement mixed routing mode support.
// Currently, this wrapper is intended for usage in the clustermesh context only.
func (em *endpointManager) Upsert(prefix string, hostIP net.IP, hostKey uint8,
	k8sMeta *ipcache.K8sMetadata, identity ipcache.Identity) (bool, error) {
	em.mu.Lock()
	defer em.mu.Unlock()
	return em.upsertLocked(prefix, hostIP, hostKey, k8sMeta, identity)
}

func (em *endpointManager) upsertLocked(prefix string, hostIP net.IP, hostKey uint8,
	k8sMeta *ipcache.K8sMetadata, identity ipcache.Identity) (bool, error) {
	hostIPStr := hostIP.String()

	if _, propagate := em.mappings.Load(hostIPStr); propagate || hostIP.IsUnspecified() {
		em.prefixes.upsert(prefix, &epEntry{hostIP, hostKey, k8sMeta, identity}, epStatePropagated)
		return em.downstream.Upsert(prefix, hostIP, hostKey, k8sMeta, identity)
	}

	// Buffer the entry until we observe the node matching the hostIP, as we don't
	// know its routing mode at the moment. Entries not associated with any tunnel
	// endpoint (i.e., 0.0.0.0 and ::) are never buffered.
	em.logger.Debug(
		"Buffering endpoint until the corresponding node entry is seen",
		logfields.Prefix, prefix,
		logfields.TunnelPeer, hostIPStr,
	)

	oldState, oldEntry := em.prefixes.upsert(prefix, &epEntry{hostIP, hostKey, k8sMeta, identity}, epStateBuffered)
	if oldState == epStatePropagated {
		// Trigger a delete event to cleanup the stale entry if the endpoint had
		// already been propagated. We don't use deleteLocked as that would also
		// mangle the prefix cache, which is already up to date.
		em.downstream.Delete(prefix, oldEntry.identity.Source)
	}

	// The return value is ignored by the upstream kvstore watcher in any case.
	return false, nil
}

// Delete wraps the correspoding ipcache.IPCache method to observe endpoint upsertions
// and perform the appropriate operations to implement mixed routing mode support.
// Currently, this wrapper is intended for usage in the clustermesh context only.
func (em *endpointManager) Delete(prefix string, source source.Source) bool {
	em.mu.Lock()
	defer em.mu.Unlock()
	return em.deleteLocked(prefix, source)
}

func (em *endpointManager) deleteLocked(prefix string, source source.Source) bool {
	// Don't propagate the deletion event if the upsertion had not been propagated.
	if em.prefixes.delete(prefix) == epStatePropagated {
		return em.downstream.Delete(prefix, source)
	}

	return false
}

// setMapping configures an host IP to routing mode mapping, triggering the
// insertion of any buffered entry, and the update of possible existing
// entries in case the routing mode changed.
func (em *endpointManager) setMapping(hostIP net.IP, mode routingModeType) {
	em.mu.Lock()
	defer em.mu.Unlock()

	hostIPStr := hostIP.String()
	prev, ok := em.mappings.Swap(hostIPStr, mode)
	if ok && needsEncapsulation(prev) == needsEncapsulation(mode) {
		return
	}

	// Iterate over all known prefixes associated with the hostIP, and trigger an
	// update to propagate the modification to the ipcache map for each of them.
	em.prefixes.listByHostIP(hostIPStr, func(prefix prefixType, entry *epEntry, state epState) {
		message := "Inserting previously buffered endpoint"
		if state == epStatePropagated {
			message = "Triggering endpoint refresh due to routing mode change"
		}

		em.logger.Debug(message,
			logfields.Prefix, prefix,
			logfields.TunnelPeer, hostIPStr,
			logfields.RoutingMode, mode,
		)

		// The routing mode associated with this endpoint changed with respect
		// to the one previously configured. Trigger a deletion to make sure
		// that the subsequent upsertion will propagate to the ipcache map.
		if state == epStatePropagated {
			// We don't use deleteLocked as that would remove the entry from
			// the map, which in turn could cause it to be processed multiple
			// times based on map iteration order, as immediately added again
			// by upsertLocked.
			em.downstream.Delete(prefix, entry.identity.Source)
		}

		em.upsertLocked(prefix, entry.hostIP, entry.hostKey, entry.k8sMeta, entry.identity)
	})
}

// unsetMapping removes an hostIP to routing mode mapping.
func (em *endpointManager) unsetMapping(hostIP net.IP) {
	// We don't explicitly trigger the deletion of the entries associated with
	// this host IP, relying instead on the corresponding deletion events.
	em.mappings.Delete(hostIP.String())
}

// warnBufferedEntries scans the list of buffered entries and emits a warning message
// if they have been buffered for longer than expected. This function is intended to
// be run periodically by a timer job.
func (em *endpointManager) warnBufferedEntries(context.Context) error {
	const deadline, limit = 1 * time.Minute, 10

	em.mu.Lock()
	defer em.mu.Unlock()

	var count int
	for prefix, entry := range em.prefixes.buffered {
		if time.Since(entry.buffered) > deadline {
			count++

			// We print only a limited number of warnings to avoid flooding logs.
			if count < limit {
				em.logger.Warn("Node entry corresponding to buffered endpoint not yet observed. "+
					"Expect connectivity disruption towards it",
					logfields.Prefix, prefix,
					logfields.TunnelPeer, entry.hostIP,
				)
			}
		}
	}

	if count > 0 {
		em.logger.Warn("Detected buffered endpoints. Please check the health of the clustermesh "+
			"control plane and whether agents are successfully connected to it.",
			logfields.Count, count,
			logfields.Omitted, max(0, count-limit),
		)
	}

	return nil
}

func (em *endpointManager) mutateRemoteEndpointInfo(key *ipcmap.Key, rei *ipcmap.RemoteEndpointInfo) {
	var ip hostIPType
	if !rei.TunnelEndpoint.IsZero() {
		// The tunnel endpoint is found, match based on it.
		ip = rei.GetTunnelEndpoint().String()
	} else {
		// Otherwise, try to match based on the prefix, if it represents a single
		// IP, so that we configure the flag correctly also for the NodeInternalIP
		// and NodeExternalIP entries, which are needed to toggle masquerading.
		if prefix := key.Prefix(); prefix.IsSingleIP() {
			ip = prefix.Addr().String()
		}
	}

	mode, ok := em.mappings.Load(ip)
	if !ok || ip == "" {
		mode = em.modes.primary()
	}

	em.logger.Debug("Configuring ipcache BPF map entry",
		logfields.Prefix, key,
		logfields.TunnelPeer, rei.TunnelEndpoint,
		logfields.RoutingMode, mode,
	)

	if needsEncapsulation(mode) {
		rei.Flags &= ^ipcmap.FlagSkipTunnel
	} else {
		rei.Flags |= ipcmap.FlagSkipTunnel
	}
}

type ipcmapwr struct {
	next    dpipc.Map
	mutator func(*ipcmap.Key, *ipcmap.RemoteEndpointInfo)
}

func (imw *ipcmapwr) SetNext(next dpipc.Map) {
	imw.next = next
}

// Update wraps the corresponding ipcachemap.Map method to appropriately mutate
// the value (setting the tunnel flag) before performing the upsertion operation.
func (imw *ipcmapwr) Update(key bpf.MapKey, value bpf.MapValue) error {
	imw.mutator(key.(*ipcmap.Key), value.(*ipcmap.RemoteEndpointInfo))
	return imw.next.Update(key, value)
}

func (imw *ipcmapwr) Delete(key bpf.MapKey) error {
	return imw.next.Delete(key)
}
