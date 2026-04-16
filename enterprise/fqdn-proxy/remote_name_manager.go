//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"regexp"
	"slices"

	"github.com/cilium/dns"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	pb "github.com/cilium/cilium/enterprise/fqdn-proxy/api/v1/dnsproxy"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/fqdn/namemanager"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

type remoteNameManager struct {
	logger *slog.Logger

	cfg     Config
	client  *fqdnAgentClient
	cache   *agentDataCache
	ipcache bpfIPCache

	identities       *identityStore
	selectors        *selectorStore
	identitiesSynced bool
	selectorsSynced  bool

	// number and reason for failed writes
	metricFailedWrite metric.Vec[metric.Counter]
}

const writeFailReasonExists = "ipc_already_exists"
const writeFailReasonLookupFail = "ipc_lookup_failed"
const writeFailReasonBPF = "bpf_write_fail"
const writeFailReasonNoID = "no_identity"
const writeFailReasonNotSync = "not_synchronized"

type remoteNameManagerParams struct {
	cell.In

	Logger *slog.Logger
	JG     job.Group

	Cfg     Config
	Client  *fqdnAgentClient
	IPCache bpfIPCache
}

func newRemoteNameManager(params remoteNameManagerParams) (*remoteNameManager, metricsOut) {
	r := &remoteNameManager{
		logger:           params.Logger.With(logfields.LogSubsys, "remote-name-manager"),
		cfg:              params.Cfg,
		client:           params.Client,
		cache:            newAgentDataCache(),
		ipcache:          params.IPCache,
		identities:       newIdentityStore(),
		selectors:        newSelectorStore(),
		identitiesSynced: false,
		selectorsSynced:  false,
	}

	r.metricFailedWrite = metric.NewCounterVec(metric.CounterOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "ipcache_write_failure_total",
		Help:      "Number of failed ipcache writes",
	}, []string{"reason"})

	if params.Cfg.EnableOfflineMode && params.JG != nil {
		params.JG.Add(job.OneShot("stream-selectors", r.streamSelectors))
	}

	return r, metricsOut{Metrics: []metric.WithMetadata{
		r.metricFailedWrite,
	}}
}

func (r *remoteNameManager) streamSelectors(ctx context.Context, _ cell.Health) error {
	var nextLog time.Time

	for {
		err := r.tryStreamSelectors(ctx)
		if ctx.Err() != nil {
			break
		}

		retryInterval := time.Second
		if isUnimplementedError(err) {
			retryInterval = 5 * time.Minute
		} else {
			now := time.Now()
			if now.After(nextLog) { // silence needless logs.
				r.logger.Info("SubscribeSelectors() failed", logfields.Error, err)
				nextLog = now.Add(30 * time.Second)
			}
		}
		sctx, cancel := context.WithTimeout(ctx, retryInterval)
		r.client.WaitMaybeReconnected(sctx)
		cancel()

	}
	return ctx.Err()
}

func (r *remoteNameManager) tryStreamSelectors(ctx context.Context) error {
	ps, err := r.client.SubscribeSelectors(ctx, &pb.Empty{})
	if err != nil {
		return err
	}

	for {
		selectorUpdate, err := ps.Recv()
		if err != nil {
			return err
		}
		r.handleSelectorUpdate(selectorUpdate)
	}
}

// LookupRegisteredEndpoint wraps logic to lookup an endpoint with any backend.
func (r *remoteNameManager) LookupRegisteredEndpoint(ip netip.Addr) (*endpoint.Endpoint, bool, error) {
	// Make sure to send IPv4 addresses as [4]byte instead of [16]byte over gRPC, so they aren't
	// mistakenly treated as IPv6-mapped IPv4 addresses anywhere in the Cilium agent.
	var bs []byte

	if ip.Is4In6() {
		b := ip.As4()
		bs = b[:]
	} else {
		bs = ip.AsSlice()
	}

	ep, err := r.client.LookupEndpointByIP(context.TODO(), &pb.FQDN_IP{IP: bs})
	if err != nil {
		if r.client.shouldLog(err) {
			r.logger.Error("LookupRegisteredEndpoint request failed", logfields.Error, err)
		}

		endpoint, ok := r.cache.GetEndpointByIP(ip)
		if !ok {
			r.logger.Error("LookupRegisteredEndpoint: agent down and endpoint IP not in cache", logfields.IPAddr, ip)
			return nil, false, fmt.Errorf("could not lookup endpoint for ip %s: %w", ip, err)
		}
		r.logger.Debug("LookupRegisteredEndpoint: agent down, endpoint IP in cache", logfields.IPAddr, ip)
		return endpoint, false, nil
	}
	endpoint := &endpoint.Endpoint{
		ID: uint16(ep.ID),
		SecurityIdentity: &identity.Identity{
			ID: identity.NumericIdentity(ep.Identity),
		},
		K8sNamespace: ep.Namespace,
		K8sPodName:   ep.PodName,
	}
	r.cache.UpsertEndpoint(ip, endpoint)
	return endpoint, false, nil
}

func (r *remoteNameManager) lookupIPCache(addr netip.Addr) (identity.NumericIdentity, error) {
	if !r.cfg.EnableOfflineMode {
		return identity.NumericIdentity(0), errors.New("BPF IP cache map access not available")
	}

	return r.ipcache.lookup(addr)
}

// LookupSecIDByIP wraps logic to lookup an IP's security ID from the ipcache.
func (r *remoteNameManager) LookupSecIDByIP(ip netip.Addr) (secID ipcache.Identity, exists bool) {
	if !ip.IsValid() {
		return ipcache.Identity{}, false
	}
	var src = source.Unspec
	id, err := r.lookupIPCache(ip)
	if err != nil {
		ident, err := r.client.LookupSecurityIdentityByIP(context.TODO(), &pb.FQDN_IP{IP: ip.AsSlice()})
		if err != nil {
			if r.client.shouldLog(err) {
				r.logger.Error("LookupSecIDByIP request failed", logfields.Error, err)
			}

			cachedID, ok := r.cache.GetIdentityByIP(ip)
			if !ok {
				r.logger.Error("LookupSecIDByIP: agent down, IP not in cache", logfields.IPAddr, ip)
				return ipcache.Identity{}, false
			}
			// TODO: check if this assumption is correct
			// we assume that the identity exists if it's in the cache
			r.logger.Debug("LookupSecIDByIP: agent down, IP in cache",
				logfields.IPAddr, ip,
				logfields.Identity, secID)
			return cachedID, true
		}

		id = identity.NumericIdentity(ident.ID)
		src = source.Source(ident.Source)
	}

	identity := ipcache.Identity{
		ID:     id,
		Source: src,
	}
	r.cache.UpsertIdentity(ip, identity)
	return identity, true
}

// LookupByIdentity wraps logic to lookup an IPs by security ID from the
// ipcache.
func (r *remoteNameManager) LookupByIdentity(nid identity.NumericIdentity) []string {
	ips, err := r.client.LookupIPsBySecurityIdentity(context.TODO(), &pb.Identity{ID: uint32(nid)})
	if err != nil {
		if r.client.shouldLog(err) {
			r.logger.Error("LookupByIdentity request failed", logfields.Error, err)
		}

		cachedIPs, ok := r.cache.GetIPsBySecID(nid)
		if !ok {
			r.logger.Error("LookupByIdentity: agent down, id not in cache", logfields.Identity, nid)
			return nil
		}

		r.logger.Debug("LookupByIdentity: agent down, id in cache", logfields.Identity, nid)
		return cachedIPs
	}

	result := make([]string, 0, len(ips.IPs))
	for _, ip := range ips.IPs {
		result = append(result, net.IP(ip).String())
	}
	r.cache.UpsertIPs(nid, result)
	return result
}

func (r *remoteNameManager) MaybeUpdateIPCache(msg *dns.Msg) {
	if !r.cfg.EnableOfflineMode {
		r.logger.Debug("offline mode disabled, not updating BPF ipcache")
		return
	}

	if !r.identitiesSynced || !r.selectorsSynced {
		r.logger.Debug("full list of identities and selectors not yet synchronized, not updating BPF ipcache")
		r.metricFailedWrite.WithLabelValues(writeFailReasonNotSync).Inc()
		return
	}

	// Not a successful DNS response, don't bother.
	if !msg.Response || msg.Rcode != dns.RcodeSuccess {
		r.logger.Debug("not a successful DNS response, not updating BPF ipcache")
		return
	}

	msgDetails, err := dnsproxy.ExtractResponseMsgDetails(msg)
	if err != nil {
		r.logger.Debug("error extracting DNS response message details", logfields.Error, err)
		return
	}

	// No addresses in DNS response. What even is this?
	if len(msgDetails.ResponseIPs) == 0 {
		r.logger.Debug("no addresses in DNS response")
		return
	}

	r.maybeUpdateIPCache(msgDetails.QName, msgDetails.ResponseIPs)
}

func (r *remoteNameManager) maybeUpdateIPCache(qname string, responseAddrs []netip.Addr) {
	r.selectors.mu.RLock()
	selLbls := namemanager.DeriveLabelsForName(qname, r.selectors.selectors)
	r.selectors.mu.RUnlock()

	if len(selLbls) == 0 {
		// No matching toFQDN selectors.
		r.logger.Debug("no matching toFQDN selectors")
		return
	}

	for _, addr := range responseAddrs {
		identityLbls := r.identityLabelsForSelectorLabels(selLbls, addr)
		newID, exists := r.identities.find(identityLbls)
		if !exists {
			// no identity matches all toFQDN selectors.
			r.logger.Debug("no identity matches toFQDN selector labels",
				logfields.IdentityLabels, identityLbls,
				logfields.Labels, selLbls,
				logfields.Address, addr,
			)
			r.metricFailedWrite.WithLabelValues(writeFailReasonNoID).Inc()
			continue
		}
		log := r.logger.With(
			logfields.FQDN, qname,
			logfields.IdentityLabels, identityLbls,
			logfields.Labels, selLbls,
			logfields.Identity, newID,
			logfields.Address, addr,
		)

		existingID, err := r.ipcache.lookup(addr)
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			log.Warn("failed to lookup BPF ipcache map",
				logfields.Error, err,
			)
			r.metricFailedWrite.WithLabelValues(writeFailReasonLookupFail).Inc()
			continue
		}

		// If the existing ID is not Unknown or any of the World identities, we cannot
		// overwrite it.
		if err == nil {
			switch existingID {
			case identity.ReservedIdentityWorld, identity.ReservedIdentityWorldIPv4, identity.ReservedIdentityWorldIPv6, identity.IdentityUnknown:
				// proceed, it's allowed to overwrite these identities.
			case newID:
				log.Debug("IP already has desired ID in IPCache")
				continue
			default:
				log.Warn("offline mode: learned new address for name, but IP already in IPCache with different identity. Look for overlapping ToFQDN or CIDR selectors. This may cause traffic drops.",
					logfields.Old, existingID,
				)
				r.metricFailedWrite.WithLabelValues(writeFailReasonExists).Inc()
				continue
			}
		}

		log.Debug("Writing new address for identity to BPF ipcache map")
		err = r.ipcache.write(addr, newID)
		if err != nil {
			log.Warn("failed to write to BPF ipcache map",
				logfields.Error, err,
			)
			r.metricFailedWrite.WithLabelValues(writeFailReasonBPF).Inc()
			continue
		}
	}
}

func (r *remoteNameManager) handleSelectorUpdate(su *pb.SelectorUpdate) {
	r.logger.Debug("got selector update message", logfields.Message, su)

	if fqdnIdentity := su.GetFqdnIdentity(); fqdnIdentity != nil {
		r.updateFQDNIdentity(fqdnIdentity)
	} else if fqdnSelector := su.GetFqdnSelector(); fqdnSelector != nil {
		r.updateFQDNSelector(fqdnSelector)
	} else {
		r.logger.Warn("unknown message, ignoring", logfields.Message, su)
	}
}

func (r *remoteNameManager) updateFQDNIdentity(m *pb.FQDNIdentityUpdate) {
	switch m.Type {
	case pb.UpdateType_UPDATETYPE_UPSERT:
		id := identity.NumericIdentity(m.GetIdentity())
		// We don't care about identities which are not pure FQDN identities.
		if lbls := extractLabels(m.GetLabels()); lbls != nil {
			r.identities.upsert(id, lbls)
		} else {
			// Make sure that we don't keep an old variant of this ID alive.
			r.identities.remove(id)
		}
	case pb.UpdateType_UPDATETYPE_REMOVE:
		r.identities.remove(identity.NumericIdentity(m.GetIdentity()))
	case pb.UpdateType_UPDATETYPE_BOOKMARK:
		r.identitiesSynced = true
	default:
		r.logger.Warn("Unknown FQDN identity update type", logfields.Type, m.Type)
	}
}

type identityStore struct {
	mu lock.RWMutex

	byID     map[identity.NumericIdentity]labels.LabelArray
	byLabels map[labelsKey]identity.NumericIdentity
}

type labelsKey string

func labelsKeyFromLabelArray(lbls labels.LabelArray) labelsKey {
	return labelsKey(lbls.String())
}

func newIdentityStore() *identityStore {
	return &identityStore{
		byID:     make(map[identity.NumericIdentity]labels.LabelArray),
		byLabels: make(map[labelsKey]identity.NumericIdentity),
	}
}

func (s *identityStore) upsert(id identity.NumericIdentity, lbls labels.LabelArray) {
	s.mu.Lock()
	defer s.mu.Unlock()

	oldLbls, ok := s.byID[id]
	if ok {
		// when upserting an entry for an existing identity, make sure to remove the old
		// labels -> identity mapping.
		delete(s.byLabels, labelsKeyFromLabelArray(oldLbls))
	}

	s.byID[id] = lbls
	s.byLabels[labelsKeyFromLabelArray(lbls)] = id
}

func (s *identityStore) remove(id identity.NumericIdentity) {
	s.mu.Lock()
	defer s.mu.Unlock()

	lbls, ok := s.byID[id]
	if !ok {
		return
	}

	delete(s.byID, id)
	delete(s.byLabels, labelsKeyFromLabelArray(lbls))
}

func (s *identityStore) find(lbls labels.LabelArray) (id identity.NumericIdentity, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := labelsKeyFromLabelArray(lbls)
	id, ok = s.byLabels[key]
	return
}

func extractLabels(in []*pb.Label) labels.LabelArray {
	lbls := make(labels.LabelArray, 0, len(in))
	for _, l := range in {
		src := l.GetSource()
		// If an identity is constituted of labels with sources other than FQDN (such as
		// CIDR), it will never be matched by the labels from matching FQDN selectors, hence
		// the identity will never be used in offline policy mode.
		if src != labels.LabelSourceFQDN && !isWorldLabel(l) {
			return nil
		}
		lbls = append(lbls, labels.NewLabel(l.GetKey(), l.GetValue(), src))
	}
	return lbls.Sort()
}

func isWorldLabel(l *pb.Label) bool {
	if l.GetSource() != labels.LabelSourceReserved {
		return false
	}
	switch l.GetKey() {
	case labels.IDNameWorld, labels.IDNameWorldIPv4, labels.IDNameWorldIPv6:
		return l.GetValue() == ""
	}
	return false
}

var (
	worldLabelNonDualStack = labels.Label{Source: labels.LabelSourceReserved, Key: labels.IDNameWorld}
	worldLabelV4           = labels.Label{Source: labels.LabelSourceReserved, Key: labels.IDNameWorldIPv4}
	worldLabelV6           = labels.Label{Source: labels.LabelSourceReserved, Key: labels.IDNameWorldIPv6}
)

func (r *remoteNameManager) worldLabel(addr netip.Addr) labels.Label {
	if r.cfg.IsDualStack() {
		if addr.Is4() {
			return worldLabelV4
		} else {
			return worldLabelV6
		}
	} else {
		return worldLabelNonDualStack
	}
}

// identityLabelsForSelectorLabels returns a sorted LabelArray which corresponds to the identity
// labels of the set of selector labels plus the world label corresponding to addr.
func (r *remoteNameManager) identityLabelsForSelectorLabels(lbls labels.Labels, addr netip.Addr) labels.LabelArray {
	idLbls := make(labels.LabelArray, 0, len(lbls)+1)
	idLbls = slices.AppendSeq(idLbls, maps.Values(lbls))
	idLbls = append(idLbls, r.worldLabel(addr))
	return idLbls.Sort()
}

func (r *remoteNameManager) updateFQDNSelector(m *pb.FQDNSelectorUpdate) {
	switch m.Type {
	case pb.UpdateType_UPDATETYPE_UPSERT:
		selector := transformSelector(m.GetSelector())
		if err := r.selectors.upsert(selector); err != nil {
			r.logger.Error("Failed to upsert FQDN selector",
				logfields.Error, err,
				logfields.Selector, selector,
			)
		}
	case pb.UpdateType_UPDATETYPE_REMOVE:
		r.selectors.remove(transformSelector(m.GetSelector()))
	case pb.UpdateType_UPDATETYPE_BOOKMARK:
		r.selectorsSynced = true
	default:
		r.logger.Warn("Unknown FQDN selector update type", logfields.Type, m.Type)
	}
}

type selectorStore struct {
	mu lock.RWMutex

	selectors map[api.FQDNSelector]*regexp.Regexp
}

func newSelectorStore() *selectorStore {
	return &selectorStore{
		selectors: make(map[api.FQDNSelector]*regexp.Regexp),
	}
}

func (s *selectorStore) upsert(selector api.FQDNSelector) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	re, err := selector.ToRegex()
	if err != nil {
		return err
	}
	s.selectors[selector] = re
	return nil
}

func (s *selectorStore) remove(selector api.FQDNSelector) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.selectors, selector)
}

func (s *selectorStore) match(name string) []api.FQDNSelector {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var selectors []api.FQDNSelector
	for selector, re := range s.selectors {
		if re.MatchString(name) {
			selectors = append(selectors, selector)
		}
	}
	return selectors
}

func transformSelector(m *pb.FQDNSelector) api.FQDNSelector {
	return api.FQDNSelector{
		MatchName:    m.GetMatchName(),
		MatchPattern: m.GetMatchPattern(),
	}
}
