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
	"log/slog"
	"net/netip"
	"testing"

	"github.com/cilium/dns"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"

	pb "github.com/cilium/cilium/enterprise/fqdn-proxy/api/v1/dnsproxy"
	fqdnDNS "github.com/cilium/cilium/pkg/fqdn/dns"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
)

func (s *identityStore) len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byID)
}

func (s *selectorStore) len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.selectors)
}

func newDNSMsg(addr netip.Addr, fqdn string) *dns.Msg {
	return &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Response: true,
			Rcode:    dns.RcodeSuccess,
		},
		Question: []dns.Question{{
			Name: fqdnDNS.FQDN(fqdn),
		}},
		Answer: []dns.RR{
			&dns.CNAME{
				Hdr: dns.RR_Header{
					Name:   fqdnDNS.FQDN(fqdn),
					Rrtype: dns.TypeCNAME,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
			},
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   fqdnDNS.FQDN(fqdn),
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				A: addr.AsSlice(),
			},
		},
	}
}

func TestRemoteNameManager(t *testing.T) {
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
	ipCache := newFakeIPCache(logger)
	r, _ := newRemoteNameManager(remoteNameManagerParams{
		Logger: logger,
		Cfg: Config{
			EnableOfflineMode: true,
			EnableIPV4:        true,
			EnableIPV6:        true,
		},
		Client:  &fqdnAgentClient{},
		IPCache: ipCache,
	})
	assert.Equal(t, 0, r.identities.len())
	assert.Equal(t, 0, r.selectors.len())
	assert.False(t, r.identitiesSynced)
	assert.False(t, r.selectorsSynced)

	ipAddr := netip.MustParseAddr("192.168.1.42")
	fqdn := "isovalent.com"

	// BPF ipcache is empty, we don't expect to find a mapping
	id, err := r.lookupIPCache(ipAddr)
	assert.EqualError(t, err, "key does not exist")
	assert.Equal(t, identity.NumericIdentity(0), id)
	assert.Len(t, ipCache.lookupCalls, 1)
	assert.Equal(t, ipAddr, ipCache.lookupCalls[0].addr)

	worldLabel := labels.LabelWorldIPv4[labels.IDNameWorldIPv4]
	wantID := identity.NumericIdentity(42)
	su := &pb.SelectorUpdate{
		FqdnIdentity: &pb.FQDNIdentityUpdate{
			Type:     pb.UpdateType_UPDATETYPE_UPSERT,
			Identity: uint64(wantID),
			Labels: []*pb.Label{
				{
					Source: labels.LabelSourceFQDN,
					Key:    fqdn,
				},
				{
					Source: worldLabel.Source,
					Key:    worldLabel.Key,
				},
			},
		},
	}

	r.handleSelectorUpdate(su)

	assert.Equal(t, 1, r.identities.len())
	assert.Equal(t, 0, r.selectors.len())

	su = &pb.SelectorUpdate{
		FqdnSelector: &pb.FQDNSelectorUpdate{
			Type: pb.UpdateType_UPDATETYPE_UPSERT,
			Selector: &pb.FQDNSelector{
				MatchName: fqdn,
			},
		},
	}

	r.handleSelectorUpdate(su)

	assert.Equal(t, 1, r.identities.len())
	assert.Equal(t, 1, r.selectors.len())

	// Bookmark
	su = &pb.SelectorUpdate{
		FqdnSelector: &pb.FQDNSelectorUpdate{
			Type: pb.UpdateType_UPDATETYPE_BOOKMARK,
		},
	}
	r.handleSelectorUpdate(su)
	su = &pb.SelectorUpdate{
		FqdnIdentity: &pb.FQDNIdentityUpdate{
			Type: pb.UpdateType_UPDATETYPE_BOOKMARK,
		},
	}
	r.handleSelectorUpdate(su)

	assert.True(t, r.identitiesSynced)
	assert.True(t, r.selectorsSynced)

	// Expect to find a mapping based on the DNS response
	r.MaybeUpdateIPCache(newDNSMsg(ipAddr, fqdn))
	id, err = r.lookupIPCache(ipAddr)
	assert.NoError(t, err)
	assert.Equal(t, wantID, id)

	// No mapping expected to be found because we have no stored identity/selector for
	// example.org
	unknownFQDN := "example.org"
	ipAddrForUnknown := netip.MustParseAddr("10.0.1.2")
	r.MaybeUpdateIPCache(newDNSMsg(ipAddrForUnknown, unknownFQDN))
	id, err = r.lookupIPCache(ipAddrForUnknown)
	assert.Error(t, err)
	assert.Equal(t, identity.NumericIdentity(0), id)

	// Expect to find a new mapping for the existing isovalent.com identity/selector based on
	// the DNS response
	newIPAddr := netip.MustParseAddr("192.168.1.99")
	r.MaybeUpdateIPCache(newDNSMsg(newIPAddr, fqdn))
	id, err = r.lookupIPCache(newIPAddr)
	assert.NoError(t, err)
	assert.Equal(t, wantID, id)
}

func TestIdentityStore(t *testing.T) {
	s := newIdentityStore()
	assert.Empty(t, s.byID)
	assert.Empty(t, s.byLabels)

	id := identity.NumericIdentity(42)
	lbls4 := labels.ParseLabelArray("fqdn:isovalent.com", labels.LabelWorldIPv4.String())
	lbls6 := labels.ParseLabelArray("fqdn:isovalent.com", labels.LabelWorldIPv6.String())

	_, ok := s.find(lbls4)
	assert.False(t, ok, "expected to not find identity for %v", lbls4)

	s.upsert(id, lbls4)
	assert.Len(t, s.byID, 1)
	assert.Len(t, s.byLabels, 1)
	got, ok := s.find(lbls4)
	assert.True(t, ok, "expected to find identity for %v", lbls4)
	assert.Equal(t, id, got)

	_, ok = s.find(lbls6)
	assert.False(t, ok, "expected to not find identity for %v", lbls6)

	s.upsert(id, lbls6)
	assert.Len(t, s.byID, 1)
	assert.Len(t, s.byLabels, 1)
	got, ok = s.find(lbls6)
	assert.True(t, ok, "expected to find identity for %v", lbls6)
	assert.Equal(t, id, got)

	s.remove(id)
	_, ok = s.find(lbls4)
	assert.False(t, ok, "expected to not find identity for %v", lbls4)
	_, ok = s.find(lbls6)
	assert.False(t, ok, "expected to not find identity for %v", lbls6)
}

func TestSelectorStore(t *testing.T) {
	s := newSelectorStore()
	assert.Equal(t, 0, s.len())

	fqdnIsovalent := fqdnDNS.FQDN("isovalent.com")

	matches := s.match(fqdnIsovalent)
	assert.Empty(t, matches)

	selector := api.FQDNSelector{
		MatchName: "[a-z]+.com",
	}
	err := s.upsert(selector)
	assert.Error(t, err)
	assert.Equal(t, 0, s.len())

	selector.MatchName = "isovalent.com"
	err = s.upsert(selector)
	assert.NoError(t, err)
	assert.Equal(t, 1, s.len())

	matches = s.match(fqdnIsovalent)
	assert.Len(t, matches, 1)

	fqdnExample := fqdnDNS.FQDN("example.org")

	matches = s.match(fqdnExample)
	assert.Empty(t, matches)

	s.remove(api.FQDNSelector{MatchName: "cilium.io"})
	assert.Equal(t, 1, s.len())
	matches = s.match(fqdnIsovalent)
	assert.Len(t, matches, 1)

	s.remove(api.FQDNSelector{MatchName: "isovalent.com"})
	assert.Equal(t, 0, s.len())
	matches = s.match(fqdnIsovalent)
	assert.Empty(t, matches)
}
