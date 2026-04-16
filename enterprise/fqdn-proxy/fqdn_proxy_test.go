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
	"io/fs"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/hive/hivetest"
	"google.golang.org/grpc"

	pb "github.com/cilium/cilium/enterprise/fqdn-proxy/api/v1/dnsproxy"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/time"
)

// Each test should be ~fast, but time is a weird soup in CI.
var testTimeout = time.Second * 5

// These tests are less about testing the behaviour of our code, but instead
// codify some of the assumptions made about gRPC's behaviour. If these were to
// change, our code would become buggy which we should see as a test failure.

// Tests that connecting to a unix domain socket without a listener fails on
// first RPC ~instantaneously.
func TestConnectionFailureNoListener(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	socket := filepath.Join(t.TempDir(), "dnsproxy-test.socket")

	// Creating the client should succeed, since there's no connection attempt
	// at creation time.
	conn, err := createClient("unix:" + socket)
	if err != nil {
		t.Errorf("failed to create the client: %v", err)
	}
	// The first RPC establishes the conn, which should then fail
	// instantaneously, since there's no listener on the unix socket.
	_, err = pb.NewFQDNProxyAgentClient(conn).GetAllRules(ctx, &pb.Empty{})
	if err == nil {
		t.Errorf("gRPC call succeeded?!")
	}
}

// Tests that connecting to to a unix domain socket with a listener, but without
// a server to handle connections fails within reasonable time (currently 0.5s).
func TestConnectionFailureNoServer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	t.Cleanup(cancel)

	startC := make(chan struct{})
	socket, err := startFakeServer(t, WithDelayStartUntil(startC))
	if err != nil {
		t.Fatalf("failed to setup the fake agent gRPC server: %v", err)
	}

	conn, err := createClient("unix:" + socket)
	if err != nil {
		t.Fatalf("failed to create the client: %v", err)
	}

	client := pb.NewFQDNProxyAgentClient(conn)

	// Total timeout of these two calls should be MinConnectionTimeout, ~500ms.
	// Give it some CI slack, but after all we're trying to test for "liveness"
	// here.
	sctx, cancel := context.WithTimeout(ctx, time.Second*2)
	t.Cleanup(cancel)

	// We want these to fail quickly if there's no connectivity to the agent,
	// and they should all fail within _one_ MinConnectionTimeout, not each wait
	// for a timeout.
	for i := range 10 {
		_, err = client.GetAllRules(sctx, &pb.Empty{})
		if err == nil {
			t.Errorf("%vth gRPC call succeeded when it should have failed", i)
		}
	}

	if sctx.Err() != nil {
		t.Errorf("context error before RPC calls completed: %v", ctx.Err())
	}

	// But once the server starts, there should be only a "small" delay.
	close(startC)

	// Once the server is up, account for a bit of time in backoff.
	tctx, cancel := context.WithTimeout(ctx, time.Millisecond*250)
	t.Cleanup(cancel)
	// Using wait for ready here to avoid retries and the race of waiting serving to start.
	_, err = client.GetAllRules(tctx, &pb.Empty{}, grpc.WaitForReady(true))
	if err != nil {
		t.Errorf("call should succeed after server started, but failed with: %v", err)
	}
}

func TestAgentCycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	t.Cleanup(cancel)

	stopC := make(chan struct{})
	socket, err := startFakeServer(t, WithStopServerOnClose(stopC))
	if err != nil {
		t.Fatalf("failed to setup the fake agent gRPC server: %v", err)
	}

	conn, err := createClient("unix:" + socket)
	if err != nil {
		t.Fatalf("failed to create the client: %v", err)
	}

	client := pb.NewFQDNProxyAgentClient(conn)

	_, err = client.GetAllRules(ctx, &pb.Empty{})
	if err != nil {
		t.Errorf("gRPC call failed before killing server: %v", err)
	}

	close(stopC)

	for ctx.Err() == nil {
		// Wait until socket is removed
		if f, err := os.Open(socket); errors.Is(err, fs.ErrNotExist) {
			break
		} else {
			f.Close()
		}
		time.Sleep(time.Millisecond * 50)
	}
	if ctx.Err() != nil {
		t.Fatalf("timed out waiting for socket removal: %v", ctx.Err())
	}

	for i := range 10 {
		_, err = client.GetAllRules(ctx, &pb.Empty{})
		if err == nil {
			t.Errorf("%vth gRPC call succeeded when it should have failed", i)
		}
	}

	// Need to make sure that the server listens on the same path as the old one.
	_, err = startFakeServer(t, WithFixedSocketPath(socket))
	if err != nil {
		t.Fatalf("failed to start new fake agent gRPC server: %v", err)
	}

	_, err = client.GetAllRules(ctx, &pb.Empty{}, grpc.WaitForReady(true))
	if err != nil {
		t.Errorf("gRPC call failed after server restart: %v", err)
	}
}

func TestLookupSecIDByIP(t *testing.T) {
	type ipIdentity struct {
		addr     netip.Addr
		identity identity.NumericIdentity
	}
	tests := []struct {
		name                   string
		disableOfflineMode     bool
		ipIdentities           []ipIdentity
		lookupAddr             netip.Addr
		exists                 bool
		expectedID             identity.NumericIdentity
		fakeIPCacheLookupCalls []fakeIPCacheCall
	}{
		{
			name: "world ipv4 identity",
			ipIdentities: []ipIdentity{
				{
					addr:     netip.MustParseAddr("172.217.4.78"),
					identity: identity.ReservedIdentityWorld,
				},
				{
					addr:     netip.MustParseAddr("10.0.0.1"),
					identity: identity.ReservedIdentityKubeAPIServer,
				},
			},
			lookupAddr: netip.MustParseAddr("172.217.4.78"),
			exists:     true,
			expectedID: identity.ReservedIdentityWorld,
			fakeIPCacheLookupCalls: []fakeIPCacheCall{
				{
					addr:     netip.MustParseAddr("172.217.4.78"),
					identity: identity.ReservedIdentityWorld,
				},
			},
		},
		{
			name: "world ipv6 identity",
			ipIdentities: []ipIdentity{
				{
					addr:     netip.MustParseAddr("2607:f8b0:4002:c06::8b"),
					identity: identity.ReservedIdentityWorld,
				},
				{
					addr:     netip.MustParseAddr("fde9:0d7d:3d43:5c63::130b"),
					identity: identity.ReservedIdentityKubeAPIServer,
				},
			},
			lookupAddr: netip.MustParseAddr("2607:f8b0:4002:c06::8b"),
			exists:     true,
			expectedID: identity.ReservedIdentityWorld,
			fakeIPCacheLookupCalls: []fakeIPCacheCall{
				{
					addr:     netip.MustParseAddr("2607:f8b0:4002:c06::8b"),
					identity: identity.ReservedIdentityWorld,
				},
			},
		},
		{
			name: "world ipv4 identity dual stack",
			ipIdentities: []ipIdentity{
				{
					addr:     netip.MustParseAddr("2607:f8b0:4002:c06::8b"),
					identity: identity.ReservedIdentityWorldIPv6,
				},
				{
					addr:     netip.MustParseAddr("172.217.4.78"),
					identity: identity.ReservedIdentityWorldIPv4,
				},
			},
			lookupAddr: netip.MustParseAddr("172.217.4.78"),
			exists:     true,
			expectedID: identity.ReservedIdentityWorldIPv4,
			fakeIPCacheLookupCalls: []fakeIPCacheCall{
				{
					addr:     netip.MustParseAddr("172.217.4.78"),
					identity: identity.ReservedIdentityWorldIPv4,
				},
			},
		},
		{
			name: "world ipv6 identity dual stack",
			ipIdentities: []ipIdentity{
				{
					addr:     netip.MustParseAddr("2607:f8b0:4002:c06::8b"),
					identity: identity.ReservedIdentityWorldIPv6,
				},
				{
					addr:     netip.MustParseAddr("172.217.4.78"),
					identity: identity.ReservedIdentityWorldIPv4,
				},
			},
			lookupAddr: netip.MustParseAddr("2607:f8b0:4002:c06::8b"),
			exists:     true,
			expectedID: identity.ReservedIdentityWorldIPv6,
			fakeIPCacheLookupCalls: []fakeIPCacheCall{
				{
					addr:     netip.MustParseAddr("2607:f8b0:4002:c06::8b"),
					identity: identity.ReservedIdentityWorldIPv6,
				},
			},
		},
		{
			name: "local identity",
			ipIdentities: []ipIdentity{
				{
					addr:     netip.MustParseAddr("172.217.4.78"),
					identity: identity.MaxLocalIdentity,
				},
			},
			lookupAddr: netip.MustParseAddr("172.217.4.78"),
			exists:     true,
			expectedID: identity.MaxLocalIdentity,
			fakeIPCacheLookupCalls: []fakeIPCacheCall{
				{
					addr:     netip.MustParseAddr("172.217.4.78"),
					identity: identity.MaxLocalIdentity,
				},
			},
		},
		{
			name: "no agent support",
			ipIdentities: []ipIdentity{
				{
					addr:     netip.MustParseAddr("172.217.4.78"),
					identity: identity.MaxLocalIdentity,
				},
			},
			lookupAddr: netip.MustParseAddr("172.217.4.78"),
			exists:     true,
			expectedID: identity.MaxLocalIdentity,
		},
		{
			name:               "no offline mode support",
			disableOfflineMode: true,
			ipIdentities: []ipIdentity{
				{
					addr:     netip.MustParseAddr("172.217.4.78"),
					identity: identity.MaxLocalIdentity,
				},
			},
			lookupAddr: netip.MustParseAddr("172.217.4.78"),
			exists:     true,
			expectedID: identity.MaxLocalIdentity,
		},
		{
			name: "does not exist",
			ipIdentities: []ipIdentity{
				{
					addr:     netip.MustParseAddr("172.217.4.78"),
					identity: identity.MaxLocalIdentity,
				},
			},
			lookupAddr: netip.MustParseAddr("172.217.4.79"),
			exists:     false,
			fakeIPCacheLookupCalls: []fakeIPCacheCall{
				{
					addr: netip.MustParseAddr("172.217.4.79"),
					err:  ebpf.ErrKeyNotExist,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ipIDMap := make(map[netip.Addr]*pb.Identity)
			ipEndpointMap := make(map[netip.Addr]identity.NumericIdentity)
			for _, ipID := range tt.ipIdentities {
				ipIDMap[ipID.addr] = &pb.Identity{ID: uint32(ipID.identity)}
				ipEndpointMap[ipID.addr] = ipID.identity
			}
			socket, err := startFakeServer(t, WithIPIdentites(ipIDMap))
			if err != nil {
				t.Fatalf("failed to setup the fake agent gRPC server: %v", err)
			}
			conn, err := createClient("unix:" + socket)
			if err != nil {
				t.Fatalf("failed to create the client: %v", err)
			}

			client := &fqdnAgentClient{
				FQDNProxyAgentClient: pb.NewFQDNProxyAgentClient(conn),
				conn:                 conn,
			}

			logger := hivetest.Logger(t)

			fIPC := &fakeIPCache{
				logger:        logger,
				ipEndpointMap: ipEndpointMap,
			}

			cfg := Config{EnableOfflineMode: !tt.disableOfflineMode} //nolint:exhaustruct

			remoteNameManager, _ := newRemoteNameManager(remoteNameManagerParams{Logger: logger, Cfg: cfg, Client: client, IPCache: fIPC})
			go func() {
				remoteNameManager.streamSelectors(t.Context(), nil)
			}()
			secID, exists := remoteNameManager.LookupSecIDByIP(tt.lookupAddr)
			if tt.exists != exists {
				expected := ""
				got := "does"
				if tt.exists {
					expected = " not"
				}
				if !exists {
					got += " not"
				}
				t.Fatalf("Expected identity to%s exist, but it %s", expected, got)
			}
			if tt.exists {
				if tt.expectedID != secID.ID {
					t.Fatalf("Expected identity %d, but got %d", tt.expectedID, secID.ID)
				}
				if !tt.disableOfflineMode {
					if len(fIPC.lookupCalls) == 0 {
						t.Fatal("Expected a lookup call to the bpf ip cache, but got none")
					}
					call := fIPC.lookupCalls[0]
					if tt.lookupAddr != call.addr {
						t.Fatalf("Expected lookup address of %s, but got %s", tt.lookupAddr, call.addr)
					}
				} else {
					if len(fIPC.lookupCalls) > 0 {
						t.Fatalf("Expected no lookup calls to the bpf ip cache, but got %d", len(fIPC.lookupCalls))
					}
				}
			}
			if len(tt.fakeIPCacheLookupCalls) > 0 {
				if len(fIPC.lookupCalls) != len(tt.fakeIPCacheLookupCalls) {
					t.Fatalf("expected ipcache lookup calls %+v, but got %+v", tt.fakeIPCacheLookupCalls, fIPC.lookupCalls)
				}
				for i := range tt.fakeIPCacheLookupCalls {
					expected := tt.fakeIPCacheLookupCalls[i]
					got := fIPC.lookupCalls[i]
					if expected.addr != got.addr {
						t.Fatalf("expected ipcache lookup call argument of %s, but got %s", expected.addr, got.addr)
					}
					if expected.identity != got.identity {
						t.Fatalf("expected ipcache lookup return value of %+v, but got %+v", expected.identity, got.identity)
					}
					if !errors.Is(got.err, expected.err) {
						t.Fatalf("expected error %v from ipcache lookup call, but got %v", expected.err, got.err)
					}
				}
			}
		})
	}
}

func startFakeServer(t *testing.T, opts ...fakeServerOpt) (string, error) {
	t.Helper()

	fakeImpl := &fakeAgent{
		ctx:        t.Context(),
		socketPath: filepath.Join(t.TempDir(), "dnsproxy-test.socket"),
	}
	for _, o := range opts {
		o(fakeImpl)
	}

	if fakeImpl.stopServerOn != nil {
		var cancel context.CancelFunc
		fakeImpl.ctx, cancel = context.WithCancel(fakeImpl.ctx)
		go func() {
			<-fakeImpl.stopServerOn
			cancel()
		}()
	}

	grpcServer := grpc.NewServer()
	pb.RegisterFQDNProxyAgentServer(grpcServer, fakeImpl)

	lis, err := net.Listen("unix", fakeImpl.socketPath)
	if err != nil {
		t.Errorf("failed to listen: %v", err)
		return "", err
	}
	go func() {
		if fakeImpl.startServerOn != nil {
			<-fakeImpl.startServerOn
		}
		err = grpcServer.Serve(lis)
		if err != nil {
			t.Logf("Server stopped with err %v", err)
		}
	}()

	go func() {
		<-fakeImpl.ctx.Done()
		grpcServer.Stop()
		lis.Close()
		os.Remove(fakeImpl.socketPath)
	}()

	return fakeImpl.socketPath, nil
}

type fakeServerOpt func(*fakeAgent)

func WithDelayStartUntil(c chan struct{}) fakeServerOpt {
	return func(fa *fakeAgent) {
		fa.startServerOn = c
	}
}

func WithStopServerOnClose(c chan struct{}) fakeServerOpt {
	return func(fa *fakeAgent) {
		fa.stopServerOn = c
	}
}

func WithFixedSocketPath(p string) fakeServerOpt {
	return func(fa *fakeAgent) {
		fa.socketPath = p
	}
}

func WithIPIdentites(ipIDMap map[netip.Addr]*pb.Identity) fakeServerOpt {
	return func(fa *fakeAgent) {
		fa.ipIdentityMap = ipIDMap
	}
}

// WithSelectorIdentities is a shorthand method that takes an fqdn selector
// and creates a world-ipv4 and world-ipv6 identity. The numeric identities start at 1001.
func WithSelectorIdentities(patterns ...string) fakeServerOpt {
	return func(fa *fakeAgent) {
		fa.selectorPatterns = patterns

		id := identity.NumericIdentity(1001)
		fa.identities = make(map[identity.NumericIdentity]labels.Labels, len(patterns)*2)

		for _, pattern := range patterns {
			sel := api.FQDNSelector{MatchPattern: pattern}
			lbl := sel.IdentityLabel()

			lbls4 := labels.NewFrom(labels.LabelWorldIPv4)
			lbls4[lbl.Key] = lbl
			fa.identities[id] = lbls4
			id++

			lbls6 := labels.NewFrom(labels.LabelWorldIPv6)
			lbls6[lbl.Key] = lbl
			fa.identities[id] = lbls6
			id++
		}
	}
}

type fakeAgent struct {
	ctx context.Context

	pb.UnimplementedFQDNProxyAgentServer

	startServerOn chan struct{}
	stopServerOn  chan struct{}

	socketPath string

	ipIdentityMap map[netip.Addr]*pb.Identity

	selectorPatterns []string
	identities       map[identity.NumericIdentity]labels.Labels
}

func (*fakeAgent) GetAllRules(context.Context, *pb.Empty) (*pb.RestoredRulesMap, error) {
	return &pb.RestoredRulesMap{}, nil
}

func (fa *fakeAgent) LookupSecurityIdentityByIP(ctx context.Context, in *pb.FQDN_IP) (*pb.Identity, error) {
	addr, ok := netip.AddrFromSlice(in.IP)
	if !ok {
		return nil, fmt.Errorf("IP, %v, is malformed", in.IP)
	}
	ident, ok := fa.ipIdentityMap[addr]
	if !ok {
		return nil, fmt.Errorf("identity for IP, %v, not found", addr)
	}
	return ident, nil
}

func (fa *fakeAgent) SubscribeSelectors(_ *pb.Empty, stream grpc.ServerStreamingServer[pb.SelectorUpdate]) error {
	for _, sel := range fa.selectorPatterns {
		err := stream.Send(&pb.SelectorUpdate{
			FqdnSelector: &pb.FQDNSelectorUpdate{
				Type:     pb.UpdateType_UPDATETYPE_UPSERT,
				Selector: &pb.FQDNSelector{MatchPattern: sel},
			},
		})
		if err != nil {
			return err
		}
	}
	err := stream.Send(&pb.SelectorUpdate{
		FqdnSelector: &pb.FQDNSelectorUpdate{
			Type: pb.UpdateType_UPDATETYPE_BOOKMARK,
		},
	})
	if err != nil {
		return err
	}

	for nid, lbls := range fa.identities {
		err := stream.Send(&pb.SelectorUpdate{
			FqdnIdentity: &pb.FQDNIdentityUpdate{
				Type:     pb.UpdateType_UPDATETYPE_UPSERT,
				Labels:   fromLabels(lbls),
				Identity: uint64(nid),
			},
		})
		if err != nil {
			return err
		}
	}
	err = stream.Send(&pb.SelectorUpdate{
		FqdnIdentity: &pb.FQDNIdentityUpdate{
			Type: pb.UpdateType_UPDATETYPE_BOOKMARK,
		},
	})
	if err != nil {
		return err
	}

	// idle forever
	<-fa.ctx.Done()
	return fa.ctx.Err()
}

type fakeIPCache struct {
	logger *slog.Logger

	ipEndpointMap map[netip.Addr]identity.NumericIdentity

	lookupCalls []fakeIPCacheCall
	writeCalls  []fakeIPCacheCall
}

func newFakeIPCache(logger *slog.Logger) *fakeIPCache {
	return &fakeIPCache{
		logger:        logger,
		ipEndpointMap: make(map[netip.Addr]identity.NumericIdentity),
	}
}

type fakeIPCacheCall struct {
	addr     netip.Addr
	identity identity.NumericIdentity
	err      error
}

func (f *fakeIPCache) lookup(addr netip.Addr) (identity.NumericIdentity, error) {
	f.logger.Debug("fake BPF ipcache map lookup", logfields.Address, addr)
	call := fakeIPCacheCall{
		addr: addr,
	}
	id, ok := f.ipEndpointMap[addr]
	if !ok {
		call.err = ebpf.ErrKeyNotExist
	} else {
		call.identity = id
	}
	f.lookupCalls = append(f.lookupCalls, call)
	return call.identity, call.err
}

func (f *fakeIPCache) write(addr netip.Addr, identity identity.NumericIdentity) error {
	f.logger.Debug("fake BPF ipcache map write",
		logfields.Address, addr,
		logfields.Identity, identity,
	)
	call := fakeIPCacheCall{
		addr:     addr,
		identity: identity,
	}
	f.ipEndpointMap[addr] = identity
	f.writeCalls = append(f.writeCalls, call)
	return nil
}

func (f *fakeIPCache) getInfo() (*ipcache.Map, time.Time, bool) {
	return nil, time.Time{}, false
}

func fromLabels(lbls labels.Labels) []*pb.Label {
	res := make([]*pb.Label, 0, len(lbls))
	for _, l := range lbls {
		res = append(res, &pb.Label{
			Key:    l.Key,
			Value:  l.Value,
			Source: l.Source,
		})
	}
	return res
}
