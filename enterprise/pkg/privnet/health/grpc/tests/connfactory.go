//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package tests

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	api "github.com/cilium/cilium/enterprise/pkg/privnet/grpc/api/v1"
	grpcclient "github.com/cilium/cilium/enterprise/pkg/privnet/grpc/client"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/time"
)

func ConnFactoryCell(path string) cell.Cell {
	return cell.Group(
		cell.Provide(
			func() *Interceptors { return &Interceptors{} },
			func(i *Interceptors) ConnFactory { return ConnFactory{path: path, interceptors: i} },
		),
	)
}

type ConnFactory struct {
	path         string
	interceptors *Interceptors
}

func (f ConnFactory) NewListener(inst Instance) (net.Listener, error) {
	path := f.Path(Instance{Cluster: inst.Cluster, Name: inst.Name})

	err := os.Remove(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("removing socket: %w", err)
	}

	lis, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listening: %w", err)
	}

	return lis, nil
}

func (f ConnFactory) ClientConnFactory() grpcclient.ConnFactoryFn {
	return func(_ context.Context, cluster tables.ClusterName, node tables.NodeName, addrPort netip.AddrPort) (*grpc.ClientConn, error) {
		return grpc.NewClient(
			"unix://"+f.Path(Instance{Cluster: cluster, Name: node}),
			grpc.WithChainStreamInterceptor(f.interceptors.Stream()...),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithConnectParams(grpc.ConnectParams{
				// Configure aggressive settings to make tests fast.
				MinConnectTimeout: 50 * time.Millisecond,
				Backoff: backoff.Config{
					BaseDelay:  20 * time.Millisecond,
					MaxDelay:   20 * time.Millisecond,
					Multiplier: 1,
					Jitter:     backoff.DefaultConfig.Jitter,
				},
			}),
		)
	}
}

func (f ConnFactory) Path(inst Instance) string {
	return path.Join(string(f.path), inst.SocketName())
}

type Interceptors struct {
	mu      lock.RWMutex
	enabled bool
	bss     []*blockingStream
}

func (i *Interceptors) Stream() []grpc.StreamClientInterceptor {
	i.mu.RLock()
	defer i.mu.RUnlock()

	if i.enabled {
		return []grpc.StreamClientInterceptor{i.stream()}
	}

	return nil
}

func (i *Interceptors) Enable() {
	i.mu.Lock()
	defer i.mu.Unlock()

	i.enabled = true
}

func (i *Interceptors) Block(inst Instance) error {
	return i.close(inst, func(bs *blockingStream) chan struct{} { return bs.block })
}

func (i *Interceptors) Unblock(inst Instance) error {
	return i.close(inst, func(bs *blockingStream) chan struct{} { return bs.unblock })
}

func (i *Interceptors) stream() grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		stream, err := streamer(ctx, desc, cc, method, opts...)
		if err != nil {
			return nil, err
		}

		return i.wrap(stream), nil
	}
}

func (i *Interceptors) wrap(cs grpc.ClientStream) grpc.ClientStream {
	i.mu.Lock()
	defer i.mu.Unlock()

	bs := &blockingStream{
		ClientStream: cs,
		block:        make(chan struct{}),
		unblock:      make(chan struct{}),
	}

	i.bss = append(i.bss, bs)
	return bs
}

func (i *Interceptors) close(inst Instance, getCh func(bs *blockingStream) chan struct{}) error {
	i.mu.RLock()
	defer i.mu.RUnlock()

	if !i.enabled {
		return errors.New("not enabled")
	}

	for _, bs := range i.bss {
		if bs.inst.Load() == inst {
			ch := getCh(bs)
			select {
			case <-ch:
			default:
				close(ch)
			}
		}
	}

	return nil
}

type blockingStream struct {
	grpc.ClientStream

	inst    atomic.Value
	block   chan struct{}
	unblock chan struct{}
}

func (bs *blockingStream) SendMsg(m any) error {
	selfer, ok := m.(interface{ GetSelf() *api.Node })
	if ok {
		self := selfer.GetSelf()
		bs.inst.Store(Instance{
			Cluster: tables.ClusterName(self.GetCluster()),
			Name:    tables.NodeName(self.GetName()),
		})
	}

	return bs.ClientStream.SendMsg(m)
}

func (bs *blockingStream) RecvMsg(m any) error {
	err := bs.ClientStream.RecvMsg(m)
	if err != nil {
		return err
	}

	select {
	case <-bs.block:
		select {
		case <-bs.unblock:
			return status.Error(codes.Aborted, "unblocked")
		case <-bs.Context().Done():
			return bs.Context().Err()
		}
	default:
		return nil
	}
}
