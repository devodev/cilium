//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pncfg "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/grpc/config"
	"github.com/cilium/cilium/pkg/crypto/certloader"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type (
	// ListenerFactory is the type of the function returning the listeners the
	// server accepts connections on.
	ListenerFactory func(ctx context.Context) ([]net.Listener, error)

	// Registrar registers a service on the shared gRPC server.
	Registrar func(*grpc.Server)
)

type serverParams struct {
	cell.In

	Logger     *slog.Logger
	JobGroup   job.Group
	Shutdowner hive.Shutdowner

	Config  pncfg.Config
	Factory ListenerFactory

	TLSConfigPromise config.ServerConfigPromise

	Registrars []Registrar `group:"privnet-grpc-registrars"`
}

func registerServer(in serverParams) {
	if !in.Config.EnabledAsBridge() || len(in.Registrars) == 0 {
		return
	}

	in.JobGroup.Add(
		job.OneShot("server-start", func(ctx context.Context, health cell.Health) error {
			gsrv, err := newGRPCServer(ctx, in.TLSConfigPromise, in.Registrars)
			if err != nil {
				return err
			}

			listeners, err := in.Factory(ctx)
			if err != nil {
				return fmt.Errorf("cannot create private networks gRPC listeners: %w", err)
			}

			// Add jobs for the listeners.
			for _, lis := range listeners {
				in.JobGroup.Add(
					job.OneShot(fmt.Sprintf("server-%s", lis.Addr()),
						func(ctx context.Context, health cell.Health) error {
							addr := lis.Addr().String()
							in.Logger.Info("Starting privnet gRPC server", logfields.Address, addr)
							health.OK("Serving " + addr)
							return gsrv.Serve(lis)
						},
						job.WithShutdown()))
			}

			// Finally add a job to tear down the server. This will be stopped before the
			// listener jobs added above.
			in.JobGroup.Add(
				job.OneShot("server-stop",
					func(ctx context.Context, health cell.Health) error {
						<-ctx.Done()
						gsrv.Stop()
						return nil
					}))

			return nil
		}))
}

func newGRPCServer(ctx context.Context, promise config.ServerConfigPromise, registrars []Registrar) (*grpc.Server, error) {
	serverOpts := []grpc.ServerOption{grpc.WaitForHandlers(true)}

	if promise != nil {
		tlsConfig, err := promise.Await(ctx)
		if err != nil {
			return nil, fmt.Errorf("awaiting private networks gRPC TLS config: %w", err)
		}
		if tlsConfig != nil {
			serverOpts = append(serverOpts, grpc.Creds(credentials.NewTLS(serverTLSConfig(tlsConfig))))
		}
	}

	gsrv := grpc.NewServer(serverOpts...)
	for _, register := range registrars {
		if register != nil {
			register(gsrv)
		}
	}

	return gsrv, nil
}

func serverTLSConfig(cfg certloader.ServerConfigBuilder) *tls.Config {
	// NOTE: gosec is unable to resolve the constant and warns about "TLS
	// MinVersion too low".
	return cfg.ServerConfig(&tls.Config{ //nolint:gosec
		MinVersion: tls.VersionTLS13,
	})
}
