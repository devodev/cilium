//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package client

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	health "google.golang.org/grpc/health"
	grpc_health_v1 "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/cilium/cilium/enterprise/pkg/privnet/grpc/config"
	privnettestutils "github.com/cilium/cilium/enterprise/pkg/privnet/testutils"
	"github.com/cilium/cilium/pkg/crypto/certloader"
	"github.com/cilium/cilium/pkg/promise"
)

func TestConnFactory(t *testing.T) {
	tests := []struct {
		name    string
		withTLS bool
	}{
		{"insecure", false},
		{"secure", true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			log := hivetest.Logger(t)
			lc := hivetest.Lifecycle(t)

			resolver, tlsPromise := promise.New[*certloader.WatchedClientConfig]()
			var srv *grpc.Server
			if test.withTLS {
				paths, _ := privnettestutils.WriteTLSFiles(t, privnettestutils.TLSConfig{
					CACommonName:   "privnet-client-test-ca",
					ServerDNSNames: []string{"remote-cluster"},
				})
				clientTLSConfig, err := certloader.NewWatchedClientConfig(log, []string{paths.CAFile}, "", "")
				require.NoError(t, err)
				t.Cleanup(clientTLSConfig.Stop)
				resolver.Resolve(clientTLSConfig)

				serverCertificate, err := tls.LoadX509KeyPair(paths.ServerCertFile, paths.ServerKeyFile)
				require.NoError(t, err)
				srv = grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{ //nolint:gosec
					Certificates: []tls.Certificate{serverCertificate},
					MinVersion:   tls.VersionTLS13,
				})))
			} else {
				srv = grpc.NewServer()
				resolver.Resolve(nil)
			}
			t.Cleanup(srv.Stop)

			healthSrv := health.NewServer()
			healthSrv.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
			grpc_health_v1.RegisterHealthServer(srv, healthSrv)

			lis, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			t.Cleanup(func() { _ = lis.Close() })

			go func() {
				_ = srv.Serve(lis)
			}()

			port := uint16(lis.Addr().(*net.TCPAddr).Port)
			factory := NewDefaultConnFactory(connFactoryParams{
				Lifecycle:        lc,
				TLSConfigPromise: config.ClientConfigPromise(tlsPromise),
			})

			conn, err := factory(t.Context(),
				"remote-cluster",
				"remote-node",
				netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", port)),
			)
			require.NoError(t, err)
			t.Cleanup(func() { _ = conn.Close() })

			resp, err := grpc_health_v1.NewHealthClient(conn).Check(t.Context(), &grpc_health_v1.HealthCheckRequest{})
			require.NoError(t, err)
			require.Equal(t, grpc_health_v1.HealthCheckResponse_SERVING, resp.GetStatus())
		})
	}
}
