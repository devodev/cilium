// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package export

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"

	timescapeexporter "github.com/isovalent/hubble-timescape/exporter"
	"google.golang.org/grpc/credentials"

	"github.com/cilium/cilium/pkg/crypto/certloader"
	"github.com/cilium/cilium/pkg/lock"
)

const minTimescapeTLSVersion uint16 = tls.VersionTLS13

func newTimescapeCredentialsProvider(
	promise timescapeTLSConfigPromise,
) timescapeexporter.TransportCredentialsProvider {
	return func(ctx context.Context) (credentials.TransportCredentials, error) {
		config, err := promise.Await(ctx)
		if err != nil {
			return nil, fmt.Errorf("get watched TLS config: %w", err)
		}
		if config == nil {
			return nil, errors.New("watched TLS config is nil")
		}
		return newTimescapeTLSCredentials(config), nil
	}
}

// timescapeTLSCredentials reloads Cilium's watched TLS configuration before
// each new gRPC connection.
type timescapeTLSCredentials struct {
	credentials.TransportCredentials

	mu       lock.Mutex
	baseConf *tls.Config
	config   certloader.ClientConfigBuilder
}

func newTimescapeTLSCredentials(config certloader.ClientConfigBuilder) *timescapeTLSCredentials {
	// The minimum version is a constant, but gosec cannot resolve it.
	baseConf := &tls.Config{MinVersion: minTimescapeTLSVersion} //nolint:gosec
	return &timescapeTLSCredentials{
		TransportCredentials: credentials.NewTLS(config.ClientConfig(baseConf)),
		baseConf:             baseConf,
		config:               config,
	}
}

func (c *timescapeTLSCredentials) ClientHandshake(
	ctx context.Context,
	authority string,
	conn net.Conn,
) (net.Conn, credentials.AuthInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.TransportCredentials = credentials.NewTLS(c.config.ClientConfig(c.baseConf))
	return c.TransportCredentials.ClientHandshake(ctx, authority, conn)
}

func (c *timescapeTLSCredentials) Clone() credentials.TransportCredentials {
	c.mu.Lock()
	defer c.mu.Unlock()
	return &timescapeTLSCredentials{
		TransportCredentials: c.TransportCredentials.Clone(),
		baseConf:             c.baseConf.Clone(),
		config:               c.config,
	}
}
