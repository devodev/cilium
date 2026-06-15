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
	"context"
	"crypto/tls"
	"net/netip"

	"github.com/cilium/hive/cell"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/cilium/cilium/enterprise/pkg/privnet/grpc/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/crypto/certloader"
)

type (
	// ConnFactoryFn is the type of the function returning a grpc client connection
	// for a given target node.
	ConnFactoryFn func(ctx context.Context, cluster tables.ClusterName, node tables.NodeName, addrPort netip.AddrPort) (*grpc.ClientConn, error)
)

type connFactoryParams struct {
	cell.In

	Lifecycle        cell.Lifecycle
	TLSConfigPromise config.ClientConfigPromise
}

func NewDefaultConnFactory(params connFactoryParams) ConnFactoryFn {
	return func(ctx context.Context, cluster tables.ClusterName, node tables.NodeName, addrPort netip.AddrPort) (*grpc.ClientConn, error) {
		var tlsConfig *certloader.WatchedClientConfig
		if params.TLSConfigPromise != nil {
			var err error
			tlsConfig, err = params.TLSConfigPromise.Await(ctx)
			if err != nil {
				return nil, err
			}
		}
		return grpc.NewClient(
			addrPort.String(),
			transportCredentials(string(cluster), tlsConfig))
	}
}

func transportCredentials(serverName string, tlsConfig *certloader.WatchedClientConfig) grpc.DialOption {
	if tlsConfig == nil {
		return grpc.WithTransportCredentials(insecure.NewCredentials())
	}

	// NOTE: gosec is unable to resolve the constant and warns about "TLS
	// MinVersion too low".
	return grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig.ClientConfig(&tls.Config{ //nolint:gosec
		ServerName: serverName,
		MinVersion: tls.VersionTLS13,
	})))
}
