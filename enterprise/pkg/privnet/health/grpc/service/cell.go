//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package service

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"google.golang.org/grpc"

	pncfg "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	api "github.com/cilium/cilium/enterprise/pkg/privnet/grpc/api/v1"
	grpcserver "github.com/cilium/cilium/enterprise/pkg/privnet/grpc/server"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
)

var Cell = cell.Group(
	cell.ProvidePrivate(
		// Provides the ReadWrite active networks table.
		tables.NewActiveNetworksTable,

		// Provides the health service implementation.
		newHealth,
	),

	cell.Provide(
		// Provides the ReadOnly active networks table.
		statedb.RWTable[tables.ActiveNetwork].ToTable,

		// Registers the health service on the shared gRPC server.
		func(svc *health, cfg pncfg.Config) grpcserver.RegistrarOut {
			if !cfg.EnabledAsBridge() {
				return grpcserver.RegistrarOut{}
			}

			return grpcserver.RegistrarOut{
				Registrar: func(gsrv *grpc.Server) {
					api.RegisterHealthServer(gsrv, svc)
					api.RegisterNetworksServer(gsrv, svc)
				},
			}
		},
	),

	cell.Invoke(
		// Registers the job to GC stale entries from the active networks table.
		(*health).registerGCer,
	),
)
