// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package migration

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"google.golang.org/grpc"

	pncfg "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	api "github.com/cilium/cilium/enterprise/pkg/privnet/grpc/api/v1"
	grpcserver "github.com/cilium/cilium/enterprise/pkg/privnet/grpc/server"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
)

var Cell = cell.Module(
	"private-network-migration",
	"Private Network workload migration",

	cell.Invoke(
		registerController,
		registerPIPRewriteReconciler,
	),
	cell.ProvidePrivate(
		newService,
		newCTTimestampConverter,
		tables.NewMigrationPIPRewriteTable,
	),
	cell.Provide(
		tables.NewMigrationsTable,
		statedb.RWTable[tables.Migration].ToTable,
		statedb.RWTable[tables.MigrationPIPRewrite].ToTable,

		func(cfg pncfg.Config, svc *service) grpcserver.RegistrarOut {
			if !cfg.EnabledWithLiveMigration() {
				return grpcserver.RegistrarOut{}
			}
			return grpcserver.RegistrarOut{Registrar: func(gsrv *grpc.Server) {
				api.RegisterMigrationServer(gsrv, svc)
			}}
		},
	),
)
