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
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	grpcConfig "github.com/cilium/cilium/enterprise/pkg/privnet/grpc/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/types"
	"github.com/cilium/cilium/pkg/node"
)

// Cell constructs the privnet gRPC server. To register a service, provide a
// grpcserver.Registrar in the "privnet-grpc-registrars" group, for example:
//
//	cell.Provide(func(svc *myService) RegistrarOut {
//		return RegistrarOut{Registrar: func(gsrv *grpc.Server) {
//			api.RegisterMyServiceServer(gsrv, svc)
//		}}
//	})
//
// The shared server will invoke all registrars during startup.
var Cell = cell.Group(
	cell.ProvidePrivate(newServerConfig),
	// Provides the connection factory via hive, so that it can be
	// overridden for testing purposes.
	cell.Provide(
		func(cfg config.Config, grpcCfg grpcConfig.Config, srvCfg ServerConfig, lns *node.LocalNodeStore) ListenerFactory {
			return NewListenerFactory(ListenerConfig{
				Port:          grpcCfg.Port,
				Enabled:       srvCfg.Enabled,
				AnnotationKey: types.PrivateNetworkINBAPIServerPortAnnotation,
			}, lns)
		},
	),

	cell.Invoke(registerServer),
)

// RegistrarOut is a utility struct for providing a single [Registrar]
// to the hive.
type RegistrarOut struct {
	cell.Out

	Registrar Registrar `group:"privnet-grpc-registrars"`
}
