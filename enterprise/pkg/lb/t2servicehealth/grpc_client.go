// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package t2servicehealth

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	api "github.com/cilium/cilium/enterprise/pkg/lb/t2servicehealth/api/v1"
)

func DialGRPC(target string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	opts = append([]grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}, opts...)
	return grpc.NewClient(target, opts...)
}

func NewGRPCClient(conn grpc.ClientConnInterface) api.ServiceHealthClient {
	return api.NewServiceHealthClient(conn)
}
