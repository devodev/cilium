// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package gobgp

import (
	"context"
	"log/slog"

	"github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	ossTypes "github.com/cilium/cilium/pkg/bgp/types"
)

// EnterpriseRouterProvider provides enterprise GoBGP server instances. It
// implements both the OSS RouterProvider interface and the
// EnterpriseRouterProvider interface, allowing it to be used in both contexts.
type EnterpriseRouterProvider struct{}

var (
	_ ossTypes.RouterProvider        = (*EnterpriseRouterProvider)(nil)
	_ types.EnterpriseRouterProvider = (*EnterpriseRouterProvider)(nil)
)

func NewEnterpriseRouterProvider() types.EnterpriseRouterProvider {
	return &EnterpriseRouterProvider{}
}

func NewEnterpriseRouterProviderAsOSS() ossTypes.RouterProvider {
	return &EnterpriseRouterProvider{}
}

func (p *EnterpriseRouterProvider) NewRouter(ctx context.Context, log *slog.Logger, params ossTypes.ServerParameters) (ossTypes.Router, error) {
	return NewEnterpriseGoBGPServer(ctx, log, params)
}

func (p *EnterpriseRouterProvider) NewEnterpriseRouter(ctx context.Context, log *slog.Logger, params ossTypes.ServerParameters) (types.EnterpriseRouter, error) {
	return NewEnterpriseGoBGPServer(ctx, log, params)
}
