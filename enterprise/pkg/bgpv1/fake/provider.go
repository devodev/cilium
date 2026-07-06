// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package fake

import (
	"context"
	"log/slog"

	"github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	ossTypes "github.com/cilium/cilium/pkg/bgp/types"
)

// EnterpriseFakeRouterProvider provides enterprise fake router instances.
type EnterpriseFakeRouterProvider struct{}

var (
	_ types.EnterpriseRouterProvider = (*EnterpriseFakeRouterProvider)(nil)
	_ ossTypes.RouterProvider        = (*EnterpriseFakeRouterProvider)(nil)
)

func NewEnterpriseFakeRouterProvider() types.EnterpriseRouterProvider {
	return &EnterpriseFakeRouterProvider{}
}

func NewEnterpriseFakeRouterProviderAsOSS() ossTypes.RouterProvider {
	return &EnterpriseFakeRouterProvider{}
}

func (p *EnterpriseFakeRouterProvider) NewRouter(context.Context, *slog.Logger, ossTypes.ServerParameters) (ossTypes.Router, error) {
	return NewEnterpriseFakeRouter(), nil
}

func (p *EnterpriseFakeRouterProvider) NewEnterpriseRouter(context.Context, *slog.Logger, types.EnterpriseServerParameters) (types.EnterpriseRouter, error) {
	return NewEnterpriseFakeRouter(), nil
}
