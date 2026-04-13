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

	fakeBgp "github.com/cilium/cilium/pkg/bgp/fake"
	"github.com/cilium/cilium/pkg/bgp/types"
)

type FakeRouterProvider struct{}

func NewFakeRouterProvider() types.RouterProvider {
	return &FakeRouterProvider{}
}

func (p *FakeRouterProvider) NewRouter(ctx context.Context, logger *slog.Logger, params types.ServerParameters) (types.Router, error) {
	return fakeBgp.NewFakeRouter(), nil
}
