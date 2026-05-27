// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package instance

import (
	"context"
	"log/slog"

	"github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	ossTypes "github.com/cilium/cilium/pkg/bgp/types"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
)

// EnterpriseBGPInstance is a container for providing interface with underlying router implementation.
type EnterpriseBGPInstance struct {
	Name                string
	Global              ossTypes.BGPGlobal
	CancelCtx           context.CancelFunc
	Config              *v1.IsovalentBGPNodeInstance
	Router              types.EnterpriseRouter
	stateNotificationCh chan struct{}
}

func (i *EnterpriseBGPInstance) NotifyStateChange() {
	select {
	case i.stateNotificationCh <- struct{}{}:
	default:
	}
}

// NewEnterpriseBGPInstance will start an underlying BGP instance using the provided types.RouterProvider,
// utilizing ossTypes.ServerParameters for its initial configuration.
//
// The returned BGPInstance has a nil IsovalentBGPNodeInstance config, and is
// ready to be provided to ReconcileBGPConfig.
//
// Canceling the provided context will kill the BGP instance along with calling the
// underlying Router's Stop() method.
func NewEnterpriseBGPInstance(ctx context.Context, routerProvider types.EnterpriseRouterProvider, log *slog.Logger, name string, params ossTypes.ServerParameters) (*EnterpriseBGPInstance, error) {
	routerCtx, cancel := context.WithCancel(ctx)
	s, err := routerProvider.NewEnterpriseRouter(routerCtx, log, params)
	if err != nil {
		cancel()
		return nil, err
	}

	return &EnterpriseBGPInstance{
		Name:                name,
		Global:              params.Global,
		CancelCtx:           cancel,
		Config:              nil,
		Router:              s,
		stateNotificationCh: params.StateNotification,
	}, nil
}
