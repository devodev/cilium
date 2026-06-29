// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/enterprise/api/v1/models"
	"github.com/cilium/cilium/enterprise/api/v1/server/restapi/daemon"
	"github.com/cilium/cilium/enterprise/pkg/api"
	privnet "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var Cell = cell.Module(
	"enterprise-config",
	"Determines which enterprise-only configuration options are enabled",

	cell.Provide(newConfigAPIHandler),
)

type GetConfigParams struct {
	cell.In

	Logger     *slog.Logger
	PrivnetCfg privnet.Config
}

func newConfigAPIHandler(p GetConfigParams) daemon.GetConfigHandler {
	return api.NewHandler(func(rp daemon.GetConfigParams) middleware.Responder {
		p.Logger.Debug("GET /v1enterprise/config request", logfields.Params, rp)
		cfg := &models.EnterpriseDaemonConfiguration{
			PrivateNetworks: &models.PrivateNetworksConfiguration{
				Enabled: p.PrivnetCfg.Enabled,
				Mode:    p.PrivnetCfg.Mode,
			},
		}
		return daemon.NewGetConfigOK().WithPayload(cfg)

	})
}
