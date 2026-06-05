// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package api

import (
	"github.com/cilium/hive/cell"

	restapi "github.com/cilium/cilium/api/v1/server/restapi/bgp"
	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/agent"
	"github.com/cilium/cilium/pkg/option"
)

var Cell = cell.Group(
	cell.DecorateAll(replaceHandler[restapi.GetBgpPeersHandler](NewGetPeerHandler)),
	cell.DecorateAll(replaceHandler[restapi.GetBgpRoutePoliciesHandler](NewGetRoutePoliciesHandler)),
	cell.DecorateAll(replaceHandler[restapi.GetBgpRoutesHandler](NewGetRoutesHandler)),
)

// Replace all OSS API handlers with the enterprise equivalent backed by the
// enterprise Controller when only enterprise BGP Control Plane is enabled.
// Otherwise, return the provided handler as is.
func replaceHandler[T any](newHandler func(*agent.Controller) T) func(config.Config, *option.DaemonConfig, *agent.Controller, T) T {
	return func(conf config.Config, dc *option.DaemonConfig, c *agent.Controller, h T) T {
		if conf.Enabled && !dc.BGPControlPlaneEnabled() {
			return newHandler(c)
		}
		return h
	}
}
