// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package privnet

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/enterprise/operator/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/operator/pkg/privnet/externalendpoints"
	"github.com/cilium/cilium/enterprise/operator/pkg/privnet/reconcilers"
	"github.com/cilium/cilium/enterprise/operator/pkg/privnet/webhook"
	"github.com/cilium/cilium/enterprise/pkg/privnet/policy/labelfilters"
	"github.com/cilium/cilium/operator/cmd"
)

var Cell = cell.Module(
	"private-networks",
	"Support for Private Networks",

	// Cells that do not depend on leader election.
	config.Cell,
	reconcilers.Cell,
	webhook.Cell,
	labelfilters.Cell,

	// Cells that do depend on leader election.
	cell.Decorate(
		func(lc *cmd.LeaderLifecycle) cell.Lifecycle { return lc },

		reconcilers.LeaderCell,
		externalendpoints.Cell,
	),
)
