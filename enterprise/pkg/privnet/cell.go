//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package privnet

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/enterprise/pkg/privnet/addressing"
	pncfg "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/dhcp"
	"github.com/cilium/cilium/enterprise/pkg/privnet/diagnostics"
	"github.com/cilium/cilium/enterprise/pkg/privnet/endpoints"
	"github.com/cilium/cilium/enterprise/pkg/privnet/grpc"
	health "github.com/cilium/cilium/enterprise/pkg/privnet/health/grpc"
	"github.com/cilium/cilium/enterprise/pkg/privnet/migration"
	"github.com/cilium/cilium/enterprise/pkg/privnet/policy"
	"github.com/cilium/cilium/enterprise/pkg/privnet/reconcilers"
	statuscollector "github.com/cilium/cilium/enterprise/pkg/privnet/status/collector"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
)

var Cell = cell.Module(
	"private-networks",
	"Support for Private Networks",

	pncfg.ValidatingCell,
	tables.DHCPLeasesCell,
	reconcilers.Cell,
	endpoints.Cell,
	grpc.Cell,
	health.Cell,
	addressing.Cell,
	statuscollector.Cell,
	policy.Cell,
	dhcp.Cell,
	diagnostics.Cell,
	migration.Cell,
)
