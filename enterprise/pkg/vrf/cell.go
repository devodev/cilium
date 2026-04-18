//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package vrf

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/enterprise/pkg/vrf/config"
)

var Cell = cell.Module(
	"vrf",
	"virtual routing and forwarding control-plane components",
	cell.Config(config.DefaultConfig),
	cell.Provide(NewVRFTableAndReflector),
	cell.Provide(NewVRFMap),
	cell.Provide(registerController),
)
