//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package lb

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/enterprise/pkg/lb/envoyhealthcheck"
	"github.com/cilium/cilium/enterprise/pkg/lb/envoyhealthsync"
	flowlogs "github.com/cilium/cilium/enterprise/pkg/lb/flowlogs"
	"github.com/cilium/cilium/enterprise/pkg/lb/metrics"
	"github.com/cilium/cilium/enterprise/pkg/lb/t2servicehealth"
)

var Cell = cell.Group(
	flowlogs.Cell,
	metrics.Cell,
	envoyhealthsync.Cell,
	envoyhealthcheck.Cell,
	t2servicehealth.Cell,
)
