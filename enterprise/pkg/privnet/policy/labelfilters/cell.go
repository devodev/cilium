//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package labelfilters

import (
	"github.com/cilium/hive/cell"

	pntypes "github.com/cilium/cilium/enterprise/pkg/privnet/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
)

// Cell configures a label filter to allowlist the private network CNI label.
var Cell = cell.Invoke(
	func() error {
		return labelsfilter.AppendPodLabelPrefixes(
			labels.LabelSourceCNI + labels.SourceDelimiter + pntypes.CNINetworkNameLabel,
		)
	},
)
