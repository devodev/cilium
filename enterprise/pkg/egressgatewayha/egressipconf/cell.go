//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package egressipconf

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/enterprise/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/gneigh"
	"github.com/cilium/cilium/pkg/option"
)

// Cell manages the configuration of Egress IPs
// on behalf of the IsovalentEgressGatewayPolicies.
var Cell = cell.Group(
	cell.ProvidePrivate(tables.NewEgressIPTable),
	cell.ProvidePrivate(startReconciler),
	cell.Invoke(newDevicesWatcher),
)

func startReconciler(
	params reconciler.Params,
	table statedb.RWTable[*tables.EgressIPEntry],
	dCfg *option.DaemonConfig,
	gneighSender gneigh.Sender,
) (reconciler.Reconciler[*tables.EgressIPEntry], error) {
	if !dCfg.EnableIPv4EgressGatewayHA {
		return nil, nil
	}

	reconciler, err := reconciler.Register(
		params,
		table,
		(*tables.EgressIPEntry).Clone,
		(*tables.EgressIPEntry).SetStatus,
		(*tables.EgressIPEntry).GetStatus,
		newOps(params.Log, gneighSender),
		nil,
	)
	return reconciler, err
}
