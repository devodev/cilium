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
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"k8s.io/apimachinery/pkg/util/sets"

	enterpriseTables "github.com/cilium/cilium/enterprise/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

func newDevicesWatcher(
	logger *slog.Logger,
	health cell.Health,
	jg job.Group,
	db *statedb.DB,
	devicesTbl statedb.Table[*tables.Device],
	egressIPsTbl statedb.RWTable[*enterpriseTables.EgressIPEntry],
	dCfg *option.DaemonConfig,
) {
	if !dCfg.EnableIPv4EgressGatewayHA {
		return
	}

	devices, devicesWatch := tables.SelectedDevices(devicesTbl, db.ReadTxn())

	jg.Add(job.OneShot("egw-ipam-devices-watcher", func(ctx context.Context, _ cell.Health) error {
		for {
			ifaces := deletedEgressIfaces(devices, db, egressIPsTbl)
			if len(ifaces) > 0 {
				logger.Warn("Egress interfaces in use by Egress Gateway IPAM have been removed."+
					"This can disrupt connectivity for traffic affected by egress gateway policies and relying on the IPAM feature."+
					"Please fix the network node configuration or update IsovalentEgressGatewayPolicy to select valid egress interfaces.",
					logfields.MissingEgressInterfaces, ifaces,
				)
				health.Degraded(
					"Egress interfaces in use by Egress Gateway IPAM have been removed",
					fmt.Errorf("egress interfaces [%s] in use by egress-gateway IPAM have been removed", strings.Join(ifaces, ",")),
				)
			} else {
				health.OK("All egress interfaces found")
			}
			select {
			case <-devicesWatch:
				devices, devicesWatch = tables.SelectedDevices(devicesTbl, db.ReadTxn())
			case <-ctx.Done():
				return nil
			}
		}
	}))
}

func deletedEgressIfaces(devices []*tables.Device, db *statedb.DB, table statedb.RWTable[*enterpriseTables.EgressIPEntry]) []string {
	devNames := sets.New(tables.DeviceNames(devices)...)

	iter := table.All(db.ReadTxn())
	egressIfaces := sets.New(
		statedb.Collect(statedb.Map(
			iter,
			func(entry *enterpriseTables.EgressIPEntry) string { return entry.Interface },
		))...)

	// Ignore virtual IPs
	egressIfaces.Delete("")

	return egressIfaces.Difference(devNames).UnsortedList()
}
