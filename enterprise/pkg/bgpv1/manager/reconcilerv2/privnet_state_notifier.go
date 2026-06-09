// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilerv2

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	evpnConfig "github.com/cilium/cilium/enterprise/pkg/evpn/config"
	privnetConfig "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
)

type StateChangeNotifier interface {
	NotifyStateChange()
}

type privnetStatusNotifierIn struct {
	cell.In

	Logger *slog.Logger

	Config        config.Config
	EVPNConfig    evpnConfig.Config
	PrivnetConfig privnetConfig.Config

	JG       job.Group
	DB       *statedb.DB
	Table    statedb.Table[tables.PrivateNetwork]
	Notifier StateChangeNotifier
}

func registerPrivnetStatusNotifier(in privnetStatusNotifierIn) {
	if !in.Config.Enabled || !in.EVPNConfig.Enabled || !in.PrivnetConfig.Enabled {
		return
	}

	in.JG.Add(job.OneShot("privnet-status-notifier", func(ctx context.Context, health cell.Health) error {
		rtxn := in.DB.ReadTxn()

		health.OK("Waiting for private-networks table initialization")

		_, watch := in.Table.Initialized(rtxn)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-watch:
		}

		for {
			rtxn := in.DB.ReadTxn()

			// We don't care about the actual changes, we just need
			// to be notified for any change.
			all, watch := in.Table.AllWatch(rtxn)

			// We want to skip the reconciliation for empty table.
			// Count the number of entries.
			count := 0
			for range all {
				count++
			}

			if count > 0 {
				in.Notifier.NotifyStateChange()
				health.OK("Status change notified")
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-watch:
			}
		}
	}))
}
