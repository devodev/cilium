//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package tunnelip

import (
	"context"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/spf13/pflag"

	dpipc "github.com/cilium/cilium/pkg/datapath/ipcache"
	"github.com/cilium/cilium/pkg/node"
	nodemanager "github.com/cilium/cilium/pkg/node/manager"
)

type Config struct {
	PreferredTunnelEndpointDevices []string
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.StringSlice("preferred-tunnel-endpoint-devices", def.PreferredTunnelEndpointDevices, "Devices to prefer for tunneling. Supports '+' as wildcard in device name, e.g. 'eth+'")
}

var defaultConfig = Config{}

var Cell = cell.Module(
	"tunnel-ip",
	"Custom tunnel endpoints",

	cell.Config(defaultConfig),

	cell.Invoke(func(p params, listener *dpipc.BPFListener, nodes nodemanager.NodeManager, jobs job.Group, localNodeStore *node.LocalNodeStore) {
		mgr := newManager(p)
		if mgr == nil {
			return
		}

		// Inject an IPCache BPF Map handler to intercept BPF map updates so we can update
		// the tunnel endpoint or drop the update if endpoint not known yet.
		// We use [InjectCEMapLate] to ensure that our override is later than any override
		// added with [InjectCEMap] (namely after mixed routing).
		dpipc.InjectCEMapLate(listener, mgr)

		// Subscribe to node updates to learn the per node set of [addressing.NodeCiliumTunnelIP].
		nodes.Subscribe(mgr)

		jobs.Add(
			// Register a job to recompute the tunnel endpoint selection and the set of tunnel IPs
			// when devices change.
			job.OneShot("tunnel-ip-sync", func(ctx context.Context, _ cell.Health) error {
				return mgr.runDeviceSync(ctx, localNodeStore)
			}),
		)
	}),
)
