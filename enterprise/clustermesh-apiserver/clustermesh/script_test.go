//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package clustermesh_test

import (
	"context"
	"flag"
	"log/slog"
	"maps"
	"testing"

	uhive "github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	"github.com/cilium/statedb"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/clustermesh-apiserver/clustermesh"
	cmk8s "github.com/cilium/cilium/clustermesh-apiserver/clustermesh/k8s"
	"github.com/cilium/cilium/clustermesh-apiserver/syncstate"
	entcm "github.com/cilium/cilium/enterprise/clustermesh-apiserver/clustermesh"
	entcmk8s "github.com/cilium/cilium/enterprise/clustermesh-apiserver/clustermesh/k8s"
	"github.com/cilium/cilium/enterprise/pkg/clustermesh/clustercfg"
	"github.com/cilium/cilium/enterprise/pkg/clustermesh/phantom"
	clustercfgcell "github.com/cilium/cilium/pkg/clustermesh/clustercfg/cell"
	mcsapitypes "github.com/cilium/cilium/pkg/clustermesh/mcsapi/types"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/hive"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	k8stestutils "github.com/cilium/cilium/pkg/k8s/testutils"
	"github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/time"
)

var debug = flag.Bool("debug", false, "Enable debug logging")

func TestScript(t *testing.T) {
	version.Force(k8stestutils.DefaultVersion)

	var opts []hivetest.LogOption
	if *debug {
		opts = append(opts, hivetest.LogLevel(slog.LevelDebug))
		logging.SetLogLevel(slog.LevelDebug)
	}
	log := hivetest.Logger(t, opts...)

	setup := func(t testing.TB, args []string) *script.Engine {
		storeFactory := store.NewFactory(hivetest.Logger(t), store.MetricsProvider())

		h := hive.New(
			cell.Config(cmtypes.DefaultClusterInfo),
			cell.Config(mcsapitypes.DefaultMCSAPIConfig),
			cell.Invoke(cmtypes.ClusterInfo.Validate),

			k8sClient.FakeClientCell(),
			cmk8s.ResourcesCell,

			cell.Provide(func(db *statedb.DB) (kvstore.Client, uhive.ScriptCmdsOut) {
				client := kvstore.NewInMemoryClient(db, "__local__")
				return client, uhive.NewScriptCmds(kvstore.Commands(client))
			}),

			cell.Provide(
				func() store.Factory {
					return storeFactory
				},
			),

			cell.Provide(func() syncstate.SyncState {
				return syncstate.SyncState{StoppableWaitGroup: lock.NewStoppableWaitGroup()}
			}),

			clustercfgcell.WithSyncedCanaries(true),
			clustercfgcell.Cell,
			clustermesh.Synchronization,

			clustercfg.Cell,
			entcmk8s.ResourcesCell,
			entcm.EnterpriseSynchronization,
			phantom.Cell,
		)

		flags := pflag.NewFlagSet("", pflag.ContinueOnError)
		h.RegisterFlags(flags)

		// Parse the shebang arguments in the script.
		require.NoError(t, flags.Parse(args), "flags.Parse")

		t.Cleanup(func() {
			assert.NoError(t, h.Stop(log, context.TODO()))
		})
		cmds, err := h.ScriptCommands(log)
		require.NoError(t, err, "ScriptCommands")
		maps.Insert(cmds, maps.All(script.DefaultCmds()))

		return &script.Engine{
			Cmds:             cmds,
			RetryInterval:    20 * time.Millisecond,
			MaxRetryInterval: time.Second,
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	scripttest.Test(t,
		ctx,
		setup,
		[]string{},
		"testdata/*.txtar")

	// Run the OSS tests as well, as sanity check. We need to skip the ones
	// asserting the cluster config though, as we use an extended version here.
	scripttest.Test(t,
		ctx,
		setup,
		[]string{},
		"../../../clustermesh-apiserver/clustermesh/testdata/cilium*.txtar")
}
