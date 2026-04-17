//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package kvstoremesh_test

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"maps"
	"path"
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

	entreflector "github.com/cilium/cilium/enterprise/clustermesh-apiserver/kvstoremesh/reflector"
	"github.com/cilium/cilium/pkg/clustermesh/common"
	"github.com/cilium/cilium/pkg/clustermesh/kvstoremesh"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/time"
)

var debug = flag.Bool("debug", false, "Enable debug logging")

func TestScript(t *testing.T) {
	var opts []hivetest.LogOption
	if *debug {
		opts = append(opts, hivetest.LogLevel(slog.LevelDebug))
		logging.SetLogLevel(slog.LevelDebug)
	}
	log := hivetest.Logger(t, opts...)

	setup := func(t testing.TB, args []string) *script.Engine {
		h := hive.New(
			cell.Config(cmtypes.DefaultClusterInfo),
			cell.Invoke(cmtypes.ClusterInfo.Validate),

			cell.Config(kvstoremesh.DefaultConfig),
			cell.Config(ClientFactoryParams{}),

			cell.Provide(func(db *statedb.DB, cinfo cmtypes.ClusterInfo, cfg ClientFactoryParams) (
				kvstore.Client, *ClientFactory, uhive.ScriptCmdsOut) {

				var (
					factory  = newClientFactory(db, cinfo.Name, cfg.RemoteClusters)
					local, _ = factory.Get(cinfo.Name)
					cmds     = factory.Commands()
				)

				return local, factory, uhive.NewScriptCmds(cmds)
			}),

			cell.Provide(
				func(log *slog.Logger) store.Factory {
					return store.NewFactory(log, store.MetricsProvider())
				},
			),

			cell.DecorateAll(func(factory *ClientFactory) common.RemoteClientFactoryFn {
				// Each remote cluster is associated with its own etcd client.
				return func(_ context.Context, _ *slog.Logger, _ string, opts kvstore.ExtraOptions) (
					kvstore.BackendOperations, chan error) {

					var errch = make(chan error, 1)
					defer close(errch)

					client, err := factory.Get(opts.ClusterName)
					if err != nil {
						errch <- err
					}

					return client, errch
				}
			}),

			kvstoremesh.Cell,
			entreflector.Cell,

			// Force instantiation of KVStoreMesh.
			cell.Invoke(func(*kvstoremesh.KVStoreMesh) {}),
		)

		flags := pflag.NewFlagSet("", pflag.ContinueOnError)
		h.RegisterFlags(flags)

		// Point clustermesh-config to the working directory of the test.
		flags.Set("clustermesh-config", path.Join(path.Dir(t.TempDir()), "001"))

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
}

type ClientFactoryParams struct {
	RemoteClusters []string `mapstructure:"test-remote-clusters"`
}

func (def ClientFactoryParams) Flags(flags *pflag.FlagSet) {
	flags.StringSlice("test-remote-clusters", def.RemoteClusters,
		"List of remote clusters used during the test, to initialize the corresponding clients")
}

type ClientFactory struct {
	localName string
	clients   map[string]kvstore.Client
}

func newClientFactory(db *statedb.DB, local string, remotes []string) *ClientFactory {
	var clients = make(map[string]kvstore.Client)
	for _, cname := range append([]string{local}, remotes...) {
		clients[cname] = kvstore.NewInMemoryClient(db, cname)
	}

	return &ClientFactory{
		localName: local,
		clients:   clients,
	}
}

func (cf *ClientFactory) Get(cname string) (kvstore.Client, error) {
	client, ok := cf.clients[cname]
	if !ok {
		return nil, fmt.Errorf("no client associated with cluster %q", cname)
	}

	return client, nil
}

func (cf *ClientFactory) Commands() map[string]script.Cmd {
	var out = make(map[string]script.Cmd)

	for name, cmd := range kvstore.Commands(cf.clients[cf.localName]) {
		out[name] = script.Command(
			script.CmdUsage{
				Summary: cmd.Usage().Summary,
				Args:    "cluster " + cmd.Usage().Args,
				Flags:   cmd.Usage().Flags,
			},
			func(s *script.State, args ...string) (script.WaitFunc, error) {
				if len(args) < 1 {
					return nil, fmt.Errorf("%w: expected cluster name", script.ErrUsage)
				}

				client, err := cf.Get(args[0])
				if err != nil {
					return nil, err
				}

				return kvstore.Commands(client)[name].Run(s, args[1:]...)
			},
		)
	}

	return out
}
