//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package tests

import (
	"context"
	"flag"
	"log/slog"
	"maps"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/enterprise/pkg/privnet/reconcilers/idpool"
	"github.com/cilium/cilium/pkg/hive"
	k8sTestutils "github.com/cilium/cilium/pkg/k8s/testutils"
	"github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/logging"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/time"
)

var debug = flag.Bool("debug", false, "Enable debug logging")

func init() {
	// Make private network and subnet IDs predictable.
	idpool.Randomize = false
}

func TestScript(t *testing.T) {
	runScriptTests(t, "testdata/*.txtar")
}

func TestPrivilegedScript(t *testing.T) {
	testutils.PrivilegedTest(t)
	runScriptTests(t, "testdata/privileged/*.txtar")
}

func runScriptTests(t *testing.T, pattern string) {
	version.Force(k8sTestutils.DefaultVersion)
	nodeTypes.SetName(nodeName)
	labelsfilter.ParseLabelPrefixCfg(slog.New(slog.DiscardHandler), nil, nil, "")

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)

	scripttest.Test(t,
		ctx,
		func(t testing.TB, args []string) *script.Engine {
			var opts []hivetest.LogOption
			if *debug {
				opts = append(opts, hivetest.LogLevel(slog.LevelDebug))
				logging.SetLogLevel(slog.LevelDebug)
			}
			log := hivetest.Logger(t, opts...)

			cmds := script.DefaultCmds()
			cmds["text/template"] = templateCmd()
			cmds["jsonpath"] = jsonPathCmd()
			var h *hive.Hive
			setupHive := func() {
				h = NewTestHive(t)
				t.Cleanup(func() {
					assert.NoError(t, h.Stop(log, context.Background()))
				})

				flags := pflag.NewFlagSet("", pflag.ContinueOnError)
				h.RegisterFlags(flags)

				require.NoError(t, flags.Parse(args), "flags.Parse")

				hiveCmds, err := h.ScriptCommands(log)
				require.NoError(t, err, "ScriptCommands")
				maps.Copy(cmds, hiveCmds)
			}
			cmds["hive/recreate"] = script.Command(
				script.CmdUsage{
					Summary: "Recreate the hive",
				},
				func(_ *script.State, _ ...string) (script.WaitFunc, error) {
					setupHive()
					return nil, nil
				},
			)
			setupHive()

			conds := map[string]script.Cond{
				"privileged": script.BoolCondition("testutils.IsPrivileged", testutils.IsPrivileged()),
			}

			return &script.Engine{
				Cmds:          cmds,
				Conds:         conds,
				RetryInterval: 10 * time.Millisecond,
			}
		}, []string{}, pattern)
}
