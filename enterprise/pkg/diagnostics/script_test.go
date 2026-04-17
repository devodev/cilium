//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package diagnostics

import (
	"context"
	"flag"
	"log/slog"
	"maps"
	"path"
	"strings"
	"testing"

	uhive "github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

var debug = flag.Bool("debug", false, "Enable debug logging")

func TestScript(t *testing.T) {
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

			h := hive.New(
				cell.Provide(
					// For [metrics.Cell]
					func() *option.DaemonConfig {
						return &option.DaemonConfig{}
					},

					newTestCommands,
				),
				metrics.Cell,

				NewCell("test", "v9.99.999"),
			)

			flags := pflag.NewFlagSet("", pflag.ContinueOnError)
			h.RegisterFlags(flags)

			// Expand $WORK in args.
			workDir := path.Join(path.Dir(t.TempDir()), "001")
			for i := range args {
				args[i] = strings.ReplaceAll(args[i], "$WORK", workDir)
			}

			// Parse args
			require.NoError(t, flags.Parse(args), "flags.Parse")

			t.Cleanup(func() {
				assert.NoError(t, h.Stop(log, context.TODO()))
			})
			cmds, err := h.ScriptCommands(log)
			require.NoError(t, err, "ScriptCommands")
			maps.Insert(cmds, maps.All(script.DefaultCmds()))

			return &script.Engine{
				Cmds: cmds,
			}
		}, []string{}, "testdata/*.txtar")
}

func newTestCommands(ic *internalConditions) uhive.ScriptCmdsOut {
	dc := diagnosticsScriptCommands{ic}
	return uhive.NewScriptCmds(map[string]script.Cmd{
		"diagnostics/toggle-fail": dc.toggleSimulatedFailure(),
	})
}

type diagnosticsScriptCommands struct {
	ic *internalConditions
}

func (dc diagnosticsScriptCommands) toggleSimulatedFailure() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Toggle the simulated condition failure",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			v := dc.ic.simulatedFailure.Load()
			dc.ic.simulatedFailure.Store(!v)
			s.Logf("Toggled simulated failure: %v => %v", v, !v)
			return nil, nil
		},
	)
}
