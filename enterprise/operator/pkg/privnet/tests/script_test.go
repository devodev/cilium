// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package tests

import (
	"context"
	"flag"
	"log/slog"
	"maps"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	"github.com/go-logr/logr"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	virt_v1 "kubevirt.io/api/core/v1"
	ctrlruntime "sigs.k8s.io/controller-runtime"

	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/enterprise/operator/pkg/evpn"
	"github.com/cilium/cilium/enterprise/operator/pkg/privnet"
	"github.com/cilium/cilium/enterprise/operator/pkg/privnet/reconcilers"
	"github.com/cilium/cilium/operator/cmd"
	"github.com/cilium/cilium/pkg/hive"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	k8sTestutils "github.com/cilium/cilium/pkg/k8s/testutils"
	"github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/option"
)

var debug = flag.Bool("debug", false, "Enable debug logging")

func init() {
	virt_v1.AddToScheme(k8sTestutils.Scheme)

	for _, kind := range []string{"Provider", "Plan"} {
		k8sTestutils.Scheme.AddKnownTypeWithName(schema.GroupVersionKind{
			Group:   "forklift.konveyor.io",
			Version: "v1beta1",
			Kind:    kind,
		}, &unstructured.Unstructured{})
		k8sTestutils.Scheme.AddKnownTypeWithName(schema.GroupVersionKind{
			Group:   "forklift.konveyor.io",
			Version: "v1beta1",
			Kind:    kind + "List",
		}, &unstructured.UnstructuredList{})
	}
}

func TestScript(t *testing.T) {
	version.Force(k8sTestutils.DefaultVersion)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)

	scripttest.Test(t,
		ctx,
		func(t testing.TB, args []string) *script.Engine {
			var opts []hivetest.LogOption
			if *debug {
				opts = append(opts, hivetest.LogLevel(slog.LevelDebug))
				logging.SetLogLevelToDebug()
			}
			log := hivetest.Logger(t, opts...)

			// Configure our test logger as the sink for controller-runtime logs as well.
			ctrlruntime.SetLogger(logr.New(logr.FromSlogHandler(log.Handler()).GetSink()))

			h := hive.New(
				cell.Provide(
					func(lc cell.Lifecycle) *cmd.LeaderLifecycle { return &cmd.LeaderLifecycle{} },
				),

				k8sClient.FakeClientCell(),
				cell.DecorateAll(k8sClient.NewFakeNADsClientset),
				cell.DecorateAll(k8sClient.NewFakeDynamicClient),
				daemonk8s.NamespaceTableCell,

				cell.Provide(func() *option.DaemonConfig {
					return &option.DaemonConfig{EnableIPv4: true, EnableIPv6: true}
				}),

				privnet.Cell,
				evpn.Cell,

				WebhookTestCell(t),

				// Ensure consistent a CNI logs debug setting, regardless of whether
				// debug logs are enabled or not in the test.
				cell.DecorateAll(func() reconcilers.CNILogsDebug { return false }),
			)

			t.Cleanup(func() {
				assert.NoError(t, h.Stop(log, context.Background()))
			})

			flags := pflag.NewFlagSet("", pflag.ContinueOnError)
			h.RegisterFlags(flags)

			require.NoError(t, flags.Parse(args), "flags.Parse")

			cmds, err := h.ScriptCommands(log)
			require.NoError(t, err, "ScriptCommands")
			maps.Insert(cmds, maps.All(script.DefaultCmds()))

			return &script.Engine{
				Cmds:          cmds,
				RetryInterval: 10 * time.Millisecond,
			}
		}, []string{}, "testdata/*.txtar",
		// The controller-runtime logger is configured via a global variable,
		// which means that we cannot run the tests in parallel.
		scripttest.NoParallel,
	)
}
