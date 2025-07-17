//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package externalendpoints

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
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
	"github.com/vmware/govmomi"
	"github.com/vmware/govmomi/find"
	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/simulator"
	"github.com/vmware/govmomi/vim25/types"

	"github.com/cilium/cilium/enterprise/operator/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/operator/pkg/privnet/externalendpoints/providers/vsphere"
	"github.com/cilium/cilium/enterprise/operator/pkg/privnet/reconcilers"
	"github.com/cilium/cilium/pkg/hive"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	k8sTestutils "github.com/cilium/cilium/pkg/k8s/testutils"
	"github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/time"
)

var debug = flag.Bool("debug", false, "Enable debug logging")

type vcsim struct {
	m      *simulator.Model
	srv    *simulator.Server
	client *govmomi.Client
}

func newVCSim(lc cell.Lifecycle) *vcsim {
	v := &vcsim{
		m: simulator.VPX(),
	}
	lc.Append(cell.Hook{
		OnStop: func(_ cell.HookContext) error {
			if v.srv != nil {
				v.srv.Close()
			}
			v.m.Remove()
			return nil
		},
	})
	return v
}

func (v *vcsim) start() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Starts the simulated vCenter API",
		},

		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if v.srv != nil {
				return nil, fmt.Errorf("simulated vCenter API is already running")
			}

			if err := v.m.Create(); err != nil {
				return nil, err
			}

			srv := v.m.Service.NewServer()
			ctx := v.m.Service.Context

			client, err := govmomi.NewClient(ctx, srv.URL, true)
			if err != nil {
				return nil, fmt.Errorf("failed to connect to simulated vCenter API")
			}

			v.srv = srv
			v.client = client

			s.Logf("Started vCenter API on: %s", v.srv.URL.String())

			return nil, nil
		},
	)
}

func (v *vcsim) setEnv() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Sets environment variables for the simulated vCenter API",
			Detail: []string{
				"Writes the credentials of the simulated vCenter API as base64 encoded strings into the following environment variables:",
				"",
				" VSCIM_URL - vCenter API URL",
				" VSCIM_USER - vCenter API username",
				" VSCIM_PASSWORD - vCenter API password",
			},
		},

		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if v.srv == nil {
				return nil, fmt.Errorf("simulated vCenter API not running")
			}

			// plainURL is the URL without userinfo
			plainURL := *v.srv.URL
			plainURL.User = nil

			b64 := func(s string) string {
				return base64.StdEncoding.EncodeToString([]byte(s))
			}

			url := plainURL.String()
			user := v.srv.URL.User.Username()
			password, _ := v.srv.URL.User.Password()

			s.Setenv("VCSIM_URL", b64(url))
			s.Setenv("VCSIM_USER", b64(user))
			s.Setenv("VCSIM_PASSWORD", b64(password))

			return nil, nil
		},
	)
}

func (v *vcsim) customizeVM() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Customizes a VM",
			Args:    "name",
			Flags: func(fs *pflag.FlagSet) {
				fs.String("ip", "", "IPv4 address")
			},
		},

		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 1 {
				return nil, fmt.Errorf("expected 1 argument")
			}

			if v.srv == nil {
				return nil, fmt.Errorf("simulated vCenter API not running")
			}

			name := args[0]
			ipv4, err := s.Flags.GetString("ip")
			if err != nil {
				return nil, fmt.Errorf("error reading ip flag: %w", err)
			}

			if ipv4 == "" {
				return nil, fmt.Errorf("ip field is required")
			}

			ctx := s.Context()
			vm, err := find.NewFinder(v.client.Client).VirtualMachine(ctx, name)
			if err != nil {
				return nil, err
			}

			adapter := types.CustomizationIPSettings{
				Ip: &types.CustomizationFixedIp{IpAddress: ipv4},
			}

			spec := types.CustomizationSpec{
				NicSettingMap: []types.CustomizationAdapterMapping{
					{
						Adapter: adapter,
					},
				},
			}

			task, err := vm.Customize(ctx, spec)
			if err != nil {
				return nil, err
			}
			if err = task.Wait(ctx); err != nil {
				return nil, err
			}
			return nil, nil
		},
	)
}

func (v *vcsim) powerVM() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Powers a VM on or off",
			Args:    "name",
			Flags: func(fs *pflag.FlagSet) {
				fs.Bool("on", true, "Power on")
			},
		},

		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 1 {
				return nil, fmt.Errorf("expected 1 argument")
			}

			name := args[0]
			on, err := s.Flags.GetBool("on")
			if err != nil {
				return nil, fmt.Errorf("error reading on flag: %w", err)
			}

			if v.srv == nil {
				return nil, fmt.Errorf("simulated vCenter API not running")
			}

			ctx := s.Context()
			vm, err := find.NewFinder(v.client.Client).VirtualMachine(ctx, name)
			if err != nil {
				return nil, err
			}

			var task *object.Task
			if on {
				task, err = vm.PowerOn(ctx)
			} else {
				task, err = vm.PowerOff(ctx)
			}
			if err != nil {
				return nil, err
			}

			if err = task.Wait(ctx); err != nil {
				return nil, err
			}
			return nil, nil
		},
	)
}

func vcsimCommands(v *vcsim) uhive.ScriptCmdsOut {
	return uhive.NewScriptCmds(map[string]script.Cmd{
		"vcsim/start":        v.start(),
		"vcsim/setenv":       v.setEnv(),
		"vcsim/vm-customize": v.customizeVM(),
		"vcsim/vm-power":     v.powerVM(),
	})
}

func TestScript(t *testing.T) {
	defer testutils.GoleakVerifyNone(t)

	version.Force(k8sTestutils.DefaultVersion)

	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
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
				Cell,

				cell.Provide(newVCSim),
				cell.Provide(vcsimCommands),
				k8sClient.FakeClientCell(),

				config.Cell,
				reconcilers.PrivateNetworksCell,
				reconcilers.ExternalEndpointsCell,
				cell.Invoke(vsphere.RegisterVSphereProvider),
			)

			t.Cleanup(func() {
				assert.NoError(t, h.Stop(log, context.Background()))
			})

			flags := pflag.NewFlagSet("", pflag.ContinueOnError)
			h.RegisterFlags(flags)
			// Set some defaults

			// Expand $WORK in args. Used by testdata/file.txtar.
			tempDir := path.Join(path.Dir(t.TempDir()), "001")
			for i := range args {
				args[i] = strings.ReplaceAll(args[i], "$WORK", tempDir)
			}

			require.NoError(t, flags.Parse(args), "flags.Parse")

			cmds, err := h.ScriptCommands(log)
			require.NoError(t, err, "ScriptCommands")
			maps.Insert(cmds, maps.All(script.DefaultCmds()))
			return &script.Engine{
				Cmds:          cmds,
				RetryInterval: 10 * time.Millisecond,
			}
		}, []string{}, "testdata/*.txtar")
}
