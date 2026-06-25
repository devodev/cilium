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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"testing"

	uhive "github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/script"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/enterprise/pkg/privnet/endpoints"
	testTypes "github.com/cilium/cilium/enterprise/pkg/privnet/tests/types"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/promise"
)

func mockEndpointCell(t testing.TB) cell.Cell {
	t.Helper()

	return cell.Group(
		cell.ProvidePrivate(
			testTypes.NewFakeEndpointEventObserver,
			testTypes.NewFakeEPM,
			newFakeRestorer,
		),
		cell.Provide(
			regeneration.NewFence,
			promise.New[endpointstate.Restorer],

			newFakeEndpointCmds,
		),
		cell.DecorateAll(func(f *testTypes.FakeEPM) endpoints.EndpointGetter { return f }),
		cell.DecorateAll(func(f *testTypes.FakeEPM) endpoints.EndpointCreator { return f }),
		cell.DecorateAll(func(f *testTypes.FakeEPM) endpoints.EndpointRemover { return f }),
		cell.DecorateAll(func(f *testTypes.FakeEndpointEventObserver) endpoints.EndpointEventObserver { return f }),
	)
}

// fakeRestorer implements endpointstate.Restorer
type fakeRestorer struct {
	fence regeneration.Fence

	observer  *testTypes.FakeEndpointEventObserver
	notifiers []endpoints.RestorationNotifier

	epm *testTypes.FakeEPM

	restored    chan struct{}
	regenerated chan struct{}
}

// newFakeRestorer provides the fakeRestorer and resolves
// the restorer promise on Hive start (allowing fences
// to be registered before Hive starts)
func newFakeRestorer(in struct {
	cell.In

	Fence     regeneration.Fence
	Promise   promise.Resolver[endpointstate.Restorer]
	Lifecycle cell.Lifecycle

	EndpointManager *testTypes.FakeEPM

	Observer  *testTypes.FakeEndpointEventObserver
	Notifiers []endpoints.RestorationNotifier `group:"privnet-endpoint-restoration-notifiers"`
}) *fakeRestorer {
	f := &fakeRestorer{
		fence:       in.Fence,
		observer:    in.Observer,
		notifiers:   in.Notifiers,
		epm:         in.EndpointManager,
		restored:    make(chan struct{}),
		regenerated: make(chan struct{}),
	}

	in.Lifecycle.Append(cell.Hook{
		OnStart: func(hookContext cell.HookContext) error {
			in.Promise.Resolve(f)
			return nil
		},
	})

	return f
}

// finishRestoration marks all endpoints as restored (but not yet regenerated)
func (f *fakeRestorer) finishRestoration() {
	for _, n := range f.notifiers {
		if n != nil {
			n.RestorationNotify(f.epm.GetEndpoints())
		}
	}
	close(f.restored)
}

// finishRegeneration marks all endpoints as regenerated. finishRestoration must be called before this.
func (f *fakeRestorer) finishRegeneration() {
	if !f.isRestored() {
		panic("endpoints were regenerated without restoration")
	}
	close(f.regenerated)
	f.observer.Queue(endpoints.EndpointInitRegenAllDone, 0)
}

func (f *fakeRestorer) isRestored() bool {
	select {
	case <-f.restored:
		return true
	default:
		return false
	}
}

// WaitForEndpointRestoreWithoutRegeneration implements endpointstate.Restorer.
func (f *fakeRestorer) WaitForEndpointRestoreWithoutRegeneration(ctx context.Context) error {
	select {
	case <-f.restored:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// WaitForEndpointRestore implements endpointstate.Restorer.
func (f *fakeRestorer) WaitForEndpointRestore(ctx context.Context) error {
	if err := f.WaitForEndpointRestoreWithoutRegeneration(ctx); err != nil {
		return err
	}
	if err := f.fence.Wait(ctx); err != nil {
		return err
	}
	select {
	case <-f.regenerated:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// WaitForInitialPolicy implements endpointstate.Restorer.
func (f *fakeRestorer) WaitForInitialPolicy(ctx context.Context) error {
	// Technically, WaitForInitialPolicy returns earlier than WaitForEndpointRestore,
	// but to keep things simpler, we currently simulate that both events occur in the
	// same instant.
	return f.WaitForEndpointRestore(ctx)
}

// Await implements promise.Promise.
func (f *fakeRestorer) Await(context.Context) (endpointstate.Restorer, error) {
	return f, nil
}

type fakeEndpointCmds struct {
	epm      *testTypes.FakeEPM
	restorer *fakeRestorer
}

func newFakeEndpointCmds(epm *testTypes.FakeEPM, restore *fakeRestorer) uhive.ScriptCmdsOut {
	f := &fakeEndpointCmds{
		epm:      epm,
		restorer: restore,
	}

	return uhive.NewScriptCmds(f.cmds())
}

func (f *fakeEndpointCmds) cmds() map[string]script.Cmd {
	return map[string]script.Cmd{
		"privnet/epm-get":     f.getEPCmd(),
		"privnet/epm-create":  f.createEPCmd(),
		"privnet/epm-restore": f.restoreEPCmd(),
		"privnet/epm-delete":  f.deleteEPCmd(),

		"privnet/epm-finish-restoration":  f.finishRestorationCmd(),
		"privnet/epm-finish-regeneration": f.finishRegenerationCmd(),
	}
}

func (f *fakeEndpointCmds) getEPCmd() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "get a fake endpoint as JSON",
			Args:    "endpoint-identifier",
			Flags: func(fs *pflag.FlagSet) {
				fs.StringP("output", "o", "", "output file name")
				fs.String("by", "id", "identifier used to fetch the endpoint (possible values: id, cep-name)")
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 1 {
				return nil, fmt.Errorf("%w: expected endpoint identifier", script.ErrUsage)
			}
			idType, err := s.Flags.GetString("by")
			if err != nil {
				return nil, err
			}
			out, err := s.Flags.GetString("output")
			if err != nil {
				return nil, err
			}

			return func(s *script.State) (stdout string, stderr string, err error) {
				var ep endpoints.Endpoint
				switch idType {
				case "id":
					id, err := strconv.ParseUint(args[0], 10, 16)
					if err != nil {
						return "", "", err
					}
					ep = f.epm.LookupID(uint16(id))
				case "cep-name":
					ep = f.epm.LookupCEPName(args[0])
				default:
					return "", "", fmt.Errorf("invalid endpoint identifier %q", idType)
				}

				if ep == nil {
					return "", "", fmt.Errorf("endpoint %q not found", args[0])
				}
				b, err := json.MarshalIndent(ep, "", "  ")
				if err != nil {
					return "", "", err
				}
				b = append(b, '\n')
				if out == "" {
					return string(b), "", nil
				}
				if err := os.WriteFile(s.Path(out), b, 0o644); err != nil {
					return "", "", err
				}
				return "", "", nil
			}, nil
		},
	)
}

func parseEndpointJSON(s *script.State, args []string) (*models.EndpointChangeRequest, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("%w: expected number of arguments", script.ErrUsage)
	}
	b, err := os.ReadFile(s.Path(args[0]))
	if err != nil {
		return nil, err
	}
	epr := &models.EndpointChangeRequest{}
	err = json.Unmarshal(b, epr)
	if err != nil {
		return nil, err
	}
	return epr, nil
}

func (f *fakeEndpointCmds) createEPCmd() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "create a fake endpoint",
			Args:    "ep-req-json-file",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			epr, err := parseEndpointJSON(s, args)
			if err != nil {
				return nil, err
			}
			_, err = f.epm.CreateEndpoint(s.Context(), epr)
			if err != nil {
				return nil, fmt.Errorf("fake endpoint creation failed: %w", err)
			}

			return nil, nil
		},
	)
}

func (f *fakeEndpointCmds) restoreEPCmd() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "restore a fake endpoint",
			Args:    "ep-req-json-file",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if f.restorer.isRestored() {
				return nil, errors.New("cannot restore endpoints after regeneration has already started")
			}
			epr, err := parseEndpointJSON(s, args)
			if err != nil {
				return nil, err
			}
			_, err = f.epm.RestoreEndpoint(s.Context(), epr)
			if err != nil {
				return nil, fmt.Errorf("fake endpoint creation failed: %w", err)
			}

			return nil, nil
		},
	)
}

func (f *fakeEndpointCmds) deleteEPCmd() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "delete a fake endpoint",
			Args:    "cep-name",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 1 {
				return nil, fmt.Errorf("%w: expected number of arguments", script.ErrUsage)
			}
			ep := f.epm.LookupCEPName(args[0])
			if ep == nil {
				return nil, fmt.Errorf("fake endpoint %q not found", args[0])
			}
			err := f.epm.RemoveEndpoint(ep)
			if err != nil {
				return nil, fmt.Errorf("fake endpoint deletion failed: %w", err)
			}

			return nil, nil
		},
	)
}

func (f *fakeEndpointCmds) finishRestorationCmd() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "mark endpoint restoration as finished",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if f.restorer.isRestored() {
				return nil, errors.New("restoration already marked as finished")
			}
			f.restorer.finishRestoration()
			return nil, nil
		},
	)
}

func (f *fakeEndpointCmds) finishRegenerationCmd() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "mark endpoint restoration and regeneration as finished",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if !f.restorer.isRestored() {
				f.restorer.finishRestoration()
			}
			f.restorer.finishRegeneration()
			return nil, nil
		},
	)
}
