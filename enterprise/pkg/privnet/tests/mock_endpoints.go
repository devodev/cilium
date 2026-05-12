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
	"iter"
	"math"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"testing"

	uhive "github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/script"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/enterprise/pkg/privnet/endpoints"
	"github.com/cilium/cilium/enterprise/pkg/privnet/observers"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	eptypes "github.com/cilium/cilium/pkg/endpoint/types"
	"github.com/cilium/cilium/pkg/endpointstate"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/promise"
)

func mockEndpointCell(t testing.TB) cell.Cell {
	t.Helper()

	return cell.Group(
		cell.ProvidePrivate(
			newFakeEventObserver,
			newFakeRestorer,
			newFakeEPM,
		),
		cell.Provide(
			regeneration.NewFence,
			promise.New[endpointstate.Restorer],

			newFakeEndpointCmds,
		),
		cell.DecorateAll(func(f *fakeEPM) endpoints.EndpointGetter { return f }),
		cell.DecorateAll(func(f *fakeEPM) endpoints.EndpointCreator { return f }),
		cell.DecorateAll(func(f *fakeEPM) endpoints.EndpointRemover { return f }),
		cell.DecorateAll(func(f *fakeEndpointEventObserver) endpoints.EndpointEventObserver { return f }),
	)
}

type fakeEP struct {
	mu lock.Mutex

	ID      uint16
	IfName  string
	IfIndex int

	IPv4 netip.Addr
	IPv6 netip.Addr
	MAC  mac.MAC

	PodName   string
	Namespace string

	Properties map[string]any
	Labels     labels.Labels
}

var _ endpoints.Endpoint = &fakeEP{}

// MarshalJSON the fake endpoint as an EndpointChangeRequest to match the format
// used by epm-create.
func (f *fakeEP) MarshalJSON() ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return json.Marshal(
		models.EndpointChangeRequest{
			ID:             int64(f.ID),
			InterfaceName:  f.IfName,
			InterfaceIndex: int64(f.IfIndex),
			K8sPodName:     f.PodName,
			K8sNamespace:   f.Namespace,
			Properties:     f.Properties,
			Addressing: &models.AddressPair{
				IPv4: f.GetIPv4Address(),
				IPv6: f.GetIPv6Address(),
			},
			Mac:    f.MAC.String(),
			Labels: f.Labels.GetPrintableModel(),
		},
	)
}

// GetID16 implements endpoints.Endpoint.
func (f *fakeEP) GetID16() uint16 {
	return f.ID
}

// HostInterface implements endpoints.Endpoint.
func (f *fakeEP) HostInterface() string {
	return f.IfName
}

// GetIfIndex implements endpoints.Endpoint.
func (f *fakeEP) GetIfIndex() int {
	return f.IfIndex
}

// IPv4Address implements endpoints.Endpoint.
func (f *fakeEP) IPv4Address() netip.Addr {
	return f.IPv4
}

// GetIPv4Address implements endpoints.Endpoint.
func (f *fakeEP) GetIPv4Address() string {
	if f.IPv4.IsValid() {
		return f.IPv4.String()
	}
	return ""
}

// IPv6Address implements endpoints.Endpoint.
func (f *fakeEP) IPv6Address() netip.Addr {
	return f.IPv6
}

// GetIPv6Address implements endpoints.Endpoint.
func (f *fakeEP) GetIPv6Address() string {
	if f.IPv6.IsValid() {
		return f.IPv6.String()
	}
	return ""
}

// GetK8sCEPName implements endpoints.Endpoint.
func (f *fakeEP) GetK8sCEPName() string {
	if cepName, ok := f.Properties[eptypes.PropertyCEPName]; ok {
		return cepName.(string)
	}
	return f.PodName
}

// GetK8sNamespaceAndCEPName implements endpoints.Endpoint.
func (f *fakeEP) GetK8sNamespaceAndCEPName() string {
	return fmt.Sprintf("%s/%s", f.Namespace, f.GetK8sCEPName())
}

// GetK8sNamespaceAndPodName implements endpoints.Endpoint.
func (f *fakeEP) GetK8sNamespaceAndPodName() string {
	return fmt.Sprintf("%s/%s", f.Namespace, f.PodName)
}

// SetK8sMetadata implements endpoints.Endpoint.
func (f *fakeEP) SetK8sMetadata(containerPorts []slim_corev1.ContainerPort) {
	// no-op
}

// GetPropertyValue implements endpoints.Endpoint.
func (f *fakeEP) GetPropertyValue(key string) any {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Properties == nil {
		return nil
	}
	return f.Properties[key]
}

// SetPropertyValue implements endpoints.Endpoint.
func (f *fakeEP) SetPropertyValue(key string, value any) any {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Properties == nil {
		f.Properties = map[string]any{}
	}
	f.Properties[key] = value
	return value
}

// IsProperty implements endpoints.Endpoint.
func (f *fakeEP) IsProperty(key string) bool {
	value, ok := f.GetPropertyValue(key).(bool)
	return ok && value
}

// LXCMac implements endpoints.Endpoint.
func (f *fakeEP) LXCMac() mac.MAC {
	return f.MAC
}

// SyncEndpointHeaderFile implements endpoints.Endpoint.
func (f *fakeEP) SyncEndpointHeaderFile() {}

// UpdateLabels implements endpoints.Endpoint.
func (f *fakeEP) UpdateLabels(ctx context.Context, sourceFilter string, identityLabels, infoLabels labels.Labels, blocking bool) (regenTriggered bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.Labels.RemoveFromSource(sourceFilter)
	f.Labels.MergeLabels(identityLabels)

	return false
}

// GetPolicyMap implements endpoints.Endpoint.
func (f *fakeEP) GetPolicyMap() (policymap.PolicyMap, error) {
	return nil, nil
}

// fakeEndpointEventObserver implements endpoints.EndpointEventObserver
type fakeEndpointEventObserver = observers.Generic[endpoints.EndpointID, endpoints.EndpointEventKind]

func newFakeEventObserver() *fakeEndpointEventObserver {
	return observers.NewGeneric[endpoints.EndpointID, endpoints.EndpointEventKind]()
}

// fakeRestorer implements endpointstate.Restorer
type fakeRestorer struct {
	fence regeneration.Fence

	observer  *fakeEndpointEventObserver
	notifiers []endpoints.RestorationNotifier

	epm *fakeEPM

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

	EndpointManager *fakeEPM

	Observer  *fakeEndpointEventObserver
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

// fakeEPM implements endpoints.Endpoint{Creator,Getter,Remover}
type fakeEPM struct {
	mu   lock.Mutex
	eps  []*fakeEP
	subs []endpoints.EndpointSubscriber

	observer *fakeEndpointEventObserver
}

func newFakeEPM(observer *fakeEndpointEventObserver) *fakeEPM {
	return &fakeEPM{
		subs: []endpoints.EndpointSubscriber{},
		eps:  []*fakeEP{},

		observer: observer,
	}
}

// CreateEndpoint implements endpoints.EndpointCreator.
func (f *fakeEPM) createEndpoint(epTemplate *models.EndpointChangeRequest, restored bool) (endpoints.Endpoint, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var err error
	ep := fakeEP{
		ID:         uint16(epTemplate.ID),
		IfName:     epTemplate.InterfaceName,
		IfIndex:    int(epTemplate.InterfaceIndex),
		PodName:    epTemplate.K8sPodName,
		Namespace:  epTemplate.K8sNamespace,
		Properties: epTemplate.Properties,
		Labels:     labels.NewLabelsFromModel(epTemplate.Labels),
	}
	if epTemplate.Addressing.IPv4 != "" {
		ep.IPv4, err = netip.ParseAddr(epTemplate.Addressing.IPv4)
		if err != nil {
			return nil, err
		}
	}
	if epTemplate.Addressing.IPv6 != "" {
		ep.IPv6, err = netip.ParseAddr(epTemplate.Addressing.IPv6)
		if err != nil {
			return nil, err
		}
	}
	if epTemplate.Mac != "" {
		ep.MAC, err = mac.ParseMAC(epTemplate.Mac)
		if err != nil {
			return nil, err
		}
	}
	if ep.ID == 0 {
		// Allocate a new endpoint ID
		epID := uint16(0)
	allocateNextID:
		for {
			epID++
			if epID == math.MaxUint16 {
				return nil, fmt.Errorf("no available endpoint IDs")
			}
			for _, other := range f.eps {
				if other.ID == epID {
					continue allocateNextID
				}
			}
			break
		}
		ep.ID = epID
	}

	// Check no duplicates with endpoint ID or CEP name exist
	for _, other := range f.eps {
		if other.ID == ep.ID {
			return nil, fmt.Errorf("endpoint id %d already exists", ep.ID)
		}
		if other.GetK8sNamespaceAndCEPName() == ep.GetK8sNamespaceAndCEPName() {
			return nil, fmt.Errorf("endpoint with CEP %s already exists", ep.GetK8sNamespaceAndCEPName())
		}
	}

	f.eps = append(f.eps, &ep)
	f.observer.Queue(endpoints.EndpointCreate, endpoints.EndpointID(ep.ID))
	for _, sub := range f.subs {
		if restored {
			sub.EndpointRestored(&ep)
		} else {
			sub.EndpointCreated(&ep)
		}
	}
	f.observer.Queue(endpoints.EndpointRegenSuccess, endpoints.EndpointID(ep.ID))
	return &ep, nil
}

// CreateEndpoint implements endpoints.EndpointCreator.
func (f *fakeEPM) CreateEndpoint(ctx context.Context, epTemplate *models.EndpointChangeRequest) (endpoints.Endpoint, error) {
	ep, err := f.createEndpoint(epTemplate, false)
	return ep, err
}

// RemoveEndpoint implements endpoints.EndpointRemover.
func (f *fakeEPM) RemoveEndpoint(ep endpoints.Endpoint) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	numEndpoints := len(f.eps)
	f.eps = slices.DeleteFunc(f.eps, func(fakeEP *fakeEP) bool {
		return fakeEP.GetID16() == ep.GetID16()
	})
	if len(f.eps) == numEndpoints {
		return fmt.Errorf("endpoint %d was already deleted", ep.GetID16())
	}
	f.observer.Queue(endpoints.EndpointDelete, endpoints.EndpointID(ep.GetID16()))
	for _, sub := range f.subs {
		sub.EndpointDeleted(ep)
	}
	return nil
}

// GetEndpointsByPodName implements endpoints.EndpointGetter.
func (f *fakeEPM) GetEndpointsByPodName(nsname string) iter.Seq[endpoints.Endpoint] {
	f.mu.Lock()
	eps := slices.Clone(f.eps)
	f.mu.Unlock()
	return func(yield func(endpoints.Endpoint) bool) {
		for _, ep := range eps {
			if ep.GetK8sNamespaceAndPodName() == nsname {
				if !yield(ep) {
					return
				}
			}
		}
	}
}

// GetEndpoints implements endpoints.EndpointGetter.
func (f *fakeEPM) GetEndpoints() iter.Seq[endpoints.Endpoint] {
	f.mu.Lock()
	eps := slices.Clone(f.eps)
	f.mu.Unlock()
	return func(yield func(endpoints.Endpoint) bool) {
		for _, ep := range eps {
			if !yield(ep) {
				return
			}
		}
	}
}

// LookupID implements endpoints.EndpointGetter.
func (f *fakeEPM) LookupID(id uint16) (ep endpoints.Endpoint) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.eps {
		if f.eps[i].GetID16() == id {
			return f.eps[i]
		}
	}
	return nil
}

// LookupCEPName implements endpoints.EndpointGetter.
func (f *fakeEPM) LookupCEPName(nsname string) (ep endpoints.Endpoint) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.eps {
		if f.eps[i].GetK8sNamespaceAndCEPName() == nsname {
			return f.eps[i]
		}
	}
	return nil
}

// Subscribe implements endpoints.EndpointGetter.
func (f *fakeEPM) Subscribe(s endpoints.EndpointSubscriber) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.subs = append(f.subs, s)
}

type fakeEndpointCmds struct {
	epm      *fakeEPM
	restorer *fakeRestorer
}

func newFakeEndpointCmds(epm *fakeEPM, restore *fakeRestorer) uhive.ScriptCmdsOut {
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
			_, err = f.epm.createEndpoint(epr, false)
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
			_, err = f.epm.createEndpoint(epr, true)
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
