//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package vrf

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/vishvananda/netlink"

	dpTables "github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/k8s/client"
	slimLabels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	k8sTables "github.com/cilium/cilium/pkg/k8s/tables"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/time"

	"github.com/cilium/cilium/enterprise/pkg/vrf/config"
	"github.com/cilium/cilium/pkg/endpointmanager"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

// CiliumVRFDevicePrefix is the prefix used for naming VRF devices created by this controller.
const CiliumVRFDevicePrefix = "cvrf-"

// CiliumVRFDeviceFMT is the format string used to generate VRF device names, where the VRF's table ID is substituted in.
const CiliumVRFDeviceFMT = CiliumVRFDevicePrefix + "%d"

// Attempt a reconciliation every 30 seconds.
//
// This allows VRFs which suffered from transient netlink errors to reconcile
// without requiring a Device or VRF stateDB event.
const reconcileInterval = 30 * time.Second

type controllerParams struct {
	cell.In

	Config            config.Config
	DaemonConfig      *option.DaemonConfig
	Logger            *slog.Logger
	DB                *statedb.DB
	JobGroup          job.Group
	Clientset         client.Clientset
	Endpoints         endpointmanager.EndpointManager
	EPRestorerPromise promise.Promise[endpointstate.Restorer]
	LocalNodeStore    *node.LocalNodeStore
	LocalNodes        statedb.Table[*node.LocalNode]
	Namespaces        statedb.Table[k8sTables.Namespace]
	Pods              statedb.Table[k8sTables.LocalPod]
	VRFs              statedb.Table[VRF]
	Devices           statedb.Table[*dpTables.Device]
	VRFMap            VRFMap
	LxcMap            lxcmap.Map
}

type controller struct {
	logger            *slog.Logger
	db                *statedb.DB
	clientset         client.Clientset
	endpoints         endpointSubscriber
	endpointManager   endpointmanager.EndpointManager
	epRestorerPromise promise.Promise[endpointstate.Restorer]
	localNodeStore    *node.LocalNodeStore
	localNodes        statedb.Table[*node.LocalNode]
	namespaces        statedb.Table[k8sTables.Namespace]
	pods              statedb.Table[k8sTables.LocalPod]
	vrfs              statedb.Table[VRF]
	devices           statedb.Table[*dpTables.Device]

	nodeName               string
	active                 map[string]*VRF
	activeByID             map[uint16]*VRF
	activeByTableID        map[uint32]*VRF
	activeByBoundInterface map[string]*VRF
	// incremental counter
	opRev                uint64
	vrfMap               VRFMap
	lxcMap               lxcmap.Map
	nl                   netLink
	status               vrfStatusReporter
	endpointManagerEvent chan struct{}
}

// disabledRestorer implements the RestorationNotify interface for use in
// releasing Endpoints from VRF membership when the VRF control plane has
// been disabled.
type disabledRestorer struct {
	logger *slog.Logger
}

// RestorationNotify iterates over all endpoints being restored and removes them
// from VRF membership by setting their RTInfo to zero, if the VRF controller
// set it when enabled.
func (r *disabledRestorer) RestorationNotify(possible map[uint16]*endpoint.Endpoint) {
	for _, ep := range possible {
		if _, enc := ep.GetRTInfo(); enc != RTInfoVRF {
			continue
		}
		ep.ClearRTInfo()
	}
}

func registerController(p controllerParams) (endpointstate.RestorationNotifierOut, error) {
	if !p.Config.EnableVRF {
		return endpointstate.RestorationNotifierOut{
			Restorer: &disabledRestorer{logger: p.Logger},
		}, nil
	}
	if p.DaemonConfig.EnableFibTableIDAnnotation {
		return endpointstate.RestorationNotifierOut{}, fmt.Errorf("--%s and --%s cannot both be set to true, conflicting use of Endpoint's RTInfo.",
			option.VRFEnabled, option.EnableFibTableIDAnnotation)
	}
	c := &controller{
		logger:                 p.Logger,
		db:                     p.DB,
		clientset:              p.Clientset,
		endpoints:              newEpSubscriber(p.Endpoints),
		endpointManager:        p.Endpoints,
		epRestorerPromise:      p.EPRestorerPromise,
		localNodeStore:         p.LocalNodeStore,
		localNodes:             p.LocalNodes,
		namespaces:             p.Namespaces,
		pods:                   p.Pods,
		vrfs:                   p.VRFs,
		devices:                p.Devices,
		vrfMap:                 p.VRFMap,
		lxcMap:                 p.LxcMap,
		active:                 make(map[string]*VRF),
		activeByID:             make(map[uint16]*VRF),
		activeByTableID:        make(map[uint32]*VRF),
		activeByBoundInterface: make(map[string]*VRF),
		nl:                     nl{},
		endpointManagerEvent:   make(chan struct{}, 1),
	}
	p.JobGroup.Add(job.OneShot("vrf-controller", c.run,
		job.WithRetry(3, &job.ExponentialBackoff{Min: 10 * time.Second, Max: 1 * time.Minute}),
		job.WithShutdown(),
	))
	return endpointstate.RestorationNotifierOut{}, nil
}

// vrfMatchesEndpoint returns true if the endpoint's pod labels and namespace
// labels match the VRF's selectors. At least one selector must be set for a match.
//
// Pod and namespace labels are sourced from their statedb tables directly,
// ensuring Cilium's configuration does not interfere with the controller's view
// of labels.
//
// nsLabels and podLabels are nil-safe: nil means "row not visible yet" and
// causes any selector that touches that side to short-circuit to no match.
func (c *controller) vrfMatchesEndpoint(ctx context.Context, nsLabels map[string]string, podLabels map[string]string, vrf *VRF, ep endpointInfo) bool {
	nsSel := vrf.namespaceSelector()
	if nsSel != nil {
		if nsLabels == nil {
			return false
		}
		if !nsSel.Matches(slimLabels.Set(nsLabels)) {
			return false
		}
	}

	podSel := vrf.selector()
	if podSel != nil {
		if podLabels == nil {
			return false
		}
		if !podSel.Matches(slimLabels.Set(podLabels)) {
			return false
		}
	}

	return nsSel != nil || podSel != nil
}

func (c *controller) regenerateEndpoint(ctx context.Context, ep endpointInfo, vrfID uint32, reason string) {
	ep.SetRTInfo(vrfID, RTInfoVRF)
	ep.RegenerateIfAlive(&regeneration.ExternalRegenerationMetadata{
		Reason:            reason,
		RegenerationLevel: regeneration.RegenerateWithDatapath,
	})
}

// membershipConflict keeps a reference, for every VRF, what other VRF matched
// the same endpoint.
//
// We need this only to detect the VRFs which select overlapping Endpoints and
// not record each Endpoint, as this could be a very large number.
type membershipConflict map[string]map[string]struct{}

// status will flatten the internal map of map structure to a map of strings,
// used directly in IsovalentCoreVRFNodeStatusStatus status report.
func (m *membershipConflict) status() map[string]string {
	if len(*m) == 0 {
		return nil
	}
	out := make(map[string]string, len(*m))
	for vrf, others := range *m {
		names := make([]string, 0, len(others))
		for name := range others {
			names = append(names, name)
		}
		slices.Sort(names)
		out[vrf] = strings.Join(names, ", ")
	}
	return out
}

// reconcileEndpoint evaluates a single endpoint against all active VRFs and
// regenerates it into the matching VRF, or releases it back to the default
// VRF if no active VRF matches. When the endpoint matches more than one VRF
// the endpoint is held out of every VRF and the overlapping VRFs are recorded
// in conflict.
func (c *controller) reconcileEndpoint(ctx context.Context, rtxn statedb.ReadTxn, ep endpointInfo, conflict membershipConflict, epMap map[netip.Addr]lxcmap.EndpointInfo) {
	// Endpoints with no associated k8s pod (host endpoint) cannot be selected by
	// any VRF, skip the matching loop entirely.
	if ep.GetK8sNamespace() == "" || ep.GetK8sPodName() == "" {
		return
	}

	// Get labels and namespace labels using a ReadTxn so lookups are cheap and
	// indexed.
	//
	// It is possible for timing issues to occur here, such as the labels not
	// being present for an endpoint. This is safe since the controller also
	// reconciles on pod and namespace changes as well.
	var podLabels map[string]string
	if pod, _, ok := c.pods.Get(rtxn, k8sTables.PodByName(ep.GetK8sNamespace(), ep.GetK8sPodName())); ok {
		podLabels = pod.Labels
	}
	var nsLabels map[string]string
	if ns, _, ok := c.namespaces.Get(rtxn, k8sTables.NamespaceByName(ep.GetK8sNamespace())); ok {
		nsLabels = ns.Labels
	}

	var matches []*VRF
	for _, vrf := range c.active {
		if c.vrfMatchesEndpoint(ctx, nsLabels, podLabels, vrf, ep) {
			matches = append(matches, vrf)
		}
	}

	// If an Endpoint matches more than one VRF we must report this as a
	// membership conflict and not join the Endpoint to any VRF.
	if len(matches) > 1 {
		for _, a := range matches {
			if conflict[a.Name] == nil {
				conflict[a.Name] = make(map[string]struct{})
			}
			for _, b := range matches {
				if a.Name == b.Name {
					continue
				}
				conflict[a.Name][b.Name] = struct{}{}
			}
		}
		return
	}

	var match *VRF
	if len(matches) == 1 {
		match = matches[0]
	}

	// Perform a lookup of the current RTInfo state in the Endpoint map.
	// We look this up from the endpoint map since, if an async regeneration
	// failed, the desired VRF ID would never be applied to the RTInfo field
	// in the map.
	curVRF := epMapRTInfo(ep, epMap)

	if match == nil {
		if curVRF == 0 {
			return
		}
		c.logger.Debug("Releasing endpoint, no VRF matches", logfields.EndpointID, ep.GetID())
		c.releaseEndpoint(ctx, ep, "endpoint no longer matches any VRF")
		return
	}

	if curVRF == uint32(match.ID) {
		return
	}

	c.logger.Debug("Regenerating endpoint into VRF",
		logfields.EndpointID, ep.GetID(),
		fieldVRF, match.Name,
	)
	c.regenerateEndpoint(ctx, ep, uint32(match.ID), "endpoint reconciled into VRF")
}

// reconcileEndpoints evaluates every local endpoint against the current set
// of active VRFs and publishes any membership conflicts discovered to the
// IsovalentCoreVRFNodeStatus CR.
func (c *controller) reconcileEndpoints(ctx context.Context, rtxn statedb.ReadTxn, conflict membershipConflict) {
	epMap, err := c.lxcMap.DumpToMap()
	if err != nil {
		c.logger.Warn("Failed to dump lxcmap, skipping endpoint reconciliation", logfields.Error, err)
		return
	}
	for _, ep := range c.endpoints.GetEndpoints() {
		c.reconcileEndpoint(ctx, rtxn, ep, conflict, epMap)
	}
	if err := c.status.setMembershipConflicts(ctx, conflict.status()); err != nil {
		c.logger.Warn("Failed to set VRF membership conflicts", logfields.Error, err)
	}
}

// epMapRTInfo performs a RTInfo lookup for an endpoint within the Endpoint map.
func epMapRTInfo(ep endpointInfo, epMap map[netip.Addr]lxcmap.EndpointInfo) uint32 {
	if v4 := ep.IPv4Address(); v4.IsValid() {
		if info, ok := epMap[v4]; ok {
			return info.RTInfo
		}
	}
	if v6 := ep.IPv6Address(); v6.IsValid() {
		if info, ok := epMap[v6]; ok {
			return info.RTInfo
		}
	}
	return 0
}

// releaseEndpoint regenerates the endpoint to the default VRF.
func (c *controller) releaseEndpoint(ctx context.Context, ep endpointInfo, reason string) {
	ep.ClearRTInfo()
	ep.RegenerateIfAlive(&regeneration.ExternalRegenerationMetadata{
		Reason:            reason,
		RegenerationLevel: regeneration.RegenerateWithDatapath,
	})
}

// createVRF device will create a linux VRF device bound to the VRF's table ID
// and set the VRF's interfaces and children.
//
// It's expected that all interfaces have been deemed present on the host prior
// to invoking this function.
func (c *controller) createVRFDevice(ctx context.Context, vrf *VRF, name string) error {
	vrfDev := &netlink.Vrf{
		LinkAttrs: netlink.LinkAttrs{
			Name: name,
		},
		Table: vrf.Table,
	}

	if err := c.nl.linkAdd(vrfDev); err != nil {
		return fmt.Errorf("failed to create VRF device %s: %w", name, err)
	}
	if err := c.nl.linkSetUp(vrfDev); err != nil {
		return fmt.Errorf("failed to bring up VRF device %s: %w", name, err)
	}

	vrfLink, err := c.nl.linkByName(name)
	if err != nil {
		return fmt.Errorf("failed to look up VRF device %s after creation: %w", name, err)
	}

	if err := c.nl.linkSetAlias(vrfLink, vrf.Name); err != nil {
		return fmt.Errorf("failed to set alias on VRF device %s: %w", name, err)
	}

	for _, iface := range vrf.Interfaces {
		child, err := c.nl.linkByName(iface)
		if err != nil {
			return fmt.Errorf("failed to look up VRF child interface %s: %w", iface, err)
		}
		if err := c.nl.linkSetMaster(child, vrfLink); err != nil {
			return fmt.Errorf("failed to enslave interface %s to VRF device %s: %w", iface, name, err)
		}
	}

	return nil
}

// indexActiveVRF will add an active VRF into the controller's indexes.
//
// The index acts as a demarcation point at which a VRF becomes eligible for
// updates. Therefore, any procedures prior to the index must be indempotent.
func (c *controller) indexActiveVRF(ctx context.Context, vrf *VRF) {
	c.active[vrf.Name] = vrf
	c.activeByID[vrf.ID] = vrf
	c.activeByTableID[vrf.Table] = vrf
	for _, intf := range vrf.Interfaces {
		c.activeByBoundInterface[intf] = vrf
	}

	c.opRev++
}

// unindexActiveVRF will remove an active VRF from the controller's indexes.
//
// The unindex acts as a demarcation point at which a VRF is no longer eligible
// for updates. Therefore any procedures prior to the unindex must be indempotent.
func (c *controller) unindexActiveVRF(ctx context.Context, vrf *VRF) {
	delete(c.active, vrf.Name)
	delete(c.activeByID, vrf.ID)
	delete(c.activeByTableID, vrf.Table)
	for _, intf := range vrf.Interfaces {
		delete(c.activeByBoundInterface, intf)
	}

	c.opRev++
}

// addVRF attempts to make a VRF active in Cilium's datpath.
//
// This function will create a Linux VRF device associated with the VRF's table.
//
// The interfaces defined in the VRF will be become children of the VRF device,
// informing the kernel that traffic over those interfaces belong to the VRF.
//
// If no errors are encountered the VRF will be added to the c.active queue.
func (c *controller) addVRF(ctx context.Context, vrf *VRF, batch *vrfStatusBatch) error {
	// If this VRF's table ID conflicts with another, we must reject the add.
	if existing, ok := c.activeByTableID[vrf.Table]; ok {
		msg := fmt.Sprintf("VRF %q has conflicting table ID with active VRF %q", vrf.Name, existing.Name)
		batch.set(vrf.Name, isovalentv1alpha1.VRFConditionConflictingTableID, false, msg)
		return errors.New(msg)
	}

	// If this VRF's ID conflicts with another, we must reject the add.
	if existing, ok := c.activeByID[vrf.ID]; ok {
		msg := fmt.Sprintf("VRF %q has conflicting VRF ID with active VRF %q", vrf.Name, existing.Name)
		batch.set(vrf.Name, isovalentv1alpha1.VRFConditionConflictingID, false, msg)
		return errors.New(msg)
	}

	for _, iface := range vrf.Interfaces {
		// Ensure all required child interfaces exist on the host.
		exists, err := c.nl.linkExists(iface)
		if err != nil {
			msg := fmt.Sprintf("failed to check interface %q for VRF %q: %v", iface, vrf.Name, err)
			batch.set(vrf.Name, isovalentv1alpha1.VRFConditionInterfaceFailure, false, msg)
			return errors.New(msg)
		}
		if !exists {
			msg := fmt.Sprintf("interface %q not found for VRF %q", iface, vrf.Name)
			batch.set(vrf.Name, isovalentv1alpha1.VRFConditionInterfaceNotFound, false, msg)
			return errors.New(msg)
		}

		// ensure no other VRF binds this interface
		if existing, ok := c.activeByBoundInterface[iface]; ok {
			msg := fmt.Sprintf("interface %q for VRF %q is already bound to VRF %q", iface, vrf.Name, existing.Name)
			batch.set(vrf.Name, isovalentv1alpha1.VRFConditionInterfaceFailure, false, msg)
			return errors.New(msg)
		}
	}

	vrfLinkName := fmt.Sprintf(CiliumVRFDeviceFMT, vrf.Table)

	// If the link exists remove it, we are in the add path, so its a stale link.
	existing, err := c.nl.linkByName(vrfLinkName)
	switch {
	case err == nil:
		if err := c.nl.linkDel(existing); err != nil {
			msg := fmt.Sprintf("failed to delete stale VRF device %s for VRF %q: %v", vrfLinkName, vrf.Name, err)
			batch.set(vrf.Name, isovalentv1alpha1.VRFConditionInterfaceFailure, false, msg)
			return errors.New(msg)
		}
	case !errors.Is(err, errLinkNotFound):
		msg := fmt.Sprintf("failed to look up VRF device %s for VRF %q: %v", vrfLinkName, vrf.Name, err)
		batch.set(vrf.Name, isovalentv1alpha1.VRFConditionInterfaceFailure, false, msg)
		return errors.New(msg)
	}

	if err = c.createVRFDevice(ctx, vrf, vrfLinkName); err != nil {
		msg := fmt.Sprintf("failed to create VRF device for VRF %q: %v", vrf.Name, err)
		batch.set(vrf.Name, isovalentv1alpha1.VRFConditionInterfaceFailure, false, msg)
		return errors.New(msg)
	}

	// from here, if we fail we need to roll back the VRF creation
	defer func() {
		if err == nil {
			return
		}
		if link, rollbackErr := c.nl.linkByName(vrfLinkName); rollbackErr == nil {
			// best effort rollback
			c.nl.linkDel(link)
		}
	}()

	// Upsert vrf to table ID mapping.
	err = c.vrfMap.Upsert(vrf.ID, vrf.Table)
	if err != nil {
		msg := fmt.Sprintf("failed to upsert VRF mapping for VRF %q: %v", vrf.Name, err)
		batch.set(vrf.Name, isovalentv1alpha1.VRFConditionInterfaceFailure, false, msg)
		return errors.New(msg)
	}

	// the VRF device is now present and configured, we can consider the VRF
	// active, and add it to our indexes.
	c.indexActiveVRF(ctx, vrf)

	msg := fmt.Sprintf("vrf %s successfully created", vrf.Name)
	batch.set(vrf.Name, "", true, msg)
	c.logger.Info(msg)

	return nil
}

// removeVRF will remove the VRF device associated with the VRF and finally
// remove the VRF from the controller's index. Endpoints previously bound to
// this VRF are released back to the default VRF by the post-reconcile
// endpoint sweep in the run loop.
func (c *controller) removeVRF(ctx context.Context, vrf *VRF) error {
	if err := c.vrfMap.Delete(vrf.ID); err != nil {
		return fmt.Errorf("failed to delete VRF mapping for VRF %q: %w", vrf.Name, err)
	}

	vrfLinkName := fmt.Sprintf(CiliumVRFDeviceFMT, vrf.Table)
	vrfLink, err := c.nl.linkByName(vrfLinkName)
	if err != nil && !errors.Is(err, errLinkNotFound) {
		return fmt.Errorf("failed to look up VRF device for VRF %q during removal: %w", vrf.Name, err)
	}

	if vrfLink != nil {
		if err := c.nl.linkDel(vrfLink); err != nil {
			return fmt.Errorf("failed to delete VRF device %s: %w", vrfLinkName, err)
		}
	}

	// VRF successfully cleaned up, we can remove it form our indexes.
	c.unindexActiveVRF(ctx, vrf)

	c.logger.Debug("VRF successfully removed", fieldVRF, vrf.Name)

	return nil
}

// updateVRF handles changes in an active VRF.
//
// This function is also crucial in the initialize and restore path used on
// agent restore.
//
// Because this function is used both for updating VRFs created during runtime
// and partial VRFs seeded during restore, we must ensure all aspects of a
// VRF are in sync with the kernel's state.
func (c *controller) updateVRF(ctx context.Context, newVRF *VRF, batch *vrfStatusBatch) error {
	oldVRF, ok := c.active[newVRF.Name]
	if !ok {
		return fmt.Errorf("VRF %q is not active, cannot update", newVRF.Name)
	}

	// An ID of 0 signals that oldVRF is a VRF that must be restored after
	// agent restart, we can set the ID now, so we avoid the full recreation
	// below, unless the table ID legitimately changed.
	if oldVRF.ID == 0 {
		oldVRF.ID = newVRF.ID
	}

	// When the VRF ID changes or the table ID changes, we'll perform a full
	// recreation of the VRF.
	if oldVRF.Table != newVRF.Table || oldVRF.ID != newVRF.ID {
		// ensure ID is not active
		if existing, ok := c.activeByID[newVRF.ID]; ok && existing.Name != newVRF.Name {
			msg := fmt.Sprintf("VRF %q has conflicting VRF ID with active VRF %q", newVRF.Name, existing.Name)
			batch.set(newVRF.Name, isovalentv1alpha1.VRFConditionConflictingID, false, msg)
			return errors.New(msg)
		}

		// ensure new TableID is not already active
		if existing, ok := c.activeByTableID[newVRF.Table]; ok && existing.Name != newVRF.Name {
			msg := fmt.Sprintf("VRF %q has conflicting table ID with active VRF %q", newVRF.Name, existing.Name)
			batch.set(newVRF.Name, isovalentv1alpha1.VRFConditionConflictingTableID, false, msg)
			return errors.New(msg)
		}

		if err := c.removeVRF(ctx, oldVRF); err != nil {
			msg := fmt.Sprintf("failed to remove old VRF %q during update: %v", oldVRF.Name, err)
			batch.set(newVRF.Name, isovalentv1alpha1.VRFConditionUpdateFailure, false, msg)
			return errors.New(msg)
		}

		if err := c.addVRF(ctx, newVRF, batch); err != nil {
			// addVRF already sets the specific error condition on the node status.
			return fmt.Errorf("failed to add new VRF %q during update: %w", newVRF.Name, err)
		}

		return nil
	}

	// Selector changes do not need any action here: the post-reconcile
	// endpoint sweep in the run loop will re-evaluate every endpoint against
	// the updated active VRF set.

	if !slices.Equal(oldVRF.Interfaces, newVRF.Interfaces) {
		vrfDevName := fmt.Sprintf(CiliumVRFDeviceFMT, newVRF.Table)
		vrfLink, err := c.nl.linkByName(vrfDevName)
		if err != nil {
			msg := fmt.Sprintf("failed to look up VRF device %s: %v", vrfDevName, err)
			batch.set(newVRF.Name, isovalentv1alpha1.VRFConditionUpdateFailure, false, msg)
			return errors.New(msg)
		}

		// Reject the update before mutating any kernel state if any new interface
		// is already bound to a different active VRF. This keeps us out of a
		// half-updated state where some interfaces have been (un)bound but the
		// update ultimately fails.
		for _, iface := range newVRF.Interfaces {
			if owner, ok := c.activeByBoundInterface[iface]; ok && owner.Name != oldVRF.Name {
				msg := fmt.Sprintf("interface %q cannot be bound to VRF %q: already bound to VRF %q", iface, oldVRF.Name, owner.Name)
				batch.set(oldVRF.Name, isovalentv1alpha1.VRFConditionInterfaceFailure, false, msg)
				return errors.New(msg)
			}
		}

		// unbind removed interfaces
		for _, iface := range oldVRF.Interfaces {
			if slices.Contains(newVRF.Interfaces, iface) {
				continue
			}
			child, err := c.nl.linkByName(iface)
			if err != nil {
				msg := fmt.Sprintf("failed to look up interface %s to unbind from %s: %v", iface, vrfDevName, err)
				batch.set(newVRF.Name, isovalentv1alpha1.VRFConditionInterfaceFailure, false, msg)
				return errors.New(msg)
			}
			if err := c.nl.linkSetNoMaster(child); err != nil {
				msg := fmt.Sprintf("failed to unbind interface %s from VRF %s: %v", iface, vrfDevName, err)
				batch.set(newVRF.Name, isovalentv1alpha1.VRFConditionInterfaceFailure, false, msg)
				return errors.New(msg)
			}
			// the interface is no longer bound to this VRF; release it from the
			// index so a future VRF can claim it.
			delete(c.activeByBoundInterface, iface)
		}

		// bind added interfaces
		for _, iface := range newVRF.Interfaces {
			if slices.Contains(oldVRF.Interfaces, iface) {
				continue
			}
			child, err := c.nl.linkByName(iface)
			if err != nil {
				msg := fmt.Sprintf("failed to look up interface %s to bind to %s: %v", iface, vrfDevName, err)
				batch.set(newVRF.Name, isovalentv1alpha1.VRFConditionInterfaceFailure, false, msg)
				return errors.New(msg)
			}
			if err := c.nl.linkSetMaster(child, vrfLink); err != nil {
				msg := fmt.Sprintf("failed to bind interface %s to VRF %s: %v", iface, vrfDevName, err)
				batch.set(newVRF.Name, isovalentv1alpha1.VRFConditionInterfaceFailure, false, msg)
				return errors.New(msg)
			}
		}
	}

	// we'll do this defensively on update, it makes the restore path simpler
	// and is an O(1) operation.
	if err := c.vrfMap.Upsert(newVRF.ID, newVRF.Table); err != nil {
		msg := fmt.Sprintf("failed to upsert VRF mapping for VRF %q: %v", newVRF.Name, err)
		batch.set(newVRF.Name, isovalentv1alpha1.VRFConditionUpdateFailure, false, msg)
		return errors.New(msg)
	}

	c.indexActiveVRF(ctx, newVRF)

	msg := fmt.Sprintf("vrf %s successfully updated", newVRF.Name)
	batch.set(newVRF.Name, "", true, msg)

	return nil
}

// vrfsForNodes filters the list of VRFs known to the control-plane to the
// set of VRFs which match this node.
func (c *controller) vrfsForNode(ctx context.Context, rtxn statedb.ReadTxn) ([]*VRF, error) {
	localNode, err := c.localNodeStore.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get local node: %w", err)
	}

	allVRFs := statedb.Collect(c.vrfs.All(rtxn))
	vrfsForNode := make([]*VRF, 0, len(allVRFs))

	for i := range allVRFs {
		if allVRFs[i].MatchesNode(localNode.Labels) {
			vrfsForNode = append(vrfsForNode, &allVRFs[i])
		}
	}

	return vrfsForNode, nil
}

func (c *controller) reconcileVRFs(ctx context.Context, rc *reconcileCache, rtxn statedb.ReadTxn) (bool, error) {
	vrfsForNode, err := c.vrfsForNode(ctx, rtxn)
	if err != nil {
		return false, fmt.Errorf("failed to get VRFs for node: %w", err)
	}

	rev := c.opRev
	batch := newVRFStatusBatch()

	// Mark all active VRFs for removal; we'll prune these out below.
	if rc.toRemove == nil {
		rc.toRemove = make(map[string]*VRF, len(c.active))
	}
	maps.Copy(rc.toRemove, c.active)

	for _, vrf := range vrfsForNode {
		if active, ok := c.active[vrf.Name]; ok {
			delete(rc.toRemove, vrf.Name)
			if !active.Equal(vrf) {
				rc.toUpdate = append(rc.toUpdate, vrf)
			}
		} else {
			rc.toAdd = append(rc.toAdd, vrf)
		}
	}

	c.logger.Debug("VRF reconciliation",
		fieldToAdd, len(rc.toAdd),
		fieldToRemove, len(rc.toRemove),
		fieldToUpdate, len(rc.toUpdate),
	)

	// Process removes first to free table/VRF IDs before adds and updates.
	for _, vrf := range rc.toRemove {
		if err := c.removeVRF(ctx, vrf); err != nil {
			c.logger.Error("Failed to remove VRF",
				fieldVRF, vrf.Name,
				logfields.Error, err,
			)
		}
	}

	for _, vrf := range rc.toUpdate {
		if err := c.updateVRF(ctx, vrf, batch); err != nil {
			c.logger.Error("Failed to update VRF",
				fieldVRF, vrf.Name,
				logfields.Error, err,
			)
		}
	}

	for _, vrf := range rc.toAdd {
		if err := c.addVRF(ctx, vrf, batch); err != nil {
			c.logger.Error("Failed to add VRF",
				fieldVRF, vrf.Name,
				logfields.Error, err,
			)
		}
	}

	// batches are snapshots, so add any active VRFs not touched by a reconcile
	// function above.
	for name, vrf := range c.active {
		if _, ok := batch.entries[name]; ok {
			continue
		}
		batch.set(name, "", true, fmt.Sprintf("vrf %s active", vrf.Name))
	}

	if err := c.status.setVRFStatuses(ctx, batch); err != nil {
		c.logger.Warn("Failed to flush VRF statuses", logfields.Error, err)
	}

	return c.opRev != rev, nil
}

// initTableSync ensures all stateDB tables the controller reads from are
// populated before c.init proceeds.
//
// Callers must acquire a fresh ReadTxn after this returns: statedb is MVCC,
// and any ReadTxn captured before init completes will not see the rows
// written during init.
func (c *controller) initTableSync(ctx context.Context) error {
	rtxn := c.db.ReadTxn()
	var watches []<-chan struct{}
	if ok, watch := c.localNodes.Initialized(rtxn); !ok {
		watches = append(watches, watch)
	}
	if ok, watch := c.namespaces.Initialized(rtxn); !ok {
		watches = append(watches, watch)
	}
	if ok, watch := c.pods.Initialized(rtxn); !ok {
		watches = append(watches, watch)
	}
	if ok, watch := c.vrfs.Initialized(rtxn); !ok {
		watches = append(watches, watch)
	}
	if ok, watch := c.devices.Initialized(rtxn); !ok {
		watches = append(watches, watch)
	}

	if len(watches) > 0 {
		c.logger.Info("Waiting for upstream stateDB tables to initialize before restore")
	}
	for _, watch := range watches {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-watch:
		}
	}
	return nil
}

func (c *controller) init(ctx context.Context) error {
	if err := c.initTableSync(ctx); err != nil {
		return err
	}
	rtxn := c.db.ReadTxn()

	// get VRFs that apply to this node
	vrfsForNode, err := c.vrfsForNode(ctx, rtxn)
	if err != nil {
		return fmt.Errorf("failed to get VRFs for node during restore: %w", err)
	}

	vrfsByName := map[string]*VRF{}
	allVRFsForNodeByID := map[uint16]*VRF{}
	for i := range vrfsForNode {
		vrf := vrfsForNode[i]
		vrfsByName[vrf.Name] = vrf
		allVRFsForNodeByID[vrf.ID] = vrf
	}

	links, err := c.nl.linkList()
	if err != nil {
		return fmt.Errorf("failed to list links during restore: %w", err)
	}

	ciliumVRFDevicesByDevName := map[string]netlink.Link{}
	restorableByDevName := map[string]*VRF{}

	for _, link := range links {
		if _, ok := link.(*netlink.Vrf); !ok {
			continue
		}
		devName := link.Attrs().Name
		if !strings.HasPrefix(devName, CiliumVRFDevicePrefix) {
			continue
		}

		ciliumVRFDevicesByDevName[devName] = link

		// if a cilium VRF device's alias matches a VRF being applied to this
		// node, we can restore it on next reconcile.
		alias := link.Attrs().Alias
		if alias == "" {
			continue
		}
		if vrf, ok := vrfsByName[alias]; ok {
			restorableByDevName[devName] = vrf
		}
	}

	// remove all invalid interfaces
	for devName, link := range ciliumVRFDevicesByDevName {
		if _, ok := restorableByDevName[devName]; ok {
			continue
		}
		c.logger.Info("Removing orphaned VRF device",
			fieldVRFDevice, devName,
			fieldAlias, link.Attrs().Alias,
		)
		if err := c.nl.linkDel(link); err != nil {
			c.logger.Warn("Failed to delete orphaned VRF device",
				fieldVRFDevice, devName,
				fieldAlias, link.Attrs().Alias,
				logfields.Error, err,
			)
		}
	}

	// restore partial VRF to active, next reconcile will perform an update
	// on this partial, and resolve it fully.
	for devName, vrf := range restorableByDevName {
		link := ciliumVRFDevicesByDevName[devName]

		var tableID uint32
		if _, err := fmt.Sscanf(devName, CiliumVRFDeviceFMT, &tableID); err != nil {
			c.logger.Warn("Failed to parse table ID from VRF device name",
				fieldVRFDevice, devName,
				logfields.Error, err,
			)
			continue
		}

		partial := VRF{
			// ID zero represents a restore, minimum ID via API is 1.
			ID:    0,
			Name:  vrf.Name,
			Table: tableID,
		}

		// get names of interfaces enslaved to associated VRF device
		for _, child := range links {
			if child.Attrs().MasterIndex == link.Attrs().Index {
				partial.Interfaces = append(partial.Interfaces, child.Attrs().Name)
			}
		}
		slices.Sort(partial.Interfaces)

		c.active[vrf.Name] = &partial
		// Populate the bound-interface index so that interface conflicts are
		// detected on the first reconcile after restore.
		for _, intf := range partial.Interfaces {
			c.activeByBoundInterface[intf] = &partial
		}
	}

	// finally sync VRF map with current set of VRFs, we should not have any
	// VRF IDs present in the map that are not present in our list of VRFs
	// targeting this host.
	vrfsInMap, err := c.vrfMap.List()
	if err != nil {
		return fmt.Errorf("failed to list VRF map during restore: %w", err)
	}
	for vid, tbid := range vrfsInMap {
		if _, ok := allVRFsForNodeByID[vid]; !ok {
			c.logger.Info("Removing stale VRF mapping from BPF map",
				fieldVRF, vid,
				fieldTable, tbid,
			)
			if err := c.vrfMap.Delete(vid); err != nil {
				c.logger.Warn("Failed to delete stale VRF mapping from BPF map",
					fieldVRF, vid,
					logfields.Error, err,
				)
			}
		}
	}

	// clear VRF statuses, will be set on next reconcile, ensuring no stale
	// statuses are present.
	if err := c.status.clearAllVRFStatuses(ctx); err != nil {
		c.logger.Warn("Failed to clear VRF statuses during init", logfields.Error, err)
	}

	return nil
}

// Run starts our controller's reconcile loop.
func (c *controller) run(ctx context.Context, _ cell.Health) error {
	c.logger.Info("Starting VRF controller")

	// wait on endpoint manager to finish restores, ensuring we start our
	// reconciliation loop with all endpoints identified.
	restorer, err := c.epRestorerPromise.Await(ctx)
	if err != nil {
		return fmt.Errorf("failed to await endpoint restorer: %w", err)
	}
	if err := restorer.WaitForEndpointRestoreWithoutRegeneration(ctx); err != nil {
		return fmt.Errorf("failed to wait for endpoint restoration: %w", err)
	}

	localNode, err := c.localNodeStore.Get(ctx)
	if err != nil {
		return fmt.Errorf("failed to get local node: %w", err)
	}
	c.nodeName = localNode.Name
	c.status = newK8sVRFStatusReporter(c.clientset, c.nodeName)

	if err := c.status.init(ctx); err != nil {
		return fmt.Errorf("failed to initialize VRF status reporter: %w", err)
	}

	var rc reconcileCache

	if err := c.init(ctx); err != nil {
		return fmt.Errorf("failed to initialize VRF controller: %w", err)
	}

	// subscribe to endpoint events, may cost one extraneous endpoint
	// reconciliation but ensures we do not miss an event between first
	// reconciliation and the reconciliation loop.
	c.endpointManager.Subscribe(c)
	defer c.endpointManager.Unsubscribe(c)

	initialTxn := c.db.ReadTxn()
	_, err = c.reconcileVRFs(ctx, &rc, initialTxn)
	if err != nil {
		c.logger.Error("Failed to reconcile VRFs", logfields.Error, err)
	}

	conflict := make(membershipConflict)
	c.reconcileEndpoints(ctx, initialTxn, conflict)

	retryTicker := time.NewTicker(reconcileInterval)
	defer retryTicker.Stop()

	for {
		// this ReadTxn is simply to get watches, we don't care about this
		// snapshot of the db.
		rtxn := c.db.ReadTxn()
		vrfsAll, vrfWatch := c.vrfs.AllWatch(rtxn)
		vrfs := statedb.Collect(vrfsAll)

		_, deviceWatch := c.devices.AllWatch(rtxn)
		_, _, nodeWatch, _ := c.localNodes.GetWatch(rtxn, node.LocalNodeQuery)
		_, namespaceWatch := c.namespaces.AllWatch(rtxn)
		_, podWatch := c.pods.AllWatch(rtxn)

		clear(conflict)

		select {
		case <-ctx.Done():
			return nil
		// watch for VRF changes
		case <-vrfWatch:
			c.logger.Debug("VRF change detected, reconciling")
		// watch for device changes, if a VRF is rejected due to an interface
		// in the VRF not being present, this event may reconcile the rejected
		// VRF.
		case <-deviceWatch:
			c.logger.Debug("Device change detected, reconciling")
		// watch for local node changes, if node labels change, a VRF may begin
		// to, or may no longer, apply to a node.
		case <-nodeWatch:
			c.logger.Debug("Local node change detected, reconciling")
		// watch for namespace changes, labels that change will effect endpoint
		// VRF memberships.
		case <-namespaceWatch:
			c.logger.Debug("Namespace change detected, reconciling endpoints")
			endpointTxn := c.db.ReadTxn()
			c.reconcileEndpoints(ctx, endpointTxn, conflict)
			continue
		// watch for pod changes, labels that change will effect endpoint
		// VRF memberships.
		case <-podWatch:
			c.logger.Debug("Pod change detected, reconciling endpoints")
			endpointTxn := c.db.ReadTxn()
			c.reconcileEndpoints(ctx, endpointTxn, conflict)
			continue
		// watch for endpoint events, endpoint lifecycle events require VRF
		// membership reconciliation.
		case <-c.endpointManagerEvent:
			c.logger.Debug("Endpoint change detected, reconciling endpoints")
			endpointTxn := c.db.ReadTxn()
			c.reconcileEndpoints(ctx, endpointTxn, conflict)
			continue
		// a general reconciliation clock, this handles any transient errors,
		// such as netlink issues, that may have rejected a VRF at the time,
		// but has subsided.
		case <-retryTicker.C:
			if len(vrfs) == 0 && len(c.active) == 0 {
				continue
			}
			c.logger.Debug("Periodic VRF reconciliation")
		}
		rc.reset()
		// first reconcile the VRF state, ensuring all VRFs reflect the
		// desired state.
		reconcileTxn := c.db.ReadTxn()
		changed, err := c.reconcileVRFs(ctx, &rc, reconcileTxn)
		if err != nil {
			c.logger.Error("Failed to reconcile VRFs", logfields.Error, err)
			continue
		}
		// only reconcile endpoints if VRF state actually changed.
		if changed {
			c.reconcileEndpoints(ctx, reconcileTxn, conflict)
		}
	}
}

// endpointManagerEventNotify bridges endpoint manager events into a coalesced
// signal to the controller via a push to the endpointManagerEvent channel.
func (c *controller) endpointManagerEventNotify() {
	select {
	case c.endpointManagerEvent <- struct{}{}:
	default:
	}
}

// EndpointCreated implements endpointmanager.Subscriber.
func (c *controller) EndpointCreated(_ *endpoint.Endpoint) { c.endpointManagerEventNotify() }

// EndpointDeleted implements endpointmanager.Subscriber.
func (c *controller) EndpointDeleted(_ *endpoint.Endpoint, _ endpoint.DeleteConfig) {
	c.endpointManagerEventNotify()
}

// EndpointRestored implements endpointmanager.Subscriber.
func (c *controller) EndpointRestored(_ *endpoint.Endpoint) { c.endpointManagerEventNotify() }
