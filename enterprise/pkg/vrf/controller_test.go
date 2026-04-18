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
	"testing"
	"time"

	"github.com/cilium/statedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/endpoint"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

func newTestController() *controller {
	db := statedb.New()
	vrfs, err := NewVRFTable(db)
	if err != nil {
		panic(fmt.Sprintf("NewVRFTable: %v", err))
	}
	return &controller{
		logger:                 slog.New(slog.DiscardHandler),
		db:                     db,
		vrfs:                   vrfs,
		pods:                   newPodTable(db),
		namespaces:             newNamespaceTable(db),
		localNodes:             newLocalNodeTable(db),
		devices:                newDeviceTable(db),
		localNodeStore:         node.NewTestLocalNodeStore(node.LocalNode{Node: nodeTypes.Node{Name: "test-node"}}),
		active:                 map[string]*VRF{},
		activeByID:             map[uint16]*VRF{},
		activeByTableID:        map[uint32]*VRF{},
		activeByBoundInterface: map[string]*VRF{},
		nl:                     newFakeNetLink(),
		vrfMap:                 newFakeVRFMap(),
		lxcMap:                 newFakeLxcMap(),
		status:                 newFakeStatusReporter(),
	}
}

// TestAddVRF_HappyPath ensures a VRF can be made active when no error case
// is encountered.
func TestAddVRF_HappyPath(t *testing.T) {
	c := newTestController()
	nl := c.nl.(*fakeNetLink)
	nl.addExisting(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0"}})

	vrf := &VRF{
		Name:       "v1",
		ID:         1,
		Table:      100,
		Interfaces: []string{"eth0"},
	}

	batch := newVRFStatusBatch()
	err := c.addVRF(context.Background(), vrf, batch)
	require.NoError(t, err)
	require.NoError(t, c.status.setVRFStatuses(context.Background(), batch))

	assert.Same(t, vrf, c.active["v1"])
	assert.Same(t, vrf, c.activeByID[1])
	assert.Same(t, vrf, c.activeByTableID[100])

	vrfDev, ok := nl.links["cvrf-100"]
	require.True(t, ok, "cvrf-100 link should exist")
	_, isVrf := vrfDev.(*netlink.Vrf)
	assert.True(t, isVrf, "cvrf-100 should be a *netlink.Vrf")
	assert.Equal(t, "cvrf-100", nl.masters["eth0"])

	vrfMap := c.vrfMap.(*fakeVRFMap)
	table, err := vrfMap.Get(1)
	require.NoError(t, err)
	assert.Equal(t, uint32(100), table)

	status := c.status.(*fakeStatusReporter)
	require.Len(t, status.calls, 1)
	require.Contains(t, status.calls[0].entries, "v1")
	assert.True(t, status.calls[0].entries["v1"].ready)
}

// TestAddVRF_ConflictingTableID ensures VRF add fails when another VRF already
// owns the VRF's table ID.
func TestAddVRF_ConflictingTableID(t *testing.T) {
	c := newTestController()
	c.activeByTableID[100] = &VRF{Name: "existing", ID: 2, Table: 100}

	vrf := &VRF{Name: "v1", ID: 1, Table: 100, Interfaces: []string{"eth0"}}
	batch := newVRFStatusBatch()
	err := c.addVRF(context.Background(), vrf, batch)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "conflicting table ID")
	require.NoError(t, c.status.setVRFStatuses(context.Background(), batch))

	assert.NotContains(t, c.active, "v1")

	status := c.status.(*fakeStatusReporter)
	require.Len(t, status.calls, 1)
	require.Contains(t, status.calls[0].entries, "v1")
	assert.Equal(t, isovalentv1alpha1.VRFConditionConflictingTableID, status.calls[0].entries["v1"].condition)
	assert.False(t, status.calls[0].entries["v1"].ready)
}

// TestAddVRF_ConflictingVRFID ensures VRF add fails when another VRF already
// owns the VRF ID.
func TestAddVRF_ConflictingVRFID(t *testing.T) {
	c := newTestController()
	c.activeByID[1] = &VRF{Name: "existing", ID: 1, Table: 200}

	vrf := &VRF{Name: "v1", ID: 1, Table: 100, Interfaces: []string{"eth0"}}
	batch := newVRFStatusBatch()
	err := c.addVRF(context.Background(), vrf, batch)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "conflicting VRF ID")
	require.NoError(t, c.status.setVRFStatuses(context.Background(), batch))

	assert.NotContains(t, c.active, "v1")

	status := c.status.(*fakeStatusReporter)
	require.Len(t, status.calls, 1)
	require.Contains(t, status.calls[0].entries, "v1")
	assert.Equal(t, isovalentv1alpha1.VRFConditionConflictingID, status.calls[0].entries["v1"].condition)
	assert.False(t, status.calls[0].entries["v1"].ready)
}

// TestAddVRF_InterfaceNotFound ensures VRF add fails when a bound interface
// cannot be found.
func TestAddVRF_InterfaceNotFound(t *testing.T) {
	c := newTestController()

	vrf := &VRF{Name: "v1", ID: 1, Table: 100, Interfaces: []string{"eth0"}}
	batch := newVRFStatusBatch()
	err := c.addVRF(context.Background(), vrf, batch)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
	require.NoError(t, c.status.setVRFStatuses(context.Background(), batch))

	assert.NotContains(t, c.active, "v1")
	nl := c.nl.(*fakeNetLink)
	_, hasLink := nl.links["cvrf-100"]
	assert.False(t, hasLink, "cvrf-100 should not exist")

	status := c.status.(*fakeStatusReporter)
	require.Len(t, status.calls, 1)
	require.Contains(t, status.calls[0].entries, "v1")
	assert.Equal(t, isovalentv1alpha1.VRFConditionInterfaceNotFound, status.calls[0].entries["v1"].condition)
	assert.False(t, status.calls[0].entries["v1"].ready)
}

// TestInitRestore tests that the controller successfully initializes and
// restores its state based on the kernel's data-path.
//
// Two cilium VRF devices are created, one of which corresponds to a valid VRF,
// and the other that does not.
//
// Additionally, two children devices are bound to both interfaces.
//
// After the restore runs, we expect `vrf-red` to be in an active state,
// the cvrf-200 device should be removed from the system because no VRF
// refers to it, and the extraneous VRF ID in the VRF map should be removed.
//
// Additionally, the scenario adds a non-partial VRF between init() and
// reconcileVRFs, ensuring asynchronous VRF additions work correctly in the presence
// of partial VRFs.
func TestInitRestore(t *testing.T) {
	c := newTestController()
	db := c.db
	vrfTable := c.vrfs.(statedb.RWTable[VRF])
	nl := c.nl.(*fakeNetLink)
	vrfMap := c.vrfMap.(*fakeVRFMap)
	status := c.status.(*fakeStatusReporter)

	wtxn := db.WriteTxn(vrfTable)
	vrfTable.Insert(wtxn, VRF{
		Name:       "vrf-red",
		ID:         1,
		Table:      100,
		Interfaces: []string{"eth0"},
	})
	wtxn.Commit()

	nl.addExisting(&netlink.Vrf{
		LinkAttrs: netlink.LinkAttrs{Name: "cvrf-100", Index: 10, Alias: "vrf-red"},
		Table:     100,
	})
	nl.addExisting(&netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{Name: "eth0", Index: 11, MasterIndex: 10},
	})
	nl.addExisting(&netlink.Vrf{
		LinkAttrs: netlink.LinkAttrs{Name: "cvrf-200", Index: 20},
		Table:     200,
	})
	nl.addExisting(&netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{Name: "eth1", Index: 21, MasterIndex: 20},
	})
	nl.addExisting(&netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{Name: "eth2", Index: 22},
	})

	vrfMap.m[1] = 100
	vrfMap.m[3] = 300

	ctx := context.Background()
	// this creates a list of partial VRFs that will be restored on next
	// reconcile, along with stale interface cleanup.
	err := c.init(ctx)
	require.NoError(t, err)

	require.Contains(t, c.active, "vrf-red")
	partial := c.active["vrf-red"]
	assert.Equal(t, uint16(0), partial.ID)
	assert.Equal(t, uint32(100), partial.Table)
	assert.Equal(t, []string{"eth0"}, partial.Interfaces)

	_, hasLink := nl.links["cvrf-200"]
	assert.False(t, hasLink, "cvrf-200 should not exist")
	_, hasLink = nl.links["cvrf-100"]
	assert.True(t, hasLink, "cvrf-100 should exist")
	_, hasEth0 := nl.links["eth0"]
	assert.True(t, hasEth0, "eth0 should still exist")
	_, hasEth1 := nl.links["eth1"]
	assert.True(t, hasEth1, "eth1 should still exist")
	_, hasEth2 := nl.links["eth2"]
	assert.True(t, hasEth2, "eth2 should still exist")

	_, err = vrfMap.Get(1)
	assert.NoError(t, err)
	_, err = vrfMap.Get(3)
	assert.Error(t, err)

	require.Len(t, status.calls, 1)
	assert.Equal(t, "clearAllVRFStatuses", status.calls[0].op)

	_, child := nl.masters["eth1"]
	assert.False(t, child, "eth1 should not be a child of any VRF device after init")

	wtxn = db.WriteTxn(vrfTable)
	vrfTable.Insert(wtxn, VRF{
		Name:       "vrf-blue",
		ID:         2,
		Table:      200,
		Interfaces: []string{"eth1"},
	})
	wtxn.Commit()

	var rc reconcileCache
	status.calls = nil

	changed, err := c.reconcileVRFs(ctx, &rc, db.ReadTxn())
	require.NoError(t, err)
	require.True(t, changed)

	require.Contains(t, c.active, "vrf-red")
	restored := c.active["vrf-red"]
	assert.Equal(t, uint16(1), restored.ID)
	assert.Equal(t, uint32(100), restored.Table)
	assert.Same(t, restored, c.activeByID[1])
	assert.Same(t, restored, c.activeByTableID[100])

	require.Contains(t, c.active, "vrf-blue")
	added := c.active["vrf-blue"]
	assert.Equal(t, uint16(2), added.ID)
	assert.Equal(t, uint32(200), added.Table)
	assert.Same(t, added, c.activeByID[2])
	assert.Same(t, added, c.activeByTableID[200])

	_, hasLink = nl.links["cvrf-100"]
	assert.True(t, hasLink, "cvrf-100 should exist")
	_, hasLink = nl.links["cvrf-200"]
	assert.True(t, hasLink, "cvrf-200 should exist")
	// a bit subtle, but this check ensures that the restore path detected
	// the original child device of the VRF, and did not need to set eth0 as
	// a child on the cvrf-100 device unnecessarily.
	_, child = nl.masters["eth0"]
	assert.False(t, child, "eth0 should not have been re-childed during restore")
	assert.Equal(t, "cvrf-200", nl.masters["eth1"])

	table, err := vrfMap.Get(1)
	require.NoError(t, err)
	assert.Equal(t, uint32(100), table)

	table, err = vrfMap.Get(2)
	require.NoError(t, err)
	assert.Equal(t, uint32(200), table)

	require.Len(t, status.calls, 1)
	require.Equal(t, "setVRFStatuses", status.calls[0].op)
	require.Len(t, status.calls[0].entries, 2)
	for _, entry := range status.calls[0].entries {
		assert.True(t, entry.ready)
	}
}

// TestUpdateVRF_TableChanged tests that when the table ID of a VRF is changed
// the recreate loop for the VRF is performed correctly.
func TestUpdateVRF_TableChanged(t *testing.T) {
	c := newTestController()
	nl := c.nl.(*fakeNetLink)
	vrfMap := c.vrfMap.(*fakeVRFMap)
	status := c.status.(*fakeStatusReporter)

	nl.addExisting(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0"}})

	oldVRF := &VRF{
		Name:       "v1",
		ID:         1,
		Table:      100,
		Interfaces: []string{"eth0"},
	}
	require.NoError(t, c.addVRF(context.Background(), oldVRF, newVRFStatusBatch()))

	_, hasLink := nl.links["cvrf-100"]
	assert.True(t, hasLink, "cvrf-100 should exist")
	assert.Equal(t, "cvrf-100", nl.masters["eth0"])

	status.calls = nil

	newVRF := &VRF{
		Name:       "v1",
		ID:         1,
		Table:      200,
		Interfaces: []string{"eth0"},
	}
	batch := newVRFStatusBatch()
	err := c.updateVRF(context.Background(), newVRF, batch)
	require.NoError(t, err)
	require.NoError(t, c.status.setVRFStatuses(context.Background(), batch))

	_, hasOld := nl.links["cvrf-100"]
	assert.False(t, hasOld, "cvrf-100 should not exist")
	_, hasNew := nl.links["cvrf-200"]
	assert.True(t, hasNew, "cvrf-200 should exist")
	assert.Equal(t, "cvrf-200", nl.masters["eth0"])

	assert.Same(t, newVRF, c.active["v1"])
	assert.Same(t, newVRF, c.activeByID[1])
	assert.Same(t, newVRF, c.activeByTableID[200])
	_, stale := c.activeByTableID[100]
	assert.False(t, stale, "old table ID should not remain indexed")

	_, err = vrfMap.Get(1)
	require.NoError(t, err)

	require.NotEmpty(t, status.calls)
	last := status.calls[len(status.calls)-1]
	require.Contains(t, last.entries, "v1")
	assert.True(t, last.entries["v1"].ready)
}

// TestUpdateVRF_InterfacesChanged ensures that when a VRF's interface list
// changes the correct children interfaces are (un)bound to the VRF device.
func TestUpdateVRF_InterfacesChanged(t *testing.T) {
	c := newTestController()
	nl := c.nl.(*fakeNetLink)
	status := c.status.(*fakeStatusReporter)

	nl.addExisting(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0"}})
	nl.addExisting(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth1"}})
	nl.addExisting(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth2"}})

	oldVRF := &VRF{
		Name:       "v1",
		ID:         1,
		Table:      100,
		Interfaces: []string{"eth0", "eth1"},
	}
	require.NoError(t, c.addVRF(context.Background(), oldVRF, newVRFStatusBatch()))

	assert.Equal(t, "cvrf-100", nl.masters["eth0"])
	assert.Equal(t, "cvrf-100", nl.masters["eth1"])

	status.calls = nil

	newVRF := &VRF{
		Name:       "v1",
		ID:         1,
		Table:      100,
		Interfaces: []string{"eth0", "eth2"},
	}
	batch := newVRFStatusBatch()
	err := c.updateVRF(context.Background(), newVRF, batch)
	require.NoError(t, err)
	require.NoError(t, c.status.setVRFStatuses(context.Background(), batch))

	assert.Equal(t, "cvrf-100", nl.masters["eth0"])
	_, isChild := nl.masters["eth1"]
	assert.False(t, isChild, "eth1 should have been removed as a child")
	assert.Equal(t, "cvrf-100", nl.masters["eth2"])

	_, hasLink := nl.links["cvrf-100"]
	assert.True(t, hasLink, "cvrf-100 should exist")

	require.NotEmpty(t, status.calls)
	last := status.calls[len(status.calls)-1]
	require.Contains(t, last.entries, "v1")
	assert.True(t, last.entries["v1"].ready)
}

// TestRemoveVRF_HappyPath ensures the proper cleanup actions are taken when a
// VRF is removed and no error case is encountered.
func TestRemoveVRF_HappyPath(t *testing.T) {
	c := newTestController()
	nl := c.nl.(*fakeNetLink)
	vrfMap := c.vrfMap.(*fakeVRFMap)
	status := c.status.(*fakeStatusReporter)

	nl.addExisting(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0"}})

	vrf := &VRF{Name: "v1", ID: 1, Table: 100, Interfaces: []string{"eth0"}}
	require.NoError(t, c.addVRF(context.Background(), vrf, newVRFStatusBatch()))
	status.calls = nil

	err := c.removeVRF(context.Background(), vrf)
	require.NoError(t, err)

	_, active := c.active["v1"]
	assert.False(t, active)
	_, byID := c.activeByID[1]
	assert.False(t, byID)
	_, byTable := c.activeByTableID[100]
	assert.False(t, byTable)

	_, hasLink := nl.links["cvrf-100"]
	assert.False(t, hasLink, "cvrf-100 should be deleted")

	_, err = vrfMap.Get(1)
	assert.Error(t, err)
}

// TestRemoveVRF_DeviceAlreadyGone ensures a VRF can be successfully removed
// even with some external entity has deleted the corresponding interface.
func TestRemoveVRF_DeviceAlreadyGone(t *testing.T) {
	c := newTestController()
	nl := c.nl.(*fakeNetLink)
	vrfMap := c.vrfMap.(*fakeVRFMap)
	status := c.status.(*fakeStatusReporter)

	nl.addExisting(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0"}})

	vrf := &VRF{Name: "v1", ID: 1, Table: 100, Interfaces: []string{"eth0"}}
	require.NoError(t, c.addVRF(context.Background(), vrf, newVRFStatusBatch()))
	status.calls = nil

	delete(nl.links, "cvrf-100")

	err := c.removeVRF(context.Background(), vrf)
	require.NoError(t, err)

	_, active := c.active["v1"]
	assert.False(t, active)

	_, err = vrfMap.Get(1)
	assert.Error(t, err)
}

// TestReconcileEndpoints ensures the reconciliation of endpoints corresponds
// with the set of active VRFs.
//
// This test aims to test the avoidance of unnecessary datapath rebuilds by
// counting regeneration invocations.
func TestReconcileEndpoints(t *testing.T) {
	c := newTestController()

	c.active["vrf-red"] = &VRF{
		Name:  "vrf-red",
		ID:    1,
		Table: 100,
		Selector: isovalentv1alpha1.IsovalentCoreVRFPodSelector{
			PodSelector: &slimv1.LabelSelector{
				MatchLabels: map[string]string{"app": "red"},
			},
		},
	}
	c.active["vrf-blue"] = &VRF{
		Name:  "vrf-blue",
		ID:    2,
		Table: 200,
		Selector: isovalentv1alpha1.IsovalentCoreVRFPodSelector{
			NamespaceSelector: &slimv1.LabelSelector{
				MatchLabels: map[string]string{"env": "staging"},
			},
		},
	}
	c.active["vrf-both"] = &VRF{
		Name:  "vrf-both",
		ID:    3,
		Table: 300,
		Selector: isovalentv1alpha1.IsovalentCoreVRFPodSelector{
			PodSelector: &slimv1.LabelSelector{
				MatchLabels: map[string]string{"app": "dual"},
			},
			NamespaceSelector: &slimv1.LabelSelector{
				MatchLabels: map[string]string{"env": "prod"},
			},
		},
	}

	newAssigned := &fakeEndpoint{
		id: 1, namespace: "default", podName: "pod-red",
	}
	c.putPod("default", "pod-red", map[string]string{"app": "red"})
	alreadyCorrect := &fakeEndpoint{
		id: 2, namespace: "default", podName: "pod-red-ok",
		rtInfo: 1,
	}
	c.putPod("default", "pod-red-ok", map[string]string{"app": "red"})
	noMatchDefault := &fakeEndpoint{
		id: 3, namespace: "default", podName: "pod-green",
	}
	c.putPod("default", "pod-green", map[string]string{"app": "green"})
	staleAssignment := &fakeEndpoint{
		id: 4, namespace: "default", podName: "pod-stale",
		rtInfo: 5,
	}
	c.putPod("default", "pod-stale", map[string]string{"app": "green"})
	hostEndpoint := &fakeEndpoint{id: 5}
	nsMatch := &fakeEndpoint{
		id: 6, namespace: "staging", podName: "pod-ns",
	}
	c.putPod("staging", "pod-ns", map[string]string{"app": "black"})
	bothMatch := &fakeEndpoint{
		id: 7, namespace: "prod", podName: "pod-dual",
	}
	c.putPod("prod", "pod-dual", map[string]string{"app": "dual"})
	podOnlyMatch := &fakeEndpoint{
		id: 8, namespace: "default", podName: "pod-dual-wrong-ns",
	}
	c.putPod("default", "pod-dual-wrong-ns", map[string]string{"app": "dual"})

	c.endpoints = newFakeEndpointSubscriber(c,
		newAssigned, alreadyCorrect, noMatchDefault,
		staleAssignment, hostEndpoint, nsMatch,
		bothMatch, podOnlyMatch,
	)

	lxc := c.lxcMap.(*fakeLxcMap)
	lxc.setRTInfo(alreadyCorrect.IPv4Address(), 1)
	lxc.setRTInfo(staleAssignment.IPv4Address(), 5)

	c.putNamespace("default", nil)
	c.putNamespace("staging", map[string]string{"env": "staging"})
	c.putNamespace("prod", map[string]string{"env": "prod"})

	c.reconcileEndpoints(context.Background(), c.db.ReadTxn(), membershipConflict{})

	assert.Equal(t, uint32(1), newAssigned.rtInfo)
	assert.Equal(t, 1, newAssigned.regenerations)

	assert.Equal(t, uint32(1), alreadyCorrect.rtInfo)
	assert.Equal(t, 0, alreadyCorrect.regenerations)

	assert.Equal(t, uint32(0), noMatchDefault.rtInfo)
	assert.Equal(t, 0, noMatchDefault.regenerations)

	assert.Equal(t, uint32(0), staleAssignment.rtInfo)
	assert.Equal(t, 1, staleAssignment.regenerations)

	assert.Equal(t, uint32(0), hostEndpoint.rtInfo)
	assert.Equal(t, 0, hostEndpoint.regenerations)

	assert.Equal(t, uint32(2), nsMatch.rtInfo)
	assert.Equal(t, 1, nsMatch.regenerations)

	assert.Equal(t, uint32(3), bothMatch.rtInfo)
	assert.Equal(t, 1, bothMatch.regenerations)

	assert.Equal(t, uint32(0), podOnlyMatch.rtInfo)
	assert.Equal(t, 0, podOnlyMatch.regenerations)
}

func TestReconcileEndpoints_MembershipConflict(t *testing.T) {
	c := newTestController()

	c.active["vrf-a"] = &VRF{
		Name:  "vrf-a",
		ID:    1,
		Table: 100,
		Selector: isovalentv1alpha1.IsovalentCoreVRFPodSelector{
			PodSelector: &slimv1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
		},
	}
	c.active["vrf-b"] = &VRF{
		Name:  "vrf-b",
		ID:    2,
		Table: 200,
		Selector: isovalentv1alpha1.IsovalentCoreVRFPodSelector{
			PodSelector: &slimv1.LabelSelector{
				MatchLabels: map[string]string{"tier": "frontend"},
			},
		},
	}
	c.active["vrf-c"] = &VRF{
		Name:  "vrf-c",
		ID:    2,
		Table: 200,
		Selector: isovalentv1alpha1.IsovalentCoreVRFPodSelector{
			PodSelector: &slimv1.LabelSelector{
				MatchLabels: map[string]string{"tier": "backend"},
			},
		},
	}

	// Ambiguous1 selects both vrf-a and vrf-b
	ambiguous1 := &fakeEndpoint{
		id: 1, namespace: "default", podName: "pod-ambiguous",
	}
	c.putPod("default", "pod-ambiguous", map[string]string{"app": "web", "tier": "frontend"})
	// Ambigous2 selects both vrf-a and vrf-c
	//
	// Therefore, ensure we see that vrf-a winds up with two overlaps, both
	// vrf-b and vrf-c.
	ambiguous2 := &fakeEndpoint{
		id: 2, namespace: "default", podName: "pod-ambiguous-2",
	}
	c.putPod("default", "pod-ambiguous-2", map[string]string{"app": "web", "tier": "backend"})

	c.endpoints = newFakeEndpointSubscriber(c, ambiguous1, ambiguous2)

	c.putNamespace("default", nil)

	conflict := make(membershipConflict)
	c.reconcileEndpoints(context.Background(), c.db.ReadTxn(), conflict)

	assert.Contains(t, conflict["vrf-a"], "vrf-b", "vrf-a should be in conflict with vrf-b")
	assert.Contains(t, conflict["vrf-a"], "vrf-c", "vrf-a should be in conflict with vrf-c")
	assert.Contains(t, conflict["vrf-b"], "vrf-a", "vrf-b should be in conflict with vrf-a")
	assert.Contains(t, conflict["vrf-c"], "vrf-a", "vrf-c should be in conflict with vrf-a")

	assert.Equal(t, uint32(0), ambiguous1.rtInfo,
		"ambiguous pod must remain in default VRF (got rtInfo=%d)", ambiguous1.rtInfo)
	assert.Equal(t, 0, ambiguous1.regenerations,
		"ambiguous pod must not be regenerated into any VRF")

	status := c.status.(*fakeStatusReporter)
	var lastConflict *statusCall
	for i := range status.calls {
		if status.calls[i].op == "setMembershipConflicts" {
			lastConflict = &status.calls[i]
		}
	}
	require.NotNil(t, lastConflict, "setMembershipConflicts must be called")
}

// TestRemoveVRF_LinkDelFailure_RetainsForRetry ensures that in the VRF
// deletion path, if a link deletion error occurs, the controller will retry
// the deletion on next reconcile, despite the VRF no longer being present
// on the kubernetes side.
func TestRemoveVRF_LinkDelFailure_RetainsForRetry(t *testing.T) {
	c := newTestController()
	nl := c.nl.(*fakeNetLink)

	nl.addExisting(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0"}})

	vrf := &VRF{Name: "v1", ID: 1, Table: 100, Interfaces: []string{"eth0"}}
	require.NoError(t, c.addVRF(context.Background(), vrf, newVRFStatusBatch()))

	nl.linkDelErr = errors.New("injected transient linkDel error")
	err := c.removeVRF(context.Background(), vrf)
	require.Error(t, err)

	assert.Contains(t, c.active, "v1", "VRF should remain active so removal is retried")
	assert.Same(t, vrf, c.activeByID[1])
	assert.Same(t, vrf, c.activeByTableID[100])

	nl.linkDelErr = nil
	err = c.removeVRF(context.Background(), vrf)
	require.NoError(t, err)

	_, active := c.active["v1"]
	assert.False(t, active, "VRF should be removed after successful retry")
	_, byID := c.activeByID[1]
	assert.False(t, byID)
	_, byTable := c.activeByTableID[100]
	assert.False(t, byTable)
}

// TestReconcileVRFs is a general test which ensures the expected state is reconciled
// over add, update, and delete events.
func TestReconcileVRFs(t *testing.T) {
	c := newTestController()
	c.localNodeStore = node.NewTestLocalNodeStore(node.LocalNode{Node: nodeTypes.Node{Name: "node-a", Labels: map[string]string{"zone": "us-east"}}})
	db := c.db
	vrfTable := c.vrfs.(statedb.RWTable[VRF])
	nl := c.nl.(*fakeNetLink)

	nl.addExisting(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0"}})
	nl.addExisting(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth1"}})
	nl.addExisting(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth2"}})
	nl.addExisting(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth3"}})

	ctx := context.Background()

	wtxn := db.WriteTxn(vrfTable)
	vrfTable.Insert(wtxn, VRF{
		Name:       "vrf-east",
		ID:         1,
		Table:      100,
		Interfaces: []string{"eth0"},
		NodeSelector: &slimv1.LabelSelector{
			MatchLabels: map[string]string{"zone": "us-east"},
		},
	})
	vrfTable.Insert(wtxn, VRF{
		Name:       "vrf-west",
		ID:         2,
		Table:      200,
		Interfaces: []string{"eth1"},
		NodeSelector: &slimv1.LabelSelector{
			MatchLabels: map[string]string{"zone": "us-west"},
		},
	})
	wtxn.Commit()

	var rc reconcileCache
	changed, err := c.reconcileVRFs(ctx, &rc, db.ReadTxn())
	require.NoError(t, err)
	require.True(t, changed)

	assert.Contains(t, c.active, "vrf-east")
	assert.NotContains(t, c.active, "vrf-west")
	_, hasEastDev := nl.links["cvrf-100"]
	assert.True(t, hasEastDev)
	_, hasWestDev := nl.links["cvrf-200"]
	assert.False(t, hasWestDev)

	wtxn = db.WriteTxn(vrfTable)
	vrfTable.Insert(wtxn, VRF{
		Name:       "vrf-east",
		ID:         1,
		Table:      100,
		Interfaces: []string{"eth0", "eth2"},
		NodeSelector: &slimv1.LabelSelector{
			MatchLabels: map[string]string{"zone": "us-east"},
		},
	})
	vrfTable.Insert(wtxn, VRF{
		Name:       "vrf-new",
		ID:         3,
		Table:      300,
		Interfaces: []string{"eth3"},
	})
	vrfTable.Delete(wtxn, VRF{Name: "vrf-west"})
	wtxn.Commit()

	rc.reset()
	changed, err = c.reconcileVRFs(ctx, &rc, db.ReadTxn())
	require.NoError(t, err)
	require.True(t, changed)

	assert.Contains(t, c.active, "vrf-east")
	assert.Contains(t, c.active, "vrf-new")
	assert.NotContains(t, c.active, "vrf-west")

	assert.Equal(t, "cvrf-100", nl.masters["eth2"])
	_, hasNewDev := nl.links["cvrf-300"]
	assert.True(t, hasNewDev)

	rc.reset()
	changed, err = c.reconcileVRFs(ctx, &rc, db.ReadTxn())
	require.NoError(t, err)
	assert.False(t, changed)
}

// TestEventOrdering ensures any order of endpoint and VRF events still result
// in the correct reconciliation.
func TestEventOrdering(t *testing.T) {
	setup := func() (*controller, *fakeEndpoint) {
		c := newTestController()
		nl := c.nl.(*fakeNetLink)
		nl.addExisting(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0"}})
		ep := &fakeEndpoint{id: 1, namespace: "default", podName: "my-pod"}
		c.endpoints = newFakeEndpointSubscriber(c, ep)
		c.putPod("default", "my-pod", map[string]string{"app": "web"})
		c.putNamespace("default", nil)
		return c, ep
	}

	insertVRF := func(c *controller) {
		tbl := c.vrfs.(statedb.RWTable[VRF])
		wtxn := c.db.WriteTxn(tbl)
		tbl.Insert(wtxn, VRF{
			Name:       "vrf-web",
			ID:         1,
			Table:      100,
			Interfaces: []string{"eth0"},
			Selector: isovalentv1alpha1.IsovalentCoreVRFPodSelector{
				PodSelector: &slimv1.LabelSelector{
					MatchLabels: map[string]string{"app": "web"},
				},
			},
		})
		wtxn.Commit()
	}

	removeVRF := func(c *controller) {
		tbl := c.vrfs.(statedb.RWTable[VRF])
		wtxn := c.db.WriteTxn(tbl)
		tbl.Delete(wtxn, VRF{Name: "vrf-web"})
		wtxn.Commit()
	}

	t.Run("VRF added then EP upsert", func(t *testing.T) {
		c, ep := setup()
		ctx := context.Background()
		var rc reconcileCache

		insertVRF(c)
		c.reconcileVRFs(ctx, &rc, c.db.ReadTxn())
		c.reconcileEndpoints(ctx, c.db.ReadTxn(), make(membershipConflict))

		c.reconcileEndpoint(ctx, c.db.ReadTxn(), ep, make(membershipConflict), c.dumpLxc())

		assert.Equal(t, uint32(1), ep.rtInfo)
		assert.Equal(t, 1, ep.regenerations)
	})

	t.Run("EP upsert then VRF added", func(t *testing.T) {
		c, ep := setup()
		ctx := context.Background()
		var rc reconcileCache

		c.reconcileEndpoint(ctx, c.db.ReadTxn(), ep, make(membershipConflict), c.dumpLxc())
		assert.Equal(t, uint32(0), ep.rtInfo)
		assert.Equal(t, 0, ep.regenerations)

		insertVRF(c)
		c.reconcileVRFs(ctx, &rc, c.db.ReadTxn())
		c.reconcileEndpoints(ctx, c.db.ReadTxn(), make(membershipConflict))

		assert.Equal(t, uint32(1), ep.rtInfo)
		assert.Equal(t, 1, ep.regenerations)
	})

	t.Run("VRF removed then EP upsert", func(t *testing.T) {
		c, ep := setup()
		ctx := context.Background()
		var rc reconcileCache

		insertVRF(c)
		c.reconcileVRFs(ctx, &rc, c.db.ReadTxn())
		c.reconcileEndpoints(ctx, c.db.ReadTxn(), make(membershipConflict))
		assert.Equal(t, uint32(1), ep.rtInfo)

		ep.regenerations = 0
		removeVRF(c)
		rc.reset()
		c.reconcileVRFs(ctx, &rc, c.db.ReadTxn())
		c.reconcileEndpoints(ctx, c.db.ReadTxn(), make(membershipConflict))

		c.reconcileEndpoint(ctx, c.db.ReadTxn(), ep, make(membershipConflict), c.dumpLxc())

		assert.Equal(t, uint32(0), ep.rtInfo)
		assert.Equal(t, 1, ep.regenerations)
	})

	t.Run("Pod label removed then VRF still active", func(t *testing.T) {
		c, ep := setup()
		ctx := context.Background()
		var rc reconcileCache

		insertVRF(c)
		c.reconcileVRFs(ctx, &rc, c.db.ReadTxn())
		c.reconcileEndpoints(ctx, c.db.ReadTxn(), make(membershipConflict))
		assert.Equal(t, uint32(1), ep.rtInfo)

		ep.regenerations = 0
		c.putPod("default", "my-pod", map[string]string{"app": "other"})
		c.reconcileEndpoint(ctx, c.db.ReadTxn(), ep, make(membershipConflict), c.dumpLxc())

		assert.Equal(t, uint32(0), ep.rtInfo)
		assert.Equal(t, 1, ep.regenerations)
	})

	t.Run("Pod label added then VRF selector updated to match", func(t *testing.T) {
		c, ep := setup()
		ctx := context.Background()
		var rc reconcileCache

		c.putPod("default", "my-pod", map[string]string{"app": "other"})

		insertVRF(c)
		c.reconcileVRFs(ctx, &rc, c.db.ReadTxn())
		c.reconcileEndpoints(ctx, c.db.ReadTxn(), make(membershipConflict))
		assert.Equal(t, uint32(0), ep.rtInfo)

		c.putPod("default", "my-pod", map[string]string{"app": "web"})
		c.reconcileEndpoint(ctx, c.db.ReadTxn(), ep, make(membershipConflict), c.dumpLxc())

		assert.Equal(t, uint32(1), ep.rtInfo)
		assert.Equal(t, 1, ep.regenerations)
	})
}

// TestAddVRF_ConflictingInterface ensures VRF add fails when one of the
// requested interfaces is already bound to another active VRF, and that the
// existing VRF retains ownership of the interface.
func TestAddVRF_ConflictingInterface(t *testing.T) {
	c := newTestController()
	nl := c.nl.(*fakeNetLink)
	status := c.status.(*fakeStatusReporter)

	nl.addExisting(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0"}})

	existing := &VRF{
		Name:       "existing",
		ID:         1,
		Table:      100,
		Interfaces: []string{"eth0"},
	}
	require.NoError(t, c.addVRF(context.Background(), existing, newVRFStatusBatch()))
	require.Equal(t, "cvrf-100", nl.masters["eth0"])

	status.calls = nil

	conflicting := &VRF{
		Name:       "v2",
		ID:         2,
		Table:      200,
		Interfaces: []string{"eth0"},
	}
	batch := newVRFStatusBatch()
	err := c.addVRF(context.Background(), conflicting, batch)
	require.Error(t, err)
	require.NoError(t, c.status.setVRFStatuses(context.Background(), batch))

	assert.Equal(t, "cvrf-100", nl.masters["eth0"],
		"eth0 must remain bound to the existing VRF")

	assert.NotContains(t, c.active, "v2")
	_, byID := c.activeByID[2]
	assert.False(t, byID, "v2 must not be indexed by ID")
	_, byTable := c.activeByTableID[200]
	assert.False(t, byTable, "v2 must not be indexed by table ID")

	require.NotEmpty(t, status.calls)
	last := status.calls[len(status.calls)-1]
	require.Contains(t, last.entries, "v2")
	assert.False(t, last.entries["v2"].ready)
}

// TestUpdateVRF_ConflictingInterface ensures VRF update fails when an
// interface added to an active VRF is already bound to another active VRF,
// and that the existing VRF retains ownership of the interface.
func TestUpdateVRF_ConflictingInterface(t *testing.T) {
	c := newTestController()
	nl := c.nl.(*fakeNetLink)
	status := c.status.(*fakeStatusReporter)

	nl.addExisting(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0"}})
	nl.addExisting(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth1"}})

	existing := &VRF{
		Name:       "existing",
		ID:         1,
		Table:      100,
		Interfaces: []string{"eth0"},
	}
	require.NoError(t, c.addVRF(context.Background(), existing, newVRFStatusBatch()))
	require.Equal(t, "cvrf-100", nl.masters["eth0"])

	other := &VRF{
		Name:       "v2",
		ID:         2,
		Table:      200,
		Interfaces: []string{"eth1"},
	}
	require.NoError(t, c.addVRF(context.Background(), other, newVRFStatusBatch()))
	require.Equal(t, "cvrf-200", nl.masters["eth1"])

	status.calls = nil

	updated := &VRF{
		Name:       "v2",
		ID:         2,
		Table:      200,
		Interfaces: []string{"eth0", "eth1"},
	}
	batch := newVRFStatusBatch()
	err := c.updateVRF(context.Background(), updated, batch)
	require.Error(t, err)
	require.NoError(t, c.status.setVRFStatuses(context.Background(), batch))

	assert.Equal(t, "cvrf-100", nl.masters["eth0"],
		"eth0 must remain bound to the existing VRF")

	require.NotEmpty(t, status.calls)
	last := status.calls[len(status.calls)-1]
	require.Contains(t, last.entries, "v2")
	assert.False(t, last.entries["v2"].ready)
}

// TestUpdateVRF_PartialInterfaceBindingFailure ensures when an update to
// interfacing binding fails, the kernel and cache remain consistent.
func TestUpdateVRF_PartialInterfaceBindingFailure(t *testing.T) {
	c := newTestController()
	nl := c.nl.(*fakeNetLink)

	nl.addExisting(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0"}})
	nl.addExisting(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth1"}})
	nl.addExisting(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth2"}})

	oldVRF := &VRF{
		Name:       "v1",
		ID:         1,
		Table:      100,
		Interfaces: []string{"eth0", "eth1"},
	}
	require.NoError(t, c.addVRF(context.Background(), oldVRF, newVRFStatusBatch()))

	assert.Equal(t, "cvrf-100", nl.masters["eth0"])
	assert.Equal(t, "cvrf-100", nl.masters["eth1"])

	nl.linkSetMasterErr = errors.New("injected bind error")

	newVRF := &VRF{
		Name:       "v1",
		ID:         1,
		Table:      100,
		Interfaces: []string{"eth0", "eth2"},
	}
	err := c.updateVRF(context.Background(), newVRF, newVRFStatusBatch())
	require.Error(t, err)

	active := c.active["v1"]
	require.NotNil(t, active)

	_, eth1Bound := nl.masters["eth1"]
	_, eth2Bound := nl.masters["eth2"]

	if eth1Bound {
		assert.Contains(t, active.Interfaces, "eth1",
			"eth1 is still bound in kernel, active state should reflect this")
	}
	if !eth2Bound {
		assert.NotContains(t, active.Interfaces, "eth2",
			"eth2 is not bound in kernel, active state should not list it")
	}
}

func TestUpdateVRF_FailureMisreportedAsActive(t *testing.T) {
	c := newTestController()
	db := c.db
	vrfTable := c.vrfs.(statedb.RWTable[VRF])
	nl := c.nl.(*fakeNetLink)

	nl.addExisting(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0"}})
	nl.addExisting(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth1"}})

	ctx := context.Background()

	wtxn := db.WriteTxn(vrfTable)
	vrfTable.Insert(wtxn, VRF{Name: "v1", ID: 1, Table: 100, Interfaces: []string{"eth0"}})
	wtxn.Commit()

	var rc reconcileCache
	_, err := c.reconcileVRFs(ctx, &rc, db.ReadTxn())
	require.NoError(t, err)
	require.Contains(t, c.active, "v1")

	nl.linkSetMasterErr = errors.New("injected bind error")
	wtxn = db.WriteTxn(vrfTable)
	vrfTable.Insert(wtxn, VRF{Name: "v1", ID: 1, Table: 100, Interfaces: []string{"eth0", "eth1"}})
	wtxn.Commit()

	rc.reset()
	_, err = c.reconcileVRFs(ctx, &rc, db.ReadTxn())
	require.NoError(t, err)

	status := c.status.(*fakeStatusReporter)
	require.NotEmpty(t, status.calls)
	last := status.calls[len(status.calls)-1]
	require.Equal(t, "setVRFStatuses", last.op)
	require.Contains(t, last.entries, "v1")
	assert.False(t, last.entries["v1"].ready,
		"updateVRF non-recreate failure must not be reported as Ready=True")
}

// TestUpdateVRF_FreedInterfaceReusableByOtherVRF ensures that when an
// interface is released from a VRF via update, the interface is removed from
// the bound-interface index so a different VRF can subsequently claim it.
func TestUpdateVRF_FreedInterfaceReusableByOtherVRF(t *testing.T) {
	c := newTestController()
	nl := c.nl.(*fakeNetLink)

	nl.addExisting(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0"}})
	nl.addExisting(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth1"}})

	red := &VRF{
		Name:       "vrf-red",
		ID:         1,
		Table:      100,
		Interfaces: []string{"eth0", "eth1"},
	}
	require.NoError(t, c.addVRF(context.Background(), red, newVRFStatusBatch()))
	require.Equal(t, "cvrf-100", nl.masters["eth0"])
	require.Equal(t, "cvrf-100", nl.masters["eth1"])
	require.Same(t, red, c.activeByBoundInterface["eth0"])
	require.Same(t, red, c.activeByBoundInterface["eth1"])

	// release eth1 from vrf-red
	redUpdated := &VRF{
		Name:       "vrf-red",
		ID:         1,
		Table:      100,
		Interfaces: []string{"eth0"},
	}
	require.NoError(t, c.updateVRF(context.Background(), redUpdated, newVRFStatusBatch()))

	_, eth1Bound := nl.masters["eth1"]
	assert.False(t, eth1Bound, "eth1 must be unbound after release")
	_, eth1Indexed := c.activeByBoundInterface["eth1"]
	assert.False(t, eth1Indexed,
		"eth1 must be removed from activeByBoundInterface after release")
	assert.Same(t, redUpdated, c.activeByBoundInterface["eth0"],
		"eth0 must remain indexed to vrf-red")

	// a new VRF must be able to claim eth1
	blue := &VRF{
		Name:       "vrf-blue",
		ID:         2,
		Table:      200,
		Interfaces: []string{"eth1"},
	}
	require.NoError(t, c.addVRF(context.Background(), blue, newVRFStatusBatch()))
	assert.Same(t, blue, c.active["vrf-blue"])
	assert.Equal(t, "cvrf-200", nl.masters["eth1"])
	assert.Same(t, blue, c.activeByBoundInterface["eth1"])
}

// TestInitRestore_PartialInterfaceConflict ensures that when two restorable
// VRFs in the spec request the same interface (one of which already holds it
// in the kernel), the cross-VRF conflict is detected on the first reconcile
// regardless of map iteration order, and the interface is not silently
// re-parented in the kernel.
func TestInitRestore_PartialInterfaceConflict(t *testing.T) {
	c := newTestController()
	db := c.db
	vrfTable := c.vrfs.(statedb.RWTable[VRF])
	nl := c.nl.(*fakeNetLink)
	vrfMap := c.vrfMap.(*fakeVRFMap)

	wtxn := db.WriteTxn(vrfTable)
	vrfTable.Insert(wtxn, VRF{
		Name:       "vrf-red",
		ID:         1,
		Table:      100,
		Interfaces: []string{"eth0"},
	})
	vrfTable.Insert(wtxn, VRF{
		Name:       "vrf-blue",
		ID:         2,
		Table:      200,
		Interfaces: []string{"eth0"},
	})
	wtxn.Commit()

	nl.addExisting(&netlink.Vrf{
		LinkAttrs: netlink.LinkAttrs{Name: "cvrf-100", Index: 10, Alias: "vrf-red"},
		Table:     100,
	})
	nl.addExisting(&netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{Name: "eth0", Index: 11, MasterIndex: 10},
	})
	nl.addExisting(&netlink.Vrf{
		LinkAttrs: netlink.LinkAttrs{Name: "cvrf-200", Index: 20, Alias: "vrf-blue"},
		Table:     200,
	})

	vrfMap.m[1] = 100
	vrfMap.m[2] = 200

	ctx := context.Background()
	require.NoError(t, c.init(ctx))

	// Both partials must be present, and the kernel-bound interface must be
	// indexed so the conflict is visible on the first reconcile regardless of
	// which partial is processed first.
	require.Contains(t, c.active, "vrf-red")
	require.Contains(t, c.active, "vrf-blue")
	require.Same(t, c.active["vrf-red"], c.activeByBoundInterface["eth0"],
		"eth0 must be indexed against the partial that owns it in kernel")

	var rc reconcileCache
	_, err := c.reconcileVRFs(ctx, &rc, db.ReadTxn())
	require.NoError(t, err)

	// vrf-red wins: it pre-owned eth0 in the kernel.
	redActive := c.active["vrf-red"]
	require.NotNil(t, redActive)
	assert.Equal(t, uint16(1), redActive.ID)
	assert.Same(t, redActive, c.activeByID[1])
	assert.Same(t, redActive, c.activeByTableID[100])
	assert.Same(t, redActive, c.activeByBoundInterface["eth0"])

	// vrf-blue must not have stolen eth0 in the kernel. The fake only
	// populates masters via linkSetMaster, so the assertion is that no
	// rebinding occurred (eth0's kernel-side MasterIndex was set up at test
	// init and is preserved by absence of any linkSetMaster call).
	_, rebound := nl.masters["eth0"]
	assert.False(t, rebound, "eth0 must not have been re-childed during reconcile")

	// vrf-blue must have a failure status reported.
	status := c.status.(*fakeStatusReporter)
	var blueFailureFound bool
	for _, call := range status.calls {
		if call.op != "setVRFStatuses" {
			continue
		}
		entry, ok := call.entries["vrf-blue"]
		if ok && !entry.ready {
			blueFailureFound = true
			break
		}
	}
	assert.True(t, blueFailureFound,
		"vrf-blue must have a failure status reported after reconcile")
}

func TestAddVRF_WritesAlias(t *testing.T) {
	c := newTestController()
	nl := c.nl.(*fakeNetLink)
	nl.addExisting(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0"}})

	vrf := &VRF{
		Name:       "vrf-red",
		ID:         1,
		Table:      100,
		Interfaces: []string{"eth0"},
	}
	require.NoError(t, c.addVRF(context.Background(), vrf, newVRFStatusBatch()))

	dev, ok := nl.links["cvrf-100"]
	require.True(t, ok, "cvrf-100 must exist")
	assert.Equal(t, "vrf-red", dev.Attrs().Alias,
		"cvrf-100 must carry vrf.Name in its alias")
}

func TestAddVRF_AliasFailureUnwinds(t *testing.T) {
	c := newTestController()
	nl := c.nl.(*fakeNetLink)
	nl.addExisting(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0"}})
	nl.linkSetAliasErr = errors.New("injected alias error")

	vrf := &VRF{
		Name:       "vrf-red",
		ID:         1,
		Table:      100,
		Interfaces: []string{"eth0"},
	}
	err := c.addVRF(context.Background(), vrf, newVRFStatusBatch())
	require.Error(t, err)

	assert.NotContains(t, c.active, "vrf-red")
}

func TestInit_OrphanRemovedWhenNoAlias(t *testing.T) {
	c := newTestController()
	db := c.db
	vrfTable := c.vrfs.(statedb.RWTable[VRF])
	nl := c.nl.(*fakeNetLink)

	wtxn := db.WriteTxn(vrfTable)
	vrfTable.Insert(wtxn, VRF{
		Name:       "vrf-red",
		ID:         1,
		Table:      100,
		Interfaces: []string{"eth0"},
	})
	wtxn.Commit()

	nl.addExisting(&netlink.Vrf{
		LinkAttrs: netlink.LinkAttrs{Name: "cvrf-100", Index: 10},
		Table:     100,
	})
	nl.addExisting(&netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{Name: "eth0", Index: 11, MasterIndex: 10},
	})

	require.NoError(t, c.init(context.Background()))

	_, hasLink := nl.links["cvrf-100"]
	assert.False(t, hasLink, "cvrf-100 with no alias must be removed as orphan")
	assert.NotContains(t, c.active, "vrf-red",
		"vrf-red must not have been restored from an aliasless device")
	assert.Empty(t, c.activeByBoundInterface,
		"no interface must be indexed when device was treated as orphan")
}

func TestInit_OrphanRemovedWhenAliasNotInSpec(t *testing.T) {
	c := newTestController()
	db := c.db
	vrfTable := c.vrfs.(statedb.RWTable[VRF])
	nl := c.nl.(*fakeNetLink)

	wtxn := db.WriteTxn(vrfTable)
	vrfTable.Insert(wtxn, VRF{
		Name:       "vrf-blue",
		ID:         2,
		Table:      200,
		Interfaces: []string{"eth1"},
	})
	wtxn.Commit()

	nl.addExisting(&netlink.Vrf{
		LinkAttrs: netlink.LinkAttrs{Name: "cvrf-100", Index: 10, Alias: "vrf-red"},
		Table:     100,
	})
	nl.addExisting(&netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{Name: "eth0", Index: 11, MasterIndex: 10},
	})

	require.NoError(t, c.init(context.Background()))

	_, hasLink := nl.links["cvrf-100"]
	assert.False(t, hasLink, "cvrf-100 with stale alias must be removed as orphan")
	assert.NotContains(t, c.active, "vrf-red")
	assert.NotContains(t, c.active, "vrf-blue")
}

func TestInit_AliasIdentityWinsOverTable(t *testing.T) {
	c := newTestController()
	db := c.db
	vrfTable := c.vrfs.(statedb.RWTable[VRF])
	nl := c.nl.(*fakeNetLink)

	wtxn := db.WriteTxn(vrfTable)
	vrfTable.Insert(wtxn, VRF{
		Name:       "vrf-blue",
		ID:         2,
		Table:      100,
		Interfaces: []string{"eth1"},
	})
	wtxn.Commit()

	nl.addExisting(&netlink.Vrf{
		LinkAttrs: netlink.LinkAttrs{Name: "cvrf-100", Index: 10, Alias: "vrf-red"},
		Table:     100,
	})
	nl.addExisting(&netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{Name: "eth0", Index: 11, MasterIndex: 10},
	})
	nl.addExisting(&netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{Name: "eth1", Index: 12},
	})

	ctx := context.Background()
	require.NoError(t, c.init(ctx))

	_, hasOldDev := nl.links["cvrf-100"]
	assert.False(t, hasOldDev,
		"cvrf-100 belonged to vrf-red (per alias); since vrf-red is not in spec it must be deleted, not silently re-attributed to vrf-blue")
	assert.NotContains(t, c.active, "vrf-blue",
		"vrf-blue must not be restored from a device that aliased a different VRF")

	var rc reconcileCache
	_, err := c.reconcileVRFs(ctx, &rc, db.ReadTxn())
	require.NoError(t, err)

	require.Contains(t, c.active, "vrf-blue", "vrf-blue must be added on first reconcile")
	dev, ok := nl.links["cvrf-100"]
	require.True(t, ok, "vrf-blue must own cvrf-100 after reconcile")
	assert.Equal(t, "vrf-blue", dev.Attrs().Alias,
		"the freshly created cvrf-100 must carry vrf-blue's alias")
	assert.Equal(t, "cvrf-100", nl.masters["eth1"], "eth1 must be enslaved to vrf-blue's device")
}

func TestInit_AliasRestoresPartial(t *testing.T) {
	c := newTestController()
	db := c.db
	vrfTable := c.vrfs.(statedb.RWTable[VRF])
	nl := c.nl.(*fakeNetLink)

	wtxn := db.WriteTxn(vrfTable)
	vrfTable.Insert(wtxn, VRF{
		Name:       "vrf-red",
		ID:         1,
		Table:      100,
		Interfaces: []string{"eth0"},
	})
	wtxn.Commit()

	nl.addExisting(&netlink.Vrf{
		LinkAttrs: netlink.LinkAttrs{Name: "cvrf-100", Index: 10, Alias: "vrf-red"},
		Table:     100,
	})
	nl.addExisting(&netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{Name: "eth0", Index: 11, MasterIndex: 10},
	})

	require.NoError(t, c.init(context.Background()))

	require.Contains(t, c.active, "vrf-red")
	partial := c.active["vrf-red"]
	assert.Equal(t, uint16(0), partial.ID)
	assert.Equal(t, uint32(100), partial.Table)
	assert.Equal(t, []string{"eth0"}, partial.Interfaces)
	assert.Same(t, partial, c.activeByBoundInterface["eth0"])

	_, hasLink := nl.links["cvrf-100"]
	assert.True(t, hasLink, "cvrf-100 must be preserved when alias matches spec")
}

// TestStaleStatusEntryAfterRejectedDelete ensures that when a VRF fails
// instantiation, and a status is written to the IsovalentCoreVRFNodeStatus, if
// the VRF is subsequently deleted prior to becoming active, the status is not
// left dangling.
func TestStaleStatusEntryAfterRejectedDelete(t *testing.T) {
	c := newTestController()
	db := c.db
	vrfTable := c.vrfs.(statedb.RWTable[VRF])
	ctx := context.Background()

	wtxn := db.WriteTxn(vrfTable)
	vrfTable.Insert(wtxn, VRF{Name: "vrf-a", ID: 1, Table: 100, Interfaces: []string{"eth-missing"}})
	wtxn.Commit()

	var rc reconcileCache
	_, err := c.reconcileVRFs(ctx, &rc, db.ReadTxn())
	require.NoError(t, err)
	require.NotContains(t, c.active, "vrf-a")

	status := c.status.(*fakeStatusReporter)
	var sawSet bool
	for _, call := range status.calls {
		if call.op != "setVRFStatuses" {
			continue
		}
		if _, ok := call.entries["vrf-a"]; ok {
			sawSet = true
		}
	}
	require.True(t, sawSet)

	wtxn = db.WriteTxn(vrfTable)
	vrfTable.Delete(wtxn, VRF{Name: "vrf-a"})
	wtxn.Commit()

	rc.reset()
	_, err = c.reconcileVRFs(ctx, &rc, db.ReadTxn())
	require.NoError(t, err)

	require.NotEmpty(t, status.calls)
	last := status.calls[len(status.calls)-1]
	require.Equal(t, "setVRFStatuses", last.op)
	assert.NotContains(t, last.entries, "vrf-a")
}

// TestDanglingVRFInterface ensures there is no scenario where a VRF interface
// can be left dangling.
func TestDanglingVRFInterface(t *testing.T) {
	newDanglingTestController := func() (*controller, *statedb.DB, statedb.RWTable[VRF], *fakeNetLink, *fakeVRFMap) {
		c := newTestController()
		db := c.db
		vrfTable := c.vrfs.(statedb.RWTable[VRF])
		nl := c.nl.(*fakeNetLink)
		vrfMap := c.vrfMap.(*fakeVRFMap)
		nl.addExisting(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0"}})
		return c, db, vrfTable, nl, vrfMap
	}

	// t0 : VRF-A Add
	// t1 : VRF-A failed (dangling vrf interface)
	// t3 : VRF-A updated with new table id
	// t4 : VRF-A seen a ADD, create with new table ID
	//
	// error case: Dangling vrf interface with old ID
	t.Run("VRF-A Add Failed -> VRF-A Updated", func(t *testing.T) {
		c, db, vrfTable, nl, vrfMap := newDanglingTestController()
		ctx := context.Background()

		// t0: apply the initial spec.
		wtxn := db.WriteTxn(vrfTable)
		vrfTable.Insert(wtxn, VRF{Name: "vrf-a", ID: 1, Table: 100, Interfaces: []string{"eth0"}})
		wtxn.Commit()

		// t1: inject vrfMap.Upsert failure. addVRF should fail after
		// createVRFDevice succeeds.
		vrfMap.upsertErr = errors.New("injected BPF map error")

		var rc reconcileCache
		_, err := c.reconcileVRFs(ctx, &rc, db.ReadTxn())
		require.NoError(t, err)
		require.NotContains(t, c.active, "vrf-a", "VRF must not be active after failed add")
		require.NotContains(t, nl.links, "cvrf-100",
			"cvrf-100 should have been rolled back")

		// t3: update the spec with a new table id.
		vrfMap.upsertErr = nil
		wtxn = db.WriteTxn(vrfTable)
		vrfTable.Insert(wtxn, VRF{Name: "vrf-a", ID: 1, Table: 200, Interfaces: []string{"eth0"}})
		wtxn.Commit()

		// t4: reconcile. Expectation: cvrf-200 created, cvrf-100 removed.
		rc.reset()
		_, err = c.reconcileVRFs(ctx, &rc, db.ReadTxn())
		require.NoError(t, err)
		assert.Contains(t, c.active, "vrf-a")
		assert.Contains(t, nl.links, "cvrf-200", "new device must exist")
		assert.NotContains(t, nl.links, "cvrf-100",
			"DANGLING: cvrf-100 from the failed first attempt must not persist")
	})

	// t0 : VRF-A Add
	// t1 : VRF-A failed (dangling vrf interface)
	// t3 : VRF-A deleted
	//
	// error case: Dangling VRF interface left over
	t.Run("VRF-A Add Failed -> VRF-A deleted", func(t *testing.T) {
		c, db, vrfTable, nl, vrfMap := newDanglingTestController()
		ctx := context.Background()

		// t0: apply the initial spec.
		wtxn := db.WriteTxn(vrfTable)
		vrfTable.Insert(wtxn, VRF{Name: "vrf-a", ID: 1, Table: 100, Interfaces: []string{"eth0"}})
		wtxn.Commit()

		// t1: inject vrfMap.Upsert failure.
		vrfMap.upsertErr = errors.New("injected BPF map error")

		var rc reconcileCache
		_, err := c.reconcileVRFs(ctx, &rc, db.ReadTxn())
		require.NoError(t, err)
		require.NotContains(t, c.active, "vrf-a")
		require.NotContains(t, nl.links, "cvrf-100",
			"cvrf-100 should have been rolled back")

		// t3: delete the CR.
		vrfMap.upsertErr = nil
		wtxn = db.WriteTxn(vrfTable)
		vrfTable.Delete(wtxn, VRF{Name: "vrf-a"})
		wtxn.Commit()

		// Reconcile after delete. Expectation: no cvrf-100 device remains.
		rc.reset()
		_, err = c.reconcileVRFs(ctx, &rc, db.ReadTxn())
		require.NoError(t, err)
		assert.NotContains(t, c.active, "vrf-a")
		assert.NotContains(t, nl.links, "cvrf-100",
			"DANGLING: cvrf-100 from the failed add must not persist after CR deletion")
	})
}

// TestEndpointMembershipStates ensures all possible Endpoint VRF states can
// transition without causing stuck or broken VRF membership conditions.
func TestEndpointMembershipStates(t *testing.T) {
	c := newTestController()

	vrfA := &VRF{
		Name: "vrf-a", ID: 10, Table: 100,
		Selector: isovalentv1alpha1.IsovalentCoreVRFPodSelector{
			PodSelector: &slimv1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
		},
	}
	vrfB := &VRF{
		Name: "vrf-b", ID: 20, Table: 200,
		Selector: isovalentv1alpha1.IsovalentCoreVRFPodSelector{
			PodSelector: &slimv1.LabelSelector{
				MatchLabels: map[string]string{"tier": "frontend"},
			},
		},
	}

	stable := &fakeEndpoint{
		id: 1, namespace: "default", podName: "stable",
	}
	c.putPod("default", "stable", map[string]string{"app": "web", "tier": "frontend"})
	c.endpoints = newFakeEndpointSubscriber(c, stable)
	c.putNamespace("default", nil)

	reconcile := func() membershipConflict {
		conflict := make(membershipConflict)
		c.reconcileEndpoints(context.Background(), c.db.ReadTxn(), conflict)
		return conflict
	}

	t.Run("VRF-A selects endpoint", func(t *testing.T) {
		c.active["vrf-a"] = vrfA
		conflict := reconcile()
		assert.Equal(t, uint32(10), stable.rtInfo)
		assert.Equal(t, 1, stable.regenerations)
		assert.Empty(t, conflict)
	})

	t.Run("VRF-B overlap with VRF-A, endpoint remains in VRF-A", func(t *testing.T) {
		c.active["vrf-b"] = vrfB
		prevRegens := stable.regenerations
		conflict := reconcile()
		assert.Equal(t, uint32(10), stable.rtInfo)
		assert.Equal(t, prevRegens, stable.regenerations)
		assert.Contains(t, conflict["vrf-a"], "vrf-b")
		assert.Contains(t, conflict["vrf-b"], "vrf-a")
	})

	t.Run("VRF overlap resolved favoring VRF-A, no VRF flap", func(t *testing.T) {
		delete(c.active, "vrf-b")
		prevRegens := stable.regenerations
		conflict := reconcile()
		assert.Equal(t, uint32(10), stable.rtInfo)
		assert.Equal(t, prevRegens, stable.regenerations)
		assert.Empty(t, conflict)
	})

	t.Run("VRF overlap resolved favoring VRF-B, Endpoint joins VRF-B", func(t *testing.T) {
		c.active["vrf-b"] = vrfB
		reconcile()
		require.Equal(t, uint32(10), stable.rtInfo, "precondition: stuck at A under conflict")

		delete(c.active, "vrf-a")
		prevRegens := stable.regenerations
		conflict := reconcile()
		assert.Equal(t, uint32(20), stable.rtInfo)
		assert.Equal(t, prevRegens+1, stable.regenerations)
		assert.Empty(t, conflict)
	})

	t.Run("Conflict resolved by removal of all VRFs, Endpoint returns to default (0) VRF", func(t *testing.T) {
		c.active["vrf-a"] = vrfA
		reconcile()
		require.Equal(t, uint32(20), stable.rtInfo, "precondition: stuck at B under conflict")

		delete(c.active, "vrf-a")
		delete(c.active, "vrf-b")
		prevRegens := stable.regenerations
		conflict := reconcile()
		assert.Equal(t, uint32(0), stable.rtInfo)
		assert.Equal(t, prevRegens+1, stable.regenerations)
		assert.Empty(t, conflict)
	})

	t.Run("Endpoint has no membership, VRF overlap on init, Endpoint joins no VRF", func(t *testing.T) {
		c.active["vrf-a"] = vrfA
		c.active["vrf-b"] = vrfB

		fresh := &fakeEndpoint{
			id: 2, namespace: "default", podName: "fresh",
		}
		c.putPod("default", "fresh", map[string]string{"app": "web", "tier": "frontend"})
		c.endpoints = newFakeEndpointSubscriber(c, fresh)

		conflict := reconcile()
		assert.Equal(t, uint32(0), fresh.rtInfo)
		assert.Equal(t, 0, fresh.regenerations)
		assert.Contains(t, conflict["vrf-a"], "vrf-b")
		assert.Contains(t, conflict["vrf-b"], "vrf-a")
	})
}

// TestReconcile_PodArrivesBeforeEndpoint covers the race where the pod row is
// reflected from the apiserver before the EndpointManager has created the
// local endpoint.
func TestReconcile_PodArrivesBeforeEndpoint(t *testing.T) {
	c := newTestController()
	c.active["vrf-web"] = &VRF{
		Name: "vrf-web", ID: 1, Table: 100,
		Selector: isovalentv1alpha1.IsovalentCoreVRFPodSelector{
			PodSelector: &slimv1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
		},
	}
	c.putNamespace("default", nil)

	c.putPod("default", "my-pod", map[string]string{"app": "web"})
	c.endpoints = newFakeEndpointSubscriber(c)

	c.reconcileEndpoints(context.Background(), c.db.ReadTxn(), make(membershipConflict))

	ep := &fakeEndpoint{id: 1, namespace: "default", podName: "my-pod"}
	c.endpoints = newFakeEndpointSubscriber(c, ep)

	c.reconcileEndpoints(context.Background(), c.db.ReadTxn(), make(membershipConflict))

	assert.Equal(t, uint32(1), ep.rtInfo)
	assert.Equal(t, 1, ep.regenerations)
}

// TestReconcile_EndpointArrivesBeforePod covers the inverse of
// TestReconcile_PodArrivesBeforeEndpoint.
func TestReconcile_EndpointArrivesBeforePod(t *testing.T) {
	c := newTestController()
	c.active["vrf-web"] = &VRF{
		Name: "vrf-web", ID: 1, Table: 100,
		Selector: isovalentv1alpha1.IsovalentCoreVRFPodSelector{
			PodSelector: &slimv1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
		},
	}
	c.putNamespace("default", nil)

	ep := &fakeEndpoint{id: 1, namespace: "default", podName: "my-pod"}
	c.endpoints = newFakeEndpointSubscriber(c, ep)

	c.reconcileEndpoints(context.Background(), c.db.ReadTxn(), make(membershipConflict))
	assert.Equal(t, uint32(0), ep.rtInfo,
		"endpoint must not be assigned without a visible pod row")
	assert.Equal(t, 0, ep.regenerations,
		"endpoint must not be regenerated without a visible pod row")

	c.putPod("default", "my-pod", map[string]string{"app": "web"})
	c.reconcileEndpoints(context.Background(), c.db.ReadTxn(), make(membershipConflict))

	assert.Equal(t, uint32(1), ep.rtInfo)
	assert.Equal(t, 1, ep.regenerations)
}

// TestReconcile_PodLabelChangeReleases covers the pod-table-driven label
// change path. The pod's label set is updated to no longer match an active
// VRF, and a sweep must release the endpoint to the default VRF.
func TestReconcile_PodLabelChangeReleases(t *testing.T) {
	c := newTestController()
	c.active["vrf-web"] = &VRF{
		Name: "vrf-web", ID: 1, Table: 100,
		Selector: isovalentv1alpha1.IsovalentCoreVRFPodSelector{
			PodSelector: &slimv1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
		},
	}
	c.putNamespace("default", nil)

	ep := &fakeEndpoint{id: 1, namespace: "default", podName: "my-pod"}
	c.endpoints = newFakeEndpointSubscriber(c, ep)
	c.putPod("default", "my-pod", map[string]string{"app": "web"})

	c.reconcileEndpoints(context.Background(), c.db.ReadTxn(), make(membershipConflict))
	require.Equal(t, uint32(1), ep.rtInfo)
	require.Equal(t, 1, ep.regenerations)

	c.putPod("default", "my-pod", map[string]string{"app": "other"})
	c.reconcileEndpoints(context.Background(), c.db.ReadTxn(), make(membershipConflict))

	assert.Equal(t, uint32(0), ep.rtInfo)
	assert.Equal(t, 2, ep.regenerations)
}

// TestReconcileEndpoint_RetriesAfterFailedRegen ensures that if a regen fails
// the controller will attempt a regen again.
func TestReconcileEndpoint_RetriesAfterFailedRegen(t *testing.T) {
	c := newTestController()
	c.active["vrf-web"] = &VRF{
		Name: "vrf-web", ID: 1, Table: 100,
		Selector: isovalentv1alpha1.IsovalentCoreVRFPodSelector{
			PodSelector: &slimv1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
		},
	}
	c.putNamespace("default", nil)

	ep := &fakeEndpoint{
		id: 1, namespace: "default", podName: "my-pod",
		regenFails: true,
	}
	c.endpoints = newFakeEndpointSubscriber(c, ep)
	c.putPod("default", "my-pod", map[string]string{"app": "web"})

	c.reconcileEndpoints(context.Background(), c.db.ReadTxn(), make(membershipConflict))

	require.Equal(t, uint32(1), ep.rtInfo)
	require.Equal(t, 1, ep.regenerations)
	lxc := c.lxcMap.(*fakeLxcMap)
	_, present := lxc.entries[ep.IPv4Address()]
	require.False(t, present, "lxcmap entry must not appear after failed regen")

	ep.regenFails = false
	c.reconcileEndpoints(context.Background(), c.db.ReadTxn(), make(membershipConflict))

	assert.Equal(t, 2, ep.regenerations, "controller must retry regen after prior failure")
	assert.Equal(t, uint32(1), lxc.entries[ep.IPv4Address()].RTInfo, "lxcmap must reflect applied RTInfo after success")
}

// TestReconcileEndpoint_RetriesAfterFailedRelease ensures that if a regen failed
// during VRF membership release, the controller will attempt the regen again.
func TestReconcileEndpoint_RetriesAfterFailedRelease(t *testing.T) {
	c := newTestController()
	c.active["vrf-web"] = &VRF{
		Name: "vrf-web", ID: 1, Table: 100,
		Selector: isovalentv1alpha1.IsovalentCoreVRFPodSelector{
			PodSelector: &slimv1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
		},
	}
	c.putNamespace("default", nil)

	ep := &fakeEndpoint{id: 1, namespace: "default", podName: "my-pod"}
	c.endpoints = newFakeEndpointSubscriber(c, ep)
	c.putPod("default", "my-pod", map[string]string{"app": "web"})

	c.reconcileEndpoints(context.Background(), c.db.ReadTxn(), make(membershipConflict))
	lxc := c.lxcMap.(*fakeLxcMap)
	require.Equal(t, uint32(1), lxc.entries[ep.IPv4Address()].RTInfo)

	ep.regenFails = true
	c.putPod("default", "my-pod", map[string]string{"app": "other"})
	c.reconcileEndpoints(context.Background(), c.db.ReadTxn(), make(membershipConflict))

	require.Equal(t, uint32(0), ep.rtInfo)
	require.Equal(t, 2, ep.regenerations)
	require.Equal(t, uint32(1), lxc.entries[ep.IPv4Address()].RTInfo, "lxcmap must not change after failed release")

	ep.regenFails = false
	c.reconcileEndpoints(context.Background(), c.db.ReadTxn(), make(membershipConflict))

	assert.Equal(t, 3, ep.regenerations, "controller must retry release after prior failure")
	assert.Equal(t, uint32(0), lxc.entries[ep.IPv4Address()].RTInfo, "lxcmap must reflect cleared RTInfo after successful release")
}

// TestReconcileEndpoint_CoalescedRegenAppliedByPendingEvent ensures if a regen is coalesced the
// endpoint is eventually reconciled correctly.
func TestReconcileEndpoint_CoalescedRegenAppliedByPendingEvent(t *testing.T) {
	c := newTestController()
	c.active["vrf-web"] = &VRF{
		Name: "vrf-web", ID: 1, Table: 100,
		Selector: isovalentv1alpha1.IsovalentCoreVRFPodSelector{
			PodSelector: &slimv1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
		},
	}
	c.putNamespace("default", nil)

	ep := &fakeEndpoint{
		id: 1, namespace: "default", podName: "my-pod",
		regenCoalesce: true,
	}
	c.endpoints = newFakeEndpointSubscriber(c, ep)
	c.putPod("default", "my-pod", map[string]string{"app": "web"})

	c.reconcileEndpoints(context.Background(), c.db.ReadTxn(), make(membershipConflict))

	require.Equal(t, uint32(1), ep.rtInfo)
	require.Equal(t, 1, ep.regenerations)
	lxc := c.lxcMap.(*fakeLxcMap)
	_, present := lxc.entries[ep.IPv4Address()]
	require.False(t, present, "lxcmap must remain empty while coalescing")

	ep.regenCoalesce = false
	lxc.setRTInfo(ep.IPv4Address(), 1)
	prevRegens := ep.regenerations
	c.reconcileEndpoints(context.Background(), c.db.ReadTxn(), make(membershipConflict))

	assert.Equal(t, prevRegens, ep.regenerations, "controller must not regen once lxcmap reflects applied RTInfo")
}

// TestEMSubscriber_TriggerCoalesces ensures the controller's Subscriber
// callbacks never block when the trigger channel is full. Callbacks fire
// under the EM RLock, so a blocking send would deadlock the agent.
func TestEMSubscriber_TriggerCoalesces(t *testing.T) {
	c := newTestController()
	c.endpointManagerEvent = make(chan struct{}, 1)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 1000 {
			c.EndpointCreated(nil)
			c.EndpointDeleted(nil, endpoint.DeleteConfig{})
			c.EndpointRestored(nil)
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("EM subscriber callbacks blocked on trigger channel")
	}

	// Drain the queued trigger and confirm the channel is empty afterward.
	select {
	case <-c.endpointManagerEvent:
	default:
		t.Fatal("expected at least one queued trigger")
	}
	select {
	case <-c.endpointManagerEvent:
		t.Fatal("trigger channel must be coalesced to a single pending event")
	default:
	}
}
