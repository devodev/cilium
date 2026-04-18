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
	"fmt"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	slimLabels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

const TableName = "cilium-vrfs"

type VRF struct {
	ID           uint16
	Name         string
	Table        uint32
	NodeSelector *slimv1.LabelSelector
	Selector     isovalentv1alpha1.IsovalentCoreVRFPodSelector
	Interfaces   []string
}

func (v VRF) TableHeader() []string {
	return []string{"Name", "Table", "Interfaces"}
}

func (v VRF) TableRow() []string {
	return []string{
		v.Name,
		fmt.Sprintf("%d", v.Table),
		strings.Join(v.Interfaces, ", "),
	}
}

func (v *VRF) Equal(vrf *VRF) bool {
	if v.ID != vrf.ID {
		return false
	}
	if v.Table != vrf.Table {
		return false
	}
	if len(v.Interfaces) != len(vrf.Interfaces) {
		return false
	}
	for i := range v.Interfaces {
		if v.Interfaces[i] != vrf.Interfaces[i] {
			return false
		}
	}
	return v.Selector.DeepEqual(&vrf.Selector)
}

// MatchesNode returns true if this VRF targets the given node labels.
// A nil NodeSelector matches all nodes.
func (vrf *VRF) MatchesNode(nodeLabels map[string]string) bool {
	if vrf.NodeSelector == nil {
		return true
	}
	sel, _ := slimv1.LabelSelectorAsSelector(vrf.NodeSelector)
	return sel.Matches(slimLabels.Set(nodeLabels))
}

// selector converts the VRF's pod label selector into a k8s label selector
// for endpoint matching.
//
// Label selectors are validated at the API server on admission, so conversion
// errors are not possible for objects that exist in the store.
func (vrf *VRF) selector() slimLabels.Selector {
	if vrf.Selector.PodSelector != nil {
		s, _ := slimv1.LabelSelectorAsSelector(vrf.Selector.PodSelector)
		return s
	}
	return nil
}

// namespaceSelector converts the VRF's namespace label selector into a k8s
// label selector for endpoint matching.
func (vrf *VRF) namespaceSelector() slimLabels.Selector {
	if vrf.Selector.NamespaceSelector != nil {
		s, _ := slimv1.LabelSelectorAsSelector(vrf.Selector.NamespaceSelector)
		return s
	}
	return nil
}

// FindVRFByLabels iterates all VRFs and returns the first whose pod and
// namespace selectors match the given labels. Returns nil if no VRF matches.
func FindVRFByLabels(txn statedb.ReadTxn, table statedb.Table[VRF], podLabels, nsLabels map[string]string) (*VRF, error) {
	podSet := slimLabels.Set(podLabels)
	nsSet := slimLabels.Set(nsLabels)
	for vrf := range table.All(txn) {
		nsSel := vrf.namespaceSelector()
		if nsSel != nil && !nsSel.Matches(nsSet) {
			continue
		}

		podSel := vrf.selector()
		if podSel != nil && !podSel.Matches(podSet) {
			continue
		}

		// At least one selector must be set for a VRF to match.
		if nsSel != nil || podSel != nil {
			return &vrf, nil
		}
	}
	return nil, nil
}

var NameIndex = statedb.Index[VRF, string]{
	Name: "name",
	FromObject: func(v VRF) index.KeySet {
		return index.NewKeySet(index.String(v.Name))
	},
	FromKey: index.String,
	Unique:  true,
}

var TableIndex = statedb.Index[VRF, uint32]{
	Name: "table",
	FromObject: func(v VRF) index.KeySet {
		return index.NewKeySet(index.Uint32(v.Table))
	},
	FromKey: index.Uint32,
	Unique:  true,
}

var IDIndex = statedb.Index[VRF, uint16]{
	Name: "id",
	FromObject: func(v VRF) index.KeySet {
		return index.NewKeySet(index.Uint16(v.ID))
	},
	FromKey: index.Uint16,
	Unique:  true,
}

func NewVRFTable(db *statedb.DB) (statedb.RWTable[VRF], error) {
	return statedb.NewTable(db, TableName, NameIndex, TableIndex, IDIndex)
}
