// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package tables

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"

	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/time"
)

// LocalWorkload represents a private networks enabled workload running locally.
type LocalWorkload struct {
	// EndpointID is the Cilium's numeric identifier of the endpoint.
	EndpointID uint16

	// Namespace is the Kubernetes namespace this endpoint lives in.
	Namespace string

	// Subnet is the name of the private network subnet this endpoint is attached to.
	Subnet SubnetName

	// Endpoint contains the identifiers from the pod network point of view.
	Endpoint iso_v1alpha1.PrivateNetworkEndpointSliceEndpoint

	// Interface contains identifiers from the private network point of view.
	Interface iso_v1alpha1.PrivateNetworkEndpointSliceInterface

	// Flags contains additional flags to characterize the endpoint.
	Flags iso_v1alpha1.PrivateNetworkEndpointSliceFlags

	// UsesDHCPv4 reports whether the workload was configured to obtain its IPv4
	// address via DHCP.
	UsesDHCPv4 bool

	// LXC is the LXC interface associated with this endpoint.
	LXC LocalWorkloadLXC

	// NICIndex is the index of the NIC of the workload. The primary interface
	// has index 0, the first secondary interface has index 1, and so on. At
	// most [addressing.MaxSecondaryInterfaces] secondary interfaces are supported.
	NICIndex uint8

	// ActivatedAt is the instant in time in which this entry was marked as active.
	ActivatedAt time.Time

	// ActivationBlockers are list of reasons why activation is blocked.
	ActivationBlockers []ActivationBlocker
}

type ActivationBlocker = string

const (
	// ActivationBlockerMigration blocks the activation due to ongoing migration.
	ActivationBlockerMigration ActivationBlocker = "migration"

	// ActivationBlockerInactive blocks the activation due to inactive annotation.
	ActivationBlockerInactive ActivationBlocker = "inactive"
)

func (lw *LocalWorkload) IsActivationBlocked() bool {
	return len(lw.ActivationBlockers) > 0
}

// GetActivatedAt returns the activation time or zero if the activation is blocked.
func (lw *LocalWorkload) GetActivatedAt() time.Time {
	if len(lw.ActivationBlockers) > 0 {
		return time.Time{}
	}
	return lw.ActivatedAt
}

func (lw *LocalWorkload) AddActivationBlocker(reason ActivationBlocker) {
	if slices.Contains(lw.ActivationBlockers, reason) {
		return
	}
	lw.ActivationBlockers = append(slices.Clone(lw.ActivationBlockers), reason)
}

func (lw *LocalWorkload) RemoveActivationBlocker(reason ActivationBlocker) {
	if idx := slices.Index(lw.ActivationBlockers, reason); idx >= 0 {
		lw.ActivationBlockers = slices.Delete(
			slices.Clone(lw.ActivationBlockers),
			idx, idx+1)
	}
	if len(lw.ActivationBlockers) == 0 && lw.ActivatedAt.IsZero() {
		lw.ActivatedAt = time.Now()
	}
}

// LocalWorkloadLXC is the LXC interface associated with an endpoint.
type LocalWorkloadLXC struct {
	// IfName is the name of the LXC interface associated with this endpoint.
	IfName string

	// IfIndex is the index of the LXC interface associated with this endpoint.
	IfIndex int
}

var _ statedb.TableWritable = &LocalWorkload{}

func (lw *LocalWorkload) TableHeader() []string {
	return []string{
		"Endpoint", "ID", "NIC",
		"Network", "NetworkIPv4", "NetworkIPv6",
		"PodIPv4", "PodIPv6", "ActivatedAt",
	}
}

func (lw *LocalWorkload) TableRow() []string {
	activatedAt := formatActivatedAt(lw.ActivatedAt)
	if lw.IsActivationBlocked() {
		activatedAt = fmt.Sprintf("<blocked: %s>",
			strings.Join(lw.ActivationBlockers, ", "))
	}

	return []string{
		lw.Namespace + "/" + lw.Endpoint.Name,
		strconv.FormatUint(uint64(lw.EndpointID), 10),
		strconv.FormatUint(uint64(lw.NICIndex), 10),
		lw.Interface.Network,
		cmp.Or(lw.Interface.Addressing.IPv4, "N/A"),
		cmp.Or(lw.Interface.Addressing.IPv6, "N/A"),
		cmp.Or(lw.Endpoint.Addressing.IPv4, "N/A"),
		cmp.Or(lw.Endpoint.Addressing.IPv6, "N/A"),
		activatedAt,
	}
}

var (
	unspecifiedIPv4String = netip.IPv4Unspecified().String()
	unspecifiedIPv6String = netip.IPv6Unspecified().String()
)

// HasUsableIP returns true if the endpoint has a valid network IPv4 or IPv6
func (lw *LocalWorkload) HasUsableIP() bool {
	if lw.Interface.Addressing.IPv4 != "" && lw.Interface.Addressing.IPv4 != unspecifiedIPv4String {
		return true
	}
	if lw.Interface.Addressing.IPv6 != "" && lw.Interface.Addressing.IPv6 != unspecifiedIPv6String {
		return true
	}
	return false
}

var (
	localWorkloadsID = statedb.Index[*LocalWorkload, uint16]{
		Name: "id",
		FromObject: func(obj *LocalWorkload) index.KeySet {
			return index.NewKeySet(index.Uint16(obj.EndpointID))
		},
		FromKey:    index.Uint16,
		FromString: index.Uint16String,
		Unique:     true,
	}

	localWorkloadsNamespace = statedb.Index[*LocalWorkload, string]{
		Name: "namespace",
		FromObject: func(obj *LocalWorkload) index.KeySet {
			return index.NewKeySet(index.String(obj.Namespace))
		},
		FromKey:    index.String,
		FromString: index.FromString,
		Unique:     false,
	}

	localWorkloadsNetwork = statedb.Index[*LocalWorkload, string]{
		Name: "network",
		FromObject: func(obj *LocalWorkload) index.KeySet {
			return index.NewKeySet(index.String(string(obj.Interface.Network)))
		},
		FromKey:    index.String,
		FromString: index.FromString,
		Unique:     false,
	}

	// LocalWorkloadsByID queries the local workloads table by ID.
	LocalWorkloadsByID = localWorkloadsID.Query

	// LocalWorkloadsByNamespace queries the local workloads table by endpoint namespace.
	LocalWorkloadsByNamespace = localWorkloadsNamespace.Query

	// localWorkloadsNetwork queries the local workloads table by network name.
	LocalWorkloadsByNetwork = localWorkloadsNetwork.Query
)

func NewLocalWorkloadsTable(db *statedb.DB) (statedb.RWTable[*LocalWorkload], error) {
	return statedb.NewTable(
		db,
		"privnet-local-workloads",
		localWorkloadsID,
		localWorkloadsNamespace,
		localWorkloadsNetwork,
	)
}
