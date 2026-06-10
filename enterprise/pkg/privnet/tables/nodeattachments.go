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
	"strconv"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/enterprise/pkg/privnet/types"
	slim_labels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	cslices "github.com/cilium/cilium/pkg/slices"
)

// DeviceName is the name of the linux device
type DeviceName string

// DeviceType is the type of the device, denoting who created it.
type DeviceType string

const (
	DeviceTypeUserManaged   DeviceType = "user-managed"
	DeviceTypeCiliumManaged DeviceType = "cilium-managed"
)

// NodeSelector is wrapper on label selector and status field denotes if
// local node labels match with the selector.
type NodeSelector struct {
	// Selector associated with the node attachment configuration.
	Selector slim_labels.Selector
	// SelectorMatches denotes whether the selector matches the node labels.
	SelectorMatches bool
}

// DeviceConfiguration is the VLAN configuration of the attachment.
type DeviceConfiguration struct {
	// Parent Interface name.
	ParentInterfaceName DeviceName
	// VLAN ID for the device.
	VLANID int
}

// GetDeviceName returns the device name based on parent interface and vlan id.
func (d DeviceConfiguration) GetDeviceName() DeviceName {
	return DeviceName(fmt.Sprintf("%s.%d", d.ParentInterfaceName, d.VLANID))
}

func (d DeviceConfiguration) String() string {
	if d.ParentInterfaceName == "" {
		return ""
	}
	return fmt.Sprintf("parent: %s, VLAN: %d", d.ParentInterfaceName, d.VLANID)
}

// AttachmentConflict is the conflict status for the attachment. Attachments can conflict if
// they are trying to use the same device name.
type AttachmentConflict string

const (
	AttachmentConflictNone     AttachmentConflict = "none"
	AttachmentConflictNetworks AttachmentConflict = "device-overlap"
)

type NodeAttachment struct {
	// Resource is the private network resource creating this device entry.
	Resource types.PrivateNetworkResource

	// Interface is the network interface.
	Interface NodeAttachmentInterface

	// ParentInterface is the parent network interface for Cilium-managed
	// devices.
	ParentInterface NodeAttachmentInterface

	// Type is device origin type (user defined or managed by Cilium).
	Type DeviceType

	// Network is the private network associated with the device.
	Network NetworkName

	// NodeSelector is the node selector configuration.
	NodeSelector NodeSelector

	// Subnets for this device, this is reflection of NodeAttachment resource.
	Subnets []SubnetName

	// Config is the device configuration.
	Config DeviceConfiguration

	// Conflict is the conflict status for this device.
	Conflict AttachmentConflict

	// OpsStatus is the reconciler status for attachment operations.
	OpsStatus reconciler.Status
}

func (a *NodeAttachment) IsManagedDevice() bool {
	return a.Type == DeviceTypeCiliumManaged &&
		a.NodeSelector.SelectorMatches &&
		a.Conflict == AttachmentConflictNone
}

func (a *NodeAttachment) IsReady() bool {
	return a.NodeSelector.SelectorMatches && a.Conflict == AttachmentConflictNone && a.Interface.Index > 0
}

var _ statedb.TableWritable = &NodeAttachment{}

func (a *NodeAttachment) Key() NodeAttachmentPrimaryKey {
	return newNodeAttachmentPrimaryKey(a.Resource, a.Interface.Name)
}

func (a *NodeAttachment) TableHeader() []string {
	return []string{"Origin", "Interface", "ParentInterface", "Type", "Config", "NodeSelected", "Network", "Subnets", "Conflict", "Status"}
}

func (a *NodeAttachment) TableRow() []string {
	parentInterface := "N/A"
	if a.ParentInterface.Name != "" {
		parentInterface = a.ParentInterface.String()
	}

	return []string{
		a.Resource.String(),
		a.Interface.String(),
		parentInterface,
		string(a.Type),
		cmp.Or(a.Config.String(), "N/A"),
		strconv.FormatBool(a.NodeSelector.SelectorMatches),
		string(a.Network),
		cmp.Or(strings.Join(cslices.Map(a.Subnets, func(s SubnetName) string { return string(s) }), ","), "<all-subnets>"), // empty list = match all
		string(a.Conflict),
		a.OpsStatus.String(),
	}
}

func (a *NodeAttachment) SetDeviceCreationStatus(status reconciler.Status) *NodeAttachment {
	a2 := *a
	a2.OpsStatus = status
	return &a2
}

func (a *NodeAttachment) Clone() *NodeAttachment {
	a2 := *a
	return &a2
}

func (a *NodeAttachment) GetDeviceCreationStatus() reconciler.Status {
	return a.OpsStatus
}

// NodeAttachmentInterface is the network interface associated with a node attachment.
type NodeAttachmentInterface struct {
	// Name is the name of the network interface.
	Name DeviceName

	// Index is the (positive) index of the network interface.
	Index int

	// Error is the possible error occurred mapping the network interface name to its index.
	Error string
}

func (nai NodeAttachmentInterface) String() string {
	var index = "!"

	if nai.Index != 0 {
		index = strconv.Itoa(nai.Index)
	}

	return string(nai.Name) + " (" + index + ")"
}

// NodeAttachmentPrimaryKey is <resource-type>/<resource-name>|<device-name>.
type NodeAttachmentPrimaryKey string

func (key NodeAttachmentPrimaryKey) Key() index.Key { return index.String(string(key)) }

func newNodeAttachmentPrimaryKey(resource types.PrivateNetworkResource, deviceName DeviceName) NodeAttachmentPrimaryKey {
	return newAttachmentKeyFromResource(resource) + NodeAttachmentPrimaryKey(deviceName)
}

func newAttachmentKeyFromResource(resource types.PrivateNetworkResource) NodeAttachmentPrimaryKey {
	return NodeAttachmentPrimaryKey(resource.String() + indexDelimiter)
}

var (
	nodeAttachmentPrimaryIndex = statedb.Index[*NodeAttachment, NodeAttachmentPrimaryKey]{
		Name: "primary",
		FromObject: func(obj *NodeAttachment) index.KeySet {
			return index.NewKeySet(obj.Key().Key())
		},
		FromKey:    NodeAttachmentPrimaryKey.Key,
		FromString: index.FromString,
		Unique:     true,
	}

	nodeAttachmentDeviceNameIndex = statedb.Index[*NodeAttachment, string]{
		Name: "device",
		FromObject: func(obj *NodeAttachment) index.KeySet {
			return index.NewKeySet(index.String(string(obj.Interface.Name)))
		},
		FromKey:    index.String,
		FromString: index.FromString,
		Unique:     false,
	}

	nodeAttachmentNetworkNameIndex = statedb.Index[*NodeAttachment, string]{
		Name:       "network",
		FromObject: func(obj *NodeAttachment) index.KeySet { return index.NewKeySet(index.String(string(obj.Network))) },
		FromKey:    index.String,
		FromString: index.FromString,
		Unique:     false,
	}
)

func NodeAttachmentByResource(resource types.PrivateNetworkResource) statedb.Query[*NodeAttachment] {
	return nodeAttachmentPrimaryIndex.Query(newAttachmentKeyFromResource(resource))
}

func NodeAttachmentsByDeviceName(deviceName DeviceName) statedb.Query[*NodeAttachment] {
	return nodeAttachmentDeviceNameIndex.Query(string(deviceName))
}

func NodeAttachmentsByNetworkName(networkName NetworkName) statedb.Query[*NodeAttachment] {
	return nodeAttachmentNetworkNameIndex.Query(string(networkName))
}

func NewNodeAttachmentsTable(db *statedb.DB) (statedb.RWTable[*NodeAttachment], error) {
	return statedb.NewTable(
		db,
		"privnet-node-attachments",
		nodeAttachmentPrimaryIndex,
		nodeAttachmentDeviceNameIndex,
		nodeAttachmentNetworkNameIndex,
	)
}
