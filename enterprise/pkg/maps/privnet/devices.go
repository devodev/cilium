// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package privnet

import (
	"encoding"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb/reconciler"
	"golang.org/x/sys/unix"

	privnetcfg "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/types"
)

const DevicesMapName = "cilium_privnet_devices"

type DeviceValType uint8

const (
	DeviceValTypeLxc DeviceValType = iota
	DeviceValTypeNetdev
)

func (d DeviceValType) String() string {
	if d == 0 {
		return "lxc"
	} else {
		return "netdev"
	}
}

// DeviceKey is the privnet_devices map key.
type DeviceKey struct {
	IfIndex uint32 `align:"ifindex"`
}

// DeviceVal is the privnet_devices map value.
type DeviceVal struct {
	NetworkID tables.NetworkID `align:"net_id"`
	Type      DeviceValType    `align:"type"`
	Pad1      uint8            `align:"pad1"`
	IPv4      types.IPv4       `align:"ipv4"`
	IPv6      types.IPv6       `align:"ipv6"`
}

// Devices allows to interact with the privnet_devices map.
type Devices struct {
	enabled bool
	*bpf.Map
}

func newDevices(
	lc cell.Lifecycle,
	cfg privnetcfg.Config,
	mapCfg Config,
) bpf.MapOut[Map[*DeviceKeyVal]] {
	devicesMap := bpf.NewMap(
		DevicesMapName,
		ebpf.Hash,
		&DeviceKey{},
		&DeviceVal{},
		int(mapCfg.DevicesMapSize),
		unix.BPF_F_NO_PREALLOC|unix.BPF_F_RDONLY_PROG,
	)

	lc.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			if !cfg.Enabled {
				if err := devicesMap.Unpin(); err != nil {
					return fmt.Errorf("unpinning privnet_devices map: %w", err)
				}
				return nil
			}

			if err := devicesMap.Recreate(); err != nil {
				return fmt.Errorf("recreating privnet_devices map: %w", err)
			}
			return nil
		},
		OnStop: func(_ cell.HookContext) error {
			if !cfg.Enabled {
				return nil
			}

			if err := devicesMap.Close(); err != nil {
				return fmt.Errorf("closing privnet_devices map: %w", err)
			}
			return nil
		},
	})

	return bpf.NewMapOut(Map[*DeviceKeyVal](Devices{enabled: cfg.Enabled, Map: devicesMap}))
}

// Ops implements Map[*DeviceKeyVal]
func (f Devices) Ops() reconciler.Operations[*DeviceKeyVal] {
	return bpf.NewMapOps[*DeviceKeyVal](f.Map)
}

// Enabled implements Map[*DeviceKeyVal]
func (f Devices) Enabled() bool {
	return f.enabled
}

// NewDeviceKey constructs a new privnet_devices map key.
func NewDeviceKey(ifindex uint32) DeviceKey {
	return DeviceKey{
		IfIndex: ifindex,
	}
}

func (k DeviceKey) String() string {
	return strconv.FormatUint(uint64(k.IfIndex), 10)
}

func (*DeviceKey) New() bpf.MapKey {
	return &DeviceKey{}
}

// NewDeviceVal constructs a new privnet_devices map value.
func NewDeviceVal(netID tables.NetworkID, devType DeviceValType, ipv4, ipv6 netip.Addr) DeviceVal {
	val := DeviceVal{
		NetworkID: netID,
		Type:      devType,
	}
	copy(val.IPv4[:], ipv4.Unmap().AsSlice())
	copy(val.IPv6[:], ipv6.Unmap().AsSlice())
	return val
}

func (v DeviceVal) String() string {
	return fmt.Sprintf("%s %s %s %s",
		v.NetworkID,
		v.Type,
		v.IPv4,
		v.IPv6)
}

func (DeviceVal) New() bpf.MapValue {
	return &DeviceVal{}
}

var _ KeyValue = &DeviceKeyVal{}

type DeviceKeyVal struct {
	Key DeviceKey
	Val DeviceVal
}

// BinaryKey implements bpf.KeyValue.
func (f *DeviceKeyVal) BinaryKey() encoding.BinaryMarshaler {
	return bpf.StructBinaryMarshaler{Target: &f.Key}
}

// BinaryValue implements bpf.KeyValue.
func (f *DeviceKeyVal) BinaryValue() encoding.BinaryMarshaler {
	return bpf.StructBinaryMarshaler{Target: &f.Val}
}

// MapKey implements KeyValue
func (f *DeviceKeyVal) MapKey() bpf.MapKey {
	return &f.Key
}

// MapValue implements KeyValue
func (f *DeviceKeyVal) MapValue() bpf.MapValue {
	return &f.Val
}

func OpenPinnedDevicesMap(logger *slog.Logger) (*Devices, error) {
	path := bpf.MapPath(logger, DevicesMapName)

	m, err := bpf.OpenMap(path, &DeviceKey{}, &DeviceVal{})
	if err != nil {
		return nil, err
	}

	return &Devices{Map: m}, nil
}
