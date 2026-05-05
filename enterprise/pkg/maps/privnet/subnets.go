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
	"unsafe"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb/reconciler"
	"golang.org/x/sys/unix"

	privnetcfg "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/types"
)

const SubnetsMapName = "cilium_privnet_subnets"

// SubnetKey is the privnet_subnets map key.
type SubnetKey struct {
	PrefixLen uint32           `align:"lpm_key"`
	NetID     tables.NetworkID `align:"net_id"`
	Family    uint8            `align:"family"`
	_         [1]uint8         `align:"pad"`
	Address   types.IPv6       `align:"$union0"`
}

const subnetKeyStaticPrefixBits = 8 * uint32(
	unsafe.Sizeof(SubnetKey{})-
		unsafe.Sizeof(SubnetKey{}.PrefixLen)-
		unsafe.Sizeof(SubnetKey{}.Address))

// SubnetVal is the privnet_subnets map value.
type SubnetVal struct {
	SubnetID tables.SubnetID `align:"subnet_id"`
}

// Subnets allows to interact with the privnet_subnets map.
type Subnets struct {
	enabled bool
	*bpf.Map
}

func newSubnets(
	lc cell.Lifecycle,
	cfg privnetcfg.Config,
	mapCfg Config,
) bpf.MapOut[Map[*SubnetKeyVal]] {
	subnetsMap := bpf.NewMap(
		SubnetsMapName,
		ebpf.LPMTrie,
		&SubnetKey{},
		&SubnetVal{},
		int(mapCfg.SubnetsMapSize),
		unix.BPF_F_NO_PREALLOC|unix.BPF_F_RDONLY_PROG,
	)

	lc.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			if !cfg.Enabled {
				if err := subnetsMap.Unpin(); err != nil {
					return fmt.Errorf("unpinning privnet_subnets map: %w", err)
				}
				return nil
			}

			if err := subnetsMap.Recreate(); err != nil {
				return fmt.Errorf("recreating privnet_subnets map: %w", err)
			}
			return nil
		},
		OnStop: func(_ cell.HookContext) error {
			if !cfg.Enabled {
				return nil
			}

			if err := subnetsMap.Close(); err != nil {
				return fmt.Errorf("closing privnet_subnets map: %w", err)
			}
			return nil
		},
	})

	return bpf.NewMapOut(Map[*SubnetKeyVal](Subnets{enabled: cfg.Enabled, Map: subnetsMap}))
}

// Ops implements Map[*SubnetKeyVal]
func (f Subnets) Ops() reconciler.Operations[*SubnetKeyVal] {
	return bpf.NewMapOps[*SubnetKeyVal](f.Map)
}

// Enabled implements Map[*SubnetKeyVal]
func (f Subnets) Enabled() bool {
	return f.enabled
}

// NewSubnetKey constructs a new privnet_subnets map key.
func NewSubnetKey(netID tables.NetworkID, prefix netip.Prefix) SubnetKey {
	family, addr := fromAddr(prefix.Addr())

	return SubnetKey{
		PrefixLen: subnetKeyStaticPrefixBits + uint32(prefix.Bits()),
		NetID:     netID,
		Family:    family,
		Address:   addr,
	}
}

func (k SubnetKey) String() string {
	return fmt.Sprintf("%s %s",
		k.NetID,
		k.ToPrefix(),
	)
}

func (k *SubnetKey) ToPrefix() netip.Prefix {
	return netip.PrefixFrom(
		toAddr(k.Family, k.Address),
		int(k.PrefixLen)-int(subnetKeyStaticPrefixBits),
	)
}

func (*SubnetKey) New() bpf.MapKey {
	return &SubnetKey{}
}

// NewSubnetVal constructs a new privnet_subnets map value.
func NewSubnetVal(subnetID tables.SubnetID) SubnetVal {
	return SubnetVal{
		SubnetID: subnetID,
	}
}

func (v SubnetVal) String() string {
	return v.SubnetID.String()
}

func (SubnetVal) New() bpf.MapValue {
	return &SubnetVal{}
}

var _ KeyValue = &SubnetKeyVal{}

type SubnetKeyVal struct {
	Key SubnetKey
	Val SubnetVal
}

// BinaryKey implements bpf.KeyValue.
func (kv *SubnetKeyVal) BinaryKey() encoding.BinaryMarshaler {
	return bpf.StructBinaryMarshaler{Target: &kv.Key}
}

// BinaryValue implements bpf.KeyValue.
func (kv *SubnetKeyVal) BinaryValue() encoding.BinaryMarshaler {
	return bpf.StructBinaryMarshaler{Target: &kv.Val}
}

// MapKey implements KeyValue
func (kv *SubnetKeyVal) MapKey() bpf.MapKey {
	return &kv.Key
}

// MapValue implements KeyValue
func (kv *SubnetKeyVal) MapValue() bpf.MapValue {
	return &kv.Val
}

func OpenPinnedSubnetsMap(logger *slog.Logger) (*Subnets, error) {
	path := bpf.MapPath(logger, SubnetsMapName)

	m, err := bpf.OpenMap(path, &SubnetKey{}, &SubnetVal{})
	if err != nil {
		return nil, err
	}

	return &Subnets{Map: m}, nil
}
