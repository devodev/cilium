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
	"github.com/cilium/cilium/enterprise/pkg/vni"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/types"
)

const FIBMapName = "cilium_privnet_fib"

// FIBKeyType indicates the type of the entry.
type FIBKeyType uint8

const (
	// FIBKeyTypeDefault is set if the entry is a route or endpoint.
	FIBKeyTypeDefault FIBKeyType = iota
	// FIBKeyTypePeering is set if the entry is a peering route.
	FIBKeyTypePeering
)

// FIBKey is the FIB map key.
type FIBKey struct {
	PrefixLen uint32           `align:"lpm_key"`
	NetID     tables.NetworkID `align:"net_id"`
	SubnetID  tables.SubnetID  `align:"subnet_id"`
	Family    uint8            `align:"family"`
	Type      FIBKeyType       `align:"type"`
	_         [2]uint8         `align:"pad"`
	Address   types.IPv6       `align:"$union0"`
}

const fibKeyStaticPrefixBits = uint32(unsafe.Sizeof(FIBKey{})-
	unsafe.Sizeof(FIBKey{}.PrefixLen)-
	unsafe.Sizeof(FIBKey{}.Address)) * 8

// FIBValFlags are the flags in the FIB map value.
type FIBValFlags uint8

const (
	// FIBFlagL2Announce is set if the privnet datapath should reply to ARPs/NDs.
	FIBFlagL2Announce FIBValFlags = 1 << iota
)

// FIBVal is the FIB map value.
type FIBVal struct {
	Address      types.IPv6    `align:"$union0"`
	MAC          types.MACAddr `align:"mac"`
	_            [3]uint8
	Type         tables.MapEntryType `align:"type"`
	Flags        FIBValFlags         `align:"flag_l2_announce"`
	Family       uint8               `align:"family"`
	IfIndex      uint32              `align:"ifindex"`
	VNI          uint32              `align:"vni"`
	PeerNetID    tables.NetworkID    `align:"peer_net_id"`
	PeerSubnetID tables.SubnetID     `align:"peer_subnet_id"`
}

// FIB allows to interact with the private network FIB map.
type FIB struct {
	enabled bool
	*bpf.Map
}

func newFIB(
	lc cell.Lifecycle,
	cfg privnetcfg.Config,
	mapCfg Config,
) bpf.MapOut[Map[*FIBKeyVal]] {
	fibMap := bpf.NewMap(
		FIBMapName,
		ebpf.LPMTrie,
		&FIBKey{},
		&FIBVal{},
		int(mapCfg.MapSize),
		unix.BPF_F_NO_PREALLOC|unix.BPF_F_RDONLY_PROG,
	)

	lc.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			if !cfg.Enabled {
				return fibMap.Unpin()
			}
			if err := fibMap.Recreate(); err != nil {
				return fmt.Errorf("failed to create FIB map: %w", err)
			}
			return nil
		},
		OnStop: func(_ cell.HookContext) error {
			if !cfg.Enabled {
				return nil
			}
			return fibMap.Close()
		},
	})

	return bpf.NewMapOut(Map[*FIBKeyVal](FIB{
		enabled: cfg.Enabled,
		Map:     fibMap,
	}))
}

// Ops implements Map[*FIBKeyVal]
func (f FIB) Ops() reconciler.Operations[*FIBKeyVal] {
	return bpf.NewMapOps[*FIBKeyVal](f.Map)
}

// Enabled implements Map[*PIPKeyVal]
func (f FIB) Enabled() bool {
	return f.enabled
}

// NewFIBKey constructs a new FIB map key.
func NewFIBKey(netID tables.NetworkID, subnetID tables.SubnetID, typ FIBKeyType, prefix netip.Prefix) FIBKey {
	family, addr := fromAddr(prefix.Addr())
	prefixLen := fibKeyStaticPrefixBits + uint32(prefix.Bits())

	return FIBKey{
		PrefixLen: prefixLen,
		NetID:     netID,
		SubnetID:  subnetID,
		Family:    family,
		Type:      typ,
		Address:   addr,
	}
}

func (k FIBKey) String() string {
	return fmt.Sprintf("%s %s %#x %s",
		k.NetID,
		k.SubnetID,
		k.Type,
		k.ToPrefix(),
	)
}

func (k *FIBKey) ToPrefix() netip.Prefix {
	return netip.PrefixFrom(
		toAddr(k.Family, k.Address),
		int(k.PrefixLen)-int(fibKeyStaticPrefixBits),
	)
}

func (*FIBKey) New() bpf.MapKey {
	return &FIBKey{}
}

// NewFIBVal constructs a new FIB map value.
func NewFIBVal(addr netip.Addr, mac types.MACAddr, typ tables.MapEntryType, flags FIBValFlags, ifindex uint32, vni vni.VNI, peerNetID tables.NetworkID, peerSubnetID tables.SubnetID) FIBVal {
	family, address := fromAddr(addr)

	return FIBVal{
		Type:         typ,
		Address:      address,
		MAC:          mac,
		Flags:        flags,
		Family:       family,
		IfIndex:      ifindex,
		VNI:          vni.AsUint32(),
		PeerNetID:    peerNetID,
		PeerSubnetID: peerSubnetID,
	}
}

func (v FIBVal) String() string {
	return fmt.Sprintf("%s %s %#x %s %d %d %s/%s",
		v.Type,
		v.ToAddr(),
		v.Flags,
		v.MAC,
		v.IfIndex,
		v.VNI,
		v.PeerNetID,
		v.PeerSubnetID,
	)
}

func (v *FIBVal) ToAddr() netip.Addr {
	return toAddr(v.Family, v.Address)
}

func (*FIBVal) New() bpf.MapValue {
	return &FIBVal{}
}

var _ KeyValue = &FIBKeyVal{}

type FIBKeyVal struct {
	Key FIBKey
	Val FIBVal
}

// BinaryKey implements bpf.KeyValue.
func (f *FIBKeyVal) BinaryKey() encoding.BinaryMarshaler {
	return bpf.StructBinaryMarshaler{Target: &f.Key}
}

// BinaryValue implements bpf.KeyValue.
func (f *FIBKeyVal) BinaryValue() encoding.BinaryMarshaler {
	return bpf.StructBinaryMarshaler{Target: &f.Val}
}

// MapKey implements KeyValue
func (f *FIBKeyVal) MapKey() bpf.MapKey {
	return &f.Key
}

// MapValue implements KeyValue
func (f *FIBKeyVal) MapValue() bpf.MapValue {
	return &f.Val
}

func fromAddr(ip netip.Addr) (family uint8, res types.IPv6) {
	addr := ip.Unmap()
	family = bpf.EndpointKeyIPv4
	if addr.Is6() {
		family = bpf.EndpointKeyIPv6
	}
	copy(res[:], addr.AsSlice())
	return
}

func toAddr(family uint8, address types.IPv6) netip.Addr {
	var addr netip.Addr

	switch family {
	case bpf.EndpointKeyIPv4:
		addr = netip.AddrFrom4([4]byte(address[:4]))
	case bpf.EndpointKeyIPv6:
		addr = netip.AddrFrom16(address)
	}

	return addr
}

func OpenPinnedFIBMap(logger *slog.Logger) (*FIB, error) {
	path := bpf.MapPath(logger, FIBMapName)

	m, err := bpf.OpenMap(path, &FIBKey{}, &FIBVal{})
	if err != nil {
		return nil, err
	}

	return &FIB{Map: m}, nil
}
