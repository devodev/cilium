// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package evpn

import (
	"encoding"
	"fmt"
	"net"
	"net/netip"
	"unsafe"

	"github.com/cilium/hive/cell"
	"golang.org/x/sys/unix"

	evpnCfg "github.com/cilium/cilium/enterprise/pkg/evpn/config"
	"github.com/cilium/cilium/enterprise/pkg/vni"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/types"
)

const fibMapName = "cilium_evpn_fib"

type FIBKey struct {
	PrefixLen uint32     `align:"lpm_key"`
	Family    uint8      `align:"family"`
	_         uint8      `align:"pad0"`
	NetID     uint16     `align:"net_id"`
	Address   types.IPv6 `align:"$union0"`
}

const fibKeyStaticPrefixBits = uint32(unsafe.Sizeof(FIBKey{})-
	unsafe.Sizeof(FIBKey{}.PrefixLen)-
	unsafe.Sizeof(FIBKey{}.Address)) * 8

func NewFIBKey(netID uint16, prefix netip.Prefix) (*FIBKey, error) {
	var family uint8
	switch {
	case prefix.Addr().Is4():
		family = unix.AF_INET
	case prefix.Addr().Is6():
		family = unix.AF_INET6
	default:
		return nil, fmt.Errorf("invalid prefix: %s", prefix)
	}
	k := &FIBKey{
		PrefixLen: uint32(prefix.Bits()) + fibKeyStaticPrefixBits,
		Family:    family,
		NetID:     netID,
	}
	copy(k.Address[:], prefix.Addr().AsSlice())
	return k, nil
}

// This is for testing. Never use this in production code, as it panics on invalid input.
func MustNewFIBKey(netID uint16, prefix netip.Prefix) *FIBKey {
	k, err := NewFIBKey(netID, prefix)
	if err != nil {
		panic(err)
	}
	return k
}

func (k *FIBKey) New() bpf.MapKey {
	return &FIBKey{}
}

func (k *FIBKey) String() string {
	return fmt.Sprintf("net_id=%d prefix=%s", k.NetID, k.Prefix())
}

func (k *FIBKey) Prefix() netip.Prefix {
	var addr netip.Addr
	switch k.Family {
	case unix.AF_INET:
		addr = netip.AddrFrom4([4]byte(k.Address[:4]))
	case unix.AF_INET6:
		addr = netip.AddrFrom16(k.Address)
	default:
		return netip.Prefix{}
	}
	return netip.PrefixFrom(addr, int(k.PrefixLen-fibKeyStaticPrefixBits))
}

type FIBVal struct {
	VNI     uint32   `align:"vni"`
	Family  uint8    `align:"family"`
	_       [3]uint8 `align:"pad0"`
	MAC     [6]uint8 `align:"mac"`
	_       [2]uint8
	Address types.IPv6 `align:"$union0"`
}

var zeroMAC48 = [6]uint8{}

func NewFIBVal(vni vni.VNI, m mac.MAC, addr netip.Addr) (*FIBVal, error) {
	var family uint8
	switch {
	case addr.Is4():
		family = unix.AF_INET
	case addr.Is6():
		family = unix.AF_INET6
	default:
		return nil, fmt.Errorf("invalid addr: %s", addr)
	}

	// We need this validation as in Linux kernel's VXLAN implementation,
	// a zero MAC is often used for representing ingress replication entries.
	// While there's no much risk to hit this in Cilium as we don't support
	// ingress replication at this point, it's safer to not use that.
	mac48 := m.As6()
	if mac48 == zeroMAC48 {
		return nil, fmt.Errorf("invalid MAC address: cannot be all zeros")
	}

	v := &FIBVal{
		VNI:    vni.AsUint32(),
		Family: family,
		MAC:    mac48,
	}
	copy(v.Address[:], addr.AsSlice())
	return v, nil
}

// This is for testing. Never use this in production code, as it panics on invalid input.
func MustNewFIBVal(vni vni.VNI, mac mac.MAC, addr netip.Addr) *FIBVal {
	v, err := NewFIBVal(vni, mac, addr)
	if err != nil {
		panic(err)
	}
	return v
}

func (v *FIBVal) String() string {
	mac := net.HardwareAddr(v.MAC[:6])
	return fmt.Sprintf("vni=%d mac=%s addr=%s", v.VNI, mac, v.Addr())
}

func (v *FIBVal) Addr() netip.Addr {
	switch v.Family {
	case unix.AF_INET:
		return netip.AddrFrom4([4]byte(v.Address[:4]))
	case unix.AF_INET6:
		return netip.AddrFrom16(v.Address)
	default:
		return netip.Addr{}
	}
}

func (v *FIBVal) New() bpf.MapValue {
	return &FIBVal{}
}

var _ bpf.KeyValue = &FIBKeyVal{}

type FIBKeyVal struct {
	Key *FIBKey
	Val *FIBVal
}

// BinaryKey implements bpf.KeyValue.
func (n *FIBKeyVal) BinaryKey() encoding.BinaryMarshaler {
	return bpf.StructBinaryMarshaler{Target: &n.Key}
}

// BinaryValue implements bpf.KeyValue.
func (n *FIBKeyVal) BinaryValue() encoding.BinaryMarshaler {
	return bpf.StructBinaryMarshaler{Target: &n.Val}
}

type FIB struct {
	*bpf.Map
}

func newFIB(
	lc cell.Lifecycle,
	evpnCfg evpnCfg.Config,
	mapCfg Config,
) bpf.MapOut[FIB] {
	fibMap := bpf.NewMap(
		fibMapName,
		ebpf.LPMTrie,
		&FIBKey{},
		&FIBVal{},
		int(mapCfg.FIBMapSize),
		unix.BPF_F_NO_PREALLOC|unix.BPF_F_RDONLY_PROG,
	)

	enabled := evpnCfg.Enabled

	lc.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			if !enabled {
				return fibMap.UnpinIfExists()
			}

			// We reuse the map from the previous run. The RIB restores the entries
			// from the map at startup and performs GC later. This allows us to avoid
			// traffic disruption on Cilium restart.
			if err := fibMap.OpenOrCreate(); err != nil {
				return fmt.Errorf("failed to open/create FIB map: %w", err)
			}

			return nil
		},
		OnStop: func(_ cell.HookContext) error {
			if !enabled {
				return nil
			}
			return fibMap.Close()
		},
	})

	return bpf.NewMapOut(FIB{fibMap})
}

func (f FIB) List() ([]FIBKeyVal, error) {
	var entries []FIBKeyVal
	err := f.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		entries = append(entries, FIBKeyVal{
			Key: k.(*FIBKey),
			Val: v.(*FIBVal),
		})
	})
	return entries, err
}
