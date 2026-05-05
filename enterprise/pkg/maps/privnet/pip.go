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

const PIPMapName = "cilium_privnet_pip"

// PIPKey is the PIP map key.
type PIPKey struct {
	PrefixLen uint32     `align:"lpm_key"`
	Family    uint8      `align:"family"`
	_         [3]uint8   `align:"pad"`
	Address   types.IPv6 `align:"$union0"`
}

const pipKeyStaticPrefixBits = uint32(unsafe.Sizeof(PIPKey{})-
	unsafe.Sizeof(PIPKey{}.PrefixLen)-
	unsafe.Sizeof(PIPKey{}.Address)) * 8

// PIPVal is the PIP map value.
type PIPVal struct {
	Address types.IPv6       `align:"$union0"`
	_       uint8            `align:"pad"`
	Family  uint8            `align:"family"`
	NetID   tables.NetworkID `align:"net_id"`
}

// PIP allows to interact with the private network PIP map.
type PIP struct {
	enabled bool
	*bpf.Map
}

func newPIP(
	lc cell.Lifecycle,
	cfg privnetcfg.Config,
	mapCfg Config,
) bpf.MapOut[Map[*PIPKeyVal]] {
	pipMap := bpf.NewMap(
		PIPMapName,
		ebpf.LPMTrie,
		&PIPKey{},
		&PIPVal{},
		int(mapCfg.MapSize),
		unix.BPF_F_NO_PREALLOC|unix.BPF_F_RDONLY_PROG,
	)

	lc.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			if !cfg.Enabled {
				return pipMap.Unpin()
			}
			if err := pipMap.Recreate(); err != nil {
				return fmt.Errorf("failed to create PIP map: %w", err)
			}
			return nil
		},
		OnStop: func(_ cell.HookContext) error {
			if !cfg.Enabled {
				return nil
			}
			return pipMap.Close()
		},
	})

	return bpf.NewMapOut(Map[*PIPKeyVal](PIP{
		enabled: cfg.Enabled,
		Map:     pipMap,
	}))
}

// Ops implements Map[*PIPKeyVal]
func (p PIP) Ops() reconciler.Operations[*PIPKeyVal] {
	return bpf.NewMapOps[*PIPKeyVal](p.Map)
}

// Enabled implements Map[*PIPKeyVal]
func (p PIP) Enabled() bool {
	return p.enabled
}

// NewPIPKey constructs a new PIP map key.
func NewPIPKey(prefix netip.Prefix) PIPKey {
	family, addr := fromAddr(prefix.Addr())
	prefixLen := pipKeyStaticPrefixBits + uint32(prefix.Bits())

	return PIPKey{
		PrefixLen: prefixLen,
		Family:    family,
		Address:   addr,
	}
}

func (k PIPKey) String() string {
	return k.ToPrefix().String()
}

func (k *PIPKey) ToPrefix() netip.Prefix {
	return netip.PrefixFrom(
		toAddr(k.Family, k.Address),
		int(k.PrefixLen)-int(pipKeyStaticPrefixBits),
	)
}

func (*PIPKey) New() bpf.MapKey {
	return &PIPKey{}
}

func NewPIPVal(
	netID tables.NetworkID,
	addr netip.Addr,
) PIPVal {
	family, address := fromAddr(addr)

	return PIPVal{
		Family:  family,
		Address: address,
		NetID:   netID,
	}
}

func (v PIPVal) String() string {
	return fmt.Sprintf("%s %s",
		v.NetID,
		v.ToAddr(),
	)
}

func (v *PIPVal) ToAddr() netip.Addr {
	return toAddr(v.Family, v.Address)
}

func (*PIPVal) New() bpf.MapValue {
	return &PIPVal{}
}

var _ KeyValue = &PIPKeyVal{}

type PIPKeyVal struct {
	Key PIPKey
	Val PIPVal
}

// BinaryKey implements bpf.KeyValue.
func (p *PIPKeyVal) BinaryKey() encoding.BinaryMarshaler {
	return bpf.StructBinaryMarshaler{Target: &p.Key}
}

// BinaryValue implements bpf.KeyValue.
func (p *PIPKeyVal) BinaryValue() encoding.BinaryMarshaler {
	return bpf.StructBinaryMarshaler{Target: &p.Val}
}

// MapKey implements KeyValue
func (p *PIPKeyVal) MapKey() bpf.MapKey {
	return &p.Key
}

// MapValue implements KeyValue
func (p *PIPKeyVal) MapValue() bpf.MapValue {
	return &p.Val
}

func OpenPinnedPIPMap(logger *slog.Logger) (*PIP, error) {
	path := bpf.MapPath(logger, PIPMapName)

	m, err := bpf.OpenMap(path, &PIPKey{}, &PIPVal{})
	if err != nil {
		return nil, err
	}

	return &PIP{Map: m}, nil
}
