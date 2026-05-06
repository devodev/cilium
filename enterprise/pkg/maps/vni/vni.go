// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package vni

import (
	"encoding"
	"errors"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"golang.org/x/sys/unix"

	evpnCfg "github.com/cilium/cilium/enterprise/pkg/evpn/config"
	privnetcfg "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
)

const vniMapName = "cilium_vni"

type VNIKey struct {
	VNI uint32 `align:"vni"`
}

func (k *VNIKey) String() string {
	return fmt.Sprintf("vni=%d", k.VNI)
}

func (k *VNIKey) New() bpf.MapKey {
	return &VNIKey{}
}

type VNIVal struct {
	NetID uint16 `align:"net_id"`
	_     uint16 `align:"pad"`
}

func (v *VNIVal) String() string {
	return fmt.Sprintf("net_id=%d", v.NetID)
}

func (v *VNIVal) New() bpf.MapValue {
	return &VNIVal{}
}

var _ bpf.KeyValue = &VNIKeyVal{}

type VNIKeyVal struct {
	Key VNIKey
	Val VNIVal
}

// BinaryKey implements bpf.KeyValue.
func (n *VNIKeyVal) BinaryKey() encoding.BinaryMarshaler {
	return bpf.StructBinaryMarshaler{Target: &n.Key}
}

// BinaryValue implements bpf.KeyValue.
func (n *VNIKeyVal) BinaryValue() encoding.BinaryMarshaler {
	return bpf.StructBinaryMarshaler{Target: &n.Val}
}

type VNI struct {
	*bpf.Map
}

func newVNI(
	lc cell.Lifecycle,
	privnetCfg privnetcfg.Config,
	evpnCfg evpnCfg.Config,
	mapCfg Config,
) bpf.MapOut[VNI] {
	vniMap := bpf.NewMap(
		vniMapName,
		ebpf.Hash,
		&VNIKey{},
		&VNIVal{},
		int(mapCfg.MapSize),
		unix.BPF_F_NO_PREALLOC|unix.BPF_F_RDONLY_PROG,
	)

	// So far, VNI map is only used for Private Networks + EVPN.
	enabled := privnetCfg.Enabled && evpnCfg.Enabled

	lc.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			if !enabled {
				return vniMap.Unpin()
			}
			if err := vniMap.Recreate(); err != nil {
				return fmt.Errorf("failed to create VNI map: %w", err)
			}
			return nil
		},
		OnStop: func(_ cell.HookContext) error {
			if !enabled {
				return nil
			}
			return errors.Join(
				vniMap.Close(),
			)
		},
	})

	return bpf.NewMapOut(VNI{vniMap})
}

func OpenPinnedVNIMap(logger *slog.Logger) (*VNI, error) {
	path := bpf.MapPath(logger, vniMapName)

	m, err := bpf.OpenMap(path, &VNIKey{}, &VNIVal{})
	if err != nil {
		return nil, err
	}

	return &VNI{Map: m}, nil
}
