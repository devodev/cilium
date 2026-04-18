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
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/maps"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/maps/registry"
)

type VrfID types.VRFID
type TableID types.VRFTableID

func (k *VrfID) String() string  { return fmt.Sprintf("%d", *k) }
func (k *VrfID) New() bpf.MapKey { return new(VrfID) }

func (v *TableID) String() string    { return fmt.Sprintf("%d", *v) }
func (v *TableID) New() bpf.MapValue { return new(TableID) }

type VRFMap interface {
	Get(uint16) (uint32, error)
	Upsert(uint16, uint32) error
	Delete(uint16) error
	List() (map[uint16]uint32, error)
}

type vrfMap struct {
	m *bpf.Map
}

func (vm *vrfMap) Get(vid uint16) (uint32, error) {
	key := VrfID(vid)
	v, err := vm.m.Lookup(&key)
	if err != nil {
		return 0, fmt.Errorf("lookup vrf_map: %w", err)
	}
	tid, ok := v.(*TableID)
	if !ok {
		return 0, fmt.Errorf("unexpected value type %T from vrf_map", v)
	}
	return uint32(*tid), nil
}

func (vm *vrfMap) Upsert(vid uint16, tid uint32) error {
	key := VrfID(vid)
	val := TableID(tid)
	if err := vm.m.Update(&key, &val); err != nil {
		return fmt.Errorf("update vrf_map: %w", err)
	}
	return nil
}

func (vm *vrfMap) List() (map[uint16]uint32, error) {
	out := map[uint16]uint32{}
	err := vm.m.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		out[uint16(*k.(*VrfID))] = uint32(*v.(*TableID))
	})
	if err != nil {
		return nil, fmt.Errorf("dump vrf_map: %w", err)
	}
	return out, nil
}

func (vm *vrfMap) Delete(vid uint16) error {
	key := VrfID(vid)
	if err := vm.m.Delete(&key); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return fmt.Errorf("delete from vrf_map: %w", err)
	}
	return nil
}

func NewVRFMap(lc cell.Lifecycle, reg *registry.MapRegistry) VRFMap {
	vm := &vrfMap{}
	lc.Append(cell.Hook{
		OnStart: func(cell.HookContext) (err error) {
			vm.m, err = bpf.NewMapFromRegistry(reg, maps.CiliumVRFMap, new(VrfID), new(TableID))
			if err != nil {
				return fmt.Errorf("create vrf map: %w", err)
			}
			return vm.m.OpenOrCreate()
		},
		OnStop: func(cell.HookContext) error { return vm.m.Close() },
	})
	return vm
}
