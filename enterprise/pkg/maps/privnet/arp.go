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
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb/reconciler"
	"golang.org/x/sys/unix"

	privnetcfg "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/types"
)

const ARPSenderMapName = "cilium_privnet_arp_sender_cache"

// ARPSenderKey is the privnet_arp_sender_cache map key.
type ARPSenderKey struct {
	NetworkID tables.NetworkID `align:"net_id"`
	SubnetID  tables.SubnetID  `align:"subnet_id"`
}

// ARPSenderVal is the privnet_arp_sender_cache map value.
type ARPSenderVal struct {
	IPv4 types.IPv4 `align:"ipv4"`
}

// ARPSenderMap allows interaction with the privnet_arp_sender_cache map.
type ARPSenderMap struct {
	enabled bool
	*bpf.Map
}

func newARPSender(
	lc cell.Lifecycle,
	cfg privnetcfg.Config,
	mapCfg Config,
) bpf.MapOut[Map[*ARPSenderKeyVal]] {
	arpMap := bpf.NewMap(
		ARPSenderMapName,
		ebpf.Hash,
		&ARPSenderKey{},
		&ARPSenderVal{},
		int(mapCfg.ARPMapSize),
		unix.BPF_F_NO_PREALLOC|unix.BPF_F_RDONLY_PROG,
	)

	lc.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			if !cfg.IsLocallyConnected() {
				if err := arpMap.Unpin(); err != nil {
					return fmt.Errorf("unpinning privnet_arp_sender_cache map: %w", err)
				}
				return nil
			}

			if err := arpMap.Recreate(); err != nil {
				return fmt.Errorf("recreating privnet_arp_sender_cache map: %w", err)
			}
			return nil
		},
		OnStop: func(_ cell.HookContext) error {
			if !cfg.IsLocallyConnected() {
				return nil
			}

			if err := arpMap.Close(); err != nil {
				return fmt.Errorf("closing privnet_arp_sender_cache map: %w", err)
			}
			return nil
		},
	})

	return bpf.NewMapOut(Map[*ARPSenderKeyVal](ARPSenderMap{enabled: cfg.Enabled, Map: arpMap}))
}

// Ops implements Map[*ARPSenderKeyVal]
func (a ARPSenderMap) Ops() reconciler.Operations[*ARPSenderKeyVal] {
	return bpf.NewMapOps[*ARPSenderKeyVal](a.Map)
}

// Enabled implements Map[*ARPSenderKeyVal]
func (a ARPSenderMap) Enabled() bool {
	return a.enabled
}

// NewARPSenderKey constructs a new privnet_arp_sender_cache map key.
func NewARPSenderKey(netID tables.NetworkID, subnetID tables.SubnetID) ARPSenderKey {
	return ARPSenderKey{
		NetworkID: netID,
		SubnetID:  subnetID,
	}
}

func (k ARPSenderKey) String() string {
	return fmt.Sprintf("%s/%s", k.NetworkID, k.SubnetID)
}

func (*ARPSenderKey) New() bpf.MapKey {
	return &ARPSenderKey{}
}

// NewARPSenderVal constructs a new privnet_arp_sender_cache map value.
func NewARPSenderVal(ipv4 netip.Addr) ARPSenderVal {
	val := ARPSenderVal{}
	val.IPv4.FromAddr(ipv4)
	return val
}

func (v ARPSenderVal) String() string {
	return v.IPv4.String()
}

func (ARPSenderVal) New() bpf.MapValue {
	return &ARPSenderVal{}
}

var _ KeyValue = &ARPSenderKeyVal{}

type ARPSenderKeyVal struct {
	Key ARPSenderKey
	Val ARPSenderVal
}

// BinaryKey implements bpf.KeyValue.
func (a *ARPSenderKeyVal) BinaryKey() encoding.BinaryMarshaler {
	return bpf.StructBinaryMarshaler{Target: &a.Key}
}

// BinaryValue implements bpf.KeyValue.
func (a *ARPSenderKeyVal) BinaryValue() encoding.BinaryMarshaler {
	return bpf.StructBinaryMarshaler{Target: &a.Val}
}

// MapKey implements KeyValue
func (a *ARPSenderKeyVal) MapKey() bpf.MapKey {
	return &a.Key
}

// MapValue implements KeyValue
func (a *ARPSenderKeyVal) MapValue() bpf.MapValue {
	return &a.Val
}
