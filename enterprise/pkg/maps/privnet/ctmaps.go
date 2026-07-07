//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package privnet

import (
	"encoding"
	"fmt"
	"strconv"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/api/v1/models"
	privnetcfg "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/option"
)

// CTMapsKey is the key for the CT map of maps
type CTMapsKey struct {
	NetworkID uint32
}

func (k *CTMapsKey) New() bpf.MapKey {
	return &CTMapsKey{}
}

func (k *CTMapsKey) String() string {
	return "0x" + strconv.FormatUint(uint64(k.NetworkID), 16)
}

// CTMapsValue is the value for the CT map of maps
type CTMapsValue struct {
	// Fd is the file descriptor of the inner CT map
	Fd uint32
}

func (v *CTMapsValue) New() bpf.MapValue {
	return &CTMapsValue{}
}

func (v *CTMapsValue) String() string {
	return fmt.Sprintf("fd=%d", v.Fd)
}

var _ KeyValue = &CTMapsKeyVal{}

type CTMapsKeyVal struct {
	Key CTMapsKey
	Val CTMapsValue
}

func (c *CTMapsKeyVal) BinaryKey() encoding.BinaryMarshaler {
	return bpf.StructBinaryMarshaler{Target: &c.Key}
}

func (c *CTMapsKeyVal) BinaryValue() encoding.BinaryMarshaler {
	return bpf.StructBinaryMarshaler{Target: &c.Val}
}

func (c *CTMapsKeyVal) MapKey() bpf.MapKey {
	return &c.Key
}

func (c *CTMapsKeyVal) MapValue() bpf.MapValue {
	return &c.Val
}

var _ Map[*CTMapsKeyVal] = &ctMapsMap{}

type ctMapsMap struct {
	enabled bool
	*bpf.Map
}

func CTMapsMapName(mapCfg ctmap.MapConfig) string {
	switch {
	case mapCfg.IPv6 && mapCfg.TCP:
		return "cilium_privnet_ct6_global"
	case mapCfg.IPv6 && !mapCfg.TCP:
		return "cilium_privnet_ct_any6_global"
	case !mapCfg.IPv6 && mapCfg.TCP:
		return "cilium_privnet_ct4_global"
	case !mapCfg.IPv6 && !mapCfg.TCP:
		return "cilium_privnet_ct_any4_global"
	}
	panic("unreachable: unable to determine map name")
}

func newCTMap(mapCfg ctmap.MapConfig, maxEntries int, enabled bool) *ctMapsMap {
	innerSpec := ctmap.NewGlobalMapSpec(mapCfg)
	m := bpf.NewMapWithInnerSpec(
		CTMapsMapName(mapCfg),
		ebpf.HashOfMaps,
		&CTMapsKey{},
		&CTMapsValue{},
		maxEntries,
		0,
		innerSpec,
	)
	return &ctMapsMap{
		enabled: enabled,
		Map:     m,
	}
}

func (c *ctMapsMap) Ops() reconciler.Operations[*CTMapsKeyVal] {
	return bpf.NewMapOps[*CTMapsKeyVal](c.Map)
}

func (c *ctMapsMap) Enabled() bool {
	return c.enabled
}

func (c *ctMapsMap) Start(cell.HookContext) error {
	if !c.enabled {
		if err := c.Map.Unpin(); err != nil {
			return fmt.Errorf("failed to unpin private network map of CT maps: %w", err)
		}
		return nil
	}

	// Re-create the map every time we restart the agent. The reconciler populating it has
	// a regeneration fence ensuring the map is populated by the time endpoint regeneration
	// starts.
	// The inner maps, i.e. the actual CT maps, are not re-created on startup to avoid
	// loosing connection tracking information during restarts.
	if err := c.Map.Recreate(); err != nil {
		return fmt.Errorf("failed to create private network map of CT maps: %w", err)
	}

	return nil
}

func (c *ctMapsMap) Stop(cell.HookContext) error {
	if c.enabled {
		c.Map.Close()
	}

	return nil
}

type (
	CTMapsMapTCP4 Map[*CTMapsKeyVal]
	CTMapsMapAny4 Map[*CTMapsKeyVal]
	CTMapsMapTCP6 Map[*CTMapsKeyVal]
	CTMapsMapAny6 Map[*CTMapsKeyVal]
)

type CTMap interface {
	Name() string
	FD() int

	OpenOrCreate() error
	Close() error
	UnpinIfExists() error

	Update(bpf.MapKey, bpf.MapValue) error
	Delete(bpf.MapKey) error
	Flush(_, _ func(ctmap.GCEvent)) int

	DumpEntriesWithTimeDiff(*models.ClockSource) (string, error)

	bpf.IterableMap
}

type CTMapWithConfig struct {
	Config ctmap.MapConfig
	Map    CTMap
}

type CTMaps interface {
	ActiveMapsForNetwork(networkName string) []CTMapWithConfig
}

func newCTMaps(in struct {
	cell.In

	Config       privnetcfg.Config
	DaemonConfig *option.DaemonConfig
	MapConfig    Config

	Lifecycle cell.Lifecycle
}) (
	bpf.MapOut[CTMapsMapTCP4],
	bpf.MapOut[CTMapsMapAny4],
	bpf.MapOut[CTMapsMapTCP6],
	bpf.MapOut[CTMapsMapAny6],
	defines.NodeOut,
) {
	// Always create all the userspace map representations, this allows
	// them to be unpinned if a feature is disabled.
	maxEntries := int(in.MapConfig.CTMapsMapSize)
	ipv4Enabled := in.Config.Enabled && in.DaemonConfig.IPv4Enabled()
	ipv6Enabled := in.Config.Enabled && in.DaemonConfig.IPv6Enabled()

	tcp4 := newCTMap(ctmap.MapConfig{TCP: true, IPv6: false}, maxEntries, ipv4Enabled)
	any4 := newCTMap(ctmap.MapConfig{TCP: false, IPv6: false}, maxEntries, ipv4Enabled)
	tcp6 := newCTMap(ctmap.MapConfig{TCP: true, IPv6: true}, maxEntries, ipv6Enabled)
	any6 := newCTMap(ctmap.MapConfig{TCP: false, IPv6: true}, maxEntries, ipv6Enabled)

	in.Lifecycle.Append(tcp4)
	in.Lifecycle.Append(any4)
	in.Lifecycle.Append(tcp6)
	in.Lifecycle.Append(any6)

	return bpf.NewMapOut(CTMapsMapTCP4(tcp4)),
		bpf.NewMapOut(CTMapsMapAny4(any4)),
		bpf.NewMapOut(CTMapsMapTCP6(tcp6)),
		bpf.NewMapOut(CTMapsMapAny6(any6)),
		defines.NodeOut{
			NodeDefines: defines.Map{
				"PRIVNET_CT_MAPS_MAP_SIZE": strconv.FormatUint(uint64(maxEntries), 10),
			},
		}
}
