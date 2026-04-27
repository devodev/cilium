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
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb/reconciler"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
)

var Cell = cell.Module(
	"private-networks-maps",
	"Private Networks eBPF Maps",

	cell.Config(defaultConfig),

	cell.Provide(
		newPIP,
		newFIB,
		newDevices,
		newSubnets,
		newWatchdog,
		newCTMaps,
		createCIDRIdentityMap,
		newARPSender,
		Config.nodeDefs,
	),
)

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Uint32("bpf-privnet-pip-fib-map-max", def.MapSize, "Maximum number of entries in the private network PIP and FIB BPF maps.")
	flags.Uint32("bpf-privnet-devices-map-max", def.DevicesMapSize, "Maximum number of entries in the private network devices BPF map.")
	flags.Uint32("bpf-privnet-subnets-map-max", def.SubnetsMapSize, "Maximum number of entries in the private network subnets BPF map.")
	flags.Uint32("bpf-privnet-cidr-identity-map-max", def.CIDRIdentityMapSize, "Maximum number of entries in the private network CIDR identity map.")
	flags.Uint32("bpf-privnet-ct-maps-map-max", def.CTMapsMapSize, "Maximum number of entries in the private network BPF map of CT maps.")
	flags.Uint32("bpf-privnet-arp-sender-map-max", def.ARPMapSize, "Maximum number of entries in the private network ARP sender map.")
}

type Config struct {
	// MapSize is the maximum number of entries in the private network PIP and FIB BPF maps.
	MapSize uint32 `mapstructure:"bpf-privnet-pip-fib-map-max"`

	DevicesMapSize      uint32 `mapstructure:"bpf-privnet-devices-map-max"`
	SubnetsMapSize      uint32 `mapstructure:"bpf-privnet-subnets-map-max"`
	CIDRIdentityMapSize uint32 `mapstructure:"bpf-privnet-cidr-identity-map-max"`

	// CTMapsMapSize is the size of the map of CT maps
	CTMapsMapSize uint32 `mapstructure:"bpf-privnet-ct-maps-map-max"`

	ARPMapSize uint32 `mapstructure:"bpf-privnet-arp-sender-map-max"`
}

var defaultConfig = Config{
	// The default value matches the size of the ipcache.
	MapSize: 512000,
	// Assuming 20% of IPCache is CIDR identities
	CIDRIdentityMapSize: 128000,
	DevicesMapSize:      16384,
	SubnetsMapSize:      16384,
	CTMapsMapSize:       512,
	ARPMapSize:          16384,
}

func (c Config) nodeDefs() defines.NodeOut {
	return defines.NodeOut{
		NodeDefines: map[string]string{
			"PRIVNET_PIP_FIB_MAP_SIZE":       fmt.Sprint(c.MapSize),
			"PRIVNET_DEVICES_MAP_SIZE":       fmt.Sprint(c.DevicesMapSize),
			"PRIVNET_SUBNETS_MAP_SIZE":       fmt.Sprint(c.SubnetsMapSize),
			"PRIVNET_CIDR_IDENTITY_MAP_SIZE": fmt.Sprint(c.CIDRIdentityMapSize),
			"PRIVNET_ARP_SENDER_MAP_SIZE":    fmt.Sprint(c.ARPMapSize),
		},
	}
}

// Map defines an interface implemented by our map types.
//
// This allows script tests to mock the maps provided by this cell
// without having to rely on real BPF maps.
//
// The first three methods are required by RegisterTablePressureMetricsJob,
// the Ops() method is to be used when registering a BPF map reconciler.
type Map[T any] interface {
	IsOpen() bool
	NonPrefixedName() string
	MaxEntries() uint32

	Ops() reconciler.Operations[T]

	Enabled() bool
}

type KeyValue interface {
	bpf.KeyValue
	MapKey() bpf.MapKey
	MapValue() bpf.MapValue
}
