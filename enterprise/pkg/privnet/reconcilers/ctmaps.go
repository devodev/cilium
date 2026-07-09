//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package reconcilers

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/script"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"k8s.io/apimachinery/pkg/util/sets"

	pnmaps "github.com/cilium/cilium/enterprise/pkg/maps/privnet"
	privnetcfg "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	ctmapgc "github.com/cilium/cilium/pkg/maps/ctmap/gc"
	"github.com/cilium/cilium/pkg/maps/timestamp"
	cslices "github.com/cilium/cilium/pkg/slices"
)

type CTMapFactory func(name string, cfg ctmap.MapConfig, opts ...ctmap.MapOption) pnmaps.CTMap

// CTMapTCPathOverride allows to override the default map pins path for testing purposes.
type CTMapTCPathOverride string

var CTMapsCell = cell.Group(
	cell.ProvidePrivate(
		// Provides the ReadWrite ConnTrackMap table.
		tables.NewConnTrackMapTable,

		// Provides the main struct for the CT map of maps reconciler
		newCTMaps,

		// Provides the pnmaps.CTMap factory, so that it can be overwritten by tests.
		newDefaultCTMapFactory,
	),

	cell.Invoke(
		// Derives the ConnTrackMap table from the private networks table
		(*CTMaps).registerDerive,
		// Registers the BPF map reconciler that populates the CT map of maps
		(*CTMaps).registerReconciler,
	),
	cell.Provide(
		// Registers script commands to inspect both the inner and outer CT maps
		(*CTMaps).registerScriptCmds,
		// Registers all live CT maps with the periodic CT GC
		(*CTMaps).registerGC,
		// Provide access to the CT maps via interface
		(*CTMaps).registerGetter,
	),
)

// CTMaps hosts the infrastructure for managing the per-privnet CT maps.
// There is are up to four outer maps (TCP4, Any4, TCP6, Any6), allowing
// the datapath to obtain a CT map given a private network ID.
// This reconciler manages the lifecycle of these per-private network CT maps,
// which includes
//   - Creating the (inner) CT maps when a new private network is discovered,
//     and upserting them into the outer map of CT maps.
//   - Providing all active (inner) per-privnet CT maps to CT GC when requested.
//   - Deleting CT maps (and removing them from the outer map) when a private
//     network is deleted
type CTMaps struct {
	mu lock.Mutex

	log *slog.Logger

	factory CTMapFactory
	tcPath  string
	ctMaps  map[tables.NetworkID]*ctMap
	global  ctmap.CTMaps

	tcp4    pnmaps.CTMapsMapTCP4
	tcp4Ops reconciler.Operations[*pnmaps.CTMapsKeyVal]

	any4    pnmaps.CTMapsMapAny4
	any4Ops reconciler.Operations[*pnmaps.CTMapsKeyVal]

	tcp6    pnmaps.CTMapsMapTCP6
	tcp6Ops reconciler.Operations[*pnmaps.CTMapsKeyVal]

	any6    pnmaps.CTMapsMapAny6
	any6Ops reconciler.Operations[*pnmaps.CTMapsKeyVal]
}

func newCTMaps(in struct {
	cell.In

	Log       *slog.Logger
	Lifecycle cell.Lifecycle

	Global  ctmap.CTMaps
	Factory CTMapFactory
	TCPath  CTMapTCPathOverride `optional:"true"`

	TCP4 pnmaps.CTMapsMapTCP4
	Any4 pnmaps.CTMapsMapAny4
	TCP6 pnmaps.CTMapsMapTCP6
	Any6 pnmaps.CTMapsMapAny6
}) *CTMaps {
	var maps = &CTMaps{
		log: in.Log,

		factory: in.Factory,
		tcPath:  cmp.Or(string(in.TCPath), bpf.TCGlobalsPath()),
		ctMaps:  make(map[tables.NetworkID]*ctMap),

		tcp4:    in.TCP4,
		tcp4Ops: in.TCP4.Ops(),
		any4:    in.Any4,
		any4Ops: in.Any4.Ops(),
		tcp6:    in.TCP6,
		tcp6Ops: in.TCP6.Ops(),
		any6:    in.Any6,
		any6Ops: in.Any6.Ops(),
	}

	in.Lifecycle.Append(
		cell.Hook{
			OnStop: func(cell.HookContext) error {
				maps.mu.Lock()
				defer maps.mu.Unlock()

				for _, m := range maps.ctMaps {
					for _, ctm := range m.all() {
						_ = ctm.Close()
					}
				}

				maps.ctMaps = nil
				return nil
			},
		},
	)

	return maps
}

func (c *CTMaps) registerDerive(in struct {
	cell.In

	Config       privnetcfg.Config
	DeriveParams statedb.DeriveParams[tables.PrivateNetwork, tables.ConnTrackMap]
}) {
	if !in.Config.Enabled {
		return
	}

	statedb.Derive("derive-ct-maps-table",
		func(obj tables.PrivateNetwork, deleted bool) (tables.ConnTrackMap, statedb.DeriveResult) {
			if deleted {
				return tables.ConnTrackMap{
					Network:   obj.Name,
					NetworkID: obj.ID,
				}, statedb.DeriveDelete
			}
			return tables.ConnTrackMap{
				Network:   obj.Name,
				NetworkID: obj.ID,
				Status:    reconciler.StatusPending(),
			}, statedb.DeriveInsert
		},
	)(in.DeriveParams)
}

func (c *CTMaps) registerReconciler(in struct {
	cell.In

	Config privnetcfg.Config

	TCP4 pnmaps.CTMapsMapTCP4
	Any4 pnmaps.CTMapsMapAny4
	TCP6 pnmaps.CTMapsMapTCP6
	Any6 pnmaps.CTMapsMapAny6

	DB    *statedb.DB
	Fence regeneration.Fence

	ConnTrackMap     statedb.RWTable[tables.ConnTrackMap]
	ReconcilerParams reconciler.Params
}) error {
	if !in.Config.Enabled {
		return nil
	}

	in.Fence.Add(
		"private-network-ct-maps-map",
		NewWaitUntilReconciledFn(in.DB, in.ConnTrackMap,
			func(c tables.ConnTrackMap) reconciler.Status { return c.Status }),
	)

	_, err := reconciler.Register(
		// params
		in.ReconcilerParams,
		// table
		in.ConnTrackMap,
		// clone
		func(c tables.ConnTrackMap) tables.ConnTrackMap {
			// We can do a shallow clone for the reconciler.
			return c
		},
		// setStatus
		func(c tables.ConnTrackMap, status reconciler.Status) tables.ConnTrackMap {
			c.Status = status
			return c
		},
		// getStatus
		func(c tables.ConnTrackMap) reconciler.Status {
			return c.Status
		},
		// ops
		c,
		// batchOps
		nil,

		reconciler.WithName("ct-maps"),
	)
	return err
}

func (c *CTMaps) registerGC(cfg privnetcfg.Config) ctmapgc.AdditionalCTMapsOut {
	if !cfg.Enabled {
		return ctmapgc.AdditionalCTMapsOut{}
	}

	return ctmapgc.AdditionalCTMapsOut{
		AdditionalCTMaps: c.listCTMapPairs,
	}
}

func (c *CTMaps) registerScriptCmds(cfg privnetcfg.Config) hive.ScriptCmdsOut {
	if !cfg.Enabled {
		return hive.ScriptCmdsOut{}
	}

	return hive.NewScriptCmds(
		map[string]script.Cmd{
			"privnet/ct-maps":       showOuterMapCmd(c),
			"privnet/ct-maps/list":  listInnerMapsCmd(c),
			"privnet/ct-maps/show":  showInnerMapCmd(c),
			"privnet/ct-maps/flush": flushInnerMapCmd(c),
		},
	)
}

func (c *CTMaps) registerGetter() pnmaps.CTMaps {
	return c
}

const (
	mapPrefix = "cilium_privnet"

	mapSuffixTCP4 = "_ct4_global"
	mapSuffixAny4 = "_ct_any4_global"
	mapSuffixTCP6 = "_ct6_global"
	mapSuffixAny6 = "_ct_any6_global"
)

func mapName(cfg ctmap.MapConfig, networkID tables.NetworkID) string {
	switch {
	case cfg.IPv6 && cfg.TCP:
		return fmt.Sprintf("%s_%05d%s", mapPrefix, networkID, mapSuffixTCP6)
	case cfg.IPv6 && !cfg.TCP:
		return fmt.Sprintf("%s_%05d%s", mapPrefix, networkID, mapSuffixAny6)
	case !cfg.IPv6 && cfg.TCP:
		return fmt.Sprintf("%s_%05d%s", mapPrefix, networkID, mapSuffixTCP4)
	case !cfg.IPv6 && !cfg.TCP:
		return fmt.Sprintf("%s_%05d%s", mapPrefix, networkID, mapSuffixAny4)
	default:
		panic("unreachable: invalid map config")
	}
}

func newDefaultCTMapFactory() CTMapFactory {
	return func(name string, cfg ctmap.MapConfig, opts ...ctmap.MapOption) pnmaps.CTMap {
		return ctmap.NewGlobalMap(name, cfg, opts...)
	}
}

type ctMap struct {
	network string

	tcp4 pnmaps.CTMap
	any4 pnmaps.CTMap
	tcp6 pnmaps.CTMap
	any6 pnmaps.CTMap
}

func (m *ctMap) all() []pnmaps.CTMap {
	return slices.DeleteFunc(
		[]pnmaps.CTMap{m.tcp4, m.tcp6, m.any4, m.any6},
		func(ctm pnmaps.CTMap) bool { return ctm == nil },
	)
}

// createCTMap creates the CT maps for a given network. We create these maps as soon as the network
// is created, to ensure the map exists when an endpoint using it is created.
func (c *CTMaps) createCTMap(networkName string, networkID tables.NetworkID) (*ctMap, error) {
	m := &ctMap{
		network: networkName,
	}

	openOrCreate := func(cfg ctmap.MapConfig) (pnmaps.CTMap, error) {
		ctm := c.factory(mapName(cfg, networkID), cfg, ctmap.WithNetworkID(uint32(networkID)))
		return ctm, ctm.OpenOrCreate()
	}

	var err error
	defer func() {
		if err == nil {
			return
		}

		// Unpin and close all previously opened maps, in case of errors. We
		// ignore all errors as best effort, and to not shadow the actual failure.
		for _, ctm := range m.all() {
			_ = ctm.UnpinIfExists()
			_ = ctm.Close()
		}
	}()

	if c.tcp4.Enabled() {
		m.tcp4, err = openOrCreate(ctmap.MapConfig{TCP: true, IPv6: false})
		if err != nil {
			return nil, fmt.Errorf("error creating tcp4 CT map: %w", err)
		}
	}
	if c.any4.Enabled() {
		m.any4, err = openOrCreate(ctmap.MapConfig{TCP: false, IPv6: false})
		if err != nil {
			return nil, fmt.Errorf("error creating any4 CT map: %w", err)
		}
	}
	if c.tcp6.Enabled() {
		m.tcp6, err = openOrCreate(ctmap.MapConfig{TCP: true, IPv6: true})
		if err != nil {
			return nil, fmt.Errorf("error creating tcp6 CT map: %w", err)
		}
	}
	if c.any6.Enabled() {
		m.any6, err = openOrCreate(ctmap.MapConfig{TCP: false, IPv6: true})
		if err != nil {
			return nil, fmt.Errorf("error creating any6 CT map: %w", err)
		}
	}

	return m, nil
}

func (c *CTMaps) upsertCTMapLocked(networkName tables.NetworkName, networkID tables.NetworkID) (*ctMap, error) {
	m, ok := c.ctMaps[networkID]
	if ok {
		return m, nil
	}

	var err error
	m, err = c.createCTMap(string(networkName), networkID)
	if err != nil {
		return nil, err
	}
	c.ctMaps[networkID] = m

	return m, nil
}

func (c *CTMaps) deleteCTMapLocked(networkID tables.NetworkID) error {
	m, ok := c.ctMaps[networkID]
	if !ok {
		return nil
	}

	unpinIfExistsAndEnabled := func(m pnmaps.CTMap) error {
		if m == nil {
			return nil
		}

		_ = m.Close()
		return m.UnpinIfExists()
	}

	delete(c.ctMaps, networkID)
	return errors.Join(
		unpinIfExistsAndEnabled(m.tcp4),
		unpinIfExistsAndEnabled(m.any4),
		unpinIfExistsAndEnabled(m.tcp6),
		unpinIfExistsAndEnabled(m.any6),
	)
}

func ctKeyVal(networkID tables.NetworkID, m pnmaps.CTMap) *pnmaps.CTMapsKeyVal {
	return &pnmaps.CTMapsKeyVal{
		Key: pnmaps.CTMapsKey{NetworkID: uint32(networkID)},
		Val: pnmaps.CTMapsValue{Fd: uint32(m.FD())},
	}
}

// ActiveMapsGlobal implements pnmaps.CTMaps
func (c *CTMaps) ActiveMapsGlobal() []pnmaps.CTMap {
	return cslices.Map(c.global.ActiveMaps(), func(m *ctmap.Map) pnmaps.CTMap { return m })
}

// ActiveMapsForNetwork implements pnmaps.CTMaps
func (c *CTMaps) ActiveMapsForNetwork(networkName string) []pnmaps.CTMapWithConfig {
	c.mu.Lock()
	defer c.mu.Unlock()

	var ctMap *ctMap
	for _, m := range c.ctMaps {
		if m.network == networkName {
			ctMap = m
			break
		}
	}

	if ctMap == nil {
		return nil
	}

	var activeMaps []pnmaps.CTMapWithConfig
	if ctMap.tcp4 != nil {
		activeMaps = append(activeMaps, pnmaps.CTMapWithConfig{
			Config: ctmap.MapConfig{TCP: true, IPv6: false},
			Map:    ctMap.tcp4,
		})
	}
	if ctMap.any4 != nil {
		activeMaps = append(activeMaps, pnmaps.CTMapWithConfig{
			Config: ctmap.MapConfig{TCP: false, IPv6: false},
			Map:    ctMap.any4,
		})
	}
	if ctMap.tcp6 != nil {
		activeMaps = append(activeMaps, pnmaps.CTMapWithConfig{
			Config: ctmap.MapConfig{TCP: true, IPv6: true},
			Map:    ctMap.tcp6,
		})
	}
	if ctMap.any6 != nil {
		activeMaps = append(activeMaps, pnmaps.CTMapWithConfig{
			Config: ctmap.MapConfig{TCP: false, IPv6: true},
			Map:    ctMap.any6,
		})
	}
	return activeMaps
}

// Update ensures the inner CT maps for the private network represented by obj are created, and upserted into the
// outer maps.
func (c *CTMaps) Update(ctx context.Context, txn statedb.ReadTxn, revision statedb.Revision, obj tables.ConnTrackMap) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	m, err := c.upsertCTMapLocked(obj.Network, obj.NetworkID)
	if err != nil {
		return fmt.Errorf("failed to create private network CT map: %w", err)
	}

	updateEntry := func(
		name string,
		outerMap pnmaps.Map[*pnmaps.CTMapsKeyVal],
		innerMap pnmaps.CTMap,
		ops reconciler.Operations[*pnmaps.CTMapsKeyVal],
	) error {
		if !outerMap.Enabled() {
			return nil
		}

		err := ops.Update(ctx, txn, revision, ctKeyVal(obj.NetworkID, innerMap))
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}

		return nil
	}

	err = errors.Join(
		updateEntry("tcp4", c.tcp4, m.tcp4, c.tcp4Ops),
		updateEntry("any4", c.any4, m.any4, c.any4Ops),
		updateEntry("tcp6", c.tcp6, m.tcp6, c.tcp6Ops),
		updateEntry("any6", c.any6, m.any6, c.any6Ops),
	)
	return err
}

// Delete ensures the CT maps for a private network are removed from the outer maps, and deletes the inner CT maps
// when no longer referenced.
func (c *CTMaps) Delete(ctx context.Context, txn statedb.ReadTxn, revision statedb.Revision, obj tables.ConnTrackMap) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	m, ok := c.ctMaps[obj.NetworkID]
	if !ok {
		return nil
	}

	deleteEntry := func(
		name string,
		outerMap pnmaps.Map[*pnmaps.CTMapsKeyVal],
		innerMap pnmaps.CTMap,
		ops reconciler.Operations[*pnmaps.CTMapsKeyVal],
	) error {
		if !outerMap.Enabled() {
			return nil
		}

		err := ops.Delete(ctx, txn, revision, ctKeyVal(obj.NetworkID, innerMap))
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}

		return nil
	}

	err := errors.Join(
		deleteEntry("tcp4", c.tcp4, m.tcp4, c.tcp4Ops),
		deleteEntry("any4", c.any4, m.any4, c.any4Ops),
		deleteEntry("tcp6", c.tcp6, m.tcp6, c.tcp6Ops),
		deleteEntry("any6", c.any6, m.any6, c.any6Ops),
	)

	// only delete CT map if all entries actually have been successfully removed
	if err == nil {
		err = c.deleteCTMapLocked(obj.NetworkID)
	}
	return err
}

// Prune removes all CT maps no longer alive
func (c *CTMaps) Prune(context.Context, statedb.ReadTxn, iter.Seq2[tables.ConnTrackMap, statedb.Revision]) error {
	// Collect the name of all expected maps.
	c.mu.Lock()

	var expected = sets.New[string]()
	for _, m := range c.ctMaps {
		for _, ctm := range m.all() {
			expected.Insert(ctm.Name())
		}
	}

	c.mu.Unlock()

	pins, err := os.ReadDir(c.tcPath)
	if err != nil {
		return fmt.Errorf("listing pinned BPF maps: %w", err)
	}

	var matcher = regexp.MustCompile(
		fmt.Sprintf("^%s_[0-9]{5}(%s|%s|%s|%s)$", mapPrefix,
			mapSuffixTCP4, mapSuffixTCP6, mapSuffixAny4, mapSuffixAny6,
		),
	)

	// Iterate over all pinned maps, and delete any that match the name format,
	// but are not expected to exist.
	for _, entry := range pins {
		if !entry.IsDir() && !expected.Has(entry.Name()) && matcher.MatchString(entry.Name()) {
			err2 := os.Remove(filepath.Join(c.tcPath, entry.Name()))
			if err2 != nil && !os.IsNotExist(err2) {
				err = errors.Join(err, fmt.Errorf("unpinning %s map: %w", entry.Name(), err2))
			} else if err2 == nil {
				c.log.Info("Pruned stale CT map", logfields.Name, entry.Name())
			}
		}
	}

	return err
}

// listCTMapPairs is invoked by CT GC to obtain all active CT maps
func (c *CTMaps) listCTMapPairs() []ctmap.MapPair {
	c.mu.Lock()
	defer c.mu.Unlock()

	var result []ctmap.MapPair
	for _, m := range c.ctMaps {
		if c.tcp4.Enabled() && c.any4.Enabled() {
			result = append(result, ctmap.MapPair{
				TCP:    m.tcp4.(*ctmap.Map),
				Any:    m.any4.(*ctmap.Map),
				IsOpen: true,
			})
		}
		if c.tcp6.Enabled() && c.any6.Enabled() {
			result = append(result, ctmap.MapPair{
				TCP:    m.tcp6.(*ctmap.Map),
				Any:    m.any6.(*ctmap.Map),
				IsOpen: true,
			})
		}
	}

	return result
}

// sortedCTMaps returns all inner CT maps sorted by network name
func (c *CTMaps) sortedCTMaps() []*ctMap {
	c.mu.Lock()
	defer c.mu.Unlock()
	ctMaps := slices.SortedFunc(maps.Values(c.ctMaps), func(a *ctMap, b *ctMap) int {
		return cmp.Compare(a.network, b.network)
	})
	return ctMaps
}

// getMap returns an inner CT map by network name and map type ("tcp4", "any4", "tcp6", or "any6).
func (c *CTMaps) getMap(network string, mapType string) (pnmaps.CTMap, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var ct *ctMap
	for _, m := range c.ctMaps {
		if m.network == network {
			ct = m
			break
		}
	}
	if ct == nil {
		return nil, fmt.Errorf("unknown network %q", network)
	}

	var m pnmaps.CTMap
	switch mapType {
	case "tcp4":
		m = ct.tcp4
	case "any4":
		m = ct.any4
	case "tcp6":
		m = ct.tcp6
	case "any6":
		m = ct.any6
	}
	if m == nil {
		return nil, fmt.Errorf("no map found for type %q", mapType)
	}
	return m, nil
}

// showOuterMapCmd dumps an outer map of CT maps
func showOuterMapCmd(c *CTMaps) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Show a map of CT BPF maps",
			Args:    "tcp4|any4|tcp6|any6",
			Detail: []string{
				"Shows the contents of a BPF map of CT maps.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) < 1 {
				return nil, fmt.Errorf("%w: expected map type argument", script.ErrUsage)
			}

			var m pnmaps.Map[*pnmaps.CTMapsKeyVal]
			switch mapType := args[0]; mapType {
			case "tcp4":
				m = c.tcp4
			case "any4":
				m = c.any4
			case "tcp6":
				m = c.tcp6
			case "any6":
				m = c.any6
			default:
				return nil, fmt.Errorf("%w: unknown map type %q", script.ErrUsage, mapType)
			}

			type dumper interface {
				DumpWithCallback(bpf.DumpCallback) error
			}

			return func(*script.State) (stdout, stderr string, err error) {
				d, ok := m.(dumper)
				if !ok {
					return stdout, stderr, fmt.Errorf("map of type %T cannot be dumped", m)
				}
				var sb strings.Builder
				w := tabwriter.NewWriter(&sb, 5, 0, 3, ' ', 0)
				fmt.Fprintln(w, "NetworkID\tCTMap")
				err = d.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
					fmt.Fprintf(w, "%s\t%s\n", k.String(), v.String())
				})
				w.Flush()
				return sb.String(), stderr, err
			}, nil
		},
	)
}

// listInnerMapsCmd lists all inner CT maps
func listInnerMapsCmd(c *CTMaps) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "List CT BPF maps",
			Detail: []string{
				"Lists all private network related connection tracking BPF maps.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			return func(*script.State) (stdout, stderr string, err error) {
				ctMaps := c.sortedCTMaps()

				var sb strings.Builder
				w := tabwriter.NewWriter(&sb, 5, 0, 3, ' ', 0)
				fmt.Fprintln(w, "Network\tType\tBPFMap")
				for _, ct := range ctMaps {
					if c.tcp4.Enabled() {
						fmt.Fprintf(w, "%s\t%s\t%s\n", ct.network, "tcp4", ct.tcp4.Name())
					}
					if c.any4.Enabled() {
						fmt.Fprintf(w, "%s\t%s\t%s\n", ct.network, "any4", ct.any4.Name())
					}
					if c.tcp6.Enabled() {
						fmt.Fprintf(w, "%s\t%s\t%s\n", ct.network, "tcp6", ct.tcp6.Name())
					}
					if c.any6.Enabled() {
						fmt.Fprintf(w, "%s\t%s\t%s\n", ct.network, "any6", ct.any6.Name())
					}
				}
				w.Flush()
				return sb.String(), stderr, err
			}, nil
		},
	)
}

// showInnerMapCmd dumps a specific inner CT map
func showInnerMapCmd(c *CTMaps) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Show a specific CT BPF",
			Args:    "<network-name> tcp4|any4|tcp6|any6",
			Detail: []string{
				"Shows the contents of a specific private network related connection tracking BPF map.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) < 1 {
				return nil, fmt.Errorf("%w: expected network name argument", script.ErrUsage)
			} else if len(args) < 2 {
				return nil, fmt.Errorf("%w: expected map type argument", script.ErrUsage)
			}

			return func(*script.State) (stdout, stderr string, err error) {
				m, err := c.getMap(args[0], args[1])
				if err != nil {
					return stdout, stderr, err
				}

				stdout, err = m.DumpEntriesWithTimeDiff(timestamp.GetClockSourceFromOptions())
				return stdout, stderr, err
			}, nil
		},
	)
}

// showInnerMapCmd flushes (i.e. clears) a specific inner CT map
func flushInnerMapCmd(c *CTMaps) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Flush a specific CT BPF",
			Args:    "<network-name> tcp4|any4|tcp6|any6",
			Detail: []string{
				"Flushes the contents of a specific private network related connection tracking BPF map.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) < 1 {
				return nil, fmt.Errorf("%w: expected network name argument", script.ErrUsage)
			} else if len(args) < 2 {
				return nil, fmt.Errorf("%w: expected map type argument", script.ErrUsage)
			}

			return func(*script.State) (stdout, stderr string, err error) {
				m, err := c.getMap(args[0], args[1])
				if err != nil {
					return stdout, stderr, err
				}

				noop := func(event ctmap.GCEvent) {}
				entries := m.Flush(noop, noop)
				return fmt.Sprintf("Flushed %d entries\n", entries), stderr, nil
			}, nil
		},
	)
}
