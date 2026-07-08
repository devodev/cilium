// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package tests

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/script"
	"github.com/spf13/pflag"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/api/v1/models"
	pnmaps "github.com/cilium/cilium/enterprise/pkg/maps/privnet"
	"github.com/cilium/cilium/enterprise/pkg/privnet/reconcilers"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/u8proto"
)

func mockCTMaps(t testing.TB) cell.Cell {
	t.Helper()

	return cell.Group(
		cell.ProvidePrivate(newFakeCTMaps),
		cell.Provide(
			func(f *fakeCTMaps) ctmap.CTMaps { return f },
			func(f *fakeCTMaps) hive.ScriptCmdsOut {
				return hive.NewScriptCmds(
					map[string]script.Cmd{
						"privnet/mock-global-ct-maps/show":   f.showMap(),
						"privnet/mock-global-ct-maps/upsert": f.upsertTuple(),
						"privnet/mock-global-ct-maps/delete": f.deleteTuple(),
					},
				)
			},
		),

		cell.ProvidePrivate(newCTMapsRegistry),
		cell.DecorateAll((*ctMapsRegistry).factory),
		cell.Provide((*ctMapsRegistry).commands),
	)
}

type ctMapsRegistry struct {
	mu lock.RWMutex

	registry map[string]*ctMap
	nextFD   int
}

func newCTMapsRegistry() *ctMapsRegistry {
	var registry = ctMapsRegistry{
		registry: make(map[string]*ctMap),
		nextFD:   1,
	}

	registry.new(ctmap.MapNameTCP4Global, ctmap.MapConfig{TCP: true, IPv6: false})
	registry.new(ctmap.MapNameAny4Global, ctmap.MapConfig{TCP: false, IPv6: false})
	registry.new(ctmap.MapNameTCP6Global, ctmap.MapConfig{TCP: true, IPv6: true})
	registry.new(ctmap.MapNameAny6Global, ctmap.MapConfig{TCP: false, IPv6: true})

	return &registry
}

func (r *ctMapsRegistry) new(name string, cfg ctmap.MapConfig, _ ...ctmap.MapOption) pnmaps.CTMap {
	r.mu.Lock()
	defer r.mu.Unlock()

	ctm, ok := r.registry[name]
	if !ok {
		ctm = &ctMap{
			name: name,
			cfg:  cfg,
			fd:   r.nextFD,
		}

		r.registry[name] = ctm
		r.nextFD++
	}

	if ctm.cfg != cfg {
		panic(fmt.Sprintf("Mismatching configuration for map %s", name))
	}

	return ctm
}

func (r *ctMapsRegistry) factory() reconcilers.CTMapFactory { return r.new }

func (r *ctMapsRegistry) commands() hive.ScriptCmdsOut {
	return hive.NewScriptCmds(
		map[string]script.Cmd{
			"privnet/ct-maps-registry/list": r.dump(),
		},
	)
}

func (r *ctMapsRegistry) dump() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "List the maps contained in the registry",
			Flags: func(fs *pflag.FlagSet) {
				fs.StringP("out", "o", "", "File to write to instead of stdout")
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			outfile, err := s.Flags.GetString("out")
			if err != nil {
				return nil, fmt.Errorf("reading out flag: %w", err)
			}

			return func(*script.State) (stdout, stderr string, err error) {
				r.mu.RLock()
				defer r.mu.RUnlock()

				var b strings.Builder
				for _, name := range slices.Sorted(maps.Keys(r.registry)) {
					var (
						ctm   = r.registry[name]
						flags = ctm.flags()
					)

					if len(flags) == 0 {
						// Closed and unpinned, hence skip.
						continue
					}

					fmt.Fprintf(&b, "%-36s (%#02x) - IPv4: %-5t, TCP: %-5t - %s\n",
						ctm.name, ctm.fd, !ctm.cfg.IPv6, ctm.cfg.TCP, strings.Join(flags, ","))
				}

				if outfile != "" {
					return "", "", os.WriteFile(s.Path(outfile), []byte(b.String()), 0644)
				}

				return b.String(), "", nil
			}, nil
		},
	)
}

type fakeCTMaps struct {
	maps map[string]*ctmap.Map
}

func newFakeCTMaps() (*fakeCTMaps, error) {
	if !testutils.IsPrivileged() {
		return &fakeCTMaps{
			maps: nil,
		}, nil
	}

	f := &fakeCTMaps{
		maps: map[string]*ctmap.Map{
			ctmap.MapNameAny4Global: ctmap.NewGlobalMap(ctmap.MapNameAny4Global, ctmap.MapConfig{TCP: false, IPv6: false}),
			ctmap.MapNameTCP4Global: ctmap.NewGlobalMap(ctmap.MapNameTCP4Global, ctmap.MapConfig{TCP: true, IPv6: false}),
			ctmap.MapNameAny6Global: ctmap.NewGlobalMap(ctmap.MapNameAny6Global, ctmap.MapConfig{TCP: false, IPv6: true}),
			ctmap.MapNameTCP6Global: ctmap.NewGlobalMap(ctmap.MapNameTCP6Global, ctmap.MapConfig{TCP: true, IPv6: true}),
		},
	}

	// Create temporary unpinned maps
	for name, m := range f.maps {
		if err := m.CreateUnpinned(); err != nil {
			return nil, fmt.Errorf("creating unpinned map %q: %w", name, err)
		}
	}

	return f, nil
}

func (f *fakeCTMaps) ActiveMaps() []*ctmap.Map {
	return slices.Collect(maps.Values(f.maps))
}

const (
	mapTypeAny4 = "any4"
	mapTypeAny6 = "any6"
	mapTypeTCP4 = "tcp4"
	mapTypeTCP6 = "tcp6"
)

func (f *fakeCTMaps) getMap(mapType string) (*ctmap.Map, error) {
	var m *ctmap.Map
	switch mapType {
	case mapTypeTCP4:
		m = f.maps[ctmap.MapNameTCP4Global]
	case mapTypeAny4:
		m = f.maps[ctmap.MapNameAny4Global]
	case mapTypeTCP6:
		m = f.maps[ctmap.MapNameTCP6Global]
	case mapTypeAny6:
		m = f.maps[ctmap.MapNameAny6Global]
	default:
		return nil, fmt.Errorf("%w: unknown map type %q", script.ErrUsage, mapType)
	}
	if m == nil {
		return nil, errors.New("map is unavailable - check if you are running tests in privileged mode")
	}

	return m, nil
}

func (f *fakeCTMaps) showMap() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Show global CT BPF maps",
			Args:    "tcp4|any4|tcp6|any6",
			Detail: []string{
				"Shows the contents of a global CT map.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) < 1 {
				return nil, fmt.Errorf("%w: expected map type argument", script.ErrUsage)
			}

			m, err := f.getMap(args[0])
			if err != nil {
				return nil, err
			}

			return func(*script.State) (stdout, stderr string, err error) {
				dump, err := ctmap.DumpEntriesWithTimeDiff(m, nil)
				stdout = strings.Join(slices.Sorted(strings.SplitAfterSeq(dump, "\n")), "")
				return stdout, stderr, err
			}, nil
		},
	)
}

func parseCtKey(args ...string) (ctKey ctmap.CtKey, mapType string, err error) {
	if len(args) < 4 {
		return ctKey, mapType, fmt.Errorf("%w: expected at least four arguments", script.ErrUsage)
	}

	proto, err := u8proto.ParseProtocol(args[0])
	if err != nil {
		return ctKey, mapType, fmt.Errorf("%w: %w", script.ErrUsage, err)
	}

	var flags uint8
	switch args[1] {
	case "IN":
		flags = ctmap.TUPLE_F_IN
	case "OUT":
		flags = ctmap.TUPLE_F_OUT
	default:
		return ctKey, mapType, fmt.Errorf(
			"%w: direction needs to be 'IN' or 'OUT' (got %q)", script.ErrUsage, args[1],
		)
	}

	saddrport, err := netip.ParseAddrPort(args[2])
	if err != nil {
		return ctKey, mapType, err
	}

	daddrport, err := netip.ParseAddrPort(args[3])
	if err != nil {
		return ctKey, mapType, err
	}

	if saddrport.Addr().Is4() != daddrport.Addr().Is4() {
		return ctKey, mapType, fmt.Errorf(
			"%w: saddr (%q) and daddr (%q) have different IP family",
			script.ErrUsage, saddrport.Addr(), daddrport.Addr(),
		)
	}

	if saddrport.Addr().Is4() {
		t := tuple.TupleKey4{
			DestPort:   daddrport.Port(),
			SourcePort: saddrport.Port(),
			NextHeader: proto,
			Flags:      flags,
		}
		t.SourceAddr.FromAddr(saddrport.Addr())
		t.DestAddr.FromAddr(daddrport.Addr())
		ctKey = &ctmap.CtKey4Global{
			TupleKey4Global: tuple.TupleKey4Global{
				TupleKey4: t,
			},
		}

		if proto == u8proto.TCP {
			mapType = mapTypeTCP4
		} else {
			mapType = mapTypeAny4
		}
	} else {
		t := tuple.TupleKey6{
			DestPort:   daddrport.Port(),
			SourcePort: saddrport.Port(),
			NextHeader: proto,
			Flags:      flags,
		}
		t.SourceAddr.FromAddr(saddrport.Addr())
		t.DestAddr.FromAddr(daddrport.Addr())
		ctKey = &ctmap.CtKey6Global{
			TupleKey6Global: tuple.TupleKey6Global{
				TupleKey6: t,
			},
		}

		if proto == u8proto.TCP {
			mapType = mapTypeTCP6
		} else {
			mapType = mapTypeAny6
		}
	}

	return ctKey.ToNetwork(), mapType, nil
}

func parseCtEntryKey(arg string, entry *ctmap.CtEntry) error {
	k, v, found := strings.Cut(arg, "=")
	if !found {
		return fmt.Errorf("%w: invalid kev-value pair %q (missing '=')", script.ErrUsage, arg)
	}

	value, err := strconv.ParseUint(v, 0, 64)
	if err != nil {
		return fmt.Errorf("%w: invalid value %q: %w", script.ErrUsage, v, err)
	}

	// Set the CtEntry field based on the C struct member name
	e := reflect.ValueOf(entry).Elem()
	for field, fieldValue := range e.Fields() {
		fieldName := field.Tag.Get("align")
		if fieldName == k {
			fieldValue.SetUint(value)
			return nil
		}
	}

	return fmt.Errorf("%w: unknown entry key %q", script.ErrUsage, k)
}

func (f *fakeCTMaps) upsertTuple() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Upserts a CT tuple",
			Args:    "<proto> IN|OUT <saddr:port> <daddr:port> [key=value...]",
			Detail: []string{
				"Upserts a connection tuple into one of the global CT maps.",
				"",
				"You can additionally specify a list of key-value pairs to set the",
				"fields of the BPF ct_entry struct. The key refers to the C struct member",
				"and the value must be an unsigned integer.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			ctKey, mapType, err := parseCtKey(args...)
			if err != nil {
				return nil, err
			}

			ctEntry := &ctmap.CtEntry{}
			for _, arg := range args[4:] {
				err = parseCtEntryKey(arg, ctEntry)
				if err != nil {
					return nil, err
				}
			}

			m, err := f.getMap(mapType)
			if err != nil {
				return nil, err
			}

			return func(*script.State) (stdout, stderr string, err error) {
				err = m.Update(ctKey, ctEntry)
				return stdout, stderr, err
			}, nil
		},
	)
}

func (f *fakeCTMaps) deleteTuple() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Deletes a CT tuple",
			Args:    "<proto> IN|OUT <saddr:port> <daddr:port>",
			Detail: []string{
				"Deletes a connection tuple from one of the global CT maps.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			ctKey, mapType, err := parseCtKey(args...)
			if err != nil {
				return nil, err
			}

			m, err := f.getMap(mapType)
			if err != nil {
				return nil, err
			}

			return func(*script.State) (stdout, stderr string, err error) {
				err = m.Delete(ctKey)
				return stdout, stderr, err
			}, nil
		},
	)
}

type ctMap struct {
	name string
	fd   int
	cfg  ctmap.MapConfig

	pinned atomic.Bool
	opened atomic.Bool

	entries lock.Map[string, ctmap.CtMapRecord]
}

func (c *ctMap) Name() string       { return c.name }
func (c *ctMap) FD() int            { return c.fd }
func (c *ctMap) Type() ebpf.MapType { return ebpf.LRUHash }
func (c *ctMap) MaxEntries() uint32 { return 4096 }

func (c *ctMap) UnpinIfExists() error {
	c.pinned.Store(false)
	return nil
}

func (c *ctMap) OpenOrCreate() error {
	if c.opened.Swap(true) {
		// Strictly validate that we don't attempt to open the same map twice,
		// even though it would be legitimate against the same instance (no-op).
		// However, it may also indicate that are attempting to keep two
		// references to the same map.
		panic("Attempting to open an already open map")
	}

	c.pinned.Store(true)
	return nil
}

func (c *ctMap) Close() error {
	c.opened.Store(false)
	return nil
}

func (c *ctMap) Update(key bpf.MapKey, val bpf.MapValue) error {
	c.entries.Store(key.String(), ctmap.CtMapRecord{
		Key: key.(ctmap.CtKey), Value: *(val.(*ctmap.CtEntry)),
	})
	return nil
}

func (c *ctMap) Delete(key bpf.MapKey) error {
	c.entries.Delete(key.String())
	return nil
}

func (c *ctMap) BatchLookup(_ *ebpf.MapBatchCursor, keysOut any, valuesOut any, _ *ebpf.BatchOptions) (int, error) {
	var (
		keys  = reflect.ValueOf(keysOut)
		vals  = reflect.ValueOf(valuesOut)
		count int
		err   error
	)

	// Try to assign src to dst, or to any of its fields. This is required because
	// [migration.ctKey{4,6}] embed [ctmap.CtKey{4,6}Global].
	var assignOrEmbed = func(dst, src reflect.Value) {
		if src.Type().AssignableTo(dst.Type()) {
			dst.Set(src)
			return
		}

		if dst.Kind() == reflect.Struct {
			for _, f := range dst.Fields() {
				if src.Type().AssignableTo(f.Type()) {
					f.Set(src)
					return
				}
			}
		}

		panic(fmt.Errorf("cannot assign %s to %s (or any of its fields)", src.Type(), dst.Type()))
	}

	// We cannot track pagination, because the cursor has only unexported fields.
	// Hence, we always attempt to return the full snapshot, under the assumption
	// that it should always fit in case of test data (and we return an error if
	// it doesn't).
	c.entries.Range(func(_ string, record ctmap.CtMapRecord) bool {
		if count > keys.Len() {
			count, err = 0, unix.ENOSPC
			return false
		}

		// record.Key is an interface holding a *ctmap.CtKey{4,6}Global.
		assignOrEmbed(keys.Index(count), reflect.ValueOf(record.Key).Elem())
		vals.Index(count).Set(reflect.ValueOf(record.Value))

		count++
		return true
	})

	// ebpf.ErrKeyNotExist signals that iteration completed.
	return count, cmp.Or(err, ebpf.ErrKeyNotExist)
}

func (c *ctMap) DumpEntriesWithTimeDiff(clockSource *models.ClockSource) (string, error) {
	var sb strings.Builder

	c.entries.Range(func(_ string, record ctmap.CtMapRecord) bool {
		record.Key.ToHost().Dump(&sb, true)
		sb.WriteString(record.Value.String())
		return true
	})

	return sb.String(), nil
}

func (c *ctMap) Flush(_ func(ctmap.GCEvent), _ func(ctmap.GCEvent)) int {
	panic("unimplemented")
}

func (c *ctMap) flags() []string {
	var flags []string

	if c.pinned.Load() {
		flags = append(flags, "pinned")
	}

	if c.opened.Load() {
		flags = append(flags, "open")
	}

	return flags
}
