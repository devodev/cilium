// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package migration

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/netip"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	pnmaps "github.com/cilium/cilium/enterprise/pkg/maps/privnet"
	pncfg "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/endpoints"
	api "github.com/cilium/cilium/enterprise/pkg/privnet/grpc/api/v1"
	grpcClient "github.com/cilium/cilium/enterprise/pkg/privnet/grpc/client"
	"github.com/cilium/cilium/enterprise/pkg/privnet/observers"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/enterprise/pkg/privnet/types"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/u8proto"
)

type controllerParams struct {
	cell.In

	Config pncfg.Config

	Log         *slog.Logger
	DB          *statedb.DB
	Migrations  statedb.RWTable[tables.Migration]
	JobGroup    job.Group
	ConnFactory grpcClient.ConnFactoryFn
	Workloads   statedb.RWTable[*tables.LocalWorkload]
	LeaseWriter *tables.DHCPLeaseWriter
	Nodes       *observers.Nodes
	ClusterInfo cmtypes.ClusterInfo

	Endpoints          endpoints.EndpointGetter
	EndpointProperties *endpoints.EndpointPropertyManager

	CTMaps pnmaps.CTMaps
	CTTime *ctTimestampConverter
}

func registerController(params controllerParams) {
	if !params.Config.EnabledWithLiveMigration() {
		return
	}

	r := &controller{controllerParams: params}
	params.JobGroup.Add(job.OneShot("controller", r.loop))
}

type controller struct {
	controllerParams
}

func (c *controller) ctMaps(network string) map[api.CTMapKind]pnmaps.CTMap {
	ctMaps := make(map[api.CTMapKind]pnmaps.CTMap)
	for _, ctMap := range c.CTMaps.ActiveMapsGlobal() {
		switch ctMap.Name() {
		case ctmap.MapNameTCP4Global:
			ctMaps[api.CTMapKind_CT_MAP_KIND_GLOBAL_TCP4] = ctMap
		case ctmap.MapNameAny4Global:
			ctMaps[api.CTMapKind_CT_MAP_KIND_GLOBAL_ANY4] = ctMap
		case ctmap.MapNameTCP6Global:
			ctMaps[api.CTMapKind_CT_MAP_KIND_GLOBAL_TCP6] = ctMap
		case ctmap.MapNameAny6Global:
			ctMaps[api.CTMapKind_CT_MAP_KIND_GLOBAL_ANY6] = ctMap
		}
	}
	for _, ctMap := range c.CTMaps.ActiveMapsForNetwork(network) {
		cfg := ctMap.Config
		switch {
		case !cfg.IPv6 && cfg.TCP:
			ctMaps[api.CTMapKind_CT_MAP_KIND_PRIVNET_TCP4] = ctMap.Map
		case !cfg.IPv6 && !cfg.TCP:
			ctMaps[api.CTMapKind_CT_MAP_KIND_PRIVNET_ANY4] = ctMap.Map
		case cfg.IPv6 && cfg.TCP:
			ctMaps[api.CTMapKind_CT_MAP_KIND_PRIVNET_TCP6] = ctMap.Map
		case cfg.IPv6 && !cfg.TCP:
			ctMaps[api.CTMapKind_CT_MAP_KIND_PRIVNET_ANY6] = ctMap.Map
		}
	}
	return ctMaps
}

func (c *controller) loop(ctx context.Context, health cell.Health) error {
	var lastRev statedb.Revision
	for {
		// Iterate over changes to [tables.Migration] and for each 'New' migration
		// create a job to manage it.
		var toStart []*migrator
		wtxn := c.DB.WriteTxn(c.Migrations)
		iter, watch := c.Migrations.LowerBoundWatch(wtxn, statedb.ByRevision[tables.Migration](lastRev+1))
		for migration, rev := range iter {
			lastRev = max(lastRev, rev)
			if migration.State == tables.MigrationStateNew {
				toStart = append(toStart,
					&migrator{
						controllerParams: c.controllerParams,
						key:              migration.MigrationKey,
						log: c.Log.With(
							logfields.K8sNamespace, migration.MigrationKey.Namespace,
							logfields.K8sPodName, migration.MigrationKey.PodName,
							logfields.MACAddr, migration.MigrationKey.MAC,
						),
						ctMaps: c.ctMaps(migration.LocalWorkload.Interface.Network),
						ctTime: c.CTTime,
					})
				migration.State = tables.MigrationStateStarting
				migration.UpdatedAt = time.Now()
				c.Migrations.Insert(wtxn, migration)
			}
		}
		wtxn.Commit()

		for _, m := range toStart {
			c.JobGroup.Add(job.OneShot(
				"migrate-"+m.key.String(),
				m.run,
			))
		}

		select {
		case <-ctx.Done():
			return nil
		case <-watch:
		}
	}
}

type migrator struct {
	controllerParams
	key tables.MigrationKey
	log *slog.Logger

	ctTime *ctTimestampConverter
	ctMaps map[api.CTMapKind]pnmaps.CTMap
}

func (m *migrator) run(ctx context.Context, health cell.Health) error {
	migration, _, watch, found := m.Migrations.GetWatch(m.DB.ReadTxn(), tables.MigrationByKey(m.key))
	if !found {
		return nil
	}
	lw := migration.LocalWorkload

	var (
		stream  *Stream
		batches <-chan batch
	)

	const (
		migrationTimeout = time.Minute
		retryInterval    = time.Second
	)
	ctx, cancel := context.WithTimeout(ctx, migrationTimeout)
	defer cancel()

	stateMachine := stateMachine{
		tables.MigrationStateStarting: transition{
			onFail:    tables.MigrationStateError,
			onSuccess: tables.MigrationStateStarted,
			exec: func(ctx context.Context) error {
				node := m.Nodes.Get(types.ClusterName(m.ClusterInfo.Name), migration.SourceNode)
				if node == nil {
					return fmt.Errorf("source node %q not found", migration.SourceNode)
				}
				var err error
				stream, err = StartMigration(ctx, m.ConnFactory, *node,
					tables.NetworkName(lw.Interface.Network),
					lw.Interface.MAC)
				if err == nil {
					// Construct a channel out of the gRPC stream so we can
					// consume the data while at the same time select on other
					// channels.
					batches = streamToChannel(stream)
				}
				return err
			},
		},

		tables.MigrationStateStarted: transition{
			onFail:    tables.MigrationStateError,
			onSuccess: tables.MigrationStateFinalizing,
			exec: func(ctx context.Context) error {
				// Start processing the data.
				for {
					select {
					case <-ctx.Done():
						return ctx.Err()
					case <-watch:
						migration, _, watch, found = m.Migrations.GetWatch(m.DB.ReadTxn(), tables.MigrationByKey(m.key))
						if !found {
							// Migration has been removed which implies the endpoint has been removed. Abort the migration.
							return fmt.Errorf("migration deleted")
						}
						if migration.Resumed {
							// The VM has resumed, move to finalizing.
							return nil
						}
					case batch, ok := <-batches:
						if !ok {
							// Stream closed early.
							return fmt.Errorf("migration aborted")
						}
						if batch.err != nil {
							return batch.err
						}
						m.processBatch(migration, batch.batch)
					}
				}
			},
		},

		tables.MigrationStateFinalizing: transition{
			onFail:    tables.MigrationStateError,
			onSuccess: tables.MigrationStateDone,
			exec: func(ctx context.Context) error {
				// Send the request for final deltas
				if err := stream.Finalize(); err != nil {
					return err
				}
				// Process the final deltas
				for {
					select {
					case <-ctx.Done():
						return ctx.Err()
					case batch, ok := <-batches:
						if !ok {
							// Stream closed and migration has completed.
							return nil
						}
						if batch.err != nil {
							return batch.err
						}
						m.processBatch(migration, batch.batch)
					}
				}
			},
		},
	}

	// Start migrating. If the migration fails we wait a bit and retry until
	// the context times out or we succeed.
	var migrationErr error
	for {
		// Run the state machine until we either reach a terminal state or
		// [ctx] is cancelled.
		migrationErr = stateMachine.run(
			ctx,
			migration.State,

			// For observability we update the job health and the
			// migration state on state changes.
			func(newState tables.MigrationState, err error) {
				if err != nil {
					health.Degraded(string(newState), err)
				} else {
					health.OK(string(newState))
				}
				wtxn := m.DB.WriteTxn(m.Migrations)
				migration, _, found = m.Migrations.Get(wtxn, tables.MigrationByKey(m.key))
				if found {
					migration.State = newState
					migration.Error = err
					migration.UpdatedAt = time.Now()
					m.Migrations.Insert(wtxn, migration)
					wtxn.Commit()
				} else {
					wtxn.Abort()
				}
			},
		)

		// In case the migration was aborted early close the stream and drain
		// the batches channel.
		if stream != nil {
			stream.Close()
			stream = nil
			if batches != nil {
				for range batches {
				}
				batches = nil
			}
		}

		if migrationErr == nil {
			break
		}

		// Migration failed. Wait a moment before retrying.
		select {
		case <-ctx.Done():
		case <-time.After(retryInterval):
		}

		ctxErr := ctx.Err()
		wtxn := m.DB.WriteTxn(m.Migrations)
		migration, _, found = m.Migrations.Get(wtxn, tables.MigrationByKey(m.key))
		if found {
			if ctxErr == nil {
				migration.State = tables.MigrationStateStarting
			} else {
				migration.State = tables.MigrationStateError
			}
			migration.Error = ctxErr
			migration.UpdatedAt = time.Now()
			m.Migrations.Insert(wtxn, migration)
			wtxn.Commit()
		} else {
			// Migration has been removed. Stop.
			wtxn.Abort()
			break
		}
		if ctxErr != nil {
			break
		}
	}

	// Regardless of outcome remove the activation blocker from the local workload
	// which was added by [reconcilers.LocalWorkloads].
	wtxn := m.DB.WriteTxn(m.Workloads)
	if lw, _, found := m.Workloads.Get(wtxn, tables.LocalWorkloadsByID(lw.EndpointID)); found {
		lw2 := *lw
		lw2.RemoveActivationBlocker(tables.ActivationBlockerMigration)
		m.Workloads.Insert(wtxn, &lw2)
		wtxn.Commit()
	} else {
		wtxn.Abort()
	}

	return migrationErr
}

func (m *migrator) processBatch(migration tables.Migration, batch *api.MigrationBatch) {
	if dhcp := batch.GetDhcpLease(); len(dhcp) != 0 {
		m.processLeases(migration, dhcp)
	}
	if addr := batch.GetEndpointAddressing(); len(addr) != 0 {
		m.processEndpointAddressing(migration, addr)
	}
	if ctRecords := batch.GetRecords(); len(ctRecords) != 0 {
		m.processCTRecords(migration, ctRecords)
	}
}

func (m *migrator) processLeases(migration tables.Migration, leases []*api.DHCPLease) {
	now := time.Now()
	network := tables.NetworkName(migration.LocalWorkload.Interface.Network)
	mac := mac.MustParseMAC(migration.LocalWorkload.Interface.MAC)
	leaseTable := m.LeaseWriter.Table()

	wtxn := m.DB.WriteTxn(leaseTable)
	defer wtxn.Commit()

	for _, lease := range leases {
		ipv4, ok := netip.AddrFromSlice(lease.GetIpv4())
		if !ok {
			m.log.Warn("Discarding DHCP lease with invalid IP")
			continue
		}
		serverID, err := netip.ParseAddr(lease.GetServerId())
		if err != nil {
			m.log.Warn("Discarding DHCP lease with invalid server ID")
			continue
		}
		expireAt := lease.GetExpireAt().AsTime()
		if now.After(expireAt) {
			m.log.Warn("Discarding expired DHCP lease", logfields.IPAddr, ipv4)
			continue
		}

		newLease := tables.DHCPLease{
			Network:    network,
			EndpointID: migration.LocalWorkload.EndpointID,
			MAC:        mac,
			IPv4:       ipv4,
			ServerID:   serverID,
			ObtainedAt: lease.GetObtainedAt().AsTime(),
			RenewAt:    lease.GetRenewAt().AsTime(),
			ExpireAt:   expireAt,
		}
		old, _, found := leaseTable.Get(wtxn, tables.DHCPLeaseByNetworkMAC(network, mac))
		if !found || newLease.ObtainedAt.After(old.ObtainedAt) {
			m.log.Debug("Migrated DHCP lease", logfields.IPAddr, newLease.IPv4)
			m.LeaseWriter.Insert(wtxn, newLease)
		}
	}
}

func (m *migrator) processEndpointAddressing(migration tables.Migration, epAddrs []*api.EndpointAddressing) {
	ep := m.Endpoints.LookupID(migration.LocalWorkload.EndpointID)
	if ep == nil {
		m.log.Warn("Unable to find endpoint")
		return
	}

	prevAddressing := make([]types.PreviousAddressing, 0, len(epAddrs))
	for _, epAddr := range epAddrs {
		prevAddr := types.PreviousAddressing{
			LastSeen: epAddr.LastSeen.AsTime().UTC(),
		}

		if ipv4 := epAddr.GetIpv4(); len(ipv4) != 0 {
			addr, ok := netip.AddrFromSlice(ipv4)
			if ok && addr.Is4() {
				prevAddr.IPv4 = addr
			} else {
				m.log.Warn("Discarding previous IPv4 address as invalid",
					logfields.IPAddr, ipv4)
			}
		}
		if ipv6 := epAddr.GetIpv6(); len(ipv6) != 0 {
			addr, ok := netip.AddrFromSlice(ipv6)
			if ok && addr.Is6() {
				prevAddr.IPv6 = addr
			} else {
				m.log.Warn("Discarding previous IPv6 address as invalid",
					logfields.IPAddr, ipv6)
			}
		}

		prevAddressing = append(prevAddressing, prevAddr)
	}

	m.EndpointProperties.SetPreviousAddressing(ep, prevAddressing)
}

func (m *migrator) ctKey(key *api.CTKey) (ctmap.CtKey, error) {
	saddr, ok := netip.AddrFromSlice(key.GetSourceIp())
	if !ok {
		return nil, fmt.Errorf("invalid CT source IP %s", key.GetSourceIp())
	}
	daddr, ok := netip.AddrFromSlice(key.GetDestIp())
	if !ok {
		return nil, fmt.Errorf("invalid CT dest IP %s", key.GetDestIp())
	}
	proto, err := u8proto.FromNumber(uint8(key.GetNextHeader()))
	if err != nil {
		return nil, err
	}
	if saddr.Is4() != daddr.Is4() {
		return nil, fmt.Errorf("invalid CT key with mismatched IP family %s and %s", saddr, daddr)
	}

	if saddr.Is4() {
		t := tuple.TupleKey4{
			DestPort:   uint16(key.GetDestPort()),
			SourcePort: uint16(key.GetSourcePort()),
			NextHeader: proto,
			Flags:      uint8(key.GetFlags()),
		}
		t.SourceAddr.FromAddr(saddr)
		t.DestAddr.FromAddr(daddr)
		return &ctmap.CtKey4Global{
			TupleKey4Global: tuple.TupleKey4Global{
				TupleKey4: t,
			},
		}, nil
	} else if saddr.Is6() {
		t := tuple.TupleKey6{
			DestPort:   uint16(key.GetDestPort()),
			SourcePort: uint16(key.GetSourcePort()),
			NextHeader: proto,
			Flags:      uint8(key.GetFlags()),
		}
		t.SourceAddr.FromAddr(saddr)
		t.DestAddr.FromAddr(daddr)
		return &ctmap.CtKey6Global{
			TupleKey6Global: tuple.TupleKey6Global{
				TupleKey6: t,
			},
		}, nil
	}

	return nil, errors.New("unknown IP family")
}

func (m *migrator) processCTRecords(migration tables.Migration, records []*api.CTRecord) {
	ctNow, err := m.ctTime.ctNow()
	if err != nil {
		m.log.Error("Unable to get current CT time", logfields.Error, err)
		return
	}

	var errs error
	for _, record := range records {
		ctMap := m.ctMaps[record.GetKind()]
		if ctMap == nil {
			m.log.Warn("Unable to resolve CT map kind", logfields.Kind, record.Kind)
			continue
		}

		k, v := record.GetKey(), record.GetValue()
		if k == nil || v == nil {
			m.log.Warn("Discarding incomplete CT record")
			continue
		}

		ctKey, err := m.ctKey(k)
		if err != nil {
			m.log.Warn("Discarding CT record", logfields.Error, err)
			continue
		}
		ctValue := &ctmap.CtEntry{
			Lifetime:    m.ctTime.toLifetime(ctNow, v.GetLifetime()),
			Flags:       uint16(v.GetFlags()),
			TxFlagsSeen: uint8(v.GetTxFlagsSeen()),
			RxFlagsSeen: uint8(v.GetRxFlagsSeen()),
		}

		err = ctMap.Update(ctKey, ctValue)
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("error updating CT entry %q: %w", ctKey.String(), err))
		}
	}

	if errs != nil {
		m.log.Warn("Unable to update CT records. Expect connection drops during endpoint migration", logfields.Error, errs)
	}
}

type batch struct {
	err   error
	batch *api.MigrationBatch
}

func streamToChannel(s *Stream) <-chan batch {
	ch := make(chan batch)
	go func() {
		defer close(ch)
		for {
			b, err := s.Recv()
			if err != nil {
				if !errors.Is(err, io.EOF) {
					ch <- batch{err: err}
				}
				return
			}
			ch <- batch{batch: b}
		}
	}()
	return ch
}

type transition struct {
	onFail    tables.MigrationState
	onSuccess tables.MigrationState
	exec      func(ctx context.Context) error
}

type stateMachine map[tables.MigrationState]transition

func (sm stateMachine) run(ctx context.Context, start tables.MigrationState, onStateChange func(newState tables.MigrationState, err error)) error {
	if err := sm.validate(start); err != nil {
		panic("BUG: invalid state machine: " + err.Error())
	}
	var lastErr error
	current := start
	for !current.IsTerminal() {
		transition := sm[current]
		lastErr = transition.exec(ctx)
		if lastErr != nil {
			current = transition.onFail
		} else {
			current = transition.onSuccess
		}
		onStateChange(current, lastErr)
	}
	return lastErr
}

func (sm stateMachine) validate(start tables.MigrationState) error {
	unreachable := maps.Clone(sm)
	delete(unreachable, start)
	for state, transition := range sm {
		if _, exists := sm[transition.onFail]; !exists && !transition.onFail.IsTerminal() {
			return fmt.Errorf("%s->%s invalid, target does not exist", state, transition.onFail)
		}
		if _, exists := sm[transition.onSuccess]; !exists && !transition.onSuccess.IsTerminal() {
			return fmt.Errorf("%s->%s invalid, target does not exist", state, transition.onSuccess)
		}
		delete(unreachable, transition.onFail)
		delete(unreachable, transition.onSuccess)
	}
	if len(unreachable) > 0 {
		return fmt.Errorf("unreachable states: %v\n", slices.Sorted(maps.Keys(unreachable)))
	}
	return nil
}
