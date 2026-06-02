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
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var RoutesCell = cell.Group(
	cell.ProvidePrivate(
		// Provides the ReadWrite Routes table.
		tables.NewRouteTable,

		// Provides the reconciler handling private network routes.
		newRoutes,
	),

	cell.Provide(
		// Provides the ReadOnly Routes table.
		statedb.RWTable[tables.Route].ToTable,
	),

	cell.Invoke(
		// Registers the reconciler
		(*Routes).registerReconciler,
	),
)

// Routes is a reconciler which watches the subnets table and populates the routes table from that
type Routes struct {
	log *slog.Logger
	jg  job.Group

	cfg config.Config

	db     *statedb.DB
	subnet statedb.Table[tables.Subnet]
	tbl    statedb.RWTable[tables.Route]
}

func newRoutes(in struct {
	cell.In

	Log      *slog.Logger
	JobGroup job.Group

	Config config.Config

	DB      *statedb.DB
	Subnets statedb.Table[tables.Subnet]
	Table   statedb.RWTable[tables.Route]
}) *Routes {
	return &Routes{
		log: in.Log,
		jg:  in.JobGroup,

		cfg: in.Config,

		db:     in.DB,
		subnet: in.Subnets,
		tbl:    in.Table,
	}
}

func (r *Routes) registerReconciler() {
	if !r.cfg.Enabled {
		return
	}

	wtx := r.db.WriteTxn(r.tbl)
	initialized := r.tbl.RegisterInitializer(wtx, "routes-initialized")
	wtx.Commit()

	// This job watches the upstream subnets table and populates the routes table from that
	r.jg.Add(job.OneShot("populate-routes-table", func(ctx context.Context, _ cell.Health) error {
		var initDone bool

		txn := r.db.WriteTxn(r.subnet)
		changeIter, _ := r.subnet.Changes(txn)
		txn.Commit()

		for {
			var initWatch <-chan struct{}
			txn := r.db.WriteTxn(r.tbl)
			changes, watch := changeIter.Next(txn)

			for change := range changes {
				r.log.Debug("Processing table event",
					logfields.Table, r.subnet.Name(),
					logfields.Event, change,
				)

				if change.Deleted {
					if err := r.deleteNetworkRoutes(txn, change.Object); err != nil {
						txn.Abort()
						return err
					}
				} else {
					if err := r.upsertNetworkRoutes(txn, change.Object); err != nil {
						txn.Abort()
						return err
					}
				}
			}

			// In order to be able to propagate initialization, we need to check if the upstream
			// tables have already been initialized
			if !initDone {
				init, nw := r.subnet.Initialized(txn)

				switch {
				case !init:
					initWatch = nw
				default:
					initDone = true
					initialized(txn)
				}
			}

			txn.Commit()

			// Wait until there's new changes to consume
			select {
			case <-ctx.Done():
				return nil
			case <-watch:
			case <-initWatch:
			}
		}
	}))
}

// extractRoutes extracts the routes from the subnet and stores it in a map, indexed
// by the StateDB key (which contains the route destination). If it detects a key conflict,
// it logs a warning and ignores the conflicting entry. CIDR entries take precedence over
// route entries.
func (r *Routes) extractRoutes(txn statedb.ReadTxn, subnet tables.Subnet) map[tables.RouteKey]tables.Route {
	routes := make(map[tables.RouteKey]tables.Route, 2+len(subnet.Routes))
	for cidr := range subnet.CIDRs() {
		entry := tables.Route{
			Network:     subnet.Network,
			Subnet:      subnet.Name,
			Destination: cidr,
		}
		key := entry.Key()
		if _, ok := routes[key]; ok {
			r.log.Warn("Duplicate private network subnet CIDRs - this should never happen",
				logfields.Network, subnet.Network,
				logfields.CIDR, cidr,
				logfields.PrivateNetworkSubnet, subnet.Name,
			)
		} else {
			routes[key] = entry
		}
	}

	for _, route := range subnet.Routes {
		entry := tables.Route{
			Network:     subnet.Network,
			Subnet:      subnet.Name,
			Destination: route.Destination,
			Gateway:     route.Gateway,
			EVPNGateway: route.EVPNGateway,
		}
		key := entry.Key()
		if _, ok := routes[key]; ok {
			r.log.Warn("Duplicate route destination in private network subnet definition",
				logfields.Network, subnet.Network,
				logfields.PrivateNetworkSubnet, subnet.Name,
				logfields.CIDR, route.Destination,
			)
			continue
		}
		routes[key] = entry
	}

	for _, peer := range subnet.Peers {
		other, _, ok := r.subnet.Get(txn, tables.SubnetsByNetworkAndName(peer.Network, peer.Subnet))
		if !ok {
			r.log.Warn("Unknown peer for subnet",
				logfields.Network, subnet.Network,
				logfields.PrivateNetworkSubnet, subnet.Name,
				logfields.PeerNetwork, peer.Network,
				logfields.PeerSubnet, peer.Subnet,
			)
			continue
		}
		for cidr := range other.CIDRs() {
			entry := tables.Route{
				Network:     subnet.Network,
				Subnet:      subnet.Name,
				Destination: cidr,
				Peer: tables.RoutePeer{
					Network: other.Network,
					Subnet:  other.Name,
					ID: tables.SubnetIDPair{
						Network: other.NetworkID,
						Subnet:  other.ID,
					},
				},
			}
			routes[entry.Key()] = entry
		}
	}

	return routes
}

// upsertNetworkRoutes extracts the desired routes from the subnet, removes all routes no longer
// in the desired set, and then upserts all missing desired routes.
func (r *Routes) upsertNetworkRoutes(txn statedb.WriteTxn, subnet tables.Subnet) error {
	desiredRoutes := r.extractRoutes(txn, subnet)
	// iterate over the existing routes in the table to determine which ones to remove
	for existing := range r.tbl.Prefix(txn, tables.RoutesByNetworkSubnet(subnet.Network, subnet.Name)) {
		routeKey := existing.Key()
		desired, ok := desiredRoutes[routeKey]
		if !ok {
			// if the route is not in the desired set, remove it
			_, _, err := r.tbl.Delete(txn, existing)
			if err != nil {
				return err
			}
		} else if desired == existing {
			// if the desired route exactly matches the existing one,
			// we do not need to re-insert it
			delete(desiredRoutes, routeKey)
		}
	}

	// upsert remaining desired routes
	for _, route := range desiredRoutes {
		_, _, err := r.tbl.Insert(txn, route)
		if err != nil {
			return err
		}
	}

	return nil
}

// deleteNetworkRoutes removes all routes belonging to a subnet
func (r *Routes) deleteNetworkRoutes(txn statedb.WriteTxn, subnet tables.Subnet) error {
	for entry := range r.tbl.Prefix(txn, tables.RoutesByNetworkSubnet(subnet.Network, subnet.Name)) {
		_, _, err := r.tbl.Delete(txn, entry)
		if err != nil {
			return err
		}
	}
	return nil
}
