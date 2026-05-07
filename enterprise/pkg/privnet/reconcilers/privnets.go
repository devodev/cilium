// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/reconcilers/idpool"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/enterprise/pkg/vni"
	"github.com/cilium/cilium/pkg/k8s"
	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	cs_iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/promise"
)

var PrivateNetworksCell = cell.Group(
	cell.ProvidePrivate(
		// Provides the ReadWrite PrivateNetworks table.
		tables.NewPrivateNetworksTable,

		// Provides the reconciler handling private networks.
		newPrivateNetworks,
	),

	cell.Provide(
		// Provide the IDPool via hive, so that it can be overridden for testing
		// purposes, as we will want stable IDs there.
		idpool.NewPrivnetIDPool,

		// Provides the ReadOnly PrivateNetworks table.
		statedb.RWTable[tables.PrivateNetwork].ToTable,
	),

	cell.Invoke(
		// Registers the k8s to table reflector.
		(*PrivateNetworks).registerK8sReflector,

		// Register the reconciler to release stale network IDs.
		(*PrivateNetworks).registerIDsReleaser,
	),
)

// PrivateNetworks is the reconciler for private networks.
type PrivateNetworks struct {
	log *slog.Logger
	jg  job.Group

	cfg config.Config

	db  *statedb.DB
	tbl statedb.RWTable[tables.PrivateNetwork]

	client cs_iso_v1alpha1.ClusterwidePrivateNetworkInterface
}

func newPrivateNetworks(in struct {
	cell.In

	Log      *slog.Logger
	JobGroup job.Group

	Config config.Config

	DB    *statedb.DB
	Table statedb.RWTable[tables.PrivateNetwork]

	Client client.Clientset
}) (*PrivateNetworks, error) {
	reconciler := &PrivateNetworks{
		log: in.Log,
		jg:  in.JobGroup,
		cfg: in.Config,
		db:  in.DB,
		tbl: in.Table,
	}

	if !in.Config.Enabled {
		return reconciler, nil
	}

	if !in.Client.IsEnabled() {
		return nil, errors.New("private networks requires Kubernetes support to be enabled")
	}

	reconciler.client = in.Client.IsovalentV1alpha1().ClusterwidePrivateNetworks()
	return reconciler, nil
}

func (pn *PrivateNetworks) registerK8sReflector(idpool *idpool.NetworkIDPool, sync promise.Promise[synced.CRDSync]) error {
	if !pn.cfg.Enabled {
		return nil
	}

	cfg := k8s.ReflectorConfig[tables.PrivateNetwork]{
		Name:          "to-table", // the full name will be "job-k8s-reflector-private-networks-to-table"
		Table:         pn.tbl,
		ListerWatcher: utils.ListerWatcherFromTyped(pn.client),
		MetricScope:   "ClusterwidePrivateNetwork",
		CRDSync:       sync,

		Transform: func(txn statedb.ReadTxn, obj any) (tables.PrivateNetwork, bool) {
			privnet, ok := obj.(*iso_v1alpha1.ClusterwidePrivateNetwork)
			if !ok {
				return tables.PrivateNetwork{}, false
			}

			// Retrieve the current ID, if already assigned.
			id := tables.NetworkIDReserved
			if curr, _, found := pn.tbl.Get(txn, tables.PrivateNetworkByName(tables.NetworkName(privnet.Name))); found {
				id = curr.ID
			}

			// Attempt to acquire a new ID, if not already assigned.
			if id == tables.NetworkIDReserved {
				var err error
				id, err = idpool.Acquire(tables.NetworkName(privnet.Name))
				if err != nil {
					pn.log.Error("Failed to assign network ID to private network",
						logfields.Error, err,
						logfields.ClusterwidePrivateNetwork, privnet.Name,
					)
					return tables.PrivateNetwork{}, false
				}
			}

			vni := pn.extractVNI(privnet)
			inbs := pn.extractINBs(privnet)
			subnets := pn.extractSubnets(privnet)

			return tables.PrivateNetwork{
				Name:    tables.NetworkName(privnet.Name),
				VNI:     vni,
				ID:      id,
				INBs:    inbs,
				Subnets: subnets,
			}, true
		},
	}

	return k8s.RegisterReflector(pn.jg, pn.db, cfg)
}

func (pn *PrivateNetworks) extractINBs(privnet *iso_v1alpha1.ClusterwidePrivateNetwork) tables.PrivateNetworkINBs {
	selectors := make(map[tables.ClusterName]tables.Selector, len(privnet.Spec.INBs))
	for _, candidate := range privnet.Spec.INBs {
		selector, err := slim_metav1.LabelSelectorAsSelector(&candidate.NodeSelector.LabelSelector)
		if err != nil {
			pn.log.Error("Encountered invalid INB node selector for cluster",
				logfields.Error, err,
				logfields.ClusterwidePrivateNetwork, privnet.Name,
				logfields.ClusterName, candidate.Cluster,
			)
			continue
		}

		// Cannot happen by construction (the label selector is never nil), but
		// better safe than sorry...
		if selector == labels.Nothing() {
			continue
		}

		selectors[tables.ClusterName(candidate.Cluster)] = tables.Selector{Selector: selector}
	}
	return tables.PrivateNetworkINBs{Selectors: selectors}
}

func (pn *PrivateNetworks) extractRoutes(privnet tables.NetworkName, subnet iso_v1alpha1.SubnetSpec) []tables.PrivateNetworkRoute {
	routes := make([]tables.PrivateNetworkRoute, 0, len(subnet.Routes))
	for _, routeSpec := range subnet.Routes {
		dst, err := netip.ParsePrefix(string(routeSpec.Destination))
		if err != nil {
			pn.log.Error("Encountered invalid route destination in private network spec",
				logfields.CIDR, routeSpec.Destination,
				logfields.Error, err,
				logfields.ClusterwidePrivateNetwork, privnet,
				logfields.PrivateNetworkSubnet, subnet.Name,
			)
			continue
		}

		if routeSpec.Gateway == iso_v1alpha1.EVPNRoute {
			routes = append(routes, tables.PrivateNetworkRoute{
				Destination: dst,
				EVPNGateway: true,
			})
			continue
		}

		gw, err := netip.ParseAddr(string(routeSpec.Gateway))
		if err != nil {
			pn.log.Error("Encountered invalid route gateway in private network spec",
				logfields.IPAddr, routeSpec.Gateway,
				logfields.Error, err,
				logfields.ClusterwidePrivateNetwork, privnet,
				logfields.PrivateNetworkSubnet, subnet.Name,
			)
			continue
		}

		routes = append(routes, tables.PrivateNetworkRoute{
			Destination: dst,
			Gateway:     gw,
		})
	}
	return routes
}

func (pn *PrivateNetworks) extractSubnets(privnet *iso_v1alpha1.ClusterwidePrivateNetwork) []tables.PrivateNetworkSubnet {
	subnets := make([]tables.PrivateNetworkSubnet, 0, len(privnet.Spec.Subnets))
	for _, subnetPrefix := range privnet.Spec.Subnets {
		subnet := tables.PrivateNetworkSubnet{
			Name: tables.SubnetName(subnetPrefix.Name),
		}

		if subnetPrefix.CIDRv4 != "" {
			cidr, err := netip.ParsePrefix(string(subnetPrefix.CIDRv4))
			if err != nil || !cidr.Addr().Is4() {
				pn.log.Error("Encountered invalid IPv4 subnet CIDR in private network spec",
					logfields.CIDR, subnetPrefix.CIDRv4,
					logfields.Error, err,
					logfields.ClusterwidePrivateNetwork, privnet.Name,
					logfields.PrivateNetworkSubnet, subnetPrefix.Name,
				)
			} else {
				subnet.CIDRv4 = cidr.Masked()
			}
		}

		if subnetPrefix.CIDRv6 != "" {
			cidrv6, err := netip.ParsePrefix(string(subnetPrefix.CIDRv6))
			if err != nil || !cidrv6.Addr().Is6() {
				pn.log.Error("Encountered invalid IPv6 subnet CIDR in private network spec",
					logfields.CIDR, subnetPrefix.CIDRv6,
					logfields.Error, err,
					logfields.ClusterwidePrivateNetwork, privnet.Name,
					logfields.PrivateNetworkSubnet, subnetPrefix.Name,
				)
			} else {
				subnet.CIDRv6 = cidrv6.Masked()
			}
		}

		subnet.Routes = pn.extractRoutes(tables.NetworkName(privnet.Name), subnetPrefix)
		dhcp := subnetPrefix.DHCP
		if dhcp.Mode == "" {
			dhcp.Mode = iso_v1alpha1.PrivateNetworkDHCPModeNone
		}
		subnet.DHCP = dhcp
		if subnet.CIDRv4.IsValid() || subnet.CIDRv6.IsValid() {
			subnets = append(subnets, subnet)
		}
	}
	return subnets
}

func (pn *PrivateNetworks) extractVNI(privnet *iso_v1alpha1.ClusterwidePrivateNetwork) vni.VNI {
	if privnet.Status != nil && privnet.Status.VNI != nil {
		res, err := vni.FromUint32(*privnet.Status.VNI)
		if err != nil {
			pn.log.Error("Encountered invalid VNI in private network status",
				logfields.Error, err,
				logfields.ClusterwidePrivateNetwork, privnet.Name,
				vni.LogFieldVNI, *privnet.Status.VNI,
			)
		}
		return res
	}
	return vni.VNI{}
}

func (pn *PrivateNetworks) registerIDsReleaser(idpool *idpool.NetworkIDPool) {
	if !pn.cfg.Enabled {
		return
	}

	pn.jg.Add(
		job.OneShot(
			"private-networks-release-ids",
			func(ctx context.Context, health cell.Health) error {
				wtx := pn.db.WriteTxn(pn.tbl)
				changeIter, _ := pn.tbl.Changes(wtx)
				wtx.Commit()

				health.OK("Primed")
				for {
					var count uint
					changes, watch := changeIter.Next(pn.db.ReadTxn())

					for change := range changes {
						if change.Deleted && change.Object.ID != tables.NetworkIDReserved {
							idpool.Release(change.Object.ID)
							count++
						}
					}

					if count > 0 {
						health.OK(fmt.Sprintf("%d IDs released", count))
					}

					select {
					case <-watch:
					case <-ctx.Done():
						return nil
					}
				}
			},
		),
		job.OneShot(
			"private-networks-id-pool-initialized",
			func(ctx context.Context, health cell.Health) error {
				// Wait for private networks table initialization
				_, watch := pn.tbl.Initialized(pn.db.ReadTxn())
				select {
				case <-watch:
				case <-ctx.Done():
					return ctx.Err()
				}

				idpool.Initialized()
				return nil
			},
		),
	)
}
