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
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/enterprise/operator/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/operator/pkg/privnet/tables"
	"github.com/cilium/cilium/enterprise/pkg/privnet/types"
	"github.com/cilium/cilium/enterprise/pkg/vni"
	"github.com/cilium/cilium/pkg/k8s"
	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	k8sconstv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/promise"
	cslices "github.com/cilium/cilium/pkg/slices"
)

// PrivateNetworksCell groups the private networks reconciliation operations that
// need to be performed by all operator replicas. Any operation that depends on
// leader election must be configured in a separate cell.
var PrivateNetworksCell = cell.Group(
	cell.ProvidePrivate(
		// Provides the ReadWrite PrivateNetworks table.
		tables.NewPrivateNetworksTable,

		// Provides the reconciler handling private networks.
		newPrivateNetworks,
	),

	cell.Provide(
		// Provides the ReadOnly PrivateNetworks table.
		statedb.RWTable[tables.PrivateNetwork].ToTable,
	),

	cell.Invoke(
		// Registers the k8s to table reflector.
		(*PrivateNetworks).registerK8sReflector,
	),
)

type PrivateNetworks struct {
	log *slog.Logger
	jg  job.Group

	cfg config.Config

	db  *statedb.DB
	tbl statedb.RWTable[tables.PrivateNetwork]

	client client.Clientset
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

	reconciler.client = in.Client
	return reconciler, nil
}

func (pn *PrivateNetworks) registerK8sReflector() error {
	if !pn.cfg.Enabled {
		return nil
	}

	return k8s.RegisterReflector(pn.jg, pn.db, k8s.ReflectorConfig[tables.PrivateNetwork]{
		Name:          "to-table",
		Table:         pn.tbl,
		ListerWatcher: utils.ListerWatcherFromTyped(pn.client.IsovalentV1alpha1().ClusterwidePrivateNetworks()),

		// We need to explicitly check for the ClusterwidePrivateNetworks CRD
		// existence because we run the reflector in all operator replicas, and
		// it may otherwise start before that the CRD got actually created.
		CRDSync: pn.newCRDSyncPromise(),

		Transform: func(txn statedb.ReadTxn, obj any) (tables.PrivateNetwork, bool) {
			privnet, ok := obj.(*iso_v1alpha1.ClusterwidePrivateNetwork)
			if !ok {
				return tables.PrivateNetwork{}, false
			}

			return tables.PrivateNetwork{
				Name:         tables.NetworkName(privnet.Name),
				Subnets:      pn.extractSubnets(privnet),
				RequestedVNI: pn.extractRequestedVNI(privnet),
				NADs:         pn.extractNADs(privnet),
				OrigResource: privnet.DeepCopy(),
				Mappings:     pn.extractMappings(privnet),
			}, true
		},
	})
}

func (pn *PrivateNetworks) extractSubnets(privnet *iso_v1alpha1.ClusterwidePrivateNetwork) []tables.PrivateNetworkSubnet {
	return cslices.Map(
		privnet.Spec.Subnets,
		func(subnet iso_v1alpha1.SubnetSpec) tables.PrivateNetworkSubnet {
			return tables.PrivateNetworkSubnet{
				Name: tables.SubnetName(subnet.Name),
				DHCP: subnet.DHCP.Mode == iso_v1alpha1.PrivateNetworkDHCPModeBroadcast ||
					subnet.DHCP.Mode == iso_v1alpha1.PrivateNetworkDHCPModeRelay,
			}
		},
	)
}

func (pn *PrivateNetworks) extractRequestedVNI(privnet *iso_v1alpha1.ClusterwidePrivateNetwork) vni.VNI {
	if privnet.Spec.VNI != nil {
		vniVal, err := vni.FromUint32(*privnet.Spec.VNI)
		if err == nil {
			return vniVal
		}
	}
	return vni.VNI{}
}

func (pn *PrivateNetworks) extractNADs(privnet *iso_v1alpha1.ClusterwidePrivateNetwork) tables.PrivateNetworkNADs {
	var selector = labels.Nothing()

	parsed, err := slim_metav1.LabelSelectorAsSelector(privnet.Spec.NetworkAttachmentDefinitions.NamespaceSelector)
	if err != nil {
		pn.log.Error("Encountered invalid NetworkAttachmentDefinition namespace selector",
			logfields.Error, err,
			logfields.ClusterwidePrivateNetwork, privnet.Name,
		)
	} else {
		selector = parsed
	}

	return tables.PrivateNetworkNADs{
		NamespaceSelector: tables.Selector{Selector: selector},
	}
}

func (pn *PrivateNetworks) newCRDSyncPromise() promise.Promise[synced.CRDSync] {
	resolve, promise := promise.New[synced.CRDSync]()

	pn.jg.Add(
		job.OneShot("wait-for-icpn-crd", func(ctx context.Context, health cell.Health) error {
			for {
				health.OK("Checking if ClusterWidePrivateNetworks CRD exists")
				crd, err := pn.client.ApiextensionsV1().CustomResourceDefinitions().Get(
					ctx, k8sconstv1alpha1.ClusterwidePrivateNetworkName, metav1.GetOptions{})

				switch {
				case err == nil:
					for _, condition := range crd.Status.Conditions {
						if condition.Type == apiextensionsv1.Established &&
							condition.Status == apiextensionsv1.ConditionTrue {
							resolve.Resolve(synced.CRDSync{})
							return nil
						}
					}

				case !k8serrors.IsNotFound(err):
					return fmt.Errorf("checking ClusterwidePrivateNetwork CRD existence: %w", err)
				}

				select {
				case <-time.After(1 * time.Second):
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}, job.WithRetry(-1, &job.ExponentialBackoff{Min: 1 * time.Second, Max: 30 * time.Second})),
	)

	return promise
}

var privnetMappingAnnotations = map[tables.ProviderName]string{
	tables.ProviderNameVSphere: tables.ProviderNameVSphere + "." + types.PrivateNetworkAnnotationPrefix + "/port-group-name",
}

func (pn *PrivateNetworks) extractMappings(privnet *iso_v1alpha1.ClusterwidePrivateNetwork) []tables.PrivateNetworkMapping {
	mappings := make([]tables.PrivateNetworkMapping, 0, len(privnetMappingAnnotations))
	for provider, key := range privnetMappingAnnotations {
		mappings = append(mappings, tables.PrivateNetworkMapping{
			Provider: provider,
			// Default to the resource name if no explicit mapping is provided.
			ID: cmp.Or(privnet.Annotations[key], privnet.Name),
		})
	}
	return mappings
}
