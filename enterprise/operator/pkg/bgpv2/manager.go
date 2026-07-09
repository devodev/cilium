// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package bgpv2

import (
	"context"
	"fmt"
	"log/slog"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	corev1 "k8s.io/api/core/v1"
	crdv1 "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8s_types "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/pkg/bgp/agent/signaler"
	"github.com/cilium/cilium/pkg/bgp/manager/store"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

var (
	// maxErrorLen is the maximum length of error message to be logged.
	maxErrorLen = 1024
)

type BGPResourceMapper struct {
	logger    *slog.Logger
	jobs      job.Group
	signal    *signaler.BGPCPSignaler
	clientSet client.Clientset
	dc        *option.DaemonConfig
	metrics   *OperatorMetrics

	// BGPv2 Resources
	clusterConfig      store.BGPCPResourceStore[*v1.IsovalentBGPClusterConfig]
	peerConfig         store.BGPCPResourceStore[*v1.IsovalentBGPPeerConfig]
	nodeConfigOverride store.BGPCPResourceStore[*v1.IsovalentBGPNodeConfigOverride]
	advertisement      store.BGPCPResourceStore[*v1.IsovalentBGPAdvertisement]
	vrf                store.BGPCPResourceStore[*v1alpha1.IsovalentVRF]
	vrfConfig          store.BGPCPResourceStore[*v1alpha1.IsovalentBGPVRFConfig]

	// for BGP node config, we do not need to trigger reconciliation on changes. So,
	// we use store.Resource instead of store.BGPCPResourceStore.
	nodeConfigStore resource.Store[*v1.IsovalentBGPNodeConfig]

	// Cilium node resource
	ciliumNode store.BGPCPResourceStore[*v2.CiliumNode]

	storesInitialized chan struct{}

	// toggle status reporting
	enableStatusReporting bool

	// Default RR peering mode
	defaultRRPeeringAddressFamily v1.RouteReflectorPeeringAddressFamily
}

type BGPResourceManagerParams struct {
	cell.In

	Logger    *slog.Logger
	Jobs      job.Group
	Config    config.Config
	Signal    *signaler.BGPCPSignaler
	ClientSet client.Clientset
	DaemonCfg *option.DaemonConfig
	Metrics   *OperatorMetrics

	// BGPv2 Resources
	ClusterConfig      store.BGPCPResourceStore[*v1.IsovalentBGPClusterConfig]
	PeerConfig         store.BGPCPResourceStore[*v1.IsovalentBGPPeerConfig]
	NodeConfigOverride store.BGPCPResourceStore[*v1.IsovalentBGPNodeConfigOverride]
	Advertisement      store.BGPCPResourceStore[*v1.IsovalentBGPAdvertisement]
	VRF                store.BGPCPResourceStore[*v1alpha1.IsovalentVRF]
	VRFConfig          store.BGPCPResourceStore[*v1alpha1.IsovalentBGPVRFConfig]
	NodeConfig         resource.Resource[*v1.IsovalentBGPNodeConfig]

	// Cilium node resource
	CiliumNode store.BGPCPResourceStore[*v2.CiliumNode]
}

// Interface to use during version migration
type listPatcher interface {
	List() ([]string, error)
	Patch(context.Context, string, k8s_types.PatchType, []byte, metav1.PatchOptions, ...string) (any, error)
}

// Wrapper around resource.Store and v1.IsovalentBGP*Interface
type resourceClient[T metav1.Object] struct {
	lister  func() ([]T, error)
	patcher func(context.Context, string, k8s_types.PatchType, []byte, metav1.PatchOptions, ...string) (T, error)
}

func (r resourceClient[T]) List() ([]string, error) {
	names := []string{}
	items, err := r.lister()

	if err != nil {
		return nil, err
	}

	for _, item := range items {
		names = append(names, item.GetName())
	}

	return names, nil
}

func (r resourceClient[T]) Patch(ctx context.Context, name string, pt k8s_types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (any, error) {
	return r.patcher(ctx, name, pt, data, opts, subresources...)
}

// Wrapper around resource.Store to be able to used as store.BGPCPResourceStore
func (m *BGPResourceMapper) nodeConfigStoreListWrapper() ([]*v1.IsovalentBGPNodeConfig, error) {
	return m.nodeConfigStore.List(), nil
}

func RegisterBGPResourceMapper(in BGPResourceManagerParams) error {
	if !in.Config.Enabled {
		return nil
	}

	m := &BGPResourceMapper{
		logger:                in.Logger,
		jobs:                  in.Jobs,
		signal:                in.Signal,
		clientSet:             in.ClientSet,
		dc:                    in.DaemonCfg,
		metrics:               in.Metrics,
		clusterConfig:         in.ClusterConfig,
		peerConfig:            in.PeerConfig,
		nodeConfigOverride:    in.NodeConfigOverride,
		advertisement:         in.Advertisement,
		ciliumNode:            in.CiliumNode,
		vrf:                   in.VRF,
		vrfConfig:             in.VRFConfig,
		enableStatusReporting: in.Config.StatusReportEnabled,
		storesInitialized:     make(chan struct{}, 1),
	}

	switch {
	case in.DaemonCfg.EnableIPv4 && !in.DaemonCfg.EnableIPv6:
		m.defaultRRPeeringAddressFamily = v1.RouteReflectorPeeringAddressFamilyIPv4Only
	case !in.DaemonCfg.EnableIPv4 && in.DaemonCfg.EnableIPv6:
		m.defaultRRPeeringAddressFamily = v1.RouteReflectorPeeringAddressFamilyIPv6Only
	case in.DaemonCfg.EnableIPv4 && in.DaemonCfg.EnableIPv6:
		m.defaultRRPeeringAddressFamily = v1.RouteReflectorPeeringAddressFamilyDual
	}

	in.Jobs.Add(
		job.OneShot("enterprise-bgpv2-operator-main", func(ctx context.Context, health cell.Health) (err error) {
			// initialize node config store
			m.nodeConfigStore, err = in.NodeConfig.Store(ctx)
			if err != nil {
				return err
			}

			m.logger.Info("Enterprise BGPv2 control plane operator started")
			close(m.storesInitialized)
			m.Run(ctx)
			return
		}),

		// If the storedVersion contains v1alpha1 then etcd probably contains BGP resource as v1alpha1.
		// This can prevent deleting the v1alpha1.
		// The solution is to add an empty patch to the resource so etcd force to update and store it with the new version.
		// After that we can delete the v1alpha1 from the storedVersion.
		job.OneShot("enterprise-bgpv2-operator-crd-storage-version-migrator", func(ctx context.Context, health cell.Health) error {
			<-m.storesInitialized

			crdClient := m.clientSet.ApiextensionsV1().CustomResourceDefinitions()
			resourceClients := map[string]listPatcher{
				"isovalentbgpclusterconfigs.isovalent.com": resourceClient[*v1.IsovalentBGPClusterConfig]{
					lister:  m.clusterConfig.List,
					patcher: m.clientSet.IsovalentV1().IsovalentBGPClusterConfigs().Patch,
				},
				"isovalentbgppeerconfigs.isovalent.com": resourceClient[*v1.IsovalentBGPPeerConfig]{
					lister:  m.peerConfig.List,
					patcher: m.clientSet.IsovalentV1().IsovalentBGPPeerConfigs().Patch,
				},
				"isovalentbgpnodeconfigoverrides.isovalent.com": resourceClient[*v1.IsovalentBGPNodeConfigOverride]{
					lister:  m.nodeConfigOverride.List,
					patcher: m.clientSet.IsovalentV1().IsovalentBGPNodeConfigOverrides().Patch,
				},
				"isovalentbgpadvertisements.isovalent.com": resourceClient[*v1.IsovalentBGPAdvertisement]{
					lister:  m.advertisement.List,
					patcher: m.clientSet.IsovalentV1().IsovalentBGPAdvertisements().Patch,
				},
				"isovalentbgpnodeconfigs.isovalent.com": resourceClient[*v1.IsovalentBGPNodeConfig]{
					lister:  m.nodeConfigStoreListWrapper,
					patcher: m.clientSet.IsovalentV1().IsovalentBGPNodeConfigs().Patch,
				},
			}
			versionFromMigrate := "v1alpha1"

			for crdName, client := range resourceClients {
				migrated, err := storageVersionMigrator(ctx, crdClient, crdName, client, versionFromMigrate)

				if err != nil {
					return err
				}

				if migrated {
					m.logger.Debug("CRD migrated", logfields.ResourceName, crdName)
				}
			}

			return nil
		}, job.WithRetry(3, &job.ExponentialBackoff{Min: 500 * time.Millisecond, Max: 3 * time.Second})),
	)

	return nil
}

func storageVersionMigrator(ctx context.Context, crdClient crdv1.CustomResourceDefinitionInterface, crdName string, client listPatcher, versionFromMigrate string) (bool, error) {
	crdDef, err := crdClient.Get(ctx, crdName, metav1.GetOptions{})

	if err != nil {
		return false, err
	}

	if slices.Contains(crdDef.Status.StoredVersions, versionFromMigrate) {
		items, err := client.List()

		if err != nil {
			return false, err
		}

		for _, name := range items {
			if _, err := client.Patch(ctx, name, k8s_types.MergePatchType, []byte("{}"), metav1.PatchOptions{}); err != nil {
				return false, err
			}
		}

		storedVersions := slices.DeleteFunc(crdDef.Status.StoredVersions, func(s string) bool {
			return s == versionFromMigrate
		})
		crdDef.Status.StoredVersions = storedVersions
		if _, err := crdClient.UpdateStatus(ctx, crdDef, metav1.UpdateOptions{}); err != nil {
			return false, err
		}

		return true, nil
	}

	return false, nil
}

func (m *BGPResourceMapper) Run(ctx context.Context) {
	// trigger initial reconcile
	m.signal.Event(struct{}{})

	for {
		select {
		case <-ctx.Done():
			m.logger.Info("Enterprise BGPv2 control plane operator stopped")
			return
		case <-m.signal.Sig:
			err := m.reconcileWithRetry(ctx)
			if err != nil {
				m.logger.Error("BGP reconciliation failed", logfields.Error, err)
			} else {
				m.logger.Debug("BGP reconciliation successful")
			}
		}
	}
}

func (m *BGPResourceMapper) reconcileWithRetry(ctx context.Context) error {
	// retry options used in reconcileWithRetry method.
	// steps will repeat for ~8.5 minutes.
	bo := wait.Backoff{
		Duration: 1 * time.Second,
		Factor:   2,
		Jitter:   0,
		Steps:    10,
		Cap:      0,
	}
	attempts := 0

	retryFn := func(ctx context.Context) (bool, error) {
		attempts++

		err := m.reconcile(ctx)
		if err != nil {
			if isRetryableError(err) && attempts%5 != 0 {
				// for retryable error print warning only every 5th attempt
				m.logger.Debug("Transient BGP reconciliation error", logfields.Error, TrimError(err, maxErrorLen))
			} else {
				// log warning, continue retry
				m.logger.Warn("BGP reconciliation error", logfields.Error, TrimError(err, maxErrorLen))
			}
			return false, nil
		}

		// no error, stop retry
		return true, nil
	}

	return wait.ExponentialBackoffWithContext(ctx, bo, retryFn)
}

func (m *BGPResourceMapper) reconcile(ctx context.Context) error {
	reconcileStart := time.Now()

	err := m.reconcileClusterConfigs(ctx)
	if err != nil {
		m.metrics.ReconcileErrorsTotal.WithLabelValues(v1.IsovalentBGPClusterConfigKindDefinition).Inc()
	}

	m.metrics.ReconcileRunDuration.WithLabelValues().Observe(time.Since(reconcileStart).Seconds())
	return err
}

// TrimError trims error message to maxLen.
func TrimError(err error, maxLen int) error {
	if err == nil {
		return nil
	}

	if len(err.Error()) > maxLen {
		return fmt.Errorf("%s... ", err.Error()[:maxLen])
	}
	return err
}

// isRetryableError returns true if the error returned by reconcile
// is likely transient, and will be addressed by a subsequent iteration.
func isRetryableError(err error) bool {
	return k8serrors.IsAlreadyExists(err) ||
		k8serrors.IsConflict(err) ||
		k8serrors.IsNotFound(err) ||
		(k8serrors.IsForbidden(err) && k8serrors.HasStatusCause(err, corev1.NamespaceTerminatingCause))
}
