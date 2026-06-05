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
	"errors"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
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
	advertisements     store.BGPCPResourceStore[*v1.IsovalentBGPAdvertisement]
	nodeConfigOverride store.BGPCPResourceStore[*v1.IsovalentBGPNodeConfigOverride]
	vrf                store.BGPCPResourceStore[*v1alpha1.IsovalentVRF]
	vrfConfig          store.BGPCPResourceStore[*v1alpha1.IsovalentBGPVRFConfig]

	// for BGP node config, we do not need to trigger reconciliation on changes. So,
	// we use store.Resource instead of store.BGPCPResourceStore.
	nodeConfigStore resource.Store[*v1.IsovalentBGPNodeConfig]

	// BGPv2 OSS resources
	ossClusterConfigStore      resource.Store[*v2.CiliumBGPClusterConfig]
	ossPeerConfigStore         resource.Store[*v2.CiliumBGPPeerConfig]
	ossAdvertStore             resource.Store[*v2.CiliumBGPAdvertisement]
	ossNodeConfigOverrideStore resource.Store[*v2.CiliumBGPNodeConfigOverride]

	// Cilium node resource
	ciliumNode store.BGPCPResourceStore[*v2.CiliumNode]

	// toggle status reporting
	enableStatusReporting bool

	// Default RR peering mode
	defaultRRPeeringAddressFamily v1.RouteReflectorPeeringAddressFamily

	// toggle cee-oss resource mapping
	enableOSSResourceMapping bool
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
	Advertisements     store.BGPCPResourceStore[*v1.IsovalentBGPAdvertisement]
	NodeConfigOverride store.BGPCPResourceStore[*v1.IsovalentBGPNodeConfigOverride]
	VRF                store.BGPCPResourceStore[*v1alpha1.IsovalentVRF]
	VRFConfig          store.BGPCPResourceStore[*v1alpha1.IsovalentBGPVRFConfig]
	NodeConfig         resource.Resource[*v1.IsovalentBGPNodeConfig]

	// BGPv2 OSS Resources
	OSSClusterConfig      resource.Resource[*v2.CiliumBGPClusterConfig]
	OSSPeerConfig         resource.Resource[*v2.CiliumBGPPeerConfig]
	OSSAdvert             resource.Resource[*v2.CiliumBGPAdvertisement]
	OSSNodeConfigOverride resource.Resource[*v2.CiliumBGPNodeConfigOverride]

	// Cilium node resource
	CiliumNode store.BGPCPResourceStore[*v2.CiliumNode]
}

func RegisterBGPResourceMapper(in BGPResourceManagerParams) error {
	if !in.Config.Enabled {
		return nil
	}

	m := &BGPResourceMapper{
		logger:                   in.Logger,
		jobs:                     in.Jobs,
		signal:                   in.Signal,
		clientSet:                in.ClientSet,
		dc:                       in.DaemonCfg,
		metrics:                  in.Metrics,
		clusterConfig:            in.ClusterConfig,
		peerConfig:               in.PeerConfig,
		advertisements:           in.Advertisements,
		nodeConfigOverride:       in.NodeConfigOverride,
		ciliumNode:               in.CiliumNode,
		vrf:                      in.VRF,
		vrfConfig:                in.VRFConfig,
		enableStatusReporting:    in.Config.StatusReportEnabled,
		enableOSSResourceMapping: in.DaemonCfg.BGPControlPlaneEnabled(),
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

			// initialize oss stores
			if m.enableOSSResourceMapping {
				m.ossClusterConfigStore, err = in.OSSClusterConfig.Store(ctx)
				if err != nil {
					return err
				}
				m.ossPeerConfigStore, err = in.OSSPeerConfig.Store(ctx)
				if err != nil {
					return err
				}
				m.ossAdvertStore, err = in.OSSAdvert.Store(ctx)
				if err != nil {
					return err
				}
				m.ossNodeConfigOverrideStore, err = in.OSSNodeConfigOverride.Store(ctx)
				if err != nil {
					return err
				}
			}

			m.logger.Info("Enterprise BGPv2 control plane operator started")
			m.Run(ctx)
			return
		}),
	)

	return nil
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
	var err error

	reconcileStart := time.Now()

	if m.enableOSSResourceMapping {
		err = m.reconcileMappings(ctx)
	}

	rErr := m.reconcileClusterConfigs(ctx)
	if rErr != nil {
		err = errors.Join(err, rErr)
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
