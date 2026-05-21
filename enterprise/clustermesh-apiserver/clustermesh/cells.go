//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package clustermesh

import (
	"github.com/cilium/hive/cell"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/clustermesh-apiserver/clustermesh"
	"github.com/cilium/cilium/clustermesh-apiserver/common"
	"github.com/cilium/cilium/clustermesh-apiserver/syncstate"
	entcmk8s "github.com/cilium/cilium/enterprise/clustermesh-apiserver/clustermesh/k8s"
	pnocfg "github.com/cilium/cilium/enterprise/operator/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/clustermesh/clustercfg"
	"github.com/cilium/cilium/enterprise/pkg/clustermesh/phantom"
	pncfg "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	iso_api_v1a1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/lock"
)

var (
	EnterpriseClusterMesh = cell.Module(
		"enterprise-clustermesh",
		"Cilium ClusterMesh Enterprise",

		common.Cell,
		clustermesh.Cell,

		entcmk8s.ResourcesCell,

		// Configure the enterprise-specific bits of the CiliumClusterConfig.
		clustercfg.Cell,

		// Override service converter to pre-process phantom services before
		// k8s-to-kvstore synchronization.
		phantom.Cell,

		EnterpriseSynchronization,
	)

	EnterpriseSynchronization = cell.Module(
		"enterprise-clustermesh-sync",
		"Synchronize information from Kubernetes to KVStore",

		cell.Config(pncfg.DefaultCommon),
		privateNetworkEndpointSlices,
	)

	privateNetworkEndpointSlices = cell.Group(
		cell.Provide(
			func(cfg pncfg.Common) *clustercfg.PrivateNetworksCapability {
				return ptr.To(clustercfg.PrivateNetworksCapability(cfg.Enabled))
			},

			func(cfg pncfg.Common) synced.CRDSyncResourceNamesOut {
				var names []string

				if cfg.Enabled {
					names = append(names, synced.CRDResourceName(iso_api_v1a1.PrivateNetworkEndpointSliceName))
				}

				return synced.NewCRDSyncResourceNamesOut(names...)
			},

			newPrivateNetworkEndpointSliceOptions,
			newPrivateNetworkEndpointSliceConverter,
			newPrivateNetworkEndpointSliceNamespacer,
		),
		cell.Invoke(clustermesh.RegisterSynchronizer[*iso_api_v1a1.PrivateNetworkEndpointSlice]),
	)

	// EnterpriseOperator is the cell that gets registered by the Cilium operator,
	// and takes care of synchronizing the resources needed by Cluster Mesh into
	// the Cilium KVStore instance, when Cilium runs in KVStore mode.
	EnterpriseOperator = cell.Module(
		"enterprise-clustermesh-sync",
		"Synchronize information from Kubernetes to KVStore",

		cell.ProvidePrivate(
			// Provide the SyncState dependency expected by the synchronization
			// logic, which is not actually used by the operator.
			func() syncstate.SyncState {
				return syncstate.SyncState{
					StoppableWaitGroup: lock.NewStoppableWaitGroup(),
				}
			},

			// Adapt the operator private network configuration.
			func(cfg pnocfg.Config) pncfg.Common { return cfg.Common },
		),

		cell.Provide(
			entcmk8s.PrivateNetworkEndpointSliceResource,
		),

		cell.Decorate(
			// Enable synchronization only if the operator is connected to the KVStore.
			func(
				client kvstore.Client, opts clustermesh.Options[*iso_api_v1a1.PrivateNetworkEndpointSlice],
			) clustermesh.Options[*iso_api_v1a1.PrivateNetworkEndpointSlice] {
				opts.Enabled = opts.Enabled && client.IsEnabled()
				return opts
			},

			privateNetworkEndpointSlices,
		),
	)
)
