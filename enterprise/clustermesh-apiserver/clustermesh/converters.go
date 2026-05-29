// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package clustermesh

import (
	"iter"
	"log/slog"

	"github.com/cilium/cilium/clustermesh-apiserver/clustermesh"
	pncfg "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	privnet "github.com/cilium/cilium/enterprise/pkg/privnet/kvstore"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	iso_api_v1a1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/kvstore/store"
	cslices "github.com/cilium/cilium/pkg/slices"
)

// ----- PrivateNetworkEndpointSlice ----- //

func newPrivateNetworkEndpointSliceOptions(cfg pncfg.Common) clustermesh.Options[*iso_api_v1a1.PrivateNetworkEndpointSlice] {
	return clustermesh.Options[*iso_api_v1a1.PrivateNetworkEndpointSlice]{
		Enabled:    cfg.Enabled,
		Resource:   "PrivateNetworkEndpointSlice",
		Prefix:     privnet.EndpointsPrefix,
		Namespaced: true,
	}
}

func newPrivateNetworkEndpointSliceConverter(logger *slog.Logger, cinfo cmtypes.ClusterInfo) clustermesh.Converter[*iso_api_v1a1.PrivateNetworkEndpointSlice] {
	return clustermesh.NewCachedConverter(privateNetworkEndpointSliceMapper(logger, cinfo))
}

func privateNetworkEndpointSliceMapper(logger *slog.Logger, cinfo cmtypes.ClusterInfo) func(slice *iso_api_v1a1.PrivateNetworkEndpointSlice) iter.Seq[store.Key] {
	return func(slice *iso_api_v1a1.PrivateNetworkEndpointSlice) iter.Seq[store.Key] {
		return cslices.MapIter(
			privnet.EndpointsFromEndpointSlice(logger, cinfo.Name, slice),
			func(ep *privnet.Endpoint) store.Key { return ep },
		)
	}
}
