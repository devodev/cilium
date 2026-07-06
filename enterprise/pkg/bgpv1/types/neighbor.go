// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package types

import (
	ossTypes "github.com/cilium/cilium/pkg/bgp/types"
)

const (
	DefaultAddPathMaxPaths = 255
)

type EnterpriseNeighbor struct {
	ossTypes.Neighbor
	RouteReflector *NeighborRouteReflector
	AddPath        *NeighborAddPath
	BindInterface  string
}

type NeighborRouteReflector struct {
	Client    bool
	ClusterID string
}

type NeighborAddPath struct {
	SendMax uint32
}
