//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package ipcache

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	identityPkg "github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/source"
)

type recordingListener struct {
	events []recordedEvent
}

type recordedEvent struct {
	modType       CacheModification
	cidrCluster   cmtypes.PrefixCluster
	newHostIP     net.IP
	newID         Identity
	encryptKey    uint8
	k8sMeta       *K8sMetadata
	endpointFlags uint8
}

func (rl *recordingListener) OnIPIdentityCacheChange(modType CacheModification,
	cidrCluster cmtypes.PrefixCluster, oldHostIP, newHostIP net.IP, oldID *Identity,
	newID Identity, encryptKey uint8, k8sMeta *K8sMetadata, endpointFlags uint8) {
	rl.events = append(rl.events, recordedEvent{
		modType:       modType,
		cidrCluster:   cidrCluster,
		newHostIP:     newHostIP,
		newID:         newID,
		encryptKey:    encryptKey,
		k8sMeta:       k8sMeta,
		endpointFlags: endpointFlags,
	})
}

func TestIPCacheRefreshByHost(t *testing.T) {
	t.Parallel()

	s := setupIPCacheTestSuite(t)
	listener := &recordingListener{}
	s.IPIdentityCache.AddListener(listener)

	hostIP := net.ParseIP("192.0.2.10")
	otherHostIP := net.ParseIP("192.0.2.11")
	meta := &K8sMetadata{
		Namespace: "default",
		PodName:   "pod-a",
	}

	_, err := s.IPIdentityCache.Upsert("10.0.0.1", hostIP, 7, meta, Identity{
		ID:     identityPkg.NumericIdentity(101),
		Source: source.KVStore,
	})
	require.NoError(t, err)

	_, err = s.IPIdentityCache.Upsert("10.0.0.2", otherHostIP, 9, nil, Identity{
		ID:     identityPkg.NumericIdentity(102),
		Source: source.KVStore,
	})
	require.NoError(t, err)

	listener.events = nil
	count := s.IPIdentityCache.RefreshByHost(hostIP)
	require.Equal(t, 1, count)
	require.Len(t, listener.events, 1)

	event := listener.events[0]
	require.Equal(t, Upsert, event.modType)
	require.Equal(t, cmtypes.MustParsePrefixCluster("10.0.0.1/32"), event.cidrCluster)
	require.Equal(t, hostIP, event.newHostIP)
	require.Equal(t, identityPkg.NumericIdentity(101), event.newID.ID)
	require.Equal(t, uint8(7), event.encryptKey)
	require.NotNil(t, event.k8sMeta)
	require.Equal(t, "default", event.k8sMeta.Namespace)
	require.Equal(t, "pod-a", event.k8sMeta.PodName)

	listener.events = nil
	count = s.IPIdentityCache.RefreshByHost(net.ParseIP("192.0.2.99"))
	require.Zero(t, count)
	require.Empty(t, listener.events)
}
