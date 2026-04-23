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

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
)

// RefreshByHost re-emits the current IPCache entries that use the provided host IP.
// Returns the number of refreshed entries.
// This is used by enterprise/pkg/tunnelip to re-emit all IPCache entries for
// a host IP whose tunnel mapping is now known and can be now inserted into the
// BPF map.
func (ipc *IPCache) RefreshByHost(hostIP net.IP) int {
	if hostIP == nil {
		return 0
	}

	ipc.mutex.RLock()
	defer ipc.mutex.RUnlock()

	count := 0
	for ip, identity := range ipc.ipToIdentityCache {
		if identity.shadowed {
			continue
		}

		entryHostIP, encryptKey := ipc.getHostIPCacheRLocked(ip)
		if !entryHostIP.Equal(hostIP) {
			continue
		}

		var k8sMeta *K8sMetadata
		if meta := ipc.getK8sMetadata(ip); meta != nil {
			metaCopy := *meta
			k8sMeta = &metaCopy
		}

		endpointFlags := ipc.getEndpointFlagsRLocked(ip)
		cidrCluster, err := cmtypes.ParsePrefixCluster(ip)
		if err != nil {
			if addrCluster, err := cmtypes.ParseAddrCluster(ip); err != nil { // Endpoint IP or Endpoint IP with ClusterID
				continue
			} else {
				cidrCluster = addrCluster.AsPrefixCluster()
			}
		}

		for _, listener := range ipc.listeners {
			listener.OnIPIdentityCacheChange(
				Upsert,
				cidrCluster,
				entryHostIP,
				entryHostIP,
				&identity,
				identity,
				encryptKey,
				k8sMeta,
				endpointFlags,
			)
		}
		count++
	}

	return count
}
