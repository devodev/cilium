//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package policy

import (
	"context"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/policy/labelfilters"
	k8sSynced "github.com/cilium/cilium/pkg/k8s/synced"
)

// Cell decorates upstream pkg/policy ingestion to intercept imported policies and CiliumCIDRGroups.
//
// It hooks into the upstream policy ingestion using `cell.DecorateAll` to collect metadata about
// CIDRs found in policies and CiliumCIDRGroups. The collected metadata is sent downstream via the
// CIDRQueuer observer.
// In addition, this cell also rewrites imported endpoint selectors in policy to implement the
// label selector behavior expected for private network labels.
var Cell = cell.Group(
	cell.DecorateAll(overridePolicyImporter),
	cell.DecorateAll(overridePolicyIPCacher),
	cell.Invoke(waitForCacheSync),

	labelfilters.Cell,
)

// waitForCacheSync waits for the K8s sync status event. This assumes that policies and cidr groups
// are imported from K8s, and thus if the caches are synced can we safely assume that we've emitted
// all CIDRLabel and CIDRGroupLabels event for the initial policy state.
func waitForCacheSync(cfg config.Config, jg job.Group, cacheStatus k8sSynced.CacheStatus, observer CIDRQueuer) {
	if !cfg.Enabled {
		return
	}

	jg.Add(job.OneShot("wait-for-cache-sync", func(ctx context.Context, health cell.Health) error {
		health.OK("Waiting for cache sync")
		select {
		case <-cacheStatus:
			// Events are enqueued via the blocking PolicyImport or UpsertMetadataBatch calls.
			// The upstream policy ingestor cannot mark its resource as synced (and thus cause
			// CacheStatus to be closed) before the our decorated PolicyImport/UpsertMetadataBatch calls
			// have returned, which guarantees that the observer queue contains all initial resources.
			observer.Queue(EventSynced, CIDRMetadata{})
		case <-ctx.Done():
			return ctx.Err()
		}
		return nil
	}))
}
