// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package externalendpoints

import (
	"context"
	"log/slog"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/enterprise/operator/pkg/privnet/externalendpoints/providers"
	"github.com/cilium/cilium/enterprise/operator/pkg/privnet/tables"
	"github.com/cilium/cilium/enterprise/pkg/privnet/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type instanceHandler struct {
	providerType string
	instanceName providers.Name

	logger  *slog.Logger
	db      *statedb.DB
	table   statedb.RWTable[*tables.ExternalEndpoint]
	pending *pendingProviders
}

func (i *instanceHandler) handleChangeEventBatch(ctx context.Context, events providers.EndpointChangeBatch) error {
	txn := i.db.WriteTxn(i.table)
	defer txn.Commit()

	i.logger.Debug("Received external endpoint change event", logfields.NumEvents, len(events))
	for _, event := range events {
		switch event.Op {
		case providers.EndpointOpUpsert:
			if event.Properties == nil {
				i.logger.Error("BUG: Received an external endpoint upsert event without properties. "+
					"Please report this bug to Cilium developers.",
					logfields.Endpoint, tables.ExternalEndpointKey(event.Namespace, event.Name))
				continue
			}
			i.upsertEndpoint(txn, event.Namespace, event.Name, event.Properties)
		case providers.EndpointOpDelete:
			i.deleteEndpoint(txn, event.Namespace, event.Name)
		case providers.EndpointOpSync:
			i.pending.Synced(txn, i.instanceName)
		default:
			i.logger.Error("BUG: Received an external endpoint change event with an invalid op. "+
				"Please report this bug to Cilium developers.",
				logfields.Operation, event.Op)
		}
	}

	return nil
}

func (i *instanceHandler) upsertEndpoint(txn statedb.WriteTxn, namespace string, name string, prop *types.EndpointProperties) {
	ep, _, found := i.table.Get(txn, tables.ExternalEndpointByName(namespace, name))
	if found {
		// Checking permission of the provider instance to update this object
		if ep.Owner != string(i.instanceName) {
			i.logger.Error("Provider instance attempted to overwrite endpoint owned by another instance",
				logfields.Endpoint, tables.ExternalEndpointKey(namespace, name),
				logfields.InstanceID, i.instanceName,
				logfields.Owner, ep.Owner,
			)
			return
		}

		// Checking if an update is needed
		if ep.EndpointProperties.Equal(prop) {
			// skipping no-op update
			return
		}
	}

	i.table.Insert(txn, &tables.ExternalEndpoint{
		Name:               name,
		Namespace:          namespace,
		EndpointProperties: *prop,
		Owner:              string(i.instanceName),
		Status:             reconciler.StatusPending(),
	})
}

func (i *instanceHandler) deleteEndpoint(txn statedb.WriteTxn, namespace string, name string) {
	ep, _, found := i.table.Get(txn, tables.ExternalEndpointByName(namespace, name))
	if !found {
		return
	}

	// Checking permission of the provider instance to update this object
	if ep.Owner != string(i.instanceName) {
		i.logger.Error("Provider instance attempted to delete endpoint owned by another instance",
			logfields.Endpoint, ep.K8sNamespaceAndName(),
		)
		return
	}

	i.table.Delete(txn, ep)
}
