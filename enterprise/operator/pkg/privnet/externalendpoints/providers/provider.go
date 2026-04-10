// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package providers

import (
	"context"
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/cilium/stream"

	"github.com/cilium/cilium/enterprise/operator/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/types"
)

// Provider is the main interface to implement when creating a new external endpoint provider
type Provider interface {
	NewInstance(ctx context.Context, config Config) (Instance, error)
}

type EndpointOp string

const (
	EndpointOpUpsert EndpointOp = "upsert"
	EndpointOpDelete EndpointOp = "delete"
	EndpointOpSync   EndpointOp = "sync"
)

// EndpointChange is used by a provider to send updates to the downstream StateDB table.
// The downstream StateDB table is only initialized once a EndpointOpSync event is received.
type EndpointChange struct {
	Op         EndpointOp
	Name       string
	Namespace  string
	Properties *types.EndpointProperties // only for "upsert"
}

type EndpointChangeBatch []EndpointChange

type Instance interface {
	// Start should start this instance of the provider.
	Start(cell.HookContext) (stream.Observable[EndpointChangeBatch], error)
	Stop(cell.HookContext)
}

// Registry contains all known external endpoint providers.
type Registry struct {
	cfg       config.Config
	providers map[string]Provider
}

func NewRegistry(cfg config.Config) *Registry {
	return &Registry{
		cfg:       cfg,
		providers: make(map[string]Provider),
	}
}

// RegisterProvider registers a new external endpoint provider.
func (r *Registry) RegisterProvider(name string, provider Provider) error {
	if !r.cfg.EnabledWithAutoExternalEndpoints() {
		return fmt.Errorf("automatic creation of external endpoints is disabled, cannot register provider %q", name)
	}

	_, ok := r.providers[name]
	if ok {
		return fmt.Errorf("provider %q already registered", name)
	}

	r.providers[name] = provider
	return nil
}

// GetProvider returns the provider with the given name.
func (r *Registry) GetProvider(providerName string) (Provider, error) {
	provider, ok := r.providers[providerName]
	if !ok {
		return nil, fmt.Errorf("provider %q not found", providerName)
	}

	return provider, nil
}
