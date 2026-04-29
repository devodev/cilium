//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package config

import "github.com/cilium/cilium/pkg/identity"

// EndpointFilter evaluates whether passive inspection should be enabled for an
// endpoint. It keeps selector/identity lookups inside the inspection hive so
// datapath config generation only has to consume the final boolean decision.
type EndpointFilter struct {
	cfg           Config
	selectorStore *SelectorStore
}

func NewEndpointFilter(cfg Config, selectorStore *SelectorStore) *EndpointFilter {
	return &EndpointFilter{
		cfg:           cfg,
		selectorStore: selectorStore,
	}
}

func (f *EndpointFilter) EnabledForEndpoint(ep EndpointConfig) bool {
	if f == nil || !f.cfg.Enabled {
		return false
	}

	// Passive inspection mirrors pod endpoint traffic. Do not let the identity
	// selector paths below enable mirroring for the local host endpoint, even
	// when the active selector is wildcard or could match reserved:host.
	if ep.GetIdentity() == identity.ReservedIdentityHost {
		return false
	}

	if selectorEP, ok := any(ep).(SelectorEndpoint); ok {
		if enabled, ok := f.selectorStore.DesiredEnabledForEndpoint(selectorEP); ok {
			return enabled
		}
	}

	if enabled, ok := f.selectorStore.DesiredEnabledForIdentityID(ep.GetIdentity()); ok {
		return enabled
	}

	enabled, _ := ep.GetPropertyValue(PropertyEndpointEnabled).(bool)
	return enabled
}
