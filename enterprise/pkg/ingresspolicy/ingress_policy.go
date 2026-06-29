// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Isovalent

package ingresspolicy

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/pkg/ciliumenvoyconfig/types"
	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	ciliumio "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
)

const (
	subsystem              = "ingress-policy"
	regenEndpointPolicyJob = "enterprise-endpoint-policy-periodic-regeneration"
)

const (
	// LabelSourceIngress is the source of the ingress policy labels.
	// This is to avoid any potential conflict with k8s labels, which can be manipulated by users.
	LabelSourceIngress = "ingress"

	// LabelNameIngress is the name of the ingress policy labels.
	LabelNameIngress = "name"
)

// ingressPolicyManager is responsible for managing the Ingress Policy for CiliumEnvoyConfig
type ingressPolicyManager struct {
	mutex lock.RWMutex

	logger *slog.Logger

	// cacheIdentityAllocator is used to look up the identity for the Ingress Policy
	cacheIdentityAllocator cache.IdentityAllocator

	// policyRepository is used to get/create the selector policy for the Ingress Policy
	policyRepository policy.PolicyRepository

	// identityManager is used to add the ingress identity for the Ingress Policy.
	identityManager identitymanager.IDManager

	// xdsServer is used to send the distilled policy to the xDS server
	xdsServer envoy.XDSServer

	// ingressIdentities is the cache to store the identity for the Ingress Policy
	ingressIdentities map[resource.Key]*identity.Identity
	// ingressPolicies is the cache to store the Ingress Policy
	ingressPolicies map[resource.Key]*IngressPolicy
}

type ingressPolicyParam struct {
	cell.In

	Logger   *slog.Logger
	JobGroup job.Group

	Config types.CECPolicyConfig

	CacheIdentityAllocator cache.IdentityAllocator
	EndpointPolicyManager  endpointmanager.PolicyUpdateCallbackManager
	PolicyRepository       policy.PolicyRepository
	IdentityManager        identitymanager.IDManager
	XdsServer              envoy.XDSServer
}

type Updater interface {
	EnsureIngressPolicy(ctx context.Context, key resource.Key, resourceLabels map[string]string) error
	DeleteIngressPolicy(ctx context.Context, key resource.Key, resourceLabels map[string]string) error
}

func newIngressPolicyManager(params ingressPolicyParam) Updater {
	p := &ingressPolicyManager{
		logger:                 params.Logger,
		cacheIdentityAllocator: params.CacheIdentityAllocator,
		policyRepository:       params.PolicyRepository,
		identityManager:        params.IdentityManager,
		xdsServer:              params.XdsServer,
		ingressIdentities:      make(map[resource.Key]*identity.Identity),
		ingressPolicies:        make(map[resource.Key]*IngressPolicy),
	}

	// Register the policy update callback with the endpoint manager
	params.EndpointPolicyManager.RegisterPolicyUpdateCallback(subsystem, p.policyUpdateCallback)

	// Register the periodic regeneration job for the endpoint policy
	params.JobGroup.Add(job.Timer(regenEndpointPolicyJob, func(ctx context.Context) error {
		return p.policyUpdateCallback(nil, false)
	}, params.Config.RegenInterval))

	return p
}

// EnsureIngressPolicy will create or use existing selector policy for a respective Identity, and then send the
// distilled policy to the xDS server.
func (m *ingressPolicyManager) EnsureIngressPolicy(ctx context.Context, key resource.Key, resourceLabels map[string]string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Lookup for existing identity in the cache or allocate a new identity.
	ingressIdentity, err := m.ensureIdentityLocked(ctx, key, resourceLabels)
	if err != nil || ingressIdentity == nil {
		return fmt.Errorf("failed to ensure identity %s %w", key, err)
	}

	if existingPolicy, ok := m.ingressPolicies[key]; ok {
		m.logger.Debug("Existing policy",
			logfields.ID, existingPolicy.GetID(),
			logfields.Identity, ingressIdentity.ID.Uint32())
		if existingPolicy.GetID() == uint64(ingressIdentity.ID.Uint32()) {
			m.logger.Debug("Using the existing policy", logfields.Identity, ingressIdentity.ID.Uint32())
			return m.policyUpdateCallbackLocked(key, existingPolicy, false)
		} else {
			// Perform the policy cleanup for the old policy if it exists.
			// This should be done after the new policy is created.
			defer func(p *IngressPolicy) {
				m.logger.Debug("Cleaning up old policy", logfields.PolicyID, p.GetID())
				if p.desiredPolicy != nil {
					p.desiredPolicy.Ready()
					p.desiredPolicy.Detach(m.logger)
				}
				m.xdsServer.RemoveNetworkPolicy(p)
			}(existingPolicy)
		}
	}

	m.identityManager.Add(ingressIdentity)

	// make sure the new identity is populated in the selector cache immediately
	wg := &sync.WaitGroup{}
	m.policyRepository.GetSelectorCache().UpdateIdentities(identity.IdentityMap{
		ingressIdentity.ID: ingressIdentity.LabelArray,
	}, nil, wg)
	wg.Wait()

	// Create a new selector policy for the identity.
	m.logger.Debug("Creating new selector policy", logfields.Identity, ingressIdentity.ID.Uint32())
	selectorPolicy, rev, err := m.policyRepository.GetSelectorPolicy(ingressIdentity, 0, NewIngressPolicyStats(), uint64(ingressIdentity.ID))
	if err != nil {
		return fmt.Errorf("failed to get selector policy %s %w", key, err)
	}

	// Create a new Ingress Policy.
	p := NewIngressPolicy(m.logger, ingressIdentity.ID, key.String(), selectorPolicy, rev)
	m.ingressPolicies[key] = p
	defer p.desiredPolicy.Ready()

	return m.syncIngressPolicy(ctx, p)
}

// DeleteIngressPolicy will remove the network policy from the xDS server.
// Additionally, the identity and policy will be removed from the cache.
func (m *ingressPolicyManager) DeleteIngressPolicy(ctx context.Context, key resource.Key, resourceLabels map[string]string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if curr, exists := m.ingressIdentities[key]; exists {
		_, err := m.cacheIdentityAllocator.Release(ctx, curr, true)
		if err != nil {
			return fmt.Errorf("failed to release identity %s %w", key, err)
		}
		delete(m.ingressIdentities, key)

		m.identityManager.Remove(curr)
	}

	if p, exists := m.ingressPolicies[key]; exists {
		if p.desiredPolicy != nil {
			p.desiredPolicy.Ready()
			p.desiredPolicy.Detach(m.logger)
		}
		m.xdsServer.RemoveNetworkPolicy(p)
		delete(m.ingressPolicies, key)
	}

	return nil
}

// ensureIdentityLocked will ensure that the identity is allocated for the given resource labels.
//
// Caller MUST hold the write lock.
func (m *ingressPolicyManager) ensureIdentityLocked(ctx context.Context, key resource.Key, resourceLabels map[string]string) (*identity.Identity, error) {
	desiredLabels := m.getIngressLabels(key, resourceLabels)
	currIdentity, exists := m.ingressIdentities[key]
	if exists && len(currIdentity.LabelArray) == len(desiredLabels) && currIdentity.LabelArray.Contains(desiredLabels) {
		return currIdentity, nil
	}

	m.logger.Debug("Previous allocated identity",
		logfields.Resource, key,
		logfields.Identity, currIdentity)
	id := identity.InvalidIdentity
	if exists {
		id = currIdentity.ID
	}

	res, allocated, err := m.cacheIdentityAllocator.AllocateIdentity(ctx, desiredLabels.Labels(), true, id)
	if err != nil {
		return nil, fmt.Errorf("failed to allocate identity %s %w", key, err)
	}
	defer func() {
		// Release the old identity if new identity is allocated and the current identity is not nil.
		if allocated && currIdentity != nil {
			_, err = m.cacheIdentityAllocator.Release(ctx, currIdentity, true)
			if err != nil {
				m.logger.Error("Failed to release old identity",
					logfields.Resource, key,
					logfields.Identity, currIdentity,
					logfields.Error, err)
			}
		}
	}()
	m.ingressIdentities[key] = res
	m.logger.Debug("Allocated identity",
		logfields.Resource, key,
		logfields.Identity, res.ID,
		logfields.Labels, res.LabelArray)
	return res, nil
}

// syncIngressPolicy updates the Envoy Network Policy. Caller is responsible for managing 'p' so
// that it has a valid version when this is called. Caller is also responsible for releasing
// resouces after this call has completed.
func (m *ingressPolicyManager) syncIngressPolicy(ctx context.Context, p *IngressPolicy) error {
	m.logger.Debug("Sync network policy",
		logfields.Name, p.GetPolicyNames(),
		logfields.Ingress, p.GetDesiredPolicy().SelectorPolicy.IngressPolicyEnabled,
		logfields.Egress, p.GetDesiredPolicy().SelectorPolicy.EgressPolicyEnabled)

	if err, rf, _ := m.xdsServer.UpdateNetworkPolicy(p, p.GetDesiredPolicy(), nil); err != nil {
		m.logger.Error("Failed to update network policy",
			logfields.Name, p.GetPolicyNames(),
			logfields.Error, err)
		if revertErr := rf(); revertErr != nil {
			m.logger.Error("Failed to revert network policy",
				logfields.Name, p.GetPolicyNames(),
				logfields.Error, revertErr)
		}
		return err
	}
	m.logger.Debug("Successfully updated network policy", logfields.Name, p.GetPolicyNames())
	return nil
}

// getIngressLabels will return the key labels and expected labels for the ingress policy.
func (m *ingressPolicyManager) getIngressLabels(key resource.Key, resourceLabels map[string]string) labels.LabelArray {
	desiredLabels := labels.LabelArray{
		labels.NewLabel(LabelNameIngress, key.Name, LabelSourceIngress),
		labels.NewLabel(ciliumio.PodNamespaceLabel, key.Namespace, labels.LabelSourceK8s),
		labels.NewLabel(labels.IDNameIngress, "", labels.LabelSourceReserved),
	}

	for k, v := range resourceLabels {
		desiredLabels = append(desiredLabels, labels.NewLabel(k, v, labels.LabelSourceK8s))
	}

	identityLabels, _ := labelsfilter.Filter(desiredLabels.Labels())
	return identityLabels.LabelArray()
}

// policyUpdateCallback is called from endpoint manager to perform incremental
// and full regeneration for all managed ingress policies.
func (m *ingressPolicyManager) policyUpdateCallback(idsRegen *set.Set[identity.NumericIdentity], incremental bool) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for k, p := range m.ingressPolicies {
		if idsRegen != nil && !idsRegen.Has(identity.NumericIdentity(p.GetID())) {
			continue
		}

		if err := m.policyUpdateCallbackLocked(k, p, incremental); err != nil {
			m.logger.Error("Failed to update ingress policy",
				logfields.Resource, k,
				logfields.Error, err)
			return err
		}
	}
	return nil
}

// policyUpdateCallbackLocked performs the incremental and full regeneration for a given ingress policy.
func (m *ingressPolicyManager) policyUpdateCallbackLocked(key resource.Key, p *IngressPolicy, incremental bool) error {
	id := m.ingressIdentities[key]
	sp, rev, err := m.policyRepository.GetSelectorPolicy(id, p.GetRev(), NewIngressPolicyStats(), uint64(id.ID))
	if err != nil {
		return fmt.Errorf("failed to get selector policy %s %w", key, err)
	}
	// use existing policy if not updated
	if sp == nil {
		sp = p.selectorPolicy
		rev = p.rev
	}
	closer, changed := p.updateSelectorPolicyLocked(sp, rev)
	// keep selector cache version available until end of this function, so that
	// m.syncIngressPolicy() call can get it.
	defer closer()

	if changed {
		m.logger.Debug("Policy update for ingress policy",
			logfields.Name, p.GetPolicyNames(),
			logfields.Incremental, incremental)
		return m.syncIngressPolicy(context.Background(), p)
	}

	return nil
}
