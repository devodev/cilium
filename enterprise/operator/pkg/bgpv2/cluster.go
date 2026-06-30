// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package bgpv2

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	k8s_errors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/ptr"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_labels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_meta_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

type reconcileCache struct {
	ClusterConfigsByName            map[string]*v1.IsovalentBGPClusterConfig
	NodeConfigsByName               map[string]*v1.IsovalentBGPNodeConfig
	NodesByName                     map[string]*v2.CiliumNode
	OverridesByName                 map[string]*v1.IsovalentBGPNodeConfigOverride
	NodesByClusterConfigName        map[string][]*v2.CiliumNode
	ClusterConfigsByNodeName        map[string][]*v1.IsovalentBGPClusterConfig
	ClusterConfigWithNoMatchingNode map[string]*v1.IsovalentBGPClusterConfig
	ConflictingClusterConfigNames   map[string]sets.Set[string]
	ConflictFreeClusterConfigs      map[string]*v1.IsovalentBGPClusterConfig
	RouteReflectorClusters          map[string]*rrCluster
}

func populateReconcileCache(
	clusterConfigs []*v1.IsovalentBGPClusterConfig,
	nodeConfigs []*v1.IsovalentBGPNodeConfig,
	nodes []*v2.CiliumNode,
	overrides []*v1.IsovalentBGPNodeConfigOverride,
	defaultRRPeeringAddressFamily v1.RouteReflectorPeeringAddressFamily,
) *reconcileCache {
	cache := &reconcileCache{
		ClusterConfigsByName:            make(map[string]*v1.IsovalentBGPClusterConfig),
		NodeConfigsByName:               make(map[string]*v1.IsovalentBGPNodeConfig),
		NodesByName:                     make(map[string]*v2.CiliumNode),
		OverridesByName:                 make(map[string]*v1.IsovalentBGPNodeConfigOverride),
		NodesByClusterConfigName:        make(map[string][]*v2.CiliumNode),
		ClusterConfigsByNodeName:        make(map[string][]*v1.IsovalentBGPClusterConfig),
		ClusterConfigWithNoMatchingNode: make(map[string]*v1.IsovalentBGPClusterConfig),
		ConflictingClusterConfigNames:   make(map[string]sets.Set[string]),
		ConflictFreeClusterConfigs:      make(map[string]*v1.IsovalentBGPClusterConfig),
		RouteReflectorClusters:          make(map[string]*rrCluster),
	}

	// Index NodeConfigs by name
	for _, nodeConfig := range nodeConfigs {
		cache.NodeConfigsByName[nodeConfig.Name] = nodeConfig
	}

	// Index Overrides by name
	for _, override := range overrides {
		cache.OverridesByName[override.Name] = override
	}

	// Populate various indices
	for _, clusterConfig := range clusterConfigs {
		// Index each cluster configs by name
		cache.ClusterConfigsByName[clusterConfig.Name] = clusterConfig

		// Find matching nodes
		labelSelector, err := slim_meta_v1.LabelSelectorAsSelector(clusterConfig.Spec.NodeSelector)
		if err != nil {
			// This should never happen as the API validation should have caught this
			continue
		}

		nodeMatched := false
		for _, node := range nodes {
			// Index Nodes by name
			cache.NodesByName[node.Name] = node

			// Nil NodeSelector means all nodes are selected. Otherwise, the node must match the selector.
			if clusterConfig.Spec.NodeSelector == nil || labelSelector.Matches(slim_labels.Set(node.Labels)) {
				// Index Nodes by the matched ClusterConfig
				// name. This will be used to detect the
				// conflicting ClusterConfigs.
				cache.NodesByClusterConfigName[clusterConfig.Name] = append(
					cache.NodesByClusterConfigName[clusterConfig.Name],
					node,
				)
				// Index ClusterConfigs by the matched Node
				// name. This will be used to build the desired
				// NodeConfigs.
				cache.ClusterConfigsByNodeName[node.Name] = append(
					cache.ClusterConfigsByNodeName[node.Name],
					clusterConfig,
				)
				nodeMatched = true
			}
		}

		// This ClusterConfig selects nothing. Record it. This will be
		// used to report the condition.
		if !nodeMatched {
			cache.ClusterConfigWithNoMatchingNode[clusterConfig.Name] = clusterConfig
		}
	}

	// Find conflicting cluster configs
	for _, clusterConfigs := range cache.ClusterConfigsByNodeName {
		// The node is selected by multiple cluster configs. Record the conflicting relationship.
		for _, clusterConfig0 := range clusterConfigs {
			for _, clusterConfig1 := range clusterConfigs {
				if clusterConfig0.Name == clusterConfig1.Name {
					continue
				}
				if ccs, found := cache.ConflictingClusterConfigNames[clusterConfig0.Name]; found {
					ccs.Insert(clusterConfig1.Name)
				} else {
					cache.ConflictingClusterConfigNames[clusterConfig0.Name] = sets.New(clusterConfig1.Name)
				}
			}
		}
	}

	// Find conflict-free cluster configs
	for _, clusterConfig := range clusterConfigs {
		ccs, found := cache.ConflictingClusterConfigNames[clusterConfig.Name]
		if !found || ccs.Len() == 0 {
			cache.ConflictFreeClusterConfigs[clusterConfig.Name] = clusterConfig
		}
	}

	// Build RouteReflectorCluster. This should be done only for the conflict-free cluster configs.
	for _, clusterConfig := range cache.ConflictFreeClusterConfigs {
		for _, instance := range clusterConfig.Spec.BGPInstances {
			if instance.RouteReflector == nil {
				continue
			}
			for _, node := range cache.NodesByClusterConfigName[clusterConfig.Name] {
				cluster, found := cache.RouteReflectorClusters[instance.RouteReflector.ClusterID]
				if !found {
					cluster = newRRCluster(defaultRRPeeringAddressFamily)
					cache.RouteReflectorClusters[instance.RouteReflector.ClusterID] = cluster
				}
				cluster.AddInstance(node, &instance)
			}
		}
	}

	return cache
}

func (m *BGPResourceMapper) reconcileClusterConfigs(ctx context.Context) error {
	clusterConfigs, err := m.clusterConfig.List()
	if err != nil {
		return err
	}

	nodes, err := m.ciliumNode.List()
	if err != nil {
		return err
	}

	nodeConfigs := m.nodeConfigStore.List()

	overrides, err := m.nodeConfigOverride.List()
	if err != nil {
		return err
	}

	cache := populateReconcileCache(clusterConfigs, nodeConfigs, nodes, overrides, m.defaultRRPeeringAddressFamily)

	// Update/Delete NodeConfigs
	if err = m.reconcileNodeConfigs(ctx, cache); err != nil {
		return err
	}

	// Update ClusterConfig status
	for _, clusterConfig := range cache.ClusterConfigsByName {
		err = errors.Join(err, m.reconcileClusterConfigStatus(ctx, cache, clusterConfig))
	}

	return err
}

func (m *BGPResourceMapper) desiredNodeConfigs(cache *reconcileCache) []*v1.IsovalentBGPNodeConfig {
	ret := []*v1.IsovalentBGPNodeConfig{}
	for clusterConfigName, clusterConfig := range cache.ConflictFreeClusterConfigs {
		for _, node := range cache.NodesByClusterConfigName[clusterConfigName] {
			ret = append(ret, m.toNodeConfig(node.Name, clusterConfig, cache))
		}
	}
	return ret
}

func (m *BGPResourceMapper) staleNodeConfigs(cache *reconcileCache) []*v1.IsovalentBGPNodeConfig {
	ret := []*v1.IsovalentBGPNodeConfig{}
	for name, nodeConfig := range cache.NodeConfigsByName {
		// If there's no cluster config that selects this node, or
		// there are multiple cluster configs that select this node
		// (conflicting), we should delete the node config.
		if clusterConfigs, ok := cache.ClusterConfigsByNodeName[name]; !ok || len(clusterConfigs) > 1 {
			ret = append(ret, nodeConfig)
		}
	}
	return ret
}

func (m *BGPResourceMapper) reconcileNodeConfigs(ctx context.Context, cache *reconcileCache) error {
	var errs error

	for _, nodeConfig := range m.staleNodeConfigs(cache) {
		err := m.deleteNodeConfig(ctx, nodeConfig)
		if err != nil {
			errs = errors.Join(errs, err)
		}
	}

	for _, newNodeConfig := range m.desiredNodeConfigs(cache) {
		err := m.upsertNodeConfig(ctx, cache.NodeConfigsByName[newNodeConfig.Name], newNodeConfig)
		if err != nil {
			errs = errors.Join(errs, err)
		}
	}

	return errs
}

func (m *BGPResourceMapper) reconcileClusterConfigStatus(ctx context.Context, cache *reconcileCache, config *v1.IsovalentBGPClusterConfig) error {
	// Update ClusterConfig conditions
	updateStatus := false

	if m.enableStatusReporting {
		// Does this ClusterConfig select any node?
		_, noMatchingNode := cache.ClusterConfigWithNoMatchingNode[config.Name]

		// ClusterConfigs conflicting with this one
		conflictingClusterConfigNames := cache.ConflictingClusterConfigNames[config.Name]

		// Collect the missing peerConfig references
		missingPCs := m.missingPeerConfigs(config)

		if changed := m.updateNoMatchingNodeCondition(config, noMatchingNode); changed {
			updateStatus = true
		}
		if changed := m.updateMissingPeerConfigsCondition(config, missingPCs); changed {
			updateStatus = true
		}
		if changed := m.updateConflictingClusterConfigsCondition(config, conflictingClusterConfigNames); changed {
			updateStatus = true
		}

		// validate VRFs and VRFConfigs if SRv6 is enabled
		if m.dc.EnableSRv6 {
			missingVRFs := m.missingVRFs(config)
			missingVRFConfigs := m.missingVRFConfigs(config)

			if changed := m.updateMissingVRFsCondition(config, missingVRFs); changed {
				updateStatus = true
			}

			if changed := m.updateMissingVRFConfigsCondition(config, missingVRFConfigs); changed {
				updateStatus = true
			}
		}
	} else {
		// If the status reporting is disabled, we need to ensure all
		// conditions managed by this controller are removed.
		// Otherwise, users may see the stale conditions which were
		// reported previously.
		for _, cond := range v1.AllBGPClusterConfigConditions {
			if removed := meta.RemoveStatusCondition(&config.Status.Conditions, cond); removed {
				updateStatus = true
			}
		}
	}

	// Sort conditions to the stable order
	slices.SortStableFunc(config.Status.Conditions, func(a, b meta_v1.Condition) int {
		return strings.Compare(a.Type, b.Type)
	})

	// Call API only when there's a condition change
	if updateStatus {
		_, err := m.clientSet.IsovalentV1().IsovalentBGPClusterConfigs().UpdateStatus(ctx, config, meta_v1.UpdateOptions{})
		if err != nil {
			return err
		}
	}

	return nil
}

// missingPeerConfigs returns a IsovalentBGPPeerConfig which is referenced from
// the ClusterConfig, but doesn't exist. The returned slice is sorted and
// deduplicated for output stability.
func (m *BGPResourceMapper) missingPeerConfigs(config *v1.IsovalentBGPClusterConfig) []string {
	missing := []string{}
	for _, instance := range config.Spec.BGPInstances {
		for _, peer := range instance.Peers {
			if peer.PeerConfigRef == nil {
				continue
			}

			_, exists, _ := m.peerConfig.GetByKey(resource.Key{Name: peer.PeerConfigRef.Name})
			if !exists {
				missing = append(missing, peer.PeerConfigRef.Name)
			}

			// Just ignore the error other than NotFound. It might
			// be a network issue, or something else, but we are
			// only interested in detecting the invalid reference
			// here.
		}
	}
	slices.Sort(missing)
	return slices.Compact(missing)
}

// missingVRFs returns a IsovalentVRF which is referenced from
// the ClusterConfig, but doesn't exist. The returned slice is sorted and
// deduplicated for output stability.
func (m *BGPResourceMapper) missingVRFs(config *v1.IsovalentBGPClusterConfig) []string {
	missing := []string{}
	for _, instance := range config.Spec.BGPInstances {
		for _, vrf := range instance.VRFs {
			if vrf.VRFRef != nil {
				_, exists, _ := m.vrf.GetByKey(resource.Key{Name: *vrf.VRFRef})
				if !exists {
					missing = append(missing, *vrf.VRFRef)
				}
			}
		}
	}
	slices.Sort(missing)
	return slices.Compact(missing)
}

// missingVRFConfigs returns a IsovalentBGPVRFConfig which is referenced from
// the ClusterConfig, but doesn't exist. The returned slice is sorted and
// deduplicated for output stability.
func (m *BGPResourceMapper) missingVRFConfigs(config *v1.IsovalentBGPClusterConfig) []string {
	missing := []string{}
	for _, instance := range config.Spec.BGPInstances {
		for _, vrf := range instance.VRFs {
			if vrf.ConfigRef == nil {
				continue
			}
			_, exists, _ := m.vrfConfig.GetByKey(resource.Key{Name: *vrf.ConfigRef})
			if !exists {
				missing = append(missing, *vrf.ConfigRef)
			}
		}
	}
	slices.Sort(missing)
	return slices.Compact(missing)
}

func (m *BGPResourceMapper) updateConflictingClusterConfigsCondition(config *v1.IsovalentBGPClusterConfig, conflictingClusterConfigs sets.Set[string]) bool {
	cond := meta_v1.Condition{
		Type:               v1.BGPClusterConfigConditionConflictingClusterConfigs,
		Status:             meta_v1.ConditionFalse,
		ObservedGeneration: config.Generation,
		LastTransitionTime: meta_v1.Now(),
		Message:            "",
		Reason:             "ClusterConfigValidated",
	}
	if conflictingClusterConfigs.Len() != 0 {
		cond.Status = meta_v1.ConditionTrue
		cond.Message = fmt.Sprintf("Selecting the same node(s) with ClusterConfig(s): %v", sets.List(conflictingClusterConfigs))
		cond.Reason = "ClusterConfigConflict"
	}
	return meta.SetStatusCondition(&config.Status.Conditions, cond)
}

func (m *BGPResourceMapper) updateMissingPeerConfigsCondition(config *v1.IsovalentBGPClusterConfig, missingPCs []string) bool {
	cond := meta_v1.Condition{
		Type:               v1.BGPClusterConfigConditionMissingPeerConfigs,
		Status:             meta_v1.ConditionFalse,
		ObservedGeneration: config.Generation,
		LastTransitionTime: meta_v1.Now(),
		Message:            "",
		Reason:             "PeerConfigsResolved",
	}
	if len(missingPCs) != 0 {
		cond.Status = meta_v1.ConditionTrue
		cond.Message = fmt.Sprintf("Referenced IsovalentBGPPeerConfig(s) are missing: %v", missingPCs)
		cond.Reason = "PeerConfigsMissing"
	}
	return meta.SetStatusCondition(&config.Status.Conditions, cond)
}

func (m *BGPResourceMapper) updateNoMatchingNodeCondition(config *v1.IsovalentBGPClusterConfig, noMatchingNode bool) bool {
	cond := meta_v1.Condition{
		Type:               v1.BGPClusterConfigConditionNoMatchingNode,
		Status:             meta_v1.ConditionTrue,
		ObservedGeneration: config.Generation,
		LastTransitionTime: meta_v1.Now(),
		Reason:             "MatchingNodeUnavailable",
		Message:            "No node matches spec.nodeSelector",
	}
	if !noMatchingNode {
		cond.Status = meta_v1.ConditionFalse
		cond.Message = ""
		cond.Reason = "MatchingNodeSelected"
	}
	return meta.SetStatusCondition(&config.Status.Conditions, cond)
}

func (m *BGPResourceMapper) updateMissingVRFsCondition(config *v1.IsovalentBGPClusterConfig, missingVRFs []string) bool {
	cond := meta_v1.Condition{
		Type:               v1.BGPClusterConfigConditionMissingVRFs,
		Status:             meta_v1.ConditionFalse,
		ObservedGeneration: config.Generation,
		LastTransitionTime: meta_v1.Now(),
		Message:            "",
		Reason:             "VRFResolved",
	}
	if len(missingVRFs) != 0 {
		cond.Status = meta_v1.ConditionTrue
		cond.Message = fmt.Sprintf("Referenced IsovalentVRF(s) are missing: %v", missingVRFs)
		cond.Reason = "VRFMissing"
	}
	return meta.SetStatusCondition(&config.Status.Conditions, cond)
}

func (m *BGPResourceMapper) updateMissingVRFConfigsCondition(config *v1.IsovalentBGPClusterConfig, missingVRFConfigs []string) bool {
	cond := meta_v1.Condition{
		Type:               v1.BGPClusterConfigConditionMissingVRFConfigs,
		Status:             meta_v1.ConditionFalse,
		ObservedGeneration: config.Generation,
		LastTransitionTime: meta_v1.Now(),
		Message:            "",
		Reason:             "BGPVRFConfigResolved",
	}
	if len(missingVRFConfigs) != 0 {
		cond.Status = meta_v1.ConditionTrue
		cond.Message = fmt.Sprintf("Referenced IsovalentBGPVRFConfig(s) are missing: %v", missingVRFConfigs)
		cond.Reason = "BGPVRFConfigMissing"
	}
	return meta.SetStatusCondition(&config.Status.Conditions, cond)
}

func (m *BGPResourceMapper) upsertNodeConfig(ctx context.Context, oldNodeConfig, newNodeConfig *v1.IsovalentBGPNodeConfig) error {
	var err error

	nodeConfigClient := m.clientSet.IsovalentV1().IsovalentBGPNodeConfigs()

	switch {
	case oldNodeConfig != nil && oldNodeConfig.Spec.DeepEqual(&newNodeConfig.Spec):
		return nil
	case oldNodeConfig != nil:
		// reinitialize spec fields
		oldNodeConfig.Spec = newNodeConfig.Spec
		_, err = nodeConfigClient.Update(ctx, oldNodeConfig, meta_v1.UpdateOptions{})
	default:
		_, err = nodeConfigClient.Create(ctx, newNodeConfig, meta_v1.CreateOptions{})
	}

	return err
}

func (m *BGPResourceMapper) deleteNodeConfig(ctx context.Context, nodeConfig *v1.IsovalentBGPNodeConfig) error {
	if nodeConfig == nil {
		return nil
	}

	err := m.clientSet.IsovalentV1().IsovalentBGPNodeConfigs().Delete(ctx, nodeConfig.Name, meta_v1.DeleteOptions{})
	if err != nil && !k8s_errors.IsNotFound(err) {
		return err
	}

	return nil
}

func (m *BGPResourceMapper) toNodeConfig(nodeName string, clusterConfig *v1.IsovalentBGPClusterConfig, cache *reconcileCache) *v1.IsovalentBGPNodeConfig {
	overrideInstances := []v1.IsovalentBGPNodeConfigInstanceOverride{}
	if override, found := cache.OverridesByName[nodeName]; found {
		overrideInstances = override.Spec.BGPInstances
	}
	return &v1.IsovalentBGPNodeConfig{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: nodeName,
			OwnerReferences: []meta_v1.OwnerReference{
				{
					APIVersion: v1.SchemeGroupVersion.String(),
					Kind:       v1.IsovalentBGPClusterConfigKindDefinition,
					Name:       clusterConfig.GetName(),
					UID:        clusterConfig.GetUID(),
				},
			},
		},
		Spec: v1.IsovalentBGPNodeSpec{
			BGPInstances: toNodeBGPInstance(nodeName, clusterConfig.Spec.BGPInstances, overrideInstances, cache),
		},
	}
}

func toNodeBGPInstance(
	nodeName string,
	clusterBGPInstances []v1.IsovalentBGPInstance,
	overrideBGPInstances []v1.IsovalentBGPNodeConfigInstanceOverride,
	cache *reconcileCache,
) []v1.IsovalentBGPNodeInstance {
	var res []v1.IsovalentBGPNodeInstance

	for _, clusterBGPInstance := range clusterBGPInstances {
		nodeBGPInstance := v1.IsovalentBGPNodeInstance{
			Name:      clusterBGPInstance.Name,
			LocalASN:  clusterBGPInstance.LocalASN,
			LocalPort: clusterBGPInstance.LocalPort,
			VRFRef:    clusterBGPInstance.VRFRef,
		}

		// find BGPResourceManager global override for this instance
		var override v1.IsovalentBGPNodeConfigInstanceOverride
		for _, overrideBGPInstance := range overrideBGPInstances {
			if overrideBGPInstance.Name == clusterBGPInstance.Name {
				nodeBGPInstance.RouterID = overrideBGPInstance.RouterID
				if overrideBGPInstance.LocalPort != nil {
					nodeBGPInstance.LocalPort = overrideBGPInstance.LocalPort
				}
				nodeBGPInstance.SRv6Responder = overrideBGPInstance.SRv6Responder
				if overrideBGPInstance.Maintenance != nil {
					nodeBGPInstance.Maintenance = overrideBGPInstance.Maintenance
				}
				override = overrideBGPInstance
				break
			}
		}

		for _, bgpInstancePeer := range clusterBGPInstance.Peers {
			nodePeer := v1.IsovalentBGPNodePeer{
				Name:          bgpInstancePeer.Name,
				PeerAddress:   bgpInstancePeer.PeerAddress,
				PeerASN:       bgpInstancePeer.PeerASN,
				AutoDiscovery: bgpInstancePeer.AutoDiscovery,
				PeerConfigRef: bgpInstancePeer.PeerConfigRef,
			}

			// find BGPResourceManager Peer override for this instance
			for _, overrideBGPPeer := range override.Peers {
				if overrideBGPPeer.Name == bgpInstancePeer.Name {
					overrideNodePeer(&nodePeer, &overrideBGPPeer)
					break
				}
			}

			nodeBGPInstance.Peers = append(nodeBGPInstance.Peers, nodePeer)
		}

		// Propagate the instance's route reflector configuration and
		// append route reflector peers.
		if clusterBGPInstance.RouteReflector != nil {
			cluster, found := cache.RouteReflectorClusters[clusterBGPInstance.RouteReflector.ClusterID]
			if !found {
				// This should never happen
				continue
			}

			nodeBGPInstance.RouteReflector = &v1.NodeRouteReflector{
				Role:      clusterBGPInstance.RouteReflector.Role,
				ClusterID: clusterBGPInstance.RouteReflector.ClusterID,
			}

			for _, peer := range cluster.ListPeers(instanceID{NodeName: nodeName, InstanceName: clusterBGPInstance.Name}) {
				nodePeer := v1.IsovalentBGPNodePeer{
					Name:           peer.Name,
					PeerAddress:    ptr.To(peer.Address),
					PeerASN:        ptr.To(*nodeBGPInstance.LocalASN), // Route Reflector is iBGP-only
					AutoDiscovery:  nil,                               // auto-discovery is not supported for Route Reflectors
					PeerConfigRef:  peer.PeerConfigRef,
					RouteReflector: peer.RouteReflector,
				}

				// It is valid to override route reflector peers
				for _, overrideBGPPeer := range override.Peers {
					if overrideBGPPeer.Name == nodePeer.Name {
						overrideNodePeer(&nodePeer, &overrideBGPPeer)

						// auto-discovery is not supported for Route Reflector peers
						nodePeer.AutoDiscovery = nil

						break
					}
				}

				nodeBGPInstance.Peers = append(nodeBGPInstance.Peers, nodePeer)
			}
		}

		for _, bgpVRF := range clusterBGPInstance.VRFs {
			nodeBGPInstance.VRFs = append(nodeBGPInstance.VRFs, v1.IsovalentBGPNodeVRF(bgpVRF))
		}

		res = append(res, nodeBGPInstance)
	}
	return res
}

func overrideNodePeer(nodePeer *v1.IsovalentBGPNodePeer, override *v1.IsovalentBGPNodeConfigPeerOverride) {
	if override.LocalAddress != nil {
		nodePeer.LocalAddress = override.LocalAddress
	}
	if override.AutoDiscovery != nil {
		nodePeer.AutoDiscovery = override.AutoDiscovery
	}
}
