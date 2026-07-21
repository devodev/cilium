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
	"maps"
	"regexp"
	"strings"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	k8s_errors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/utils/ptr"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	slim_meta_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/node/addressing"
	"github.com/cilium/cilium/pkg/time"
)

var (
	isoNodeConfigSpecWithOverride = func() v1.IsovalentBGPNodeInstance {
		cpy := isoNodeConfigSpec.DeepCopy()
		cpy.SRv6Responder = ptr.To[bool](true)
		cpy.LocalPort = ptr.To[int32](1179)
		cpy.Maintenance = &v1.IsovalentBGPMaintenance{
			Mode: v1.BGPMaintenanceModeCommunity,
		}
		return *cpy
	}
)

func Test_ClusterConfigSteps(t *testing.T) {
	steps := []struct {
		name                   string
		clusterConfig          *v1.IsovalentBGPClusterConfig
		nodeConfigOverride     *v1.IsovalentBGPNodeConfigOverride
		nodes                  []*cilium_v2.CiliumNode
		expectedNodeConfigs    []*v1.IsovalentBGPNodeConfig
		expectedTrueConditions []string
	}{
		{
			name:          "initial node setup",
			clusterConfig: nil,
			nodes: []*cilium_v2.CiliumNode{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-1",
						Labels: map[string]string{
							"bgp": "rack1",
						},
					},
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-2",
						Labels: map[string]string{
							"bgp": "rack1",
						},
					},
				},
			},
			expectedNodeConfigs: nil,
		},
		{
			name:          "initial cluster configuration",
			clusterConfig: isoClusterConfig,
			expectedNodeConfigs: []*v1.IsovalentBGPNodeConfig{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-1",
					},
					Spec: v1.IsovalentBGPNodeSpec{
						BGPInstances: []v1.IsovalentBGPNodeInstance{isoNodeConfigSpec},
					},
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-2",
					},
					Spec: v1.IsovalentBGPNodeSpec{
						BGPInstances: []v1.IsovalentBGPNodeInstance{isoNodeConfigSpec},
					},
				},
			},
		},
		{
			name:          "add new node",
			clusterConfig: isoClusterConfig,
			nodes: []*cilium_v2.CiliumNode{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-3",
						Labels: map[string]string{
							"bgp": "rack1",
						},
					},
				},
			},
			expectedNodeConfigs: []*v1.IsovalentBGPNodeConfig{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-1",
					},
					Spec: v1.IsovalentBGPNodeSpec{
						BGPInstances: []v1.IsovalentBGPNodeInstance{isoNodeConfigSpec},
					},
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-2",
					},
					Spec: v1.IsovalentBGPNodeSpec{
						BGPInstances: []v1.IsovalentBGPNodeInstance{isoNodeConfigSpec},
					},
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-3",
					},
					Spec: v1.IsovalentBGPNodeSpec{
						BGPInstances: []v1.IsovalentBGPNodeInstance{isoNodeConfigSpec},
					},
				},
			},
		},
		{
			name:          "add node config override",
			clusterConfig: isoClusterConfig,
			nodeConfigOverride: &v1.IsovalentBGPNodeConfigOverride{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "node-3",
				},
				Spec: v1.IsovalentBGPNodeConfigOverrideSpec{
					BGPInstances: []v1.IsovalentBGPNodeConfigInstanceOverride{
						{
							Name:          "instance-1",
							LocalPort:     ptr.To[int32](1179),
							SRv6Responder: ptr.To[bool](true),
							Maintenance: &v1.IsovalentBGPMaintenance{
								Mode: v1.BGPMaintenanceModeCommunity,
							},
						},
					},
				},
			},
			nodes: []*cilium_v2.CiliumNode{},
			expectedNodeConfigs: []*v1.IsovalentBGPNodeConfig{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-1",
					},
					Spec: v1.IsovalentBGPNodeSpec{
						BGPInstances: []v1.IsovalentBGPNodeInstance{isoNodeConfigSpec},
					},
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-2",
					},
					Spec: v1.IsovalentBGPNodeSpec{
						BGPInstances: []v1.IsovalentBGPNodeInstance{isoNodeConfigSpec},
					},
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-3",
					},
					Spec: v1.IsovalentBGPNodeSpec{
						BGPInstances: []v1.IsovalentBGPNodeInstance{isoNodeConfigSpecWithOverride()},
					},
				},
			},
		},
		{
			name:          "remove node labels",
			clusterConfig: isoClusterConfig,
			nodes: []*cilium_v2.CiliumNode{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-1",
					},
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-2",
					},
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-3",
					},
				},
			},
			expectedNodeConfigs: nil,
			expectedTrueConditions: []string{
				v1.BGPClusterConfigConditionNoMatchingNode,
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	f := newFixture(t, ctx, require.New(t), fixtureConfig{enableStatusReport: true})

	tlog := hivetest.Logger(t)
	f.hive.Start(tlog, ctx)
	defer f.hive.Stop(tlog, ctx)

	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			req := require.New(t)

			// setup nodes
			for _, node := range step.nodes {
				upsertNode(req, ctx, f, node)
			}

			// upsert BGP cluster config
			upsertIsoBGPCC(req, ctx, f, step.clusterConfig)

			// upsert BGP node config override
			upsertIsoBGPNodeConfigOR(req, ctx, f, step.nodeConfigOverride)

			// validate node configs
			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				runningIsoNodeConfigs, err := f.isoBGPNodeConfClient.List(ctx, meta_v1.ListOptions{})
				if err != nil {
					assert.NoError(c, err)
					return
				}
				assert.Len(c, runningIsoNodeConfigs.Items, len(step.expectedNodeConfigs))

				for _, expectedNodeConfig := range step.expectedNodeConfigs {
					isoNodeConfig, err := f.isoBGPNodeConfClient.Get(ctx, expectedNodeConfig.Name, meta_v1.GetOptions{})
					if err != nil {
						assert.NoError(c, err)
						return
					}
					assert.Equal(c, expectedNodeConfig.Spec, isoNodeConfig.Spec)
				}

			}, TestTimeout, 50*time.Millisecond)

			// Condition checks. Assuming the cluster config already exists on the API server.
			if len(step.expectedTrueConditions) > 0 {
				assert.EventuallyWithT(t, func(c *assert.CollectT) {
					bgpcc, err := f.isoClusterClient.Get(ctx, isoClusterConfig.Name, meta_v1.GetOptions{})
					if err != nil {
						assert.NoError(c, err)
						return
					}

					trueConditions := sets.New[string]()
					for _, cond := range bgpcc.Status.Conditions {
						trueConditions.Insert(cond.Type)
					}

					for _, cond := range step.expectedTrueConditions {
						assert.True(c, trueConditions.Has(cond), "Condition missing or not true: %s", cond)
					}
				}, TestTimeout, 50*time.Millisecond)
			}
		})
	}
}

func TestClusterConfigConditions(t *testing.T) {
	clusterConfigName := "cluster-config0"
	peerConfigName := "peer-config0"
	vrfName := "vrf0"
	bgpVrfConfigName := "vrf0-bgp-config"

	node := cilium_v2.CiliumNode{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "node-1",
			Labels: map[string]string{
				"bgp": "rack1",
			},
		},
	}

	peerConfig := v1.IsovalentBGPPeerConfig{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: peerConfigName,
		},
	}

	vrf := v1alpha1.IsovalentVRF{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: vrfName,
		},
	}

	bgpVrfConfig := v1alpha1.IsovalentBGPVRFConfig{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: bgpVrfConfigName,
		},
	}

	tests := []struct {
		name                    string
		clusterConfig           *v1.IsovalentBGPClusterConfig
		expectedConditionStatus map[string]meta_v1.ConditionStatus
		expectedConditionReason map[string]string
	}{
		{
			name: "NoMatchingNode False",
			clusterConfig: &v1.IsovalentBGPClusterConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: clusterConfigName,
				},
				Spec: v1.IsovalentBGPClusterConfigSpec{
					NodeSelector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"bgp": "rack1",
						},
					},
				},
			},
			expectedConditionStatus: map[string]meta_v1.ConditionStatus{
				v1.BGPClusterConfigConditionNoMatchingNode: meta_v1.ConditionFalse,
			},
			expectedConditionReason: map[string]string{
				v1.BGPClusterConfigConditionNoMatchingNode: "ClusterConfigValidated",
			},
		},
		{
			name: "NoMatchingNode False Nil Selector",
			clusterConfig: &v1.IsovalentBGPClusterConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: clusterConfigName,
				},
				Spec: v1.IsovalentBGPClusterConfigSpec{
					NodeSelector: nil,
				},
			},
			expectedConditionStatus: map[string]meta_v1.ConditionStatus{
				v1.BGPClusterConfigConditionNoMatchingNode: meta_v1.ConditionFalse,
			},
			expectedConditionReason: map[string]string{
				v1.BGPClusterConfigConditionNoMatchingNode: "ClusterConfigValidated",
			},
		},
		{
			name: "NoMatchingNode True",
			clusterConfig: &v1.IsovalentBGPClusterConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: clusterConfigName,
				},
				Spec: v1.IsovalentBGPClusterConfigSpec{
					NodeSelector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"bgp": "rack2",
						},
					},
				},
			},
			expectedConditionStatus: map[string]meta_v1.ConditionStatus{
				v1.BGPClusterConfigConditionNoMatchingNode: meta_v1.ConditionTrue,
			},
			expectedConditionReason: map[string]string{
				v1.BGPClusterConfigConditionNoMatchingNode: "ClusterConfigConflict",
			},
		},
		{
			name: "MissingPeerConfig False",
			clusterConfig: &v1.IsovalentBGPClusterConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: clusterConfigName,
				},
				Spec: v1.IsovalentBGPClusterConfigSpec{
					NodeSelector: nil,
					BGPInstances: []v1.IsovalentBGPInstance{
						{
							Peers: []v1.IsovalentBGPPeer{
								{
									Name: "peer0",
									PeerConfigRef: &v1.PeerConfigReference{
										Name: peerConfigName,
									},
								},
							},
						},
					},
				},
			},
			expectedConditionStatus: map[string]meta_v1.ConditionStatus{
				v1.BGPClusterConfigConditionMissingPeerConfigs: meta_v1.ConditionFalse,
			},
			expectedConditionReason: map[string]string{
				v1.BGPClusterConfigConditionMissingPeerConfigs: "PeerConfigsResolved",
			},
		},
		{
			name: "MissingPeerConfig False nil PeerConfigRef",
			clusterConfig: &v1.IsovalentBGPClusterConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: clusterConfigName,
				},
				Spec: v1.IsovalentBGPClusterConfigSpec{
					NodeSelector: nil,
					BGPInstances: []v1.IsovalentBGPInstance{
						{
							Peers: []v1.IsovalentBGPPeer{
								{
									Name: "peer0",
								},
							},
						},
					},
				},
			},
			expectedConditionStatus: map[string]meta_v1.ConditionStatus{
				v1.BGPClusterConfigConditionMissingPeerConfigs: meta_v1.ConditionFalse,
			},
			expectedConditionReason: map[string]string{
				v1.BGPClusterConfigConditionMissingPeerConfigs: "PeerConfigsResolved",
			},
		},
		{
			name: "MissingPeerConfig True",
			clusterConfig: &v1.IsovalentBGPClusterConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: clusterConfigName,
				},
				Spec: v1.IsovalentBGPClusterConfigSpec{
					NodeSelector: nil,
					BGPInstances: []v1.IsovalentBGPInstance{
						{
							Peers: []v1.IsovalentBGPPeer{
								{
									Name: "peer0",
									PeerConfigRef: &v1.PeerConfigReference{
										Name: peerConfigName + "-foo",
									},
								},
							},
						},
					},
				},
			},
			expectedConditionStatus: map[string]meta_v1.ConditionStatus{
				v1.BGPClusterConfigConditionMissingPeerConfigs: meta_v1.ConditionTrue,
			},
			expectedConditionReason: map[string]string{
				v1.BGPClusterConfigConditionMissingPeerConfigs: "PeerConfigsMissing",
			},
		},
		{
			name: "MissingVRF and MissingVRFConfig False",
			clusterConfig: &v1.IsovalentBGPClusterConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: clusterConfigName,
				},
				Spec: v1.IsovalentBGPClusterConfigSpec{
					BGPInstances: []v1.IsovalentBGPInstance{
						{
							VRFs: []v1.BGPVRF{
								{
									VRFRef:    &vrfName,
									ConfigRef: ptr.To[string](bgpVrfConfigName),
								},
							},
						},
					},
				},
			},
			expectedConditionStatus: map[string]meta_v1.ConditionStatus{
				v1.BGPClusterConfigConditionMissingVRFs:       meta_v1.ConditionFalse,
				v1.BGPClusterConfigConditionMissingVRFConfigs: meta_v1.ConditionFalse,
			},
			expectedConditionReason: map[string]string{
				v1.BGPClusterConfigConditionMissingVRFs:       "VRFResolved",
				v1.BGPClusterConfigConditionMissingVRFConfigs: "BGPVRFConfigResolved",
			},
		},
		{
			name: "MissingVRF True, MissingVRFConfig False",
			clusterConfig: &v1.IsovalentBGPClusterConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: clusterConfigName,
				},
				Spec: v1.IsovalentBGPClusterConfigSpec{
					BGPInstances: []v1.IsovalentBGPInstance{
						{
							VRFs: []v1.BGPVRF{
								{
									VRFRef:    ptr.To("foo"),
									ConfigRef: ptr.To(bgpVrfConfigName),
								},
							},
						},
					},
				},
			},
			expectedConditionStatus: map[string]meta_v1.ConditionStatus{
				v1.BGPClusterConfigConditionMissingVRFs:       meta_v1.ConditionTrue,
				v1.BGPClusterConfigConditionMissingVRFConfigs: meta_v1.ConditionFalse,
			},
			expectedConditionReason: map[string]string{
				v1.BGPClusterConfigConditionMissingVRFs:       "VRFMissing",
				v1.BGPClusterConfigConditionMissingVRFConfigs: "BGPVRFConfigResolved",
			},
		},
		{
			name: "MissingVRF True, MissingVRFConfig True",
			clusterConfig: &v1.IsovalentBGPClusterConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: clusterConfigName,
				},
				Spec: v1.IsovalentBGPClusterConfigSpec{
					BGPInstances: []v1.IsovalentBGPInstance{
						{
							VRFs: []v1.BGPVRF{
								{
									VRFRef:    ptr.To("foo"),
									ConfigRef: ptr.To("bar"),
								},
							},
						},
					},
				},
			},
			expectedConditionStatus: map[string]meta_v1.ConditionStatus{
				v1.BGPClusterConfigConditionMissingVRFs:       meta_v1.ConditionTrue,
				v1.BGPClusterConfigConditionMissingVRFConfigs: meta_v1.ConditionTrue,
			},
			expectedConditionReason: map[string]string{
				v1.BGPClusterConfigConditionMissingVRFs:       "VRFMissing",
				v1.BGPClusterConfigConditionMissingVRFConfigs: "BGPVRFConfigMissing",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)

			ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
			defer cancel()

			f := newFixture(t, ctx, require.New(t), fixtureConfig{enableStatusReport: true})

			tlog := hivetest.Logger(t)
			f.hive.Start(tlog, ctx)
			defer f.hive.Stop(tlog, ctx)

			// Setup resources
			upsertNode(req, ctx, f, &node)
			upsertIsoBGPCC(req, ctx, f, tt.clusterConfig)
			upsertIsoBGPPC(req, ctx, f, &peerConfig)
			upsertIsoVrf(req, ctx, f, &vrf)
			upsertIsoBGPVrfConfig(req, ctx, f, &bgpVrfConfig)

			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				// Check conditions
				cc, err := f.isoClusterClient.Get(ctx, clusterConfigName, meta_v1.GetOptions{})
				if !assert.NoError(ct, err, "Cannot get cluster config") {
					return
				}

				// Check if the expected condition exists and has an intended values
				missing := maps.Clone(tt.expectedConditionStatus)
				for condType, status := range tt.expectedConditionStatus {
					for _, cond := range cc.Status.Conditions {
						if cond.Type == condType {
							if !assert.Equal(ct, status, cond.Status) {
								return
							}
							delete(missing, cond.Type)
						}
					}
				}

				assert.Empty(ct, missing, "Missing conditions: %v", missing)
			}, time.Second*3, time.Millisecond*100)
		})
	}
}

func TestConflictingClusterConfigCondition(t *testing.T) {
	nodes := []*cilium_v2.CiliumNode{
		{
			ObjectMeta: meta_v1.ObjectMeta{
				Name: "node-0",
				Labels: map[string]string{
					"rack":             "rack0",
					"complete-overlap": "true",
					"partial-overlap0": "true",
				},
			},
		},
		{
			ObjectMeta: meta_v1.ObjectMeta{
				Name: "node-1",
				Labels: map[string]string{
					"rack":             "rack1",
					"complete-overlap": "true",
					"partial-overlap0": "true",
					"partial-overlap1": "true",
				},
			},
		},
		{
			ObjectMeta: meta_v1.ObjectMeta{
				Name: "node-2",
				Labels: map[string]string{
					"rack":             "rack2",
					"complete-overlap": "true",
					"partial-overlap1": "true",
				},
			},
		},
	}

	type clusterConfig struct {
		name                      string
		selector                  *slim_meta_v1.LabelSelector
		conflictingClusterConfigs []string
	}

	tests := []struct {
		name           string
		clusterConfigs []clusterConfig
	}{
		{
			name: "ConflictingClusterConfig False",
			clusterConfigs: []clusterConfig{
				{
					name: "cluster-config-0",
					selector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"rack": "rack0",
						},
					},
					conflictingClusterConfigs: []string{},
				},
				{
					name: "cluster-config-1",
					selector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"rack": "rack1",
						},
					},
					conflictingClusterConfigs: []string{},
				},
				{
					name: "cluster-config-2",
					selector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"rack": "rack2",
						},
					},
					conflictingClusterConfigs: []string{},
				},
			},
		},
		{
			name: "ConflictingClusterConfig True complete overlap",
			clusterConfigs: []clusterConfig{
				{
					name: "cluster-config-0",
					selector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"complete-overlap": "true",
						},
					},
					conflictingClusterConfigs: []string{"cluster-config-1"},
				},
				{
					name: "cluster-config-1",
					selector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"complete-overlap": "true",
						},
					},
					conflictingClusterConfigs: []string{"cluster-config-0"},
				},
			},
		},
		{
			name: "ConflictingClusterConfig True complete overlap with nil",
			clusterConfigs: []clusterConfig{
				{
					name:                      "cluster-config-0",
					selector:                  nil,
					conflictingClusterConfigs: []string{"cluster-config-1"},
				},
				{
					name:                      "cluster-config-1",
					selector:                  nil,
					conflictingClusterConfigs: []string{"cluster-config-0"},
				},
			},
		},
		{
			name: "ConflictingClusterConfig True partial overlap",
			clusterConfigs: []clusterConfig{
				{
					name: "cluster-config-0",
					selector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"partial-overlap0": "true",
						},
					},
					conflictingClusterConfigs: []string{"cluster-config-1"},
				},
				{
					name: "cluster-config-1",
					selector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"partial-overlap1": "true",
						},
					},
					conflictingClusterConfigs: []string{"cluster-config-0"},
				},
			},
		},
		{
			name: "ConflictingClusterConfig True partial overlap of four configs",
			clusterConfigs: []clusterConfig{
				{
					name: "cluster-config-0",
					selector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"partial-overlap0": "true",
						},
					},
					conflictingClusterConfigs: []string{"cluster-config-1", "cluster-config-2"},
				},
				{
					name: "cluster-config-1",
					selector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"rack": "rack0",
						},
					},
					conflictingClusterConfigs: []string{"cluster-config-0"},
				},
				{
					name: "cluster-config-2",
					selector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"rack": "rack1",
						},
					},
					conflictingClusterConfigs: []string{"cluster-config-0"},
				},
				{
					name: "cluster-config-3",
					selector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"rack": "rack2",
						},
					},
					conflictingClusterConfigs: []string{},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)

			ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
			defer cancel()

			f := newFixture(t, ctx, require.New(t), fixtureConfig{enableStatusReport: true})

			tlog := hivetest.Logger(t)
			f.hive.Start(tlog, ctx)
			defer f.hive.Stop(tlog, ctx)

			// Setup resources
			for _, node := range nodes {
				upsertNode(req, ctx, f, node)
			}

			for _, config := range tt.clusterConfigs {
				clusterConfig := &v1.IsovalentBGPClusterConfig{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: config.name,
						// Fake client doesn't set UID. Assign it manually.
						UID: uuid.NewUUID(),
					},
					Spec: v1.IsovalentBGPClusterConfigSpec{
						NodeSelector: config.selector,
						BGPInstances: []v1.IsovalentBGPInstance{
							{
								Peers: []v1.IsovalentBGPPeer{},
							},
						},
					},
				}
				upsertIsoBGPCC(req, ctx, f, clusterConfig)
			}

			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				for _, config := range tt.clusterConfigs {
					cc, err := f.isoClusterClient.Get(ctx, config.name, meta_v1.GetOptions{})
					if !assert.NoError(ct, err, "Cannot get cluster config") {
						return
					}

					cond := meta.FindStatusCondition(
						cc.Status.Conditions,
						v1.BGPClusterConfigConditionConflictingClusterConfigs,
					)
					if !assert.NotNil(ct, cond, "Condition not found") {
						return
					}

					if len(config.conflictingClusterConfigs) == 0 {
						if !assert.Equal(ct, "ClusterConfigValidated", cond.Reason, "Expected reason to be ClusterConfigValidated") {
							return
						}
						if !assert.Equal(ct, meta_v1.ConditionFalse, cond.Status, "Expected condition to be false") {
							return
						}
						return
					}

					if cond.Status == meta_v1.ConditionFalse {
						continue
					}

					// Parse the list of conflicting cluster configs in the condition message
					expr, err := regexp.Compile(
						`Selecting the same node\(s\) with ClusterConfig\(s\): \[(.*)\]`,
					)
					if !assert.NoError(ct, err, "Error during regexp match") {
						return
					}

					match := expr.FindSubmatch([]byte(cond.Message))
					if !assert.Len(ct, match, 2, "Invalid number of match") {
						return
					}

					if !assert.Equal(ct, "ClusterConfigConflict", cond.Reason, "Expected reason to be ClusterConfigConflict") {
						return
					}
					if !assert.ElementsMatch(
						t,
						strings.Split(string(match[1]), " "),
						config.conflictingClusterConfigs,
						"Conflicting cluster configs do not match",
					) {
						return
					}
				}
			}, time.Second*3, time.Millisecond*100)
		})
	}
}

func TestDisableClusterConfigStatusReport(t *testing.T) {
	req := require.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	t.Cleanup(func() {
		cancel()
	})

	f := newFixture(t, ctx, req, fixtureConfig{enableStatusReport: false})

	logger := hivetest.Logger(t)

	f.hive.Start(logger, ctx)
	t.Cleanup(func() {
		f.hive.Stop(logger, ctx)
	})

	clusterConfig := &v1.IsovalentBGPClusterConfig{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "config0",
		},
		Spec: v1.IsovalentBGPClusterConfigSpec{},
		Status: v1.IsovalentBGPClusterConfigStatus{
			Conditions: []meta_v1.Condition{},
		},
	}

	// Fill with all known conditions
	for _, cond := range v1.AllBGPClusterConfigConditions {
		clusterConfig.Status.Conditions = append(clusterConfig.Status.Conditions, meta_v1.Condition{
			Type: cond,
		})
	}
	upsertIsoBGPCC(req, ctx, f, clusterConfig)

	// Wait for status to be cleared
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		// Check conditions
		cc, err := f.isoClusterClient.Get(ctx, clusterConfig.Name, meta_v1.GetOptions{})
		if !assert.NoError(ct, err, "Cannot get cluster config") {
			return
		}

		assert.Empty(ct, cc.Status.Conditions, "Conditions are not cleared")
	}, time.Second*3, time.Millisecond*100)
}

func TestRRPeeringSingleInstance(t *testing.T) {
	newClusterConfig := func(name string, role v1.RouteReflectorRole, clusterID string) *v1.IsovalentBGPClusterConfig {
		return &v1.IsovalentBGPClusterConfig{
			ObjectMeta: meta_v1.ObjectMeta{
				Name: name,
			},
			Spec: v1.IsovalentBGPClusterConfigSpec{
				NodeSelector: &slim_meta_v1.LabelSelector{
					MatchLabels: map[string]string{
						"rr-role":   string(role),
						"clusterID": clusterID,
					},
				},
				BGPInstances: []v1.IsovalentBGPInstance{
					{
						Name:     "instance0",
						LocalASN: ptr.To(int64(65000)),
						// TODO: Specify port
						RouteReflector: &v1.RouteReflector{
							Role:                 role,
							ClusterID:            clusterID,
							PeeringAddressFamily: ptr.To(v1.RouteReflectorPeeringAddressFamilyDual),
							PeerConfigRefV4: &v1.PeerConfigReference{
								Name: clusterID + "-peer-config-v4",
							},
							PeerConfigRefV6: &v1.PeerConfigReference{
								Name: clusterID + "-peer-config-v6",
							},
						},
					},
				},
			},
		}
	}

	newNode := func(name string, rrRole v1.RouteReflectorRole, clusterID, ipv4, ipv6 string) *cilium_v2.CiliumNode {
		return &cilium_v2.CiliumNode{
			ObjectMeta: meta_v1.ObjectMeta{
				Name: name,
				Labels: map[string]string{
					"rr-role":   string(rrRole),
					"clusterID": clusterID,
				},
			},
			Spec: cilium_v2.NodeSpec{
				Addresses: []cilium_v2.NodeAddress{
					{
						Type: addressing.NodeInternalIP,
						IP:   ipv4,
					},
					{
						Type: addressing.NodeInternalIP,
						IP:   ipv6,
					},
				},
			},
		}
	}

	tests := []struct {
		name           string
		clusterConfigs []*v1.IsovalentBGPClusterConfig
		nodes          []*cilium_v2.CiliumNode

		// Mapping from node name to expected BGP node peers
		expectedNodePeers map[string][]v1.IsovalentBGPNodePeer
	}{
		{
			name: "One Cluster",
			clusterConfigs: []*v1.IsovalentBGPClusterConfig{
				newClusterConfig("rrs", v1.RouteReflectorRoleRouteReflector, "255.0.0.1"),
				newClusterConfig("clients", v1.RouteReflectorRoleClient, "255.0.0.1"),
			},
			nodes: []*cilium_v2.CiliumNode{
				newNode("node0", v1.RouteReflectorRoleRouteReflector, "255.0.0.1", "10.0.0.0", "fd00:10::"),
				newNode("node1", v1.RouteReflectorRoleRouteReflector, "255.0.0.1", "10.0.0.1", "fd00:10::1"),
				newNode("node2", v1.RouteReflectorRoleClient, "255.0.0.1", "10.0.0.2", "fd00:10::2"),
				newNode("node3", v1.RouteReflectorRoleClient, "255.0.0.1", "10.0.0.3", "fd00:10::3"),
			},
			expectedNodePeers: map[string][]v1.IsovalentBGPNodePeer{
				"node0": {
					{
						Name:        "rr-client-node2-instance0-v4",
						PeerAddress: ptr.To("10.0.0.2"),
						PeerASN:     ptr.To(int64(65000)),
						PeerConfigRef: &v1.PeerConfigReference{
							Name: "255.0.0.1-peer-config-v4",
						},
						RouteReflector: &v1.NodeRouteReflector{
							Role:      v1.RouteReflectorRoleClient,
							ClusterID: "255.0.0.1",
						},
					},
					{
						Name:        "rr-client-node2-instance0-v6",
						PeerAddress: ptr.To("fd00:10::2"),
						PeerASN:     ptr.To(int64(65000)),
						PeerConfigRef: &v1.PeerConfigReference{
							Name: "255.0.0.1-peer-config-v6",
						},
						RouteReflector: &v1.NodeRouteReflector{
							Role:      v1.RouteReflectorRoleClient,
							ClusterID: "255.0.0.1",
						},
					},
					{
						Name:        "rr-client-node3-instance0-v4",
						PeerAddress: ptr.To("10.0.0.3"),
						PeerASN:     ptr.To(int64(65000)),
						PeerConfigRef: &v1.PeerConfigReference{
							Name: "255.0.0.1-peer-config-v4",
						},
						RouteReflector: &v1.NodeRouteReflector{
							Role:      v1.RouteReflectorRoleClient,
							ClusterID: "255.0.0.1",
						},
					},
					{
						Name:        "rr-client-node3-instance0-v6",
						PeerAddress: ptr.To("fd00:10::3"),
						PeerASN:     ptr.To(int64(65000)),
						PeerConfigRef: &v1.PeerConfigReference{
							Name: "255.0.0.1-peer-config-v6",
						},
						RouteReflector: &v1.NodeRouteReflector{
							Role:      v1.RouteReflectorRoleClient,
							ClusterID: "255.0.0.1",
						},
					},
					{
						Name:        "rr-route-reflector-node1-instance0-v4",
						PeerAddress: ptr.To("10.0.0.1"),
						PeerASN:     ptr.To(int64(65000)),
						PeerConfigRef: &v1.PeerConfigReference{
							Name: "255.0.0.1-peer-config-v4",
						},
						RouteReflector: &v1.NodeRouteReflector{
							Role:      v1.RouteReflectorRoleRouteReflector,
							ClusterID: "255.0.0.1",
						},
					},
					{
						Name:        "rr-route-reflector-node1-instance0-v6",
						PeerAddress: ptr.To("fd00:10::1"),
						PeerASN:     ptr.To(int64(65000)),
						PeerConfigRef: &v1.PeerConfigReference{
							Name: "255.0.0.1-peer-config-v6",
						},
						RouteReflector: &v1.NodeRouteReflector{
							Role:      v1.RouteReflectorRoleRouteReflector,
							ClusterID: "255.0.0.1",
						},
					},
				},
				"node1": {
					{
						Name:        "rr-client-node2-instance0-v4",
						PeerAddress: ptr.To("10.0.0.2"),
						PeerASN:     ptr.To(int64(65000)),
						PeerConfigRef: &v1.PeerConfigReference{
							Name: "255.0.0.1-peer-config-v4",
						},
						RouteReflector: &v1.NodeRouteReflector{
							Role:      v1.RouteReflectorRoleClient,
							ClusterID: "255.0.0.1",
						},
					},
					{
						Name:        "rr-client-node2-instance0-v6",
						PeerAddress: ptr.To("fd00:10::2"),
						PeerASN:     ptr.To(int64(65000)),
						PeerConfigRef: &v1.PeerConfigReference{
							Name: "255.0.0.1-peer-config-v6",
						},
						RouteReflector: &v1.NodeRouteReflector{
							Role:      v1.RouteReflectorRoleClient,
							ClusterID: "255.0.0.1",
						},
					},
					{
						Name:        "rr-client-node3-instance0-v4",
						PeerAddress: ptr.To("10.0.0.3"),
						PeerASN:     ptr.To(int64(65000)),
						PeerConfigRef: &v1.PeerConfigReference{
							Name: "255.0.0.1-peer-config-v4",
						},
						RouteReflector: &v1.NodeRouteReflector{
							Role:      v1.RouteReflectorRoleClient,
							ClusterID: "255.0.0.1",
						},
					},
					{
						Name:        "rr-client-node3-instance0-v6",
						PeerAddress: ptr.To("fd00:10::3"),
						PeerASN:     ptr.To(int64(65000)),
						PeerConfigRef: &v1.PeerConfigReference{
							Name: "255.0.0.1-peer-config-v6",
						},
						RouteReflector: &v1.NodeRouteReflector{
							Role:      v1.RouteReflectorRoleClient,
							ClusterID: "255.0.0.1",
						},
					},
					{
						Name:        "rr-route-reflector-node0-instance0-v4",
						PeerAddress: ptr.To("10.0.0.0"),
						PeerASN:     ptr.To(int64(65000)),
						PeerConfigRef: &v1.PeerConfigReference{
							Name: "255.0.0.1-peer-config-v4",
						},
						RouteReflector: &v1.NodeRouteReflector{
							Role:      v1.RouteReflectorRoleRouteReflector,
							ClusterID: "255.0.0.1",
						},
					},
					{
						Name:        "rr-route-reflector-node0-instance0-v6",
						PeerAddress: ptr.To("fd00:10::"),
						PeerASN:     ptr.To(int64(65000)),
						PeerConfigRef: &v1.PeerConfigReference{
							Name: "255.0.0.1-peer-config-v6",
						},
						RouteReflector: &v1.NodeRouteReflector{
							Role:      v1.RouteReflectorRoleRouteReflector,
							ClusterID: "255.0.0.1",
						},
					},
				},
				"node2": {
					{
						Name:        "rr-route-reflector-node0-instance0-v4",
						PeerAddress: ptr.To("10.0.0.0"),
						PeerASN:     ptr.To(int64(65000)),
						PeerConfigRef: &v1.PeerConfigReference{
							Name: "255.0.0.1-peer-config-v4",
						},
						RouteReflector: &v1.NodeRouteReflector{
							Role:      v1.RouteReflectorRoleRouteReflector,
							ClusterID: "255.0.0.1",
						},
					},
					{
						Name:        "rr-route-reflector-node0-instance0-v6",
						PeerAddress: ptr.To("fd00:10::"),
						PeerASN:     ptr.To(int64(65000)),
						PeerConfigRef: &v1.PeerConfigReference{
							Name: "255.0.0.1-peer-config-v6",
						},
						RouteReflector: &v1.NodeRouteReflector{
							Role:      v1.RouteReflectorRoleRouteReflector,
							ClusterID: "255.0.0.1",
						},
					},
					{
						Name:        "rr-route-reflector-node1-instance0-v4",
						PeerAddress: ptr.To("10.0.0.1"),
						PeerASN:     ptr.To(int64(65000)),
						PeerConfigRef: &v1.PeerConfigReference{
							Name: "255.0.0.1-peer-config-v4",
						},
						RouteReflector: &v1.NodeRouteReflector{
							Role:      v1.RouteReflectorRoleRouteReflector,
							ClusterID: "255.0.0.1",
						},
					},
					{
						Name:        "rr-route-reflector-node1-instance0-v6",
						PeerAddress: ptr.To("fd00:10::1"),
						PeerASN:     ptr.To(int64(65000)),
						PeerConfigRef: &v1.PeerConfigReference{
							Name: "255.0.0.1-peer-config-v6",
						},
						RouteReflector: &v1.NodeRouteReflector{
							Role:      v1.RouteReflectorRoleRouteReflector,
							ClusterID: "255.0.0.1",
						},
					},
				},
				"node3": {
					{
						Name:        "rr-route-reflector-node0-instance0-v4",
						PeerAddress: ptr.To("10.0.0.0"),
						PeerASN:     ptr.To(int64(65000)),
						PeerConfigRef: &v1.PeerConfigReference{
							Name: "255.0.0.1-peer-config-v4",
						},
						RouteReflector: &v1.NodeRouteReflector{
							Role:      v1.RouteReflectorRoleRouteReflector,
							ClusterID: "255.0.0.1",
						},
					},
					{
						Name:        "rr-route-reflector-node0-instance0-v6",
						PeerAddress: ptr.To("fd00:10::"),
						PeerASN:     ptr.To(int64(65000)),
						PeerConfigRef: &v1.PeerConfigReference{
							Name: "255.0.0.1-peer-config-v6",
						},
						RouteReflector: &v1.NodeRouteReflector{
							Role:      v1.RouteReflectorRoleRouteReflector,
							ClusterID: "255.0.0.1",
						},
					},
					{
						Name:        "rr-route-reflector-node1-instance0-v4",
						PeerAddress: ptr.To("10.0.0.1"),
						PeerASN:     ptr.To(int64(65000)),
						PeerConfigRef: &v1.PeerConfigReference{
							Name: "255.0.0.1-peer-config-v4",
						},
						RouteReflector: &v1.NodeRouteReflector{
							Role:      v1.RouteReflectorRoleRouteReflector,
							ClusterID: "255.0.0.1",
						},
					},
					{
						Name:        "rr-route-reflector-node1-instance0-v6",
						PeerAddress: ptr.To("fd00:10::1"),
						PeerASN:     ptr.To(int64(65000)),
						PeerConfigRef: &v1.PeerConfigReference{
							Name: "255.0.0.1-peer-config-v6",
						},
						RouteReflector: &v1.NodeRouteReflector{
							Role:      v1.RouteReflectorRoleRouteReflector,
							ClusterID: "255.0.0.1",
						},
					},
				},
			},
		},
		{
			name: "Two Clusters",
			clusterConfigs: []*v1.IsovalentBGPClusterConfig{
				newClusterConfig("rrs-cluster0", v1.RouteReflectorRoleRouteReflector, "255.0.0.1"),
				newClusterConfig("clients-cluster0", v1.RouteReflectorRoleClient, "255.0.0.1"),
				newClusterConfig("rrs-cluster1", v1.RouteReflectorRoleRouteReflector, "255.0.0.2"),
				newClusterConfig("clients-cluster1", v1.RouteReflectorRoleClient, "255.0.0.2"),
			},
			nodes: []*cilium_v2.CiliumNode{
				newNode("node0", v1.RouteReflectorRoleRouteReflector, "255.0.0.1", "10.0.0.0", "fd00:10::"),
				newNode("node1", v1.RouteReflectorRoleClient, "255.0.0.1", "10.0.0.1", "fd00:10::1"),
				newNode("node2", v1.RouteReflectorRoleRouteReflector, "255.0.0.2", "10.0.0.2", "fd00:10::2"),
				newNode("node3", v1.RouteReflectorRoleClient, "255.0.0.2", "10.0.0.3", "fd00:10::3"),
			},
			expectedNodePeers: map[string][]v1.IsovalentBGPNodePeer{
				"node0": {
					{
						Name:        "rr-client-node1-instance0-v4",
						PeerAddress: ptr.To("10.0.0.1"),
						PeerASN:     ptr.To(int64(65000)),
						PeerConfigRef: &v1.PeerConfigReference{
							Name: "255.0.0.1-peer-config-v4",
						},
						RouteReflector: &v1.NodeRouteReflector{
							Role:      v1.RouteReflectorRoleClient,
							ClusterID: "255.0.0.1",
						},
					},
					{
						Name:        "rr-client-node1-instance0-v6",
						PeerAddress: ptr.To("fd00:10::1"),
						PeerASN:     ptr.To(int64(65000)),
						PeerConfigRef: &v1.PeerConfigReference{
							Name: "255.0.0.1-peer-config-v6",
						},
						RouteReflector: &v1.NodeRouteReflector{
							Role:      v1.RouteReflectorRoleClient,
							ClusterID: "255.0.0.1",
						},
					},
				},
				"node1": {
					{
						Name:        "rr-route-reflector-node0-instance0-v4",
						PeerAddress: ptr.To("10.0.0.0"),
						PeerASN:     ptr.To(int64(65000)),
						PeerConfigRef: &v1.PeerConfigReference{
							Name: "255.0.0.1-peer-config-v4",
						},
						RouteReflector: &v1.NodeRouteReflector{
							Role:      v1.RouteReflectorRoleRouteReflector,
							ClusterID: "255.0.0.1",
						},
					},
					{
						Name:        "rr-route-reflector-node0-instance0-v6",
						PeerAddress: ptr.To("fd00:10::"),
						PeerASN:     ptr.To(int64(65000)),
						PeerConfigRef: &v1.PeerConfigReference{
							Name: "255.0.0.1-peer-config-v6",
						},
						RouteReflector: &v1.NodeRouteReflector{
							Role:      v1.RouteReflectorRoleRouteReflector,
							ClusterID: "255.0.0.1",
						},
					},
				},
				"node2": {
					{
						Name:        "rr-client-node3-instance0-v4",
						PeerAddress: ptr.To("10.0.0.3"),
						PeerASN:     ptr.To(int64(65000)),
						PeerConfigRef: &v1.PeerConfigReference{
							Name: "255.0.0.2-peer-config-v4",
						},
						RouteReflector: &v1.NodeRouteReflector{
							Role:      v1.RouteReflectorRoleClient,
							ClusterID: "255.0.0.2",
						},
					},
					{
						Name:        "rr-client-node3-instance0-v6",
						PeerAddress: ptr.To("fd00:10::3"),
						PeerASN:     ptr.To(int64(65000)),
						PeerConfigRef: &v1.PeerConfigReference{
							Name: "255.0.0.2-peer-config-v6",
						},
						RouteReflector: &v1.NodeRouteReflector{
							Role:      v1.RouteReflectorRoleClient,
							ClusterID: "255.0.0.2",
						},
					},
				},
				"node3": {
					{
						Name:        "rr-route-reflector-node2-instance0-v4",
						PeerAddress: ptr.To("10.0.0.2"),
						PeerASN:     ptr.To(int64(65000)),
						PeerConfigRef: &v1.PeerConfigReference{
							Name: "255.0.0.2-peer-config-v4",
						},
						RouteReflector: &v1.NodeRouteReflector{
							Role:      v1.RouteReflectorRoleRouteReflector,
							ClusterID: "255.0.0.2",
						},
					},
					{
						Name:        "rr-route-reflector-node2-instance0-v6",
						PeerAddress: ptr.To("fd00:10::2"),
						PeerASN:     ptr.To(int64(65000)),
						PeerConfigRef: &v1.PeerConfigReference{
							Name: "255.0.0.2-peer-config-v6",
						},
						RouteReflector: &v1.NodeRouteReflector{
							Role:      v1.RouteReflectorRoleRouteReflector,
							ClusterID: "255.0.0.2",
						},
					},
				},
			},
		},
		{
			name: "No RR",
			clusterConfigs: []*v1.IsovalentBGPClusterConfig{
				newClusterConfig("rrs", v1.RouteReflectorRoleRouteReflector, "255.0.0.1"),
				newClusterConfig("clients", v1.RouteReflectorRoleClient, "255.0.0.1"),
			},
			nodes: []*cilium_v2.CiliumNode{
				newNode("node0", v1.RouteReflectorRoleClient, "255.0.0.1", "10.0.0.0", "fd00:10::"),
				newNode("node1", v1.RouteReflectorRoleClient, "255.0.0.1", "10.0.0.1", "fd00:10::1"),
			},
			expectedNodePeers: map[string][]v1.IsovalentBGPNodePeer{
				"node0": nil,
				"node1": nil,
			},
		},
		{
			name: "No Client",
			clusterConfigs: []*v1.IsovalentBGPClusterConfig{
				newClusterConfig("rrs", v1.RouteReflectorRoleRouteReflector, "255.0.0.1"),
				newClusterConfig("clients", v1.RouteReflectorRoleClient, "255.0.0.1"),
			},
			nodes: []*cilium_v2.CiliumNode{
				newNode("node0", v1.RouteReflectorRoleRouteReflector, "255.0.0.1", "10.0.0.0", "fd00:10::"),
				newNode("node1", v1.RouteReflectorRoleRouteReflector, "255.0.0.1", "10.0.0.1", "fd00:10::1"),
			},
			expectedNodePeers: map[string][]v1.IsovalentBGPNodePeer{
				"node0": {
					{
						Name:        "rr-route-reflector-node1-instance0-v4",
						PeerAddress: ptr.To("10.0.0.1"),
						PeerASN:     ptr.To(int64(65000)),
						PeerConfigRef: &v1.PeerConfigReference{
							Name: "255.0.0.1-peer-config-v4",
						},
						RouteReflector: &v1.NodeRouteReflector{
							Role:      v1.RouteReflectorRoleRouteReflector,
							ClusterID: "255.0.0.1",
						},
					},
					{
						Name:        "rr-route-reflector-node1-instance0-v6",
						PeerAddress: ptr.To("fd00:10::1"),
						PeerASN:     ptr.To(int64(65000)),
						PeerConfigRef: &v1.PeerConfigReference{
							Name: "255.0.0.1-peer-config-v6",
						},
						RouteReflector: &v1.NodeRouteReflector{
							Role:      v1.RouteReflectorRoleRouteReflector,
							ClusterID: "255.0.0.1",
						},
					},
				},
				"node1": {
					{
						Name:        "rr-route-reflector-node0-instance0-v4",
						PeerAddress: ptr.To("10.0.0.0"),
						PeerASN:     ptr.To(int64(65000)),
						PeerConfigRef: &v1.PeerConfigReference{
							Name: "255.0.0.1-peer-config-v4",
						},
						RouteReflector: &v1.NodeRouteReflector{
							Role:      v1.RouteReflectorRoleRouteReflector,
							ClusterID: "255.0.0.1",
						},
					},
					{
						Name:        "rr-route-reflector-node0-instance0-v6",
						PeerAddress: ptr.To("fd00:10::"),
						PeerASN:     ptr.To(int64(65000)),
						PeerConfigRef: &v1.PeerConfigReference{
							Name: "255.0.0.1-peer-config-v6",
						},
						RouteReflector: &v1.NodeRouteReflector{
							Role:      v1.RouteReflectorRoleRouteReflector,
							ClusterID: "255.0.0.1",
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := populateReconcileCache(tt.clusterConfigs, []*v1.IsovalentBGPNodeConfig{}, tt.nodes, []*v1.IsovalentBGPNodeConfigOverride{}, v1.RouteReflectorPeeringAddressFamilyDual)
			for _, nodeConfig := range (&BGPResourceMapper{}).desiredNodeConfigs(cache) {
				require.Equal(t, nodeConfig.Spec.BGPInstances[0].Peers, tt.expectedNodePeers[nodeConfig.Name])
			}
		})
	}
}

func TestRRPeeringMultiInstance(t *testing.T) {
	newNode := func(name string, rrRole v1.RouteReflectorRole, ipv4, ipv6 string) *cilium_v2.CiliumNode {
		return &cilium_v2.CiliumNode{
			ObjectMeta: meta_v1.ObjectMeta{
				Name: name,
				Labels: map[string]string{
					"rr-role": string(rrRole),
				},
			},
			Spec: cilium_v2.NodeSpec{
				Addresses: []cilium_v2.NodeAddress{
					{
						Type: addressing.NodeInternalIP,
						IP:   ipv4,
					},
					{
						Type: addressing.NodeInternalIP,
						IP:   ipv6,
					},
				},
			},
		}
	}

	rrClusterConfig := v1.IsovalentBGPClusterConfig{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "rrs",
		},
		Spec: v1.IsovalentBGPClusterConfigSpec{
			NodeSelector: &slim_meta_v1.LabelSelector{
				MatchLabels: map[string]string{
					"rr-role": string(v1.RouteReflectorRoleRouteReflector),
				},
			},
			BGPInstances: []v1.IsovalentBGPInstance{
				{
					Name:     "instance0",
					LocalASN: ptr.To(int64(65000)),
					// TODO: Specify port
					RouteReflector: &v1.RouteReflector{
						Role:                 v1.RouteReflectorRoleRouteReflector,
						ClusterID:            "255.0.0.1",
						PeeringAddressFamily: ptr.To(v1.RouteReflectorPeeringAddressFamilyDual),
						PeerConfigRefV4: &v1.PeerConfigReference{
							Name: "255.0.0.1-peer-config-v4",
						},
						PeerConfigRefV6: &v1.PeerConfigReference{
							Name: "255.0.0.1-peer-config-v6",
						},
					},
				},
				{
					Name:     "instance1",
					LocalASN: ptr.To(int64(65000)),
					// TODO: Specify port
					RouteReflector: &v1.RouteReflector{
						Role:                 v1.RouteReflectorRoleRouteReflector,
						ClusterID:            "255.0.0.2",
						PeeringAddressFamily: ptr.To(v1.RouteReflectorPeeringAddressFamilyDual),
						PeerConfigRefV4: &v1.PeerConfigReference{
							Name: "255.0.0.2-peer-config-v4",
						},
						PeerConfigRefV6: &v1.PeerConfigReference{
							Name: "255.0.0.2-peer-config-v6",
						},
					},
				},
			},
		},
	}

	clientClusterConfig := v1.IsovalentBGPClusterConfig{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "clients",
		},
		Spec: v1.IsovalentBGPClusterConfigSpec{
			NodeSelector: &slim_meta_v1.LabelSelector{
				MatchLabels: map[string]string{
					"rr-role": string(v1.RouteReflectorRoleClient),
				},
			},
			BGPInstances: []v1.IsovalentBGPInstance{
				{
					Name:     "instance0",
					LocalASN: ptr.To(int64(65000)),
					// TODO: Specify port
					RouteReflector: &v1.RouteReflector{
						Role:                 v1.RouteReflectorRoleClient,
						ClusterID:            "255.0.0.2",
						PeeringAddressFamily: ptr.To(v1.RouteReflectorPeeringAddressFamilyDual),
						PeerConfigRefV4: &v1.PeerConfigReference{
							Name: "255.0.0.2-peer-config-v4",
						},
						PeerConfigRefV6: &v1.PeerConfigReference{
							Name: "255.0.0.2-peer-config-v6",
						},
					},
				},
				{
					Name:     "instance1",
					LocalASN: ptr.To(int64(65000)),
					// TODO: Specify port
					RouteReflector: &v1.RouteReflector{
						Role:                 v1.RouteReflectorRoleClient,
						ClusterID:            "255.0.0.1",
						PeeringAddressFamily: ptr.To(v1.RouteReflectorPeeringAddressFamilyDual),
						PeerConfigRefV4: &v1.PeerConfigReference{
							Name: "255.0.0.1-peer-config-v4",
						},
						PeerConfigRefV6: &v1.PeerConfigReference{
							Name: "255.0.0.1-peer-config-v6",
						},
					},
				},
			},
		},
	}

	// node => instance => peers
	expectedNodePeers := map[string]map[string][]v1.IsovalentBGPNodePeer{
		"node0": {
			"instance0": {
				{
					Name:        "rr-client-node1-instance1-v4",
					PeerAddress: ptr.To("10.0.0.1"),
					PeerASN:     ptr.To(int64(65000)),
					PeerConfigRef: &v1.PeerConfigReference{
						Name: "255.0.0.1-peer-config-v4",
					},
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleClient,
						ClusterID: "255.0.0.1",
					},
				},
				{
					Name:        "rr-client-node1-instance1-v6",
					PeerAddress: ptr.To("fd00:10::1"),
					PeerASN:     ptr.To(int64(65000)),
					PeerConfigRef: &v1.PeerConfigReference{
						Name: "255.0.0.1-peer-config-v6",
					},
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleClient,
						ClusterID: "255.0.0.1",
					},
				},
			},
			"instance1": {
				{
					Name:        "rr-client-node1-instance0-v4",
					PeerAddress: ptr.To("10.0.0.1"),
					PeerASN:     ptr.To(int64(65000)),
					PeerConfigRef: &v1.PeerConfigReference{
						Name: "255.0.0.2-peer-config-v4",
					},
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleClient,
						ClusterID: "255.0.0.2",
					},
				},
				{
					Name:        "rr-client-node1-instance0-v6",
					PeerAddress: ptr.To("fd00:10::1"),
					PeerASN:     ptr.To(int64(65000)),
					PeerConfigRef: &v1.PeerConfigReference{
						Name: "255.0.0.2-peer-config-v6",
					},
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleClient,
						ClusterID: "255.0.0.2",
					},
				},
			},
		},
		"node1": {
			"instance0": {
				{
					Name:        "rr-route-reflector-node0-instance1-v4",
					PeerAddress: ptr.To("10.0.0.0"),
					PeerASN:     ptr.To(int64(65000)),
					PeerConfigRef: &v1.PeerConfigReference{
						Name: "255.0.0.2-peer-config-v4",
					},
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleRouteReflector,
						ClusterID: "255.0.0.2",
					},
				},
				{
					Name:        "rr-route-reflector-node0-instance1-v6",
					PeerAddress: ptr.To("fd00:10::"),
					PeerASN:     ptr.To(int64(65000)),
					PeerConfigRef: &v1.PeerConfigReference{
						Name: "255.0.0.2-peer-config-v6",
					},
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleRouteReflector,
						ClusterID: "255.0.0.2",
					},
				},
			},
			"instance1": {
				{
					Name:        "rr-route-reflector-node0-instance0-v4",
					PeerAddress: ptr.To("10.0.0.0"),
					PeerASN:     ptr.To(int64(65000)),
					PeerConfigRef: &v1.PeerConfigReference{
						Name: "255.0.0.1-peer-config-v4",
					},
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleRouteReflector,
						ClusterID: "255.0.0.1",
					},
				},
				{
					Name:        "rr-route-reflector-node0-instance0-v6",
					PeerAddress: ptr.To("fd00:10::"),
					PeerASN:     ptr.To(int64(65000)),
					PeerConfigRef: &v1.PeerConfigReference{
						Name: "255.0.0.1-peer-config-v6",
					},
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleRouteReflector,
						ClusterID: "255.0.0.1",
					},
				},
			},
		},
	}

	node0 := newNode("node0", v1.RouteReflectorRoleRouteReflector, "10.0.0.0", "fd00:10::")
	node1 := newNode("node1", v1.RouteReflectorRoleClient, "10.0.0.1", "fd00:10::1")

	cache := populateReconcileCache(
		[]*v1.IsovalentBGPClusterConfig{&rrClusterConfig, &clientClusterConfig},
		[]*v1.IsovalentBGPNodeConfig{},
		[]*cilium_v2.CiliumNode{node0, node1},
		[]*v1.IsovalentBGPNodeConfigOverride{},
		v1.RouteReflectorPeeringAddressFamilyDual,
	)
	for _, nodeConfig := range (&BGPResourceMapper{}).desiredNodeConfigs(cache) {
		for _, instance := range nodeConfig.Spec.BGPInstances {
			require.Equal(t, expectedNodePeers[nodeConfig.Name][instance.Name], instance.Peers)
		}
	}
}

func upsertNode(req *require.Assertions, ctx context.Context, f *fixture, node *cilium_v2.CiliumNode) {
	prev, err := f.nodeClient.Get(ctx, node.Name, meta_v1.GetOptions{})
	if err != nil && k8sErrors.IsNotFound(err) {
		_, err = f.nodeClient.Create(ctx, node, meta_v1.CreateOptions{})
	} else if err != nil {
		req.Fail(err.Error())
	} else {
		node.SetResourceVersion(prev.GetResourceVersion())
		_, err = f.nodeClient.Update(ctx, node, meta_v1.UpdateOptions{})
	}
	req.NoError(err)
}

func upsertIsoBGPCC(req *require.Assertions, ctx context.Context, f *fixture, bgpcc *v1.IsovalentBGPClusterConfig) {
	if bgpcc == nil {
		return
	}

	prev, err := f.isoClusterClient.Get(ctx, bgpcc.Name, meta_v1.GetOptions{})
	if err != nil && k8sErrors.IsNotFound(err) {
		_, err = f.isoClusterClient.Create(ctx, bgpcc, meta_v1.CreateOptions{})
	} else if err != nil {
		req.Fail(err.Error())
	} else {
		bgpcc.SetResourceVersion(prev.GetResourceVersion())
		_, err = f.isoClusterClient.Update(ctx, bgpcc, meta_v1.UpdateOptions{})
	}
	req.NoError(err)
}

func upsertIsoBGPPC(req *require.Assertions, ctx context.Context, f *fixture, bgppc *v1.IsovalentBGPPeerConfig) {
	if bgppc == nil {
		return
	}

	prev, err := f.isoPeerConfClient.Get(ctx, bgppc.Name, meta_v1.GetOptions{})
	if err != nil && k8sErrors.IsNotFound(err) {
		_, err = f.isoPeerConfClient.Create(ctx, bgppc, meta_v1.CreateOptions{})
	} else if err != nil {
		req.Fail(err.Error())
	} else {
		bgppc.SetResourceVersion(prev.GetResourceVersion())
		_, err = f.isoPeerConfClient.Update(ctx, bgppc, meta_v1.UpdateOptions{})
	}
	req.NoError(err)
}

func upsertIsoBGPNodeConfigOR(req *require.Assertions, ctx context.Context, f *fixture, bgpNodeConfigOR *v1.IsovalentBGPNodeConfigOverride) {
	if bgpNodeConfigOR == nil {
		return
	}

	prev, err := f.isoBGPNodeConfORClient.Get(ctx, bgpNodeConfigOR.Name, meta_v1.GetOptions{})
	if err != nil && k8sErrors.IsNotFound(err) {
		_, err = f.isoBGPNodeConfORClient.Create(ctx, bgpNodeConfigOR, meta_v1.CreateOptions{})
	} else if err != nil {
		req.Fail(err.Error())
	} else {
		bgpNodeConfigOR.SetResourceVersion(prev.GetResourceVersion())
		_, err = f.isoBGPNodeConfORClient.Update(ctx, bgpNodeConfigOR, meta_v1.UpdateOptions{})
	}
	req.NoError(err)
}

func upsertIsoVrf(req *require.Assertions, ctx context.Context, f *fixture, vrf *v1alpha1.IsovalentVRF) {
	if vrf == nil {
		return
	}

	prev, err := f.isoVrfClient.Get(ctx, vrf.Name, meta_v1.GetOptions{})
	if err != nil && k8s_errors.IsNotFound(err) {
		_, err = f.isoVrfClient.Create(ctx, vrf, meta_v1.CreateOptions{})
	} else if err != nil {
		req.Fail(err.Error())
	} else {
		vrf.SetResourceVersion(prev.GetResourceVersion())
		_, err = f.isoVrfClient.Update(ctx, vrf, meta_v1.UpdateOptions{})
	}
	req.NoError(err)
}

func upsertIsoBGPVrfConfig(req *require.Assertions, ctx context.Context, f *fixture, vrfConfig *v1alpha1.IsovalentBGPVRFConfig) {
	if vrfConfig == nil {
		return
	}

	prev, err := f.isoBGPVrfClient.Get(ctx, vrfConfig.Name, meta_v1.GetOptions{})
	if err != nil && k8sErrors.IsNotFound(err) {
		_, err = f.isoBGPVrfClient.Create(ctx, vrfConfig, meta_v1.CreateOptions{})
	} else if err != nil {
		req.Fail(err.Error())
	} else {
		vrfConfig.SetResourceVersion(prev.GetResourceVersion())
		_, err = f.isoBGPVrfClient.Update(ctx, vrfConfig, meta_v1.UpdateOptions{})
	}
	req.NoError(err)
}
