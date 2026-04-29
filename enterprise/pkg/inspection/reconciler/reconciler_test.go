//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package reconciler

import (
	"log/slog"
	"maps"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	inspectionConfig "github.com/cilium/cilium/enterprise/pkg/inspection/config"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/k8s"
	ciliumio "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	isovalent_api_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
)

type fakeEndpoint struct {
	namespace  string
	name       string
	id         *identity.Identity
	properties map[string]any
}

type fakeEndpointRegistry struct {
	endpoints []*endpoint.Endpoint
	byID      map[uint16]*endpoint.Endpoint
}

func (f *fakeEndpointRegistry) Subscribe(endpointmanager.Subscriber)        {}
func (f *fakeEndpointRegistry) Unsubscribe(endpointmanager.Subscriber)      {}
func (f *fakeEndpointRegistry) GetEndpoints() []*endpoint.Endpoint          { return f.endpoints }
func (f *fakeEndpointRegistry) LookupCiliumID(id uint16) *endpoint.Endpoint { return f.byID[id] }

func (f *fakeEndpoint) K8sNamespaceAndPodNameIsSet() bool { return f.namespace != "" && f.name != "" }
func (f *fakeEndpoint) GetSecurityIdentity() (*identity.Identity, error) {
	return f.id, nil
}
func (f *fakeEndpoint) GetPropertyValue(key string) any { return f.properties[key] }
func (f *fakeEndpoint) SetPropertyValue(key string, value any) any {
	old := f.properties[key]
	f.properties[key] = value
	return old
}

func newTestReconciler(t *testing.T) *inspectionReconciler {
	t.Helper()

	r := &inspectionReconciler{
		synced:             make(chan struct{}),
		selectorStore:      inspectionConfig.NewSelectorStore(),
		pendingEndpointIDs: map[uint16]struct{}{},
	}
	r.setSelector(nil)
	return r
}

func newFakeEndpoint(namespace, name string, podLabels, namespaceLabels map[string]string, properties map[string]any) *fakeEndpoint {
	allLabels := map[string]string{
		ciliumio.PodNamespaceLabel:         namespace,
		ciliumio.PodNamespaceMetaNameLabel: namespace,
	}
	maps.Copy(allLabels, podLabels)
	for key, value := range namespaceLabels {
		allLabels[ciliumio.PodNamespaceMetaLabelsPrefix+key] = value
	}

	idLabels := labels.Map2Labels(allLabels, labels.LabelSourceK8s)
	id := &identity.Identity{Labels: idLabels}
	id.Sanitize()

	if properties == nil {
		properties = map[string]any{}
	}

	return &fakeEndpoint{
		namespace:  namespace,
		name:       name,
		id:         id,
		properties: properties,
	}
}

// endpointSelector builds an api.EndpointSelector from raw match labels and
// expressions, mirroring how a user would write it in YAML.
func endpointSelector(matchLabels map[string]string, expressions ...slimv1.LabelSelectorRequirement) *api.EndpointSelector {
	es := &api.EndpointSelector{LabelSelector: &slimv1.LabelSelector{
		MatchLabels:      matchLabels,
		MatchExpressions: expressions,
	}}
	return es
}

func TestInspectionReconciler_ReconcileEndpointState(t *testing.T) {
	r := newTestReconciler(t)
	// Select endpoints in namespace "payments" with app=checkout, but exclude
	// the "checkout-canary" rollout via NotIn.
	r.upsertConfig(&isovalent_api_v1alpha1.IsovalentInspectionConfig{
		ObjectMeta: metav1.ObjectMeta{Name: isovalent_api_v1alpha1.InspectionConfigName},
		Spec: isovalent_api_v1alpha1.IsovalentInspectionConfigSpec{
			EndpointSelector: endpointSelector(
				map[string]string{
					ciliumio.PodNamespaceLabel: "payments",
				},
				slimv1.LabelSelectorRequirement{
					Key:      "app",
					Operator: slimv1.LabelSelectorOpNotIn,
					Values:   []string{"checkout-canary"},
				},
			),
		},
	})

	tests := []struct {
		name      string
		ep        *fakeEndpoint
		wantValue any
		wantRegen bool
	}{
		{
			name:      "different namespace is disabled",
			ep:        newFakeEndpoint("security-tools", "snort", map[string]string{"app": "snort"}, nil, nil),
			wantValue: false,
			wantRegen: true,
		},
		{
			name:      "matched workload with missing cache regenerates to stamp enabled state",
			ep:        newFakeEndpoint("payments", "checkout-0", map[string]string{"app": "checkout"}, nil, nil),
			wantValue: true,
			wantRegen: true,
		},
		{
			name: "NotIn expression excludes canary even in matched namespace",
			ep: newFakeEndpoint(
				"payments",
				"checkout-canary-0",
				map[string]string{"app": "checkout-canary"},
				nil,
				map[string]any{inspectionConfig.PropertyEndpointEnabled: true},
			),
			wantValue: false,
			wantRegen: true,
		},
		{
			name: "matched workload with cached false regenerates back to enabled",
			ep: newFakeEndpoint(
				"payments",
				"checkout-1",
				map[string]string{"app": "checkout"},
				nil,
				map[string]any{inspectionConfig.PropertyEndpointEnabled: false},
			),
			wantValue: true,
			wantRegen: true,
		},
		{
			name:      "non matched workload is disabled",
			ep:        newFakeEndpoint("default", "client", map[string]string{"app": "client"}, nil, nil),
			wantValue: false,
			wantRegen: true,
		},
		{
			name: "excluded workload with cached false stays disabled without regeneration",
			ep: newFakeEndpoint(
				"security-tools",
				"snort-1",
				map[string]string{"app": "snort"},
				nil,
				map[string]any{inspectionConfig.PropertyEndpointEnabled: false},
			),
			wantValue: false,
			wantRegen: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var regenerated bool
			r.reconcileEndpointState(tt.ep, func() { regenerated = true })
			require.Equal(t, tt.wantValue, tt.ep.properties[inspectionConfig.PropertyEndpointEnabled])
			require.Equal(t, tt.wantRegen, regenerated)
		})
	}
}

func TestInspectionReconciler_DefaultConfigLifecycle(t *testing.T) {
	r := newTestReconciler(t)

	kubeSystem := newFakeEndpoint("kube-system", "dns", map[string]string{"app": "dns"}, nil, nil)
	monitoring := newFakeEndpoint("monitoring", "prometheus", map[string]string{"app": "prometheus"}, nil, nil)

	// Exclude kube-system and security-tools using a NotIn expression.
	r.upsertConfig(&isovalent_api_v1alpha1.IsovalentInspectionConfig{
		ObjectMeta: metav1.ObjectMeta{Name: isovalent_api_v1alpha1.InspectionConfigName},
		Spec: isovalent_api_v1alpha1.IsovalentInspectionConfigSpec{
			EndpointSelector: endpointSelector(nil, slimv1.LabelSelectorRequirement{
				Key:      ciliumio.PodNamespaceLabel,
				Operator: slimv1.LabelSelectorOpNotIn,
				Values:   []string{"kube-system", "security-tools"},
			}),
		},
	})
	enabled, ok := r.desiredEnabledForEndpoint(kubeSystem)
	require.True(t, ok)
	require.False(t, enabled)

	// Switch the exclusion to monitoring only.
	r.upsertConfig(&isovalent_api_v1alpha1.IsovalentInspectionConfig{
		ObjectMeta: metav1.ObjectMeta{Name: isovalent_api_v1alpha1.InspectionConfigName},
		Spec: isovalent_api_v1alpha1.IsovalentInspectionConfigSpec{
			EndpointSelector: endpointSelector(nil, slimv1.LabelSelectorRequirement{
				Key:      ciliumio.PodNamespaceLabel,
				Operator: slimv1.LabelSelectorOpNotIn,
				Values:   []string{"monitoring"},
			}),
		},
	})
	enabled, ok = r.desiredEnabledForEndpoint(kubeSystem)
	require.True(t, ok)
	require.True(t, enabled)

	enabled, ok = r.desiredEnabledForEndpoint(monitoring)
	require.True(t, ok)
	require.False(t, enabled)

	// Deleting another config must not reset the default config.
	r.deleteConfig("custom")
	enabled, ok = r.desiredEnabledForEndpoint(monitoring)
	require.True(t, ok)
	require.False(t, enabled)

	// Deleting the config restores the wildcard (everything enabled).
	r.deleteConfig(isovalent_api_v1alpha1.InspectionConfigName)
	enabled, ok = r.desiredEnabledForEndpoint(monitoring)
	require.True(t, ok)
	require.True(t, enabled)
}

func TestInspectionReconciler_IgnoresNonDefaultConfig(t *testing.T) {
	r := newTestReconciler(t)
	ep := newFakeEndpoint("kube-system", "dns", map[string]string{"app": "dns"}, nil, nil)

	r.upsertConfig(&isovalent_api_v1alpha1.IsovalentInspectionConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "custom"},
		Spec: isovalent_api_v1alpha1.IsovalentInspectionConfigSpec{
			EndpointSelector: endpointSelector(map[string]string{
				ciliumio.PodNamespaceLabel: "payments",
			}),
		},
	})

	enabled, ok := r.desiredEnabledForEndpoint(ep)
	require.True(t, ok)
	require.True(t, enabled)
}

func TestInspectionReconciler_HandleConfigEvents(t *testing.T) {
	r := &inspectionReconciler{
		logger:                slog.Default(),
		synced:                make(chan struct{}),
		selectorStore:         inspectionConfig.NewSelectorStore(),
		pendingEndpointIDs:    map[uint16]struct{}{},
		reconcileRequestsChan: make(chan struct{}, 1),
	}
	require.False(t, r.isSynced())

	r.handleConfigEvent(resource.Event[*isovalent_api_v1alpha1.IsovalentInspectionConfig]{
		Kind: resource.Sync,
	})
	require.True(t, r.isSynced())
	require.True(t, r.selectorStore.HasSelector())
	require.True(t, r.fullReconcilePending)

	fullReconcilePending, pendingIDs := r.snapshotPending()
	require.True(t, fullReconcilePending)
	require.Empty(t, pendingIDs)

	r.handleConfigEvent(resource.Event[*isovalent_api_v1alpha1.IsovalentInspectionConfig]{
		Kind: resource.Upsert,
		Object: &isovalent_api_v1alpha1.IsovalentInspectionConfig{
			ObjectMeta: metav1.ObjectMeta{Name: isovalent_api_v1alpha1.InspectionConfigName},
			Spec: isovalent_api_v1alpha1.IsovalentInspectionConfigSpec{
				EndpointSelector: endpointSelector(map[string]string{
					ciliumio.PodNamespaceLabel: "payments",
				}),
			},
		},
	})
	enabled, ok := r.desiredEnabledForEndpoint(newFakeEndpoint("payments", "checkout", map[string]string{"app": "checkout"}, nil, nil))
	require.True(t, ok)
	require.True(t, enabled)
	enabled, ok = r.desiredEnabledForEndpoint(newFakeEndpoint("default", "client", map[string]string{"app": "client"}, nil, nil))
	require.True(t, ok)
	require.False(t, enabled)

	r.handleConfigEvent(resource.Event[*isovalent_api_v1alpha1.IsovalentInspectionConfig]{
		Kind: resource.Delete,
		Key:  resource.Key{Name: isovalent_api_v1alpha1.InspectionConfigName},
	})
	enabled, ok = r.desiredEnabledForEndpoint(newFakeEndpoint("default", "client", map[string]string{"app": "client"}, nil, nil))
	require.True(t, ok)
	require.True(t, enabled)
}

func TestInspectionReconciler_EndpointSubscriberCallbacks(t *testing.T) {
	r := &inspectionReconciler{
		pendingEndpointIDs:    map[uint16]struct{}{},
		reconcileRequestsChan: make(chan struct{}, 1),
	}

	ep := &endpoint.Endpoint{ID: 42}
	r.EndpointCreated(ep)
	_, ok := r.pendingEndpointIDs[42]
	require.True(t, ok)

	r.EndpointDeleted(ep, endpoint.DeleteConfig{})
	_, ok = r.pendingEndpointIDs[42]
	require.False(t, ok)

	r.EndpointRestored(ep)
	_, ok = r.pendingEndpointIDs[42]
	require.True(t, ok)
}

func TestInspectionReconciler_ProcessPendingWithMissingEndpoints(t *testing.T) {
	r := &inspectionReconciler{
		endpointManager:       &fakeEndpointRegistry{byID: map[uint16]*endpoint.Endpoint{}},
		pendingEndpointIDs:    map[uint16]struct{}{7: {}},
		reconcileRequestsChan: make(chan struct{}, 1),
	}
	r.processPendingReconciles()
	require.Empty(t, r.pendingEndpointIDs)

	r.endpointManager = &fakeEndpointRegistry{}
	r.enqueueFullReconcile()
	r.processPendingReconciles()
	require.False(t, r.fullReconcilePending)
}

func TestInspectionReconciler_SanitizeEndpointSelectorInvalidIsRejected(t *testing.T) {
	r := newTestReconciler(t)
	r.logger = slog.Default()

	selector, ok := r.sanitizeEndpointSelector(endpointSelector(nil, slimv1.LabelSelectorRequirement{
		Key:      "app",
		Operator: slimv1.LabelSelectorOperator("DefinitelyNotARealOperator"),
		Values:   []string{"checkout"},
	}))
	require.Nil(t, selector)
	require.False(t, ok)
}

func TestInspectionReconciler_InvalidSelectorPreservesPreviousSelector(t *testing.T) {
	r := newTestReconciler(t)
	r.logger = slog.Default()

	r.upsertConfig(&isovalent_api_v1alpha1.IsovalentInspectionConfig{
		ObjectMeta: metav1.ObjectMeta{Name: isovalent_api_v1alpha1.InspectionConfigName},
		Spec: isovalent_api_v1alpha1.IsovalentInspectionConfigSpec{
			EndpointSelector: endpointSelector(map[string]string{
				ciliumio.PodNamespaceLabel: "payments",
			}),
		},
	})

	r.upsertConfig(&isovalent_api_v1alpha1.IsovalentInspectionConfig{
		ObjectMeta: metav1.ObjectMeta{Name: isovalent_api_v1alpha1.InspectionConfigName},
		Spec: isovalent_api_v1alpha1.IsovalentInspectionConfigSpec{
			EndpointSelector: endpointSelector(nil, slimv1.LabelSelectorRequirement{
				Key:      "app",
				Operator: slimv1.LabelSelectorOperator("DefinitelyNotARealOperator"),
				Values:   []string{"checkout"},
			}),
		},
	})

	enabled, ok := r.desiredEnabledForEndpoint(newFakeEndpoint("payments", "checkout", map[string]string{"app": "checkout"}, nil, nil))
	require.True(t, ok)
	require.True(t, enabled)
	enabled, ok = r.desiredEnabledForEndpoint(newFakeEndpoint("default", "client", map[string]string{"app": "client"}, nil, nil))
	require.True(t, ok)
	require.False(t, enabled)
}

func TestInspectionReconciler_InvalidInitialSelectorSelectsNone(t *testing.T) {
	r := &inspectionReconciler{
		logger:                slog.Default(),
		synced:                make(chan struct{}),
		selectorStore:         inspectionConfig.NewSelectorStore(),
		pendingEndpointIDs:    map[uint16]struct{}{},
		reconcileRequestsChan: make(chan struct{}, 1),
	}

	r.upsertConfig(&isovalent_api_v1alpha1.IsovalentInspectionConfig{
		ObjectMeta: metav1.ObjectMeta{Name: isovalent_api_v1alpha1.InspectionConfigName},
		Spec: isovalent_api_v1alpha1.IsovalentInspectionConfigSpec{
			EndpointSelector: endpointSelector(nil, slimv1.LabelSelectorRequirement{
				Key:      "app",
				Operator: slimv1.LabelSelectorOperator("DefinitelyNotARealOperator"),
				Values:   []string{"checkout"},
			}),
		},
	})
	r.handleConfigEvent(resource.Event[*isovalent_api_v1alpha1.IsovalentInspectionConfig]{
		Kind: resource.Sync,
	})

	enabled, ok := r.desiredEnabledForEndpoint(newFakeEndpoint("payments", "checkout", map[string]string{"app": "checkout"}, nil, nil))
	require.True(t, ok)
	require.False(t, enabled)
}

func TestNewInspectionConfigResourceDisabled(t *testing.T) {
	res, err := newInspectionConfigResource(inspectionConfig.Config{}, k8s.CiliumResourceParams{})
	require.NoError(t, err)
	require.Nil(t, res)

}

func TestInspectionReconciler_SnapshotPending(t *testing.T) {
	r := &inspectionReconciler{
		pendingEndpointIDs: map[uint16]struct{}{},
	}

	r.enqueueEndpointID(7)
	r.enqueueEndpointID(7)
	r.enqueueEndpointID(11)

	fullReconcilePending, pendingIDs := r.snapshotPending()
	require.False(t, fullReconcilePending)
	require.Equal(t, []uint16{7, 11}, pendingIDs)

	r.enqueueEndpointID(13)
	r.enqueueFullReconcile()
	fullReconcilePending, pendingIDs = r.snapshotPending()
	require.True(t, fullReconcilePending)
	require.Empty(t, pendingIDs)
}
