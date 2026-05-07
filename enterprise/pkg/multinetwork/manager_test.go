// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multinetwork

import (
	"errors"
	"sort"
	"testing"

	"github.com/cilium/statedb"
	"github.com/go-openapi/swag"
	"github.com/google/go-cmp/cmp"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/enterprise/api/v1/models"
	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_meta_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sTables "github.com/cilium/cilium/pkg/k8s/tables"
)

type mockStore[T comparable] map[resource.Key]T

func (m mockStore[T]) List() []T {
	panic("not implemented")
}

func (m mockStore[T]) IterKeys() resource.KeyIter {
	panic("not implemented")
}

func (m mockStore[T]) Get(obj T) (item T, exists bool, err error) {
	panic("not implemented")
}

func (m mockStore[T]) GetByKey(key resource.Key) (item T, exists bool, err error) {
	item, exists = m[key]
	return item, exists, nil
}

func (m mockStore[T]) IndexKeys(indexName, indexedValue string) ([]string, error) {
	panic("not implemented")
}

func (m mockStore[T]) ByIndex(indexName, indexedValue string) ([]T, error) {
	panic("not implemented")
}

func (m mockStore[T]) CacheStore() cache.Store {
	panic("not implemented")
}

func networkKey(name string) resource.Key {
	return resource.Key{
		Name: name,
	}
}

func TestManager_GetNetworksForPod(t *testing.T) {
	db := statedb.New()
	pods, err := k8sTables.NewPodTable(db)
	if err != nil {
		t.Fatalf("NewPodTable: %s", err)
	}
	wtxn := db.WriteTxn(pods)
	newPod := func(namespace, name string, annotations map[string]string) k8sTables.LocalPod {
		return k8sTables.LocalPod{Pod: &slim_core_v1.Pod{
			ObjectMeta: slim_meta_v1.ObjectMeta{
				Namespace:   namespace,
				Name:        name,
				Annotations: annotations,
			},
		}}
	}
	pods.Insert(wtxn, newPod("default", "client", nil))
	pods.Insert(wtxn, newPod("default", "multi-homed-workload", map[string]string{PodNetworkKey: "default,jupiter"}))
	pods.Insert(wtxn, newPod("default", "secondary-only-workload", map[string]string{PodNetworkKey: "jupiter"}))
	pods.Insert(wtxn, newPod("default", "nonexistent-network-workload", map[string]string{PodNetworkKey: "mars"}))
	pods.Insert(wtxn, newPod("default", "existent-and-nonexistent-network-workload", map[string]string{PodNetworkKey: "jupiter,mars"}))
	wtxn.Commit()

	m := &Manager{
		db:   db,
		pods: pods,
		networkStore: mockStore[*iso_v1alpha1.IsovalentPodNetwork]{
			networkKey("default"): &iso_v1alpha1.IsovalentPodNetwork{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: defaultNetwork,
				},
				Spec: iso_v1alpha1.PodNetworkSpec{
					IPAM: iso_v1alpha1.IPAMSpec{
						Mode: "multi-pool",
						Pool: iso_v1alpha1.IPAMPoolSpec{
							Name: "default",
						},
					},
					Routes: []iso_v1alpha1.RouteSpec{},
				},
			},
			networkKey("jupiter"): &iso_v1alpha1.IsovalentPodNetwork{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "jupiter",
				},
				Spec: iso_v1alpha1.PodNetworkSpec{
					IPAM: iso_v1alpha1.IPAMSpec{
						Mode: "multi-pool",
						Pool: iso_v1alpha1.IPAMPoolSpec{
							Name: "jupiter",
						},
					},
					Routes: []iso_v1alpha1.RouteSpec{
						{
							Destination: "192.168.0.0/16",
							Gateway:     "192.168.0.1",
						},
					},
				},
			},
		},
	}

	tests := []struct {
		name            string
		podNamespace    string
		podName         string
		wantAttachments []*models.NetworkAttachmentElement
		wantErr         error
	}{
		{
			name:         "no annotations",
			podNamespace: "default",
			podName:      "client",
			wantAttachments: []*models.NetworkAttachmentElement{
				{
					Name: swag.String(defaultNetwork),
					Ipam: &models.NetworkAttachmentIPAMParameters{
						IpamPool: "default",
					},
				},
			},
		},
		{
			name:         "multi-homed",
			podNamespace: "default",
			podName:      "multi-homed-workload",
			wantAttachments: []*models.NetworkAttachmentElement{
				{
					Name: swag.String(defaultNetwork),
					Ipam: &models.NetworkAttachmentIPAMParameters{
						IpamPool: "default",
					},
				},
				{
					Name: swag.String("jupiter"),
					Ipam: &models.NetworkAttachmentIPAMParameters{
						IpamPool: "jupiter",
					},
					Routes: []*models.NetworkAttachmentRoute{
						{
							Destination: "192.168.0.0/16",
							Gateway:     "192.168.0.1",
						},
					},
				},
			},
		},
		{
			name:         "secondary only",
			podNamespace: "default",
			podName:      "secondary-only-workload",
			wantAttachments: []*models.NetworkAttachmentElement{
				{
					Name: swag.String("jupiter"),
					Ipam: &models.NetworkAttachmentIPAMParameters{
						IpamPool: "jupiter",
					},
					Routes: []*models.NetworkAttachmentRoute{
						{
							Destination: "192.168.0.0/16",
							Gateway:     "192.168.0.1",
						},
					},
				},
			},
		},
		{
			name:         "nonexistent pod",
			podNamespace: "nonesuch",
			podName:      "pod",
			wantErr:      &ResourceNotFound{Resource: "Pod"},
		},
		{
			name:         "nonexistent network",
			podNamespace: "default",
			podName:      "nonexistent-network-workload",
			wantErr:      &ResourceNotFound{Resource: "IsovalentPodNetwork"},
		},
		{
			name:         "existent and nonexistent network",
			podNamespace: "default",
			podName:      "existent-and-nonexistent-network-workload",
			wantErr:      &ResourceNotFound{Resource: "IsovalentPodNetwork"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			networks, err := m.GetNetworksForPod(tt.podNamespace, tt.podName)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("GetNetworksForPod() error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr != nil {
				return
			}
			if networks.PodNamespace != tt.podNamespace {
				t.Errorf("GetNetworksForPod() pod namespace = %v, want %v", networks.PodNamespace, tt.podNamespace)
			}
			if networks.PodName != tt.podName {
				t.Errorf("GetNetworksForPod() pod name = %v, want %v", networks.PodName, tt.podName)
			}
			attachments := networks.Attachments
			sort.Slice(attachments, func(i, j int) bool {
				return swag.StringValue(attachments[i].Name) < swag.StringValue(attachments[j].Name)
			})
			if diff := cmp.Diff(tt.wantAttachments, attachments); diff != "" {
				t.Errorf("GetNetworksForPod() attachments mismatch (-want +got):\n%s", diff)
			}
		})
	}

}
