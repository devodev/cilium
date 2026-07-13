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
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	crdv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/time"
)

func TestVersionMigration(t *testing.T) {
	tests := []struct {
		name                   string
		crd                    *crdv1.CustomResourceDefinition
		expectedReturnValue    bool
		expectedStoredVersions []string
	}{
		{
			name: "Migrate v2alpha1",
			crd: &crdv1.CustomResourceDefinition{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "isovalentbgppeerconfigs.isovalent.com",
				},
				Status: crdv1.CustomResourceDefinitionStatus{
					StoredVersions: []string{"v1", "v1alpha1"},
				},
			},
			expectedReturnValue:    true,
			expectedStoredVersions: []string{"v1"},
		},
		{
			name: "No Migration",
			crd: &crdv1.CustomResourceDefinition{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "isovalentbgppeerconfigs.isovalent.com",
				},
				Status: crdv1.CustomResourceDefinitionStatus{
					StoredVersions: []string{"v1"},
				},
			},
			expectedReturnValue:    false,
			expectedStoredVersions: []string{"v1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), TestTimeout*3)
			t.Cleanup(func() {
				cancel()
			})

			fakeClientSet, _ := k8sClient.NewFakeClientset(slog.Default())
			crdClient := fakeClientSet.ApiextensionsV1().CustomResourceDefinitions()
			client := resourceClient[*v1.IsovalentBGPPeerConfig]{
				lister:  list,
				patcher: fakeClientSet.IsovalentV1().IsovalentBGPPeerConfigs().Patch,
			}
			versionFromMigrate := "v1alpha1"
			_, err := crdClient.Create(
				ctx, tt.crd, meta_v1.CreateOptions{},
			)
			require.NoError(t, err)

			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				migrated, err := storageVersionMigrator(
					ctx, crdClient, tt.crd.Name, client, versionFromMigrate,
				)
				if !assert.NoError(ct, err, "Failed to migrate storage version") {
					return
				}

				crd, err := crdClient.Get(ctx, tt.crd.Name, meta_v1.GetOptions{})
				if !assert.NoError(ct, err, "Failed to get CustomResourceDefinition") {
					return
				}
				assert.Equal(ct, tt.expectedStoredVersions, crd.Status.StoredVersions, "Unexpected Status.StoredVersions")
				assert.Equal(ct, tt.expectedReturnValue, migrated, "Unexpected return value")
			}, time.Second*3, time.Millisecond*100)
		})
	}
}

func list() ([]*v1.IsovalentBGPPeerConfig, error) {
	return nil, nil
}
