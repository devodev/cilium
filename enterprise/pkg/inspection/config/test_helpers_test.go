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

import (
	"testing"

	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
)

type fakeConfigEndpoint struct {
	properties map[string]any
	id         identity.NumericIdentity
}

type fakeSelectorEndpoint struct {
	properties     map[string]any
	id             *identity.Identity
	k8sMetadataSet bool
	identityErr    error
}

func (f fakeConfigEndpoint) GetPropertyValue(key string) any { return f.properties[key] }
func (f fakeConfigEndpoint) GetIdentity() identity.NumericIdentity {
	return f.id
}

func (f fakeSelectorEndpoint) GetPropertyValue(key string) any { return f.properties[key] }
func (f fakeSelectorEndpoint) GetIdentity() identity.NumericIdentity {
	if f.id == nil {
		return identity.InvalidIdentity
	}
	return f.id.ID
}
func (f fakeSelectorEndpoint) K8sNamespaceAndPodNameIsSet() bool {
	return f.k8sMetadataSet || f.id != nil
}
func (f fakeSelectorEndpoint) GetSecurityIdentity() (*identity.Identity, error) {
	return f.id, f.identityErr
}

func newFakeIdentity(labelsMap map[string]string) *identity.Identity {
	idLabels := labels.Map2Labels(labelsMap, labels.LabelSourceK8s)
	id := &identity.Identity{Labels: idLabels}
	id.Sanitize()
	return id
}

func newTestSelectorStore(t *testing.T, identities identity.IdentityMap) *SelectorStore {
	t.Helper()

	store := NewSelectorStore()
	store.selectorCache = policy.NewSelectorCache(hivetest.Logger(t), identities)
	return store
}
