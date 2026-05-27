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
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/meta"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/hive/health"
	healthTypes "github.com/cilium/cilium/pkg/hive/health/types"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_meta_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func TestMissingAuthSecretCondition(t *testing.T) {
	secretName := "auth-secret"
	secretNamespace := "kube-system"
	peerConfigName := "peer-config0"

	secret := &slim_core_v1.Secret{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:      secretName,
			Namespace: secretNamespace,
		},
	}

	tests := []struct {
		name          string
		peerConfig    *v1.IsovalentBGPPeerConfig
		expectedState meta_v1.ConditionStatus
	}{
		{
			name: "MissingAuthSecret False",
			peerConfig: &v1.IsovalentBGPPeerConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: peerConfigName,
				},
				Spec: v1.IsovalentBGPPeerConfigSpec{
					AuthSecretRef: &secretName,
				},
			},
			expectedState: meta_v1.ConditionFalse,
		},
		{
			name: "MissingAuthSecret False nil AuthSecretRef",
			peerConfig: &v1.IsovalentBGPPeerConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: peerConfigName,
				},
				Spec: v1.IsovalentBGPPeerConfigSpec{},
			},
			expectedState: meta_v1.ConditionFalse,
		},
		{
			name: "MissingAuthSecret True",
			peerConfig: &v1.IsovalentBGPPeerConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: peerConfigName,
				},
				Spec: v1.IsovalentBGPPeerConfigSpec{
					AuthSecretRef: ptr.To(secretName + "foo"),
				},
			},
			expectedState: meta_v1.ConditionTrue,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)
			testLogger := hivetest.Logger(t)

			ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
			t.Cleanup(func() {
				cancel()
			})

			f := newFixture(t, ctx, req, fixtureConfig{enableStatusReport: true})

			f.hive.Start(testLogger, ctx)
			t.Cleanup(func() {
				f.hive.Stop(testLogger, ctx)
			})

			_, err := f.fakeClientSet.CiliumFakeClientset.IsovalentV1().IsovalentBGPPeerConfigs().Create(
				ctx, tt.peerConfig, meta_v1.CreateOptions{},
			)
			req.NoError(err)

			_, err = f.fakeClientSet.SlimFakeClientset.CoreV1().Secrets(secretNamespace).Create(
				ctx, secret, meta_v1.CreateOptions{},
			)
			req.NoError(err)

			req.EventuallyWithT(func(ct *assert.CollectT) {
				pc, err := f.isoPeerConfClient.Get(ctx, peerConfigName, meta_v1.GetOptions{})
				if !assert.NoError(ct, err, "Failed to get PeerConfig") {
					return
				}
				cond := meta.FindStatusCondition(
					pc.Status.Conditions,
					v1.BGPPeerConfigConditionMissingAuthSecret,
				)
				if !assert.NotNil(ct, cond, "Condition not found") {
					return
				}
				assert.Equal(ct, tt.expectedState, cond.Status, "Unexpected condition status")
			}, time.Second*3, time.Millisecond*100)
		})
	}
}

func TestMissingBFDProfileCondition(t *testing.T) {
	peerConfigName := "peer-config0"

	bfdProfile := &v1alpha1.IsovalentBFDProfile{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "bfd-profile0",
		},
	}

	tests := []struct {
		name          string
		peerConfig    *v1.IsovalentBGPPeerConfig
		expectedState meta_v1.ConditionStatus
		enableBFD     bool
	}{
		{
			name: "MissingBFDProfile False",
			peerConfig: &v1.IsovalentBGPPeerConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: peerConfigName,
				},
				Spec: v1.IsovalentBGPPeerConfigSpec{
					BFDProfileRef: &bfdProfile.Name,
				},
			},
			expectedState: meta_v1.ConditionFalse,
			enableBFD:     true,
		},
		{
			name: "MissingBFDProfile False nil BFDProfileRef",
			peerConfig: &v1.IsovalentBGPPeerConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: peerConfigName,
				},
				Spec: v1.IsovalentBGPPeerConfigSpec{},
			},
			expectedState: meta_v1.ConditionFalse,
			enableBFD:     true,
		},
		{
			name: "MissingBFDProfile True",
			peerConfig: &v1.IsovalentBGPPeerConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: peerConfigName,
				},
				Spec: v1.IsovalentBGPPeerConfigSpec{
					BFDProfileRef: ptr.To(bfdProfile.Name + "foo"),
				},
			},
			expectedState: meta_v1.ConditionTrue,
			enableBFD:     true,
		},
		{
			name: "MissingBFDProfile False disable BFD",
			peerConfig: &v1.IsovalentBGPPeerConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: peerConfigName,
				},
				Spec: v1.IsovalentBGPPeerConfigSpec{
					// This BFD profile doesn't exist, but
					// since the BFD itself is disabled,
					// the condition will be always false.
					BFDProfileRef: ptr.To(bfdProfile.Name + "foo"),
				},
			},
			expectedState: meta_v1.ConditionFalse,
			enableBFD:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)
			testLogger := hivetest.Logger(t)

			ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
			t.Cleanup(func() {
				cancel()
			})

			f := newFixture(t, ctx, req, fixtureConfig{enableBFD: tt.enableBFD, enableStatusReport: true})

			f.hive.Start(testLogger, ctx)
			t.Cleanup(func() {
				f.hive.Stop(testLogger, ctx)
			})

			_, err := f.fakeClientSet.CiliumFakeClientset.IsovalentV1().IsovalentBGPPeerConfigs().Create(
				ctx,
				tt.peerConfig,
				meta_v1.CreateOptions{},
			)
			req.NoError(err)

			_, err = f.fakeClientSet.CiliumFakeClientset.IsovalentV1alpha1().IsovalentBFDProfiles().Create(
				ctx,
				bfdProfile,
				meta_v1.CreateOptions{},
			)
			req.NoError(err)

			req.EventuallyWithT(func(ct *assert.CollectT) {
				pc, err := f.isoPeerConfClient.Get(ctx, peerConfigName, meta_v1.GetOptions{})
				if !assert.NoError(ct, err, "Failed to get PeerConfig") {
					return
				}
				cond := meta.FindStatusCondition(
					pc.Status.Conditions,
					v1.BGPPeerConfigConditionMissingBFDProfile,
				)
				if !assert.NotNil(ct, cond, "Condition not found") {
					return
				}
				assert.Equal(ct, tt.expectedState, cond.Status, "Unexpected condition status")
			}, time.Second*3, time.Millisecond*100)
		})
	}
}

func TestDisablePeerConfigStatusReport(t *testing.T) {
	req := require.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	t.Cleanup(func() {
		cancel()
	})

	f := newFixture(t, ctx, req, fixtureConfig{enableBFD: true, enableStatusReport: false})

	logger := hivetest.Logger(t)

	f.hive.Start(logger, ctx)
	t.Cleanup(func() {
		f.hive.Stop(logger, ctx)
	})

	peerConfig := &v1.IsovalentBGPPeerConfig{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "config0",
		},
		Spec: v1.IsovalentBGPPeerConfigSpec{
			AuthSecretRef: ptr.To("secret0"),
			BFDProfileRef: ptr.To("bfd0"),
		},
		Status: v1.IsovalentBGPPeerConfigStatus{
			Conditions: []meta_v1.Condition{},
		},
	}

	// Fill with all known conditions
	for _, cond := range v1.AllBGPPeerConfigConditions {
		peerConfig.Status.Conditions = append(peerConfig.Status.Conditions, meta_v1.Condition{
			Type: cond,
		})
	}

	_, err := f.fakeClientSet.CiliumFakeClientset.IsovalentV1().IsovalentBGPPeerConfigs().Create(
		ctx, peerConfig, meta_v1.CreateOptions{},
	)
	require.NoError(t, err)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		pc, err := f.fakeClientSet.CiliumFakeClientset.IsovalentV1().IsovalentBGPPeerConfigs().Get(
			ctx, peerConfig.Name, meta_v1.GetOptions{})
		if !assert.NoError(ct, err, "Cannot get peer config") {
			return
		}

		assert.Empty(ct, pc.Status.Conditions, "Conditions are not cleared")

		rtxn := f.db.ReadTxn()

		_, _, found := f.healthTable.Get(rtxn, health.PrimaryIndex.Query(healthTypes.HealthID("bgp-enterprise-operator.job-cleanup-peer-config-status")))
		assert.False(ct, found, "expected job to finish")
	}, time.Second*3, time.Millisecond*100)
}
