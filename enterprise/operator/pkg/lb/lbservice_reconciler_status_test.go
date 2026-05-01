//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package lb

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

func TestLBServiceStatusVIP(t *testing.T) {
	r := lbServiceReconciler{}

	conditionType := "lb.cilium.io/VIPExist"

	testCases := []struct {
		desc                   string
		lbsvc                  *isovalentv1alpha1.LBService
		vip                    *isovalentv1alpha1.LBVIP
		expectedNrOfConditions int
		expectedStatus         metav1.ConditionStatus
		expectedReason         string
		expectedMessage        string
	}{
		{
			desc:                   "VIP exists",
			lbsvc:                  &isovalentv1alpha1.LBService{Spec: isovalentv1alpha1.LBServiceSpec{VIPRef: isovalentv1alpha1.LBServiceVIPRef{Name: "my-vip"}}},
			vip:                    &isovalentv1alpha1.LBVIP{},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "VIPExists",
			expectedMessage:        "Referenced VIP exist",
		},
		{
			desc:                   "Missing VIP",
			lbsvc:                  &isovalentv1alpha1.LBService{Spec: isovalentv1alpha1.LBServiceSpec{VIPRef: isovalentv1alpha1.LBServiceVIPRef{Name: "my-vip"}}},
			vip:                    nil,
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionFalse,
			expectedReason:         "VIPMissing",
			expectedMessage:        "Referenced VIP my-vip is missing",
		},
		{
			desc: "Update existing condition",
			lbsvc: &isovalentv1alpha1.LBService{
				Spec:   isovalentv1alpha1.LBServiceSpec{VIPRef: isovalentv1alpha1.LBServiceVIPRef{Name: "my-vip"}},
				Status: isovalentv1alpha1.LBServiceStatus{Conditions: []metav1.Condition{{Type: conditionType, Status: metav1.ConditionTrue, Reason: "reason", Message: "message"}}},
			},
			vip:                    &isovalentv1alpha1.LBVIP{},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "VIPExists",
			expectedMessage:        "Referenced VIP exist",
		},
		{
			desc: "Doesn't delete other conditions",
			lbsvc: &isovalentv1alpha1.LBService{Status: isovalentv1alpha1.LBServiceStatus{Conditions: []metav1.Condition{
				{Type: "other-type", Status: metav1.ConditionTrue, Reason: "other-reason", Message: "other-message"},
				{Type: conditionType, Status: metav1.ConditionTrue, Reason: "reason", Message: "message"},
			}}},
			vip:                    &isovalentv1alpha1.LBVIP{},
			expectedNrOfConditions: 2,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "VIPExists",
			expectedMessage:        "Referenced VIP exist",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			r.updateVIPInStatus(tc.lbsvc, tc.vip)

			assert.Len(t, tc.lbsvc.Status.Conditions, tc.expectedNrOfConditions)

			c := tc.lbsvc.GetStatusCondition(conditionType)
			require.NotNil(t, c)
			assert.Equal(t, tc.expectedStatus, c.Status)
			assert.Equal(t, tc.expectedReason, c.Reason)
			assert.Equal(t, tc.expectedMessage, c.Message)
		})
	}
}

func TestLBServiceStatusAssignedIP(t *testing.T) {
	r := lbServiceReconciler{}

	conditionType := "lb.cilium.io/IPAssigned"

	testCases := []struct {
		desc                   string
		model                  *lbService
		lbsvc                  *isovalentv1alpha1.LBService
		expectedNrOfConditions int
		expectedStatus         metav1.ConditionStatus
		expectedReason         string
		expectedMessage        string
	}{
		{
			desc:                   "IP pending",
			model:                  &lbService{vip: lbVIP{ipFamily: ipFamilyV4}},
			lbsvc:                  &isovalentv1alpha1.LBService{},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionFalse,
			expectedReason:         "IPPending",
			expectedMessage:        "VIP pending",
		},
		{
			desc:                   "IP assigned",
			model:                  &lbService{vip: lbVIP{ipFamily: ipFamilyV4, assignedIPv4: ptr.To("100.64.0.1")}},
			lbsvc:                  &isovalentv1alpha1.LBService{},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "IPAssigned",
			expectedMessage:        "VIP assigned",
		},
		{
			desc: "Failed to bind ip",
			model: &lbService{vip: lbVIP{ipFamily: ipFamilyV4, bindStatus: lbVIPBindStatus{
				serviceExists:  true,
				bindSuccessful: false,
				bindIssue:      "not possible to bind",
			}}},
			lbsvc:                  &isovalentv1alpha1.LBService{},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionFalse,
			expectedReason:         "IPFailure",
			expectedMessage:        "Failed to bind to VIP: not possible to bind",
		},
		{
			desc:  "Update existing condition",
			model: &lbService{vip: lbVIP{ipFamily: ipFamilyV4, assignedIPv4: ptr.To("100.64.0.1")}},
			lbsvc: &isovalentv1alpha1.LBService{Status: isovalentv1alpha1.LBServiceStatus{Conditions: []metav1.Condition{
				{Type: conditionType, Status: metav1.ConditionFalse, Reason: "reason", Message: "message"},
			}}},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "IPAssigned",
			expectedMessage:        "VIP assigned",
		},
		{
			desc:  "Doesn't delete other conditions",
			model: &lbService{vip: lbVIP{ipFamily: ipFamilyV4, assignedIPv4: ptr.To("100.64.0.1")}},
			lbsvc: &isovalentv1alpha1.LBService{Status: isovalentv1alpha1.LBServiceStatus{Conditions: []metav1.Condition{
				{Type: "other-type", Status: metav1.ConditionFalse, Reason: "other-reason", Message: "other-message"},
				{Type: conditionType, Status: metav1.ConditionTrue, Reason: "reason", Message: "message"},
			}}},
			expectedNrOfConditions: 2,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "IPAssigned",
			expectedMessage:        "VIP assigned",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			r.updateAssignedIpInStatus(tc.model, tc.lbsvc)

			assert.Len(t, tc.lbsvc.Status.Conditions, tc.expectedNrOfConditions)

			c := tc.lbsvc.GetStatusCondition(conditionType)
			require.NotNil(t, c)
			assert.Equal(t, tc.expectedStatus, c.Status)
			assert.Equal(t, tc.expectedReason, c.Reason)
			assert.Equal(t, tc.expectedMessage, c.Message)
		})
	}
}

func TestLBServiceStatusSecret(t *testing.T) {
	r := lbServiceReconciler{}

	conditionType := "lb.cilium.io/SecretsExist"

	testCases := []struct {
		desc                   string
		lbsvc                  *isovalentv1alpha1.LBService
		missingSecrets         []string
		expectedNrOfConditions int
		expectedStatus         metav1.ConditionStatus
		expectedReason         string
		expectedMessage        string
	}{
		{
			desc:                   "All secrets exist",
			lbsvc:                  &isovalentv1alpha1.LBService{},
			missingSecrets:         []string{},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "AllSecretsExist",
			expectedMessage:        "All referenced TLS secrets exist",
		},
		{
			desc:                   "Missing secrets",
			lbsvc:                  &isovalentv1alpha1.LBService{},
			missingSecrets:         []string{"missing-secret", "another-missing-secret"},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionFalse,
			expectedReason:         "MissingSecrets",
			expectedMessage:        "There are referenced TLS secrets that do not exist: [missing-secret another-missing-secret]",
		},
		{
			desc:                   "Update existing condition",
			lbsvc:                  &isovalentv1alpha1.LBService{Status: isovalentv1alpha1.LBServiceStatus{Conditions: []metav1.Condition{{Type: conditionType, Status: metav1.ConditionTrue, Reason: "reason", Message: "message"}}}},
			missingSecrets:         []string{},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "AllSecretsExist",
			expectedMessage:        "All referenced TLS secrets exist",
		},
		{
			desc: "Doesn't delete other conditions",
			lbsvc: &isovalentv1alpha1.LBService{Status: isovalentv1alpha1.LBServiceStatus{Conditions: []metav1.Condition{
				{Type: "other-type", Status: metav1.ConditionTrue, Reason: "other-reason", Message: "other-message"},
				{Type: conditionType, Status: metav1.ConditionTrue, Reason: "reason", Message: "message"},
			}}},
			missingSecrets:         []string{},
			expectedNrOfConditions: 2,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "AllSecretsExist",
			expectedMessage:        "All referenced TLS secrets exist",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			r.updateSecretExistenceInStatus(tc.lbsvc, tc.missingSecrets)

			assert.Len(t, tc.lbsvc.Status.Conditions, tc.expectedNrOfConditions)

			c := tc.lbsvc.GetStatusCondition(conditionType)
			require.NotNil(t, c)
			assert.Equal(t, tc.expectedStatus, c.Status)
			assert.Equal(t, tc.expectedReason, c.Reason)
			assert.Equal(t, tc.expectedMessage, c.Message)
		})
	}
}

func TestLBServiceStatusBackendExistence(t *testing.T) {
	r := lbServiceReconciler{}

	conditionType := "lb.cilium.io/BackendsExist"

	testCases := []struct {
		desc                   string
		lbsvc                  *isovalentv1alpha1.LBService
		missingBackends        []string
		expectedNrOfConditions int
		expectedStatus         metav1.ConditionStatus
		expectedReason         string
		expectedMessage        string
	}{
		{
			desc:                   "All backends exist",
			lbsvc:                  &isovalentv1alpha1.LBService{},
			missingBackends:        []string{},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "AllBackendsExist",
			expectedMessage:        "All referenced backends exist",
		},
		{
			desc:                   "Missing backends",
			lbsvc:                  &isovalentv1alpha1.LBService{},
			missingBackends:        []string{"missing-backend", "another-missing-backend"},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionFalse,
			expectedReason:         "MissingBackends",
			expectedMessage:        "There are referenced backends that do not exist: [missing-backend another-missing-backend]",
		},
		{
			desc:                   "Update existing condition",
			lbsvc:                  &isovalentv1alpha1.LBService{Status: isovalentv1alpha1.LBServiceStatus{Conditions: []metav1.Condition{{Type: conditionType, Status: metav1.ConditionTrue, Reason: "reason", Message: "message"}}}},
			missingBackends:        []string{},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "AllBackendsExist",
			expectedMessage:        "All referenced backends exist",
		},
		{
			desc: "Doesn't delete other conditions",
			lbsvc: &isovalentv1alpha1.LBService{Status: isovalentv1alpha1.LBServiceStatus{Conditions: []metav1.Condition{
				{Type: "other-type", Status: metav1.ConditionTrue, Reason: "other-reason", Message: "other-message"},
				{Type: conditionType, Status: metav1.ConditionTrue, Reason: "reason", Message: "message"},
			}}},
			missingBackends:        []string{},
			expectedNrOfConditions: 2,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "AllBackendsExist",
			expectedMessage:        "All referenced backends exist",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			r.updateBackendExistenceInStatus(tc.lbsvc, tc.missingBackends)

			assert.Len(t, tc.lbsvc.Status.Conditions, tc.expectedNrOfConditions)

			c := tc.lbsvc.GetStatusCondition(conditionType)
			require.NotNil(t, c)
			assert.Equal(t, tc.expectedStatus, c.Status)
			assert.Equal(t, tc.expectedReason, c.Reason)
			assert.Equal(t, tc.expectedMessage, c.Message)
		})
	}
}

func TestLBServiceStatusBackendCompatibility(t *testing.T) {
	r := lbServiceReconciler{}

	conditionType := "lb.cilium.io/BackendsCompatible"

	testCases := []struct {
		desc                   string
		lbsvc                  *isovalentv1alpha1.LBService
		backends               []*isovalentv1alpha1.LBBackendPool
		expectedNrOfConditions int
		expectedStatus         metav1.ConditionStatus
		expectedReason         string
		expectedMessage        string
	}{
		{
			desc: "All backends compatible (no persistent backends)",
			lbsvc: &isovalentv1alpha1.LBService{Spec: isovalentv1alpha1.LBServiceSpec{Applications: isovalentv1alpha1.LBServiceApplications{
				HTTPProxy: &isovalentv1alpha1.LBServiceApplicationHTTPProxy{
					Routes: []isovalentv1alpha1.LBServiceHTTPRoute{{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-1"}}},
				},
				HTTPSProxy: &isovalentv1alpha1.LBServiceApplicationHTTPSProxy{
					Routes: []isovalentv1alpha1.LBServiceHTTPSRoute{{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-1"}}},
				},
				TLSPassthrough: &isovalentv1alpha1.LBServiceApplicationTLSPassthrough{
					Routes: []isovalentv1alpha1.LBServiceTLSPassthroughRoute{{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-1"}}},
				},
				TLSProxy: &isovalentv1alpha1.LBServiceApplicationTLSProxy{
					Routes: []isovalentv1alpha1.LBServiceTLSRoute{{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-1"}}},
				},
			}}},
			backends: []*isovalentv1alpha1.LBBackendPool{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "backend-1"},
					Spec:       isovalentv1alpha1.LBBackendPoolSpec{},
					Status: isovalentv1alpha1.LBBackendPoolStatus{
						Conditions: []metav1.Condition{acceptedCondition()},
					},
				},
			},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "AllBackendsCompatible",
			expectedMessage:        "All referenced backends are compatible",
		},
		{
			desc: "All backends compatible (with persistent backends)",
			lbsvc: &isovalentv1alpha1.LBService{Spec: isovalentv1alpha1.LBServiceSpec{Applications: isovalentv1alpha1.LBServiceApplications{
				HTTPProxy: &isovalentv1alpha1.LBServiceApplicationHTTPProxy{
					Routes: []isovalentv1alpha1.LBServiceHTTPRoute{
						{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-1"}},
						{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-2"}, PersistentBackend: &isovalentv1alpha1.LBServiceHTTPRoutePersistentBackend{}},
					},
				},
				HTTPSProxy: &isovalentv1alpha1.LBServiceApplicationHTTPSProxy{
					Routes: []isovalentv1alpha1.LBServiceHTTPSRoute{
						{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-1"}},
						{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-2"}, PersistentBackend: &isovalentv1alpha1.LBServiceHTTPRoutePersistentBackend{}},
					},
				},
				TLSPassthrough: &isovalentv1alpha1.LBServiceApplicationTLSPassthrough{
					Routes: []isovalentv1alpha1.LBServiceTLSPassthroughRoute{
						{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-1"}},
						{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-2"}, PersistentBackend: &isovalentv1alpha1.LBServiceTLSRoutePersistentBackend{}},
					},
				},
				TLSProxy: &isovalentv1alpha1.LBServiceApplicationTLSProxy{
					Routes: []isovalentv1alpha1.LBServiceTLSRoute{
						{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-1"}},
						{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-2"}, PersistentBackend: &isovalentv1alpha1.LBServiceTLSRoutePersistentBackend{}},
					},
				},
			}}},
			backends: []*isovalentv1alpha1.LBBackendPool{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "backend-1"},
					Spec:       isovalentv1alpha1.LBBackendPoolSpec{},
					Status: isovalentv1alpha1.LBBackendPoolStatus{
						Conditions: []metav1.Condition{acceptedCondition()},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "backend-2"},
					Spec:       isovalentv1alpha1.LBBackendPoolSpec{Loadbalancing: &isovalentv1alpha1.Loadbalancing{Algorithm: isovalentv1alpha1.LoadbalancingAlgorithm{ConsistentHashing: &isovalentv1alpha1.LoadbalancingAlgorithmConsistentHashing{}}}},
					Status: isovalentv1alpha1.LBBackendPoolStatus{
						Conditions: []metav1.Condition{acceptedCondition()},
					},
				},
			},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "AllBackendsCompatible",
			expectedMessage:        "All referenced backends are compatible",
		},
		{
			desc: "Incompatible backends (persistent backend selection but no consistent hashing)",
			lbsvc: &isovalentv1alpha1.LBService{Spec: isovalentv1alpha1.LBServiceSpec{Applications: isovalentv1alpha1.LBServiceApplications{
				HTTPProxy: &isovalentv1alpha1.LBServiceApplicationHTTPProxy{
					Routes: []isovalentv1alpha1.LBServiceHTTPRoute{
						{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-1"}},
						{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-2"}, PersistentBackend: &isovalentv1alpha1.LBServiceHTTPRoutePersistentBackend{}},
					},
				},
				HTTPSProxy: &isovalentv1alpha1.LBServiceApplicationHTTPSProxy{
					Routes: []isovalentv1alpha1.LBServiceHTTPSRoute{
						{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-1"}},
						{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-2"}, PersistentBackend: &isovalentv1alpha1.LBServiceHTTPRoutePersistentBackend{}},
					},
				},
				TLSPassthrough: &isovalentv1alpha1.LBServiceApplicationTLSPassthrough{
					Routes: []isovalentv1alpha1.LBServiceTLSPassthroughRoute{
						{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-1"}},
						{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-2"}, PersistentBackend: &isovalentv1alpha1.LBServiceTLSRoutePersistentBackend{}},
					},
				},
				TLSProxy: &isovalentv1alpha1.LBServiceApplicationTLSProxy{
					Routes: []isovalentv1alpha1.LBServiceTLSRoute{
						{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-1"}},
						{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-2"}, PersistentBackend: &isovalentv1alpha1.LBServiceTLSRoutePersistentBackend{}},
					},
				},
			}}},
			backends: []*isovalentv1alpha1.LBBackendPool{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "backend-1"},
					Spec:       isovalentv1alpha1.LBBackendPoolSpec{},
					Status: isovalentv1alpha1.LBBackendPoolStatus{
						Conditions: []metav1.Condition{acceptedCondition()},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "backend-2"},
					Spec:       isovalentv1alpha1.LBBackendPoolSpec{Loadbalancing: &isovalentv1alpha1.Loadbalancing{Algorithm: isovalentv1alpha1.LoadbalancingAlgorithm{RoundRobin: &isovalentv1alpha1.LoadbalancingAlgorithmRoundRobin{}}}},
					Status: isovalentv1alpha1.LBBackendPoolStatus{
						Conditions: []metav1.Condition{acceptedCondition()},
					},
				},
			},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionFalse,
			expectedReason:         "IncompatibleBackends",
			expectedMessage:        `Backend "backend-2" is incompatible: Configured "persistentBackend" without LB algorithm "consistentHashing"`,
		},
		{
			desc: "Update existing condition",
			lbsvc: &isovalentv1alpha1.LBService{
				Spec: isovalentv1alpha1.LBServiceSpec{Applications: isovalentv1alpha1.LBServiceApplications{
					HTTPProxy: &isovalentv1alpha1.LBServiceApplicationHTTPProxy{
						Routes: []isovalentv1alpha1.LBServiceHTTPRoute{
							{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-1"}},
						},
					},
				}},
				Status: isovalentv1alpha1.LBServiceStatus{Conditions: []metav1.Condition{{Type: conditionType, Status: metav1.ConditionTrue, Reason: "reason", Message: "message"}}},
			},
			backends: []*isovalentv1alpha1.LBBackendPool{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "backend-1"},
					Spec:       isovalentv1alpha1.LBBackendPoolSpec{},
					Status: isovalentv1alpha1.LBBackendPoolStatus{
						Conditions: []metav1.Condition{acceptedCondition()},
					},
				},
			},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "AllBackendsCompatible",
			expectedMessage:        "All referenced backends are compatible",
		},
		{
			desc: "Doesn't delete other conditions",
			lbsvc: &isovalentv1alpha1.LBService{
				Spec: isovalentv1alpha1.LBServiceSpec{Applications: isovalentv1alpha1.LBServiceApplications{
					HTTPProxy: &isovalentv1alpha1.LBServiceApplicationHTTPProxy{
						Routes: []isovalentv1alpha1.LBServiceHTTPRoute{
							{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-1"}},
						},
					},
				}},
				Status: isovalentv1alpha1.LBServiceStatus{Conditions: []metav1.Condition{
					{Type: conditionType, Status: metav1.ConditionTrue, Reason: "reason", Message: "message"},
					{Type: "other-type", Status: metav1.ConditionTrue, Reason: "other-reason", Message: "other-message"},
				}},
			},
			backends: []*isovalentv1alpha1.LBBackendPool{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "backend-1"},
					Spec:       isovalentv1alpha1.LBBackendPoolSpec{},
					Status: isovalentv1alpha1.LBBackendPoolStatus{
						Conditions: []metav1.Condition{acceptedCondition()},
					},
				},
			},
			expectedNrOfConditions: 2,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "AllBackendsCompatible",
			expectedMessage:        "All referenced backends are compatible",
		},
		{
			desc: "Incompatible proxy protocol backends",
			lbsvc: &isovalentv1alpha1.LBService{Spec: isovalentv1alpha1.LBServiceSpec{Applications: isovalentv1alpha1.LBServiceApplications{
				HTTPProxy: &isovalentv1alpha1.LBServiceApplicationHTTPProxy{
					Routes: []isovalentv1alpha1.LBServiceHTTPRoute{{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-1"}}},
				},
			}}},
			backends: []*isovalentv1alpha1.LBBackendPool{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "backend-1"},
					Spec: isovalentv1alpha1.LBBackendPoolSpec{
						ProxyProtocolConfig: &isovalentv1alpha1.LBBackendPoolProxyProtocolConfig{
							Version: 1,
						},
					},
					Status: isovalentv1alpha1.LBBackendPoolStatus{
						Conditions: []metav1.Condition{acceptedCondition()},
					},
				},
			},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionFalse,
			expectedReason:         "IncompatibleBackends",
			expectedMessage:        "Backend \"backend-1\" is incompatible: ProxyProtocolConfig is not supported for LB services",
		},
		{
			desc: "Incompatible proxy protocol version backends",
			lbsvc: &isovalentv1alpha1.LBService{Spec: isovalentv1alpha1.LBServiceSpec{
				ProxyProtocolConfig: &isovalentv1alpha1.LBServiceProxyProtocolConfig{
					DisallowedVersions: []isovalentv1alpha1.LBProxyProtocolVersion{1},
				},
				Applications: isovalentv1alpha1.LBServiceApplications{
					HTTPProxy: &isovalentv1alpha1.LBServiceApplicationHTTPProxy{
						Routes: []isovalentv1alpha1.LBServiceHTTPRoute{{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-1"}}},
					},
				},
			}},
			backends: []*isovalentv1alpha1.LBBackendPool{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "backend-1"},
					Spec: isovalentv1alpha1.LBBackendPoolSpec{
						ProxyProtocolConfig: &isovalentv1alpha1.LBBackendPoolProxyProtocolConfig{
							Version: 1,
						},
					},
					Status: isovalentv1alpha1.LBBackendPoolStatus{
						Conditions: []metav1.Condition{acceptedCondition()},
					},
				},
			},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionFalse,
			expectedReason:         "IncompatibleBackends",
			expectedMessage:        "Backend \"backend-1\" is incompatible: ProxyProtocolConfig version 1 is disallowed",
		},
		{
			desc: "All backend compatible (proxy protocol)",
			lbsvc: &isovalentv1alpha1.LBService{Spec: isovalentv1alpha1.LBServiceSpec{
				ProxyProtocolConfig: &isovalentv1alpha1.LBServiceProxyProtocolConfig{},
				Applications: isovalentv1alpha1.LBServiceApplications{
					HTTPProxy: &isovalentv1alpha1.LBServiceApplicationHTTPProxy{
						Routes: []isovalentv1alpha1.LBServiceHTTPRoute{{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-1"}}},
					},
				},
			}},
			backends: []*isovalentv1alpha1.LBBackendPool{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "backend-1"},
					Spec: isovalentv1alpha1.LBBackendPoolSpec{
						ProxyProtocolConfig: &isovalentv1alpha1.LBBackendPoolProxyProtocolConfig{
							Version: 2,
						},
					},
					Status: isovalentv1alpha1.LBBackendPoolStatus{
						Conditions: []metav1.Condition{acceptedCondition()},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "backend-2"},
					Spec: isovalentv1alpha1.LBBackendPoolSpec{
						ProxyProtocolConfig: &isovalentv1alpha1.LBBackendPoolProxyProtocolConfig{
							Version: 1,
						},
					},
					Status: isovalentv1alpha1.LBBackendPoolStatus{
						Conditions: []metav1.Condition{acceptedCondition()},
					},
				},
			},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "AllBackendsCompatible",
			expectedMessage:        "All referenced backends are compatible",
		},
		{
			desc: "Backends not yet accepted",
			lbsvc: &isovalentv1alpha1.LBService{Spec: isovalentv1alpha1.LBServiceSpec{
				ProxyProtocolConfig: &isovalentv1alpha1.LBServiceProxyProtocolConfig{},
				Applications: isovalentv1alpha1.LBServiceApplications{
					HTTPProxy: &isovalentv1alpha1.LBServiceApplicationHTTPProxy{
						Routes: []isovalentv1alpha1.LBServiceHTTPRoute{{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-1"}}},
					},
				},
			}},
			backends: []*isovalentv1alpha1.LBBackendPool{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "backend-1"},
					Spec:       isovalentv1alpha1.LBBackendPoolSpec{},
					Status:     isovalentv1alpha1.LBBackendPoolStatus{},
				},
			},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionFalse,
			expectedReason:         "IncompatibleBackends",
			expectedMessage:        "Backend \"backend-1\" is not yet accepted (no accepted condition)",
		},
		{
			desc: "Backend misses addresses for IP families",
			lbsvc: &isovalentv1alpha1.LBService{
				Spec: isovalentv1alpha1.LBServiceSpec{
					ProxyProtocolConfig: &isovalentv1alpha1.LBServiceProxyProtocolConfig{},
					Applications: isovalentv1alpha1.LBServiceApplications{
						TCPProxy: &isovalentv1alpha1.LBServiceApplicationTCPProxy{
							ForceDeploymentMode: ptr.To(isovalentv1alpha1.LBTCPProxyForceDeploymentModeT1),
							Routes:              []isovalentv1alpha1.LBServiceTCPRoute{{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-1"}}},
						},
					},
				},
				Status: isovalentv1alpha1.LBServiceStatus{
					Addresses: isovalentv1alpha1.LBServiceVIPAddresses{
						IPv4: ptr.To("100.64.0.1"),
						IPv6: ptr.To("2004::"),
					},
				},
			},
			backends: []*isovalentv1alpha1.LBBackendPool{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "backend-1"},
					Spec: isovalentv1alpha1.LBBackendPoolSpec{
						BackendType: isovalentv1alpha1.BackendTypeIP,
						Backends:    []isovalentv1alpha1.Backend{},
					},
					Status: isovalentv1alpha1.LBBackendPoolStatus{
						Conditions: []metav1.Condition{acceptedCondition()},
					},
				},
			},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionFalse,
			expectedReason:         "IncompatibleBackends",
			expectedMessage: `forceDeploymentMode t1-only requires all BackendPools to have at least one address per enabled IP address family configured - IPv4 is missing [backend-1]
forceDeploymentMode t1-only requires all BackendPools to have at least one address per enabled IP address family configured - IPv6 is missing [backend-1]`,
		},
		{
			desc: "Backend contains addresses for IP families",
			lbsvc: &isovalentv1alpha1.LBService{
				Spec: isovalentv1alpha1.LBServiceSpec{
					ProxyProtocolConfig: &isovalentv1alpha1.LBServiceProxyProtocolConfig{},
					Applications: isovalentv1alpha1.LBServiceApplications{
						TCPProxy: &isovalentv1alpha1.LBServiceApplicationTCPProxy{
							ForceDeploymentMode: ptr.To(isovalentv1alpha1.LBTCPProxyForceDeploymentModeT1),
							Routes:              []isovalentv1alpha1.LBServiceTCPRoute{{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-1"}}},
						},
					},
				},
				Status: isovalentv1alpha1.LBServiceStatus{
					Addresses: isovalentv1alpha1.LBServiceVIPAddresses{
						IPv4: ptr.To("100.64.0.1"),
						IPv6: ptr.To("2004::"),
					},
				},
			},
			backends: []*isovalentv1alpha1.LBBackendPool{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "backend-1"},
					Spec: isovalentv1alpha1.LBBackendPoolSpec{
						BackendType: isovalentv1alpha1.BackendTypeIP,
						Backends: []isovalentv1alpha1.Backend{
							{IP: ptr.To("192.168.1.8")},
							{IP: ptr.To("2005::1")},
						},
					},
					Status: isovalentv1alpha1.LBBackendPoolStatus{
						Conditions: []metav1.Condition{acceptedCondition()},
					},
				},
			},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "AllBackendsCompatible",
			expectedMessage:        "All referenced backends are compatible",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			r.updateBackendCompatibilityInStatus(tc.lbsvc, tc.backends)

			assert.Len(t, tc.lbsvc.Status.Conditions, tc.expectedNrOfConditions)

			c := tc.lbsvc.GetStatusCondition(conditionType)
			require.NotNil(t, c)
			assert.Equal(t, tc.expectedStatus, c.Status)
			assert.Equal(t, tc.expectedReason, c.Reason)
			assert.Equal(t, tc.expectedMessage, c.Message)
		})
	}
}

func Test_LBServiceReconciler_getIncompatibleSecretTypes(t *testing.T) {
	testCases := []struct {
		desc             string
		svc              *isovalentv1alpha1.LBService
		secrets          map[string]*corev1.Secret
		expectedMessages []string
	}{
		{
			desc: "skip services that aren't found",
			svc: &isovalentv1alpha1.LBService{Spec: isovalentv1alpha1.LBServiceSpec{Applications: isovalentv1alpha1.LBServiceApplications{
				HTTPSProxy: &isovalentv1alpha1.LBServiceApplicationHTTPSProxy{
					TLSConfig: isovalentv1alpha1.LBServiceTLSConfig{
						Certificates: []isovalentv1alpha1.LBServiceTLSCertificate{
							{SecretRef: isovalentv1alpha1.LBServiceSecretRef{Name: "tls-2"}},
							{SecretRef: isovalentv1alpha1.LBServiceSecretRef{Name: "tls-1"}},
						},
						Validation: &isovalentv1alpha1.LBTLSValidationConfig{
							SecretRef: isovalentv1alpha1.LBServiceSecretRef{Name: "ca-cert-1"},
						},
					},
				},
				TLSProxy: &isovalentv1alpha1.LBServiceApplicationTLSProxy{
					TLSConfig: isovalentv1alpha1.LBServiceTLSConfig{
						Certificates: []isovalentv1alpha1.LBServiceTLSCertificate{
							{SecretRef: isovalentv1alpha1.LBServiceSecretRef{Name: "tls-2"}},
							{SecretRef: isovalentv1alpha1.LBServiceSecretRef{Name: "tls-1"}},
						},
						Validation: &isovalentv1alpha1.LBTLSValidationConfig{
							SecretRef: isovalentv1alpha1.LBServiceSecretRef{Name: "ca-cert-2"},
						},
					},
				},
			}}},
			secrets:          map[string]*corev1.Secret{},
			expectedMessages: []string{},
		},
		{
			desc: "list incompatible secrets",
			svc: &isovalentv1alpha1.LBService{Spec: isovalentv1alpha1.LBServiceSpec{Applications: isovalentv1alpha1.LBServiceApplications{
				HTTPSProxy: &isovalentv1alpha1.LBServiceApplicationHTTPSProxy{
					TLSConfig: isovalentv1alpha1.LBServiceTLSConfig{
						Certificates: []isovalentv1alpha1.LBServiceTLSCertificate{
							{SecretRef: isovalentv1alpha1.LBServiceSecretRef{Name: "tls-2"}},
							{SecretRef: isovalentv1alpha1.LBServiceSecretRef{Name: "tls-1"}},
						},
						Validation: &isovalentv1alpha1.LBTLSValidationConfig{
							SecretRef: isovalentv1alpha1.LBServiceSecretRef{Name: "ca-cert-1"},
						},
					},
				},
				TLSProxy: &isovalentv1alpha1.LBServiceApplicationTLSProxy{
					TLSConfig: isovalentv1alpha1.LBServiceTLSConfig{
						Certificates: []isovalentv1alpha1.LBServiceTLSCertificate{
							{SecretRef: isovalentv1alpha1.LBServiceSecretRef{Name: "tls-2"}},
							{SecretRef: isovalentv1alpha1.LBServiceSecretRef{Name: "tls-1"}},
						},
						Validation: &isovalentv1alpha1.LBTLSValidationConfig{
							SecretRef: isovalentv1alpha1.LBServiceSecretRef{Name: "ca-cert-2"},
						},
					},
				},
			}}},
			secrets: map[string]*corev1.Secret{
				"tls-1": {
					ObjectMeta: metav1.ObjectMeta{Name: "tls-1"},
					Type:       corev1.SecretTypeTLS,
				},
				"tls-2": {
					ObjectMeta: metav1.ObjectMeta{Name: "tls-2"},
					Type:       corev1.SecretTypeOpaque,
					Data: map[string][]byte{
						"tls.key": []byte("bla"),
						"tls.crt": []byte("bla"),
					},
				},
				"ca-cert-1": {
					ObjectMeta: metav1.ObjectMeta{Name: "ca-cert-1"},
					Type:       corev1.SecretTypeOpaque,
				},
				"ca-cert-2": {
					ObjectMeta: metav1.ObjectMeta{Name: "ca-cert-2"},
					Type:       corev1.SecretTypeTLS,
					Data: map[string][]byte{
						"ca.crt": []byte("bla"),
					},
				},
			},
			expectedMessages: []string{
				`Secret "tls-1" is incompatible: Referenced as TLS Certificate but not of type TLS and/or relevant data fields ("tls.crt", "tls.key") missing`,
				`Secret "tls-2" is incompatible: Referenced as TLS Certificate but not of type TLS and/or relevant data fields ("tls.crt", "tls.key") missing`,
				`Secret "ca-cert-1" is incompatible: Referenced as CA Certificate but not of type Opaque and/or relevant data fields ("ca.crt") missing`,
				`Secret "ca-cert-2" is incompatible: Referenced as CA Certificate but not of type Opaque and/or relevant data fields ("ca.crt") missing`,
			},
		},
		{
			desc: "don't list any secrets if everything is compatible",
			svc: &isovalentv1alpha1.LBService{Spec: isovalentv1alpha1.LBServiceSpec{Applications: isovalentv1alpha1.LBServiceApplications{
				HTTPSProxy: &isovalentv1alpha1.LBServiceApplicationHTTPSProxy{
					TLSConfig: isovalentv1alpha1.LBServiceTLSConfig{
						Certificates: []isovalentv1alpha1.LBServiceTLSCertificate{
							{SecretRef: isovalentv1alpha1.LBServiceSecretRef{Name: "tls-2"}},
							{SecretRef: isovalentv1alpha1.LBServiceSecretRef{Name: "tls-1"}},
						},
						Validation: &isovalentv1alpha1.LBTLSValidationConfig{
							SecretRef: isovalentv1alpha1.LBServiceSecretRef{Name: "ca-cert-1"},
						},
					},
				},
				TLSProxy: &isovalentv1alpha1.LBServiceApplicationTLSProxy{
					TLSConfig: isovalentv1alpha1.LBServiceTLSConfig{
						Certificates: []isovalentv1alpha1.LBServiceTLSCertificate{
							{SecretRef: isovalentv1alpha1.LBServiceSecretRef{Name: "tls-2"}},
							{SecretRef: isovalentv1alpha1.LBServiceSecretRef{Name: "tls-1"}},
						},
						Validation: &isovalentv1alpha1.LBTLSValidationConfig{
							SecretRef: isovalentv1alpha1.LBServiceSecretRef{Name: "ca-cert-2"},
						},
					},
				},
			}}},
			secrets: map[string]*corev1.Secret{
				"tls-1": {
					ObjectMeta: metav1.ObjectMeta{Name: "tls-1"},
					Type:       corev1.SecretTypeTLS,
					Data: map[string][]byte{
						"tls.key": []byte("bla"),
						"tls.crt": []byte("bla"),
					},
				},
				"tls-2": {
					ObjectMeta: metav1.ObjectMeta{Name: "tls-2"},
					Type:       corev1.SecretTypeTLS,
					Data: map[string][]byte{
						"tls.key": []byte("bla"),
						"tls.crt": []byte("bla"),
					},
				},
				"ca-cert-1": {
					ObjectMeta: metav1.ObjectMeta{Name: "ca-cert-1"},
					Type:       corev1.SecretTypeOpaque,
					Data: map[string][]byte{
						"ca.crt": []byte("bla"),
					},
				},
				"ca-cert-2": {
					ObjectMeta: metav1.ObjectMeta{Name: "ca-cert-2"},
					Type:       corev1.SecretTypeOpaque,
					Data: map[string][]byte{
						"ca.crt": []byte("bla"),
					},
				},
			},
			expectedMessages: []string{},
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			r := lbServiceReconciler{}
			messages := r.getIncompatibleSecretTypes(tC.svc, tC.secrets)

			assert.Equal(t, tC.expectedMessages, messages)
		})
	}
}

func Test_LBServiceReconciler_updateSecretCompatibilityInStatus(t *testing.T) {
	testCases := []struct {
		desc                    string
		svc                     *isovalentv1alpha1.LBService
		secrets                 map[string]*corev1.Secret
		expectedConditionStatus metav1.ConditionStatus
	}{
		{
			desc: "skip services that aren't found",
			svc: &isovalentv1alpha1.LBService{Spec: isovalentv1alpha1.LBServiceSpec{Applications: isovalentv1alpha1.LBServiceApplications{
				HTTPSProxy: &isovalentv1alpha1.LBServiceApplicationHTTPSProxy{
					TLSConfig: isovalentv1alpha1.LBServiceTLSConfig{
						Certificates: []isovalentv1alpha1.LBServiceTLSCertificate{
							{SecretRef: isovalentv1alpha1.LBServiceSecretRef{Name: "tls-2"}},
							{SecretRef: isovalentv1alpha1.LBServiceSecretRef{Name: "tls-1"}},
						},
						Validation: &isovalentv1alpha1.LBTLSValidationConfig{
							SecretRef: isovalentv1alpha1.LBServiceSecretRef{Name: "ca-cert-1"},
						},
					},
				},
				TLSProxy: &isovalentv1alpha1.LBServiceApplicationTLSProxy{
					TLSConfig: isovalentv1alpha1.LBServiceTLSConfig{
						Certificates: []isovalentv1alpha1.LBServiceTLSCertificate{
							{SecretRef: isovalentv1alpha1.LBServiceSecretRef{Name: "tls-2"}},
							{SecretRef: isovalentv1alpha1.LBServiceSecretRef{Name: "tls-1"}},
						},
						Validation: &isovalentv1alpha1.LBTLSValidationConfig{
							SecretRef: isovalentv1alpha1.LBServiceSecretRef{Name: "ca-cert-2"},
						},
					},
				},
			}}},
			secrets:                 map[string]*corev1.Secret{},
			expectedConditionStatus: metav1.ConditionTrue,
		},
		{
			desc: "list incompatible secrets",
			svc: &isovalentv1alpha1.LBService{Spec: isovalentv1alpha1.LBServiceSpec{Applications: isovalentv1alpha1.LBServiceApplications{
				HTTPSProxy: &isovalentv1alpha1.LBServiceApplicationHTTPSProxy{
					TLSConfig: isovalentv1alpha1.LBServiceTLSConfig{
						Certificates: []isovalentv1alpha1.LBServiceTLSCertificate{
							{SecretRef: isovalentv1alpha1.LBServiceSecretRef{Name: "tls-2"}},
							{SecretRef: isovalentv1alpha1.LBServiceSecretRef{Name: "tls-1"}},
						},
						Validation: &isovalentv1alpha1.LBTLSValidationConfig{
							SecretRef: isovalentv1alpha1.LBServiceSecretRef{Name: "ca-cert-1"},
						},
					},
				},
				TLSProxy: &isovalentv1alpha1.LBServiceApplicationTLSProxy{
					TLSConfig: isovalentv1alpha1.LBServiceTLSConfig{
						Certificates: []isovalentv1alpha1.LBServiceTLSCertificate{
							{SecretRef: isovalentv1alpha1.LBServiceSecretRef{Name: "tls-2"}},
							{SecretRef: isovalentv1alpha1.LBServiceSecretRef{Name: "tls-1"}},
						},
						Validation: &isovalentv1alpha1.LBTLSValidationConfig{
							SecretRef: isovalentv1alpha1.LBServiceSecretRef{Name: "ca-cert-2"},
						},
					},
				},
			}}},
			secrets: map[string]*corev1.Secret{
				"tls-1": {
					ObjectMeta: metav1.ObjectMeta{Name: "tls-1"},
					Type:       corev1.SecretTypeTLS,
				},
				"tls-2": {
					ObjectMeta: metav1.ObjectMeta{Name: "tls-2"},
					Type:       corev1.SecretTypeOpaque,
					Data: map[string][]byte{
						"tls.key": []byte("bla"),
						"tls.crt": []byte("bla"),
					},
				},
				"ca-cert-1": {
					ObjectMeta: metav1.ObjectMeta{Name: "ca-cert-1"},
					Type:       corev1.SecretTypeOpaque,
				},
				"ca-cert-2": {
					ObjectMeta: metav1.ObjectMeta{Name: "ca-cert-2"},
					Type:       corev1.SecretTypeTLS,
					Data: map[string][]byte{
						"ca.crt": []byte("bla"),
					},
				},
			},
			expectedConditionStatus: metav1.ConditionFalse,
		},
		{
			desc: "don't list any secrets if everything is compatible",
			svc: &isovalentv1alpha1.LBService{Spec: isovalentv1alpha1.LBServiceSpec{Applications: isovalentv1alpha1.LBServiceApplications{
				HTTPSProxy: &isovalentv1alpha1.LBServiceApplicationHTTPSProxy{
					TLSConfig: isovalentv1alpha1.LBServiceTLSConfig{
						Certificates: []isovalentv1alpha1.LBServiceTLSCertificate{
							{SecretRef: isovalentv1alpha1.LBServiceSecretRef{Name: "tls-2"}},
							{SecretRef: isovalentv1alpha1.LBServiceSecretRef{Name: "tls-1"}},
						},
						Validation: &isovalentv1alpha1.LBTLSValidationConfig{
							SecretRef: isovalentv1alpha1.LBServiceSecretRef{Name: "ca-cert-1"},
						},
					},
				},
				TLSProxy: &isovalentv1alpha1.LBServiceApplicationTLSProxy{
					TLSConfig: isovalentv1alpha1.LBServiceTLSConfig{
						Certificates: []isovalentv1alpha1.LBServiceTLSCertificate{
							{SecretRef: isovalentv1alpha1.LBServiceSecretRef{Name: "tls-2"}},
							{SecretRef: isovalentv1alpha1.LBServiceSecretRef{Name: "tls-1"}},
						},
						Validation: &isovalentv1alpha1.LBTLSValidationConfig{
							SecretRef: isovalentv1alpha1.LBServiceSecretRef{Name: "ca-cert-2"},
						},
					},
				},
			}}},
			secrets: map[string]*corev1.Secret{
				"tls-1": {
					ObjectMeta: metav1.ObjectMeta{Name: "tls-1"},
					Type:       corev1.SecretTypeTLS,
					Data: map[string][]byte{
						"tls.key": []byte("bla"),
						"tls.crt": []byte("bla"),
					},
				},
				"tls-2": {
					ObjectMeta: metav1.ObjectMeta{Name: "tls-2"},
					Type:       corev1.SecretTypeTLS,
					Data: map[string][]byte{
						"tls.key": []byte("bla"),
						"tls.crt": []byte("bla"),
					},
				},
				"ca-cert=-1": {
					ObjectMeta: metav1.ObjectMeta{Name: "ca-cert-1"},
					Type:       corev1.SecretTypeOpaque,
					Data: map[string][]byte{
						"ca.crt": []byte("bla"),
					},
				},
				"ca-cert-2": {
					ObjectMeta: metav1.ObjectMeta{Name: "ca-cert-2"},
					Type:       corev1.SecretTypeOpaque,
					Data: map[string][]byte{
						"ca.crt": []byte("bla"),
					},
				},
			},
			expectedConditionStatus: metav1.ConditionTrue,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			r := lbServiceReconciler{}
			r.updateSecretCompatibilityInStatus(tC.svc, tC.secrets)

			c := tC.svc.GetStatusCondition(isovalentv1alpha1.ConditionTypeSecretsCompatible)
			require.NotNil(t, c)

			assert.Equal(t, tC.expectedConditionStatus, c.Status)
		})
	}
}

func TestLBServiceLBDeployments(t *testing.T) {
	r := lbServiceReconciler{}

	conditionType := "lb.cilium.io/LBDeploymentsUsed"

	testCases := []struct {
		desc                   string
		lbsvc                  *isovalentv1alpha1.LBService
		deployments            []isovalentv1alpha1.LBDeployment
		expectedNrOfConditions int
		expectedStatus         metav1.ConditionStatus
		expectedReason         string
		expectedMessage        string
	}{
		{
			desc:                   "No matching LBDeployments",
			lbsvc:                  &isovalentv1alpha1.LBService{Spec: isovalentv1alpha1.LBServiceSpec{VIPRef: isovalentv1alpha1.LBServiceVIPRef{Name: "my-svc"}}},
			deployments:            []isovalentv1alpha1.LBDeployment{},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "NoLBDeploymentsUsed",
			expectedMessage:        "No LBDeployments are used",
		},
		{
			desc:                   "One matching LBDeployment",
			lbsvc:                  &isovalentv1alpha1.LBService{Spec: isovalentv1alpha1.LBServiceSpec{VIPRef: isovalentv1alpha1.LBServiceVIPRef{Name: "my-svc"}}},
			deployments:            []isovalentv1alpha1.LBDeployment{{ObjectMeta: metav1.ObjectMeta{Namespace: "test", Name: "test"}}},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "LBDeploymentsUsed",
			expectedMessage:        "1 LBDeployments are used: [test]",
		},
		{
			desc:                   "Multiple matching LBDeployment",
			lbsvc:                  &isovalentv1alpha1.LBService{Spec: isovalentv1alpha1.LBServiceSpec{VIPRef: isovalentv1alpha1.LBServiceVIPRef{Name: "my-svc"}}},
			deployments:            []isovalentv1alpha1.LBDeployment{{ObjectMeta: metav1.ObjectMeta{Namespace: "test", Name: "test"}}, {ObjectMeta: metav1.ObjectMeta{Namespace: "test", Name: "test2"}}},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "LBDeploymentsUsed",
			expectedMessage:        "2 LBDeployments are used: [test test2]",
		},
		{
			desc: "Update existing condition",
			lbsvc: &isovalentv1alpha1.LBService{
				Spec:   isovalentv1alpha1.LBServiceSpec{VIPRef: isovalentv1alpha1.LBServiceVIPRef{Name: "my-svc"}},
				Status: isovalentv1alpha1.LBServiceStatus{Conditions: []metav1.Condition{{Type: conditionType, Status: metav1.ConditionTrue, Reason: "reason", Message: "message"}}},
			},
			deployments:            []isovalentv1alpha1.LBDeployment{{ObjectMeta: metav1.ObjectMeta{Namespace: "test", Name: "test"}}, {ObjectMeta: metav1.ObjectMeta{Namespace: "test", Name: "test2"}}},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "LBDeploymentsUsed",
			expectedMessage:        "2 LBDeployments are used: [test test2]",
		},
		{
			desc: "Doesn't delete other conditions",
			lbsvc: &isovalentv1alpha1.LBService{Status: isovalentv1alpha1.LBServiceStatus{Conditions: []metav1.Condition{
				{Type: "other-type", Status: metav1.ConditionTrue, Reason: "other-reason", Message: "other-message"},
				{Type: conditionType, Status: metav1.ConditionTrue, Reason: "reason", Message: "message"},
			}}},
			deployments:            []isovalentv1alpha1.LBDeployment{{ObjectMeta: metav1.ObjectMeta{Namespace: "test", Name: "test"}}, {ObjectMeta: metav1.ObjectMeta{Namespace: "test", Name: "test2"}}},
			expectedNrOfConditions: 2,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "LBDeploymentsUsed",
			expectedMessage:        "2 LBDeployments are used: [test test2]",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			r.updateDeploymentsInStatus(tc.lbsvc, tc.deployments)

			assert.Len(t, tc.lbsvc.Status.Conditions, tc.expectedNrOfConditions)

			c := tc.lbsvc.GetStatusCondition(conditionType)
			require.NotNil(t, c)
			assert.Equal(t, tc.expectedStatus, c.Status)
			assert.Equal(t, tc.expectedReason, c.Reason)
			assert.Equal(t, tc.expectedMessage, c.Message)
		})
	}
}

func acceptedCondition() metav1.Condition {
	return metav1.Condition{
		Type:    isovalentv1alpha1.ConditionTypeBackendAccepted,
		Status:  metav1.ConditionTrue,
		Reason:  isovalentv1alpha1.BackendAcceptedConditionReasonValid,
		Message: "BackendPool is valid and accepted",
	}
}
