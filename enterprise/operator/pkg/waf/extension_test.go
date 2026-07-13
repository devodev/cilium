//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package waf

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"

	lbextension "github.com/cilium/cilium/enterprise/operator/pkg/lb/extension"
	wafenvoy "github.com/cilium/cilium/enterprise/operator/pkg/waf/envoy"
	wafpolicy "github.com/cilium/cilium/enterprise/operator/pkg/waf/policy"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

func TestHTTPFilters(t *testing.T) {
	testCases := []struct {
		name        string
		state       lbextension.State
		expectedNil bool
		expectedErr string
	}{
		{
			name:        "nil state returns nil filter",
			state:       nil,
			expectedNil: true,
		},
		{
			name:        "unexpected state type returns error",
			state:       "invalid",
			expectedErr: "unexpected WAF extension state string",
		},
		{
			name: "inline rules return WAF filter",
			state: &wafpolicy.EffectiveConfig{
				Enabled: true,
				Rules: wafpolicy.EffectiveRules{
					Source: wafpolicy.EffectiveRuleSourceInline,
					Inline: wafpolicy.InlineRules{
						Inline: `SecAction "id:1000,phase:1,pass,nolog"`,
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ext := &lbExtension{
				translator: wafenvoy.NewTranslator(hivetest.Logger(t), wafenvoy.NewProxyConfigBuilder()),
			}

			actual, err := ext.HTTPFilters(types.NamespacedName{Namespace: "default", Name: "waf-test"}, tc.state)

			if tc.expectedErr != "" {
				require.ErrorContains(t, err, tc.expectedErr)
				require.Nil(t, actual)
				return
			}

			require.NoError(t, err)
			if tc.expectedNil {
				require.Nil(t, actual)
				return
			}

			require.Len(t, actual, 1)
			require.Zero(t, actual[0].Order)
			require.Equal(t, wafenvoy.HTTPFilterName, actual[0].Filter.GetName())
			require.NotNil(t, actual[0].Filter.GetTypedConfig())
		})
	}
}

func TestHTTPRoutes(t *testing.T) {
	blockStatusCode := int32(418)
	blockBody := "blocked by policy"
	testCases := []struct {
		name        string
		state       lbextension.State
		expectedNil bool
		expectedErr string
	}{
		{
			name:        "nil state returns nil route",
			state:       nil,
			expectedNil: true,
		},
		{
			name:        "unexpected state type returns error",
			state:       "invalid",
			expectedErr: "unexpected WAF extension state string",
		},
		{
			name: "managed rules return WAF block route",
			state: &wafpolicy.EffectiveConfig{
				Enabled: true,
				Mode:    isovalentv1alpha1.IsovalentWAFPolicyModeEnforce,
				Rules: wafpolicy.EffectiveRules{
					Source:        wafpolicy.EffectiveRuleSourceManaged,
					PolicyProfile: isovalentv1alpha1.IsovalentWAFPolicyProfileBalanced,
				},
				HandlingOverrides: wafpolicy.EffectiveHandlingOverrides{
					BlockResponseStatusCode: &blockStatusCode,
					BlockResponseBody:       &blockBody,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ext := &lbExtension{
				translator: wafenvoy.NewTranslator(hivetest.Logger(t), wafenvoy.NewProxyConfigBuilder()),
			}

			actual, err := ext.HTTPRoutes(types.NamespacedName{Namespace: "default", Name: "waf-test"}, tc.state)

			if tc.expectedErr != "" {
				require.ErrorContains(t, err, tc.expectedErr)
				require.Nil(t, actual)
				return
			}

			require.NoError(t, err)
			if tc.expectedNil {
				require.Nil(t, actual)
				return
			}

			require.Len(t, actual, 1)

			blockRoute := actual[0].Route
			require.Equal(t, "/__waf_block__", blockRoute.GetMatch().GetPath())
			require.Equal(t, uint32(blockStatusCode), blockRoute.GetDirectResponse().GetStatus())
			require.Equal(t, blockBody, blockRoute.GetDirectResponse().GetBody().GetInlineString())
		})
	}
}

func TestAccessLogFields(t *testing.T) {
	testCases := []struct {
		name     string
		state    lbextension.State
		expected []lbextension.AccessLogField
	}{
		{
			name:  "nil state returns nil fields",
			state: nil,
		},
		{
			name:  "disabled config returns nil fields",
			state: &wafpolicy.EffectiveConfig{},
		},
		{
			name:  "enabled config returns WAF fields",
			state: &wafpolicy.EffectiveConfig{Enabled: true},
			expected: []lbextension.AccessLogField{
				{
					Text: []string{
						`http.req.x-waf-rule-id="%REQ(X-WAF-RULE-ID)%"`,
						`http.req.x-waf-original-path="%REQ(X-WAF-ORIGINAL-PATH)%"`,
						`http.resp.x-waf-rule-id="%RESP(X-WAF-RULE-ID)%"`,
					},
					JSON: map[string]string{
						"http.req.x-waf-rule-id":       "%REQ(X-WAF-RULE-ID)%",
						"http.req.x-waf-original-path": "%REQ(X-WAF-ORIGINAL-PATH)%",
						"http.resp.x-waf-rule-id":      "%RESP(X-WAF-RULE-ID)%",
					},
				},
			},
		},
		{
			name:  "unexpected state type returns nil fields",
			state: "invalid",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ext := &lbExtension{
				translator: wafenvoy.NewTranslator(hivetest.Logger(t), wafenvoy.NewProxyConfigBuilder()),
			}
			actual := ext.AccessLogFields(tc.state)

			require.Equal(t, tc.expected, actual)
		})
	}
}
