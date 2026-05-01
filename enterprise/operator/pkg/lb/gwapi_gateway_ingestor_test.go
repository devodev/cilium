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
	"fmt"
	"os"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/enterprise/operator/pkg/wafpolicy"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

const (
	ilbgatewayTestdataDir = "testdata/gwapi_translation"
)

func TestHTTP(t *testing.T) {
	tests := map[string]struct{}{
		"basic-http": {},
	}

	for name := range tests {
		t.Run(name, func(t *testing.T) {

			input := readGatewayInput(t, name)
			ing := newGWIngestor(hivetest.Logger(t), defaultT1LabelSelector, defaultT2LabelSelector)

			inputGW, err := ing.ingestGatewayAPItoLB(input, t.Context())

			assert.NoError(t, err)

			config := reconcilerConfig{}
			readInput(t, fmt.Sprintf("%s/%s/input-config.yaml", ilbgatewayTestdataDir, name), &config)

			expected := lbService{}
			readOutput(t, fmt.Sprintf("%s/%s/%s", ilbgatewayTestdataDir, name, "output-lbservice.yaml"), &expected)
			// read output files
			expectedServiceYaml := readOutput(t, fmt.Sprintf("%s/%s/output-t1-service.yaml", ilbgatewayTestdataDir, name), &corev1.Service{})
			expectedEndpointSliceYaml := readOutput(t, fmt.Sprintf("%s/%s/output-endpointslice.yaml", ilbgatewayTestdataDir, name), &discoveryv1.EndpointSlice{})
			expectedCiliumEnvoyConfigYaml := readOutput(t, fmt.Sprintf("%s/%s/output-t2-ciliumenvoyconfig.yaml", ilbgatewayTestdataDir, name), &ciliumv2.CiliumEnvoyConfig{})

			// translation
			t1Translator := &lbServiceT1Translator{
				logger: hivetest.Logger(t),
				config: config,
			}
			t2Translator := &lbServiceT2Translator{
				logger: hivetest.Logger(t),
				config: config,
				wafTranslator: wafpolicy.NewTranslator(
					hivetest.Logger(t),
					wafpolicy.NewProxyConfigBuilder(),
				),
			}

			// desired T1 from translation
			desiredT1Service := t1Translator.DesiredService(inputGW)

			testT1ServiceYaml := ""
			if desiredT1Service != nil {
				desiredT1Service.TypeMeta = metav1.TypeMeta{APIVersion: "v1", Kind: "Service"} // fix missing typemeta
				testT1ServiceYaml = toYaml(t, desiredT1Service)
			}
			assert.Equal(t, expectedServiceYaml, testT1ServiceYaml) //nolint:all (assert.YAMLEq output is not super readable)

			// desired endpoint slices
			desiredEndpointSlices := t1Translator.DesiredEndpointSlice(inputGW, false)

			testEndpointSlice := ""
			if desiredEndpointSlices != nil {
				desiredEndpointSlices.TypeMeta = metav1.TypeMeta{APIVersion: "discovery/v1", Kind: "EndpointSlice"}
				testEndpointSlice = toYaml(t, desiredEndpointSlices)
			}
			assert.Equal(t, expectedEndpointSliceYaml, testEndpointSlice) //nolint:all (assert.YAMLEq output is not super readable)

			// desired T2 from translation
			cec, err := t2Translator.DesiredCiliumEnvoyConfig(inputGW)
			require.NoError(t, err)

			actualCiliumEnvoyConfigYaml := ""
			if cec != nil {
				cec.TypeMeta = metav1.TypeMeta{APIVersion: "cilium.io/v2", Kind: "CiliumEnvoyConfig"} // fix missing typemeta
				actualCiliumEnvoyConfigYaml = toYaml(t, cec)
			}

			assert.Equal(t, expectedCiliumEnvoyConfigYaml, actualCiliumEnvoyConfigYaml) //nolint:all (assert.YAMLEq output is not super readable)

		})
	}
}

func readGatewayInput(t *testing.T, testName string) Input {
	input := Input{}
	readInput(t, fmt.Sprintf("%s/%s/%s", ilbgatewayTestdataDir, (testName), "input-gatewayclass.yaml"), &input.GatewayClass)
	readInput(t, fmt.Sprintf("%s/%s/%s", ilbgatewayTestdataDir, (testName), "input-gateway.yaml"), &input.Gateway)
	readInput(t, fmt.Sprintf("%s/%s/%s", ilbgatewayTestdataDir, (testName), "input-lbvip.yaml"), &input.VIP)

	input.Services = []corev1.Service{}
	input.AllNodes = []*slim_corev1.Node{}
	input.EndpointSlices = []discoveryv1.EndpointSlice{}
	input.HTTPRoutes = []gatewayv1.HTTPRoute{}

	entries, _ := os.ReadDir(fmt.Sprintf("%s/%s", ilbgatewayTestdataDir, testName))
	for _, d := range entries {
		if d.IsDir() {
			continue
		}
		fname := fmt.Sprintf("%s/%s/%s", ilbgatewayTestdataDir, testName, d.Name())
		switch {
		case strings.HasPrefix(d.Name(), "input-k8s-node-"):
			inputNode := &slim_corev1.Node{}
			readInput(t, fname, inputNode)
			input.AllNodes = append(input.AllNodes, inputNode)
		case strings.HasPrefix(d.Name(), "input-k8s-service"):
			inputK8sService := &corev1.Service{}
			readInput(t, fname, inputK8sService)
			input.Services = append(input.Services, *inputK8sService)
		case strings.HasPrefix(d.Name(), "input-k8s-endpointslice-"):
			inputK8sEPSlice := &discoveryv1.EndpointSlice{}
			readInput(t, fname, inputK8sEPSlice)
			input.EndpointSlices = append(input.EndpointSlices, *inputK8sEPSlice)
		case strings.HasPrefix(d.Name(), "input-httproute"):
			inputHTTPRoute := &gatewayv1.HTTPRoute{}
			readInput(t, fname, inputHTTPRoute)
			input.HTTPRoutes = append(input.HTTPRoutes, *inputHTTPRoute)
		}
	}
	return input
}
