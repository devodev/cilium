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
	"slices"
	"strings"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8syaml "sigs.k8s.io/yaml"

	ossannotation "github.com/cilium/cilium/pkg/annotation"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

type testcase struct {
	name string
}

const (
	translationDir = "./testdata/lbservice_translation"
)

func TestTranslation(t *testing.T) {
	entries, err := os.ReadDir(translationDir)
	require.NoError(t, err)

	testCases := []testcase{}

	for _, d := range entries {
		if !d.IsDir() {
			continue
		}

		testCases = append(testCases, testcase{
			name: d.Name(),
		})
	}

	for _, tc := range testCases {
		t.Run(tc.name, testTranslationSingle(tc))
	}
}

func testTranslationSingle(tc testcase) func(t *testing.T) {
	return func(t *testing.T) {
		// read input files
		var inputLBVIP *isovalentv1alpha1.LBVIP
		if _, err := os.Stat(fmt.Sprintf("%s/%s/input-lbvip.yaml", translationDir, tc.name)); err == nil {
			inputLBVIP = &isovalentv1alpha1.LBVIP{}
			readInput(t, fmt.Sprintf("%s/%s/input-lbvip.yaml", translationDir, tc.name), inputLBVIP)
		}

		inputLBService := &isovalentv1alpha1.LBService{}
		readInput(t, fmt.Sprintf("%s/%s/input-lbservice.yaml", translationDir, tc.name), inputLBService)

		entries, err := os.ReadDir(fmt.Sprintf("%s/%s", translationDir, tc.name))
		require.NoError(t, err)

		inputNodes := []*slim_corev1.Node{}
		inputLBBackends := []*isovalentv1alpha1.LBBackendPool{}
		inputLBDeployments := []isovalentv1alpha1.LBDeployment{}
		inputSecrets := map[string]*corev1.Secret{}
		inputK8sServices := []corev1.Service{}
		inputK8sEPSlices := []discoveryv1.EndpointSlice{}

		for _, d := range entries {
			if d.IsDir() {
				continue
			}
			fname := fmt.Sprintf("%s/%s/%s", translationDir, tc.name, d.Name())
			switch {
			case strings.HasPrefix(d.Name(), "input-lbbackend-"):
				inputLBBackend := &isovalentv1alpha1.LBBackendPool{}
				readInput(t, fname, inputLBBackend)
				inputLBBackends = append(inputLBBackends, inputLBBackend)
			case strings.HasPrefix(d.Name(), "input-lbdeployment-"):
				inputLBDeployment := &isovalentv1alpha1.LBDeployment{}
				readInput(t, fname, inputLBDeployment)
				inputLBDeployments = append(inputLBDeployments, *inputLBDeployment)
			case strings.HasPrefix(d.Name(), "input-secret-"):
				inputSecret := &corev1.Secret{}
				readInput(t, fname, inputSecret)
				inputSecrets[inputSecret.Name] = inputSecret
			case strings.HasPrefix(d.Name(), "input-k8s-node-"):
				inputNode := &slim_corev1.Node{}
				readInput(t, fname, inputNode)
				inputNodes = append(inputNodes, inputNode)
			case strings.HasPrefix(d.Name(), "input-k8s-service-"):
				inputK8sService := &corev1.Service{}
				readInput(t, fname, inputK8sService)
				inputK8sServices = append(inputK8sServices, *inputK8sService)
			case strings.HasPrefix(d.Name(), "input-k8s-endpointslice-"):
				inputK8sEPSlice := &discoveryv1.EndpointSlice{}
				readInput(t, fname, inputK8sEPSlice)
				inputK8sEPSlices = append(inputK8sEPSlices, *inputK8sEPSlice)
			}
		}

		var inputService *corev1.Service
		if _, err := os.Stat(fmt.Sprintf("%s/%s/input-t1-service.yaml", translationDir, tc.name)); err == nil {
			inputService = &corev1.Service{}
			readInput(t, fmt.Sprintf("%s/%s/input-t1-service.yaml", translationDir, tc.name), inputService)
		}

		// read output files
		expectedServiceYaml := readOutput(t, fmt.Sprintf("%s/%s/output-t1-service.yaml", translationDir, tc.name), &corev1.Service{})
		expectedEndpointSliceYaml := readOutput(t, fmt.Sprintf("%s/%s/output-t1-endpointslice.yaml", translationDir, tc.name), &discoveryv1.EndpointSlice{})
		expectedEndpointSliceIPv6Yaml := readOutput(t, fmt.Sprintf("%s/%s/output-t1-endpointslice-ipv6.yaml", translationDir, tc.name), &discoveryv1.EndpointSlice{})
		expectedCiliumEnvoyConfigYamls := readCECOutputs(t, fmt.Sprintf("%s/%s", translationDir, tc.name))

		// ingestion
		ing := newIngestor(hivetest.Logger(t), defaultT1LabelSelector, defaultT2LabelSelector)

		model, err := ing.ingest(t.Context(), inputLBVIP, inputLBService, inputLBBackends, inputLBDeployments, inputNodes, inputService, inputSecrets, inputK8sServices, inputK8sEPSlices)
		assert.NoError(t, err)

		// Input Config
		config := reconcilerConfig{}
		readInput(t, fmt.Sprintf("%s/%s/input-config.yaml", translationDir, tc.name), &config)

		// translation
		t1Translator := &lbServiceT1Translator{
			logger: hivetest.Logger(t),
			config: config,
		}
		t2Translator := &lbServiceT2Translator{
			logger: hivetest.Logger(t),
			config: config,
		}

		// T1 Service
		service := t1Translator.DesiredService(model)

		actualServiceYaml := ""
		if service != nil {
			service.TypeMeta = metav1.TypeMeta{APIVersion: "v1", Kind: "Service"} // fix missing typemeta
			actualServiceYaml = toYaml(t, service)
		}
		assert.Equal(t, expectedServiceYaml, actualServiceYaml) //nolint:all (assert.YAMLEq output is not super readable)

		// T1 EndpointSlice
		endpointSlice := t1Translator.DesiredEndpointSlice(model, false)

		actualEndpointSliceYaml := ""
		if endpointSlice != nil {
			endpointSlice.TypeMeta = metav1.TypeMeta{APIVersion: "discovery/v1", Kind: "EndpointSlice"} // fix missing typemeta
			actualEndpointSliceYaml = toYaml(t, endpointSlice)
		}
		assert.Equal(t, expectedEndpointSliceYaml, actualEndpointSliceYaml) //nolint:all (assert.YAMLEq output is not super readable)

		// T1 EndpointSlice IPv6
		endpointSliceIPv6 := t1Translator.DesiredEndpointSlice(model, true)

		actualEndpointSliceIPv6Yaml := ""
		if endpointSliceIPv6 != nil {
			endpointSliceIPv6.TypeMeta = metav1.TypeMeta{APIVersion: "discovery/v1", Kind: "EndpointSlice"} // fix missing typemeta
			actualEndpointSliceIPv6Yaml = toYaml(t, endpointSliceIPv6)
		}
		assert.Equal(t, expectedEndpointSliceIPv6Yaml, actualEndpointSliceIPv6Yaml) //nolint:all (assert.YAMLEq output is not super readable)

		// T2 CiliumEnvoyConfig
		cecs, err := t2Translator.DesiredCiliumEnvoyConfigs(model)
		require.NoError(t, err)

		slices.SortFunc(cecs, func(a, b *ciliumv2.CiliumEnvoyConfig) int {
			return strings.Compare(a.Name, b.Name)
		})

		actualCiliumEnvoyConfigYamls := []string{}
		for _, cec := range cecs {
			cec.TypeMeta = metav1.TypeMeta{APIVersion: "cilium.io/v2", Kind: "CiliumEnvoyConfig"} // fix missing typemeta
			actualCiliumEnvoyConfigYamls = append(actualCiliumEnvoyConfigYamls, toYaml(t, cec))
		}

		assert.Equal(t, expectedCiliumEnvoyConfigYamls, actualCiliumEnvoyConfigYamls) //nolint:all (assert.YAMLEq output is not super readable)
	}
}

func readInput(t *testing.T, file string, obj any) {
	inputYaml, err := os.ReadFile(file)
	require.NoError(t, err)

	require.NoError(t, k8syaml.Unmarshal(inputYaml, obj))
}

func readOutput(t *testing.T, file string, obj any) string {
	// unmarshal and marshal to prevent forrmatting diffs

	if _, err := os.Stat(file); err != nil {
		return ""
	}

	outputYaml, err := os.ReadFile(file)
	require.NoError(t, err)

	if strings.TrimSpace(string(outputYaml)) == "" {
		return strings.TrimSpace(string(outputYaml))
	}

	require.NoError(t, k8syaml.Unmarshal(outputYaml, obj))

	yamlText := toYaml(t, obj)

	return strings.TrimSpace(string(yamlText))
}

func readCECOutputs(t *testing.T, dir string) []string {
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	outputs := []string{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "output-t2-ciliumenvoyconfig") || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}

		output := readOutput(t, fmt.Sprintf("%s/%s", dir, entry.Name()), &ciliumv2.CiliumEnvoyConfig{})
		if output == "" {
			continue
		}
		outputs = append(outputs, output)
	}

	slices.Sort(outputs)
	return outputs
}

func toYaml(t *testing.T, obj any) string {
	yamlText, err := k8syaml.Marshal(obj)
	require.NoError(t, err)

	return strings.TrimSpace(string(yamlText))
}

var (
	defaultT1LabelSelector = slim_metav1.LabelSelector{
		MatchExpressions: []slim_metav1.LabelSelectorRequirement{
			{
				Key:      ossannotation.ServiceNodeExposure,
				Operator: slim_metav1.LabelSelectorOpIn,
				Values: []string{
					lbNodeTypeT1,
					lbNodeTypeT1AndT2,
				},
			},
		},
	}

	defaultT2LabelSelector = slim_metav1.LabelSelector{
		MatchExpressions: []slim_metav1.LabelSelectorRequirement{
			{
				Key:      ossannotation.ServiceNodeExposure,
				Operator: slim_metav1.LabelSelectorOpIn,
				Values: []string{
					lbNodeTypeT2,
					lbNodeTypeT1AndT2,
				},
			},
		},
	}
)
