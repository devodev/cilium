// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package status

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8syaml "sigs.k8s.io/yaml"

	isovalentv1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	ciliumfake "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/fake"
)

const statusFixtureDir = "testdata"

func TestStatusFixtures(t *testing.T) {
	entries, err := os.ReadDir(statusFixtureDir)
	require.NoError(t, err)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		fixtureDir := filepath.Join(statusFixtureDir, entry.Name())

		t.Run(entry.Name(), func(t *testing.T) {
			fixture := readStatusFixture(t, fixtureDir)

			k8sClient := fake.NewSimpleClientset(fixture.k8sObjects...)
			ciliumClient := ciliumfake.NewSimpleClientset(fixture.ciliumObjects...)

			client := NewLoadbalancerClient(k8sClient, ciliumClient, &rest.Config{}, Parameters{
				CiliumNamespace: "kube-system",
			})
			client.execInPodOverride = fixture.execInPod

			require.NoError(t, client.InitNodeAgentPods(t.Context()))

			model, err := client.GetLoadbalancerStatusModel(t.Context())
			require.NoError(t, err)
			require.Equal(t, fixture.expectedModel, *model)

			var summaryOutput bytes.Buffer
			require.NoError(t, model.Output(&summaryOutput, fixture.summaryParams))
			require.Equal(t, strings.TrimSpace(fixture.expectedSummary), strings.TrimSpace(summaryOutput.String()))
		})
	}
}

type statusFixture struct {
	k8sObjects      []runtime.Object
	ciliumObjects   []runtime.Object
	execOutputs     map[string]string
	expectedModel   LoadbalancerStatusModel
	expectedSummary string
	summaryParams   Parameters
}

func (f *statusFixture) execInPod(_ context.Context, namespace, pod, container string, command []string) (bytes.Buffer, bytes.Buffer, error) {
	output, ok := f.execOutputs[execOutputKey(command, pod)]
	if !ok {
		return bytes.Buffer{}, bytes.Buffer{}, fmt.Errorf("missing exec fixture for %s in %s/%s", strings.Join(command, " "), namespace, pod)
	}

	var stdout bytes.Buffer
	stdout.WriteString(output)
	return stdout, bytes.Buffer{}, nil
}

func execOutputKey(command []string, pod string) string {
	switch strings.Join(command, " ") {
	case "cilium-dbg bgp peers -o json":
		return "t1-bgp-peers/" + pod
	case "cilium-dbg bgp routes advertised -o json":
		return "t1-bgp-routes/" + pod
	case "cilium-dbg service list -o json":
		return "t1-services/" + pod
	case "cilium-dbg envoy admin config":
		return "t2-envoyconfig/" + pod
	default:
		return strings.Join(command, " ") + "/" + pod
	}
}

func readStatusFixture(t *testing.T, fixtureDir string) *statusFixture {
	t.Helper()

	entries, err := os.ReadDir(fixtureDir)
	require.NoError(t, err)

	fixture := &statusFixture{
		execOutputs: map[string]string{},
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		path := filepath.Join(fixtureDir, name)

		switch {
		case strings.HasPrefix(name, "input-k8s-namespace-"):
			obj := &corev1.Namespace{}
			readYAMLFixture(t, path, obj)
			fixture.k8sObjects = append(fixture.k8sObjects, obj)
		case strings.HasPrefix(name, "input-k8s-node-"):
			obj := &corev1.Node{}
			readYAMLFixture(t, path, obj)
			fixture.k8sObjects = append(fixture.k8sObjects, obj)
		case strings.HasPrefix(name, "input-k8s-pod-"):
			obj := &corev1.Pod{}
			readYAMLFixture(t, path, obj)
			fixture.k8sObjects = append(fixture.k8sObjects, obj)
		case strings.HasPrefix(name, "input-lbservice-"):
			obj := &isovalentv1alpha1.LBService{}
			readYAMLFixture(t, path, obj)
			fixture.ciliumObjects = append(fixture.ciliumObjects, obj)
		case strings.HasPrefix(name, "input-lbvip-"):
			obj := &isovalentv1alpha1.LBVIP{}
			readYAMLFixture(t, path, obj)
			fixture.ciliumObjects = append(fixture.ciliumObjects, obj)
		case strings.HasPrefix(name, "input-lbdeployment-"):
			obj := &isovalentv1alpha1.LBDeployment{}
			readYAMLFixture(t, path, obj)
			fixture.ciliumObjects = append(fixture.ciliumObjects, obj)
		case strings.HasPrefix(name, "input-bgpclusterconfig-"):
			obj := &isovalentv1.IsovalentBGPClusterConfig{}
			readYAMLFixture(t, path, obj)
			fixture.ciliumObjects = append(fixture.ciliumObjects, obj)
		case strings.HasPrefix(name, "input-bgppeerconfig-"):
			obj := &isovalentv1.IsovalentBGPPeerConfig{}
			readYAMLFixture(t, path, obj)
			fixture.ciliumObjects = append(fixture.ciliumObjects, obj)
		case strings.HasPrefix(name, "input-bgpadvertisement-"):
			obj := &isovalentv1.IsovalentBGPAdvertisement{}
			readYAMLFixture(t, path, obj)
			fixture.ciliumObjects = append(fixture.ciliumObjects, obj)
		case strings.HasPrefix(name, "input-t1-bgp-peers-"):
			fixture.execOutputs["t1-bgp-peers/"+fixtureExecName(name, "input-t1-bgp-peers-")] = readTextFixture(t, path)
		case strings.HasPrefix(name, "input-t1-bgp-routes-"):
			fixture.execOutputs["t1-bgp-routes/"+fixtureExecName(name, "input-t1-bgp-routes-")] = readTextFixture(t, path)
		case strings.HasPrefix(name, "input-t1-services-"):
			fixture.execOutputs["t1-services/"+fixtureExecName(name, "input-t1-services-")] = readTextFixture(t, path)
		case strings.HasPrefix(name, "input-t2-envoyconfig-"):
			fixture.execOutputs["t2-envoyconfig/"+fixtureExecName(name, "input-t2-envoyconfig-")] = readTextFixture(t, path)
		case name == "input-summary-params.json":
			readJSONFixture(t, path, &fixture.summaryParams)
		case name == "expected-model.json":
			readJSONFixture(t, path, &fixture.expectedModel)
		case name == "expected-summary.txt":
			fixture.expectedSummary = readTextFixture(t, path)
		}
	}

	return fixture
}

func fixtureExecName(name, prefix string) string {
	return strings.TrimSuffix(strings.TrimPrefix(name, prefix), filepath.Ext(name))
}

func readYAMLFixture(t *testing.T, file string, obj any) {
	t.Helper()

	data, err := os.ReadFile(file)
	require.NoError(t, err)
	require.NoError(t, k8syaml.Unmarshal(data, obj))
}

func readJSONFixture(t *testing.T, file string, obj any) {
	t.Helper()

	data, err := os.ReadFile(file)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, obj))
}

func readTextFixture(t *testing.T, file string) string {
	t.Helper()

	data, err := os.ReadFile(file)
	require.NoError(t, err)

	return string(data)
}
