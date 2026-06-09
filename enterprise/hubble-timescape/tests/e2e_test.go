// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this
// information or reproduction of this material is strictly forbidden unless
// prior written permission is obtained from Isovalent Inc.

package tests

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/testing/protocmp"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"

	k8spb "github.com/isovalent/hubble-timescape/api/k8sevent/v1"
	tspb "github.com/isovalent/hubble-timescape/api/timescape/v1"

	fakeflow "github.com/cilium/fake/flow"

	observerpb "github.com/cilium/cilium/api/v1/observer"
)

const enableIntegratedTimescapeE2E = "ENABLE_ENTERPRISE_INTEGRATED_TIMESCAPE_E2E"

func requireIntegratedTimescapeE2E(t *testing.T) {
	t.Helper()

	if !strings.EqualFold(os.Getenv(enableIntegratedTimescapeE2E), "true") {
		t.Skipf("skipping: set %s=true to run integrated Timescape e2e tests", enableIntegratedTimescapeE2E)
	}
}

func hubbleObserveTLS() bool {
	return strings.EqualFold(os.Getenv("TEST_HUBBLE_OBSERVE_TLS"), "true")
}

func hubbleObserve(t *testing.T, ctx context.Context, extraArgs ...string) string {
	t.Helper()
	args := append(
		[]string{"observe", "-o", "json"},
		extraArgs...,
	)
	if hubbleObserveTLS() {
		args = append(args, "--tls", "--tls-allow-insecure")
	}
	out, err := HubbleCLI(ctx, args...)
	require.NoError(t, err, out)
	return out
}

func TestHubbleObserve(t *testing.T) {
	requireIntegratedTimescapeE2E(t)

	ctx := context.Background()

	out := hubbleObserve(t, ctx)
	flows := GetFlowsResponseFromReader(t, strings.NewReader(out))
	require.NotEmpty(t, flows, "expected flows to be returned")
}

func TestPushFlows(t *testing.T) {
	requireIntegratedTimescapeE2E(t)

	now := time.Now()
	ctx := context.Background()
	// Generate some fake flow data to push to timescape
	nodeName := fmt.Sprintf("integrated-ts-test-node-%d", now.Unix())
	t.Log("using node name", nodeName) // log for troubleshooting
	inputFlows := genFakeExportFlows(t, 4, now, nodeName)
	flowBuf := encodeGetFlowsResponse(t, inputFlows)

	tlsConf := tls.Config{InsecureSkipVerify: true}

	if os.Getenv("TEST_PUSH_API_CLIENT_KEY") != "" {
		cert, err := tls.LoadX509KeyPair(os.Getenv("TEST_PUSH_API_CLIENT_CRT"), os.Getenv("TEST_PUSH_API_CLIENT_KEY"))
		require.NoError(t, err)
		tlsConf.Certificates = []tls.Certificate{cert}
	}
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tlsConf,
	}}

	pushURL := "http://localhost:4260/push"
	if hubbleObserveTLS() {
		pushURL = "https://localhost:4260/push"
	}

	// Push the flows
	http.NewRequestWithContext(ctx, http.MethodPost, pushURL, flowBuf)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, pushURL, flowBuf)
	require.NoError(t, err, "Should succeed creating request")
	res, err := client.Do(req)
	require.NoError(t, err)
	require.NoError(t, err, "Should succeed pushing flows to timescape push API")
	res.Body.Close()
	require.Equal(t, http.StatusOK, res.StatusCode, "Should succeed pushing flows to timescape push API")

	// Query the flows back so we can verify they have been stored
	out := hubbleObserve(t, ctx, "--node-name", nodeName)
	gotFlows := GetFlowsResponseFromReader(t, strings.NewReader(out))
	if diff := cmp.Diff(inputFlows, gotFlows, protocmp.Transform()); diff != "" {
		assert.Fail(t, fmt.Sprintf("not equal (-want +got):\n%s", diff))
	}

}

func TestIngestK8sEvents(t *testing.T) {
	requireIntegratedTimescapeE2E(t)

	ctx := context.Background()
	now := time.Now()

	var conn *grpc.ClientConn
	var err error
	if hubbleObserveTLS() {
		creds := credentials.NewTLS(&tls.Config{
			InsecureSkipVerify: true, // #nosec G402
		})
		conn, err = grpc.NewClient("localhost:4245", grpc.WithTransportCredentials(creds))
	} else {
		conn, err = grpc.NewClient("localhost:4245", grpc.WithTransportCredentials(insecure.NewCredentials()))

	}
	require.NoError(t, err)
	defer conn.Close()
	client := tspb.NewK8SEventServiceClient(conn)
	k8sClient, err := newK8sClient("", "")
	require.NoError(t, err)

	// Create network policy
	netPolName := fmt.Sprintf("integrated-ts-test-netpol-%d", now.Unix())
	_, err = k8sClient.NetworkingV1().NetworkPolicies("default").Create(ctx, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: netPolName,
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	defer func() {
		// Cleanup network policy
		err = k8sClient.NetworkingV1().NetworkPolicies("default").Delete(ctx, netPolName, metav1.DeleteOptions{})
		require.NoError(t, err)
	}()

	// Check that Timescape ingests a matching k8s event
	require.Eventually(t, func() bool {
		stream, err := client.GetK8SEvents(ctx, &tspb.GetK8SEventsRequest{
			Include: []*tspb.K8SEventFilter{
				{
					Name:      []string{netPolName},
					Namespace: []string{"default"},
				},
			},
		})
		if err != nil {
			t.Logf("Failed to get stream: %s", err)
			return false
		}
		var events []*k8spb.Event
		for {
			resp, err := stream.Recv()
			if errors.Is(err, io.EOF) {
				break
			} else if err != nil {
				t.Logf("Unexpected error receiving k8s events: %s", err)
				return false
			}
			events = append(events, resp.GetEvent())
		}

		return len(events) > 0
	}, 30*time.Second, 500*time.Millisecond, "failed to get k8s event in 30 seconds")
}

func encodeGetFlowsResponse(t *testing.T, flows []*observerpb.GetFlowsResponse) io.Reader {
	t.Helper()
	var buf bytes.Buffer
	flowEn := json.NewEncoder(&buf)
	for _, flow := range flows {
		err := flowEn.Encode(flow)
		require.NoError(t, err)
	}
	return &buf
}

func genFakeExportFlows(t *testing.T, count int, baseTime time.Time, nodeName string) []*observerpb.GetFlowsResponse {
	t.Helper()
	flows := make([]*observerpb.GetFlowsResponse, 0, count)
	for i := range count {
		flow := fakeflow.New(
			// Use a specific NodeName for exported flows so we can query the flow
			fakeflow.WithFlowNodeName(nodeName),
			// ensure time is increasing so that results are pre-sorted by time
			fakeflow.WithFlowTime(baseTime.Add(time.Second*time.Duration(i))),
		)
		// Exported flows are wrapped in GetFlowsResponse
		resp := &observerpb.GetFlowsResponse{
			NodeName: flow.GetNodeName(),
			Time:     flow.GetTime(),
			ResponseTypes: &observerpb.GetFlowsResponse_Flow{
				Flow: flow,
			},
		}
		flows = append(flows, resp)
	}
	return flows
}

func newK8sClient(kubeconfig, contextName string) (kubernetes.Interface, error) {
	restClientGetter := genericclioptions.ConfigFlags{
		Context:    &contextName,
		KubeConfig: &kubeconfig,
	}
	rawKubeConfigLoader := restClientGetter.ToRawKubeConfigLoader()

	config, err := rawKubeConfigLoader.ClientConfig()
	if err != nil {
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return clientset, nil
}

func HubbleCLI(ctx context.Context, args ...string) (string, error) {
	_, fname, _, _ := runtime.Caller(0)
	hubbleDir := path.Join(
		fname, "..", "..", "..", "..", "enterprise", "hubble",
	)

	args = append([]string{"run", hubbleDir}, args...)
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = path.Join(fname, "..", "..", "..", "..")
	output, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(output)), err
}

func GetFlowsResponseFromReader(t *testing.T, out io.Reader) []*observerpb.GetFlowsResponse {
	t.Helper()
	var flows []*observerpb.GetFlowsResponse
	dec := json.NewDecoder(out)
	for dec.More() {
		var flow observerpb.GetFlowsResponse
		err := dec.Decode(&flow)
		require.NoError(t, err)
		flows = append(flows, &flow)
	}
	return flows
}
