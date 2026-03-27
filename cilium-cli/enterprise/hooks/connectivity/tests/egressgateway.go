// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/defaults"
	enterpriseK8s "github.com/cilium/cilium/cilium-cli/enterprise/hooks/k8s"
	"github.com/cilium/cilium/cilium-cli/utils/features"
	"github.com/cilium/cilium/cilium-cli/utils/wait"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	slimcorev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/versioncheck"
)

const (
	EgressGroupLabelKey   = "egress-group"
	EgressGroupLabelValue = "test"

	K8sZoneLabel = corev1.LabelTopologyZone

	EgressGatewayIPAMRoutingTable = 2050

	egwBGPAdvertisementName        = "test-egw-bgp-advertisement"
	egwRRCommonBGPPeerConfigName   = "test-egw-rr-common-bgp-peer-config"
	egwExternalBGPPeerConfigName   = "test-egw-external-bgp-peer-config"
	egwRRsBGPClusterConfigName     = "test-egw-route-reflectors-bgp-cluster-config"
	egwClientsBGPClusterConfigName = "test-egw-clients-bgp-cluster-config"
	egwBFDProfileName              = "test-egw-bfd-profile"

	egwBGPCiliumASN   = 65001
	egwBGPRRLocalPort = 11179
	egwBGPRRClusterID = "255.0.0.1"
)

// bpfEgressGatewayPolicyEntry represents an entry in the BPF egress gateway policy map
type bpfEgressGatewayPolicyEntry struct {
	SourceIP   string
	DestCIDR   string
	EgressIP   string
	GatewayIPs []string
}

// matches is an helper used to compare the receiver bpfEgressGatewayPolicyEntry with another entry
func (e *bpfEgressGatewayPolicyEntry) matches(t bpfEgressGatewayPolicyEntry) bool {
	sort.Strings(t.GatewayIPs)
	sort.Strings(e.GatewayIPs)

	return t.SourceIP == e.SourceIP &&
		t.DestCIDR == e.DestCIDR &&
		t.EgressIP == e.EgressIP &&
		cmp.Equal(t.GatewayIPs, e.GatewayIPs, cmpopts.EquateEmpty())
}

// ipAddrEntry represents an entry from "ip --json addr show" output
// only the fields relevant for the tests are defined
type ipAddrEntry struct {
	AddrInfo []addrInfo `json:"addr_info"`
}

type addrInfo struct {
	Local string
}

// ipRuleEntry represents an entry from "ip --json rule show" output
// only the fields relevant for the tests are defined
type ipRuleEntry struct {
	Src string
}

// ipRouteEntry represents an entry from "ip --json route show" output
// only the fields relevant for the tests are defined
type ipRouteEntry struct {
	PrefSrc string
}

// waitForBpfPolicyEntries waits for the egress gateway policy maps on each node to be populated with the entries
// returned by the targetEntriesCallback
func waitForBpfPolicyEntries(ctx context.Context, t *check.Test,
	targetEntriesCallback func(ciliumPod check.Pod) []bpfEgressGatewayPolicyEntry,
) error {
	return waitForBpfPolicyEntriesWithEntryMatcher(ctx, t.Context().CiliumPods(), targetEntriesCallback, nil, nil)
}

func waitForBpfPolicyEntriesWithEntryMatcher(ctx context.Context,
	ciliumPods map[string]check.Pod,
	targetEntriesCallback func(ciliumPod check.Pod) []bpfEgressGatewayPolicyEntry,
	entryMatcher func(targetEntry, entry bpfEgressGatewayPolicyEntry) bool,
	excludeEntries func(ciliumPod check.Pod) ([]bpfEgressGatewayPolicyEntry, error),
) error {
	w := wait.NewObserver(ctx, wait.Parameters{Timeout: 10 * time.Second})
	defer w.Cancel()

	ensureBpfPolicyEntries := func() error {
		for _, ciliumPod := range ciliumPods {
			targetEntries := targetEntriesCallback(ciliumPod)

			cmd := strings.Split("cilium bpf egress-ha list -o json", " ")
			stdout, err := ciliumPod.K8sClient.ExecInPod(ctx, ciliumPod.Pod.Namespace, ciliumPod.Pod.Name, defaults.AgentContainerName, cmd)
			if err != nil {
				return fmt.Errorf("failed to run cilium bpf egress-ha list command: %w", err)
			}

			entries := []bpfEgressGatewayPolicyEntry{}
			json.Unmarshal(stdout.Bytes(), &entries)

			if excludeEntries != nil {
				excludes, err := excludeEntries(ciliumPod)
				if err != nil {
					return fmt.Errorf("failed to get exclude entries: %w", err)
				}
				for _, exclude := range excludes {
					entries = slices.DeleteFunc(entries, func(entry bpfEgressGatewayPolicyEntry) bool {
						return entry.matches(exclude)
					})
				}
			}

		nextTargetEntry:
			for _, targetEntry := range targetEntries {
				for _, entry := range entries {
					if entryMatcher != nil {
						if entryMatcher(targetEntry, entry) {
							continue nextTargetEntry
						}
					} else if targetEntry.matches(entry) {
						continue nextTargetEntry
					}
				}

				return fmt.Errorf("could not find egress gateway policy entry matching %+v on %s", targetEntry, ciliumPod.Name())
			}

		nextEntry:
			for _, entry := range entries {
				for _, targetEntry := range targetEntries {
					if entryMatcher != nil {
						if entryMatcher(targetEntry, entry) {
							continue nextEntry
						}
					} else if targetEntry.matches(entry) {
						continue nextEntry
					}
				}

				return fmt.Errorf("untracked entry %+v in the egress gateway policy map on %s", entry, ciliumPod.Name())
			}
		}

		return nil
	}

	for {
		if err := ensureBpfPolicyEntries(); err != nil {
			if err := w.Retry(err); err != nil {
				return fmt.Errorf("failed to ensure egress gateway policy map is properly populated: %w", err)
			}

			continue
		}

		return nil
	}
}

// waitForAllocatedEgressIP waits for the operator to allocate an egress IP to the gateway node identified by its IP.
// The allocated egress IP is looked for in the policy and egress group specified as input.
func waitForAllocatedEgressIP(ctx context.Context, t *check.Test, policyName string, egressGroup int, gatewayIP string) net.IP {
	ct := t.Context()
	iegpClient := ct.K8sClient().CiliumClientset.IsovalentV1().IsovalentEgressGatewayPolicies()

	w := wait.NewObserver(ctx, wait.Parameters{Timeout: 30 * time.Second})
	defer w.Cancel()

	ensureGroupEgressIP := func() (net.IP, error) {
		p, err := iegpClient.Get(ctx, policyName, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to get policy %s: %w", policyName, err)
		}
		if len(p.Status.GroupStatuses) <= egressGroup {
			return nil, fmt.Errorf("not enough egress group in policy %s, found %d", policyName, len(p.Status.GroupStatuses))
		}
		group := p.Status.GroupStatuses[egressGroup]
		masqueradeIP, found := group.EgressIPByGatewayIP[gatewayIP]
		if !found {
			return nil, fmt.Errorf("no egress ip allocated for gateway node with address %s in egressIPByGatewayIP map: %v", gatewayIP, group.EgressIPByGatewayIP)
		}

		return net.ParseIP(masqueradeIP), nil
	}

	for {
		masqueradeIP, err := ensureGroupEgressIP()
		if err != nil {
			if err := w.Retry(err); err != nil {
				t.Fatal("Failed to ensure egress IP allocation for active gateway:", err)
			}

			continue
		}

		return masqueradeIP
	}
}

func waitforGwNetworkConfig(ctx context.Context, t *check.Test, nodeEgressIPCallback func(ciliumPod check.Pod) *net.IP) {
	ct := t.Context()

	w := wait.NewObserver(ctx, wait.Parameters{Timeout: 10 * time.Second})
	defer w.Cancel()

	ensureNodeNetworkConfig := func() error {
		for _, ciliumPod := range ct.CiliumPods() {
			egressIP := nodeEgressIPCallback(ciliumPod)
			if egressIP == nil {
				// no egress IP assigned to this node
				continue
			}

			cmd := strings.Split("ip --json --family inet addr show", " ")
			stdout, err := ciliumPod.K8sClient.ExecInPod(ctx, ciliumPod.Pod.Namespace, ciliumPod.Pod.Name, defaults.AgentContainerName, cmd)
			if err != nil {
				t.Fatalf("failed to run ip addr show command: %s", err)
			}

			var addrEntries []ipAddrEntry
			if err := json.Unmarshal(stdout.Bytes(), &addrEntries); err != nil {
				t.Fatalf("failed to unmarshal ip addr show command output: %s", err)
			}

			var addrs []net.IP
			for _, entry := range addrEntries {
				for _, info := range entry.AddrInfo {
					addrs = append(addrs, net.ParseIP(info.Local))
				}
			}
			found := slices.ContainsFunc(addrs, func(addr net.IP) bool {
				return addr.Equal(*egressIP)
			})
			if !found {
				return fmt.Errorf("egress IP %s is not assigned to any interface in gateway node %s", egressIP, getGatewayNodeInternalIP(ct, ciliumPod.NodeName()))
			}

			if versioncheck.MustCompile("<1.19.0")(ct.CiliumVersion) {

				cmd = strings.Split(fmt.Sprintf("ip --json rule show table %d", EgressGatewayIPAMRoutingTable), " ")
				stdout, err = ciliumPod.K8sClient.ExecInPod(ctx, ciliumPod.Pod.Namespace, ciliumPod.Pod.Name, defaults.AgentContainerName, cmd)
				if err != nil {
					t.Fatalf("failed to run ip rule show command: %s", err)
				}

				var rules []ipRuleEntry
				if err := json.Unmarshal(stdout.Bytes(), &rules); err != nil {
					t.Fatalf("failed to unmarshal ip rule show command output: %s", err)
				}
				found = false
				for _, rule := range rules {
					if net.ParseIP(rule.Src).Equal(*egressIP) {
						found = true
						break
					}
				}
				if !found {
					return fmt.Errorf("no rule found for egress IP %s in gateway node %s", egressIP, getGatewayNodeInternalIP(ct, ciliumPod.NodeName()))
				}

				cmd = strings.Split(fmt.Sprintf("ip --json route show table %d", EgressGatewayIPAMRoutingTable), " ")
				stdout, err = ciliumPod.K8sClient.ExecInPod(ctx, ciliumPod.Pod.Namespace, ciliumPod.Pod.Name, defaults.AgentContainerName, cmd)
				if err != nil {
					t.Fatalf("failed to run ip route show command: %s", err)
				}

				var routes []ipRouteEntry
				if err := json.Unmarshal(stdout.Bytes(), &routes); err != nil {
					t.Fatalf("failed to unmarshal ip route show command output: %s", err)
				}
				found = false
				for _, route := range routes {
					if net.ParseIP(route.PrefSrc).Equal(*egressIP) {
						found = true
						break
					}
				}
				if !found {
					return fmt.Errorf("no route found for egress IP %s in gateway node %s", egressIP, getGatewayNodeInternalIP(ct, ciliumPod.NodeName()))
				}

			}
		}

		return nil
	}

	for {
		if err := ensureNodeNetworkConfig(); err != nil {
			if err := w.Retry(err); err != nil {
				t.Fatal("Failed to ensure egress gateway network configuration is properly setup:", err)
			}
			continue
		}
		return
	}
}

func curlRetryOptions() []string {
	opts := []string{
		"--retry", strconv.FormatInt(int64(Params.EgressGateway.Retry), 10),
		"--retry-all-errors",
	}
	if retryDelay := Params.EgressGateway.RetryDelay.Seconds(); retryDelay > 0.0 {
		opts = append(opts, "--retry-delay", strconv.FormatFloat(retryDelay, 'f', -1, 64))
	}
	return opts
}

// getGatewayNodeInternalIP returns the k8s internal IP of the node acting as gateway for this test
func getGatewayNodeInternalIP(ct *check.ConnectivityTest, egressGatewayNode string) net.IP {
	gatewayNode, ok := ct.Nodes()[egressGatewayNode]
	if !ok {
		return nil
	}

	for _, addr := range gatewayNode.Status.Addresses {
		if addr.Type != slimcorev1.NodeInternalIP {
			continue
		}

		ip := net.ParseIP(addr.Address)
		if ip == nil || ip.To4() == nil {
			continue
		}

		return ip
	}

	return nil
}

// splitJSonBlobs takes a string encoding multiple json blobs, for example:
//
//	{
//	"client-ip": "a"
//	}{
//	"client-ip": "b"
//	}
//
// and returns a slice of individual blobs:
//
//	[{"client-ip": "a"}, {"client-ip": "b"}]
func splitJsonBlobs(s string) []string {
	re := regexp.MustCompile("(?s)}.*?{")
	blobs := re.Split(s, -1)

	for i, blob := range blobs {
		blob = strings.TrimSpace(blob)
		if !strings.HasPrefix(blob, "{") {
			blob = "{" + blob
		}
		if !strings.HasSuffix(blob, "}") {
			blob = blob + "}"
		}
		blobs[i] = blob
	}

	return blobs
}

// extractClientIPFromResponses extracts the client IPs from a string containing multiple responses of the echo-external service
func extractClientIPsFromEchoServiceResponses(res string) []net.IP {
	var clientIP struct {
		ClientIP string `json:"client-ip"`
	}

	var clientIPs []net.IP

	blobs := splitJsonBlobs(res)

	for _, blob := range blobs {
		json.Unmarshal([]byte(blob), &clientIP)
		clientIPs = append(clientIPs, net.ParseIP(clientIP.ClientIP).To4())
	}

	return clientIPs
}

// EgressGateway is a test case which, given the iegp-sample-client IsovalentEgressGatewayPolicy targeting:
// - a couple of client pods (kind=client) as source
// - the 0.0.0.0/0 destination CIDR
// - kind-worker2 as gateway node
//
// and the iegp-sample-echo IsovalentEgressGatewayPolicy targeting:
// - the echo service pods (kind=echo) as source
// - the 0.0.0.0/0 destination CIDR
// - kind-worker2 as gateway node
//
// tests connectivity for:
// - pod to host traffic
// - pod to service traffic
// - pod to external IP traffic
// - reply traffic for services
// - reply traffic for pods
func EgressGatewayHA() check.Scenario {
	return &egressGatewayHA{
		ScenarioBase: check.NewScenarioBase(),
	}
}

type egressGatewayHA struct {
	check.ScenarioBase
}

func (s *egressGatewayHA) Name() string {
	return "egress-gateway-ha"
}

func (s *egressGatewayHA) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()

	egressGatewayNode := t.EgressGatewayNode()
	if egressGatewayNode == "" {
		t.Fatal("Cannot get egress gateway node")
	}

	egressGatewayNodeInternalIP := getGatewayNodeInternalIP(ct, egressGatewayNode)
	if egressGatewayNodeInternalIP == nil {
		t.Fatal("Cannot get egress gateway node internal IP")
	}

	if err := waitForBpfPolicyEntries(ctx, t, func(ciliumPod check.Pod) []bpfEgressGatewayPolicyEntry {
		targetEntries := []bpfEgressGatewayPolicyEntry{}

		egressIP := "0.0.0.0"
		if ciliumPod.Pod.Spec.NodeName == egressGatewayNode {
			egressIP = egressGatewayNodeInternalIP.String()
		}

		for _, client := range ct.ClientPods() {
			targetEntries = append(targetEntries,
				bpfEgressGatewayPolicyEntry{
					SourceIP:   client.Pod.Status.PodIP,
					DestCIDR:   "0.0.0.0/0",
					EgressIP:   egressIP,
					GatewayIPs: []string{egressGatewayNodeInternalIP.String()},
				})
		}

		for _, echo := range ct.EchoPods() {
			targetEntries = append(targetEntries,
				bpfEgressGatewayPolicyEntry{
					SourceIP:   echo.Pod.Status.PodIP,
					DestCIDR:   "0.0.0.0/0",
					EgressIP:   egressIP,
					GatewayIPs: []string{egressGatewayNodeInternalIP.String()},
				})
		}

		return targetEntries
	}); err != nil {
		t.Fatalf("%v", err)
	}

	// Ping hosts (pod to host connectivity). Should not get masqueraded with egress IP
	i := 0
	for _, client := range ct.ClientPods() {
		for _, dst := range ct.HostNetNSPodsByNode() {
			t.NewAction(s, fmt.Sprintf("ping-%d", i), &client, &dst, features.IPFamilyV4).Run(func(a *check.Action) {
				a.ExecInPod(ctx, ct.PingCommand(dst, features.IPFamilyV4))
			})
			i++
		}
	}

	// DNS query (pod to service connectivity). Should not get masqueraded with egress IP
	i = 0
	for _, client := range ct.ClientPods() {
		kubeDNSService, err := ct.K8sClient().GetService(ctx, "kube-system", "kube-dns", metav1.GetOptions{})
		if err != nil {
			t.Fatal("Cannot get kube-dns service")
		}
		kubeDNSServicePeer := check.Service{Service: kubeDNSService}

		t.NewAction(s, fmt.Sprintf("dig-%d", i), &client, kubeDNSServicePeer, features.IPFamilyV4).Run(func(a *check.Action) {
			a.ExecInPod(ctx, ct.DigCommand(kubeDNSServicePeer, features.IPFamilyV4))
		})
		i++
	}

	// Traffic matching an egress gateway policy should leave the cluster masqueraded with the egress IP (pod to external service using DNS)
	i = 0
	for _, client := range ct.ClientPods() {
		for _, externalEchoSvc := range ct.EchoExternalServices() {
			externalEcho := externalEchoSvc.ToEchoIPService()

			t.NewAction(s, fmt.Sprintf("curl-external-echo-service-%d", i), &client, externalEcho, features.IPFamilyV4).Run(func(a *check.Action) {
				a.ExecInPod(ctx, ct.CurlCommandWithOutput(externalEcho, features.IPFamilyV4, true, nil))
				clientIPs := extractClientIPsFromEchoServiceResponses(a.CmdOutput())

				for _, clientIP := range clientIPs {
					if !clientIP.Equal(egressGatewayNodeInternalIP) {
						a.Fatal("Request reached external echo service with wrong source IP")
					}
				}
			})
			i++
		}
	}

	// Traffic matching an egress gateway policy should leave the cluster masqueraded with the egress IP (pod to external service)
	i = 0
	for _, client := range ct.ClientPods() {
		for _, externalEcho := range ct.ExternalEchoPods() {
			externalEcho := externalEcho.ToEchoIPPod()

			t.NewAction(s, fmt.Sprintf("curl-external-echo-pod-%d", i), &client, externalEcho, features.IPFamilyV4).Run(func(a *check.Action) {
				a.ExecInPod(ctx, ct.CurlCommandWithOutput(externalEcho, features.IPFamilyV4, true, nil))
				clientIPs := extractClientIPsFromEchoServiceResponses(a.CmdOutput())

				for _, clientIP := range clientIPs {
					if !clientIP.Equal(egressGatewayNodeInternalIP) {
						a.Fatal("Request reached external echo service with wrong source IP")
					}
				}
			})
			i++
		}
	}

	// When connecting from outside the cluster to a nodeport service whose pods are selected by an egress policy,
	// the reply traffic should not be SNATed with the egress IP
	i = 0
	for _, client := range ct.ExternalEchoPods() {
		for _, node := range ct.Nodes() {
			for _, echo := range ct.EchoServices() {
				// convert the service to a ServiceExternalIP as we want to access it through its external IP
				echo := echo.ToNodeportService(node)

				t.NewAction(s, fmt.Sprintf("curl-echo-service-%d", i), &client, echo, features.IPFamilyV4).Run(func(a *check.Action) {
					a.ExecInPod(ctx, ct.CurlCommand(echo, features.IPFamilyV4, true, nil))
				})
				i++
			}
		}
	}

	if status, ok := ct.Feature(features.Tunnel); ok && !status.Enabled {
		// When connecting from outside the cluster directly to a pod which is selected by an egress policy, the
		// reply traffic should not be SNATed with the egress IP (only connections originating from these pods
		// should go through egress gateway).
		//
		// This test is executed only when Cilium is running in direct routing mode, since we can simply add a
		// route on the node that doesn't run Cilium to direct pod's traffic to the node where the pod is
		// running (while in tunneling mode we would need the external node to send the traffic over the tunnel)
		i = 0
		for _, client := range ct.ExternalEchoPods() {
			for _, echo := range ct.EchoPods() {
				t.NewAction(s, fmt.Sprintf("curl-echo-pod-%d", i), &client, echo, features.IPFamilyV4).Run(func(a *check.Action) {
					a.ExecInPod(ctx, ct.CurlCommand(echo, features.IPFamilyV4, true, nil))
				})
				i++
			}
		}
	}
}

// EgressGatewayExcludedCIDRs is a test case which, given the iegp-sample IsovalentEgressGatewayPolicy targeting:
// - a couple of client pods (kind=client) as source
// - the 0.0.0.0/0 destination CIDR
// - the IP of the external node as excluded CIDR
// - kind-worker2 as gateway node
//
// This suite tests the excludedCIDRs property and ensure traffic matching an excluded CIDR does not get masqueraded with the egress IP.
func EgressGatewayExcludedCIDRs() check.Scenario {
	return &egressGatewayExcludedCIDRs{
		ScenarioBase: check.NewScenarioBase(),
	}
}

type egressGatewayExcludedCIDRs struct {
	check.ScenarioBase
}

func (s *egressGatewayExcludedCIDRs) Name() string {
	return "egress-gateway-excluded-cidrs"
}

func (s *egressGatewayExcludedCIDRs) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()

	egressGatewayNode := t.EgressGatewayNode()
	if egressGatewayNode == "" {
		t.Fatal("Cannot get egress gateway node")
	}

	egressGatewayNodeInternalIP := getGatewayNodeInternalIP(ct, egressGatewayNode)
	if egressGatewayNodeInternalIP == nil {
		t.Fatal("Cannot get egress gateway node internal IP")
	}

	if err := waitForBpfPolicyEntries(ctx, t, func(ciliumPod check.Pod) []bpfEgressGatewayPolicyEntry {
		targetEntries := []bpfEgressGatewayPolicyEntry{}

		egressIP := "0.0.0.0"
		if ciliumPod.Pod.Spec.NodeName == egressGatewayNode {
			egressIP = egressGatewayNodeInternalIP.String()
		}

		for _, client := range ct.ClientPods() {
			for _, nodeWithoutCiliumName := range t.NodesWithoutCilium() {
				nodeWithoutCilium, err := ciliumPod.K8sClient.GetNode(context.Background(), nodeWithoutCiliumName, metav1.GetOptions{})
				if err != nil {
					if k8sErrors.IsNotFound(err) {
						continue
					}

					t.Fatalf("Cannot retrieve external node")
				}

				targetEntries = append(targetEntries,
					bpfEgressGatewayPolicyEntry{
						SourceIP:   client.Pod.Status.PodIP,
						DestCIDR:   "0.0.0.0/0",
						EgressIP:   egressIP,
						GatewayIPs: []string{egressGatewayNodeInternalIP.String()},
					})

				targetEntries = append(targetEntries,
					bpfEgressGatewayPolicyEntry{
						SourceIP:   client.Pod.Status.PodIP,
						DestCIDR:   fmt.Sprintf("%s/32", nodeWithoutCilium.Status.Addresses[0].Address),
						EgressIP:   egressIP,
						GatewayIPs: []string{"Excluded CIDR"},
					})
			}
		}

		return targetEntries
	}); err != nil {
		t.Fatalf("%v", err)
	}

	// Traffic matching an egress gateway policy and an excluded CIDR should leave the cluster masqueraded with the
	// node IP where the pod is running rather than with the egress IP(pod to external service)
	i := 0
	for _, client := range ct.ClientPods() {
		for _, externalEcho := range ct.ExternalEchoPods() {
			externalEcho := externalEcho.ToEchoIPPod()

			t.NewAction(s, fmt.Sprintf("curl-%d", i), &client, externalEcho, features.IPFamilyV4).Run(func(a *check.Action) {
				a.ExecInPod(ctx, ct.CurlCommandParallelWithOutput(externalEcho, features.IPFamilyV4, 10))
				clientIPs := extractClientIPsFromEchoServiceResponses(a.CmdOutput())

				for _, clientIP := range clientIPs {
					if !clientIP.Equal(net.ParseIP(client.Pod.Status.HostIP)) {
						a.Fatal("Request reached external echo service with wrong source IP")
					}
				}
			})
			i++
		}
	}
}

// EgressGatewayMultipleGateways is a test case which, given the iegp-sample IsovalentEgressGatewayPolicy targeting:
// - a couple of client pods (kind=client) as source
// - the 0.0.0.0/0 destination CIDR
// - the IP of the external node as excluded CIDR
// - nodes with the egress-group=test label as gateways (usually kind-control-plane, kind-worker and kind-worker3)
//
// tests that requests from the kind=client pods are redirected to _all_ gateways of the egressGroup
func EgressGatewayMultipleGateways() check.Scenario {
	return &egressGatewayMultipleGateways{
		ScenarioBase: check.NewScenarioBase(),
	}
}

type egressGatewayMultipleGateways struct {
	check.ScenarioBase
}

func (s *egressGatewayMultipleGateways) Name() string {
	return "egress-gateway-multiple-gateway"
}

func (s *egressGatewayMultipleGateways) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()

	// apply the egress-group=test label to all the nodes running Cilium and build a gatewayNodeName -> egressIP mapping for all such nodes
	gatewayIPsToNames := map[string]string{}
	addNodeLabelPatch := fmt.Sprintf(`[{"op":"add","path":"/metadata/labels/%s","value":"%s"}]`, EgressGroupLabelKey, EgressGroupLabelValue)
	for _, node := range ct.Nodes() {
		if _, ok := node.GetLabels()[defaults.CiliumNoScheduleLabel]; ok {
			continue
		}

		if _, err := ct.K8sClient().PatchNode(ctx, node.Name, types.JSONPatchType, []byte(addNodeLabelPatch)); err != nil {
			t.Fatalf("cannot add %s=%s label to node %s: %w", EgressGroupLabelKey, EgressGroupLabelValue, node.Name, err)
		}

		gatewayIP := getGatewayNodeInternalIP(ct, node.Name)
		if gatewayIP == nil {
			t.Fatal("Cannot get egress gateway node internal IP")
		}

		gatewayIPsToNames[gatewayIP.String()] = node.Name
	}

	// remove the labels after the test is done
	t.WithFinalizer(func(_ context.Context) error {
		return finalizeForMultipleGatewaysScenario(ctx, t, false)
	})

	// wait for the policy map to be populated
	if err := waitForBpfPolicyEntries(ctx, t, func(ciliumPod check.Pod) []bpfEgressGatewayPolicyEntry {
		return getTargetEntriesForMultipleGateways(t, ciliumPod, gatewayIPsToNames, nil)
	}); err != nil {
		t.Fatalf("%v", err)
	}

	// run the test
	i := 0
	responsesByClientIP := map[string]int{}

	// Traffic matching an egress gateway policy should leave the cluster masqueraded with the egress IP of one of the multiple GWs (pod to external service using DNS)
	for _, client := range ct.ClientPods() {
		for _, externalEchoSvc := range ct.EchoExternalServices() {
			externalEcho := externalEchoSvc.ToEchoIPService()

			t.NewAction(s, fmt.Sprintf("curl-external-echo-service-%d", i), &client, externalEcho, features.IPFamilyV4).Run(func(a *check.Action) {
				a.ExecInPod(ctx, ct.CurlCommandParallelWithOutput(externalEcho, features.IPFamilyV4, 100, "-4"))
				clientIPs := extractClientIPsFromEchoServiceResponses(a.CmdOutput())

				for _, clientIP := range clientIPs {
					responsesByClientIP[clientIP.String()]++
				}
			})
			i++
		}
	}

	// all client IPs should be egress IPs
	for clientIP := range responsesByClientIP {
		if _, ok := gatewayIPsToNames[clientIP]; !ok {
			t.Fatalf("Request reached external echo service with wrong source IP %s", clientIP)
		}
	}

	// and traffic should go through all gateways
	for gatewayIP := range gatewayIPsToNames {
		if _, ok := responsesByClientIP[gatewayIP]; !ok {
			t.Fatalf("No request has gone through gateway %s", gatewayIP)
		}
	}

	// Traffic matching an egress gateway policy should leave the cluster masqueraded with the egress IP of one of the multiple GWs (pod to external service)
	i = 0
	responsesByClientIP = map[string]int{}
	for _, client := range ct.ClientPods() {
		for _, externalEcho := range ct.ExternalEchoPods() {
			externalEcho := externalEcho.ToEchoIPPod()

			t.NewAction(s, fmt.Sprintf("curl-external-echo-pod-%d", i), &client, externalEcho, features.IPFamilyV4).Run(func(a *check.Action) {
				a.ExecInPod(ctx, ct.CurlCommandParallelWithOutput(externalEcho, features.IPFamilyV4, 100))
				clientIPs := extractClientIPsFromEchoServiceResponses(a.CmdOutput())

				for _, clientIP := range clientIPs {
					responsesByClientIP[clientIP.String()]++
				}
			})
		}
		i++
	}

	// all client IPs should be egress IPs
	for clientIP := range responsesByClientIP {
		if _, ok := gatewayIPsToNames[clientIP]; !ok {
			t.Fatalf("Request reached external echo service with wrong source IP %s", clientIP)
		}
	}

	// and traffic should go through all gateways
	for gatewayIP := range gatewayIPsToNames {
		if _, ok := responsesByClientIP[gatewayIP]; !ok {
			t.Fatalf("No request has gone through gateway %s", gatewayIP)
		}
	}
}

// EgressGatewayAZAffinity is a test case which, given the iegp-sample IsovalentEgressGatewayPolicy targeting:
// - three client pods (kind=client) as source, in 2 different AZ
// - the 0.0.0.0/0 destination CIDR
// - nodes with the egress-group=test label as gateways (usually kind-control-plane, kind-worker and kind-worker3)
//
// tests that requests from the kind=client pods are redirected only to the "local" (i.e. same AZ) gateway as the source pod
func EgressGatewayAZAffinity(clients []*enterpriseK8s.EnterpriseClient) check.Scenario {
	return &egressGatewayAZAffinity{
		ScenarioBase: check.NewScenarioBase(),
		entClients:   clients,
	}
}

type egressGatewayAZAffinity struct {
	check.ScenarioBase
	entClients []*enterpriseK8s.EnterpriseClient
}

func (s *egressGatewayAZAffinity) Name() string {
	return "egress-gateway-az-affinity"
}

func (s *egressGatewayAZAffinity) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()
	gatewayIPsToNames := map[string]string{}

	// apply the AZ label to all nodes
	for nodeName, node := range ct.Nodes() {
		if _, ok := node.GetLabels()[defaults.CiliumNoScheduleLabel]; ok {
			continue
		}

		addNodeLabelPatch := fmt.Sprintf(`[{"op":"add","path":"/metadata/labels/%s","value":"%s"}]`,
			escapePatchString(K8sZoneLabel), fmt.Sprintf("zone-%s", nodeName))
		if _, err := ct.K8sClient().PatchNode(ctx, node.Name, types.JSONPatchType, []byte(addNodeLabelPatch)); err != nil {
			t.Fatalf("cannot add label to node %s: %s", node.Name, err)
		}

		addNodeLabelPatch = fmt.Sprintf(`[{"op":"add","path":"/metadata/labels/%s","value":"%s"}]`, EgressGroupLabelKey, EgressGroupLabelValue)
		if _, err := ct.K8sClient().PatchNode(ctx, node.Name, types.JSONPatchType, []byte(addNodeLabelPatch)); err != nil {
			t.Fatalf("cannot add %s=%s label to node %s: %w", EgressGroupLabelKey, EgressGroupLabelValue, node.Name, err)
		}

		gatewayIP := getGatewayNodeInternalIP(ct, node.Name)
		if gatewayIP == nil {
			t.Fatal("Cannot get egress gateway node internal IP")
		}

		gatewayIPsToNames[gatewayIP.String()] = node.Name
	}

	iegpName := "iegp-sample-client-az-affinity"

	// remove the labels after the test is done
	t.WithFinalizer(func(_ context.Context) error {
		if err := s.updateAZAffinity(ctx, iegpName, "disabled"); err == nil {
			if err := waitForBpfPolicyEntries(ctx, t, func(ciliumPod check.Pod) []bpfEgressGatewayPolicyEntry {
				return getTargetEntriesForMultipleGateways(t, ciliumPod, gatewayIPsToNames, nil)
			}); err != nil {
				return err
			}
		}

		return finalizeForMultipleGatewaysScenario(ctx, t, true)
	})

	// Before configuring AZAffinity, we wait for the operator to select Gateway nodes labeled with topology.kubernetes.io/zone,
	// and for the agent to reference them and populate the Policy map. This helps prevent error logs missing node AZs from appearing.
	if err := waitForBpfPolicyEntries(ctx, t, func(ciliumPod check.Pod) []bpfEgressGatewayPolicyEntry {
		return getTargetEntriesForMultipleGateways(t, ciliumPod, gatewayIPsToNames, nil)
	}); err != nil {
		t.Fatalf("%v", err)
	}

	// we are only e2e testing the localOnly mode for now.
	// Other configurations are already thoroughly tested in unit tests and would require additional nodes
	if err := s.updateAZAffinity(ctx, iegpName, "localOnly"); err != nil {
		t.Fatalf("cannot enable azAffinity %s: %s", iegpName, err)
	}

	// wait for the policy map to be populated
	if err := waitForBpfPolicyEntriesWithEntryMatcher(ctx, ct.CiliumPods(), func(ciliumPod check.Pod) []bpfEgressGatewayPolicyEntry {
		targetEntries := []bpfEgressGatewayPolicyEntry{}

		for _, client := range ct.ClientPods() {
			egressIP := getGatewayNodeInternalIP(ct, ciliumPod.Pod.Spec.NodeName).String()
			egressGatewayNodeInternalIPs := []string{
				getGatewayNodeInternalIP(ct, client.Pod.Spec.NodeName).String(),
			}

			targetEntries = append(targetEntries, bpfEgressGatewayPolicyEntry{
				SourceIP:   client.Pod.Status.PodIP,
				DestCIDR:   "0.0.0.0/0",
				EgressIP:   egressIP,
				GatewayIPs: egressGatewayNodeInternalIPs,
			})
		}

		return targetEntries
	}, func(targetEntry, entry bpfEgressGatewayPolicyEntry) bool {
		sort.Strings(targetEntry.GatewayIPs)
		sort.Strings(entry.GatewayIPs)

		return targetEntry.SourceIP == entry.SourceIP &&
			targetEntry.DestCIDR == entry.DestCIDR &&
			// In the version >= 1.18.0, a gateway node retains the egress IP as long as it exists in the healthy
			// gateway list, regardless of the endpoint's AZ. This is because it must continue handling existing
			// connections even after being removed from the active gateway list and may receive traffic from a different
			// AZ depending on the AZ mode.
			// The egressIP allows both the node IP and 0.0.0.0 to support both the new and old versions.
			(targetEntry.EgressIP == entry.EgressIP || entry.EgressIP == "0.0.0.0") &&
			cmp.Equal(targetEntry.GatewayIPs, entry.GatewayIPs, cmpopts.EquateEmpty())
	}, nil); err != nil {
		t.Fatalf("%v", err)
	}

	// run the test
	i := 0
	for _, client := range ct.ClientPods() {
		for _, externalEcho := range ct.ExternalEchoPods() {
			externalEcho := externalEcho.ToEchoIPPod()

			t.NewAction(s, fmt.Sprintf("curl-external-echo-pod-%d", i), &client, externalEcho, features.IPFamilyV4).Run(func(a *check.Action) {
				a.ExecInPod(ctx, ct.CurlCommandParallelWithOutput(externalEcho, features.IPFamilyV4, 100))
				clientIPs := extractClientIPsFromEchoServiceResponses(a.CmdOutput())

				for _, clientIP := range clientIPs {
					if !clientIP.Equal(getGatewayNodeInternalIP(ct, client.Pod.Spec.NodeName)) {
						a.Fatal("Request reached external echo service with wrong source IP")
					}
				}
			})
		}
		i++
	}
}

func escapePatchString(str string) string {
	// From https://www.rfc-editor.org/rfc/rfc6901#section-3:
	// Because the characters '~' (%x7E) and '/' (%x2F) have special meanings in JSON Pointer,
	// '~' needs to be encoded as '~0' and '/' needs to be encoded as '~1' when these characters
	// appear in a reference token.
	str = strings.ReplaceAll(str, "~", "~0")
	str = strings.ReplaceAll(str, "/", "~1")
	return str
}

func (s *egressGatewayAZAffinity) updateAZAffinity(ctx context.Context, iegpName, azAffinity string) error {
	for _, entClient := range s.entClients {
		if _, err := entClient.PatchIsovalentEgressGatewayPolicy(ctx, iegpName, types.JSONPatchType,
			fmt.Appendf(nil, `[{"op": "replace", "path": "/spec/azAffinity", "value": "%s"}]`, azAffinity)); err != nil {
			return err
		}
	}
	return nil
}

func EgressGatewayHAIPAM() check.Scenario {
	return &egressGatewayHAIPAM{
		ScenarioBase: check.NewScenarioBase(),
	}
}

type egressGatewayHAIPAM struct {
	check.ScenarioBase
}

func (s *egressGatewayHAIPAM) Name() string {
	return "egress-gateway-ha-ipam"
}

func (s *egressGatewayHAIPAM) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()

	egressGatewayNode := t.EgressGatewayNode()
	if egressGatewayNode == "" {
		t.Fatal("Cannot get egress gateway node")
	}

	egressGatewayNodeInternalIP := getGatewayNodeInternalIP(ct, egressGatewayNode)
	if egressGatewayNodeInternalIP == nil {
		t.Fatal("Cannot get egress gateway node internal IP")
	}

	policyName := "iegp-sample-client"

	masqueradeIP := waitForAllocatedEgressIP(ctx, t, policyName, 0, egressGatewayNodeInternalIP.String())

	if err := waitForBpfPolicyEntries(ctx, t, func(ciliumPod check.Pod) []bpfEgressGatewayPolicyEntry {
		targetEntries := []bpfEgressGatewayPolicyEntry{}

		egressIP := "0.0.0.0"
		if ciliumPod.Pod.Spec.NodeName == egressGatewayNode {
			egressIP = masqueradeIP.String()
		}

		for _, client := range ct.ClientPods() {
			targetEntries = append(targetEntries,
				bpfEgressGatewayPolicyEntry{
					SourceIP:   client.Pod.Status.PodIP,
					DestCIDR:   "0.0.0.0/0",
					EgressIP:   egressIP,
					GatewayIPs: []string{egressGatewayNodeInternalIP.String()},
				})
		}

		return targetEntries
	}); err != nil {
		t.Fatalf("%v", err)
	}

	waitforGwNetworkConfig(ctx, t, func(ciliumPod check.Pod) *net.IP {
		if ciliumPod.NodeName() != egressGatewayNode {
			return nil
		}
		return &masqueradeIP
	})

	// Traffic matching an egress gateway policy should leave the cluster masqueraded with the egress IP (pod to external service)
	i := 0
	for _, client := range ct.ClientPods() {
		for _, externalEcho := range ct.ExternalEchoPods() {
			externalEcho := externalEcho.ToEchoIPPod()

			t.NewAction(s, fmt.Sprintf("curl-external-echo-pod-%d", i), &client, externalEcho, features.IPFamilyV4).Run(func(a *check.Action) {
				a.ExecInPod(ctx, ct.CurlCommandWithOutput(externalEcho, features.IPFamilyV4, true, curlRetryOptions()))
				clientIPs := extractClientIPsFromEchoServiceResponses(a.CmdOutput())

				for _, clientIP := range clientIPs {
					if !clientIP.Equal(masqueradeIP) {
						a.Fatal("Request reached external echo service with wrong source IP")
					}
				}
			})
			i++
		}
	}
}

func EgressGatewayHAIPAMMultipleGateways() check.Scenario {
	return &egressGatewayHAIPAMMultipleGateways{
		ScenarioBase: check.NewScenarioBase(),
	}
}

type egressGatewayHAIPAMMultipleGateways struct {
	check.ScenarioBase
}

func (s *egressGatewayHAIPAMMultipleGateways) Name() string {
	return "egress-gateway-ha-ipam-multiple-gateways"
}

func (s *egressGatewayHAIPAMMultipleGateways) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()

	// apply the egress-group=test label to all the nodes running Cilium and build a gatewayNodeName -> egressIP mapping for all such nodes
	gatewayIPsToNames := map[string]string{}
	addNodeLabelPatch := fmt.Sprintf(`[{"op":"add","path":"/metadata/labels/%s","value":"%s"}]`, EgressGroupLabelKey, EgressGroupLabelValue)
	for _, node := range ct.Nodes() {
		if _, ok := node.GetLabels()[defaults.CiliumNoScheduleLabel]; ok {
			continue
		}

		if _, err := ct.K8sClient().PatchNode(ctx, node.Name, types.JSONPatchType, []byte(addNodeLabelPatch)); err != nil {
			t.Fatalf("cannot add %s=%s label to node %s: %w", EgressGroupLabelKey, EgressGroupLabelValue, node.Name, err)
		}

		gatewayIP := getGatewayNodeInternalIP(ct, node.Name)
		if gatewayIP == nil {
			t.Fatal("Cannot get egress gateway node internal IP")
		}

		gatewayIPsToNames[gatewayIP.String()] = node.Name
	}

	// remove the labels after the test is done
	t.WithFinalizer(func(_ context.Context) error {
		return finalizeForMultipleGatewaysScenario(ctx, t, false)
	})

	policyName := "iegp-sample-client"

	gatewayIPsToMasqueradeIPs := make(map[string]net.IP, len(gatewayIPsToNames))
	masqueradeIPs := make([]string, 0, len(gatewayIPsToNames))
	for gatewayIP := range gatewayIPsToNames {
		masqueradeIP := waitForAllocatedEgressIP(ctx, t, policyName, 0, gatewayIP)
		masqueradeIPs = append(masqueradeIPs, masqueradeIP.String())
		gatewayIPsToMasqueradeIPs[gatewayIP] = masqueradeIP
	}

	// wait for the policy map to be populated
	if err := waitForBpfPolicyEntries(ctx, t, func(ciliumPod check.Pod) []bpfEgressGatewayPolicyEntry {
		return getTargetEntriesForMultipleGateways(t, ciliumPod, gatewayIPsToNames, gatewayIPsToMasqueradeIPs)
	}); err != nil {
		t.Fatalf("%v", err)
	}

	waitforGwNetworkConfig(ctx, t, func(ciliumPod check.Pod) *net.IP {
		for gatewayIP, nodeName := range gatewayIPsToNames {
			if ciliumPod.Pod.Spec.NodeName == nodeName {
				masqueradeIP := gatewayIPsToMasqueradeIPs[gatewayIP]
				return &masqueradeIP
			}
		}
		return nil
	})

	// run the test
	i := 0
	responsesByClientIP := map[string]int{}

	// Traffic matching an egress gateway policy should leave the cluster masqueraded with the egress IP of one of the multiple GWs (pod to external service using DNS)
	for _, client := range ct.ClientPods() {
		for _, externalEchoSvc := range ct.EchoExternalServices() {
			externalEcho := externalEchoSvc.ToEchoIPService()

			t.NewAction(s, fmt.Sprintf("curl-external-echo-service-%d", i), &client, externalEcho, features.IPFamilyV4).Run(func(a *check.Action) {
				curlOpts := append(curlRetryOptions(), "-4")
				a.ExecInPod(ctx, ct.CurlCommandParallelWithOutput(externalEcho, features.IPFamilyV4, 100, curlOpts...))
				clientIPs := extractClientIPsFromEchoServiceResponses(a.CmdOutput())

				for _, clientIP := range clientIPs {
					responsesByClientIP[clientIP.String()]++
				}
			})
			i++
		}
	}

	// all client IPs should be egress IPs
	for clientIP := range responsesByClientIP {
		if !slices.Contains(masqueradeIPs, clientIP) {
			t.Fatalf("Request reached external echo service with wrong source IP %s", clientIP)
		}
	}

	// and traffic should go through all gateways, masqueraded with theirs egress IPs
	for _, egressIP := range masqueradeIPs {
		if _, ok := responsesByClientIP[egressIP]; !ok {
			t.Fatalf("No request has gone through gateway with egress IP %s", egressIP)
		}
	}

	// Traffic matching an egress gateway policy should leave the cluster masqueraded with the egress IP of one of the multiple GWs (pod to external service)
	i = 0
	responsesByClientIP = map[string]int{}
	for _, client := range ct.ClientPods() {
		for _, externalEcho := range ct.ExternalEchoPods() {
			externalEcho := externalEcho.ToEchoIPPod()

			t.NewAction(s, fmt.Sprintf("curl-external-echo-pod-%d", i), &client, externalEcho, features.IPFamilyV4).Run(func(a *check.Action) {
				a.ExecInPod(ctx, ct.CurlCommandParallelWithOutput(externalEcho, features.IPFamilyV4, 100, curlRetryOptions()...))
				clientIPs := extractClientIPsFromEchoServiceResponses(a.CmdOutput())

				for _, clientIP := range clientIPs {
					responsesByClientIP[clientIP.String()]++
				}
			})
		}
		i++
	}

	// all client IPs should be egress IPs
	for clientIP := range responsesByClientIP {
		if !slices.Contains(masqueradeIPs, clientIP) {
			t.Fatalf("Request reached external echo service with wrong source IP %s", clientIP)
		}
	}

	// and traffic should go through all gateways, masqueraded with theirs egress IPs
	for _, egressIP := range masqueradeIPs {
		if _, ok := responsesByClientIP[egressIP]; !ok {
			t.Fatalf("No request has gone through gateway with egress IP %s", egressIP)
		}
	}
}

// IPAMEgressCIDRs returns the IPv4 egress CIDRs to be used in IsovalentEgressGatewayPolicy for IPAM.
// First, it looks for user-specified CIDRs. If there aren't any, it tries to auto-detect the
// native routing CIDR from the local address and mask of the interface managing the default route.
// Then the egress CIDR to use is calculated as a subset of the native routing CIDR.
// In case of error, it returns a nil slice.
func IPAMEgressCIDRs(ctx context.Context, t *check.Test, ct *check.ConnectivityTest) []string {
	// user-specified CIDRs take precedence
	if len(Params.EgressGateway.CIDRs) != 0 {
		return Params.EgressGateway.CIDRs
	}

	// detect native routing CIDR or fallback to default values in case of error
	nativeCIDR, err := nativeRoutingCIDR(ctx, ct)
	if err != nil {
		t.Logf("Failed to get native routing CIDR: %s", err)
		return nil
	}
	t.Logf("Detected native routing CIDR %s", nativeCIDR.String())

	egressCIDR, err := egressCIDRFromNative(nativeCIDR)
	if err != nil {
		t.Logf("Failed to reserve an egress CIDR from native routing CIDR: %s", err)
		return nil
	}

	return []string{egressCIDR.String()}
}

func nativeRoutingCIDR(ctx context.Context, ct *check.ConnectivityTest) (netip.Prefix, error) {
	var ciliumPod *check.Pod
	for _, pod := range ct.CiliumPods() {
		ciliumPod = &pod
	}
	if ciliumPod == nil {
		return netip.Prefix{}, errors.New("unable to find any Cilium pod")
	}

	// get iface managing default route
	cmd := []string{"/bin/sh", "-c", "ip --family inet --json route show default | jq -j -r '.[0].dev'"}
	stdout, err := ct.K8sClient().ExecInPod(ctx, ciliumPod.Pod.Namespace, ciliumPod.Pod.Name, defaults.AgentContainerName, cmd)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("failed to get interface managing default route: %w", err)
	}
	iface := strings.TrimSpace(stdout.String())

	// get iface local address
	cmd = []string{"/bin/sh", "-c", fmt.Sprintf("ip --family inet --json addr show %s | jq -j -r '.[0].addr_info[0].local'", iface)}
	stdout, err = ct.K8sClient().ExecInPod(ctx, ciliumPod.Pod.Namespace, ciliumPod.Pod.Name, defaults.AgentContainerName, cmd)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("failed to get interface %s address: %w", iface, err)
	}
	addr := stdout.String()

	// get iface local address mask bitlen
	cmd = []string{"/bin/sh", "-c", fmt.Sprintf("ip --family inet --json addr show %s | jq -j -r '.[0].addr_info[0].prefixlen'", iface)}
	stdout, err = ct.K8sClient().ExecInPod(ctx, ciliumPod.Pod.Namespace, ciliumPod.Pod.Name, defaults.AgentContainerName, cmd)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("failed to get interface %s mask bitlen: %w", iface, err)
	}
	bits := stdout.String()

	prefix, err := netip.ParsePrefix(fmt.Sprintf("%s/%s", addr, bits))
	if err != nil {
		return netip.Prefix{}, err
	}

	return prefix.Masked(), nil
}

func egressCIDRFromNative(nativeCIDR netip.Prefix) (netip.Prefix, error) {
	notEnoughAddrs := errors.New("not enough addresses in native routing CIDR")

	if nativeCIDR.Bits() >= 30 {
		return netip.Prefix{}, notEnoughAddrs
	}

	bitlen := nativeCIDR.Bits()
	if bitlen > 28 {
		// for egwha IPAM tests we need at least a total of 7 addresses:
		// - 4 address for the kind cluster
		//   - 1 controlplane node
		//   - 2 worker nodes
		//   - 1 worker node without Cilium
		// - 3 addresses to be allocated through IPAM to each node managed by Cilium
		//
		// Moreover, we have to consider that the addresses allocation for the cluster does not
		// start with the first available IP (as an example, for a kind cluster the first IP used
		// for a node is usually 172.18.0.2, taken from a native routing CIDR equal to 172.18.0.0/16).
		//
		// Therefore, in order to extract an egress CIDR wide enough to fulfill the allocations needed
		// for the tests, while not overlapping with the initial allocations for the nodes, we require
		// at least a "/28" CIDR.
		return netip.Prefix{}, notEnoughAddrs
	}

	// avoid using the first 8 addresses in the native routing CIDR as
	// they might be already used for the nodes.
	first := nativeCIDR.Addr()
	for range 8 {
		first = first.Next()
	}
	if !first.IsValid() {
		return netip.Prefix{}, notEnoughAddrs
	}

	return netip.PrefixFrom(first, 30), nil
}

func getTargetEntriesForMultipleGateways(t *check.Test, ciliumPod check.Pod, gatewayIPsToNames map[string]string, gatewayIPsToMasqueradeIPs map[string]net.IP) []bpfEgressGatewayPolicyEntry {
	ct := t.Context()

	egressIP := "0.0.0.0"
	var egressGatewayNodeInternalIPs []string

	for gatewayIP, nodeName := range gatewayIPsToNames {
		if ciliumPod.Pod.Spec.NodeName == nodeName {
			egressIP = gatewayIP
			if gatewayIPsToMasqueradeIPs != nil {
				egressIP = gatewayIPsToMasqueradeIPs[gatewayIP].String()
			}
		}
		egressGatewayNodeInternalIPs = append(egressGatewayNodeInternalIPs, gatewayIP)
	}

	var targetEntries []bpfEgressGatewayPolicyEntry

	for _, client := range ct.ClientPods() {
		for _, nodeWithoutCiliumName := range t.NodesWithoutCilium() {
			if _, err := ciliumPod.K8sClient.GetNode(context.Background(), nodeWithoutCiliumName, metav1.GetOptions{}); err != nil {
				if k8sErrors.IsNotFound(err) {
					continue
				}

				t.Fatalf("Cannot retrieve external node: %w", err)
			}

			targetEntries = append(targetEntries, bpfEgressGatewayPolicyEntry{
				SourceIP:   client.Pod.Status.PodIP,
				DestCIDR:   "0.0.0.0/0",
				EgressIP:   egressIP,
				GatewayIPs: egressGatewayNodeInternalIPs,
			})
		}
	}

	return targetEntries
}

func finalizeForMultipleGatewaysScenario(ctx context.Context, t *check.Test, needRemoveZoneLabel bool) error {
	ct := t.Context()

	for _, node := range ct.Nodes() {
		if _, ok := node.GetLabels()[defaults.CiliumNoScheduleLabel]; ok {
			continue
		}

		if needRemoveZoneLabel {
			removeNodeLabelPatch := fmt.Sprintf(`[{"op":"remove","path":"/metadata/labels/%s"}]`, escapePatchString(K8sZoneLabel))
			if _, err := ct.K8sClient().PatchNode(ctx, node.Name, types.JSONPatchType, []byte(removeNodeLabelPatch)); err != nil {
				return fmt.Errorf("cannot remove %s label from node %s: %w", K8sZoneLabel, node.Name, err)
			}
		}

		removeNodeLabelPatch := fmt.Sprintf(`[{"op":"remove","path":"/metadata/labels/%s"}]`, EgressGroupLabelKey)
		if _, err := ct.K8sClient().PatchNode(ctx, node.Name, types.JSONPatchType, []byte(removeNodeLabelPatch)); err != nil {
			return fmt.Errorf("cannot remove %s label from node %s: %w", EgressGroupLabelKey, node.Name, err)
		}
	}

	// Make sure all gateway nodes are removed before deleting the IEGP. This is to prevent the operator from logging the error
	// "Cannot update IsovalentEgressGatewayPolicy status"
	if err := waitForBpfPolicyEntries(ctx, t, func(ciliumPod check.Pod) []bpfEgressGatewayPolicyEntry {
		return getTargetEntriesForEmptyMultipleGateways(t, ciliumPod)
	}); err != nil {
		return err
	}

	return nil
}

func getTargetEntriesForEmptyMultipleGateways(t *check.Test, ciliumPod check.Pod) []bpfEgressGatewayPolicyEntry {
	ct := t.Context()

	var targetEntries []bpfEgressGatewayPolicyEntry
	for _, client := range ct.ClientPods() {
		for _, nodeWithoutCiliumName := range t.NodesWithoutCilium() {
			if _, err := ciliumPod.K8sClient.GetNode(context.Background(), nodeWithoutCiliumName, metav1.GetOptions{}); err != nil {
				if k8sErrors.IsNotFound(err) {
					continue
				}

				t.Fatalf("Cannot retrieve external node: %v", err)
			}

			targetEntries = append(targetEntries, bpfEgressGatewayPolicyEntry{
				SourceIP:   client.Pod.Status.PodIP,
				DestCIDR:   "0.0.0.0/0",
				EgressIP:   "0.0.0.0",
				GatewayIPs: nil,
			})
		}
	}

	return targetEntries
}

func EgressGatewayHABGPAdvertisement(bfdEnabled bool) check.Scenario {
	return &egressGatewayHABGPAdvertisement{
		ScenarioBase: check.NewScenarioBase(),
		bfdEnabled:   bfdEnabled,
	}
}

type egressGatewayHABGPAdvertisement struct {
	check.ScenarioBase
	bfdEnabled bool
}

func (s *egressGatewayHABGPAdvertisement) Name() string {
	return "egress-gateway-ha-ipam-bgp-advertisement"
}

func (s *egressGatewayHABGPAdvertisement) Run(ctx context.Context, t *check.Test) {
	defer deleteEGWBGPK8sResources(ctx, t)
	bfdProfileName := ""
	if s.bfdEnabled {
		bfdProfileName = egwBFDProfileName

		bfdProfile := generateBFDProfileForEGW()
		configureBFDProfileForEGW(ctx, t, bfdProfile)
	}
	configureBGPPeeringForEGW(ctx, t, features.IPFamilyV4, bfdProfileName)

	ct := t.Context()

	gatewayIPsToNames := map[string]string{}
	for _, node := range ct.Nodes() {
		if value, ok := node.GetLabels()[EgressGroupLabelKey]; !ok || value != EgressGroupLabelValue {
			continue
		}

		gatewayIP := getGatewayNodeInternalIP(ct, node.Name)
		if gatewayIP == nil {
			t.Fatal("Cannot get egress gateway node internal IP")
		}

		gatewayIPsToNames[gatewayIP.String()] = node.Name
	}

	policyName := "iegp-sample-client"

	gatewayIPsToMasqueradeIPs := make(map[string]net.IP, len(gatewayIPsToNames))
	masqueradeIPs := make([]string, 0, len(gatewayIPsToNames))
	for gatewayIP := range gatewayIPsToNames {
		masqueradeIP := waitForAllocatedEgressIP(ctx, t, policyName, 0, gatewayIP)
		masqueradeIPs = append(masqueradeIPs, masqueradeIP.String())
		gatewayIPsToMasqueradeIPs[gatewayIP] = masqueradeIP
	}

	// wait for the policy map to be populated
	if err := waitForBpfPolicyEntries(ctx, t, func(ciliumPod check.Pod) []bpfEgressGatewayPolicyEntry {
		return getTargetEntriesForMultipleGateways(t, ciliumPod, gatewayIPsToNames, gatewayIPsToMasqueradeIPs)
	}); err != nil {
		t.Fatalf("%v", err)
	}

	waitforGwNetworkConfig(ctx, t, func(ciliumPod check.Pod) *net.IP {
		for gatewayIP, nodeName := range gatewayIPsToNames {
			if ciliumPod.Pod.Spec.NodeName == nodeName {
				masqueradeIP := gatewayIPsToMasqueradeIPs[gatewayIP]
				return &masqueradeIP
			}
		}
		return nil
	})

	// run the test
	i := 0
	responsesByClientIP := map[string]struct{}{}

	// Traffic matching an egress gateway policy should leave the cluster masqueraded with the egress IP of one of the multiple GWs (pod to external service using DNS)
	for _, client := range ct.ClientPods() {
		for _, externalEchoSvc := range ct.EchoExternalServices() {
			externalEcho := externalEchoSvc.ToEchoIPService()

			t.NewAction(s, fmt.Sprintf("curl-external-echo-service-%d", i), &client, externalEcho, features.IPFamilyV4).Run(func(a *check.Action) {
				curlOpts := append(curlRetryOptions(), "-4")
				a.ExecInPod(ctx, ct.CurlCommandParallelWithOutput(externalEcho, features.IPFamilyV4, 100, curlOpts...))
				clientIPs := extractClientIPsFromEchoServiceResponses(a.CmdOutput())

				for _, clientIP := range clientIPs {
					responsesByClientIP[clientIP.String()] = struct{}{}
				}
			})
			i++
		}
	}

	// all client IPs should be egress IPs
	for clientIP := range responsesByClientIP {
		if !slices.Contains(masqueradeIPs, clientIP) {
			t.Fatalf("Request reached external echo service with wrong source IP %s", clientIP)
		}
	}

	// and traffic should go through all gateways, masqueraded with theirs egress IPs
	for _, egressIP := range masqueradeIPs {
		if _, ok := responsesByClientIP[egressIP]; !ok {
			t.Fatalf("No request has gone through gateway with egress IP %s", egressIP)
		}
	}

	// Traffic matching an egress gateway policy should leave the cluster masqueraded with the egress IP of one of the multiple GWs (pod to external service)
	i = 0
	responsesByClientIP = map[string]struct{}{}
	for _, client := range ct.ClientPods() {
		for _, externalEcho := range ct.ExternalEchoPods() {
			externalEcho := externalEcho.ToEchoIPPod()

			t.NewAction(s, fmt.Sprintf("curl-external-echo-pod-%d", i), &client, externalEcho, features.IPFamilyV4).Run(func(a *check.Action) {
				a.ExecInPod(ctx, ct.CurlCommandParallelWithOutput(externalEcho, features.IPFamilyV4, 100, curlRetryOptions()...))
				clientIPs := extractClientIPsFromEchoServiceResponses(a.CmdOutput())

				for _, clientIP := range clientIPs {
					responsesByClientIP[clientIP.String()] = struct{}{}
				}
			})
		}
		i++
	}

	// all client IPs should be egress IPs
	for clientIP := range responsesByClientIP {
		if !slices.Contains(masqueradeIPs, clientIP) {
			t.Fatalf("Request reached external echo service with wrong source IP %s", clientIP)
		}
	}

	// and traffic should go through all gateways, masqueraded with theirs egress IPs
	for _, egressIP := range masqueradeIPs {
		if _, ok := responsesByClientIP[egressIP]; !ok {
			t.Fatalf("No request has gone through gateway with egress IP %s", egressIP)
		}
	}
}

func configureBGPPeeringForEGW(ctx context.Context, t *check.Test, ipFamily features.IPFamily, bfdProfile string) {
	deleteBGPPeeringResources(ctx, t)
	configureBGPPeeringV1ForEGW(ctx, t, ipFamily, bfdProfile)
}

func configureBGPPeeringV1ForEGW(ctx context.Context, t *check.Test, ipFamily features.IPFamily, bfdProfile string) {
	ct := t.Context()
	client := ct.K8sClient().CiliumClientset.IsovalentV1()

	// configure advertisement
	advertisement := &v1.IsovalentBGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name:   egwBGPAdvertisementName,
			Labels: map[string]string{"test": "bgp"},
		},
		Spec: v1.IsovalentBGPAdvertisementSpec{
			Advertisements: []v1.BGPAdvertisement{
				{
					AdvertisementType: v1.BGPEGWAdvert,
					Selector: &slimv1.LabelSelector{
						MatchLabels: map[string]string{"egw": "bgp-advertise"},
					},
				},
			},
		},
	}

	_, err := client.IsovalentBGPAdvertisements().Create(ctx, advertisement, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create IsovalentBGPAdvertisement: %v", err)
	}

	// configure peer config
	rrCommonPeerConfig := &v1.IsovalentBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: egwRRCommonBGPPeerConfigName,
		},
		Spec: v1.IsovalentBGPPeerConfigSpec{
			Transport: &ciliumv2.CiliumBGPTransport{
				PeerPort: ptr.To(int32(egwBGPRRLocalPort)),
			},
			Families: []v1.IsovalentBGPFamilyWithAdverts{
				{
					CiliumBGPFamily: ciliumv2.CiliumBGPFamily{
						Afi:  ipFamily.String(),
						Safi: "unicast",
					},
					Advertisements: &slimv1.LabelSelector{
						MatchLabels: advertisement.Labels,
					},
				},
			},
		},
	}
	_, err = client.IsovalentBGPPeerConfigs().Create(ctx, rrCommonPeerConfig, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create IsovalentBGPPeerConfig: %v", err)
	}

	externalPeerConfig := &v1.IsovalentBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: egwExternalBGPPeerConfigName,
		},
		Spec: v1.IsovalentBGPPeerConfigSpec{
			Families: []v1.IsovalentBGPFamilyWithAdverts{
				{
					CiliumBGPFamily: ciliumv2.CiliumBGPFamily{
						Afi:  ipFamily.String(),
						Safi: "unicast",
					},
					Advertisements: &slimv1.LabelSelector{
						MatchLabels: advertisement.Labels,
					},
				},
			},
		},
	}
	if bfdProfile != "" {
		externalPeerConfig.Spec.BFDProfileRef = &bfdProfile
	}
	_, err = client.IsovalentBGPPeerConfigs().Create(ctx, externalPeerConfig, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create IsovalentBGPPeerConfig: %v", err)
	}

	// configure cluster config
	rrClusterConfig := &v1.IsovalentBGPClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: egwRRsBGPClusterConfigName,
		},
		Spec: v1.IsovalentBGPClusterConfigSpec{
			NodeSelector: &slimv1.LabelSelector{
				MatchLabels: map[string]string{"rr-role": "route-reflector"},
			},
			BGPInstances: []v1.IsovalentBGPInstance{
				{
					Name:      "test-instance",
					LocalASN:  ptr.To[int64](egwBGPCiliumASN),
					LocalPort: ptr.To[int32](egwBGPRRLocalPort),
					RouteReflector: &v1.RouteReflector{
						Role:                 v1.RouteReflectorRoleRouteReflector,
						ClusterID:            egwBGPRRClusterID,
						PeeringAddressFamily: ptr.To(v1.RouteReflectorPeeringAddressFamilyIPv4Only),
					},
				},
			},
		},
	}
	if ipFamily == features.IPFamilyV4 {
		rrClusterConfig.Spec.BGPInstances[0].RouteReflector.PeerConfigRefV4 = &v1.PeerConfigReference{
			Name: rrCommonPeerConfig.Name,
		}
	} else {
		rrClusterConfig.Spec.BGPInstances[0].RouteReflector.PeerConfigRefV6 = &v1.PeerConfigReference{
			Name: rrCommonPeerConfig.Name,
		}
	}
	for _, peerAddress := range Params.EgressGateway.PeerAddresses {
		rrClusterConfig.Spec.BGPInstances[0].Peers = append(rrClusterConfig.Spec.BGPInstances[0].Peers,
			v1.IsovalentBGPPeer{
				Name:        "peer-" + peerAddress,
				PeerAddress: ptr.To[string](peerAddress),
				PeerASN:     ptr.To[int64](Params.EgressGateway.PeerASN),
				PeerConfigRef: &v1.PeerConfigReference{
					Name: externalPeerConfig.Name,
				},
			})
	}
	_, err = client.IsovalentBGPClusterConfigs().Create(ctx, rrClusterConfig, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create IsovalentBGPClusterConfig: %v", err)
	}

	clientClusterConfig := &v1.IsovalentBGPClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: egwClientsBGPClusterConfigName,
		},
		Spec: v1.IsovalentBGPClusterConfigSpec{
			NodeSelector: &slimv1.LabelSelector{
				MatchLabels: map[string]string{"rr-role": "client"},
			},
			BGPInstances: []v1.IsovalentBGPInstance{
				{
					Name:     "test-instance",
					LocalASN: ptr.To[int64](egwBGPCiliumASN),
					RouteReflector: &v1.RouteReflector{
						Role:                 v1.RouteReflectorRoleClient,
						ClusterID:            egwBGPRRClusterID,
						PeeringAddressFamily: ptr.To(v1.RouteReflectorPeeringAddressFamilyIPv4Only),
					},
				},
			},
		},
	}
	if ipFamily == features.IPFamilyV4 {
		clientClusterConfig.Spec.BGPInstances[0].RouteReflector.PeerConfigRefV4 = &v1.PeerConfigReference{
			Name: rrCommonPeerConfig.Name,
		}
	} else {
		clientClusterConfig.Spec.BGPInstances[0].RouteReflector.PeerConfigRefV6 = &v1.PeerConfigReference{
			Name: rrCommonPeerConfig.Name,
		}
	}
	_, err = client.IsovalentBGPClusterConfigs().Create(ctx, clientClusterConfig, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create IsovalentBGPClusterConfig: %v", err)
	}
}

func deleteEGWBGPK8sResources(ctx context.Context, t *check.Test) {
	client := t.Context().K8sClient().CiliumClientset.IsovalentV1alpha1()

	deleteEGWBGPPeeringResources(ctx, t)

	check.DeleteK8sResourceWithWait(ctx, t, client.IsovalentBFDProfiles(), egwBFDProfileName)
}

func deleteEGWBGPPeeringResources(ctx context.Context, t *check.Test) {
	client := t.Context().K8sClient().CiliumClientset.IsovalentV1()
	check.DeleteK8sResourceWithWait(ctx, t, client.IsovalentBGPClusterConfigs(), egwRRsBGPClusterConfigName)
	check.DeleteK8sResourceWithWait(ctx, t, client.IsovalentBGPClusterConfigs(), egwClientsBGPClusterConfigName)
	check.DeleteK8sResourceWithWait(ctx, t, client.IsovalentBGPPeerConfigs(), egwRRCommonBGPPeerConfigName)
	check.DeleteK8sResourceWithWait(ctx, t, client.IsovalentBGPPeerConfigs(), egwExternalBGPPeerConfigName)
	check.DeleteK8sResourceWithWait(ctx, t, client.IsovalentBGPAdvertisements(), egwBGPAdvertisementName)
}

func generateBFDProfileForEGW() *v1alpha1.IsovalentBFDProfile {
	profile := &v1alpha1.IsovalentBFDProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name: egwBFDProfileName,
		},
		Spec: v1alpha1.BFDProfileSpec{
			ReceiveIntervalMilliseconds:  ptr.To[int32](300),
			TransmitIntervalMilliseconds: ptr.To[int32](300),
			DetectMultiplier:             ptr.To[int32](3),
		},
	}
	return profile
}

func configureBFDProfileForEGW(ctx context.Context, t *check.Test, profile *v1alpha1.IsovalentBFDProfile) {
	ct := t.Context()
	client := ct.K8sClient().CiliumClientset.IsovalentV1alpha1()

	_, err := client.IsovalentBFDProfiles().Create(ctx, profile, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create IsovalentBFDProfile: %v", err)
	}
}
