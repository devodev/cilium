// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package evpn

import (
	"context"
	"fmt"
	"maps"
	"math"
	"net/netip"
	"strconv"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	slimlabels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

const (
	fabricSecurityGroupsPollInterval = 2 * time.Second
	fabricSecurityGroupsPollTimeout  = 2 * time.Minute

	appLabelKey         = "app"
	appLabelValuePrefix = "test-app"
)

// fabricSecurityGroupsTest tests EVPN Fabric Security Group integration.
// It deploys 2 pods in each discovered private network, each with 2 different app labels (same across privnets).
// Then performs these steps:
//   - Validates, that privnet pod IPs are first advertised with the default Security Group ID.
//   - Deploys a Security Group matching app 1 label. Validates that privnet pod IPs of pods matching that
//     label are now advertised with this app-specific SGT.
//   - Deploys a Security Group matching app 2 label. Validates that all privnet POD IPs are now
//     advertised with app-specific SGTs.
//   - Deletes app-specific Security Groups and validates per-privnet SGTs are advertised again.
//   - Deletes per-privnet SGTs and validates default SGTs are advertised again.
//
// Since SGTs (Extended Communities) are not recognized by FRR, and it does not provide an easy way to retrieve them,
// for now we are only validating advertised SGTs using the cilium-agent-local dump of advertised routes.
// Apart from this check we perform one connectivity check after applying all FSG changes to ensure
// Security Group changes did not break connectivity.
type fabricSecurityGroupsTest struct {
	testPods []*fsgTestPod

	privnetGroupIDs map[string]uint16 // per-privnet allocated FSG ID
	app1GroupID     uint16
	app2GroupID     uint16
}

type fsgTestPod struct {
	config *privnetPodConfig
	labels map[string]string
	k8sPod *corev1.Pod
}

func newFabricSecurityGroupsTest() *fabricSecurityGroupsTest {
	return &fabricSecurityGroupsTest{}
}

func (t *fabricSecurityGroupsTest) Name() string {
	return "fabric-security-groups"
}

func (t *fabricSecurityGroupsTest) Run(ctx context.Context, run *TestRun, env *testEnv) error {
	if !env.evpnConfig.securityGroupTagsEnabled {
		return fmt.Errorf("EVPN security group tags are disabled in the cilium configuration")
	}
	fmt.Fprintf(run.out, "Default EVPN security group ID: %d\n", env.evpnConfig.defaultSecurityGroupID)

	// deploy 2 pods with different app labels in each privnet
	err := t.deployPodsForPrivnets(ctx, run, env.evpnPrivnets, 2)
	if err != nil {
		return err
	}

	// allocate FSG IDs for each privnet + 2 extra for each app label selector
	err = t.allocateFabricSecurityGroupIDs(ctx, run)
	if err != nil {
		return err
	}

	// expect default SGTs for all pods
	if err := t.waitForAdvertisedSecurityGroups(ctx, run, t.allPodsSameGroupID(env.evpnConfig.defaultSecurityGroupID),
		"default security group advertisements"); err != nil {
		return err
	}

	// deploy per-privnet FSGs, expect privnet-specific SGTs on each pod
	for privnetName := range env.evpnPrivnets {
		if err := t.createFabricSecurityGroup(ctx, run, t.privnetGroupIDs[privnetName], map[string]string{privnetNetworkNameLabel: privnetName}); err != nil {
			return err
		}
	}
	if err := t.waitForAdvertisedSecurityGroups(ctx, run, t.perPrivnetGroupIDs(),
		"privnet-specific security group advertisements"); err != nil {
		return err
	}

	// deploy app-1 FSG applied across privnets, expect app-1 specific SGTs for matching pods, privnet-specific SGTs on other pods
	if err := t.createFabricSecurityGroup(ctx, run, t.app1GroupID, map[string]string{appLabelKey: appLabelValue(1)}); err != nil {
		return err
	}
	expectGroupIDs := t.perPrivnetGroupIDs()
	maps.Copy(expectGroupIDs, t.perAppLabelGroupIDs(map[string]uint16{appLabelValue(1): t.app1GroupID})) // overrides per-privnet expected FSG
	if err := t.waitForAdvertisedSecurityGroups(ctx, run, expectGroupIDs,
		"mixed privnet-specififc and per-app security group advertisements"); err != nil {
		return err
	}

	// deploy app-2 FSG applied across privnets, expect app-specific SGTs for all pods
	if err := t.createFabricSecurityGroup(ctx, run, t.app2GroupID, map[string]string{appLabelKey: appLabelValue(2)}); err != nil {
		return err
	}
	expectGroupIDs = t.perAppLabelGroupIDs(map[string]uint16{
		appLabelValue(1): t.app1GroupID,
		appLabelValue(2): t.app2GroupID,
	})
	if err := t.waitForAdvertisedSecurityGroups(ctx, run, expectGroupIDs,
		"app-specific security group advertisements"); err != nil {
		return err
	}

	// run ping from test pods as a sanity check (FSGs do not affect connectivity,
	// so we just check that changing FSGs did not break it)
	if err := t.pingFromTestPods(ctx, run, "ping with app-specific security group advertisements"); err != nil {
		return err
	}

	// delete app-specific FSGs, expect privnet-specific FSGs again
	if err := t.deleteFabricSecurityGroup(ctx, run, t.app1GroupID); err != nil {
		return err
	}
	if err := t.deleteFabricSecurityGroup(ctx, run, t.app2GroupID); err != nil {
		return err
	}
	if err := t.waitForAdvertisedSecurityGroups(ctx, run, t.perPrivnetGroupIDs(),
		"fallback to privnet-specific security group advertisements"); err != nil {
		return err
	}

	// delete privnet-specific FSGs, expect default SGTs again
	for privnetName := range env.evpnPrivnets {
		if err := t.deleteFabricSecurityGroup(ctx, run, t.privnetGroupIDs[privnetName]); err != nil {
			return err
		}
	}
	if err := t.waitForAdvertisedSecurityGroups(ctx, run, t.allPodsSameGroupID(env.evpnConfig.defaultSecurityGroupID),
		"fallback to default security group advertisements"); err != nil {
		return err
	}

	return nil
}

func (t *fabricSecurityGroupsTest) allPodsSameGroupID(groupID uint16) map[string]uint16 {
	expected := make(map[string]uint16, len(t.testPods))
	for _, testPod := range t.testPods {
		expected[testPod.config.name] = groupID
	}
	return expected
}

func (t *fabricSecurityGroupsTest) perPrivnetGroupIDs() map[string]uint16 {
	expected := make(map[string]uint16, len(t.testPods))
	for _, testPod := range t.testPods {
		expected[testPod.config.name] = t.privnetGroupIDs[testPod.config.privnet.Name]
	}
	return expected
}

func (t *fabricSecurityGroupsTest) perAppLabelGroupIDs(appGroupIDs map[string]uint16) map[string]uint16 {
	expected := make(map[string]uint16, len(t.testPods))
	for _, testPod := range t.testPods {
		if appGroupID, ok := appGroupIDs[testPod.labels[appLabelKey]]; ok {
			expected[testPod.config.name] = appGroupID
		}
	}
	return expected
}

func (t *fabricSecurityGroupsTest) Cleanup(ctx context.Context, run *TestRun, env *testEnv) error {
	fmt.Fprintf(run.out, "Cleaning up test resources...\n")

	if err := cleanupPods(ctx, run.client, run.params.TestNamespace, testResourceLabels(t.Name())); err != nil {
		return fmt.Errorf("failed to clean up test pods: %w", err)
	}

	if err := t.cleanupFabricSecurityGroups(ctx, run); err != nil {
		return fmt.Errorf("failed to clean up FabricSecurityGroups: %w", err)
	}

	return nil
}

func (t *fabricSecurityGroupsTest) deployPodsForPrivnets(ctx context.Context, run *TestRun, privnets map[string]privnetInfo, countPerPrivnet int) (err error) {
	for _, privnet := range privnets {
		for i := 1; i <= countPerPrivnet; i++ {
			pod := &fsgTestPod{}
			pod.config, err = getPrivnetTestPodConfig(privnet, fmt.Sprintf("%s-app%d", t.Name(), i), uint32(i))
			if err != nil {
				return err
			}
			pod.labels = testResourceLabels(t.Name())
			maps.Copy(pod.labels, map[string]string{appLabelKey: appLabelValue(i)})
			t.testPods = append(t.testPods, pod)

			pod.k8sPod, err = buildPrivnetK8sPod(pod.config, run.params, pod.labels)
			if err != nil {
				return err
			}
		}
	}

	for _, testPod := range t.testPods {
		fmt.Fprintf(run.out, "Creating pod %s/%s for privnet %s with app=%s...\n",
			testPod.k8sPod.Namespace, testPod.k8sPod.Name, testPod.config.privnet.Name, testPod.labels[appLabelKey])
		if _, err := run.client.CreatePod(ctx, run.params.TestNamespace, testPod.k8sPod, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("error creating pod %s/%s: %w", testPod.k8sPod.Namespace, testPod.k8sPod.Name, err)
		}
	}

	for _, testPod := range t.testPods {
		k8sPod, err := waitForPodReady(ctx, run.client, run.params.TestNamespace, testPod.config.name)
		if err != nil {
			return err
		}
		testPod.k8sPod = k8sPod
		fmt.Fprintf(run.out, "Pod %s/%s is running on node %s\n", k8sPod.Namespace, k8sPod.Name, k8sPod.Spec.NodeName)
	}

	return nil
}

func (t *fabricSecurityGroupsTest) allocateFabricSecurityGroupIDs(ctx context.Context, run *TestRun) error {
	// find already used IDs
	list, err := run.client.EnterpriseCiliumClientset.IsovalentV1alpha1().FabricSecurityGroups().List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed listing FabricSecurityGroups: %w", err)
	}
	used := map[uint16]struct{}{}
	for i := range list.Items {
		groupID, err := strconv.ParseUint(list.Items[i].Name, 10, 16)
		if err != nil {
			continue
		}
		used[uint16(groupID)] = struct{}{}
	}

	// allocate all necessary IDs
	count := len(run.env.evpnPrivnets) + 2
	start := run.env.evpnConfig.defaultSecurityGroupID + 100
	allocated := make([]uint16, 0, count)
	for groupID := start; groupID < math.MaxUint16 && len(allocated) < count; groupID++ {
		candidate := groupID
		if _, exists := used[candidate]; exists {
			continue
		}
		allocated = append(allocated, candidate)
	}
	if len(allocated) != count {
		return fmt.Errorf("could not allocate %d FabricSecuritySGTs", count)
	}

	// assign allocated IDs to privnets and apps
	t.privnetGroupIDs = make(map[string]uint16, len(run.env.evpnPrivnets))
	i := 0
	for privnet := range run.env.evpnPrivnets {
		t.privnetGroupIDs[privnet] = allocated[i]
		i++
	}
	t.app1GroupID = allocated[len(allocated)-2]
	t.app2GroupID = allocated[len(allocated)-1]

	return nil
}

func (t *fabricSecurityGroupsTest) createFabricSecurityGroup(ctx context.Context, run *TestRun, groupID uint16, selector map[string]string) error {
	fsg := &v1alpha1.FabricSecurityGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name:   strconv.FormatUint(uint64(groupID), 10),
			Labels: testResourceLabels(t.Name()),
		},
		Spec: v1alpha1.FabricSecurityGroupSpec{
			EndpointSelector: &slimv1.LabelSelector{
				MatchLabels: selector,
			},
		},
	}
	fmt.Fprintf(run.out, "Creating FabricSecurityGroup %s...\n", fsg.Name)

	if _, err := run.client.EnterpriseCiliumClientset.IsovalentV1alpha1().FabricSecurityGroups().Create(ctx, fsg, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("failed creating FabricSecurityGroup %s: %w", fsg.Name, err)
	}
	return nil
}

func (t *fabricSecurityGroupsTest) waitForAdvertisedSecurityGroups(ctx context.Context, run *TestRun, expected map[string]uint16, description string) error {
	fmt.Fprintf(run.out, "Waiting for %s...\n", description)

	err := wait.PollUntilContextTimeout(ctx, fabricSecurityGroupsPollInterval, fabricSecurityGroupsPollTimeout, true, func(ctx context.Context) (bool, error) {
		routesByNode := make(map[string]map[netip.Prefix]rt5Route)
		for _, testPod := range t.testPods {
			nodeName := testPod.k8sPod.Spec.NodeName
			nodeInfo, ok := run.env.bgpNodeInfo[nodeName]
			if !ok {
				return false, fmt.Errorf("missing bgp node info for node %s", nodeName)
			}
			routes, err := run.retrieveAdvertisedRT5Routes(ctx, nodeInfo)
			if err != nil {
				return false, err
			}
			routesByNode[nodeName] = routes
		}
		for _, testPod := range t.testPods {
			expectedSG, ok := expected[testPod.config.name]
			if !ok {
				return false, fmt.Errorf("no expected security group configured for pod %s", testPod.config.name)
			}
			if err := validatePodAdvertisedSecurityGroup(testPod, routesByNode[testPod.k8sPod.Spec.NodeName], expectedSG); err != nil {
				fmt.Fprintf(run.out, "%v\n", err)
				return false, nil
			}
		}
		return true, nil
	})
	if err != nil {
		return fmt.Errorf("failed waiting for %s: %w", description, err)
	}
	fmt.Fprintf(run.out, "Advertised RT-5 routes match %s\n", description)
	return nil
}

func validatePodAdvertisedSecurityGroup(testPod *fsgTestPod, routes map[netip.Prefix]rt5Route, expectedSecurityGroupID uint16) error {
	for _, addr := range []netip.Addr{testPod.config.ipv4, testPod.config.ipv6} {
		if !addr.IsValid() {
			continue
		}
		prefix := netip.PrefixFrom(addr, addr.BitLen())
		route, ok := routes[prefix]
		if !ok {
			return fmt.Errorf("RT-5 route for pod %s/%s prefix %s not advertised yet", testPod.k8sPod.Namespace, testPod.k8sPod.Name, prefix)
		}
		if route.SecurityGroupID == nil {
			return fmt.Errorf("RT-5 route for pod %s/%s prefix %s has no GroupPolicyID attribute", testPod.k8sPod.Namespace, testPod.k8sPod.Name, prefix)
		}
		if *route.SecurityGroupID != expectedSecurityGroupID {
			return fmt.Errorf("RT-5 route for pod %s/%s prefix %s advertises GroupPolicyID %d, expected %d",
				testPod.k8sPod.Namespace, testPod.k8sPod.Name, prefix, *route.SecurityGroupID, expectedSecurityGroupID)
		}
	}
	return nil
}

func (t *fabricSecurityGroupsTest) pingFromTestPods(ctx context.Context, run *TestRun, description string) error {
	fmt.Fprintf(run.out, "Pinging from test pods with %s...\n", description)
	for _, testPod := range t.testPods {
		targets, err := getRemoteTargetsForPod(ctx, run, run.env, testPod.config, testPod.k8sPod.Spec.NodeName)
		if err != nil {
			return err
		}
		for _, target := range targets {
			if (target.Is4() && testPod.config.ipv4.IsValid()) || (target.Is6() && testPod.config.ipv6.IsValid()) {
				if err := pingFromPod(ctx, run, testPod.k8sPod, target); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (t *fabricSecurityGroupsTest) deleteFabricSecurityGroup(ctx context.Context, run *TestRun, groupID uint16) error {
	name := strconv.FormatUint(uint64(groupID), 10)
	fmt.Fprintf(run.out, "Deleting FabricSecurityGroup %s...\n", name)

	err := run.client.EnterpriseCiliumClientset.IsovalentV1alpha1().FabricSecurityGroups().Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil && !k8serrors.IsNotFound(err) {
		return fmt.Errorf("failed deleting FabricSecurityGroup %s: %w", name, err)
	}
	return nil
}

func (t *fabricSecurityGroupsTest) cleanupFabricSecurityGroups(ctx context.Context, run *TestRun) error {
	labels := testResourceLabels(t.Name())

	list, err := run.client.EnterpriseCiliumClientset.IsovalentV1alpha1().FabricSecurityGroups().List(ctx, metav1.ListOptions{
		LabelSelector: slimlabels.FormatLabels(labels),
	})
	if err != nil {
		return err
	}
	for i := range list.Items {
		if err := run.client.EnterpriseCiliumClientset.IsovalentV1alpha1().FabricSecurityGroups().Delete(ctx, list.Items[i].Name, metav1.DeleteOptions{}); err != nil && !k8serrors.IsNotFound(err) {
			return err
		}
	}
	return wait.PollUntilContextTimeout(ctx, fabricSecurityGroupsPollInterval, fabricSecurityGroupsPollTimeout, true, func(ctx context.Context) (bool, error) {
		list, err := run.client.EnterpriseCiliumClientset.IsovalentV1alpha1().FabricSecurityGroups().List(ctx, metav1.ListOptions{
			LabelSelector: slimlabels.FormatLabels(labels),
		})
		if err != nil {
			return false, err
		}
		return len(list.Items) == 0, nil
	})
}

func appLabelValue(i int) string {
	return fmt.Sprintf("%s-%d", appLabelValuePrefix, i)
}
