//  Copyright (C) Isovalent, Inc. - All Rights Reserved
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package ilb

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"

	isovalentv1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/versioncheck"
)

const (
	mySqlUser     = "root"
	mySqlPassword = "my-secret-pw"
	mySqlPort     = 3306
)

func TestNodeMaintenance_T2_T1T2_TCPProxy(t T) {
	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	// label based backends are only supported in v1.18 and newer
	minVersion := ">=1.18.0"
	currentVersion := GetCiliumVersion(t, k8sCli)
	if !versioncheck.MustCompile(minVersion)(currentVersion) {
		fmt.Printf("skipping due to version mismatch - expected: %s - current: %s\n", minVersion, currentVersion.String())
		return
	}

	t1NodeList, err := k8sCli.CoreV1().Nodes().List(t.Context(), metav1.ListOptions{LabelSelector: "service.cilium.io/node in ( t1, t1-t2 )"})
	if err != nil {
		t.Failedf("failed to retrieve t1 k8s nodes: %s", err)
	}

	// Skip test in environments with only one T2 node instance because this breaks connection
	// because VIP will no longer be announced on T1 nodes if there's no healthy T2 node
	t2NodeList, err := k8sCli.CoreV1().Nodes().List(t.Context(), metav1.ListOptions{LabelSelector: "service.cilium.io/node in ( t2, t1-t2 )"})
	if err != nil {
		t.Failedf("failed to retrieve t2 k8s nodes: %s", err)
	}

	if len(t2NodeList.Items) < 2 {
		fmt.Printf("skipping due to not at least 2 T2 nodes available\n")
		return
	}

	t.RunTestCase(func(t T) {
		mode := isovalentv1alpha1.LBTCPProxyForceDeploymentModeT2
		testName := "node-maintenance-t2-tcp-proxy-" + string(mode)

		//
		// Setup test scenario (backends, clients & LB resources)
		//
		scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

		t.Log("Creating backend apps...")
		scenario.addBackendApplications(1, backendApplicationConfig{h2cEnabled: true, image: FlagMariaDBImage, listenPort: mySqlPort, envVars: map[string]string{"MARIADB_ROOT_PASSWORD": mySqlPassword}})

		t.Log("Creating clients and add BGP peering ...")
		client := scenario.addFRRClients(1, frrClientConfig{})[0]

		t.Log("Creating LB VIP resources...")
		vip := lbVIP(testName)
		scenario.createLBVIP(vip)

		t.Log("Creating LB BackendPool resources...")
		backends := []backendPoolOption{
			withTCPHealthCheck(nil, nil),
		}

		sqlServerIP := ""
		sqlServerPort := uint32(0)

		for _, b := range scenario.backendApps {
			sqlServerIP = b.ipv4
			sqlServerPort = b.port
			backends = append(backends, withIPBackend(b.ipv4, b.port))
		}

		backendPool := lbBackendPool(testName, backends...)
		scenario.createLBBackendPool(backendPool)

		t.Log("Creating LB Service resources...")
		service := lbService(testName, withPort(80), withTCPProxyApplication(withTCPForceDeploymentMode(mode), withTCPProxyRoute(backendPool.Name)))
		scenario.createLBService(service)

		t.Log("Waiting for full VIP connectivity...")
		vipIP := scenario.waitForFullVIPConnectivity(testName)

		// Additional check to prevent the persistent connection from being killed because there's not a single healthy T2 endpoint available.
		// This can be caused for two reasons:
		// 1. Initial BGP status / Service health flapping. The service gets created in `healthy` state and then gets reconciled based on the active health check.
		//    In this short period, the service might already be advertised via BGP (initial state healthy) and gets withdraw immediately after (endpoint not ready yet).
		// 2. There's only one healthy T2 instance at the time of testing - and that's the one that gets put into maintenance
		//
		// In both cases, the BGP route gets withdraw if there's no healthy (T2) endpoint available. Which leads to terminating the persistent connection if the same happens on all T1 nodes.
		t.Log("Waiting until all T2 endpoints are active on all T1 nodes...")
		scenario.waitForAllT2EndpointsActive(testName, vipIP, 80, t1NodeList, t2NodeList)

		//
		// Actual start of tests
		//
		testCmd := fmt.Sprintf("lb-test-client sql %s:%s@tcp(%s:%s)/%s", mySqlUser, mySqlPassword, vipIP, "80", "sys")
		t.Log("Starting SQL client that opens TCP connection %q...", testCmd)
		testClientOutputReader, err := client.ExecDetached(t.Context(), []string{"lb-test-client", "sql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mySqlUser, mySqlPassword, vipIP, "80", "sys")})
		if err != nil {
			t.Failedf("failed to start sql client (cmd: %q): %s", testCmd, err)
		}

		if FlagVerbose {
			go func() {
				if _, err := io.Copy(os.Stdout, testClientOutputReader); err != nil {
					fmt.Printf("failed to copy test app output: %s\n", err)
				}
			}()
		}

		t.Log("Waiting for connection on SQL server side...")
		t2NodeIP, t2NodeSourcePort, connTimeout := waitForConnectionOnSQLServer(t, client, sqlServerIP, sqlServerPort)

		t.Log("Connection found with client IP %s, port %s and timeout %s", t2NodeIP, t2NodeSourcePort, connTimeout)

		t.Log("Loading T2 node that is handling the long-living sql connection")
		t2Node := getK8sNodeWithIP(t, k8sCli, t2NodeIP)

		if nodeIsT1AndT2(t2Node) {
			// This step is necessary for nodes that serve T1 & T2 functionality. If T1 & T2 are put into maintenance
			// by marking the node as unschedulable it will break existing persistent connections.
			t.Log("Disable T1 BGP node maintenance of node %s ", t2Node.Name)
			createBGPNodeConfigOverrideWithMaintenance(t, ciliumCli, t2Node.Name, isovalentv1.BGPMaintenanceModeDisabled)
			time.Sleep(5 * time.Second) // we don't get a CRD status of the BGP controlplane. Therefore give it 5s to disable BGP maintenance
		}

		t.Log("Marking T2 node %s that is handling the long-living sql connection as unschedulable", t2Node.Name)
		markNodeAsUnschedulable(t, k8sCli, t2Node.Name)

		//  register cleanup to revert all k8s nodes to be schedulable (in case we abort early due to an error)
		t.RegisterCleanup(markAllNodesAsSchedulable(k8sCli))

		t.Log("Waiting until 100 consecutive new connections don't use T2 node %s that is marked as unschedulable", t2Node.Name)
		waitUntil100NewConnectionsDontUseT2Node(t, client, vipIP, 80, t2NodeIP)

		t.Log("Checking existing connection is still alive / pinged")
		checkInitialConnectionAlive(t, client, sqlServerIP, sqlServerPort, t2NodeIP, t2NodeSourcePort)

		t.Log("Checking that 100 additional new connections don't use T2 node %s that is marked as unschedulable", t2Node.Name)
		check100NewConnectionsDontUseT2Node(t, client, vipIP, 80, t2NodeIP)

		t.Log("Marking T2 node %s as schedulable", t2Node.Name)
		markNodeAsSchedulable(t, k8sCli, t2Node.Name)
		if nodeIsT1AndT2(t2Node) {
			ciliumCli.IsovalentV1().IsovalentBGPNodeConfigOverrides().Delete(t.Context(), t2Node.Name, metav1.DeleteOptions{})
		}

		t.Log("Checking that new connections eventually use T2 node %s again", t2Node.Name)
		checkNewConnectionsUseT2(t, client, vipIP, 80, t2NodeIP)

		t.Log("Checking existing connection is still alive / pinged")
		checkInitialConnectionAlive(t, client, sqlServerIP, sqlServerPort, t2NodeIP, t2NodeSourcePort)
	})
}

func toMySQLCommand(sqlServerIP string, sqlServerPort uint32, command string) string {
	return fmt.Sprintf(`mysql -h%s -P%d -u%s -p%s --skip-column-names --raw --silent --execute "%s"`, sqlServerIP, sqlServerPort, mySqlUser, mySqlPassword, command)
}

func waitForConnectionOnSQLServer(t T, client *frrContainer, sqlServerIP string, sqlServerPort uint32) (string, string, string) {
	checkCmd := toMySQLCommand(sqlServerIP, sqlServerPort, "SELECT HOST, TIME FROM information_schema.processlist WHERE DB = 'sys';")
	result := ""

	eventually(t, func() error {
		stdout, _, err := client.Exec(t.Context(), checkCmd)
		if err != nil {
			return fmt.Errorf("failed to fetch sql processes: %w", err)
		}

		if strings.TrimSpace(stdout) == "" {
			return fmt.Errorf("connection not yet found")
		}

		result = strings.TrimSpace(stdout)
		return nil
	}, longTimeout, pollInterval)

	initialConnectionResultSplit := strings.Split(result, "\t")
	if len(initialConnectionResultSplit) != 2 {
		t.Failedf("unexpected result - expected clientip and time")
	}

	initialConnectionIPPort := strings.Split(initialConnectionResultSplit[0], ":")

	return initialConnectionIPPort[0], initialConnectionIPPort[1], initialConnectionResultSplit[1]
}

func getK8sNodeWithIP(t T, k8sCli *clientset.Clientset, nodeIP string) *corev1.Node {
	nl, err := k8sCli.CoreV1().Nodes().List(t.Context(), metav1.ListOptions{})
	if err != nil {
		t.Failedf("failed to list all k8s nodes: %s", err)
	}

	var t2Node *corev1.Node
	for _, n := range nl.Items {
		for _, na := range n.Status.Addresses {
			if na.Address == nodeIP {
				t2Node = &n
				break
			}
		}
	}

	if t2Node == nil {
		t.Failedf("failed to find t2 node with ip: %s", nodeIP)
	}

	return t2Node
}

func markNodeAsUnschedulable(t T, k8sCli *clientset.Clientset, nodeName string) {
	err := retry.RetryOnConflict(bgpUpdateBackoff, func() error {
		n, err := k8sCli.CoreV1().Nodes().Get(t.Context(), nodeName, metav1.GetOptions{})
		if err != nil {
			t.Failedf("failed to get node %s: %s", nodeName, err)
			return nil
		}

		if n.Spec.Unschedulable {
			t.Failedf("Node %s is already marked as unschedulable", n.Name)
			return nil
		}

		for _, nt := range n.Spec.Taints {
			if nt.Key == corev1.TaintNodeUnschedulable {
				t.Failedf("Node %s is already tainted as unschedulable", n.Name)
				return nil
			}
		}

		n.Spec.Taints = append(n.Spec.Taints, corev1.Taint{
			Key:    corev1.TaintNodeUnschedulable,
			Effect: corev1.TaintEffectNoSchedule,
			TimeAdded: &metav1.Time{
				Time: time.Now(),
			},
		})

		n.Spec.Unschedulable = true

		_, err = k8sCli.CoreV1().Nodes().Update(t.Context(), n, metav1.UpdateOptions{})
		return err
	})
	if err != nil {
		t.Failedf("failed to mark node as unschedulable: %s", err)
	}
}

func markNodeAsSchedulable(t T, k8sCli *clientset.Clientset, nodeName string) {
	err := retry.RetryOnConflict(bgpUpdateBackoff, func() error {
		n, err := k8sCli.CoreV1().Nodes().Get(t.Context(), nodeName, metav1.GetOptions{})
		if err != nil {
			t.Failedf("failed to get node %s: %s", nodeName, err)
			return nil
		}

		newTaints := []corev1.Taint{}
		for _, nt := range n.Spec.Taints {
			if nt.Key != corev1.TaintNodeUnschedulable {
				newTaints = append(newTaints, nt)
			}
		}
		n.Spec.Taints = newTaints

		n.Spec.Unschedulable = false

		_, err = k8sCli.CoreV1().Nodes().Update(t.Context(), n, metav1.UpdateOptions{})
		return err
	})
	if err != nil {
		t.Failedf("failed to mark node as schedulable: %s", err)
	}
}

func markAllNodesAsSchedulable(k8sCli *clientset.Clientset) func(context.Context) error {
	return func(ctx context.Context) error {
		nl, err := k8sCli.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
		if err != nil {
			return fmt.Errorf("failed to list all nodes: %w", err)
		}

		for _, n := range nl.Items {
			newTaints := []corev1.Taint{}
			for _, nt := range n.Spec.Taints {
				if nt.Key != corev1.TaintNodeUnschedulable {
					newTaints = append(newTaints, nt)
				}
			}
			n.Spec.Taints = newTaints

			n.Spec.Unschedulable = false

			if _, err := k8sCli.CoreV1().Nodes().Update(ctx, &n, metav1.UpdateOptions{}); err != nil {
				return fmt.Errorf("failed to mark node %s as scheudlable: %w", n.Name, err)
			}

		}

		return nil
	}
}

func checkInitialConnectionAlive(t T, client *frrContainer, sqlServerIP string, sqlServerPort uint32, initialConnectionIP string, initialConnectionPort string) {
	checkCmd := toMySQLCommand(sqlServerIP, sqlServerPort, "SELECT HOST, TIME FROM information_schema.processlist WHERE DB = 'sys';")

	stdout, _, err := client.Exec(t.Context(), checkCmd)
	if err != nil {
		t.Failedf("failed to fetch sql processes while checking existing connection: %s", err)
	}

	if strings.TrimSpace(stdout) == "" {
		t.Failedf("existing connection no longer exists")
	}

	splitFirstCheck := strings.Split(strings.TrimSpace(stdout), "\t")
	if len(splitFirstCheck) != 2 {
		t.Failedf("unexpected result while checkign existing connection - expected clientip and time")
	}

	ipPortFirstCheck := strings.Split(splitFirstCheck[0], ":")

	if initialConnectionIP != ipPortFirstCheck[0] || initialConnectionPort != ipPortFirstCheck[1] {
		t.Failedf("new connection %s:%s != %s:%s", initialConnectionIP, initialConnectionPort, ipPortFirstCheck[0], ipPortFirstCheck[1])
	}

	eventually(t, func() error {
		stdout, _, err := client.Exec(t.Context(), checkCmd)
		if err != nil {
			return fmt.Errorf("failed to fetch sql processes: %w", err)
		}

		if strings.TrimSpace(stdout) == "" {
			return fmt.Errorf("connection not yet found")
		}

		split := strings.Split(strings.TrimSpace(stdout), "\t")
		if len(split) != 2 {
			return fmt.Errorf("unexpected result while checking existing connection - expected clientip and time")
		}

		ipPort := strings.Split(split[0], ":")

		if initialConnectionIP != ipPort[0] || initialConnectionPort != ipPort[1] {
			return fmt.Errorf("new connection doesn't match %s:%s != %s:%s", initialConnectionIP, initialConnectionPort, ipPort[0], ipPort[1])
		}

		newTimeout, err := strconv.Atoi(split[1])
		if err != nil {
			return err
		}

		previousTimeout, err := strconv.Atoi(splitFirstCheck[1])
		if err != nil {
			return err
		}

		if previousTimeout == 0 {
			previousTimeout = 1
		}

		if newTimeout > previousTimeout {
			return fmt.Errorf("connection no longer active / not pinged %d > %d", newTimeout, previousTimeout)
		}

		return nil
	}, shortTimeout, pollInterval)
}

func waitUntil100NewConnectionsDontUseT2Node(t T, client *frrContainer, ip string, port uint32, initialConnectionIP string) {
	checkCmd := toMySQLCommand(ip, port, "SELECT HOST FROM information_schema.processlist WHERE COMMAND = 'query';")

	eventually(t, func() error {
		for range 100 {
			stdout, _, err := client.Exec(t.Context(), checkCmd)
			if err != nil {
				return fmt.Errorf("failed to fetch sql processes: %w", err)
			}

			ipPort := strings.Split(stdout, ":")
			if ipPort[0] == initialConnectionIP {
				return fmt.Errorf("new connection still using unschedulable node as T2 node")
			}
		}

		return nil
	}, shortTimeout, pollInterval)
}

func check100NewConnectionsDontUseT2Node(t T, client *frrContainer, ip string, port uint32, initialConnectionIP string) {
	checkCmd := toMySQLCommand(ip, port, "SELECT HOST FROM information_schema.processlist WHERE COMMAND = 'query';")
	for range 100 {
		stdout, _, err := client.Exec(t.Context(), checkCmd)
		if err != nil {
			t.Failedf("failed to fetch sql processes: %s", err)
		}

		ipPort := strings.Split(stdout, ":")
		if ipPort[0] == initialConnectionIP {
			t.Failedf("new connection using unschedulable node as T2 node detected")
		}
	}
}

func checkNewConnectionsUseT2(t T, client *frrContainer, ip string, port uint32, initialConnectionIP string) {
	checkCmd := toMySQLCommand(ip, port, "SELECT HOST FROM information_schema.processlist WHERE COMMAND = 'query';")
	eventually(t, func() error {
		stdout, _, err := client.Exec(t.Context(), checkCmd)
		if err != nil {
			return fmt.Errorf("failed to fetch sql processes: %w", err)
		}

		ipPort := strings.Split(stdout, ":")
		if ipPort[0] != initialConnectionIP {
			return fmt.Errorf("new connection not using node as T2 again")
		}

		return nil
	}, shortTimeout, pollInterval)
}

func nodeIsT1AndT2(node *corev1.Node) bool {
	v, ok := node.Labels["service.cilium.io/node"]
	return ok && v == "t1-t2"
}
