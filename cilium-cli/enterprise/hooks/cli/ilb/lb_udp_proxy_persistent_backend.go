//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
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
	"fmt"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

func TestUDPProxyT1OnlyPersistentBackend(t T) {
	testUDPProxyPersistentBackend(t, isovalentv1alpha1.LBUDPProxyForceDeploymentModeT1)
}

func TestUDPProxyT1T2PersistentBackend(t T) {
	testUDPProxyPersistentBackend(t, isovalentv1alpha1.LBUDPProxyForceDeploymentModeT2)
}

func TestUDPProxyAutoPersistentBackend(t T) {
	testUDPProxyPersistentBackend(t, isovalentv1alpha1.LBUDPProxyForceDeploymentModeAuto)
}

func testUDPProxyPersistentBackend(t T, forceDeploymentMode isovalentv1alpha1.LBUDPProxyForceDeploymentModeType) {
	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	if skipIfOnSingleNode(">1 backends are not supported") {
		return
	}

	testName := "udp-proxy-persistent-backend-" + string(forceDeploymentMode)

	// 0. Setup test scenario (backends, clients & LB resources)
	scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating backend apps...")

	scenario.addBackendApplications(2, backendApplicationConfig{h2cEnabled: true})

	t.Log("Creating clients and add BGP peering ...")
	client := scenario.addFRRClients(1, frrClientConfig{})[0]

	t.Log("Creating LB VIP resources...")
	vip := lbVIP(testName)
	scenario.createLBVIP(vip)

	t.Log("Creating LB BackendPool resources...")
	backends := []backendPoolOption{}
	backends = append(backends, withConsistentHashing())
	for _, b := range scenario.backendApps {
		backends = append(backends, withIPBackend(b.ipv4, b.port))
	}
	backendPool := lbBackendPool(testName, backends...)
	scenario.createLBBackendPool(backendPool)

	t.Log("Creating LB Service resources...")
	service := lbService(testName, withPort(80), withUDPProxyApplication(withUDPForceDeploymentMode(forceDeploymentMode), withUDPProxyRoute(backendPool.Name, withUDPProxyBackendPersistenceBySourceIP())))
	scenario.createLBService(service)

	t.Log("Waiting for full VIP connectivity...")
	vipIP := scenario.waitForFullVIPConnectivity(testName)

	// Do a few attempts, as neither UDP nor nc are reliable.
	testCmd := fmt.Sprintf("echo -n deadbeef | nc -n -v -u -w 1 %s 80", vipIP)

	t.Log("Warming up UDP flow until backend selection is stable...")
	stabilizeUDPSessionBackend(t, client, testCmd, 5)

	t.Log("Testing UDP persistent backend with 10 requests: %q...", testCmd)
	testUDPSessionWithNRequests(t, client, testCmd, 10)
}
