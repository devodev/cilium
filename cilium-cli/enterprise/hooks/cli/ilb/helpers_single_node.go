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
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8s "k8s.io/client-go/kubernetes"
)

func IsSingleNode() bool {
	return FlagMode == "single-node"
}

func useRemoteAddressEnabled() bool {
	return FlagUseRemoteAddress
}

func useRemoteAddressDisabled() bool {
	return !FlagUseRemoteAddress
}

func xffNumTrustedHopsEnabled() bool {
	return FlagXffNumTrustedHops > 0
}

func xffNumTrustedHopsDisabled() bool {
	return FlagXffNumTrustedHops <= 0
}

func getSingleNodeIPAddr() string {
	return FlagSingleNodeIPAddr
}

func getSingleNodeIPv6Addr() string {
	return FlagSingleNodeIPv6Addr
}

func skipIfOnSingleNode(msg string) bool {
	if IsSingleNode() {
		fmt.Printf("skipping due to single-mode: %s\n", msg)
		return true
	}

	return false
}

func skipIfNotUseRemoteAddress(msg string) bool {
	if useRemoteAddressDisabled() {
		fmt.Printf("skipping due to not using remote address: %s\n", msg)
		return true
	}

	return false
}

func skipIfWAFDisabled(t T, k8sCli *k8s.Clientset, msg string) bool {
	configmap, err := k8sCli.CoreV1().ConfigMaps(t.CiliumNamespace()).Get(t.Context(), "cilium-config", metav1.GetOptions{})
	if err != nil {
		t.Failedf("failed to get cilium-config: %s", err)
		return true
	}

	if strings.EqualFold(configmap.Data["waf-enabled"], "true") {
		return false
	}

	fmt.Printf("skipping due to WAF being disabled: %s\n", msg)
	return true
}

func SetupSingleNodeMode(ctx context.Context, dockerCli *dockerCli, k8sCli *k8s.Clientset) error {
	if FlagSingleNodeIPAddr != "" {
		return nil
	}

	if err := dockerCli.EnsureImage(ctx, FlagUtilsImage); err != nil {
		return fmt.Errorf("failed to ensure %s image: %w", FlagUtilsImage, err)
	}

	ipv4s, ipv6s, err := getT1NodeIPs(ctx, k8sCli)
	if err != nil {
		return fmt.Errorf("failed to derive T1 node IP addrs: %w", err)
	}

	if err := deriveSingleNodeIP(ctx, dockerCli, ipv4s, ipv6s); err != nil {
		return fmt.Errorf("failed to derive single-node IP addr (you can set -single-node-ip): %w", err)
	}

	fmt.Printf("Derived single-node IP addr: %s\n", getSingleNodeIPAddr())

	return nil
}

func deriveSingleNodeIP(ctx context.Context, dockerCli *dockerCli, t1NodeIPv4Addrs []string, t1NodeIPv6Addrs []string) error {
	name := "single-node-ip"

	// It will run in the single-node's host netns
	_, _, _, err := dockerCli.createContainer(ctx, name, FlagUtilsImage, nil, "", false, []string{"sleep", "infinity"}, nil)
	if err != nil {
		return fmt.Errorf("failed to start %s: %w", name, err)
	}
	defer dockerCli.deleteContainer(ctx, name)

	if len(t1NodeIPv4Addrs) > 0 {
		ipv4, _, err := dockerCli.ContainerExec(ctx, name,
			[]string{
				"/bin/sh", "-c",
				fmt.Sprintf("ip -4 route get %s | grep -o 'src [0-9\\.]*' | cut -d' ' -f2", t1NodeIPv4Addrs[0]),
			})
		ipv4 = strings.TrimSpace(ipv4)
		if err != nil {
			return fmt.Errorf("failed to get route to %s: %w", t1NodeIPv4Addrs[0], err)
		}

		FlagSingleNodeIPAddr = ipv4
	}

	if len(t1NodeIPv6Addrs) > 0 {
		ipv6, _, err := dockerCli.ContainerExec(ctx, name,
			[]string{
				"/bin/sh", "-c",
				fmt.Sprintf("ip -6 route get %s | grep -o 'src [0-9\\.]*' | cut -d' ' -f2", t1NodeIPv6Addrs[0]),
			})
		ipv6 = strings.TrimSpace(ipv6)
		if err != nil {
			return fmt.Errorf("failed to get route to %s: %w", t1NodeIPv6Addrs[0], err)
		}

		FlagSingleNodeIPv6Addr = ipv6
	}

	return nil
}
