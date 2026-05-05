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
	"time"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	slimlabels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
)

const (
	networkPolicyPollInterval      = 2 * time.Second
	networkPolicyEgressPollTimeout = 3 * time.Minute
)

func createNetworkPolicy(ctx context.Context, run *TestRun, policy *isovalentv1alpha1.IsovalentNetworkPolicy) error {
	fmt.Fprintf(run.out, "Creating IsovalentNetworkPolicy %s/%s...\n", policy.Namespace, policy.Name)

	if _, err := run.client.EnterpriseCiliumClientset.IsovalentV1alpha1().IsovalentNetworkPolicies(policy.Namespace).Create(ctx, policy, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("failed creating IsovalentNetworkPolicy %s/%s: %w", policy.Namespace, policy.Name, err)
	}

	err := wait.PollUntilContextTimeout(ctx, networkPolicyPollInterval, networkPolicyEgressPollTimeout, true, func(ctx context.Context) (bool, error) {
		_, err := run.client.EnterpriseCiliumClientset.IsovalentV1alpha1().IsovalentNetworkPolicies(policy.Namespace).Get(ctx, policy.Name, metav1.GetOptions{})
		if k8serrors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return true, nil
	})
	if err != nil {
		return fmt.Errorf("failed waiting for IsovalentNetworkPolicy %s/%s to exist: %w", policy.Namespace, policy.Name, err)
	}
	return nil
}

func deleteNetworkPolicy(ctx context.Context, run *TestRun, name string) error {
	fmt.Fprintf(run.out, "Deleting IsovalentNetworkPolicy %s/%s...\n", run.params.TestNamespace, name)

	err := run.client.EnterpriseCiliumClientset.IsovalentV1alpha1().IsovalentNetworkPolicies(run.params.TestNamespace).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil && !k8serrors.IsNotFound(err) {
		return fmt.Errorf("failed deleting IsovalentNetworkPolicy %s/%s: %w", run.params.TestNamespace, name, err)
	}

	err = wait.PollUntilContextTimeout(ctx, networkPolicyPollInterval, networkPolicyEgressPollTimeout, true, func(ctx context.Context) (bool, error) {
		_, err := run.client.EnterpriseCiliumClientset.IsovalentV1alpha1().IsovalentNetworkPolicies(run.params.TestNamespace).Get(ctx, name, metav1.GetOptions{})
		if k8serrors.IsNotFound(err) {
			return true, nil
		}
		if err != nil {
			return false, err
		}
		return false, nil
	})
	if err != nil {
		return fmt.Errorf("failed waiting for IsovalentNetworkPolicy %s/%s to be deleted: %w", run.params.TestNamespace, name, err)
	}
	return nil
}

func cleanupTestPolicies(ctx context.Context, run *TestRun, testName string) error {
	labels := testResourceLabels(testName)

	list, err := run.client.EnterpriseCiliumClientset.IsovalentV1alpha1().IsovalentNetworkPolicies(run.params.TestNamespace).List(ctx, metav1.ListOptions{
		LabelSelector: slimlabels.FormatLabels(labels),
	})
	if err != nil {
		return err
	}
	for i := range list.Items {
		if err := run.client.EnterpriseCiliumClientset.IsovalentV1alpha1().IsovalentNetworkPolicies(run.params.TestNamespace).Delete(ctx, list.Items[i].Name, metav1.DeleteOptions{}); err != nil && !k8serrors.IsNotFound(err) {
			return err
		}
	}

	return wait.PollUntilContextTimeout(ctx, networkPolicyPollInterval, networkPolicyEgressPollTimeout, true, func(ctx context.Context) (bool, error) {
		list, err := run.client.EnterpriseCiliumClientset.IsovalentV1alpha1().IsovalentNetworkPolicies(run.params.TestNamespace).List(ctx, metav1.ListOptions{
			LabelSelector: slimlabels.FormatLabels(labels),
		})
		if err != nil {
			return false, err
		}
		return len(list.Items) == 0, nil
	})
}

func waitForExpectedPolicyResult(ctx context.Context, description string, check func(context.Context) error) error {
	var lastErr error

	err := wait.PollUntilContextTimeout(ctx, networkPolicyPollInterval, networkPolicyEgressPollTimeout, true, func(ctx context.Context) (bool, error) {
		if err := check(ctx); err != nil {
			lastErr = err
			return false, nil
		}

		lastErr = nil
		return true, nil
	})
	if err == nil {
		return nil
	}
	if lastErr != nil {
		return fmt.Errorf("failed waiting for %s: %w", description, lastErr)
	}
	return fmt.Errorf("failed waiting for %s: %w", description, err)
}
