//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package check

import (
	"context"
	"errors"
	"fmt"
	"maps"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	enterpriseK8s "github.com/cilium/cilium/cilium-cli/enterprise/hooks/k8s"
	isovalentv1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

// createOrUpdateIEGP creates the IEGP and updates it if it already exists.
func createOrUpdateIEGP(ctx context.Context, client *enterpriseK8s.EnterpriseClient, iegp *isovalentv1.IsovalentEgressGatewayPolicy) error {
	_, err := check.CreateOrUpdatePolicy(ctx, client.EnterpriseCiliumClientset.IsovalentV1().IsovalentEgressGatewayPolicies(),
		iegp, func(current *isovalentv1.IsovalentEgressGatewayPolicy) bool {
			if maps.Equal(current.GetLabels(), iegp.GetLabels()) &&
				current.Spec.DeepEqual(&iegp.Spec) {
				return false
			}

			current.ObjectMeta.Labels = iegp.ObjectMeta.Labels
			current.Spec = iegp.Spec
			return true
		})

	return err
}

// deleteIEGP deletes an IsovalentEgressGatewayPolicy from the cluster.
func deleteIEGP(ctx context.Context, client *enterpriseK8s.EnterpriseClient, iegp *isovalentv1.IsovalentEgressGatewayPolicy) error {
	if err := client.DeleteIsovalentEgressGatewayPolicy(ctx, iegp.Name, metav1.DeleteOptions{}); err != nil {
		return fmt.Errorf("%s/%s policy delete failed: %w", client.ClusterName(), iegp.Name, err)
	}

	return nil
}

// createOrUpdateIMG creates the IMG and updates it if it already exists.
func createOrUpdateIMG(ctx context.Context, client *enterpriseK8s.EnterpriseClient, img *isovalentv1alpha1.IsovalentMulticastGroup) error {
	_, err := client.CreateIsovalentMulticastGroup(ctx, img, metav1.CreateOptions{})
	if err == nil {
		return nil
	}

	if !k8serrors.IsAlreadyExists(err) {
		return err
	}

	// Group is modified, update it.
	mcastGroup, err := client.GetIsovalentMulticastGroup(ctx, img.Name, metav1.GetOptions{})
	if err != nil {
		//
		return fmt.Errorf("failed to retrieve isovalent multicast group %s: %w", img.Name, err)
	}

	// override spec
	mcastGroup.Spec = img.Spec

	_, err = client.UpdateIsovalentMulticastGroup(ctx, mcastGroup, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update isovalent multicast group %s: %w", img.Name, err)
	}

	return nil
}

// deleteIMG deletes a IsovalentMulticastGroup from the cluster.
func deleteIMG(ctx context.Context, client *enterpriseK8s.EnterpriseClient, img *isovalentv1alpha1.IsovalentMulticastGroup) error {
	if err := client.DeleteIsovalentMulticastGroup(ctx, img.Name, metav1.DeleteOptions{}); err != nil {
		return fmt.Errorf("%s/%s group delete failed: %w", client.ClusterName(), img.Name, err)
	}

	return nil
}

// addIEGPs adds one or more IsovalentEgressGatewayPolicy resources to the Test.
func (t *EnterpriseTest) addIEGPs(iegps ...*isovalentv1.IsovalentEgressGatewayPolicy) (err error) {
	t.iegps, err = check.RegisterPolicy(t.iegps, iegps...)
	return err
}

// addimg adds one or more IsovalentMulticastGroup resources to the Test.
func (t *EnterpriseTest) addIMGs(imgs ...*isovalentv1alpha1.IsovalentMulticastGroup) error {
	for _, p := range imgs {
		if p == nil {
			return errors.New("cannot add nil IsovalentMulticastGroup to test")
		}
		if p.Name == "" {
			return fmt.Errorf("adding IsovalentMulticastGroup with empty name to test: %v", p)
		}
		if _, ok := t.imgs[p.Name]; ok {
			return fmt.Errorf("IsovalentMulticastGroup with name %s already in test scope", p.Name)
		}

		t.imgs[p.Name] = p
	}

	return nil
}

// addICEPs adds one or more IsovalentClusterwideEncryptionPolicy resources to the Test.
func (t *EnterpriseTest) addICEPs(iceps ...*isovalentv1alpha1.IsovalentClusterwideEncryptionPolicy) (err error) {
	t.iceps, err = check.RegisterPolicy(t.iceps, iceps...)
	return err
}

func (t *EnterpriseTest) addInspectionConfig(cfg *isovalentv1alpha1.IsovalentInspectionConfig) error {
	if cfg == nil {
		return errors.New("cannot add nil IsovalentInspectionConfig to test")
	}
	if cfg.Name != isovalentv1alpha1.InspectionConfigName {
		return fmt.Errorf("IsovalentInspectionConfig must use singleton name %q", isovalentv1alpha1.InspectionConfigName)
	}
	if t.inspectionConfig != nil {
		return fmt.Errorf("IsovalentInspectionConfig %q already registered in test scope", t.inspectionConfig.Name)
	}

	t.inspectionConfig = cfg
	return nil
}

// applyPolicies applies all the Test's registered network policies.
func (t *EnterpriseTest) applyPolicies(ctx context.Context) error {
	if len(t.iegps) == 0 && len(t.imgs) == 0 && len(t.iceps) == 0 && t.inspectionConfig == nil {
		return nil
	}

	// Apply all given Cilium Egress Gateway Policies.
	for _, iegp := range t.iegps {
		for _, client := range t.Context().clients.clients() {
			t.Infof("📜 Applying IsovalentEgressGatewayPolicy '%s' to namespace '%s'..", iegp.Name, iegp.Namespace)
			if err := createOrUpdateIEGP(ctx, client, iegp); err != nil {
				return fmt.Errorf("policy application failed: %w", err)
			}
		}
	}

	// Apply all given Isovalent Multicast groups
	for _, img := range t.imgs {
		for _, client := range t.Context().clients.clients() {
			t.Infof("📜 Applying IsovalentMulticastGroup '%s' to namespace '%s'..", img.Name, img.Namespace)
			if err := createOrUpdateIMG(ctx, client, img); err != nil {
				return fmt.Errorf("policy application failed: %w", err)
			}
		}
	}

	// Delete all the Test's iceps from all Clients.
	for _, icep := range t.iceps {
		t.Infof("📜 Applying IsovalentClusterwideEncryptionPolicy '%s'..", icep.Name)
		for _, client := range t.Context().clients.clients() {
			if _, err := client.ApplyGeneric(ctx, icep); err != nil {
				return fmt.Errorf("applying IsovalentClusterwideEncryptionPolicy failed: %w", err)
			}
		}
	}

	if t.inspectionConfig != nil {
		t.Infof("📜 Applying IsovalentInspectionConfig '%s'..", t.inspectionConfig.Name)
		for _, client := range t.Context().clients.clients() {
			current, err := client.GetIsovalentInspectionConfig(ctx, t.inspectionConfig.Name, metav1.GetOptions{})
			if err != nil && !k8serrors.IsNotFound(err) {
				return fmt.Errorf("retrieving IsovalentInspectionConfig failed: %w", err)
			}
			if err == nil {
				key := fmt.Sprintf("%s/%s", client.ClusterName(), t.inspectionConfig.Name)
				t.originalInspectionConfigs[key] = current.DeepCopy()
			}
			if _, err := client.ApplyGeneric(ctx, t.inspectionConfig); err != nil {
				return fmt.Errorf("applying IsovalentInspectionConfig failed: %w", err)
			}
		}
	}

	// Register a finalizer with the Test immediately to enable cleanup.
	// If we return a cleanup closure from this function, cleanup cannot be
	// performed if the user cancels during the policy revision wait time.
	t.WithFinalizer(func(_ context.Context) error {
		// Use a detached context to make sure this call is not affected by
		// context cancellation. This deletion needs to happen event when the
		// user interrupted the program.
		if err := t.deletePolicies(context.TODO()); err != nil {
			t.ContainerLogs(ctx)
			return err
		}

		return nil
	})

	if len(t.iegps) > 0 {
		t.Debugf("📜 Successfully applied %d IsovalentEgressGatewayPolicies", len(t.iegps))
	}

	if len(t.imgs) > 0 {
		t.Debugf("📜 Successfully applied %d IsovalentMulticastGroups", len(t.imgs))
	}

	if len(t.iceps) > 0 {
		t.Debugf("📜 Successfully applied %d IsovalentClusterwideEncryptionPolicies", len(t.iceps))
	}

	if t.inspectionConfig != nil {
		t.Debugf("📜 Successfully applied IsovalentInspectionConfig %q", t.inspectionConfig.Name)
	}

	return nil
}

// deletePolicies deletes a given set of network policies from the cluster.
func (t *EnterpriseTest) deletePolicies(ctx context.Context) error {
	if len(t.iegps) == 0 && len(t.imgs) == 0 && len(t.iceps) == 0 && t.inspectionConfig == nil {
		return nil
	}

	// Delete all the Test's iegps from all clients.
	for _, iegp := range t.iegps {
		t.Infof("📜 Deleting IsovalentEgressGatewayPolicy '%s' from namespace '%s'..", iegp.Name, iegp.Namespace)
		for _, client := range t.Context().clients.clients() {
			if err := deleteIEGP(ctx, client, iegp); err != nil {
				return fmt.Errorf("deleting IsovalentEgressGatewayPolicy: %w", err)
			}
		}
	}

	// Delete all the Test's imgs from all Clients.
	for _, img := range t.imgs {
		t.Infof("📜 Deleting IsovalentMulticastGroup '%s' from namespace '%s'..", img.Name, img.Namespace)
		for _, client := range t.Context().clients.clients() {
			if err := deleteIMG(ctx, client, img); err != nil {
				return fmt.Errorf("deleting IsovalentMulticastGroup: %w", err)
			}
		}
	}

	// Delete all the Test's iceps from all Clients.
	for _, icep := range t.iceps {
		t.Infof("📜 Deleting IsovalentClusterwideEncryptionPolicy '%s'..", icep.Name)
		for _, client := range t.Context().clients.clients() {
			if err := client.DeleteGeneric(ctx, icep); err != nil {
				return fmt.Errorf("deleting IsovalentClusterwideEncryptionPolicy : %w", err)
			}
		}
	}

	if t.inspectionConfig != nil {
		t.Infof("📜 Restoring IsovalentInspectionConfig '%s'..", t.inspectionConfig.Name)
		for _, client := range t.Context().clients.clients() {
			key := fmt.Sprintf("%s/%s", client.ClusterName(), t.inspectionConfig.Name)
			if originalConfig, ok := t.originalInspectionConfigs[key]; ok {
				if _, err := client.ApplyGeneric(ctx, originalConfig); err != nil {
					return fmt.Errorf("restoring IsovalentInspectionConfig: %w", err)
				}
				continue
			}
			if err := client.DeleteGeneric(ctx, t.inspectionConfig); err != nil && !k8serrors.IsNotFound(err) {
				return fmt.Errorf("deleting IsovalentInspectionConfig: %w", err)
			}
		}
	}

	if len(t.iegps) > 0 {
		t.Debugf("📜 Successfully deleted %d IsovalentEgressGatewayPolicies", len(t.iegps))
	}

	if len(t.imgs) > 0 {
		t.Debugf("📜 Successfully deleted %d IsovalentMulticastGroups", len(t.imgs))
	}

	if len(t.iceps) > 0 {
		t.Debugf("📜 Successfully deleted %d IsovalentClusterwideEncryptionPolicies", len(t.iceps))
	}

	if t.inspectionConfig != nil {
		t.Debugf("📜 Successfully restored/deleted IsovalentInspectionConfig %q", t.inspectionConfig.Name)
	}

	return nil
}
