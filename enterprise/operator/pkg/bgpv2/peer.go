// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package bgpv2

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/stream"
	"k8s.io/apimachinery/pkg/api/meta"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	k8s_client "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/resiliency"
	"github.com/cilium/cilium/pkg/time"
)

type peerConfigStatusReconciler struct {
	cs                 k8s_client.Clientset
	secretNamespace    string
	secretStore        resource.Store[*slim_core_v1.Secret]
	secretResource     resource.Resource[*slim_core_v1.Secret]
	bfdProfileStore    resource.Store[*v1alpha1.IsovalentBFDProfile]
	bfdProfileResource resource.Resource[*v1alpha1.IsovalentBFDProfile]
	peerConfigStore    resource.Store[*v1.IsovalentBGPPeerConfig]
	peerConfigResource resource.Resource[*v1.IsovalentBGPPeerConfig]
}

type peerConfigStatusReconcilerIn struct {
	cell.In

	Clientset    k8s_client.Clientset
	Config       config.Config
	DaemonConfig *option.DaemonConfig
	JobGroup     job.Group

	SecretResource     resource.Resource[*slim_core_v1.Secret]
	BFDProfileResource resource.Resource[*v1alpha1.IsovalentBFDProfile]
	PeerConfigResource resource.Resource[*v1.IsovalentBGPPeerConfig]
}

func registerPeerConfigStatusReconciler(in peerConfigStatusReconcilerIn) {
	if !in.Config.Enabled {
		return
	}

	u := &peerConfigStatusReconciler{
		cs:                 in.Clientset,
		secretNamespace:    in.DaemonConfig.BGPSecretsNamespace,
		secretResource:     in.SecretResource,
		bfdProfileResource: in.BFDProfileResource,
		peerConfigResource: in.PeerConfigResource,
	}

	if !in.Config.StatusReportEnabled {
		// Register a job to cleanup the conditions from the existing
		// PeerConfig resources. This is needed for the case that the
		// status report was enabled previously and some conditions
		// are already reported. Since we don't update the condition
		// anymore, remove all previously reported conditions to avoid
		// confusion.
		in.JobGroup.Add(job.OneShot(
			"cleanup-peer-config-status",
			u.cleanupStatus,
		))

		// When the status reporting is disabled, don't register the
		// status reconciler job.
		return
	}

	in.JobGroup.Add(job.OneShot(
		"peer-config-status-reconciler",
		u.reconcileStatus,
	))
}

func (u *peerConfigStatusReconciler) reconcileStatus(ctx context.Context, health cell.Health) error {
	ps, err := u.peerConfigResource.Store(ctx)
	if err != nil {
		return err
	}
	u.peerConfigStore = ps
	pe := u.peerConfigResource.Events(ctx)

	// Secret resource is initialized conditionally, only if bgp-secrets-namespace is provided.
	// If not provided, do not attempt to initialize the store. Use empty store and stucking events in that case.
	var se <-chan resource.Event[*slim_core_v1.Secret]
	if u.secretResource != nil {
		ss, err := u.secretResource.Store(ctx)
		if err != nil {
			return err
		}
		u.secretStore = ss

		// Real events
		se = u.secretResource.Events(ctx)
	} else {
		// Dummy event channel. It will never produce any event.
		stuck := stream.Stuck[resource.Event[*slim_core_v1.Secret]]()
		se = stream.ToChannel(ctx, stuck)
	}

	// BFDProfile is initialized conditionally. When BFD is
	// not enabled, it doesn't make sense to subscribe
	// BFDProfile. Use empty store and stucking events when
	// BFD is disabled (the Resource[T] is not provided).
	var be <-chan resource.Event[*v1alpha1.IsovalentBFDProfile]
	if u.bfdProfileResource != nil {
		bp, err := u.bfdProfileResource.Store(ctx)
		if err != nil {
			return err
		}
		u.bfdProfileStore = bp

		// Real events
		be = u.bfdProfileResource.Events(ctx)
	} else {
		// Dummy event channel. It will never produce any event.
		stuck := stream.Stuck[resource.Event[*v1alpha1.IsovalentBFDProfile]]()
		be = stream.ToChannel(ctx, stuck)
	}

	health.OK("Running")

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e, ok := <-se:
			if !ok {
				continue
			}
			if e.Kind == resource.Sync {
				e.Done(nil)
				continue
			}
			e.Done(u.handleSecret(ctx, e))
		case e, ok := <-be:
			if !ok {
				continue
			}
			if e.Kind == resource.Sync {
				e.Done(nil)
				continue
			}
			e.Done(u.handleBFDProfile(ctx, e))
		case e, ok := <-pe:
			if !ok {
				continue
			}
			if e.Kind != resource.Upsert {
				e.Done(nil)
				continue
			}
			e.Done(u.reconcilePeerConfig(ctx, e.Object))
		}
	}
}

func (u *peerConfigStatusReconciler) cleanupStatus(ctx context.Context, health cell.Health) error {
	pcs, err := u.peerConfigResource.Store(ctx)
	if err != nil {
		return err
	}

	remaining := sets.New[resource.Key]()

	iter := pcs.IterKeys()
	for iter.Next() {
		remaining.Insert(iter.Key())
	}

	// Ensure all conditions managed by this
	// controller are removed from all resources.
	// Retry until we remove conditions from all
	// existing resources.
	err = resiliency.Retry(ctx, 3*time.Second, 20, func(ctx context.Context, _ int) (bool, error) {
		removed := sets.New[resource.Key]()

		for k := range remaining {
			pc, exists, err := pcs.GetByKey(k)
			if err != nil {
				// Failed to get the resource. Skip and retry.
				continue
			}

			// The resource doesn't exist anymore which is fine.
			if !exists {
				removed.Insert(k)
				continue
			}

			updateStatus := false
			for _, cond := range v1.AllBGPPeerConfigConditions {
				if removed := meta.RemoveStatusCondition(&pc.Status.Conditions, cond); removed {
					updateStatus = true
				}
			}

			if updateStatus {
				if _, err := u.cs.IsovalentV1().IsovalentBGPPeerConfigs().UpdateStatus(ctx, pc, meta_v1.UpdateOptions{}); err != nil {
					// Failed to update status. Skip and retry.
					continue
				} else {
					removed.Insert(k)
				}
			}
		}

		remaining = remaining.Difference(removed)

		return len(remaining) == 0, nil
	})

	// We use OK here since the semantics of Stopped() in the OneShot job is still undefined.
	if err == nil {
		health.OK("Cleanup job is done successfully")
	}

	return err
}

func (u *peerConfigStatusReconciler) reconcilePeerConfig(ctx context.Context, config *v1.IsovalentBGPPeerConfig) error {
	updateStatus := false

	authSecretConfigured, authSecretMissing := u.authSecretMissing(config)
	bfdProfileConfigured, bfdProfileMissing := u.bfdProfileMissing(config)

	if changed := u.updateMissingAuthSecretCondition(config, authSecretConfigured, authSecretMissing); changed {
		updateStatus = true
	}
	if changed := u.updateMissingBFDProfileCondition(config, bfdProfileConfigured, bfdProfileMissing); changed {
		updateStatus = true
	}

	slices.SortStableFunc(config.Status.Conditions, func(a, b meta_v1.Condition) int {
		return strings.Compare(a.Type, b.Type)
	})

	if updateStatus {
		if _, err := u.cs.IsovalentV1().IsovalentBGPPeerConfigs().UpdateStatus(ctx, config, meta_v1.UpdateOptions{}); err != nil {
			return err
		}
	}

	return nil
}

func (u *peerConfigStatusReconciler) authSecretMissing(c *v1.IsovalentBGPPeerConfig) (isConfigured bool, isMissing bool) {
	if u.secretStore == nil || c.Spec.AuthSecretRef == nil {
		return false, false
	}
	if _, exists, _ := u.secretStore.GetByKey(resource.Key{Namespace: u.secretNamespace, Name: *c.Spec.AuthSecretRef}); !exists {
		return true, true
	}
	return true, false
}

func (u *peerConfigStatusReconciler) updateMissingAuthSecretCondition(config *v1.IsovalentBGPPeerConfig, configured, missing bool) bool {
	cond := meta_v1.Condition{
		Type:               v1.BGPPeerConfigConditionMissingAuthSecret,
		Status:             meta_v1.ConditionFalse,
		ObservedGeneration: config.Generation,
		LastTransitionTime: meta_v1.Now(),
		Message:            "",
		Reason:             "AuthSecretValidated",
	}
	if !configured {
		cond.Status = meta_v1.ConditionFalse
		cond.Message = "Auth Secret is not configured"
		cond.Reason = "AuthSecretNotConfigured"
	}
	if missing && configured {
		cond.Status = meta_v1.ConditionTrue
		cond.Message = fmt.Sprintf("Referenced Auth Secret %q is missing", *config.Spec.AuthSecretRef)
		cond.Reason = "AuthSecretMissing"
	}
	return meta.SetStatusCondition(&config.Status.Conditions, cond)
}

func (u *peerConfigStatusReconciler) bfdProfileMissing(c *v1.IsovalentBGPPeerConfig) (isConfigured bool, isMissing bool) {
	if u.bfdProfileStore == nil {
		// If BFD is disabled, always false.
		return false, false
	}
	if c.Spec.BFDProfileRef == nil {
		return false, false
	}
	if _, exists, _ := u.bfdProfileStore.GetByKey(resource.Key{Name: *c.Spec.BFDProfileRef}); !exists {
		return true, true
	}
	return true, false
}

func (u *peerConfigStatusReconciler) updateMissingBFDProfileCondition(config *v1.IsovalentBGPPeerConfig, configured, missing bool) bool {
	cond := meta_v1.Condition{
		Type:               v1.BGPPeerConfigConditionMissingBFDProfile,
		Status:             meta_v1.ConditionFalse,
		ObservedGeneration: config.Generation,
		LastTransitionTime: meta_v1.Now(),
		Message:            "",
		Reason:             "BFDProfileValidated",
	}
	if !configured {
		cond.Status = meta_v1.ConditionFalse
		cond.Message = "BFD Profile is not configured"
		cond.Reason = "BFDProfileNotConfigured"
	}
	if missing && configured {
		cond.Status = meta_v1.ConditionTrue
		cond.Message = fmt.Sprintf("Referenced BFP Profile %q is missing", *config.Spec.BFDProfileRef)
		cond.Reason = "BFDProfileMissing"
	}
	return meta.SetStatusCondition(&config.Status.Conditions, cond)
}

func (u *peerConfigStatusReconciler) handleSecret(ctx context.Context, e resource.Event[*slim_core_v1.Secret]) error {
	// Reconcile all peer configs that reference this secret. This is a bit
	// inefficient but since we don't expect a large number of PeerConfigs
	// or Secret in the BGP Secret namespace, this is acceptable.
	for _, pc := range u.peerConfigStore.List() {
		if pc.Spec.AuthSecretRef == nil {
			continue
		}
		if *pc.Spec.AuthSecretRef != e.Key.Name {
			continue
		}
		if err := u.reconcilePeerConfig(ctx, pc); err != nil {
			return err
		}
	}
	return nil
}

func (u *peerConfigStatusReconciler) handleBFDProfile(ctx context.Context, e resource.Event[*v1alpha1.IsovalentBFDProfile]) error {
	// Reconcile all peer configs that reference this BFDProfile. This is a bit
	// inefficient but since we don't expect a large number of PeerConfigs
	// or BFDProfile, this is acceptable.
	for _, pc := range u.peerConfigStore.List() {
		if pc.Spec.BFDProfileRef == nil {
			continue
		}
		if *pc.Spec.BFDProfileRef != e.Key.Name {
			continue
		}
		if err := u.reconcilePeerConfig(ctx, pc); err != nil {
			return err
		}
	}
	return nil
}
