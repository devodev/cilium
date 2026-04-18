//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package vrf

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
)

// vrfStatusReporter reports VRF status.
type vrfStatusReporter interface {
	init(ctx context.Context) error
	setVRFStatuses(ctx context.Context, batch *vrfStatusBatch) error
	clearAllVRFStatuses(ctx context.Context) error
	setMembershipConflicts(ctx context.Context, conflicts map[string]string) error
}

type vrfStatusEntry struct {
	condition string
	ready     bool
	message   string
}

// vrfStatusBatch is the complete intended state of status.VRFs for one
// node-scoped IsovalentCoreVRFNodeStatus CR. Each entry is a "set" of
// per-VRF status; absence from the map means the VRF has no status entry on
// the CR. setVRFStatuses applies it as a snapshot replace.
type vrfStatusBatch struct {
	entries map[string]vrfStatusEntry
}

func newVRFStatusBatch() *vrfStatusBatch {
	return &vrfStatusBatch{entries: map[string]vrfStatusEntry{}}
}

func (b *vrfStatusBatch) set(vrfName, condition string, ready bool, message string) {
	b.entries[vrfName] = vrfStatusEntry{
		condition: condition,
		ready:     ready,
		message:   message,
	}
}

// k8sVRFStatusReporter manages an IsovalentCoreVRFNodeStatus CR per node.
type k8sVRFStatusReporter struct {
	clientset client.Clientset
	nodeName  string
}

func newK8sVRFStatusReporter(cs client.Clientset, nodeName string) vrfStatusReporter {
	return &k8sVRFStatusReporter{clientset: cs, nodeName: nodeName}
}

// init creates the IsovalentCoreVRFNodeStatus CR for this node if it doesn't exist.
func (r *k8sVRFStatusReporter) init(ctx context.Context) error {
	return retry.OnError(retry.DefaultBackoff, isTransientAPIError, func() error {
		_, err := r.clientset.IsovalentV1alpha1().IsovalentCoreVRFNodeStatuses().Get(ctx, r.nodeName, metav1.GetOptions{})
		if err == nil {
			return nil
		}
		if !errors.IsNotFound(err) {
			return fmt.Errorf("failed to get IsovalentCoreVRFNodeStatus %q: %w", r.nodeName, err)
		}

		cr := &isovalentv1alpha1.IsovalentCoreVRFNodeStatus{
			ObjectMeta: metav1.ObjectMeta{
				Name: r.nodeName,
			},
		}
		_, err = r.clientset.IsovalentV1alpha1().IsovalentCoreVRFNodeStatuses().Create(ctx, cr, metav1.CreateOptions{})
		if errors.IsAlreadyExists(err) {
			return nil
		}
		return err
	})
}

func isTransientAPIError(err error) bool {
	return errors.IsServerTimeout(err) ||
		errors.IsServiceUnavailable(err) ||
		errors.IsTooManyRequests(err) ||
		errors.IsTimeout(err) ||
		errors.IsInternalError(err)
}

// updateStatus performs a read-modify-write on the status subresource.
func (r *k8sVRFStatusReporter) updateStatus(ctx context.Context, update func(*isovalentv1alpha1.IsovalentCoreVRFNodeStatusStatus)) error {
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		cr, err := r.clientset.IsovalentV1alpha1().IsovalentCoreVRFNodeStatuses().Get(ctx, r.nodeName, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("failed to get IsovalentCoreVRFNodeStatus %q: %w", r.nodeName, err)
		}

		if cr.Status.VRFs == nil {
			cr.Status.VRFs = make(map[string]isovalentv1alpha1.IsovalentCoreVRFStatus)
		}

		update(&cr.Status)

		_, err = r.clientset.IsovalentV1alpha1().IsovalentCoreVRFNodeStatuses().UpdateStatus(ctx, cr, metav1.UpdateOptions{})
		return err
	})
}

// applySet mutates vrfStatus in place. clears all error conditions, then
// applies the supplied condition/ready/message.
func applySet(vrfStatus *isovalentv1alpha1.IsovalentCoreVRFStatus, condition string, ready bool, message string) {
	meta.RemoveStatusCondition(&vrfStatus.Conditions, isovalentv1alpha1.VRFConditionInterfaceNotFound)
	meta.RemoveStatusCondition(&vrfStatus.Conditions, isovalentv1alpha1.VRFConditionConflictingTableID)
	meta.RemoveStatusCondition(&vrfStatus.Conditions, isovalentv1alpha1.VRFConditionConflictingID)
	meta.RemoveStatusCondition(&vrfStatus.Conditions, isovalentv1alpha1.VRFConditionInterfaceFailure)
	meta.RemoveStatusCondition(&vrfStatus.Conditions, isovalentv1alpha1.VRFConditionUpdateFailure)

	if ready {
		meta.SetStatusCondition(&vrfStatus.Conditions, metav1.Condition{
			Type:    isovalentv1alpha1.VRFConditionReady,
			Status:  metav1.ConditionTrue,
			Reason:  "Active",
			Message: message,
		})
		return
	}

	meta.SetStatusCondition(&vrfStatus.Conditions, metav1.Condition{
		Type:    condition,
		Status:  metav1.ConditionTrue,
		Reason:  "Pending",
		Message: message,
	})
	meta.SetStatusCondition(&vrfStatus.Conditions, metav1.Condition{
		Type:    isovalentv1alpha1.VRFConditionReady,
		Status:  metav1.ConditionFalse,
		Reason:  "Pending",
		Message: message,
	})
}

// setVRFStatuses replaces status.VRFs with the snapshot in batch:
// any name on the CR that is absent from batch is removed, and any name
// present has applySet applied to it. A nil batch is a no-op.
func (r *k8sVRFStatusReporter) setVRFStatuses(ctx context.Context, batch *vrfStatusBatch) error {
	if batch == nil {
		return nil
	}
	return r.updateStatus(ctx, func(status *isovalentv1alpha1.IsovalentCoreVRFNodeStatusStatus) {
		if status.VRFs == nil {
			status.VRFs = map[string]isovalentv1alpha1.IsovalentCoreVRFStatus{}
		}
		for name := range status.VRFs {
			if _, keep := batch.entries[name]; !keep {
				delete(status.VRFs, name)
			}
		}
		for name, entry := range batch.entries {
			vrfStatus := status.VRFs[name]
			applySet(&vrfStatus, entry.condition, entry.ready, entry.message)
			status.VRFs[name] = vrfStatus
		}
	})
}

func (r *k8sVRFStatusReporter) clearAllVRFStatuses(ctx context.Context) error {
	return r.updateStatus(ctx, func(status *isovalentv1alpha1.IsovalentCoreVRFNodeStatusStatus) {
		clear(status.VRFs)
		status.MembershipConflicts = nil
	})
}

func (r *k8sVRFStatusReporter) setMembershipConflicts(ctx context.Context, conflicts map[string]string) error {
	return r.updateStatus(ctx, func(status *isovalentv1alpha1.IsovalentCoreVRFNodeStatusStatus) {
		if len(conflicts) == 0 {
			status.MembershipConflicts = nil
			return
		}
		status.MembershipConflicts = conflicts
	})
}
