// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

// This file originates from Ciliums's codebase and is governed by an
// Apache 2.0 license (see original header below):
//
// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package secretsync

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	"k8s.io/apimachinery/pkg/runtime"
	ctrlRuntime "sigs.k8s.io/controller-runtime"

	operatorOption "github.com/cilium/cilium/operator/option"
	netPolSecretSync "github.com/cilium/cilium/operator/pkg/networkpolicy/secretsync"
	"github.com/cilium/cilium/operator/pkg/secretsync"
	isovalent_api_v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var Cell = cell.Module(
	"isovalent-secretsync-watcher",
	"Watches Isovalent network policy updates for TLS secrets to sync",

	cell.Provide(registerINPSecretSync),
	cell.Provide(registerICNPSecretSync),
)

type networkPolicyParams struct {
	cell.In

	Logger             *slog.Logger
	K8sClient          k8sClient.Clientset
	CtrlRuntimeManager ctrlRuntime.Manager
	Scheme             *runtime.Scheme

	AgentConfig         *option.DaemonConfig
	OperatorConfig      *operatorOption.OperatorConfig
	NetworkPolicyConfig netPolSecretSync.SecretSyncConfig
}

// registerINPSecretSync registers the Network Policy controllers for secret synchronization based on TLS secrets referenced
// by a INP resource.
func registerINPSecretSync(params networkPolicyParams) secretsync.SecretSyncRegistrationOut {
	if !params.NetworkPolicyConfig.EnablePolicySecretsSync {
		return secretsync.SecretSyncRegistrationOut{}
	}

	return secretsync.SecretSyncRegistrationOut{
		SecretSyncRegistration: &secretsync.SecretSyncRegistration{
			RefObject:            &isovalent_api_v1.IsovalentNetworkPolicy{},
			RefObjectEnqueueFunc: EnqueueTLSSecrets(params.CtrlRuntimeManager.GetClient(), params.Logger),
			RefObjectCheckFunc:   IsReferencedByIsovalentNetworkPolicy,
			SecretsNamespace:     params.NetworkPolicyConfig.PolicySecretsNamespace,
		},
	}
}

// registerICNPSecretSync registers the Network Policy controllers for secret synchronization based on TLS secrets referenced
// by a ICNP resource.
func registerICNPSecretSync(params networkPolicyParams) secretsync.SecretSyncRegistrationOut {
	if !params.NetworkPolicyConfig.EnablePolicySecretsSync {
		return secretsync.SecretSyncRegistrationOut{}
	}

	return secretsync.SecretSyncRegistrationOut{
		SecretSyncRegistration: &secretsync.SecretSyncRegistration{
			RefObject:            &isovalent_api_v1.IsovalentClusterwideNetworkPolicy{},
			RefObjectEnqueueFunc: EnqueueTLSSecrets(params.CtrlRuntimeManager.GetClient(), params.Logger),
			RefObjectCheckFunc:   IsReferencedByIsovalentClusterwideNetworkPolicy,
			SecretsNamespace:     params.NetworkPolicyConfig.PolicySecretsNamespace,
		},
	}
}

// EnqueueTLSSecrets returns a map function that, given a IsovalentNetworkPolicy or IsovalentClusterwideNetworkPolicy,
// will return a slice of requests for any Secrets referenced in that IsovalentNetworkPolicy.
//
// This includes both TLS secrets (Origination or Termination), plus Secrets used for storing header values.
func EnqueueTLSSecrets(c client.Client, logger *slog.Logger) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		objName := types.NamespacedName{
			Namespace: obj.GetNamespace(),
			Name:      obj.GetName(),
		}
		scopedLog := logger.With(
			logfields.Controller, "secrets",
			logfields.Resource, objName,
		)

		var specs []*api.Rule

		switch o := obj.(type) {
		case *isovalent_api_v1.IsovalentNetworkPolicy:
			if o.Spec != nil {
				specs = append(specs, &o.Spec.Rule)
			}
			for _, rule := range o.Specs {
				specs = append(specs, &rule.Rule)
			}
			scopedLog = scopedLog.With(logfields.Kind, "IsovalentNetworkPolicy")
		case *isovalent_api_v1.IsovalentClusterwideNetworkPolicy:
			if o.Spec != nil {
				specs = append(specs, &o.Spec.Rule)
			}
			for _, rule := range o.Specs {
				specs = append(specs, &rule.Rule)
			}
			scopedLog = scopedLog.With(logfields.Kind, "IsovalentClusterwideNetworkPolicy")
		}

		var reqs []reconcile.Request
		for _, rule := range specs {
			for _, egress := range rule.Egress {
				reqs = append(reqs, netPolSecretSync.GetReferencedTLSSecretsFromPortRules(egress.ToPorts, scopedLog)...)
				reqs = append(reqs, netPolSecretSync.GetReferencedSecretsFromHeaderRules(egress.ToPorts, scopedLog)...)
			}
			for _, ingress := range rule.Ingress {
				reqs = append(reqs, netPolSecretSync.GetReferencedTLSSecretsFromPortRules(ingress.ToPorts, scopedLog)...)
				reqs = append(reqs, netPolSecretSync.GetReferencedSecretsFromHeaderRules(ingress.ToPorts, scopedLog)...)
			}
		}
		return reqs
	})
}

func IsReferencedByIsovalentNetworkPolicy(ctx context.Context, c client.Client, logger *slog.Logger, obj *corev1.Secret) bool {
	scopedLog := logger.With(
		logfields.Controller, "netpol-inp-secretsync",
		logfields.Resource, obj.GetName(),
	)

	secretName := types.NamespacedName{
		Namespace: obj.GetNamespace(),
		Name:      obj.GetName(),
	}

	inpList := &isovalent_api_v1.IsovalentNetworkPolicyList{}
	if err := c.List(ctx, inpList); err != nil {
		scopedLog.Warn("Unable to list IsovalentNetworkPolicies", logfields.Error, err)
		return false
	}

	for _, inp := range inpList.Items {
		var rules []*api.Rule

		if inp.Spec != nil {
			rules = append(rules, &inp.Spec.Rule)
		}

		for _, rule := range inp.Specs {
			rules = append(rules, &rule.Rule)
		}

		for _, rule := range rules {
			for _, egress := range rule.Egress {
				if netPolSecretSync.IsSecretReferencedByPortRule(egress.ToPorts, scopedLog, secretName) {
					return true
				}
			}
			for _, ingress := range rule.Ingress {
				if netPolSecretSync.IsSecretReferencedByPortRule(ingress.ToPorts, scopedLog, secretName) {
					return true
				}
			}
		}
	}
	return false
}

func IsReferencedByIsovalentClusterwideNetworkPolicy(ctx context.Context, c client.Client, logger *slog.Logger, obj *corev1.Secret) bool {
	scopedLog := logger.With(
		logfields.Controller, "netpol-icnp-secretsync",
		logfields.Resource, obj.GetName(),
	)

	secretName := types.NamespacedName{
		Namespace: obj.GetNamespace(),
		Name:      obj.GetName(),
	}

	icnpList := &isovalent_api_v1.IsovalentClusterwideNetworkPolicyList{}
	if err := c.List(ctx, icnpList); err != nil {
		scopedLog.Warn("Unable to list IsovalentClusterwideNetworkPolicies", logfields.Error, err)
		return false
	}

	for _, icnp := range icnpList.Items {
		var rules []*api.Rule

		if icnp.Spec != nil {
			rules = append(rules, &icnp.Spec.Rule)
		}

		for _, rule := range icnp.Specs {
			rules = append(rules, &rule.Rule)
		}

		for _, rule := range rules {
			for _, egress := range rule.Egress {
				if netPolSecretSync.IsSecretReferencedByPortRule(egress.ToPorts, scopedLog, secretName) {
					return true
				}
			}
			for _, ingress := range rule.Ingress {
				if netPolSecretSync.IsSecretReferencedByPortRule(ingress.ToPorts, scopedLog, secretName) {
					return true
				}
			}
		}
	}

	return false
}
