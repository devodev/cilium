// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package providers

import (
	"context"
	"log/slog"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/cilium/cilium/enterprise/operator/pkg/privnet/config"
	"github.com/cilium/cilium/pkg/k8s/client"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type SecretsManager struct {
	logger           *slog.Logger
	clientset        client.Clientset
	secretsNamespace string
}

func NewSecretsManager(
	logger *slog.Logger,
	clientset client.Clientset,
	config config.Config,
) *SecretsManager {
	return &SecretsManager{
		logger:           logger,
		clientset:        clientset,
		secretsNamespace: config.AutoExternalEndpoints.SecretsNamespace,
	}
}

func (s *SecretsManager) WaitForSecret(ctx context.Context, secretName string) (map[string][]byte, error) {
	var logged bool
	var secret *slim_core_v1.Secret
	err := wait.PollUntilContextCancel(ctx, 5*time.Second, true, func(ctx context.Context) (done bool, err error) {
		secret, err = s.clientset.Slim().CoreV1().Secrets(s.secretsNamespace).Get(ctx, secretName, metav1.GetOptions{})
		if err != nil {
			if !logged {
				s.logger.Info("Kubernetes Secret not found. Retrying...",
					logfields.Secret, secretName,
					logfields.K8sNamespace, s.secretsNamespace,
					logfields.Error, err)
				logged = true
			}
			return false, nil
		}

		return true, nil
	})
	if err != nil {
		return nil, err
	}

	out := make(map[string][]byte, len(secret.Data))
	for k, v := range secret.Data {
		out[k] = v
	}
	return out, nil
}
