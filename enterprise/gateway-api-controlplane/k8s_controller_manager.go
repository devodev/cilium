//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/discovery"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlcache "sigs.k8s.io/controller-runtime/pkg/cache"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

type controllerRuntimeManagerParams struct {
	cell.In

	Logger   *slog.Logger
	Config   Config
	JobGroup job.Group
}

func newControllerRuntimeManager(params controllerRuntimeManagerParams) (ctrl.Manager, error) {
	scheme := runtime.NewScheme()
	if err := gatewayv1.Install(scheme); err != nil {
		return nil, fmt.Errorf("failed to install Gateway API scheme: %w", err)
	}

	restConfig, err := ctrl.GetConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get Kubernetes rest config: %w", err)
	}

	ctrl.SetLogger(logr.FromSlogHandler(params.Logger.Handler()))

	mgr, err := ctrl.NewManager(restConfig, ctrl.Options{
		Scheme: scheme,
		Cache: ctrlcache.Options{
			DefaultNamespaces: map[string]ctrlcache.Config{
				params.Config.GatewayNamespace: {},
			},
		},
		Metrics: metricsserver.Options{
			BindAddress: "0",
		},
		HealthProbeBindAddress: "0",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create controller manager: %w", err)
	}

	params.JobGroup.Add(job.OneShot("k8s-controller-manager", func(ctx context.Context, health cell.Health) error {
		params.Logger.Info("Checking whether Gateway API resources are installed")
		exists, err := gatewayAPIResourcesExist(params.Logger)
		if err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("Gateway API resources are not installed")
		}
		params.Logger.Info("Gateway API resources are installed")

		params.Logger.Info("Starting K8s controller manager")
		health.OK("K8s controller manager is running")
		return mgr.Start(ctx)
	}, job.WithShutdown()))

	return mgr, nil
}

func gatewayAPIResourcesExist(logger *slog.Logger) (bool, error) {
	restConfig, err := ctrl.GetConfig()
	if err != nil {
		return false, fmt.Errorf("failed to get Kubernetes rest config: %w", err)
	}

	discoveryClient, err := discovery.NewDiscoveryClientForConfig(restConfig)
	if err != nil {
		return false, fmt.Errorf("failed to create discovery client: %w", err)
	}

	resourceList, err := discoveryClient.ServerResourcesForGroupVersion(gatewayv1.GroupVersion.String())
	if err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		if discovery.IsGroupDiscoveryFailedError(err) {
			logger.Info("Gateway API discovery failed, skipping Gateway controller", logfields.Error, err)
			return false, nil
		}
		return false, fmt.Errorf("failed to discover Gateway API resources: %w", err)
	}

	hasGateway := false
	for _, resource := range resourceList.APIResources {
		switch resource.Kind {
		case "Gateway":
			hasGateway = true
		}
	}

	return hasGateway, nil
}
