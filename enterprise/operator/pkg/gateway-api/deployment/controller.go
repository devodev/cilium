//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package deployment

import (
	"context"
	"log/slog"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	controllerName = "io.cilium/gateway-deployment-controller"
)

func gatewayOwnedByControllerFunc(ctx context.Context, c client.Client, logger *slog.Logger) func(object client.Object) bool {
	return func(obj client.Object) bool {
		scopedLog := logger.With(logfields.Resource, obj.GetName())

		gw, ok := obj.(*gatewayv1.Gateway)
		if !ok {
			return false
		}

		gwc := &gatewayv1.GatewayClass{}
		key := types.NamespacedName{Name: string(gw.Spec.GatewayClassName)}
		if err := c.Get(ctx, key, gwc); err != nil {
			scopedLog.ErrorContext(ctx, "Unable to get GatewayClass", logfields.Error, err)
			return false
		}

		return string(gwc.Spec.ControllerName) == controllerName
	}
}

func gatewayClassOwnedByControllerFunc(expected string) func(object client.Object) bool {
	return func(object client.Object) bool {
		gwc, ok := object.(*gatewayv1.GatewayClass)
		if !ok {
			return false
		}

		return string(gwc.Spec.ControllerName) == expected
	}
}

func gatewayOwnedByController(ctx context.Context, c client.Client, logger *slog.Logger) predicate.Predicate {
	matches := gatewayOwnedByControllerFunc(ctx, c, logger)

	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return matches(e.Object)
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			// Reconcile one last time when a Gateway moves away from this controller
			// so previously managed resources can be cleaned up.
			return matches(e.ObjectOld) || matches(e.ObjectNew)
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return matches(e.Object)
		},
		GenericFunc: func(e event.GenericEvent) bool {
			return matches(e.Object)
		},
	}
}

func gatewayClassOwnedByController(expected string) predicate.Predicate {
	matches := gatewayClassOwnedByControllerFunc(expected)

	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return matches(e.Object)
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			// Reconcile one last time when a Gateway moves away from this controller
			// so previously managed resources can be cleaned up.
			return matches(e.ObjectOld) || matches(e.ObjectNew)
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return matches(e.Object)
		},
		GenericFunc: func(e event.GenericEvent) bool {
			return matches(e.Object)
		},
	}
}
