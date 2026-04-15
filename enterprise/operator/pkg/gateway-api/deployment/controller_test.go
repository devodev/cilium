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
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestGatewayOwnedByControllerAllowsGatewayClassChange(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, gatewayv1.Install(scheme))

	managedClass := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "cilium-deployment"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayv1.GatewayController(controllerName),
		},
	}
	otherClass := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "other"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayv1.GatewayController("example.com/other"),
		},
	}

	oldGateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "example"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: gatewayv1.ObjectName(managedClass.Name),
		},
	}
	newGateway := oldGateway.DeepCopy()
	newGateway.Spec.GatewayClassName = gatewayv1.ObjectName(otherClass.Name)

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(managedClass, otherClass).Build()
	p := gatewayOwnedByController(context.Background(), c, slog.Default())

	require.True(t, p.Update(event.UpdateEvent{
		ObjectOld: oldGateway,
		ObjectNew: newGateway,
	}))
}

func TestGatewayClassOwnedByControllerAllowsHandoffUpdate(t *testing.T) {
	p := gatewayClassOwnedByController(controllerName)

	oldClass := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "cilium-deployment"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayv1.GatewayController(controllerName),
		},
	}
	newClass := oldClass.DeepCopy()
	newClass.Spec.ControllerName = gatewayv1.GatewayController("example.com/other")

	require.True(t, p.Update(event.UpdateEvent{
		ObjectOld: oldClass,
		ObjectNew: newClass,
	}))
}
