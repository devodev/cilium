// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilers

import (
	"context"
	"errors"
	"iter"
	"log/slog"
	"maps"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cilium/cilium/enterprise/operator/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/operator/pkg/privnet/tables"
	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// ExternalEndpointsCell groups the external endpoints reconciliation operations
// It should run only in the leader operator replica.
var ExternalEndpointsCell = cell.Group(
	cell.ProvidePrivate(
		// Provides the ReadWrite ExternalEndpoints table.
		tables.NewExternalEndpointsTable,

		// Provides the reconciler handling external endpoints.
		newExternalEndpoints,
	),

	cell.Invoke(
		// Starts reflecting local endpoints into the local workloads table
		(*ExternalEndpoints).registerReconciler,
	),
)

type ExternalEndpoints struct {
	config            config.Config
	log               *slog.Logger
	clientset         client.Clientset
	db                *statedb.DB
	externalEndpoints statedb.RWTable[*tables.ExternalEndpoint]
	reconcilerParams  reconciler.Params
}

func newExternalEndpoints(in struct {
	cell.In

	Config config.Config
	Log    *slog.Logger

	Clientset         client.Clientset
	DB                *statedb.DB
	ExternalEndpoints statedb.RWTable[*tables.ExternalEndpoint]
	ReconcilerParams  reconciler.Params
}) *ExternalEndpoints {
	return &ExternalEndpoints{
		config:            in.Config,
		log:               in.Log,
		clientset:         in.Clientset,
		db:                in.DB,
		externalEndpoints: in.ExternalEndpoints,
		reconcilerParams:  in.ReconcilerParams,
	}
}

func (e *ExternalEndpoints) registerReconciler() (reconciler.Reconciler[*tables.ExternalEndpoint], error) {
	if !e.config.EnabledWithAutoExternalEndpoints() {
		return nil, nil
	}

	ops := &externalEndpointsOps{
		clientset: e.clientset,
		logger:    e.log,
	}

	return reconciler.Register[*tables.ExternalEndpoint](
		// params
		e.reconcilerParams,
		// table
		e.externalEndpoints,
		// clone
		func(ep *tables.ExternalEndpoint) *tables.ExternalEndpoint {
			cpy := *ep // shallow copy
			return &cpy
		},
		// setStatus
		func(ep *tables.ExternalEndpoint, s reconciler.Status) *tables.ExternalEndpoint {
			ep.Status = s
			return ep
		},
		// getStatus
		func(ep *tables.ExternalEndpoint) reconciler.Status {
			return ep.Status
		},
		// ops
		ops,
		// batchOps
		nil,
	)
}

func ipString(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	return addr.String()
}

type externalEndpointsOps struct {
	clientset client.Clientset
	logger    *slog.Logger
}

func (e *externalEndpointsOps) Update(ctx context.Context, txn statedb.ReadTxn, revision statedb.Revision, ep *tables.ExternalEndpoint) error {
	labels := maps.Clone(ep.Labels)
	if labels == nil {
		labels = map[string]string{}
	}
	labels[managedByLabelKey] = managedByLabelVal

	client := e.clientset.IsovalentV1alpha1().PrivateNetworkExternalEndpoints(ep.Namespace)

	missing := false
	obj, err := client.Get(ctx, ep.Name, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			missing = true
		} else {
			return err
		}
	}

	if !missing && obj.Labels[managedByLabelKey] != managedByLabelVal {
		e.logger.Info("External endpoint is not managed by Cilium",
			logfields.Endpoint, obj.Namespace+"/"+obj.Name,
		)
		return nil
	}

	if missing || e.immutableFieldChanged(obj, ep) {
		if !missing {
			err = client.Delete(ctx, obj.Name, metav1.DeleteOptions{
				Preconditions: &metav1.Preconditions{
					UID:             &obj.UID,
					ResourceVersion: &obj.ResourceVersion,
				},
			})
			if err != nil {
				return err
			}
		}

		obj = &iso_v1alpha1.PrivateNetworkExternalEndpoint{
			ObjectMeta: metav1.ObjectMeta{
				Name:      ep.Name,
				Namespace: ep.Namespace,
				Labels:    labels,
			},
			Spec: iso_v1alpha1.PrivateNetworkExternalEndpointSpec{
				Interface: iso_v1alpha1.PrivateNetworkEndpointSliceInterface{
					Addressing: iso_v1alpha1.PrivateNetworkEndpointAddressing{
						IPv4: ipString(ep.IPv4),
						IPv6: ipString(ep.IPv6),
					},
					MAC:     ep.MAC.String(),
					Network: ep.Network,
				},
			},
		}

		_, err = client.Create(ctx, obj, metav1.CreateOptions{
			FieldManager: fieldManager,
		})
		// If creation fails with not found, it should be due to missing namespace.
		if err != nil && k8serrors.IsNotFound(err) {
			_, err = e.clientset.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: obj.Namespace,
				},
			}, metav1.CreateOptions{})
			if err != nil {
				return err
			}
			// Try to create the external endpoint again.
			_, err = client.Create(ctx, obj, metav1.CreateOptions{
				FieldManager: fieldManager,
			})
		}

		return err
	}

	maps.Copy(obj.Labels, labels)
	obj.Spec = iso_v1alpha1.PrivateNetworkExternalEndpointSpec{
		Interface: iso_v1alpha1.PrivateNetworkEndpointSliceInterface{
			Addressing: iso_v1alpha1.PrivateNetworkEndpointAddressing{
				IPv4: ipString(ep.IPv4),
				IPv6: ipString(ep.IPv6),
			},
			MAC:     ep.MAC.String(),
			Network: ep.Network,
		},
	}

	_, err = client.Update(ctx, obj, metav1.UpdateOptions{
		FieldManager: fieldManager,
	})

	return err
}

func (e *externalEndpointsOps) immutableFieldChanged(obj *iso_v1alpha1.PrivateNetworkExternalEndpoint, ep *tables.ExternalEndpoint) bool {
	// This must be in sync with what the agent considers immutable
	iface := obj.Spec.Interface
	return iface.Network != ep.Network ||
		iface.MAC != ep.MAC.String() ||
		iface.Addressing.IPv4 != ipString(ep.IPv4) ||
		iface.Addressing.IPv6 != ipString(ep.IPv6)
}

func (e *externalEndpointsOps) Delete(ctx context.Context, txn statedb.ReadTxn, revision statedb.Revision, ep *tables.ExternalEndpoint) error {
	client := e.clientset.IsovalentV1alpha1().PrivateNetworkExternalEndpoints(ep.Namespace)
	obj, err := client.Get(ctx, ep.Name, metav1.GetOptions{})
	if err != nil {
		return ctrlclient.IgnoreNotFound(err)
	}

	if obj.Labels[managedByLabelKey] != managedByLabelVal {
		return nil // don't delete unmanaged external endpoints
	}

	return client.Delete(ctx, obj.Name, metav1.DeleteOptions{
		Preconditions: &metav1.Preconditions{
			UID:             &obj.UID,
			ResourceVersion: &obj.ResourceVersion,
		},
	})
}

func (e *externalEndpointsOps) Prune(ctx context.Context, txn statedb.ReadTxn, eps iter.Seq2[*tables.ExternalEndpoint, statedb.Revision]) error {
	endpointsByName := make(map[string]*tables.ExternalEndpoint)
	for ep := range eps {
		endpointsByName[ep.K8sNamespaceAndName()] = ep
	}

	// Obtain list of all managed external endpoints in all namespaces.
	objs, err := e.clientset.IsovalentV1alpha1().
		PrivateNetworkExternalEndpoints(corev1.NamespaceAll).
		List(ctx, metav1.ListOptions{
			LabelSelector: managedByLabelKey + "=" + managedByLabelVal,
		})
	if err != nil {
		return err
	}

	var errs error
	for _, obj := range objs.Items {
		ep := tables.ExternalEndpointKey(obj.Namespace, obj.Name)
		_, ok := endpointsByName[ep]
		if ok {
			continue
		}

		// If external endpoint is not in the set of alive endpoints, we prune it.
		e.logger.Info("Pruning orphaned external endpoint", logfields.Endpoint, ep)
		err = e.clientset.IsovalentV1alpha1().
			PrivateNetworkExternalEndpoints(obj.Namespace).
			Delete(ctx, obj.Name, metav1.DeleteOptions{
				Preconditions: &metav1.Preconditions{
					UID:             &obj.UID,
					ResourceVersion: &obj.ResourceVersion,
				},
			})
		if err != nil {
			errs = errors.Join(errs, err)
		}
	}

	return errs
}
