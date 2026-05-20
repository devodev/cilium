package lb

import (
	"context"
	"maps"
	s "slices"
	"strings"

	"fmt"
	"net"

	"log/slog"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/routechecks"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/shortener"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/handler"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	gatewayLabel                 = "io.isovalent.gateway"
	controllerName               = "io.isovalent/gateway-controller"
	gateway                      = "ilbgateway"
	lastTransitionTime           = "LastTransitionTime"
	owningGatewayLabel           = "io.isovalent.gateway/owning-gateway"
	backendServiceHTTPRouteIndex = "backendServiceHTTPRouteIndex"
	gatewayHTTPRouteIndex        = "gatewayHTTPRouteIndex"
)

type gatewayReconciler struct {
	client.Client
	Scheme       *runtime.Scheme
	t1Translator *lbServiceT1Translator
	t2Translator *lbServiceT2Translator
	logger       *slog.Logger
	gwIngestor   *gwIngestor
	nodeSource   *ciliumNodeSource
}

func newGatewayReconciler(client client.Client, t1Translator *lbServiceT1Translator, t2Translator *lbServiceT2Translator, logger *slog.Logger, gwIngestor *gwIngestor, nodeSource *ciliumNodeSource) *gatewayReconciler {
	return &gatewayReconciler{
		Client:       client,
		logger:       logger,
		gwIngestor:   gwIngestor,
		t1Translator: t1Translator,
		t2Translator: t2Translator,
		nodeSource:   nodeSource,
	}
}

func hasMatchingController(ctx context.Context, c client.Client, controllerName string, logger *slog.Logger) func(object client.Object) bool {
	return func(obj client.Object) bool {

		scopedLog := logger.With(
			logfields.Controller, gateway,
			logfields.Resource, obj.GetName(),
		)
		gw, ok := obj.(*gatewayv1.Gateway)
		if !ok {
			return false
		}

		gwc := &gatewayv1.GatewayClass{}
		key := types.NamespacedName{Name: string(gw.Spec.GatewayClassName)}
		if err := c.Get(ctx, key, gwc); err != nil {
			scopedLog.Error("Unable to get GatewayClass", logfields.Error, err)
			return false
		}

		return string(gwc.Spec.ControllerName) == controllerName
	}
}

func (r *gatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	hasMatchingControllerFn := hasMatchingController(context.Background(), r.Client, controllerName, r.logger)

	gatewayBuilder := ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1.Gateway{},
			builder.WithPredicates(predicate.NewPredicateFuncs(hasMatchingControllerFn))).
		Watches(&gatewayv1.GatewayClass{},
			r.enqueueRequestForOwningGatewayClass(),
			builder.WithPredicates(predicate.NewPredicateFuncs(matchesControllerName(controllerName)))).
		Watches(&gatewayv1.HTTPRoute{},
			r.enqueueRequestForOwningHTTPRoute(r.logger)).
		Owns(&ciliumv2.CiliumEnvoyConfig{}).
		Owns(&corev1.Service{}).
		Owns(&discoveryv1.EndpointSlice{})

	return gatewayBuilder.Complete(r)

}
func (r *gatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	scopedLog := r.logger.With(
		logfields.Controller,
		gateway,
		logfields.Resource,
		req.NamespacedName,
	)

	scopedLog.Info("Reconciling Gateway")

	// Step 1: Retrieve the Gateway
	original := &gatewayv1.Gateway{}
	if err := r.Client.Get(ctx, req.NamespacedName, original); err != nil {
		if k8serrors.IsNotFound(err) {
			return controllerruntime.Success()
		}
		scopedLog.ErrorContext(ctx, "Unable to get Gateway", logfields.Error, err)
		return controllerruntime.Fail(err)
	}

	// Ignore deleting Gateway, this can happen when foregroundDeletion is enabled
	// The reconciliation loop will automatically kick off for related Gateway resources.
	if original.GetDeletionTimestamp() != nil {
		scopedLog.Info("Gateway is being deleted, doing nothing")
		return controllerruntime.Success()
	}

	gw := original.DeepCopy()

	// Step 2: Gather all required information for the ingestion model
	gwc := &gatewayv1.GatewayClass{}
	if err := r.Client.Get(ctx, client.ObjectKey{Name: string(gw.Spec.GatewayClassName)}, gwc); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to get GatewayClass",
			gatewayClass, gw.Spec.GatewayClassName,
			logfields.Error, err)
		// Doing nothing till the GatewayClass is available and matching controller name
		return controllerruntime.Success()
	}

	if string(gwc.Spec.ControllerName) != controllerName {
		scopedLog.Debug("GatewayClass does not have matching controller name, doing nothing")
		return controllerruntime.Success()
	}

	httpRouteList := &gatewayv1.HTTPRouteList{}
	if err := r.Client.List(ctx, httpRouteList); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to list HTTPRoutes", logfields.Error, err)
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	}

	servicesList := &corev1.ServiceList{}
	if err := r.Client.List(ctx, servicesList); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to list Services", logfields.Error, err)
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	}

	endpoints := r.loadK8sEndpointSlices(ctx, gw, httpRouteList)

	// Load all nodes
	nodeStore, err := r.nodeSource.Store(ctx)
	if err != nil {
		scopedLog.ErrorContext(ctx, "Failed to get node store", logfields.Error, err)
		return controllerruntime.Fail(err)
	}
	allNodes := nodeStore.List()

	// Get the VIPs to know which IP addresses to use
	vip, err := r.loadVIP(ctx, gw)
	if err != nil {
		return controllerruntime.Fail(err)
	}

	if err := r.setHTTPRouteStatuses(scopedLog, ctx, httpRouteList); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to update HTTPRoute Status", logfields.Error, err)
		return controllerruntime.Fail(err)
	}

	// for now just grabbing httproute
	httpRoutes := r.filterHTTPRoutesByGateway(ctx, gw, httpRouteList.Items)

	model, err := r.gwIngestor.ingestGatewayAPItoLB(Input{
		GatewayClass:   *gwc,
		Gateway:        *gw,
		HTTPRoutes:     httpRoutes,
		Services:       servicesList.Items,
		EndpointSlices: endpoints,
		AllNodes:       allNodes,
		VIP:            vip,
	}, ctx)
	if err != nil {
		scopedLog.ErrorContext(ctx, "Failed to get model for gateway", logfields.Error, err)
		return controllerruntime.Fail(err)
	}

	// step 3 - translation
	// TODO call upon the translation from ILB
	if model == nil {
		scopedLog.Info("Gateway LB has no ip address yet and model is nil")

		return controllerruntime.Success()
	}
	if err := r.verifyGatewayStaticAddresses(gw); err != nil {
		scopedLog.ErrorContext(ctx, "The gateway static address is not yet supported", logfields.Error, err)
		setGatewayAccepted(gw, false, "The gateway static address is not yet supported", gatewayv1.GatewayReasonUnsupportedAddress)
		setGatewayProgrammed(gw, false, "Address is not ready", gatewayv1.GatewayReasonListenersNotReady)
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	}

	desiredT1Service := r.t1Translator.DesiredService(model)
	if desiredT1Service == nil { // the service hasn't been created the desired svcs can only be populated if the lbvip svc is ready
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}
	if model.name == "" {
		// model hasn't been generated, missing lbvip
		setGatewayProgrammed(gw, false, "lbvip isn't provisioned yet, can't be used", gatewayv1.GatewayReasonAddressNotUsable)

		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)

	}
	// TODO check if desiredT1 svc is null
	desiredT1Service.OwnerReferences = []metav1.OwnerReference{
		{
			APIVersion: gatewayv1beta1.GroupVersion.String(),
			Kind:       gw.Kind,
			Name:       gw.Name,
			UID:        types.UID(gw.UID),
			Controller: ptr.To(true),
		},
	}

	// add a gateway label to the desired T1 Svc so the Gateway can pick up the IP address
	desiredT1Service.Labels = mergeMap(desiredT1Service.Labels, map[string]string{
		gatewayLabel: gw.Name,
	})

	desiredT1EndpointSliceIPv4 := r.t1Translator.DesiredEndpointSlice(model, false)
	desiredT1EndpointSliceIPv6 := r.t1Translator.DesiredEndpointSlice(model, true)

	if desiredT1EndpointSliceIPv4 != nil {
		desiredT1EndpointSliceIPv4.OwnerReferences = []metav1.OwnerReference{
			{
				APIVersion: gatewayv1beta1.GroupVersion.String(),
				Kind:       gw.Kind,
				Name:       gw.Name,
				UID:        types.UID(gw.UID),
				Controller: ptr.To(true),
			},
		}
	}
	if desiredT1EndpointSliceIPv6 != nil {
		desiredT1EndpointSliceIPv6.OwnerReferences = []metav1.OwnerReference{
			{
				APIVersion: gatewayv1beta1.GroupVersion.String(),
				Kind:       gw.Kind,
				Name:       gw.Name,
				UID:        types.UID(gw.UID),
				Controller: ptr.To(true),
			},
		}
	}
	if err := r.createOrUpdateService(ctx, desiredT1Service); err != nil {
		return ctrl.Result{}, err
	}

	if desiredT1EndpointSliceIPv4 != nil {
		if err := r.createOrUpdateEndpointSlice(ctx, desiredT1EndpointSliceIPv4); err != nil {
			return controllerruntime.Fail(err)
		}
	} else {
		if err := r.ensureEndpointSliceDeleted(ctx, model, false); err != nil {
			return controllerruntime.Fail(err)
		}
	}
	if desiredT1EndpointSliceIPv6 != nil {
		if err := r.createOrUpdateEndpointSlice(ctx, desiredT1EndpointSliceIPv6); err != nil {
			return controllerruntime.Fail(err)
		}
	} else {
		if err := r.ensureEndpointSliceDeleted(ctx, model, true); err != nil {
			return controllerruntime.Fail(err)
		}
	}

	// stops reconciliation if T1 svc is not available yet or not able to bind to VIP
	if !model.vip.bindStatus.serviceExists || !model.vip.bindStatus.bindSuccessful {
		return ctrl.Result{}, nil
	}

	// get the desired T2 Services
	desiredT2CiliumEnvoyConfigs, err := r.t2Translator.DesiredCiliumEnvoyConfigs(model)
	if err != nil {
		return ctrl.Result{}, err
	}
	if len(desiredT2CiliumEnvoyConfigs) != 1 {
		scopedLog.ErrorContext(ctx, "Gateway reconciliation expected exactly one T2 CiliumEnvoyConfig", logfields.Found, len(desiredT2CiliumEnvoyConfigs))
		return ctrl.Result{}, fmt.Errorf("gateway reconciliation expected exactly 1 T2 CiliumEnvoyConfig, got %d", len(desiredT2CiliumEnvoyConfigs))
	}

	desiredT2CiliumEnvoyConfig := desiredT2CiliumEnvoyConfigs[0]

	// Set controlling ownerreferences
	desiredT2CiliumEnvoyConfig.OwnerReferences = []metav1.OwnerReference{
		{
			APIVersion: gatewayv1beta1.GroupVersion.String(),
			Kind:       gw.Kind,
			Name:       gw.Name,
			UID:        types.UID(gw.UID),
			Controller: ptr.To(true),
		},
	}

	if err := r.createOrUpdateCiliumEnvoyConfig(ctx, desiredT2CiliumEnvoyConfig); err != nil {
		return ctrl.Result{}, err
	}

	//create or update the resources
	if err := r.createOrUpdateService(ctx, desiredT1Service); err != nil {
		scopedLog.ErrorContext(ctx, "unable to create desired t1 svc,", logfields.Error, err)
		setGatewayAccepted(gw, false, "Unable to create Service resource", gatewayv1.GatewayReasonNoResources)
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	}

	//step 4

	if err := r.updateStatus(ctx, original, gw); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to update Gateway status: %w", err)
	}
	if err := r.setAddressStatus(ctx, gw); err != nil {
		scopedLog.ErrorContext(ctx, "Address is not ready", logfields.Error, err)
		setGatewayProgrammed(gw, false, "Address is not ready", gatewayv1.GatewayReasonListenersNotReady)
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	}
	if err := r.setStaticAddressStatus(ctx, gw); err != nil {
		scopedLog.ErrorContext(ctx, "StaticAddress can't be used", logfields.Error, err)
		setGatewayProgrammed(gw, false, "StaticAddress can't be used", gatewayv1.GatewayReasonAddressNotUsable)
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	}

	setGatewayProgrammed(gw, true, "Gateway successfully reconciled", gatewayv1.GatewayReasonProgrammed)

	if err := r.updateStatus(ctx, original, gw); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to update Gateway status: %w", err)
	}
	setGatewayAccepted(gw, true, "Gateway successfully scheduled", gatewayv1.GatewayReasonAccepted)
	return controllerruntime.Success()
}

// return the enpoint slices for the application services associated with
// is there an easier way to do this hmm
func (r *gatewayReconciler) loadK8sEndpointSlices(ctx context.Context, gw *gatewayv1.Gateway, httproutelist *gatewayv1.HTTPRouteList) []discoveryv1.EndpointSlice {

	// first get the names of backend refs
	backendRefNames := []string{}

	for _, httproute := range httproutelist.Items {
		// for each rule in the route
		for _, routeRule := range httproute.Spec.Rules {
			// get the name of the app

			for _, backendref := range routeRule.BackendRefs {
				backendRefNames = append(backendRefNames, string(backendref.Name))
			}
		}
	}
	res := []discoveryv1.EndpointSlice{}
	// for each backend ref, get the endpoint slices associated with it (?)
	for _, n := range backendRefNames {
		es := &discoveryv1.EndpointSliceList{}
		listOptions := []client.ListOption{
			client.InNamespace(gw.Namespace),
			client.MatchingLabels{
				discoveryv1.LabelServiceName: n,
			},
		}
		if err := r.Client.List(ctx, es, listOptions...); err != nil {
			return nil
		}
		res = append(res, es.Items...)
	}

	return res
}

func (r *gatewayReconciler) ensureEndpointSliceDeleted(ctx context.Context, model *lbService, ipv6 bool) error {
	midfix := ""
	if ipv6 {
		midfix = endpointSliceIPv6Midfix
	}
	ep := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: model.namespace,
			Name:      model.getOwningResourceNameWithMidfix(midfix),
		},
	}
	if err := r.Delete(ctx, ep); err != nil {
		if !k8serrors.IsNotFound(err) {
			return fmt.Errorf("failed to ensure enpointslice is deleted %w", err)
		}
	}
	return nil
}

// creates/updates the svc from the T1 model
func (r *gatewayReconciler) createOrUpdateService(ctx context.Context, desiredService *corev1.Service) error {
	svc := desiredService.DeepCopy()
	result, err := controllerutil.CreateOrUpdate(ctx, r.Client, svc, func() error {
		svc.Spec = desiredService.Spec
		svc.OwnerReferences = desiredService.OwnerReferences
		//	svc.Annotations = desiredService.Annotations
		//svc.Labels = desiredService.Labels

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to create or update Service: %w", err)
	}

	r.logger.Debug("Service has been updated",
		logfields.Resource, client.ObjectKeyFromObject(svc),
		logfieldResult, result,
	)

	return nil
}
func (r *gatewayReconciler) createOrUpdateCiliumEnvoyConfig(ctx context.Context, desiredCEC *ciliumv2.CiliumEnvoyConfig) error {
	cec := desiredCEC.DeepCopy()

	result, err := controllerutil.CreateOrUpdate(ctx, r.Client, cec, func() error {
		cec.Spec = desiredCEC.Spec
		cec.OwnerReferences = desiredCEC.OwnerReferences
		cec.Annotations = desiredCEC.Annotations
		cec.Labels = desiredCEC.Labels

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to create or update CiliumEnvoyConfig: %w", err)
	}

	r.logger.Debug("CiliumEnvoyConfig has been updated",
		logfields.Resource, client.ObjectKeyFromObject(cec),
		logfieldResult, result,
	)

	return nil
}
func (r *gatewayReconciler) createOrUpdateEndpointSlice(ctx context.Context, desiredEndpointSlice *discoveryv1.EndpointSlice) error {
	ep := desiredEndpointSlice.DeepCopy()
	result, err := controllerutil.CreateOrUpdate(ctx, r.Client, ep, func() error {
		ep.AddressType = desiredEndpointSlice.AddressType
		ep.Endpoints = desiredEndpointSlice.Endpoints
		ep.Ports = desiredEndpointSlice.Ports
		ep.OwnerReferences = desiredEndpointSlice.OwnerReferences
		ep.Annotations = desiredEndpointSlice.Annotations
		ep.Labels = desiredEndpointSlice.Labels

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to create or update EndpointSlice: %w", err)
	}

	r.logger.Debug("EndpointSlice has been updated",
		logfields.Resource, client.ObjectKeyFromObject(ep),
		logfieldResult, result,
	)
	return nil
}

func (r *gatewayReconciler) loadVIP(ctx context.Context, gw *gatewayv1.Gateway) (*isovalentv1alpha1.LBVIP, error) {
	vip := &isovalentv1alpha1.LBVIP{}

	// getting the lb vip that just currently matches the name of the gateway aka it's just hardcoded for now
	if err := r.Client.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: "isovalentlb-" + gw.GetName()}, vip); err != nil {
		// create the lbvip if it's not created. Will grab a random ip from the ip pool

		vip = &isovalentv1alpha1.LBVIP{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "isovalentlb-" + gw.Name,
				Namespace: gw.Namespace,
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion: gatewayv1beta1.GroupVersion.String(),
						Kind:       gw.Kind,
						Name:       gw.Name,
						UID:        types.UID(gw.UID),
						Controller: ptr.To(true),
					},
				},
			},
		}
		if err := r.Client.Create(ctx, vip); err != nil {
			return nil, fmt.Errorf("failed to create the ilbgateway vip %w", err)
		}
		return vip, nil
	}

	return vip, nil

}

func (r *gatewayReconciler) setAddressStatus(ctx context.Context, gw *gatewayv1.Gateway) error {
	svcList := &corev1.ServiceList{}
	name := shortener.ShortenK8sResourceName(gw.GetName())
	if err := r.Client.List(ctx, svcList, client.MatchingLabels{
		gatewayLabel: name,
	}, client.InNamespace(gw.GetNamespace())); err != nil {
		return err
	}

	if len(svcList.Items) == 0 {
		return fmt.Errorf("no service found")
	}

	svc := svcList.Items[0]
	if len(svc.Status.LoadBalancer.Ingress) == 0 {
		// Potential loadbalancer service isn't ready yet. No need to report as an error, because
		// reconciliation should be triggered when the loadbalancer services gets updated.
		return nil
	}

	var addresses []gatewayv1.GatewayStatusAddress
	for _, s := range svc.Status.LoadBalancer.Ingress {
		if len(s.IP) != 0 {
			addresses = append(addresses, gatewayv1.GatewayStatusAddress{
				Type:  GatewayAddressTypePtr(gatewayv1.IPAddressType),
				Value: s.IP,
			})
		}
		if len(s.Hostname) != 0 {
			addresses = append(addresses, gatewayv1.GatewayStatusAddress{
				Type:  GatewayAddressTypePtr(gatewayv1.HostnameAddressType),
				Value: s.Hostname,
			})
		}
	}

	gw.Status.Addresses = addresses
	return nil
}

func (r *gatewayReconciler) setStaticAddressStatus(ctx context.Context, gw *gatewayv1.Gateway) error {
	if len(gw.Spec.Addresses) == 0 {
		return nil
	}
	svcList := &corev1.ServiceList{}
	if err := r.Client.List(ctx, svcList, client.MatchingLabels{
		owningGatewayLabel: shortener.ShortenK8sResourceName(gw.GetName()),
	}, client.InNamespace(gw.GetNamespace())); err != nil {
		return err
	}

	if len(svcList.Items) == 0 {
		return fmt.Errorf("no service found")
	}

	svc := svcList.Items[0]
	if len(svc.Status.LoadBalancer.Ingress) == 0 {
		// Potential loadbalancer service isn't ready yet. No need to report as an error, because
		// reconciliation should be triggered when the loadbalancer services gets updated.
		return nil
	}
	addresses := make(map[string]struct{})
	for _, addr := range svc.Status.LoadBalancer.Ingress {
		addresses[addr.IP] = struct{}{}
	}

	for _, addr := range gw.Spec.Addresses {
		if _, ok := addresses[addr.Value]; !ok {
			return fmt.Errorf("static address %q can't be used", addr.Value)
		}
	}

	return nil
}

func (r *gatewayReconciler) setHTTPRouteStatuses(scopedLog *slog.Logger, ctx context.Context, httpRoutes *gatewayv1.HTTPRouteList) error {
	scopedLog.DebugContext(ctx, "Updating HTTPRoute statuses for Gateway")
	for httpRouteIndex, original := range httpRoutes.Items {

		hr := original.DeepCopy()

		// input for the validators
		// The validators will mutate the HTTPRoute as required, setting its status correctly.
		i := &routechecks.HTTPRouteInput{
			Ctx:       ctx,
			Logger:    scopedLog.With(logfields.HTTPRoute, hr),
			Client:    r.Client,
			HTTPRoute: hr,
		}

		if err := r.runCommonRouteChecks(i, hr.Spec.ParentRefs, hr.Namespace); err != nil {
			return r.handleHTTPRouteReconcileErrorWithStatus(ctx, scopedLog, err, hr, &original)
		}

		// Route-specific checks will go in here separately if required.

		// Checks finished, apply the status to the actual objects.
		if err := r.updateHTTPRouteStatus(ctx, scopedLog, &original, hr); err != nil {
			return fmt.Errorf("failed to update HTTPRoute status: %w", err)
		}

		// Update the cached copy with the same status changes to prevent re-fetching from client cache.
		httpRoutes.Items[httpRouteIndex].Status = hr.Status
	}

	return nil
}

func (r *gatewayReconciler) updateHTTPRouteStatus(ctx context.Context, scopedLog *slog.Logger, original *gatewayv1.HTTPRoute, new *gatewayv1.HTTPRoute) error {
	oldStatus := original.Status.DeepCopy()
	newStatus := new.Status.DeepCopy()

	if cmp.Equal(oldStatus, newStatus, cmpopts.IgnoreFields(metav1.Condition{}, lastTransitionTime)) {
		return nil
	}
	scopedLog.DebugContext(ctx, "Updating HTTPRoute status")
	return r.Client.Status().Update(ctx, new)
}

func (r *gatewayReconciler) handleHTTPRouteReconcileErrorWithStatus(ctx context.Context, scopedLog *slog.Logger, reconcileErr error, original *gatewayv1.HTTPRoute, modified *gatewayv1.HTTPRoute) error {
	if err := r.updateHTTPRouteStatus(ctx, scopedLog, original, modified); err != nil {
		return fmt.Errorf("failed to update Gateway status while handling the reconcile error: %w: %w", reconcileErr, err)
	}
	return nil
}

// runCommonRouteChecks runs all the checks that are common across all supported Route types.
//
// Uses the helpers.Input interface to ensure that this still applies as new types are added.
func (r *gatewayReconciler) runCommonRouteChecks(input routechecks.Input, parentRefs []gatewayv1.ParentReference, objNamespace string) error {
	for _, parent := range parentRefs {
		// If this parentRef is not a Gateway parentRef, skip it.
		if !helpers.IsGateway(parent) {
			continue
		}

		// Similarly, if this Gateway is not a matching one, skip it.
		if !r.parentIsMatchingGateway(parent, objNamespace) {
			continue
		}

		// set Accepted to okay, this wil be overwritten in checks if needed
		input.SetParentCondition(parent, metav1.Condition{
			Type:    string(gatewayv1.RouteConditionAccepted),
			Status:  metav1.ConditionTrue,
			Reason:  string(gatewayv1.RouteReasonAccepted),
			Message: "Accepted HTTPRoute",
		})

		// set ResolvedRefs to okay, this wil be overwritten in checks if needed
		input.SetParentCondition(parent, metav1.Condition{
			Type:    string(gatewayv1.RouteConditionResolvedRefs),
			Status:  metav1.ConditionTrue,
			Reason:  string(gatewayv1.RouteReasonResolvedRefs),
			Message: "Service reference is valid",
		})

		// run the Gateway validators
		for _, fn := range []routechecks.CheckWithParentFunc{
			routechecks.CheckGatewayRouteKindAllowed,
			routechecks.CheckGatewayMatchingPorts,
			routechecks.CheckGatewayMatchingHostnames,
			routechecks.CheckGatewayMatchingSection,
			routechecks.CheckGatewayAllowedForNamespace,
		} {
			continueCheck, err := fn(input, parent)
			if err != nil {
				return fmt.Errorf("failed to apply Gateway check: %w", err)
			}

			if !continueCheck {
				break
			}
		}

		// Run the Rule validators, these need to be run per-parent so that we
		// don't update status for parents we don't own.
		for _, fn := range []routechecks.CheckWithParentFunc{
			routechecks.CheckAgainstCrossNamespaceBackendReferences,
			routechecks.CheckBackend,
			routechecks.CheckHasServiceImportSupport,
			routechecks.CheckBackendIsExistingService,
		} {
			continueCheck, err := fn(input, parent)
			if err != nil {
				return fmt.Errorf("failed to apply Backend check: %w", err)
			}

			if !continueCheck {
				break
			}
		}

	}

	return nil
}
func (r *gatewayReconciler) parentIsMatchingGateway(parent gatewayv1.ParentReference, namespace string) bool {
	hasMatchingControllerFn := hasMatchingController(context.Background(), r.Client, controllerName, r.logger)
	if !helpers.IsGateway(parent) {
		return false
	}
	gw := &gatewayv1.Gateway{}
	if err := r.Client.Get(context.Background(), types.NamespacedName{
		Namespace: helpers.NamespaceDerefOr(parent.Namespace, namespace),
		Name:      string(parent.Name),
	}, gw); err != nil {
		return false
	}
	return hasMatchingControllerFn(gw)
}

func GatewayAddressTypePtr(addr gatewayv1.AddressType) *gatewayv1.AddressType {
	return &addr
}

func setGatewayAccepted(gw *gatewayv1.Gateway, accepted bool, msg string, reason gatewayv1.GatewayConditionReason) *gatewayv1.Gateway {
	gw.Status.Conditions = merge(gw.Status.Conditions, gatewayStatusAcceptedCondition(gw, accepted, msg, reason))
	return gw
}
func gatewayStatusAcceptedCondition(gw *gatewayv1.Gateway, accepted bool, msg string, reason gatewayv1.GatewayConditionReason) metav1.Condition {
	switch accepted {
	case true:
		return metav1.Condition{
			Type:               string(gatewayv1.GatewayConditionAccepted),
			Status:             metav1.ConditionTrue,
			Reason:             string(reason),
			Message:            msg,
			ObservedGeneration: gw.GetGeneration(),
			LastTransitionTime: metav1.NewTime(time.Now()),
		}
	default:
		return metav1.Condition{
			Type:               string(gatewayv1.GatewayConditionAccepted),
			Status:             metav1.ConditionFalse,
			Reason:             string(reason),
			Message:            msg,
			ObservedGeneration: gw.GetGeneration(),
			LastTransitionTime: metav1.NewTime(time.Now()),
		}
	}
}

func gatewayStatusProgrammedCondition(gw *gatewayv1.Gateway, scheduled bool, msg string, reason gatewayv1.GatewayConditionReason) metav1.Condition {
	switch scheduled {
	case true:
		return metav1.Condition{
			Type:   string(gatewayv1.GatewayConditionProgrammed),
			Status: metav1.ConditionTrue,
			//Reason:             string(gatewayv1.GatewayReasonProgrammed),
			Reason:             string(reason),
			Message:            msg,
			ObservedGeneration: gw.GetGeneration(),
			LastTransitionTime: metav1.NewTime(time.Now()),
		}
	default:
		return metav1.Condition{
			Type:   string(gatewayv1.GatewayConditionProgrammed),
			Status: metav1.ConditionFalse,
			//Reason:             string(gatewayv1.GatewayReasonListenersNotReady),
			Reason:             string(reason),
			Message:            msg,
			ObservedGeneration: gw.GetGeneration(),
			LastTransitionTime: metav1.NewTime(time.Now()),
		}
	}
}
func setGatewayProgrammed(gw *gatewayv1.Gateway, ready bool, msg string, reason gatewayv1.GatewayConditionReason) *gatewayv1.Gateway {
	gw.Status.Conditions = merge(gw.Status.Conditions, gatewayStatusProgrammedCondition(gw, ready, msg, reason))
	return gw
}
func (r *gatewayReconciler) updateStatus(ctx context.Context, original *gatewayv1.Gateway, new *gatewayv1.Gateway) error {
	oldStatus := original.Status.DeepCopy()
	newStatus := new.Status.DeepCopy()

	if cmp.Equal(oldStatus, newStatus, cmpopts.IgnoreFields(metav1.Condition{}, lastTransitionTime)) {
		return nil
	}
	return r.Client.Status().Update(ctx, new)
}

func (r *gatewayReconciler) verifyGatewayStaticAddresses(gw *gatewayv1.Gateway) error {
	if len(gw.Spec.Addresses) == 0 {
		return nil
	}
	for _, address := range gw.Spec.Addresses {
		if address.Type != nil && *address.Type != gatewayv1.IPAddressType {
			return fmt.Errorf("address type is not supported")
		}
		if address.Value == "" {
			return fmt.Errorf("address value is not set")
		}
		ip := net.ParseIP(address.Value)
		if ip == nil {
			return fmt.Errorf("invalid ip address")
		}
	}
	return nil
}

// enqueueRequestForOwningGatewayClass returns an event handler for all Gateway objects
// belonging to the given GatewayClass.
func (r *gatewayReconciler) enqueueRequestForOwningGatewayClass() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, a client.Object) []reconcile.Request {
		scopedLog := r.logger.With(
			logfields.Controller, gateway,
			logfields.Resource, a.GetName(),
		)
		var reqs []reconcile.Request
		gwList := &gatewayv1.GatewayList{}
		if err := r.Client.List(ctx, gwList); err != nil {
			scopedLog.Error("Unable to list Gateways")
			return nil
		}

		for _, gw := range gwList.Items {
			if gw.Spec.GatewayClassName != gatewayv1.ObjectName(a.GetName()) {
				continue
			}
			req := reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: gw.Namespace,
					Name:      gw.Name,
				},
			}
			reqs = append(reqs, req)
			scopedLog.Info("Queueing gateway",
				logfields.K8sNamespace, gw.GetNamespace(),
				gateway, gw.GetName(),
			)
		}
		return reqs
	})
}

// enqueueRequestForOwningHTTPRoute returns an event handler for any changes with HTTP Routes
// belonging to the given Gateway
func (r *gatewayReconciler) enqueueRequestForOwningHTTPRoute(logger *slog.Logger) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, a client.Object) []reconcile.Request {
		hr, ok := a.(*gatewayv1.HTTPRoute)
		if !ok {
			return nil
		}

		return getReconcileRequestsForRoute(context.Background(), r.Client, a, hr.Spec.CommonRouteSpec, logger)
	})
}

func getReconcileRequestsForRoute(ctx context.Context, c client.Client, object metav1.Object, route gatewayv1.CommonRouteSpec, logger *slog.Logger) []reconcile.Request {
	var reqs []reconcile.Request

	scopedLog := logger.With(
		logfields.Controller, gateway,
		logfields.Resource, types.NamespacedName{
			Namespace: object.GetNamespace(),
			Name:      object.GetName(),
		},
	)

	for _, parent := range route.ParentRefs {
		if !helpers.IsGateway(parent) {
			continue
		}

		ns := helpers.NamespaceDerefOr(parent.Namespace, object.GetNamespace())

		gw := &gatewayv1.Gateway{}
		if err := c.Get(ctx, types.NamespacedName{
			Namespace: ns,
			Name:      string(parent.Name),
		}, gw); err != nil {
			if !k8serrors.IsNotFound(err) {
				scopedLog.Error("Failed to get Gateway", logfields.Error, err)
			}
			continue
		}

		if !hasMatchingController(ctx, c, controllerName, logger)(gw) {
			scopedLog.Debug("Gateway does not have matching controller, skipping")
			continue
		}

		scopedLog.Info("Enqueued gateway for Route",
			logfields.K8sNamespace, ns,
			logfields.ParentResource, parent.Name,
			logfields.Route, object.GetName())

		reqs = append(reqs, reconcile.Request{
			NamespacedName: types.NamespacedName{
				Namespace: ns,
				Name:      string(parent.Name),
			},
		})
	}

	return reqs
}

func (r *gatewayReconciler) handleReconcileErrorWithStatus(ctx context.Context, reconcileErr error, original *gatewayv1.Gateway, modified *gatewayv1.Gateway) (ctrl.Result, error) {
	if err := r.updateStatus(ctx, original, modified); err != nil {
		return controllerruntime.Fail(fmt.Errorf("failed to update Gateway status while handling the reconcile error: %w: %w", reconcileErr, err))
	}

	return controllerruntime.Fail(reconcileErr)
}

func (r *gatewayReconciler) filterHTTPRoutesByGateway(ctx context.Context, gw *gatewayv1.Gateway, routes []gatewayv1.HTTPRoute) []gatewayv1.HTTPRoute {
	var filtered []gatewayv1.HTTPRoute

	allListenerHostNames := routechecks.GetAllListenerHostNames(gw.Spec.Listeners)
	for _, route := range routes {
		if isAttachable(ctx, gw, &route, route.Status.Parents) && isAllowed(ctx, r.Client, gw, &route, r.logger) && len(computeHosts(gw, route.Spec.Hostnames, allListenerHostNames)) > 0 {
			filtered = append(filtered, route)
		}
	}
	return filtered
}

func computeHosts[T ~string](gw *gatewayv1.Gateway, hostnames []T, excludeHostNames []T) []string {
	hosts := make([]string, 0, len(hostnames))
	for _, listener := range gw.Spec.Listeners {
		hosts = append(hosts, computeHostsForListener(&listener, hostnames, excludeHostNames)...)
	}

	return hosts
}

func isAttachable(_ context.Context, gw *gatewayv1.Gateway, route metav1.Object, parents []gatewayv1.RouteParentStatus) bool {
	for _, rps := range parents {
		if helpers.NamespaceDerefOr(rps.ParentRef.Namespace, route.GetNamespace()) != gw.GetNamespace() ||
			string(rps.ParentRef.Name) != gw.GetName() {
			continue
		}

		for _, cond := range rps.Conditions {
			if cond.Type == string(gatewayv1.RouteConditionAccepted) && cond.Status == metav1.ConditionTrue {
				return true
			}

			if cond.Type == string(gatewayv1.RouteConditionResolvedRefs) && cond.Status == metav1.ConditionFalse {
				return true
			}
		}
	}
	return false
}

// below funcs are from helpers.go
func computeHostsForListener[T ~string](listener *gatewayv1.Listener, hostnames []T, excludeHostNames []T) []string {
	return ComputeHosts(toStringSliceT(hostnames), (*string)(listener.Hostname), toStringSliceT(excludeHostNames))
}
func toStringSliceT[T ~string](s []T) []string {
	res := make([]string, 0, len(s))
	for _, h := range s {
		res = append(res, string(h))
	}
	return res
}

// isAllowed returns true if the provided Route is allowed to attach to given gateway
func isAllowed(ctx context.Context, c client.Client, gw *gatewayv1.Gateway, route metav1.Object, logger *slog.Logger) bool {
	for _, listener := range gw.Spec.Listeners {
		// all routes in the same namespace are allowed for this listener
		if listener.AllowedRoutes == nil || listener.AllowedRoutes.Namespaces == nil {
			return route.GetNamespace() == gw.GetNamespace()
		}

		// check if route is kind-allowed
		//	if !isKindAllowed(listener, route) {
		//		continue
		//	}

		// check if route is namespace-allowed
		switch *listener.AllowedRoutes.Namespaces.From {
		case gatewayv1.NamespacesFromAll:
			return true
		case gatewayv1.NamespacesFromSame:
			if route.GetNamespace() == gw.GetNamespace() {
				return true
			}
		case gatewayv1.NamespacesFromSelector:
			nsList := &corev1.NamespaceList{}
			selector, _ := metav1.LabelSelectorAsSelector(listener.AllowedRoutes.Namespaces.Selector)
			if err := c.List(ctx, nsList, client.MatchingLabelsSelector{Selector: selector}); err != nil {
				logger.Error("Unable to list namespaces", logfields.Error, err)
				return false
			}

			for _, ns := range nsList.Items {
				if ns.Name == route.GetNamespace() {
					return true
				}
			}
		}
	}
	return false
}

// ComputeHosts returns a list of the intersecting hostnames between the route and the listener.
// The below function is inspired from https://github.com/envoyproxy/gateway/blob/main/internal/gatewayapi/helpers.go.
// Special thanks to Envoy team.
// The function takes a list of route hostnames, a listener hostname, and a list of other listener hostnames.
// Note that the listenerHostname value will be skipped if it is present in the otherListenerHosts list.
func ComputeHosts(routeHostnames []string, listenerHostname *string, otherListenerHosts []string) []string {
	var listenerHostnameVal string
	if listenerHostname != nil {
		listenerHostnameVal = *listenerHostname
	}

	// No route hostnames specified: use the listener hostname if specified,
	// or else match all hostnames.
	if len(routeHostnames) == 0 {
		if len(listenerHostnameVal) > 0 {
			return []string{listenerHostnameVal}
		}

		return []string{allHosts}
	}

	var hostnames []string

	for i := range routeHostnames {
		routeHostname := routeHostnames[i]

		switch {
		// No listener hostname: use the route hostname if there is no overlapping with other listener hostnames.
		case len(listenerHostnameVal) == 0:
			if !checkHostNameIsolation(routeHostname, listenerHostnameVal, otherListenerHosts) {
				hostnames = append(hostnames, routeHostname)
			}

		// Listener hostname matches the route hostname: use it.
		case listenerHostnameVal == routeHostname:
			hostnames = append(hostnames, routeHostname)

		// Listener has a wildcard hostname: check if the route hostname matches.
		case strings.HasPrefix(listenerHostnameVal, allHosts):
			if hostnameMatchesWildcardHostname(routeHostname, listenerHostnameVal) &&
				!checkHostNameIsolation(routeHostname, listenerHostnameVal, otherListenerHosts) {
				hostnames = append(hostnames, routeHostname)
			}

		// Route has a wildcard hostname: check if the listener hostname matches.
		case strings.HasPrefix(routeHostname, allHosts):
			if hostnameMatchesWildcardHostname(listenerHostnameVal, routeHostname) {
				hostnames = append(hostnames, listenerHostnameVal)
			}
		}
	}

	s.Sort(hostnames)
	return hostnames
}

func mergeMap(left, right map[string]string) map[string]string {
	if left == nil {
		return right
	}
	maps.Copy(left, right)
	return left
}

func checkHostNameIsolation(routeHostname string, listenerHostName string, excludedListenerHostnames []string) bool {
	for _, exHost := range excludedListenerHostnames {
		if exHost == listenerHostName {
			continue
		}
		if routeHostname == exHost {
			return true
		}
		if strings.HasPrefix(exHost, allHosts) &&
			hostnameMatchesWildcardHostname(routeHostname, exHost) &&
			len(exHost) > len(listenerHostName) {
			return true
		}
	}

	return false
}

// hostnameMatchesWildcardHostname returns true if hostname has the non-wildcard
// portion of wildcardHostname as a suffix, plus at least one DNS label matching the
// wildcard.
func hostnameMatchesWildcardHostname(hostname, wildcardHostname string) bool {
	if !strings.HasSuffix(hostname, strings.TrimPrefix(wildcardHostname, allHosts)) {
		return false
	}

	wildcardMatch := strings.TrimSuffix(hostname, strings.TrimPrefix(wildcardHostname, allHosts))
	return len(wildcardMatch) > 0
}
