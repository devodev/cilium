//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package lb

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/cilium/cilium/enterprise/operator/pkg/wafpolicy"
	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	lbServiceVIPIndexName        = ".spec.vipRef.name"
	lbServiceBackendIndexName    = ".spec.routes.http.backend"
	lbServiceTlsSecretsIndexName = ".spec.tls.secrets" // TLS Certificates & Validation secrets
	lbServiceK8sServiceIndexName = ".status.k8sServiceRef.name"
)

const (
	logfieldIPv4Assigned        = "ipv4Assigned"
	logfieldIPv6Assigned        = "ipv6Assigned"
	logfieldStatusConditionsMet = "statusConditionsMet"
	logfieldResult              = "result"
)

const (
	endpointSliceIPv6Midfix = "ipv6-"
)

type lbServiceReconciler struct {
	logger       *slog.Logger
	client       client.Client
	scheme       *runtime.Scheme
	nodeSource   *ciliumNodeSource
	ingestor     *ingestor
	t1Translator *lbServiceT1Translator
	t2Translator *lbServiceT2Translator
	wafResolver  *wafpolicy.Resolver
}

type reconcilerConfig struct {
	SecretsNamespace    string
	ServerName          string
	AccessLog           reconcilerAccesslogConfig
	Metrics             reconcilerMetricsConfig
	RequestID           reconcilerRequestIDConfig
	T1T2HealthCheck     reconcilerT1T2HealthCheckConfig
	OriginalIPDetection reconcilerOriginalIPDetectionConfig
	Policy              reconcilerPolicyConfig
	IPFamilies          reconcilerIPFamilyConfig
}

type reconcilerAccesslogConfig struct {
	EnableStdOut             bool
	EnableGRPC               bool
	FilePath                 string
	EnableHC                 bool
	EnableTCP                bool
	EnableUDP                bool
	FormatHC                 string
	JSONFormatHC             string
	FormatTCP                string
	JSONFormatTCP            string
	FormatUDP                string
	JSONFormatUDP            string
	FormatTLSPassthrough     string
	JSONFormatTLSPassthrough string
	FormatTLS                string
	JSONFormatTLS            string
	FormatHTTPS              string
	JSONFormatHTTPS          string
	FormatHTTP               string
	JSONFormatHTTP           string
}

type reconcilerMetricsConfig struct {
	ClusterTimeoutBudget             bool
	ClusterAdditionalRequestResponse bool
	ClusterPerEndpoint               bool
}

type reconcilerRequestIDConfig struct {
	Generate bool
	Preserve bool
	Response bool
}

type reconcilerT1T2HealthCheckConfig struct {
	T1ProbeTimeoutSeconds              uint
	T1ProbeHttpPath                    string
	T1ProbeHttpMethod                  string
	T1ProbeHttpUserAgentPrefix         string
	T2HCPushEnabled                    bool
	T2ProbeMinHealthyBackendPercentage uint
	T2EnvoyHCEventLoggingEnabled       bool
	T2EnvoyHCEventLoggingStateDir      string
}

type reconcilerOriginalIPDetectionConfig struct {
	UseRemoteAddress  bool
	XffNumTrustedHops uint
}

type reconcilerPolicyConfig struct {
	EnableCiliumPolicyFilters bool
}

func newLbServiceReconciler(logger *slog.Logger, client client.Client, scheme *runtime.Scheme, nodeSource *ciliumNodeSource, ingestor *ingestor, t1Translator *lbServiceT1Translator, t2Translator *lbServiceT2Translator, wafResolver *wafpolicy.Resolver) *lbServiceReconciler {
	return &lbServiceReconciler{
		logger:       logger,
		client:       client,
		scheme:       scheme,
		nodeSource:   nodeSource,
		ingestor:     ingestor,
		t1Translator: t1Translator,
		t2Translator: t2Translator,
		wafResolver:  wafResolver,
	}
}

// SetupWithManager sets up the controller with the Manager and configures
// the different watches. All the watcher trigger a reconciliation.
func (r *lbServiceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	for indexName, indexerFunc := range map[string]client.IndexerFunc{
		lbServiceVIPIndexName: func(rawObj client.Object) []string {
			return rawObj.(*isovalentv1alpha1.LBService).AllReferencedVIPNames()
		},
		lbServiceBackendIndexName: func(rawObj client.Object) []string {
			return rawObj.(*isovalentv1alpha1.LBService).AllReferencedBackendNames()
		},
		lbServiceTlsSecretsIndexName: func(rawObj client.Object) []string {
			return rawObj.(*isovalentv1alpha1.LBService).AllReferencedSecretNames()
		},
		lbServiceK8sServiceIndexName: func(rawObj client.Object) []string {
			return rawObj.(*isovalentv1alpha1.LBService).AllReferencedK8sServiceNames()
		},
	} {
		if err := mgr.GetFieldIndexer().IndexField(context.Background(), &isovalentv1alpha1.LBService{}, indexName, indexerFunc); err != nil {
			return fmt.Errorf("failed to setup field indexer %q: %w", indexName, err)
		}
	}

	builder := ctrl.NewControllerManagedBy(mgr).
		// Watch for changed LBService resources (main resource)
		For(&isovalentv1alpha1.LBService{}).
		// Watch for changed LBVIP resources and trigger LBServices that reference the changed lbvip
		Watches(&isovalentv1alpha1.LBVIP{}, r.enqueueReferencingLBServicesByIndex(lbServiceVIPIndexName, byName)).
		// Watch for changed LBBackend resources and trigger LBServices that reference the changed backend
		Watches(&isovalentv1alpha1.LBBackendPool{}, r.enqueueReferencingLBServicesByIndex(lbServiceBackendIndexName, byName)).
		// Watch for changed LBDeployment resources and trigger all LBServices
		Watches(&isovalentv1alpha1.LBDeployment{}, r.enqueueAllLBServices(true)).
		// Watch for changed Secrets resources and trigger LBServices that reference the changed Secret.
		// This is mainly to update the status. The actual content of the Secrets are getting transferred via sDS.
		Watches(&corev1.Secret{}, r.enqueueReferencingLBServicesByIndex(lbServiceTlsSecretsIndexName, byName)).
		// Watch for changed K8s Service resources and trigger LBServices that indirectly reference the changed Service.
		Watches(&corev1.Service{}, r.enqueueReferencingLBServicesByIndex(lbServiceK8sServiceIndexName, byName)).
		// Watch for changed EndpointSlice resources and trigger LBServices that indirectly reference the changed EndpointSlice.
		// Note: Multiple EndpointSlice can exist per K8s Service by design. They reference their K8s Service via K8s Label.
		Watches(&discoveryv1.EndpointSlice{}, r.enqueueReferencingLBServicesByIndex(lbServiceK8sServiceIndexName, byServiceNameLabel)).
		// T1 Service resource with OwnerReference to the LBService
		Owns(&corev1.Service{}).
		// T1 EndpointSlice resource with OwnerReference to the LBService
		Owns(&discoveryv1.EndpointSlice{}).
		// T2 CiliumEnvoyConfig resource with OwnerReference to the LBService
		Owns(&ciliumv2.CiliumEnvoyConfig{}).
		// CiliumNode changes should trigger a reconciliation of all LBServices
		WatchesRawSource(r.nodeSource.ToSource(r.enqueueAllLBServices(false)))

	if r.wafResolver.Enabled() {
		// Watch for changed IsovalentWAFPolicy resources and trigger all LBServices in the same namespace.
		builder = builder.Watches(&isovalentv1alpha1.IsovalentWAFPolicy{}, r.enqueueAllLBServices(true))
	}

	return builder.Complete(r)
}

// Reconcile implements the main reconciliation loop that gets triggered whenever a LBService resource or a related resource changes.
func (r *lbServiceReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	scopedLog := r.logger.With(
		logfields.Controller, "LBService",
		logfields.Resource, req.NamespacedName,
	)

	scopedLog.Info("Reconciling LBService")
	lb := &isovalentv1alpha1.LBService{}
	if err := r.client.Get(ctx, req.NamespacedName, lb); err != nil {
		if !k8serrors.IsNotFound(err) {
			return controllerruntime.Fail(fmt.Errorf("failed to get LBService: %w", err))
		}

		scopedLog.Debug("LBService not found - assuming it has been deleted")

		// LBService has been deleted in the meantime
		return controllerruntime.Success()
	}

	// LBService gets deleted via foreground deletion (DeletionTimestamp set)
	// -> abort and wait for the actual deletion to trigger a reconcile
	if lb.GetDeletionTimestamp() != nil {
		scopedLog.Debug("LBService is marked for deletion - waiting for actual deletion")
		return controllerruntime.Success()
	}

	if err := r.reconcileResources(ctx, lb); err != nil {
		if k8serrors.IsForbidden(err) && k8serrors.HasStatusCause(err, corev1.NamespaceTerminatingCause) {
			// The creation of one of the resources failed because the
			// namespace is terminating. The LBService resource itself is also expected
			// to be marked for deletion, but we haven't yet received the
			// corresponding event, so let's not print an error message.
			scopedLog.Info("Aborting reconciliation because namespace is being terminated")
			return controllerruntime.Success()
		}

		return controllerruntime.Fail(fmt.Errorf("failed to reconcile LBService: %w", err))
	}

	lb.UpdateResourceStatus()

	// Update the status of LBService
	if err := r.client.Status().Update(ctx, lb); err != nil {
		return controllerruntime.Fail(fmt.Errorf("failed to update LBService status: %w", err))
	}

	return controllerruntime.Success()
}

func (r *lbServiceReconciler) reconcileResources(ctx context.Context, lbsvc *isovalentv1alpha1.LBService) error {
	// Validate LBService (in addition to CRD validation)
	r.updateJWTAuthInStatus(lbsvc)

	//
	// Load dependent resources that have relevant input for the model
	//

	// Load all nodes
	nodeStore, err := r.nodeSource.Store(ctx)
	if err != nil {
		return fmt.Errorf("failed to get node store: %w", err)
	}
	allNodes := nodeStore.List()

	// Try loading relevant LBDeployments that match this LBService
	// -> can be an empty list
	deployments, err := r.loadDeployments(ctx, lbsvc)
	if err != nil {
		return fmt.Errorf("failed to load LBDeployments: %w", err)
	}

	r.updateDeploymentsInStatus(lbsvc, deployments)

	// Try loading referenced LBVIP
	// -> vip can be nil
	vip, err := r.loadVIP(ctx, lbsvc)
	if err != nil {
		return fmt.Errorf("failed to load referenced LBVIP: %w", err)
	}

	r.updateVIPInStatus(lbsvc, vip)

	// Try loading any existing T1 K8s Service from a previous reconciliation as this might contain the IP that has been allocated by LB IPAM
	// -> existingT1K8sService can be nil
	existingT1K8sService, err := r.loadT1Service(ctx, lbsvc)
	if err != nil {
		return fmt.Errorf("failed to load existing T1 k8s service: %w", err)
	}

	// Try loading referenced LBBackends (in same namespace)
	backends, missingBackends, err := r.loadBackends(ctx, lbsvc)
	if err != nil {
		return fmt.Errorf("failed to load referenced backends: %w", err)
	}

	r.updateBackendExistenceInStatus(lbsvc, missingBackends)
	r.updateBackendCompatibilityInStatus(lbsvc, backends)
	r.updateBackendK8sServiceRefsInStatus(lbsvc, backends)

	// Try loading referenced TLS Secrets (in same namespace) to update the status accordingly
	referencedSecrets, missingSecrets, err := r.loadTLSSecrets(ctx, lbsvc)
	if err != nil {
		return fmt.Errorf("failed to load referenced TLS secrets: %w", err)
	}

	r.updateSecretExistenceInStatus(lbsvc, missingSecrets)
	r.updateSecretCompatibilityInStatus(lbsvc, referencedSecrets)

	// Try loading referenced K8s Services
	referencedK8sServices, missingK8sServices, err := r.loadK8sServices(ctx, lbsvc)
	if err != nil {
		return fmt.Errorf("failed to load referenced K8s Services: %w", err)
	}

	r.updateK8sServiceExistenceInStatus(lbsvc, missingK8sServices)

	// Try loading EndpointSlices of referenced K8s Services
	referencedEndpointSlices, missingEndpointSlices, err := r.loadK8sEndpointSlices(ctx, lbsvc)
	if err != nil {
		return fmt.Errorf("failed to load referenced EndpointSlices (for K8s Services): %w", err)
	}

	r.updateEndpointSliceExistenceInStatus(lbsvc, missingEndpointSlices)

	// Try resolving WAF configuration for the LBService
	var wafConfig *wafpolicy.EffectiveConfig
	if lbsvc.IsL7Proxy() {
		wafConfig, err = r.wafResolver.ResolveConfig(ctx, wafpolicy.PolicyTarget{
			Name:      lbsvc.Name,
			Namespace: lbsvc.Namespace,
			Labels:    lbsvc.Labels,
		})
		if err != nil {
			return err
		}
	}

	//
	// Translate into internal model
	//

	model, err := r.ingestor.ingest(ctx, vip, lbsvc, backends, deployments, allNodes, existingT1K8sService, referencedSecrets, referencedK8sServices, referencedEndpointSlices)
	if err != nil {
		return fmt.Errorf("failed to ingest resources: %w", err)
	}
	model.effectiveWAFConfig = wafConfig

	r.updateNodesAssignedInStatus(model, lbsvc)
	r.updateAssignedIpInStatus(model, lbsvc)
	r.updateModesInStatus(model, lbsvc)

	// Stop reconciliation if assigned IP is not available or some status
	// conditions on the LBService aren't met yet. Also, we
	// should delete the T1 Service, EndpointSlice, and T2 CEC if they exist.
	// Otherwise, the BGP keeps advertise the stale VIP, DPlane keeps
	// handling the traffic towards the stable VIP, etc. - or creating
	// depending resources might fail due to incompatibilities.

	if (model.vip.IPv4SupportedByIPFamily() && !model.vip.IPv4Assigned()) || (model.vip.IPv6SupportedByIPFamily() && !model.vip.IPv6Assigned()) || !lbsvc.AllStatusConditionsMet() {
		r.logger.Debug("Stopping reconciliation - no IP assigned or status conditions not met (yet)",
			logfieldIPv4Assigned, model.vip.IPv4Assigned(),
			logfieldIPv6Assigned, model.vip.IPv6Assigned(),
			logfieldStatusConditionsMet, lbsvc.AllStatusConditionsMet())
		if err = r.ensureServiceDeleted(ctx, model); err != nil {
			return fmt.Errorf("failed to ensure service is deleted: %w", err)
		}
		if err = r.ensureEndpointSliceDeleted(ctx, model, false); err != nil {
			return fmt.Errorf("failed to ensure IPv4 endpointslice is deleted: %w", err)
		}
		if err = r.ensureEndpointSliceDeleted(ctx, model, true); err != nil {
			return fmt.Errorf("failed to ensure IPv6 endpointslice is deleted: %w", err)
		}
		if err = r.ensureCECDeleted(ctx, model); err != nil {
			return fmt.Errorf("failed to ensure CEC is deleted: %w", err)
		}
		return nil
	}

	//
	// T1
	//

	// Build desired resources
	desiredT1Service := r.t1Translator.DesiredService(model)
	desiredT1EndpointSliceIPv4 := r.t1Translator.DesiredEndpointSlice(model, false)
	desiredT1EndpointSliceIPv6 := r.t1Translator.DesiredEndpointSlice(model, true)

	// Set controlling ownerreferences
	if err := controllerutil.SetControllerReference(lbsvc, desiredT1Service, r.scheme); err != nil {
		return fmt.Errorf("failed to set ownerreference on T1 Service: %w", err)
	}

	if desiredT1EndpointSliceIPv4 != nil {
		if err := controllerutil.SetControllerReference(lbsvc, desiredT1EndpointSliceIPv4, r.scheme); err != nil {
			return fmt.Errorf("failed to set ownerreference on T1 EndpointSlice: %w", err)
		}
	}

	if desiredT1EndpointSliceIPv6 != nil {
		if err := controllerutil.SetControllerReference(lbsvc, desiredT1EndpointSliceIPv6, r.scheme); err != nil {
			return fmt.Errorf("failed to set ownerreference on T1 EndpointSlice: %w", err)
		}
	}

	// Create or update resources
	//
	// delete service if ip family changed (to prevent that current clusterip doesn't match new ipfamily)
	if existingT1K8sService != nil && !slices.Equal(existingT1K8sService.Spec.IPFamilies, desiredT1Service.Spec.IPFamilies) {
		if err := r.client.Delete(ctx, existingT1K8sService); err != nil {
			return fmt.Errorf("failed to delete Service due to ipfamily changes: %w", err)
		}
	}

	if err := r.createOrUpdateService(ctx, desiredT1Service); err != nil {
		return err
	}

	if desiredT1EndpointSliceIPv4 != nil {
		if err := r.createOrUpdateEndpointSlice(ctx, desiredT1EndpointSliceIPv4); err != nil {
			return err
		}
	} else {
		if err := r.ensureEndpointSliceDeleted(ctx, model, false); err != nil {
			return err
		}
	}

	if desiredT1EndpointSliceIPv6 != nil {
		if err := r.createOrUpdateEndpointSlice(ctx, desiredT1EndpointSliceIPv6); err != nil {
			return err
		}
	} else {
		if err := r.ensureEndpointSliceDeleted(ctx, model, true); err != nil {
			return err
		}
	}

	//
	// T2
	//

	// Stop reconciliation if T1-only, T1 service is not available yet or is not able to bind
	// to the VIP (e.g. due to port clash with another service on the same VIP).
	// In this case any existing CEC gets deleted too. We don't delete Services & EndpointSlice
	// as this would result in a loop when the same services is created in the next
	// reconciliation.
	// Creating/Updating the T1 Service will trigger an additional reconciliation.
	if !model.vip.bindStatus.serviceExists || !model.vip.bindStatus.bindSuccessful || model.isTCPProxyT1OnlyMode() || model.isUDPProxyT1OnlyMode() {
		if err = r.ensureCECDeleted(ctx, model); err != nil {
			return fmt.Errorf("failed to ensure CEC is deleted: %w", err)
		}
		return nil
	}

	// Build desired resources
	desiredT2CiliumEnvoyConfig, err := r.t2Translator.DesiredCiliumEnvoyConfig(model)
	if err != nil {
		return err
	}

	// Set controlling ownerreferences
	if err := controllerutil.SetControllerReference(lbsvc, desiredT2CiliumEnvoyConfig, r.scheme); err != nil {
		return fmt.Errorf("failed to set ownerreference on T2 CiliumEnvoyConfig: %w", err)
	}

	// Create or update resources
	if err := r.createOrUpdateCiliumEnvoyConfig(ctx, desiredT2CiliumEnvoyConfig); err != nil {
		return err
	}

	return nil
}

func (r *lbServiceReconciler) loadDeployments(ctx context.Context, lbsvc *isovalentv1alpha1.LBService) ([]isovalentv1alpha1.LBDeployment, error) {
	matchingDeployments := []isovalentv1alpha1.LBDeployment{}

	deploymentList := &isovalentv1alpha1.LBDeploymentList{}
	if err := r.client.List(ctx, deploymentList, client.InNamespace(lbsvc.Namespace)); err != nil {
		return nil, err
	}

	for _, depl := range deploymentList.Items {
		if cond := depl.GetStatusCondition(isovalentv1alpha1.ConditionTypeDeploymentAccepted); cond == nil || cond.Status == metav1.ConditionFalse {
			r.logger.Debug("Not yet accepted or invalid LBDeployment - skipping",
				logfields.K8sNamespace, lbsvc.Namespace,
				logfields.Name, depl.Name,
				logfields.Service, lbsvc.Name,
			)

			continue
		}

		if depl.Spec.Services.LabelSelector != nil {
			selector, err := slim_metav1.LabelSelectorAsSelector(depl.Spec.Services.LabelSelector)
			if err != nil {
				// In case of an error, skip the LBDeployment. This should never be the case as this is already validated
				// by the LBDeployment reconciler - therefore skipping without logging.
				continue
			}

			if selector.Matches(labels.Set(lbsvc.Labels)) {
				matchingDeployments = append(matchingDeployments, depl)
			}
		}
	}

	return matchingDeployments, nil
}

func (r *lbServiceReconciler) loadVIP(ctx context.Context, lbsvc *isovalentv1alpha1.LBService) (*isovalentv1alpha1.LBVIP, error) {
	vip := &isovalentv1alpha1.LBVIP{}
	if err := r.client.Get(ctx, types.NamespacedName{Namespace: lbsvc.Namespace, Name: lbsvc.Spec.VIPRef.Name}, vip); err != nil {
		if !k8serrors.IsNotFound(err) {
			return nil, err
		}

		// Continue if not found
		return nil, nil
	}

	return vip, nil
}

func (r *lbServiceReconciler) loadBackends(ctx context.Context, lbsvc *isovalentv1alpha1.LBService) ([]*isovalentv1alpha1.LBBackendPool, []string, error) {
	backends := []*isovalentv1alpha1.LBBackendPool{}
	missingBackends := []string{}

	allReferencedBackendNames := lbsvc.AllReferencedBackendNames()

	for _, bName := range allReferencedBackendNames {
		b := &isovalentv1alpha1.LBBackendPool{}
		if err := r.client.Get(ctx, types.NamespacedName{Namespace: lbsvc.Namespace, Name: bName}, b); err != nil {
			if !k8serrors.IsNotFound(err) {
				return nil, nil, fmt.Errorf("failed to get referenced LBBackend: %w", err)
			}

			// Continue reconciliation if backends don't exist (yet).
			// But keep track of them to report in log and status later on.
			// Once the missing referenced backends gets created it will trigger a reconciliation
			missingBackends = append(missingBackends, bName)
			continue
		}

		backends = append(backends, b)
	}

	return backends, missingBackends, nil
}

func (r *lbServiceReconciler) loadTLSSecrets(ctx context.Context, lbsvc *isovalentv1alpha1.LBService) (map[string]*corev1.Secret, []string, error) {
	missingSecrets := []string{}
	secretMap := map[string]*corev1.Secret{}

	// TLS Certs
	allReferencedSecretNames := lbsvc.AllReferencedSecretNames()

	for _, secretName := range allReferencedSecretNames {
		s := &corev1.Secret{}
		if err := r.client.Get(ctx, types.NamespacedName{Namespace: lbsvc.Namespace, Name: secretName}, s); err != nil {
			if !k8serrors.IsNotFound(err) {
				return nil, nil, fmt.Errorf("failed to get referenced TLS Secret: %w", err)
			}

			// Continue reconciliation if TLS Secrets don't exist (yet).
			// But keep track of them to report in log and status later on.
			// Once the missing referenced backends gets created it will trigger a reconciliation
			missingSecrets = append(missingSecrets, secretName)
			continue
		}

		secretMap[secretName] = s
	}

	return secretMap, missingSecrets, nil
}

func (r *lbServiceReconciler) loadK8sServices(ctx context.Context, lbsvc *isovalentv1alpha1.LBService) ([]corev1.Service, []string, error) {
	missingSVCs := []string{}
	result := []corev1.Service{}

	// K8s Services
	allReferencedK8sServiceNames := lbsvc.AllReferencedK8sServiceNames()

	for _, serviceName := range allReferencedK8sServiceNames {
		s := &corev1.Service{}
		if err := r.client.Get(ctx, types.NamespacedName{Namespace: lbsvc.Namespace, Name: serviceName}, s); err != nil {
			if !k8serrors.IsNotFound(err) {
				return nil, nil, fmt.Errorf("failed to get referenced K8s Service: %w", err)
			}

			// Continue reconciliation if K8s Service don't exist (yet).
			// But keep track of them to report in log and status later on.
			// Once the missing referenced service gets created it will trigger a reconciliation
			missingSVCs = append(missingSVCs, serviceName)
			continue
		}

		result = append(result, *s)
	}

	return result, missingSVCs, nil
}

func (r *lbServiceReconciler) loadK8sEndpointSlices(ctx context.Context, lbsvc *isovalentv1alpha1.LBService) ([]discoveryv1.EndpointSlice, []string, error) {
	missingES := []string{}
	result := []discoveryv1.EndpointSlice{}

	// K8s Services
	allReferencedK8sServiceNames := lbsvc.AllReferencedK8sServiceNames()

	for _, serviceName := range allReferencedK8sServiceNames {
		esList := &discoveryv1.EndpointSliceList{}
		listOptions := []client.ListOption{
			client.InNamespace(lbsvc.Namespace),
			client.MatchingLabels{
				discoveryv1.LabelServiceName: serviceName,
			},
		}
		if err := r.client.List(ctx, esList, listOptions...); err != nil {
			return nil, nil, fmt.Errorf("failed to list EndpointSlices for Service %s: %w", serviceName, err)
		}

		if len(esList.Items) == 0 {
			// Continue reconciliation if no EndpointSlice exists for the given K8s Service (yet).
			// But keep track of them to report in log and status later on.
			// Once the missing referenced EndpointSlice gets created it will trigger a reconciliation
			missingES = append(missingES, serviceName)
			continue
		}

		result = append(result, esList.Items...)
	}

	return result, missingES, nil
}

func (r *lbServiceReconciler) loadT1Service(ctx context.Context, lbsvc *isovalentv1alpha1.LBService) (*corev1.Service, error) {
	svc := &corev1.Service{}
	if err := r.client.Get(ctx, types.NamespacedName{Namespace: lbsvc.Namespace, Name: getOwningResourceName(lbsvc.Name)}, svc); err != nil {
		if !k8serrors.IsNotFound(err) {
			return nil, err
		}

		// Continue if not found
		return nil, nil
	}

	return svc, nil
}

func (r *lbServiceReconciler) createOrUpdateService(ctx context.Context, desiredService *corev1.Service) error {
	svc := desiredService.DeepCopy()

	result, err := controllerutil.CreateOrUpdate(ctx, r.client, svc, func() error {
		svc.Spec = desiredService.Spec
		svc.OwnerReferences = desiredService.OwnerReferences
		svc.Annotations = desiredService.Annotations
		svc.Labels = desiredService.Labels

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

func (r *lbServiceReconciler) ensureServiceDeleted(ctx context.Context, model *lbService) error {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: model.namespace,
			Name:      model.getOwningResourceName(),
		},
	}
	if err := r.client.Delete(ctx, svc); err != nil {
		if !k8serrors.IsNotFound(err) {
			return err
		}
		// Service does not exist, which is fine
	}
	return nil
}

func (r *lbServiceReconciler) createOrUpdateEndpointSlice(ctx context.Context, desiredEndpointSlice *discoveryv1.EndpointSlice) error {
	ep := desiredEndpointSlice.DeepCopy()
	result, err := controllerutil.CreateOrUpdate(ctx, r.client, ep, func() error {
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

func (r *lbServiceReconciler) ensureEndpointSliceDeleted(ctx context.Context, model *lbService, ipv6 bool) error {
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
	if err := r.client.Delete(ctx, ep); err != nil {
		if !k8serrors.IsNotFound(err) {
			return fmt.Errorf("failed to ensure endpointslice is deleted: %w", err)
		}
		// EndpointSlice does not exist, which is fine
	}
	return nil
}

func (r *lbServiceReconciler) createOrUpdateCiliumEnvoyConfig(ctx context.Context, desiredCEC *ciliumv2.CiliumEnvoyConfig) error {
	cec := desiredCEC.DeepCopy()

	result, err := controllerutil.CreateOrUpdate(ctx, r.client, cec, func() error {
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

func (r *lbServiceReconciler) ensureCECDeleted(ctx context.Context, model *lbService) error {
	cec := &ciliumv2.CiliumEnvoyConfig{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: model.namespace,
			Name:      model.getOwningResourceName(),
		},
	}
	if err := r.client.Delete(ctx, cec); err != nil {
		if !k8serrors.IsNotFound(err) {
			return err
		}
		// CEC does not exist, which is fine
	}
	return nil
}

func (r *lbServiceReconciler) enqueueReferencingLBServicesByIndex(indexName string, indexKeyFunc func(obj client.Object) string) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		lbList := isovalentv1alpha1.LBServiceList{}

		listOps := &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(indexName, indexKeyFunc(obj)),
			Namespace:     obj.GetNamespace(),
		}

		if err := r.client.List(ctx, &lbList, listOps); err != nil {
			r.logger.Warn("Failed to list LBServices", logfields.Error, err)
			return nil
		}

		result := []reconcile.Request{}

		for _, i := range lbList.Items {
			result = append(result, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: i.Namespace,
					Name:      i.Name,
				},
			})
		}

		return result
	})
}

func byName(obj client.Object) string {
	return obj.GetName()
}

func byServiceNameLabel(obj client.Object) string {
	return obj.GetLabels()[discoveryv1.LabelServiceName]
}

func (r *lbServiceReconciler) enqueueAllLBServices(onlySameNamespace bool) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		lbList := isovalentv1alpha1.LBServiceList{}
		listOpts := []client.ListOption{}
		if onlySameNamespace {
			listOpts = append(listOpts, client.InNamespace(obj.GetNamespace()))
		}

		if err := r.client.List(ctx, &lbList, listOpts...); err != nil {
			r.logger.Warn("Failed to list LBServices", logfields.Error, err)
			return nil
		}

		result := []reconcile.Request{}

		for _, i := range lbList.Items {
			result = append(result, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: i.Namespace,
					Name:      i.Name,
				},
			})
		}

		return result
	})
}

func (*lbServiceReconciler) updateJWTAuthInStatus(lbsvc *isovalentv1alpha1.LBService) {
	condition := metav1.Condition{
		Type:               isovalentv1alpha1.ConditionTypeServiceValid,
		Status:             metav1.ConditionTrue,
		Reason:             isovalentv1alpha1.ServiceValidReasonValid,
		Message:            "Service is valid",
		ObservedGeneration: lbsvc.GetGeneration(),
		LastTransitionTime: metav1.Now(),
	}

	if lbsvc.Spec.Applications.HTTPProxy != nil {
		httpGlobalAuth := lbsvc.Spec.Applications.HTTPProxy.Auth
		globalJWTAuthConfigured := httpGlobalAuth != nil && httpGlobalAuth.JWT != nil

		for _, route := range lbsvc.Spec.Applications.HTTPProxy.Routes {
			routeJWTAuthConfigured := route.Auth != nil && route.Auth.JWT != nil

			if route.RequestFiltering != nil {
				for _, rule := range route.RequestFiltering.Rules {
					if rule.JWTClaims != nil && !globalJWTAuthConfigured && !routeJWTAuthConfigured {
						condition.Status = metav1.ConditionFalse
						condition.Reason = isovalentv1alpha1.ServiceValidReasonInvalidJWTAuthMissing
						condition.Message = "One or more HTTP routes use JWT claim requestfiltering without configured JWT authentication"
					}
				}
			}
		}

	} else if lbsvc.Spec.Applications.HTTPSProxy != nil {
		httpGlobalAuth := lbsvc.Spec.Applications.HTTPSProxy.Auth
		globalJWTAuthConfigured := httpGlobalAuth != nil && httpGlobalAuth.JWT != nil

		for _, route := range lbsvc.Spec.Applications.HTTPSProxy.Routes {
			routeJWTAuthConfigured := route.Auth != nil && route.Auth.JWT != nil

			if route.RequestFiltering != nil {
				for _, rule := range route.RequestFiltering.Rules {
					if rule.JWTClaims != nil && !globalJWTAuthConfigured && !routeJWTAuthConfigured {
						condition.Status = metav1.ConditionFalse
						condition.Reason = isovalentv1alpha1.ServiceValidReasonInvalidJWTAuthMissing
						condition.Message = "One or more HTTP routes use JWT claim requestfiltering without configured JWT authentication"
					}
				}
			}
		}
	}

	lbsvc.UpsertStatusCondition(isovalentv1alpha1.ConditionTypeServiceValid, condition)
}

func (*lbServiceReconciler) updateAssignedIpInStatus(model *lbService, lbsvc *isovalentv1alpha1.LBService) {
	ipAssignedCondition := metav1.Condition{
		Type:               isovalentv1alpha1.ConditionTypeIPAssigned,
		Status:             metav1.ConditionFalse,
		Reason:             isovalentv1alpha1.IPAssignedConditionReasonIPPending,
		Message:            "VIP pending",
		ObservedGeneration: lbsvc.GetGeneration(),
		LastTransitionTime: metav1.Now(),
	}

	var assignedIPv4 *string
	var assignedIPv6 *string

	ipsAssigned := true
	if model.vip.IPv4SupportedByIPFamily() && !model.vip.IPv4Assigned() {
		ipsAssigned = false
	}
	if model.vip.IPv6SupportedByIPFamily() && !model.vip.IPv6Assigned() {
		ipsAssigned = false
	}

	if model.vip.bindStatus.serviceExists && !model.vip.bindStatus.bindSuccessful {
		ipAssignedCondition.Reason = isovalentv1alpha1.IPAssignedConditionReasonIPFailure
		ipAssignedCondition.Message = "Failed to bind to VIP: " + model.vip.bindStatus.bindIssue
	} else if ipsAssigned {
		ipAssignedCondition.Status = metav1.ConditionTrue
		ipAssignedCondition.Reason = isovalentv1alpha1.IPAssignedConditionReasonIPAssigned
		ipAssignedCondition.Message = "VIP assigned"

		assignedIPv4 = model.vip.assignedIPv4
		assignedIPv6 = model.vip.assignedIPv6
	}

	lbsvc.Status.Addresses.IPv4 = assignedIPv4
	lbsvc.Status.Addresses.IPv6 = assignedIPv6

	lbsvc.UpsertStatusCondition(isovalentv1alpha1.ConditionTypeIPAssigned, ipAssignedCondition)
}

func (*lbServiceReconciler) updateModesInStatus(model *lbService, lbsvc *isovalentv1alpha1.LBService) {
	appStatus := isovalentv1alpha1.LBServiceApplicationsStatus{}

	if model.isTCPProxy() {
		tcpProxyDeploymentMode := isovalentv1alpha1.LBTCPProxyDeploymentModeTypeT1T2
		tcpProxyForwardingMode := isovalentv1alpha1.LBTCPProxyForwardingModeDSR

		if model.isTCPProxyT1OnlyMode() {
			tcpProxyDeploymentMode = isovalentv1alpha1.LBTCPProxyDeploymentModeTypeT1Only
			if !model.isTCPProxyT1OnlyWithDSR() {
				tcpProxyForwardingMode = isovalentv1alpha1.LBTCPProxyForwardingModeSNAT
			}
		}

		appStatus.TCPProxy = &isovalentv1alpha1.LBServiceApplicationTCPProxyStatus{
			DeploymentMode: &tcpProxyDeploymentMode,
			ForwardingMode: &tcpProxyForwardingMode,
		}
	}

	if model.isUDPProxy() {
		udpProxyDeploymentMode := isovalentv1alpha1.LBUDPProxyDeploymentModeTypeT1T2
		udpProxyForwardingMode := isovalentv1alpha1.LBUDPProxyForwardingModeDSR

		if model.isUDPProxyT1OnlyMode() {
			udpProxyDeploymentMode = isovalentv1alpha1.LBUDPProxyDeploymentModeTypeT1Only
			if !model.isUDPProxyT1OnlyWithDSR() {
				udpProxyForwardingMode = isovalentv1alpha1.LBUDPProxyForwardingModeSNAT
			}
		}

		appStatus.UDPProxy = &isovalentv1alpha1.LBServiceApplicationUDPProxyStatus{
			DeploymentMode: &udpProxyDeploymentMode,
			ForwardingMode: &udpProxyForwardingMode,
		}
	}

	lbsvc.Status.Applications = appStatus
}

func (*lbServiceReconciler) updateDeploymentsInStatus(lbsvc *isovalentv1alpha1.LBService, deployments []isovalentv1alpha1.LBDeployment) {
	condition := metav1.Condition{
		Type:               isovalentv1alpha1.ConditionTypeLBDeploymentsUsed,
		Status:             metav1.ConditionTrue,
		Reason:             isovalentv1alpha1.LBDeploymentUsedConditionReasonNoLBDeploymentsUsed,
		Message:            "No LBDeployments are used",
		ObservedGeneration: lbsvc.GetGeneration(),
		LastTransitionTime: metav1.Now(),
	}

	if len(deployments) > 0 {
		names := []string{}
		for _, a := range deployments {
			names = append(names, a.Name)
		}
		slices.Sort(names)
		condition.Reason = isovalentv1alpha1.LBDeploymentUsedConditionReasonLBDeploymentsUsed
		condition.Message = fmt.Sprintf("%d LBDeployments are used: %v", len(deployments), names)
	}

	lbsvc.UpsertStatusCondition(isovalentv1alpha1.ConditionTypeLBDeploymentsUsed, condition)
}

func (*lbServiceReconciler) updateNodesAssignedInStatus(model *lbService, lbsvc *isovalentv1alpha1.LBService) {
	condition := metav1.Condition{
		Type:               isovalentv1alpha1.ConditionTypeNodesAssigned,
		Status:             metav1.ConditionTrue,
		Reason:             isovalentv1alpha1.NodesAssignedConditionReasonNodesAssigned,
		Message:            "T1 & T2 nodes assigned",
		ObservedGeneration: lbsvc.GetGeneration(),
		LastTransitionTime: metav1.Now(),
	}

	if len(model.t1NodeIPv4Addresses)+len(model.t1NodeIPv6Addresses) == 0 {
		condition.Status = metav1.ConditionFalse
		condition.Reason = isovalentv1alpha1.NodesAssignedConditionReasonNoNodesAssigned
		condition.Message = "No T1 nodes are assigned"
	}

	if len(model.t2NodeIPv4Addresses)+len(model.t2NodeIPv6Addresses) == 0 {
		condition.Status = metav1.ConditionFalse
		condition.Reason = isovalentv1alpha1.NodesAssignedConditionReasonNoNodesAssigned
		condition.Message = "No T2 nodes are assigned"
	}

	if len(model.t1NodeIPv4Addresses)+len(model.t1NodeIPv6Addresses) == 0 && len(model.t2NodeIPv4Addresses)+len(model.t2NodeIPv6Addresses) == 0 {
		condition.Status = metav1.ConditionFalse
		condition.Reason = isovalentv1alpha1.NodesAssignedConditionReasonNoNodesAssigned
		condition.Message = "No T1 & T2 nodes are assigned"
	}

	lbsvc.UpsertStatusCondition(isovalentv1alpha1.ConditionTypeNodesAssigned, condition)
}

func (*lbServiceReconciler) updateVIPInStatus(lbsvc *isovalentv1alpha1.LBService, vip *isovalentv1alpha1.LBVIP) {
	vipExistsCondition := metav1.Condition{
		Type:               isovalentv1alpha1.ConditionTypeVIPExist,
		Status:             metav1.ConditionTrue,
		Reason:             isovalentv1alpha1.VIPExistConditionReasonVIPExists,
		Message:            "Referenced VIP exist",
		ObservedGeneration: lbsvc.GetGeneration(),
		LastTransitionTime: metav1.Now(),
	}

	if vip == nil {
		vipExistsCondition.Status = metav1.ConditionFalse
		vipExistsCondition.Reason = isovalentv1alpha1.VIPExistConditionReasonVIPMissing
		vipExistsCondition.Message = fmt.Sprintf("Referenced VIP %v is missing", lbsvc.Spec.VIPRef.Name)
	}

	lbsvc.UpsertStatusCondition(isovalentv1alpha1.ConditionTypeVIPExist, vipExistsCondition)
}

func (*lbServiceReconciler) updateBackendExistenceInStatus(lbsvc *isovalentv1alpha1.LBService, missingBackends []string) {
	backendsExistCondition := metav1.Condition{
		Type:               isovalentv1alpha1.ConditionTypeBackendsExist,
		Status:             metav1.ConditionTrue,
		Reason:             isovalentv1alpha1.BackendsExistConditionReasonAllBackendsExist,
		Message:            "All referenced backends exist",
		ObservedGeneration: lbsvc.GetGeneration(),
		LastTransitionTime: metav1.Now(),
	}

	if len(missingBackends) > 0 {
		backendsExistCondition.Status = metav1.ConditionFalse
		backendsExistCondition.Reason = isovalentv1alpha1.BackendsExistConditionReasonMissingBackends
		backendsExistCondition.Message = fmt.Sprintf("There are referenced backends that do not exist: %v", missingBackends)
	}

	lbsvc.UpsertStatusCondition(isovalentv1alpha1.ConditionTypeBackendsExist, backendsExistCondition)
}

func (r *lbServiceReconciler) updateBackendCompatibilityInStatus(lbsvc *isovalentv1alpha1.LBService, backends []*isovalentv1alpha1.LBBackendPool) {
	backendsCompatibleCondition := metav1.Condition{
		Type:               isovalentv1alpha1.ConditionTypeBackendsCompatible,
		Status:             metav1.ConditionTrue,
		Reason:             isovalentv1alpha1.BackendsCompatibleConditionReasonAllBackendsCompatible,
		Message:            "All referenced backends are compatible",
		ObservedGeneration: lbsvc.GetGeneration(),
		LastTransitionTime: metav1.Now(),
	}

	incompatibleBackendMessages := []string{}

	incompatibleBackendMessages = append(incompatibleBackendMessages, r.getIncompatiblePersistentBackendLBAlgorithms(lbsvc, backends)...)
	incompatibleBackendMessages = append(incompatibleBackendMessages, r.getIncompatibleT1MultipleBackendPorts(lbsvc, backends)...)
	incompatibleBackendMessages = append(incompatibleBackendMessages, r.getIncompatibleT1HostnameBackends(lbsvc, backends)...)
	incompatibleBackendMessages = append(incompatibleBackendMessages, r.getIncompatibleT1TLSHealthCheckBackends(lbsvc, backends)...)
	incompatibleBackendMessages = append(incompatibleBackendMessages, r.getIncompatibleT1BackendIPFamilies(lbsvc, backends)...)
	incompatibleBackendMessages = append(incompatibleBackendMessages, r.getInvalidBackends(backends)...)
	incompatibleBackendMessages = append(incompatibleBackendMessages, r.getIncompatibleProxyProtocol(lbsvc, backends)...)

	if len(incompatibleBackendMessages) > 0 {
		backendsCompatibleCondition.Status = metav1.ConditionFalse
		backendsCompatibleCondition.Reason = isovalentv1alpha1.BackendsCompatibleConditionReasonIncompatibleBackends
		backendsCompatibleCondition.Message = strings.Join(incompatibleBackendMessages, "\n")
	}

	lbsvc.UpsertStatusCondition(isovalentv1alpha1.ConditionTypeBackendsCompatible, backendsCompatibleCondition)
}

func (r *lbServiceReconciler) updateBackendK8sServiceRefsInStatus(lbsvc *isovalentv1alpha1.LBService, backends []*isovalentv1alpha1.LBBackendPool) {
	allReferencedK8sServiceNames := []string{}

	for _, b := range backends {
		allReferencedK8sServiceNames = append(allReferencedK8sServiceNames, b.AllReferencedK8sServiceNames()...)
	}

	slices.Sort(allReferencedK8sServiceNames)
	allReferencedK8sServiceNames = slices.Compact(allReferencedK8sServiceNames)

	k8sServiceRefs := make([]isovalentv1alpha1.LBBackendPoolK8sServiceRef, 0, len(allReferencedK8sServiceNames))

	for _, s := range allReferencedK8sServiceNames {
		k8sServiceRefs = append(k8sServiceRefs, isovalentv1alpha1.LBBackendPoolK8sServiceRef{
			Name: s,
		})
	}

	lbsvc.Status.K8sServiceRefs = k8sServiceRefs
}

func (*lbServiceReconciler) getIncompatiblePersistentBackendLBAlgorithms(lbsvc *isovalentv1alpha1.LBService, backends []*isovalentv1alpha1.LBBackendPool) []string {
	incompatibleBackendMessages := []string{}

	backendsUsedForPersistentBackend := map[string]struct{}{}

	switch {
	case lbsvc.Spec.Applications.HTTPProxy != nil:
		for _, r := range lbsvc.Spec.Applications.HTTPProxy.Routes {
			if r.PersistentBackend != nil {
				backendsUsedForPersistentBackend[r.BackendRef.Name] = struct{}{}
			}
		}
	case lbsvc.Spec.Applications.HTTPSProxy != nil:
		for _, r := range lbsvc.Spec.Applications.HTTPSProxy.Routes {
			if r.PersistentBackend != nil {
				backendsUsedForPersistentBackend[r.BackendRef.Name] = struct{}{}
			}
		}
	case lbsvc.Spec.Applications.TLSPassthrough != nil:
		for _, r := range lbsvc.Spec.Applications.TLSPassthrough.Routes {
			if r.PersistentBackend != nil {
				backendsUsedForPersistentBackend[r.BackendRef.Name] = struct{}{}
			}
		}
	case lbsvc.Spec.Applications.TLSProxy != nil:
		for _, r := range lbsvc.Spec.Applications.TLSProxy.Routes {
			if r.PersistentBackend != nil {
				backendsUsedForPersistentBackend[r.BackendRef.Name] = struct{}{}
			}
		}
	case lbsvc.Spec.Applications.TCPProxy != nil:
		for _, r := range lbsvc.Spec.Applications.TCPProxy.Routes {
			if r.PersistentBackend != nil {
				backendsUsedForPersistentBackend[r.BackendRef.Name] = struct{}{}
			}
		}
	case lbsvc.Spec.Applications.UDPProxy != nil:
		for _, r := range lbsvc.Spec.Applications.UDPProxy.Routes {
			if r.PersistentBackend != nil {
				backendsUsedForPersistentBackend[r.BackendRef.Name] = struct{}{}
			}
		}
	}

	for b := range backendsUsedForPersistentBackend {
		for _, configuredBackend := range backends {
			if b == configuredBackend.Name && (configuredBackend.Spec.Loadbalancing == nil || configuredBackend.Spec.Loadbalancing.Algorithm.ConsistentHashing == nil) {
				incompatibleBackendMessages = append(incompatibleBackendMessages, fmt.Sprintf("Backend %q is incompatible: Configured \"persistentBackend\" without LB algorithm \"consistentHashing\"", b))
			}
		}
	}

	return incompatibleBackendMessages
}

func (*lbServiceReconciler) getIncompatibleT1MultipleBackendPorts(lbsvc *isovalentv1alpha1.LBService, backends []*isovalentv1alpha1.LBBackendPool) []string {
	incompatibleBackendMessages := []string{}

	backendsUsedAsT1OnlyBackend := map[string]struct{}{}

	if lbsvc.Spec.Applications.TCPProxy != nil && lbsvc.Spec.Applications.TCPProxy.ForceDeploymentMode != nil && *lbsvc.Spec.Applications.TCPProxy.ForceDeploymentMode == isovalentv1alpha1.LBTCPProxyForceDeploymentModeT1 {
		for _, t1r := range lbsvc.Spec.Applications.TCPProxy.Routes {
			backendsUsedAsT1OnlyBackend[t1r.BackendRef.Name] = struct{}{}
		}
	} else if lbsvc.Spec.Applications.UDPProxy != nil && lbsvc.Spec.Applications.UDPProxy.ForceDeploymentMode != nil && *lbsvc.Spec.Applications.UDPProxy.ForceDeploymentMode == isovalentv1alpha1.LBUDPProxyForceDeploymentModeT1 {
		for _, t1r := range lbsvc.Spec.Applications.UDPProxy.Routes {
			backendsUsedAsT1OnlyBackend[t1r.BackendRef.Name] = struct{}{}
		}
	}

	for b := range backendsUsedAsT1OnlyBackend {
		for _, configuredBackend := range backends {
			if b == configuredBackend.Name {
				port := int32(0)

				for _, be := range configuredBackend.Spec.Backends {
					if port == 0 {
						port = be.Port
					}
					if port != be.Port {
						incompatibleBackendMessages = append(incompatibleBackendMessages, fmt.Sprintf("Backend %q is incompatible: T1 only service does not support backends with different ports", b))
						break
					}
				}
			}
		}
	}

	return incompatibleBackendMessages
}

func (r *lbServiceReconciler) getIncompatibleT1HostnameBackends(lbsvc *isovalentv1alpha1.LBService, backends []*isovalentv1alpha1.LBBackendPool) []string {
	backendMap := map[string]*isovalentv1alpha1.LBBackendPool{}
	for _, b := range backends {
		backendMap[b.Name] = b
	}

	backendsWithHostname := []string{}

	if lbsvc.Spec.Applications.TCPProxy != nil && lbsvc.Spec.Applications.TCPProxy.ForceDeploymentMode != nil && *lbsvc.Spec.Applications.TCPProxy.ForceDeploymentMode == isovalentv1alpha1.LBTCPProxyForceDeploymentModeT1 {
		for _, t1r := range lbsvc.Spec.Applications.TCPProxy.Routes {
			if b, ok := backendMap[t1r.BackendRef.Name]; ok && b.Spec.BackendType == isovalentv1alpha1.BackendTypeHostname {
				backendsWithHostname = append(backendsWithHostname, t1r.BackendRef.Name)
			}
		}
	} else if lbsvc.Spec.Applications.UDPProxy != nil && lbsvc.Spec.Applications.UDPProxy.ForceDeploymentMode != nil && *lbsvc.Spec.Applications.UDPProxy.ForceDeploymentMode == isovalentv1alpha1.LBUDPProxyForceDeploymentModeT1 {
		for _, t1r := range lbsvc.Spec.Applications.UDPProxy.Routes {
			if b, ok := backendMap[t1r.BackendRef.Name]; ok && b.Spec.BackendType == isovalentv1alpha1.BackendTypeHostname {
				backendsWithHostname = append(backendsWithHostname, t1r.BackendRef.Name)
			}
		}
	}
	incompatibleBackendMessages := []string{}

	if len(backendsWithHostname) > 0 {
		incompatibleBackendMessages = append(incompatibleBackendMessages, fmt.Sprintf("forceDeploymentMode t1-only is incompatible with LBBackendPools of type Hostname %v", backendsWithHostname))
	}

	return incompatibleBackendMessages
}

func (r *lbServiceReconciler) getIncompatibleT1TLSHealthCheckBackends(lbsvc *isovalentv1alpha1.LBService, backends []*isovalentv1alpha1.LBBackendPool) []string {
	backendMap := map[string]*isovalentv1alpha1.LBBackendPool{}
	for _, b := range backends {
		backendMap[b.Name] = b
	}

	backendsWithHTTPTLSHealthCheck := []string{}
	backendsWithPayloadInHealthCheck := []string{}
	backendsWithMethodOrStatusCodesInHealthCheck := []string{}

	if lbsvc.Spec.Applications.TCPProxy != nil && lbsvc.Spec.Applications.TCPProxy.ForceDeploymentMode != nil && *lbsvc.Spec.Applications.TCPProxy.ForceDeploymentMode == isovalentv1alpha1.LBTCPProxyForceDeploymentModeT1 {
		for _, t1r := range lbsvc.Spec.Applications.TCPProxy.Routes {
			if b, ok := backendMap[t1r.BackendRef.Name]; ok {
				if b.Spec.HealthCheck.TLSConfig != nil && b.Spec.HealthCheck.HTTP == nil {
					backendsWithHTTPTLSHealthCheck = append(backendsWithHTTPTLSHealthCheck, t1r.BackendRef.Name)
				}

				if b.Spec.HealthCheck.ConfiguresPayload() {
					backendsWithPayloadInHealthCheck = append(backendsWithPayloadInHealthCheck, t1r.BackendRef.Name)
				}

				if b.Spec.HealthCheck.ConfiguresHTTPMethodOrStatusCodes() {
					backendsWithMethodOrStatusCodesInHealthCheck = append(backendsWithMethodOrStatusCodesInHealthCheck, t1r.BackendRef.Name)
				}
			}
		}
	} else if lbsvc.Spec.Applications.UDPProxy != nil && lbsvc.Spec.Applications.UDPProxy.ForceDeploymentMode != nil && *lbsvc.Spec.Applications.UDPProxy.ForceDeploymentMode == isovalentv1alpha1.LBUDPProxyForceDeploymentModeT1 {
		for _, t1r := range lbsvc.Spec.Applications.UDPProxy.Routes {
			if b, ok := backendMap[t1r.BackendRef.Name]; ok {
				if b.Spec.HealthCheck.TLSConfig != nil && b.Spec.HealthCheck.HTTP == nil {
					backendsWithHTTPTLSHealthCheck = append(backendsWithHTTPTLSHealthCheck, t1r.BackendRef.Name)
				}

				if b.Spec.HealthCheck.ConfiguresPayload() {
					backendsWithPayloadInHealthCheck = append(backendsWithPayloadInHealthCheck, t1r.BackendRef.Name)
				}

				if b.Spec.HealthCheck.ConfiguresHTTPMethodOrStatusCodes() {
					backendsWithMethodOrStatusCodesInHealthCheck = append(backendsWithMethodOrStatusCodesInHealthCheck, t1r.BackendRef.Name)
				}
			}
		}
	}
	incompatibleBackendMessages := []string{}

	if len(backendsWithHTTPTLSHealthCheck) > 0 {
		incompatibleBackendMessages = append(incompatibleBackendMessages, fmt.Sprintf("forceDeploymentMode t1-only is incompatible with LBBackendPools that configure TLS health checks %v", backendsWithHTTPTLSHealthCheck))
	}

	if len(backendsWithPayloadInHealthCheck) > 0 {
		incompatibleBackendMessages = append(incompatibleBackendMessages, fmt.Sprintf("forceDeploymentMode t1-only is incompatible with LBBackendPools that configure health checks with payloads (sent/receive) %v", backendsWithPayloadInHealthCheck))
	}

	if len(backendsWithMethodOrStatusCodesInHealthCheck) > 0 {
		incompatibleBackendMessages = append(incompatibleBackendMessages, fmt.Sprintf("forceDeploymentMode t1-only is incompatible with LBBackendPools that configure health checks with method or status codes %v", backendsWithMethodOrStatusCodesInHealthCheck))
	}

	return incompatibleBackendMessages
}

func (r *lbServiceReconciler) getIncompatibleT1BackendIPFamilies(lbsvc *isovalentv1alpha1.LBService, backends []*isovalentv1alpha1.LBBackendPool) []string {
	backendMap := map[string]*isovalentv1alpha1.LBBackendPool{}
	for _, b := range backends {
		backendMap[b.Name] = b
	}

	ipv4Service := lbsvc.Status.Addresses.IPv4 != nil
	ipv6Service := lbsvc.Status.Addresses.IPv6 != nil

	backendsWithoutIPv4 := []string{}
	backendsWithoutIPv6 := []string{}

	if lbsvc.Spec.Applications.TCPProxy != nil && lbsvc.Spec.Applications.TCPProxy.ForceDeploymentMode != nil && *lbsvc.Spec.Applications.TCPProxy.ForceDeploymentMode == isovalentv1alpha1.LBTCPProxyForceDeploymentModeT1 {
		for _, t1r := range lbsvc.Spec.Applications.TCPProxy.Routes {
			if bp, ok := backendMap[t1r.BackendRef.Name]; ok && bp.Spec.BackendType == isovalentv1alpha1.BackendTypeIP {
				missesIPv4Backend, missesIPv6Backend := r.missesBackendsForIPFamily(bp, ipv4Service, ipv6Service)
				if missesIPv4Backend {
					backendsWithoutIPv4 = append(backendsWithoutIPv4, t1r.BackendRef.Name)
				}
				if missesIPv6Backend {
					backendsWithoutIPv6 = append(backendsWithoutIPv6, t1r.BackendRef.Name)
				}
			}
		}
	} else if lbsvc.Spec.Applications.UDPProxy != nil && lbsvc.Spec.Applications.UDPProxy.ForceDeploymentMode != nil && *lbsvc.Spec.Applications.UDPProxy.ForceDeploymentMode == isovalentv1alpha1.LBUDPProxyForceDeploymentModeT1 {
		for _, t1r := range lbsvc.Spec.Applications.UDPProxy.Routes {
			if bp, ok := backendMap[t1r.BackendRef.Name]; ok && bp.Spec.BackendType == isovalentv1alpha1.BackendTypeIP {
				missesIPv4Backend, missesIPv6Backend := r.missesBackendsForIPFamily(bp, ipv4Service, ipv6Service)
				if missesIPv4Backend {
					backendsWithoutIPv4 = append(backendsWithoutIPv4, t1r.BackendRef.Name)
				}
				if missesIPv6Backend {
					backendsWithoutIPv6 = append(backendsWithoutIPv6, t1r.BackendRef.Name)
				}
			}
		}
	}
	incompatibleBackendMessages := []string{}

	if len(backendsWithoutIPv4) > 0 {
		incompatibleBackendMessages = append(incompatibleBackendMessages, fmt.Sprintf("forceDeploymentMode t1-only requires all BackendPools to have at least one address per enabled IP address family configured - IPv4 is missing %v", backendsWithoutIPv4))
	}

	if len(backendsWithoutIPv6) > 0 {
		incompatibleBackendMessages = append(incompatibleBackendMessages, fmt.Sprintf("forceDeploymentMode t1-only requires all BackendPools to have at least one address per enabled IP address family configured - IPv6 is missing %v", backendsWithoutIPv6))
	}

	return incompatibleBackendMessages
}

func (r *lbServiceReconciler) missesBackendsForIPFamily(bp *isovalentv1alpha1.LBBackendPool, ipv4Service bool, ipv6Service bool) (bool, bool) {
	hasAtLeastOneIPv4Backend := false
	hasAtLeastOneIPv6Backend := false

	for _, b := range bp.Spec.Backends {
		if b.IP != nil && net.ParseIP(*b.IP).To4() == nil {
			hasAtLeastOneIPv6Backend = true
		} else {
			hasAtLeastOneIPv4Backend = true
		}
	}

	return ipv4Service && !hasAtLeastOneIPv4Backend, ipv6Service && !hasAtLeastOneIPv6Backend
}

func (*lbServiceReconciler) getInvalidBackends(backends []*isovalentv1alpha1.LBBackendPool) []string {
	invalidBackendMessages := []string{}

	for _, b := range backends {
		condition := b.GetStatusCondition(isovalentv1alpha1.ConditionTypeBackendAccepted)

		if condition == nil {
			invalidBackendMessages = append(invalidBackendMessages, fmt.Sprintf("Backend %q is not yet accepted (no accepted condition)", b.Name))
			continue
		}

		if condition.Reason == isovalentv1alpha1.BackendAcceptedConditionReasonInvalid {
			invalidBackendMessages = append(invalidBackendMessages, fmt.Sprintf("Backend %q is invalid: %q", b.Name, condition.Message))
		}
	}

	return invalidBackendMessages
}

func (*lbServiceReconciler) getIncompatibleProxyProtocol(lbsvc *isovalentv1alpha1.LBService, backends []*isovalentv1alpha1.LBBackendPool) []string {
	invalidBackendMessages := []string{}

	if lbsvc.Spec.ProxyProtocolConfig == nil {
		for _, b := range backends {
			// This is to avoid DownstreamProtocolError for any request with ProxyProtocol to the given backend
			if b.Spec.ProxyProtocolConfig != nil {
				invalidBackendMessages = append(invalidBackendMessages, fmt.Sprintf("Backend %q is incompatible: ProxyProtocolConfig is not supported for LB services", b.Name))
			}
		}
	} else {
		for _, b := range backends {
			if b.Spec.ProxyProtocolConfig != nil && slices.Contains(lbsvc.Spec.ProxyProtocolConfig.DisallowedVersions, b.Spec.ProxyProtocolConfig.Version) {
				invalidBackendMessages = append(invalidBackendMessages, fmt.Sprintf("Backend %q is incompatible: ProxyProtocolConfig version %d is disallowed", b.Name, b.Spec.ProxyProtocolConfig.Version))
			}
		}
	}

	return invalidBackendMessages
}

func (*lbServiceReconciler) updateSecretExistenceInStatus(lbsvc *isovalentv1alpha1.LBService, missingSecrets []string) {
	secretsExistCondition := metav1.Condition{
		Type:               isovalentv1alpha1.ConditionTypeSecretsExist,
		Status:             metav1.ConditionTrue,
		Reason:             isovalentv1alpha1.SecretsExistConditionReasonAllSecretsExist,
		Message:            "All referenced TLS secrets exist",
		ObservedGeneration: lbsvc.GetGeneration(),
		LastTransitionTime: metav1.Now(),
	}

	if len(missingSecrets) > 0 {
		secretsExistCondition.Status = metav1.ConditionFalse
		secretsExistCondition.Reason = isovalentv1alpha1.SecretsExistConditionReasonMissingSecrets
		secretsExistCondition.Message = fmt.Sprintf("There are referenced TLS secrets that do not exist: %v", missingSecrets)
	}

	lbsvc.UpsertStatusCondition(isovalentv1alpha1.ConditionTypeSecretsExist, secretsExistCondition)
}

func (r *lbServiceReconciler) updateSecretCompatibilityInStatus(lbsvc *isovalentv1alpha1.LBService, referencedSecrets map[string]*corev1.Secret) {
	secretsCompatibleCondition := metav1.Condition{
		Type:               isovalentv1alpha1.ConditionTypeSecretsCompatible,
		Status:             metav1.ConditionTrue,
		Reason:             isovalentv1alpha1.SecretsCompatibleConditionReasonAllSecretsCompatible,
		Message:            "All referenced secrets are compatible",
		ObservedGeneration: lbsvc.GetGeneration(),
		LastTransitionTime: metav1.Now(),
	}

	incompatibleSecretMessages := []string{}

	incompatibleSecretMessages = append(incompatibleSecretMessages, r.getIncompatibleSecretTypes(lbsvc, referencedSecrets)...)

	if len(incompatibleSecretMessages) > 0 {
		secretsCompatibleCondition.Status = metav1.ConditionFalse
		secretsCompatibleCondition.Reason = isovalentv1alpha1.SecretsCompatibleConditionReasonIncompatibleSecrets
		secretsCompatibleCondition.Message = strings.Join(incompatibleSecretMessages, "\n")
	}

	lbsvc.UpsertStatusCondition(isovalentv1alpha1.ConditionTypeSecretsCompatible, secretsCompatibleCondition)
}

func (r *lbServiceReconciler) getIncompatibleSecretTypes(lbsvc *isovalentv1alpha1.LBService, secretMap map[string]*corev1.Secret) []string {
	messages := []string{}

	for _, s := range lbsvc.AllReferencedTLSCertificateSecretNames() {
		secret, ok := secretMap[s]
		if !ok {
			continue
		}

		if secret.Type != corev1.SecretTypeTLS ||
			secret.Data[corev1.TLSCertKey] == nil || string(secret.Data[corev1.TLSCertKey]) == "" ||
			secret.Data[corev1.TLSPrivateKeyKey] == nil || string(secret.Data[corev1.TLSPrivateKeyKey]) == "" {

			messages = append(messages, fmt.Sprintf("Secret %q is incompatible: Referenced as TLS Certificate but not of type TLS and/or relevant data fields (%q, %q) missing", s, corev1.TLSCertKey, corev1.TLSPrivateKeyKey))
		}
	}

	for _, s := range lbsvc.AllReferencedTLSCACertValidationSecretNames() {
		secret, ok := secretMap[s]
		if !ok {
			continue
		}

		if secret.Type != corev1.SecretTypeOpaque ||
			secret.Data["ca.crt"] == nil || string(secret.Data["ca.crt"]) == "" {

			messages = append(messages, fmt.Sprintf("Secret %q is incompatible: Referenced as CA Certificate but not of type Opaque and/or relevant data fields (%q) missing", s, "ca.crt"))
		}
	}

	for _, s := range lbsvc.AllReferencedBasicAuthSecretNames() {
		secret, ok := secretMap[s]
		if !ok {
			continue
		}
		if secret.Type != corev1.SecretTypeOpaque {
			messages = append(messages, fmt.Sprintf("Secret %q is incompatible: Referenced as BasicAuth but not of type Opaque", s))
		}
	}

	return messages
}

func (*lbServiceReconciler) updateK8sServiceExistenceInStatus(lbsvc *isovalentv1alpha1.LBService, missingK8sServices []string) {
	svcExistCondition := metav1.Condition{
		Type:               isovalentv1alpha1.ConditionTypeK8sServiceExist,
		Status:             metav1.ConditionTrue,
		Reason:             isovalentv1alpha1.K8sServiceExistConditionReasonAllK8sServicesExist,
		Message:            "All K8s Services exist",
		ObservedGeneration: lbsvc.GetGeneration(),
		LastTransitionTime: metav1.Now(),
	}

	if len(missingK8sServices) > 0 {
		svcExistCondition.Status = metav1.ConditionFalse
		svcExistCondition.Reason = isovalentv1alpha1.K8sServiceExistConditionReasonMissingK8sServices
		svcExistCondition.Message = fmt.Sprintf("There are referenced K8s Services that do not exist: %v", missingK8sServices)
	}

	lbsvc.UpsertStatusCondition(isovalentv1alpha1.ConditionTypeK8sServiceExist, svcExistCondition)
}

func (*lbServiceReconciler) updateEndpointSliceExistenceInStatus(lbsvc *isovalentv1alpha1.LBService, missingEndpointSlices []string) {
	esExistCondition := metav1.Condition{
		Type:               isovalentv1alpha1.ConditionTypeEPSlicesExist,
		Status:             metav1.ConditionTrue,
		Reason:             isovalentv1alpha1.EPSlicesExistConditionReasonAllEndpointSlicesExist,
		Message:            "All EndpointSlices exist",
		ObservedGeneration: lbsvc.GetGeneration(),
		LastTransitionTime: metav1.Now(),
	}

	if len(missingEndpointSlices) > 0 {
		esExistCondition.Status = metav1.ConditionFalse
		esExistCondition.Reason = isovalentv1alpha1.EPSlicesExistConditionReasonMissingEndpointSlices
		esExistCondition.Message = fmt.Sprintf("There are referenced K8s Services where the corresponding EndpointSlices do not exist: %v", missingEndpointSlices)
	}

	lbsvc.UpsertStatusCondition(isovalentv1alpha1.ConditionTypeEPSlicesExist, esExistCondition)
}
