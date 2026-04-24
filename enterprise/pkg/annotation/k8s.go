// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package annotation

import (
	ossannotation "github.com/cilium/cilium/pkg/annotation"
)

const (
	// ServiceHealthMode annotation declares that backend health for a service
	// is provided externally rather than native active probing.
	ServiceHealthMode = ossannotation.ServicePrefix + "/health-check-mode"

	// ServiceHealthModeExternal indicates that health for the service is managed
	// externally rather than via native active probing.
	ServiceHealthModeExternal = "external"

	// ServiceHealthProbeInterval / ServiceHealthProbeTimeout / ServiceHealthProbePort annotations
	// determine the probe interval of a service and timeout duration for
	// when a probe is considered as failed. ServiceHealthProbePort configures
	// an optional port override for the health check probes.
	// Allowed values:
	//  - A duration, for example:
	//    "service.cilium.io/health-check-probe-interval": "1s"
	//    "service.cilium.io/health-check-probe-timeout": "5s"
	ServiceHealthProbeInterval = ossannotation.ServicePrefix + "/health-check-probe-interval"
	ServiceHealthProbeTimeout  = ossannotation.ServicePrefix + "/health-check-probe-timeout"
	ServiceHealthProbePort     = ossannotation.ServicePrefix + "/health-check-probe-port"

	// ServiceHealthThresholdHealthy / ServiceHealthThresholdUnhealthy annotations
	// determine the threshold of probes needed until a specific backend's state
	// changes from healthy to unhealthy and vice versa.
	// Allowed values:
	//  - A number, for example:
	//    "service.cilium.io/health-check-threshold-unhealthy": "3"
	//    "service.cilium.io/health-check-threshold-healthy": "3"
	ServiceHealthThresholdHealthy   = ossannotation.ServicePrefix + "/health-check-threshold-healthy"
	ServiceHealthThresholdUnhealthy = ossannotation.ServicePrefix + "/health-check-threshold-unhealthy"

	// ServiceHealthQuarantineTimeout annotation determines the timeout duration
	// for a given backend to reside in unhealthy state before probes are resumed
	// again.
	// Allowed values:
	//  - A duration, for example:
	//    "service.cilium.io/health-check-quarantine-timeout": "30s"
	ServiceHealthQuarantineTimeout = ossannotation.ServicePrefix + "/health-check-quarantine-timeout"

	// ServiceHealthHTTP* annotations provide further information on HTTP/HTTPS
	// health checking for the given service. ServiceHealthHTTPPath specifies
	// the path, ServiceHealthHTTPMethod specifies the method with GET being the
	// default if nothing was specified, ServiceHealthHTTPHost specifies the HTTP
	// Host header / Server Name for SNI, and lastly ServiceHealthHTTPScheme
	// specifies whether http (default) or https should be used for the probe.
	// Allowed values:
	//  - A string, for example:
	//    "service.cilium.io/health-check-http-path": "/healthcheck"
	//    "service.cilium.io/health-check-http-method": "GET"
	//    "service.cilium.io/health-check-http-host": "my.host.com"
	//    "service.cilium.io/health-check-http-scheme": "https"
	ServiceHealthHTTPPath   = ossannotation.ServicePrefix + "/health-check-http-path"
	ServiceHealthHTTPMethod = ossannotation.ServicePrefix + "/health-check-http-method"
	ServiceHealthHTTPHost   = ossannotation.ServicePrefix + "/health-check-http-host"
	ServiceHealthHTTPScheme = ossannotation.ServicePrefix + "/health-check-http-scheme"

	// ServiceHealthBGPAdvertiseThreshold annotation defines threshold in minimal number of healthy backends,
	// when service routes will be advertised by the BGP Control Plane.
	// Allowed values:
	//  - A number, for example:
	//      "service.cilium.io/health-check-bgp-advertise-threshold": "1"
	//  - none (default)
	//      same as "1" - the service routes will be advertised when there is at least 1 healthy backend.
	ServiceHealthBGPAdvertiseThreshold = ossannotation.ServicePrefix + "/health-check-bgp-advertise-threshold"

	// ServiceNoAdvertisement annotation is used to disable advertisement
	// of specific Service. This is useful when the service is selected by
	// for example, BGP Control Plane, but we still want to disable
	// advertisement. This annotation is used by the IsovalentLB internally
	// to prevent "placeholder" services from being advertised. It is not
	// intended to be used by users.
	ServiceNoAdvertisement = ossannotation.ServicePrefix + "/no-advertisement"

	// CEServicePrefix is the common prefix for service related annotations
	// used for enterprise-only functionalities.
	CEServicePrefix = "service.isovalent.com"

	// PhantomServiceKey if set to true, marks a service (which must be of type
	// LoadBalancer) to become a phantom service. It means that the corresponding
	// LB IP address becomes reachable from the remote clusters, even if a service
	// with the same namespace/name does not exist there.
	PhantomServiceKey = CEServicePrefix + "/phantom"

	// ServiceTrafficPolicyZone marks a service for enterprise-only strict
	// zone-aware backend selection in the agent.
	ServiceTrafficPolicyZone = ossannotation.ServicePrefix + "/traffic-policy-zone"

	// ServiceTrafficPolicyZoneRequireSameZone enforces strict same-zone backend
	// selection. If no same-zone backend is available, traffic is dropped.
	ServiceTrafficPolicyZoneRequireSameZone = "require-same-zone"
)
