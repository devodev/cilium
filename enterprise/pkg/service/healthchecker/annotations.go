// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package healthchecker

import (
	"strconv"
	"strings"

	"github.com/cilium/cilium/enterprise/pkg/annotation"
	ossannotation "github.com/cilium/cilium/pkg/annotation"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/time"
)

// HealthCheckState is the health check state for a given service.
type HealthCheckState uint32

const (
	HealthCheckDisabled = iota
	HealthCheckEnabledNative
	HealthCheckEnabledExternal
)

// HealthCheckScheme is the health check scheme for L7 probes.
type HealthCheckScheme uint32

const (
	HealthCheckSchemeHTTP = iota
	HealthCheckSchemeHTTPS
)

const (
	HealthCheckSchemeHTTPString  = "http"
	HealthCheckSchemeHTTPSString = "https"
)

// HealthCheckMethod is the health check method for L7 probes.
type HealthCheckMethod uint32

const (
	HealthCheckMethodGet = iota
	HealthCheckMethodHead
)

const (
	HealthCheckMethodGetString  = "get"
	HealthCheckMethodHeadString = "head"
)

// HealthCheckConfig represents the current health check config
// of a given service.
// +deepequal-gen=true
type HealthCheckConfig struct {
	State              HealthCheckState
	L7                 bool
	ProbeInterval      time.Duration
	ProbeTimeout       time.Duration
	ProbePort          uint16
	QuarantineTimeout  time.Duration
	ThresholdHealthy   uint
	ThresholdUnhealthy uint
	HTTPScheme         HealthCheckScheme
	HTTPMethod         HealthCheckMethod
	HTTPPath           string
	HTTPHost           string
	DSR                bool
}

func defaultHealthCheckConfig() HealthCheckConfig {
	return HealthCheckConfig{
		State:              HealthCheckDisabled,
		ProbeInterval:      time.Duration(3) * time.Second,
		ProbeTimeout:       time.Duration(1) * time.Second,
		QuarantineTimeout:  time.Duration(30) * time.Second,
		HTTPScheme:         HealthCheckSchemeHTTP,
		HTTPMethod:         HealthCheckMethodGet,
		ThresholdHealthy:   3,
		ThresholdUnhealthy: 3,
	}
}

func getAnnotationHealthCheckConfig(svcAnnotations map[string]string) HealthCheckConfig {
	hc := defaultHealthCheckConfig()

	if value, ok := svcAnnotations[annotation.ServiceHealthMode]; ok {
		switch strings.ToLower(value) {
		case annotation.ServiceHealthModeExternal:
			hc.State = HealthCheckEnabledExternal
		}
	}

	if value, ok := svcAnnotations[annotation.ServiceHealthProbeInterval]; ok {
		if duration, err := time.ParseDuration(value); err == nil {
			hc.ProbeInterval = duration
			if duration > 0 {
				hc.State = HealthCheckEnabledNative
			} else {
				hc.State = HealthCheckDisabled
			}
		}
	}
	if value, ok := svcAnnotations[annotation.ServiceHealthProbeTimeout]; ok {
		if duration, err := time.ParseDuration(value); err == nil {
			hc.ProbeTimeout = duration
		}
	}
	if value, ok := svcAnnotations[annotation.ServiceHealthProbePort]; ok {
		if port, err := strconv.ParseUint(value, 10, 16); err == nil {
			hc.ProbePort = uint16(port)
		}
	}
	if value, ok := svcAnnotations[annotation.ServiceHealthQuarantineTimeout]; ok {
		if duration, err := time.ParseDuration(value); err == nil {
			hc.QuarantineTimeout = duration
		}
	}
	if value, ok := svcAnnotations[annotation.ServiceHealthThresholdHealthy]; ok {
		if threshold, err := strconv.ParseUint(value, 10, 32); err == nil {
			hc.ThresholdHealthy = uint(threshold)
		}
	}
	if value, ok := svcAnnotations[annotation.ServiceHealthThresholdUnhealthy]; ok {
		if threshold, err := strconv.ParseUint(value, 10, 32); err == nil {
			hc.ThresholdUnhealthy = uint(threshold)
		}
	}
	if value, ok := svcAnnotations[annotation.ServiceHealthHTTPPath]; ok {
		hc.HTTPPath = value
		hc.L7 = true
	}
	if value, ok := svcAnnotations[annotation.ServiceHealthHTTPHost]; ok {
		hc.HTTPHost = value
	}
	if value, ok := svcAnnotations[annotation.ServiceHealthHTTPMethod]; ok {
		value = strings.ToLower(value)
		switch value {
		case HealthCheckMethodGetString:
			hc.HTTPMethod = HealthCheckMethodGet
		case HealthCheckMethodHeadString:
			hc.HTTPMethod = HealthCheckMethodHead
		}
	}
	if value, ok := svcAnnotations[annotation.ServiceHealthHTTPScheme]; ok {
		value = strings.ToLower(value)
		switch value {
		case HealthCheckSchemeHTTPSString:
			hc.HTTPScheme = HealthCheckSchemeHTTPS
		case HealthCheckSchemeHTTPString:
			hc.HTTPScheme = HealthCheckSchemeHTTP
		}
	}
	if value, ok := svcAnnotations[ossannotation.ServiceForwardingMode]; ok {
		if lb.SVCForwardingMode(strings.ToLower(value)) == lb.SVCForwardingModeDSR {
			hc.DSR = true
		}
	}

	return hc
}

func IsHealthCheckEnabled(svcAnnotations map[string]string) bool {
	return getAnnotationHealthCheckConfig(svcAnnotations).State != HealthCheckDisabled
}
