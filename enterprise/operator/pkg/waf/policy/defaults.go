//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package policy

import (
	"fmt"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

type GlobalDefaults struct {
	Enabled       bool
	Mode          isovalentv1alpha1.IsovalentWAFPolicyModeType
	PolicyProfile isovalentv1alpha1.IsovalentWAFPolicyProfileType
	FailureMode   isovalentv1alpha1.WAFFailureModeType
}

func NewGlobalDefaults(enabled bool, mode, policyProfile, failureMode string) (GlobalDefaults, error) {
	defaults := GlobalDefaults{
		Enabled:       enabled,
		Mode:          isovalentv1alpha1.IsovalentWAFPolicyModeType(mode),
		PolicyProfile: isovalentv1alpha1.IsovalentWAFPolicyProfileType(policyProfile),
		FailureMode:   isovalentv1alpha1.WAFFailureModeType(failureMode),
	}

	switch defaults.Mode {
	case isovalentv1alpha1.IsovalentWAFPolicyModeMonitor, isovalentv1alpha1.IsovalentWAFPolicyModeEnforce:
	default:
		return GlobalDefaults{}, fmt.Errorf("unsupported waf-mode %q", mode)
	}

	switch defaults.PolicyProfile {
	case isovalentv1alpha1.IsovalentWAFPolicyProfileMaxSecurity,
		isovalentv1alpha1.IsovalentWAFPolicyProfileHighSecurity,
		isovalentv1alpha1.IsovalentWAFPolicyProfileBalanced,
		isovalentv1alpha1.IsovalentWAFPolicyProfileLowFriction,
		isovalentv1alpha1.IsovalentWAFPolicyProfileMinFriction:
	default:
		return GlobalDefaults{}, fmt.Errorf("unsupported waf-policy-profile %q", policyProfile)
	}

	switch defaults.FailureMode {
	case isovalentv1alpha1.WAFFailureModeOpen, isovalentv1alpha1.WAFFailureModeClose:
	default:
		return GlobalDefaults{}, fmt.Errorf("unsupported waf-failure-mode %q", failureMode)
	}

	return defaults, nil
}
