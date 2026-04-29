//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package config

import "github.com/cilium/cilium/pkg/identity"

// SelectorEndpoint is the subset of endpoint state needed to evaluate
// CNP-style endpoint selectors.
type SelectorEndpoint interface {
	K8sNamespaceAndPodNameIsSet() bool
	GetSecurityIdentity() (*identity.Identity, error)
}

// EndpointConfig is the subset of datapath endpoint config needed to evaluate
// whether passive inspection should be enabled.
type EndpointConfig interface {
	GetIdentity() identity.NumericIdentity
	GetPropertyValue(key string) any
}
