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

import (
	"log/slog"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
)

type selectorCacheUser struct{}

func (*selectorCacheUser) IdentitySelectionUpdated(
	*slog.Logger,
	policy.CachedSelector,
	[]identity.NumericIdentity,
	[]identity.NumericIdentity,
) {
}

func (*selectorCacheUser) IdentitySelectionCommit(*slog.Logger, policy.SelectorSnapshot) {}

func (*selectorCacheUser) IsPeerSelector() bool { return false }

func (*selectorCacheUser) GetRuleLabels(policy.CachedSelector) labels.LabelArrayList {
	return nil
}
