// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

// This file originates from Ciliums's codebase and is governed by an
// Apache 2.0 license (see original header below):
//
// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkpolicy

import (
	"github.com/cilium/hive/cell"

	enterpriseSecretSync "github.com/cilium/cilium/enterprise/operator/pkg/networkpolicy/secretsync"
)

var Cell = cell.Module(
	"isovalent-netpol-validator",
	"Validates INPs and ICNPs and reports their validity status",

	cell.Invoke(registerPolicyValidator),
	cell.Invoke(registerPolicyToGroupController),
	enterpriseSecretSync.Cell,
)
