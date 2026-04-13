//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package linux

import (
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/types"
)

// InjectCEEnableEncapsulation overrides the function used to determine whether
// native routing or tunnel encapsulation should be used for the given node.
func InjectCEEnableEncapsulation(nh node.Handler, fn func(node *types.Node) bool) {
	nodeHandler, ok := nh.(*linuxNodeHandler)
	if !ok {
		return
	}

	nodeHandler.OverrideEnableEncapsulation(fn)
}
