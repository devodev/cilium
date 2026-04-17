//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package endpoint

import (
	"fmt"

	"github.com/cilium/cilium/pkg/maps/policymap"
)

func (e *Endpoint) GetPolicyMap() (policymap.PolicyMap, error) {
	var err error

	if e.policyMap != nil {
		return e.policyMap, nil
	}

	if e.policyMapFactory == nil {
		return nil, fmt.Errorf("endpoint has nil policyMapFactory")
	}
	e.policyMap, err = e.policyMapFactory.OpenEndpoint(e.ID)
	return e.policyMap, err
}
