//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package tests

import "time"

var Params Parameters

type Parameters struct {
	EgressGateway EgressGatewayParameters
	ConnDisrupt   ConnDisruptParameters
}

type ConnDisruptParameters struct {
	IncludeConnDisruptTestEGWHA bool
	EgressCIDRs                 []string
}

type EgressGatewayParameters struct {
	CIDRs         []string
	Retry         uint
	RetryDelay    time.Duration
	PeerASN       int64
	PeerAddresses []string
}
