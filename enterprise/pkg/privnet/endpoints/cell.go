//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package endpoints

import "github.com/cilium/hive/cell"

// Cell provides the various interfaces defined in this package, implemented as adapters
// on top of the upstream pkg/endpoint and pkg/endpointmanager packages.
// The types provided by this cell are usually overwritten via `cell.DecorateAll` in
// unit tests. As this cell is therefore not covered by script tests, it should be
// kept as simple possible. Any control-plane logic must be added elsewhere.
var Cell = cell.Group(
	cell.Provide(
		newEndpointManagerAdapter,
		newEndpointAPIManagerAdapter,
		newEndpointEventObserver,
		newEndpointPropertyManager,
		newRestorationNotifier,

		newIPAM,
	),
)
