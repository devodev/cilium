// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package t2servicehealth

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/time"
)

func TestShouldRetainExistingRemoteRowOnFullSnapshot(t *testing.T) {
	now := time.Now()

	require.True(t, shouldRetainExistingRemoteRowOnFullSnapshot(&remoteServiceHealth{
		ExpiresAt: now.Add(time.Second),
	}, now))

	require.False(t, shouldRetainExistingRemoteRowOnFullSnapshot(&remoteServiceHealth{
		ExpiresAt: now,
	}, now))

	require.False(t, shouldRetainExistingRemoteRowOnFullSnapshot(&remoteServiceHealth{
		ExpiresAt: now.Add(-time.Second),
	}, now))

	require.False(t, shouldRetainExistingRemoteRowOnFullSnapshot(&remoteServiceHealth{}, now))
	require.False(t, shouldRetainExistingRemoteRowOnFullSnapshot(nil, now))
}
