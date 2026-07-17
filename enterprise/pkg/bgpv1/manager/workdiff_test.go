// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package manager

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/enterprise/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	ossTypes "github.com/cilium/cilium/pkg/bgp/types"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
)

func TestReconcileDiff(t *testing.T) {
	dummyResolver := func(instance *v1.IsovalentBGPNodeInstance) (types.EnterpriseBGPVRF, error) {
		return types.EnterpriseBGPVRF{
			Name:          "dummy-vrf",
			TableID:       1000,
			DeviceName:    "cvrf-dummy-vrf",
			DeviceIfindex: 123,
		}, nil
	}

	t.Run("Register", func(t *testing.T) {
		desired := &v1.IsovalentBGPNodeConfig{
			Spec: v1.IsovalentBGPNodeSpec{
				BGPInstances: []v1.IsovalentBGPNodeInstance{
					{
						Name:     "instance-ok",
						LocalASN: ptr.To(int64(65000)),
						RouterID: ptr.To("10.0.0.1"),
					},
					{
						Name: "instance-bad",
						// Missing LocalASN, so requiresRecreate
						// will return an error for this
						// instance.
						LocalASN: nil,
						RouterID: ptr.To("10.0.0.2"),
					},
				},
			},
		}

		rd := newReconcileDiff(nil, dummyResolver)
		err := rd.diff(map[string]*instance.EnterpriseBGPInstance{}, desired)
		require.NoError(t, err, "diff() should not return an error even if one instance fails")
		require.Equal(t, []string{"instance-ok"}, rd.register)
		require.Contains(t, rd.errored, "instance-bad")
	})

	t.Run("Reconcile", func(t *testing.T) {
		desired := &v1.IsovalentBGPNodeConfig{
			Spec: v1.IsovalentBGPNodeSpec{
				BGPInstances: []v1.IsovalentBGPNodeInstance{
					{
						Name:     "instance-ok",
						LocalASN: ptr.To(int64(65000)),
						RouterID: ptr.To("10.0.0.1"),
					},
					{
						Name: "instance-bad",
						// Missing LocalASN, so requiresRecreate
						// will return an error for this
						// instance.
						LocalASN: nil,
						RouterID: ptr.To("10.0.0.2"),
					},
				},
			},
		}

		rd := newReconcileDiff(nil, dummyResolver)
		err := rd.diff(map[string]*instance.EnterpriseBGPInstance{
			"instance-ok": {
				Global: types.EnterpriseBGPGlobal{
					BGPGlobal: ossTypes.BGPGlobal{
						ASN:        65000,
						RouterID:   "10.0.0.1",
						ListenPort: -1,
					},
					BindToDevice:  "cvrf-dummy-vrf",
					BindToIfindex: 123,
				},
			},
		}, desired)
		require.NoError(t, err, "diff() should not return an error even if one instance fails")
		require.Equal(t, []string{"instance-ok"}, rd.reconcile)
		require.Contains(t, rd.errored, "instance-bad")
	})

	t.Run("Recreate", func(t *testing.T) {
		desired := &v1.IsovalentBGPNodeConfig{
			Spec: v1.IsovalentBGPNodeSpec{
				BGPInstances: []v1.IsovalentBGPNodeInstance{
					{
						Name:     "instance-ok",
						LocalASN: ptr.To(int64(65000)),
						RouterID: ptr.To("10.0.0.1"),
					},
					{
						Name: "instance-bad",
						// Missing LocalASN, so requiresRecreate
						// will return an error for this
						// instance.
						LocalASN: nil,
						RouterID: ptr.To("10.0.0.2"),
					},
				},
			},
		}

		rd := newReconcileDiff(nil, dummyResolver)
		err := rd.diff(map[string]*instance.EnterpriseBGPInstance{
			"instance-ok": {
				Global: types.EnterpriseBGPGlobal{
					BGPGlobal: ossTypes.BGPGlobal{
						ASN:        65000,
						RouterID:   "10.0.0.1",
						ListenPort: -1,
					},
					BindToDevice:  "cvrf-dummy-vrf",
					BindToIfindex: 567,
				},
			},
		}, desired)
		require.NoError(t, err, "diff() should not return an error even if one instance fails")
		require.Equal(t, []string{"instance-ok"}, rd.register)
		require.Equal(t, []string{"instance-ok"}, rd.withdraw)
		require.Contains(t, rd.errored, "instance-bad")
	})

	t.Run("Withdraw with Error", func(t *testing.T) {
		desired := &v1.IsovalentBGPNodeConfig{
			Spec: v1.IsovalentBGPNodeSpec{
				BGPInstances: []v1.IsovalentBGPNodeInstance{
					{
						Name:     "instance-ok",
						LocalASN: ptr.To(int64(65000)),
						RouterID: ptr.To("10.0.0.1"),
					},
					{
						Name: "instance-bad",
						// Missing LocalASN, so requiresRecreate
						// will return an error for this
						// instance.
						LocalASN: nil,
						RouterID: ptr.To("10.0.0.2"),
					},
				},
			},
		}

		rd := newReconcileDiff(nil, dummyResolver)
		err := rd.diff(map[string]*instance.EnterpriseBGPInstance{
			"instance-ok": {
				Global: types.EnterpriseBGPGlobal{
					BGPGlobal: ossTypes.BGPGlobal{
						ASN:        65000,
						RouterID:   "10.0.0.1",
						ListenPort: -1,
					},
					BindToDevice:  "cvrf-dummy-vrf",
					BindToIfindex: 123,
				},
			},
			"instance-bad": {
				Global: types.EnterpriseBGPGlobal{
					BGPGlobal: ossTypes.BGPGlobal{
						ASN:        65000,
						RouterID:   "10.0.0.2",
						ListenPort: -1,
					},
				},
			},
		}, desired)
		require.NoError(t, err, "diff() should not return an error even if one instance fails")
		require.Equal(t, []string{"instance-ok"}, rd.reconcile)
		require.Equal(t, []string{"instance-bad"}, rd.withdraw)
		require.Contains(t, rd.errored, "instance-bad")
	})
}
