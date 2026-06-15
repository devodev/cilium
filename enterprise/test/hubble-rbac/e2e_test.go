// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this
// information or reproduction of this material is strictly forbidden unless
// prior written permission is obtained from Isovalent Inc.

package hubblerbac

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/enterprise/test/helpers"
)

var (
	adminUser     = os.Getenv("ADMIN_OIDC_USER")
	adminPassword = os.Getenv("ADMIN_OIDC_PASSWORD")

	demoUser     = os.Getenv("DEMO_OIDC_USER")
	demoPassword = os.Getenv("DEMO_OIDC_PASSWORD")
)

const enableHubbleRBACE2E = "ENABLE_ENTERPRISE_HUBBLE_RBAC_E2E"

func requireHubbleRBACE2E(t *testing.T) {
	t.Helper()

	if !strings.EqualFold(os.Getenv(enableHubbleRBACE2E), "true") {
		t.Skipf("skipping: set %s=true to run Hubble RBAC e2e tests", enableHubbleRBACE2E)
	}
}

func TestHubbleObserve(t *testing.T) {
	requireHubbleRBACE2E(t)

	ctx := context.Background()

	t.Run("unauthenticated", func(t *testing.T) {
		// Logout to make sure we have no credentials before running each test
		helpers.HubbleCLI(ctx, "logout")
		defer helpers.HubbleCLI(ctx, "logout")

		// unauthenticated requests should fail
		out, err := helpers.HubbleCLI(ctx, "observe", "--namespace=kube-system")
		require.Error(t, err, out)
		assert.Contains(t, out, "Unauthenticated", "Should be unauthenticated")
	})

	t.Run("authenticated as admin", func(t *testing.T) {
		// Logout to make sure we have no credentials before running each test
		helpers.HubbleCLI(ctx, "logout")
		defer helpers.HubbleCLI(ctx, "logout")

		helpers.HubbleLogin(ctx, t, adminUser, adminPassword)

		t.Run("get all flows should succeed", func(t *testing.T) {
			out, err := helpers.HubbleCLI(ctx, "observe", "-o", "json")
			require.NoError(t, err, out)

			flows := helpers.GetFlowsResponseFromReader(t, strings.NewReader(out))
			require.NotEmpty(t, flows, "expected flows to be returned")
		})
		t.Run("get flows in kube-system should succeed", func(t *testing.T) {
			out, err := helpers.HubbleCLI(ctx, "observe", "-o", "json", "--namespace", "kube-system")
			require.NoError(t, err, out)

			flows := helpers.GetFlowsResponseFromReader(t, strings.NewReader(out))
			require.NotEmpty(t, flows, "expected flows to be returned")
		})
	})

	t.Run("authenticated as demo", func(t *testing.T) {
		// Logout to make sure we have no credentials before running each test
		helpers.HubbleCLI(ctx, "logout")
		defer helpers.HubbleCLI(ctx, "logout")

		helpers.HubbleLogin(ctx, t, demoUser, demoPassword)

		t.Run("get all flows should fail", func(t *testing.T) {
			out, err := helpers.HubbleCLI(ctx, "observe", "-o", "json")
			require.Error(t, err, out)
			assert.Contains(t, out, "PermissionDenied", "should get permission denied")
		})
		t.Run("get flows in kube-system should succeed", func(t *testing.T) {
			out, err := helpers.HubbleCLI(ctx, "observe", "-o", "json", "--namespace", "kube-system")
			require.NoError(t, err, out)

			flows := helpers.GetFlowsResponseFromReader(t, strings.NewReader(out))
			require.NotEmpty(t, flows, "expected flows to be returned")
		})
	})
}
