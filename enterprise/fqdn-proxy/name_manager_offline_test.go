package main

import (
	"log/slog"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/time"
)

var (
	ip1 = netip.MustParseAddr("1.1.1.1")
	ip2 = netip.MustParseAddr("1.1.1.2")
	ip3 = netip.MustParseAddr("1::1")
	ip4 = netip.MustParseAddr("1::2")
)

func TestOfflineWrite(t *testing.T) {
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

	ipcache := newFakeIPCache(logger)
	ipcache.ipEndpointMap[ip1] = identity.ReservedIdentityWorldIPv4
	ipcache.ipEndpointMap[ip2] = identity.IdentityScopeLocal // simulate in use
	ipcache.ipEndpointMap[ip3] = identity.ReservedIdentityWorldIPv6
	ipcache.ipEndpointMap[ip4] = 1002 // already the ID we want

	cfg := Config{
		EnableOfflineMode: true,
		EnableIPV6:        true,
		EnableIPV4:        true,
	}

	stopAgent := make(chan struct{})
	socketPath, err := startFakeServer(t,
		WithSelectorIdentities("*.example.com"),
		WithStopServerOnClose(stopAgent))
	require.NoError(t, err)
	t.Log(socketPath)
	client, err := makeClient(logger, "unix://"+socketPath)
	require.NoError(t, err)

	nm, _ := newRemoteNameManager(remoteNameManagerParams{
		Logger:  logger,
		Cfg:     cfg,
		Client:  client,
		IPCache: ipcache,
	})

	go nm.streamSelectors(t.Context(), nil)

	require.Eventually(t, func() bool { return nm.identitiesSynced && nm.selectorsSynced }, 5*time.Second, 10*time.Millisecond)
	require.Len(t, nm.selectors.selectors, 1)
	require.Len(t, nm.identities.byID, 2)

	nm.maybeUpdateIPCache("foo.example.com.", []netip.Addr{ip1, ip2, ip3, ip4})

	expected := map[netip.Addr]identity.NumericIdentity{
		ip1: 1001,
		ip2: identity.IdentityScopeLocal,
		ip3: 1002,
		ip4: 1002,
	}

	require.Equal(t, expected, ipcache.ipEndpointMap)

}
