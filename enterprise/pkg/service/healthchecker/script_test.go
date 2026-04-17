// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package healthchecker

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	"github.com/cilium/statedb"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/datapath/tables"
	envoyCfg "github.com/cilium/cilium/pkg/envoy/config"
	"github.com/cilium/cilium/pkg/hive"
	k8sfake "github.com/cilium/cilium/pkg/k8s/client/testutils"
	k8stestutils "github.com/cilium/cilium/pkg/k8s/testutils"
	"github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/lbipamconfig"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	lbcell "github.com/cilium/cilium/pkg/loadbalancer/cell"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/nodeipamconfig"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

var debug = flag.Bool("debug", false, "Enable debug logging")

func TestScript(t *testing.T) {
	// version/capabilities are unfortunately a global variable, so we're forcing it here.
	// This makes it difficult to have different k8s version/capabilities (e.g. use Endpoints
	// not EndpointSlice) in the tests here, which is why we're currently only testing against
	// the default.
	// Issue for fixing this: https://github.com/cilium/cilium/issues/35537
	version.Force(k8stestutils.DefaultVersion)

	// Set the node name
	nodeTypes.SetName("testnode")

	const (
		testHTTPHost      = "test.cilium.io"
		validHTTPPath     = "/success"
		checkHostHTTPPath = "/check-host"
	)

	// request handler used for both HTTP and HTTPS servers
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.RequestURI {
		case "/":
		case validHTTPPath:
			w.WriteHeader(http.StatusOK)
		case checkHostHTTPPath:
			// returns internal error if HTTP host / TLS Server Name does not match the expected value
			fail := false
			if r.Host != testHTTPHost {
				fail = true
			}
			if r.TLS != nil {
				if r.TLS.ServerName != testHTTPHost {
					fail = true
				}
			}
			if fail {
				w.WriteHeader(http.StatusInternalServerError)
			} else {
				w.WriteHeader(http.StatusOK)
			}
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	})

	// Run some test servers. All scripts share these.
	httpServer := httptest.NewServer(testHandler)
	httpAddr := getTestServerL3n4Addr(t, httpServer.Listener.Addr())

	httpsServer := httptest.NewTLSServer(testHandler)
	httpsAddr := getTestServerL3n4Addr(t, httpsServer.Listener.Addr())

	udpServer, err := newUdpServer()
	require.NoError(t, err, "newUdpServer")

	t.Cleanup(func() {
		httpServer.Close()
		httpsServer.Close()
		udpServer.close()
	})

	var opts []hivetest.LogOption
	if *debug {
		opts = append(opts, hivetest.LogLevel(slog.LevelDebug))
		logging.SetLogLevel(slog.LevelDebug)
	}
	log := hivetest.Logger(t, opts...)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	scripttest.Test(t,
		ctx,
		func(t testing.TB, args []string) *script.Engine {
			h := hive.New(
				k8sfake.FakeClientCell(),
				daemonk8s.ResourcesCell,
				daemonk8s.TablesCell,
				cell.Config(envoyCfg.SecretSyncConfig{}),
				lbcell.Cell,
				cell.Config(lb.TestConfig{}),
				maglev.Cell,
				node.LocalNodeStoreTestCell,
				metrics.Cell,
				lbipamconfig.Cell,
				nodeipamconfig.Cell,

				cell.Provide(
					func(cfg lb.TestConfig) *lb.TestConfig { return &cfg },

					source.NewSources,
					tables.NewNodeAddressTable,
					statedb.RWTable[tables.NodeAddress].ToTable,
					func(cfg lb.TestConfig) *option.DaemonConfig {
						return &option.DaemonConfig{
							EnableIPv4: true,
							EnableIPv6: true,
						}
					},
					func() kpr.KPRConfig {
						return kpr.KPRConfig{
							KubeProxyReplacement: true,
						}
					},
				),

				Cell,
			)

			flags := pflag.NewFlagSet("", pflag.ContinueOnError)
			h.RegisterFlags(flags)

			flags.Set("enable-active-lb-health-checking", "true")

			// Parse the shebang arguments in the script.
			require.NoError(t, flags.Parse(args), "flags.Parse")

			t.Cleanup(func() {
				assert.NoError(t, h.Stop(log, context.TODO()))
			})
			cmds, err := h.ScriptCommands(log)
			require.NoError(t, err, "ScriptCommands")
			maps.Insert(cmds, maps.All(script.DefaultCmds()))

			return &script.Engine{
				Cmds:             cmds,
				RetryInterval:    20 * time.Millisecond,
				MaxRetryInterval: 500 * time.Millisecond,
			}
		}, []string{
			fmt.Sprintf("HTTP_PORT=%d", httpAddr.Port()),
			fmt.Sprintf("HTTPS_PORT=%d", httpsAddr.Port()),
			fmt.Sprintf("UDP_PORT=%d", udpServer.port()),
		},
		"testdata/*.txtar")
}

type udpServer struct {
	stopped chan struct{}
	conn    net.PacketConn
}

func newUdpServer() (u *udpServer, err error) {
	u = &udpServer{
		stopped: make(chan struct{}),
	}
	u.conn, err = net.ListenPacket("udp4", "127.0.0.1:0")
	if err == nil {
		go u.loop()
	}
	return
}

func (u *udpServer) port() int {
	s := u.conn.LocalAddr().String()
	_, after, _ := strings.Cut(s, ":")
	p, _ := strconv.ParseInt(after, 10, 32)
	return int(p)
}

func (u *udpServer) loop() {
	defer close(u.stopped)
	for {
		buf := make([]byte, 0, 10)
		n, addr, err := u.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		u.conn.WriteTo(buf[:n], addr)
	}
}

func (u *udpServer) close() {
	u.conn.Close()
	<-u.stopped
}
