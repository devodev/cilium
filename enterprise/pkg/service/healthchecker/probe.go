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
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"

	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/version"
)

const (
	userAgentName   = "cilium-probe"
	logfieldNetwork = "network"

	SO_MARK           = 36
	MARK_MAGIC_HEALTH = 0x0D00
)

func probe(p probeParams) probeResult {
	switch {
	case p.config.L7:
		return sendL7Probe(p)
	case p.beAddr.Protocol() == lb.TCP:
		return sendTCPProbe(p)
	case p.beAddr.Protocol() == lb.UDP:
		return sendUDPProbe(p)
	default:
		return probeResult{ts: time.Now(), healthy: true, message: "unsupported protocol"}
	}
}

type probeResult struct {
	ts      time.Time
	healthy bool
	message string
}

type probeParams struct {
	ctx             context.Context
	logger          *slog.Logger
	config          HealthCheckConfig
	svcAddr, beAddr lb.L3n4Addr
}

// backendAddrKey is used as a key to context.Value(). It is used
// to pass the backend address.
type backendAddrKey struct{}

// dialerConnSetupDSRviaIPIP is a custom dialer which interacts with Cilium's bpf_sock
// BPF program to mark the socket as "special" for health probes. It will first bind()
// to the targeted backend and then connect(). bind() records the targeted backend via
// socket cookie, and connect() skips any translation, so that this later is sent as
// original packet via IPIP tunnel with the backend (T2 node) as destination address in
// the outer packet.
func (p probeParams) dialerConnSetupDSRviaIPIP(ctx context.Context, network string, address string, c syscall.RawConn) error {
	var errCB error
	var fn func(uintptr)

	if !option.Config.UnsafeDaemonConfigOption.EnableHealthDatapath {
		return nil
	}
	backend := ctx.Value(backendAddrKey{}).(string)

	p.logger.
		Debug("dialerConnSetupDSRviaIPIP",
			logfieldNetwork, network,
			logfields.Address, address,
			logfields.Backend, backend)

	switch network {
	case "tcp4", "tcp6":
		tcpAddr, err := net.ResolveTCPAddr(network, backend)
		if err != nil {
			return err
		}

		fn = func(s uintptr) {
			errCB = syscall.SetsockoptInt(int(s), syscall.SOL_SOCKET, SO_MARK, MARK_MAGIC_HEALTH)
			if errCB == nil {
				if network == "tcp4" {
					sa := &syscall.SockaddrInet4{
						Port: tcpAddr.Port,
					}
					ip4 := tcpAddr.IP.To4()
					copy(sa.Addr[:], ip4)
					errCB = syscall.Bind(int(s), sa)
				} else {
					sa := &syscall.SockaddrInet6{
						Port: tcpAddr.Port,
					}
					ip6 := tcpAddr.IP.To16()
					copy(sa.Addr[:], ip6)
					errCB = syscall.Bind(int(s), sa)
				}
			}
		}
	case "udp4", "udp6":
		udpAddr, err := net.ResolveUDPAddr(network, backend)
		if err != nil {
			return err
		}
		fn = func(s uintptr) {
			errCB = syscall.SetsockoptInt(int(s), syscall.SOL_SOCKET, SO_MARK, MARK_MAGIC_HEALTH)
			if errCB == nil {
				if network == "udp4" {
					sa := &syscall.SockaddrInet4{
						Port: udpAddr.Port,
					}
					ip4 := udpAddr.IP.To4()
					copy(sa.Addr[:], ip4)
					errCB = syscall.Bind(int(s), sa)
				} else {
					sa := &syscall.SockaddrInet6{
						Port: udpAddr.Port,
					}
					ip6 := udpAddr.IP.To16()
					copy(sa.Addr[:], ip6)
					errCB = syscall.Bind(int(s), sa)
				}
			}
		}
	default:
		return nil
	}
	if err := c.Control(fn); err != nil {
		return err
	}
	if errCB != nil {
		return errCB
	}
	return nil
}

func (p probeParams) addrWithProbePort(addr lb.L3n4Addr) lb.L3n4Addr {
	if p.config.ProbePort == 0 || addr.Port() == p.config.ProbePort {
		return addr
	}
	return lb.NewL3n4Addr(addr.Protocol(), addr.AddrCluster(), p.config.ProbePort, addr.Scope())
}

func probeFailSignal(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENOPROTOOPT) ||
		errors.Is(err, syscall.EHOSTDOWN) ||
		errors.Is(err, syscall.ENONET)
}

func sendTCPProbe(p probeParams) probeResult {
	d := net.Dialer{
		Timeout: p.config.ProbeTimeout,
	}
	connAddr := ""
	backendAddr := p.beAddr
	// IPIP DSR needs special dialer so that packets can be encapped the same way as regular LB traffic.
	if option.Config.UnsafeDaemonConfigOption.EnableHealthDatapath && p.config.DSR {
		connAddr = getAddrStr(p.svcAddr)
		d.ControlContext = p.dialerConnSetupDSRviaIPIP
	} else {
		connAddr = getAddrStr(p.addrWithProbePort(p.beAddr))
		backendAddr = p.addrWithProbePort(p.beAddr)
	}
	ctx := context.WithValue(p.ctx, backendAddrKey{}, getAddrStr(backendAddr))
	conn, err := d.DialContext(ctx, "tcp", connAddr)
	if err != nil {
		// Be conservative while failing a probe.
		if probeFailSignal(err) || os.IsTimeout(err) {
			return getProbeData(fmt.Errorf("err: %w", err))
		}
		p.logger.Debug("Dial TCP failed while sending out probe",
			logfields.Backend, backendAddr,
			logfields.Error, err)
		return getProbeData(nil)
	}
	defer conn.Close()

	probe := getProbeData(nil)
	p.logger.Debug("TCP health check success",
		logfields.Backend, backendAddr,
		logfields.Probe, probe)
	return probe
}

func sendUDPProbe(p probeParams) probeResult {
	d := net.Dialer{}
	connAddr := ""
	backendAddr := p.beAddr
	// IPIP DSR needs special dialer so that packets can be encapped the same way as regular LB traffic.
	if option.Config.UnsafeDaemonConfigOption.EnableHealthDatapath && p.config.DSR {
		connAddr = getAddrStr(p.svcAddr)
		d.ControlContext = p.dialerConnSetupDSRviaIPIP
	} else {
		connAddr = getAddrStr(p.addrWithProbePort(p.beAddr))
		backendAddr = p.addrWithProbePort(p.beAddr)
	}
	ctx := context.WithValue(p.ctx, backendAddrKey{}, getAddrStr(backendAddr))
	// In the absence of flow control, the only definitive signal we can rely
	// on for checking if remote UDP server is up is the receipt of
	// ICMP_PORT_UNREACHABLE message.
	// These messages, however, can sometimes get dropped by middle boxes. The
	// health checker doesn't fail probes in such cases.
	// ECONNREFUSED only sent for connected UDP:
	// https://elixir.bootlin.com/linux/v6.0/source/net/ipv4/icmp.c#L130
	conn, err := d.DialContext(ctx, "udp", connAddr)
	if err != nil {
		p.logger.Debug("DialUDP() failed while sending out probe",
			logfields.Backend, backendAddr,
			logfields.Error, err)
		return getProbeData(nil)
	}
	defer conn.Close()
	// UDP send/receive blocks only when the buffer is full, so we need not set
	// the timeout here. But just in case...
	conn.SetDeadline(time.Now().Add(p.config.ProbeTimeout))
	if _, err = conn.Write([]byte("")); err != nil {
		p.logger.Info("Write() failed while sending out probe",
			logfields.Backend, backendAddr,
			logfields.Error, err)
		return getProbeData(nil)
	}
	_, err = bufio.NewReader(conn).ReadString('\n')
	var errno syscall.Errno
	if errors.As(err, &errno) {
		// ECONNREFUSED wraps ICMP_PORT_UNREACHABLE
		// https://elixir.bootlin.com/linux/v6.0/source/net/ipv4/icmp.c#L130
		if probeFailSignal(err) {
			p.logger.Debug("probe failed",
				logfields.Backend, backendAddr,
				logfields.Error, err)
			return getProbeData(fmt.Errorf("error: %w", err))
		}
	} else if os.IsTimeout(err) {
		// In case of timeout, this either means the packet got lost
		// somewhere on the network, or the remote application accepted
		// the probe packet. Consider this a success case since we did
		// not get an ICMP error back.
		probe := getProbeData(nil)
		p.logger.Debug("UDP health check success (via timeout)",
			logfields.Backend, backendAddr,
			logfields.Probe, probe)
		return probe
	}

	// In case of an actual reply, we obviously consider this a success.
	probe := getProbeData(nil)
	p.logger.Debug("UDP health check success (via reply)",
		logfields.Backend, backendAddr,
		logfields.Probe, probe)
	return probe
}

func getProbeData(err error) probeResult {
	var probe probeResult

	probe.ts = time.Now()
	if err == nil {
		probe.healthy = true
		probe.message = "success"
	} else {
		probe.healthy = false
		probe.message = fmt.Sprintf("failed: %v", err)
	}

	return probe
}

func sendL7Probe(p probeParams) probeResult {
	// create a client with proper timeout and TLS config in case of HTTPS
	d := &net.Dialer{}
	tr := &http.Transport{
		DialContext: d.DialContext,
	}
	// close all connections after we're done probing.
	client := http.Client{
		Timeout:   p.config.ProbeTimeout,
		Transport: tr,
	}
	if p.config.HTTPScheme == HealthCheckSchemeHTTPS {
		tls := &tls.Config{
			InsecureSkipVerify: true,              // #nosec G402 - health-checker does not check server's certificate
			ServerName:         p.config.HTTPHost, // used for SNI
		}
		tr.TLSClientConfig = tls
	}
	url := ""
	// IPIP DSR needs special dialer so that packets can be encapped the same way as regular LB traffic.
	if option.Config.UnsafeDaemonConfigOption.EnableHealthDatapath && p.config.DSR {
		url = getConnURL(p.config, p.svcAddr)
		d.ControlContext = p.dialerConnSetupDSRviaIPIP
	} else {
		url = getConnURL(p.config, p.addrWithProbePort(p.beAddr))
	}
	method := getSvcHTTPMethod(p.config)
	backend := getAddrStr(p.addrWithProbePort(p.beAddr))
	logFields := []slog.Attr{
		slog.String(logfields.URL, url),
		slog.String(logfields.Method, method),
		slog.String(logfields.Host, p.config.HTTPHost),
		slog.String(logfields.Backend, backend),
	}

	// create a request with proper method, URL and HTTP Host
	ctx := context.WithValue(p.ctx, backendAddrKey{}, backend)
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		fields := append(logFields, slog.Any(logfields.Error, err))
		p.logger.LogAttrs(context.Background(), slog.LevelDebug, "L7 health check failure", fields...)
		return getProbeData(err)
	}
	req.Header.Set("User-Agent", fmt.Sprintf("%s/%s", userAgentName, version.GetCiliumVersion().Version))
	req.Close = true             // do not attempt to re-use TCP connection
	req.Host = p.config.HTTPHost // need to set the Host explicitly, as URL contains the backend IP

	// send the request
	res, err := client.Do(req)
	if res != nil {
		defer res.Body.Close()
	}
	if err != nil {
		fields := append(logFields, slog.Any(logfields.Error, err))
		p.logger.LogAttrs(context.Background(), slog.LevelDebug, "L7 health check failure", fields...)
		return getProbeData(err)
	}

	// only consider status code 200 as success
	if res.StatusCode != http.StatusOK {
		err = fmt.Errorf("invalid status code: %d", res.StatusCode)
		fields := append(logFields, slog.Any(logfields.Error, err))
		p.logger.LogAttrs(context.Background(), slog.LevelDebug, "L7 health check failure", fields...)
		return getProbeData(err)
	}

	p.logger.LogAttrs(context.Background(), slog.LevelDebug, "L7 health check success", logFields...)

	return getProbeData(nil)
}

func getAddrStr(addr lb.L3n4Addr) string {
	portStr := strconv.FormatUint(uint64(addr.Port()), 10)

	if addr.IsIPv6() {
		return fmt.Sprintf("[%s]:%s", addr.AddrCluster().String(), portStr)
	}

	return addr.AddrCluster().String() + ":" + portStr
}

func getSvcHTTPMethod(config HealthCheckConfig) string {
	switch config.HTTPMethod {
	case HealthCheckMethodHead:
		return http.MethodHead
	default:
		return http.MethodGet
	}
}

func getConnURL(config HealthCheckConfig, connAddr lb.L3n4Addr) string {
	var scheme, addr, path string
	switch config.HTTPScheme {
	case HealthCheckSchemeHTTPS:
		scheme = "https"
	default:
		scheme = "http"
	}
	if connAddr.AddrCluster().Addr().Is6() {
		addr = fmt.Sprintf("[%s]", connAddr.AddrCluster().Addr().String())
	} else {
		addr = connAddr.AddrCluster().Addr().String()
	}
	if config.HTTPPath != "" {
		path = config.HTTPPath
		if !strings.HasPrefix(path, "/") {
			path = "/" + path // make sure the path always starts with a slash
		}
	}
	return fmt.Sprintf("%s://%s:%d%s", scheme, addr, connAddr.Port(), path)
}
