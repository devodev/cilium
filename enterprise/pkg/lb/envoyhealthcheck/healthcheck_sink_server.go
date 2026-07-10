// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoyhealthcheck

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"syscall"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_data_core_v3 "github.com/envoyproxy/go-control-plane/envoy/data/core/v3"
	"github.com/spf13/pflag"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/pkg/ciliumenvoyconfig"
	"github.com/cilium/cilium/pkg/envoy/config"
	envoyutil "github.com/cilium/cilium/pkg/envoy/util"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

const (
	healthcheckSinkSocketName = "healthcheck_sink.sock"
)

var Cell = cell.Module(
	"loadbalancer-envoy-hc-events",
	"Handles Envoy healthcheck events",

	cell.Invoke(registerHealthCheckSinkServer),
	cell.ProvidePrivate(newHealthCheckTable),
	cell.Provide(statedb.RWTable[*HealthCheck].ToTable),
	cell.Config(envoyHealthCheckSinkConfig{
		EnvoyHealthCheckEventServerEnabled:    false,
		EnvoyHealthCheckEventServerGCInterval: 30 * time.Second,
	}),
)

type envoyHealthCheckSinkConfig struct {
	EnvoyHealthCheckEventServerEnabled    bool
	EnvoyHealthCheckEventServerGCInterval time.Duration
}

func (c envoyHealthCheckSinkConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("envoy-health-check-event-server-enabled", c.EnvoyHealthCheckEventServerEnabled, "Enables and deploys the Envoy health check event server that receives health check events from the node-local Envoy proxy")
	flags.Duration("envoy-health-check-event-server-gc-interval", c.EnvoyHealthCheckEventServerGCInterval, "Interval of the Envoy health check table garbage collection")
}

type healthcheckSinkServerParams struct {
	cell.In

	Config envoyHealthCheckSinkConfig

	JobGroup         job.Group
	Health           cell.Health
	Logger           *slog.Logger
	EnvoyProxyConfig config.ProxyConfig

	DB               *statedb.DB
	HealthCheckTable statedb.RWTable[*HealthCheck]
	CECTable         statedb.Table[*ciliumenvoyconfig.CEC]
}

func registerHealthCheckSinkServer(params healthcheckSinkServerParams) error {
	if !option.Config.EnableL7Proxy {
		params.Logger.Debug("L7 proxies are disabled - not starting Envoy HealthCheck sink server")
		return nil
	}

	if !params.Config.EnvoyHealthCheckEventServerEnabled {
		return nil
	}

	server := newHealthCheckSinkServer(
		params.Logger,
		params.DB,
		params.HealthCheckTable,
		params.CECTable,
		envoyutil.GetSocketDir(option.Config.RunDir),
		params.EnvoyProxyConfig.ProxyGID,
		params.EnvoyProxyConfig.EnvoyAccessLogBufferSize,
	)

	params.JobGroup.Add(job.OneShot("server", func(ctx context.Context, health cell.Health) error {
		if err := server.start(); err != nil {
			return fmt.Errorf("failed to start Envoy HealthCheck sink server: %w", err)
		}
		<-ctx.Done()
		server.stop()
		return nil
	}))

	params.JobGroup.Add(job.OneShot("interval-sync", server.syncHealthCheckIntervalsFromCEC))

	params.JobGroup.Add(job.Timer("gc", server.performHealthCheckTableGC, params.Config.EnvoyHealthCheckEventServerGCInterval))

	return nil
}

type HealthCheckSinkServer struct {
	logger           *slog.Logger
	db               *statedb.DB
	healthCheckTable statedb.RWTable[*HealthCheck]
	cecTable         statedb.Table[*ciliumenvoyconfig.CEC]

	socketPath string
	proxyGID   uint
	stopCh     chan struct{}
	bufferSize uint

	intervals      map[string]time.Duration
	intervalsMutex lock.RWMutex
}

func newHealthCheckSinkServer(logger *slog.Logger, db *statedb.DB, healthCheckTable statedb.RWTable[*HealthCheck], cecTable statedb.Table[*ciliumenvoyconfig.CEC], envoySocketDir string, proxyGID uint, bufferSize uint) *HealthCheckSinkServer {
	return &HealthCheckSinkServer{
		logger:           logger,
		db:               db,
		healthCheckTable: healthCheckTable,
		cecTable:         cecTable,
		socketPath:       filepath.Join(envoySocketDir, healthcheckSinkSocketName),
		proxyGID:         proxyGID,
		bufferSize:       bufferSize,
		intervals:        map[string]time.Duration{},
	}
}

// start starts the healthcheck sink server.
func (s *HealthCheckSinkServer) start() error {
	socketListener, err := s.newSocketListener()
	if err != nil {
		return fmt.Errorf("failed to create socket listener: %w", err)
	}

	s.stopCh = make(chan struct{})

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		s.logger.Info("Envoy: Starting healthcheck sink server listening",
			logfields.Address, socketListener.Addr(),
		)
		for {
			// Each Envoy listener opens a new connection over the Unix domain socket.
			// Multiple worker threads serving the listener share that same connection
			uc, err := socketListener.AcceptUnix()
			if err != nil {
				// These errors are expected when we are closing down
				if errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.EINVAL) {
					break
				}
				s.logger.Warn("Envoy: Failed to accept healthcheck sink connection",
					logfields.Error, err,
				)
				continue
			}
			s.logger.Info("Envoy: Accepted healthcheck sink connection")

			// Serve this healthcheck sink socket in a goroutine, so we can serve multiple
			// connections concurrently.
			go s.handleConn(ctx, uc)
		}
	}()

	go func() {
		<-s.stopCh
		_ = socketListener.Close()
		cancel()
	}()

	return nil
}

func (s *HealthCheckSinkServer) newSocketListener() (*net.UnixListener, error) {
	// Remove/Unlink the old unix domain socket, if any.
	_ = os.Remove(s.socketPath)

	// Create the listener
	listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: s.socketPath, Net: "unixpacket"})
	if err != nil {
		return nil, fmt.Errorf("failed to open healthcheck sink listen socket at %s: %w", s.socketPath, err)
	}
	listener.SetUnlinkOnClose(true)

	// Make the socket accessible by owner and group only.
	if err = os.Chmod(s.socketPath, 0o660); err != nil {
		return nil, fmt.Errorf("failed to change mode of healthcheck sink listen socket at %s: %w", s.socketPath, err)
	}
	// Change the group to ProxyGID allowing access from any process from that group.
	if err = os.Chown(s.socketPath, -1, int(s.proxyGID)); err != nil {
		s.logger.Warn("Envoy: Failed to change the group of healthcheck sink listen socket",
			logfields.Path, s.socketPath,
			logfields.Error, err,
		)
	}
	return listener, nil
}

func (s *HealthCheckSinkServer) stop() {
	if s.stopCh != nil {
		s.stopCh <- struct{}{}
	}
}

func (s *HealthCheckSinkServer) handleConn(ctx context.Context, conn *net.UnixConn) {
	stopCh := make(chan struct{})

	go func() {
		select {
		case <-stopCh:
		case <-ctx.Done():
			_ = conn.Close()
		}
	}()

	defer func() {
		s.logger.Info("Envoy: Closing healthcheck sink connection")
		_ = conn.Close()
		stopCh <- struct{}{}
	}()

	buf := make([]byte, s.bufferSize)
	for {
		n, _, flags, _, err := conn.ReadMsgUnix(buf, nil)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				s.logger.Error("Envoy: Error while reading from healthcheck sink connection",
					logfields.Error, err,
				)
			}
			break
		}
		if flags&unix.MSG_TRUNC != 0 {
			s.logger.Warn("Envoy: Discarded truncated healthcheck event message - increase buffer size via --envoy-access-log-buffer-size",
				logfields.BufferSize, s.bufferSize,
			)
			continue
		}
		hcEvent := envoy_data_core_v3.HealthCheckEvent{}
		err = proto.Unmarshal(buf[:n], &hcEvent)
		if err != nil {
			s.logger.Warn("Envoy: Discarded invalid healthcheck event message",
				logfields.Error, err,
			)
			continue
		}

		s.logger.Debug("Received Envoy health event",
			logfields.ClusterName, hcEvent.ClusterName,
			logfields.Backend, toBackendAddress(hcEvent.Host),
			logfields.Event, toHealthEventType(&hcEvent),
		)

		if err := s.updateHealthCheckEvent(&hcEvent); err != nil {
			s.logger.Warn("Envoy: Failed to update healthcheck statedb table",
				logfields.Error, err,
			)
		}
	}
}

func (s *HealthCheckSinkServer) updateHealthCheckEvent(event *envoy_data_core_v3.HealthCheckEvent) error {
	wtxn := s.db.WriteTxn(s.healthCheckTable)
	defer wtxn.Commit()

	_, _, err := s.healthCheckTable.Insert(wtxn, &HealthCheck{
		Cluster:   event.ClusterName,
		Backend:   toBackendAddress(event.Host),
		Type:      toHealthCheckType(event.HealthCheckerType),
		Interval:  s.getInterval(event.ClusterName),
		UpdatedAt: event.Timestamp.AsTime(),
		Healthy:   toHealthState(event),
	})
	if err != nil {
		wtxn.Abort()
		return err
	}

	return nil
}

func (s *HealthCheckSinkServer) syncHealthCheckIntervalsFromCEC(ctx context.Context, health cell.Health) error {
	wtxn := s.db.WriteTxn(s.cecTable)

	cecs := s.cecTable.All(wtxn)

	for cec := range cecs {
		for _, c := range cec.Resources.Clusters {
			s.intervalsMutex.Lock()
			s.intervals[c.Name] = shortestHCIntervalFromCluster(c)
			s.intervalsMutex.Unlock()
		}
	}

	cecChanges, err := s.cecTable.Changes(wtxn)
	if err != nil {
		wtxn.Abort()
		return err
	}
	wtxn.Commit()

	for {
		changes, watch := cecChanges.Next(s.db.ReadTxn())
		for change := range changes {
			s.logger.Debug("Processing CEC change", logfields.Deleted, change.Deleted)

			cec := change.Object

			for _, c := range cec.Resources.Clusters {

				shortestInterval := shortestHCIntervalFromCluster(c)

				if change.Deleted || shortestInterval == 0*time.Second {
					s.intervalsMutex.Lock()
					delete(s.intervals, c.Name)
					s.intervalsMutex.Unlock()
					continue
				}

				s.intervalsMutex.Lock()
				s.intervals[c.Name] = shortestInterval
				s.intervalsMutex.Unlock()
			}
		}

		select {
		case <-ctx.Done():
			return nil
		case <-watch:
		}
	}
}

func shortestHCIntervalFromCluster(c *envoy_config_cluster_v3.Cluster) time.Duration {
	shortestInterval := 0 * time.Second
	for _, hc := range c.HealthChecks {
		if len(hc.EventLogger) > 0 && hc.Interval != nil && (shortestInterval == 0*time.Second || hc.Interval.AsDuration() < shortestInterval) {
			shortestInterval = hc.Interval.AsDuration()
		}
	}

	return shortestInterval
}

func (s *HealthCheckSinkServer) performHealthCheckTableGC(ctx context.Context) error {
	wtxn := s.db.WriteTxn(s.healthCheckTable)
	hcs := s.healthCheckTable.All(wtxn)
	defer wtxn.Commit()

	for hc := range hcs {
		if time.Since(hc.UpdatedAt) > hc.Interval+5 {
			s.logger.Debug("Cleaning up health check entry",
				logfields.ClusterName, hc.Cluster,
				logfields.Backend, hc.Backend,
			)
			if _, _, err := s.healthCheckTable.Delete(wtxn, hc); err != nil {
				wtxn.Abort()
				return fmt.Errorf("failed to delete health check entry in GC: %w", err)
			}
		}
	}

	return nil
}

func toBackendAddress(address *corev3.Address) string {
	switch {
	case address.GetSocketAddress() != nil:
		return fmt.Sprintf("%s:%d", address.GetSocketAddress().GetAddress(), address.GetSocketAddress().GetPortValue())
	default:
		// not supported
		return "n/a"
	}
}

func toHealthCheckType(hcType envoy_data_core_v3.HealthCheckerType) string {
	switch hcType {
	case envoy_data_core_v3.HealthCheckerType_TCP:
		return "tcp"
	case envoy_data_core_v3.HealthCheckerType_HTTP:
		return "http"
	case envoy_data_core_v3.HealthCheckerType_GRPC:
		return "grpc"
	case envoy_data_core_v3.HealthCheckerType_REDIS:
		return "redis"
	case envoy_data_core_v3.HealthCheckerType_THRIFT:
		return "thrift"
	default:
		return "unknown"
	}
}

func toHealthState(event *envoy_data_core_v3.HealthCheckEvent) bool {
	switch event.Event.(type) {
	case *envoy_data_core_v3.HealthCheckEvent_AddHealthyEvent, *envoy_data_core_v3.HealthCheckEvent_SuccessfulHealthCheckEvent:
		return true
	case *envoy_data_core_v3.HealthCheckEvent_EjectUnhealthyEvent, *envoy_data_core_v3.HealthCheckEvent_HealthCheckFailureEvent:
		return false
	default:
		return false
	}
}

func (s *HealthCheckSinkServer) getInterval(clusterName string) time.Duration {
	s.intervalsMutex.RLock()
	defer s.intervalsMutex.RUnlock()
	return s.intervals[clusterName]
}

func toHealthEventType(event *envoy_data_core_v3.HealthCheckEvent) string {
	switch event.Event.(type) {
	case *envoy_data_core_v3.HealthCheckEvent_AddHealthyEvent:
		return "add_healthy"
	case *envoy_data_core_v3.HealthCheckEvent_EjectUnhealthyEvent:
		return "eject_unhealthy"
	case *envoy_data_core_v3.HealthCheckEvent_HealthCheckFailureEvent:
		return "healthcheck_failure"
	case *envoy_data_core_v3.HealthCheckEvent_SuccessfulHealthCheckEvent:
		return "healthcheck_successful"
	case *envoy_data_core_v3.HealthCheckEvent_DegradedHealthyHost:
		return "degraded"
	case *envoy_data_core_v3.HealthCheckEvent_NoLongerDegradedHost:
		return "no_longer_degraded"
	default:
		return "unknown"
	}
}
