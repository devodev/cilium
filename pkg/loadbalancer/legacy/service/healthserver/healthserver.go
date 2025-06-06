// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package healthserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"sync/atomic"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/counter"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// ServiceName is the name and namespace of the service
type ServiceName struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// Service represents the object returned by the health server
type Service struct {
	Service        ServiceName `json:"service"`
	LocalEndpoints int         `json:"localEndpoints"`
}

// NewService creates a new service
func NewService(ns, name string, localEndpoints int) *Service {
	return &Service{
		Service: ServiceName{
			Namespace: ns,
			Name:      name,
		},
		LocalEndpoints: localEndpoints,
	}
}

// healthHTTPServer is a running HTTP health server for a certain service
type healthHTTPServer interface {
	updateService(*Service)
	shutdown()
}

// healthHTTPServerFactory creates a new HTTP health server, used for mocking
type healthHTTPServerFactory interface {
	newHTTPHealthServer(port uint16, svc *Service) healthHTTPServer
}

// ServiceHealthServer manages HTTP health check ports. For each added service,
// it opens a HTTP server on the specified HealthCheckNodePort and either
// responds with 200 OK if there are local endpoints for the service, or with
// 503 Service Unavailable if the service does not have any local endpoints.
type ServiceHealthServer struct {
	logger                  *slog.Logger
	healthHTTPServerByPort  map[uint16]healthHTTPServer
	portRefCount            counter.IntCounter
	portByServiceID         map[lb.ID]uint16
	healthHTTPServerFactory healthHTTPServerFactory
}

// New creates a new health service server which services health checks by
// serving an HTTP endpoint for each service on the given HealthCheckNodePort.
func New(logger *slog.Logger) *ServiceHealthServer {
	return WithHealthHTTPServerFactory(logger, &httpHealthHTTPServerFactory{logger: logger})
}

// WithHealthHTTPServerFactory creates a new health server with a specific health
// server factory for testing purposes.
func WithHealthHTTPServerFactory(logger *slog.Logger, healthHTTPServerFactory healthHTTPServerFactory) *ServiceHealthServer {
	return &ServiceHealthServer{
		logger:                  logger,
		healthHTTPServerByPort:  map[uint16]healthHTTPServer{},
		portRefCount:            counter.IntCounter{},
		portByServiceID:         map[lb.ID]uint16{},
		healthHTTPServerFactory: healthHTTPServerFactory,
	}
}

func (s *ServiceHealthServer) removeHTTPListener(port uint16) {
	if s.portRefCount.Delete(int(port)) {
		srv, ok := s.healthHTTPServerByPort[port]
		if !ok {
			s.logger.Warn(
				"Invalid refcount for service health check port",
				logfields.Port, port,
			)
			return
		}
		srv.shutdown()
		delete(s.healthHTTPServerByPort, port)
	}
}

// UpsertService inserts or updates a service health check server on 'port'. If
// 'port' is zero, the listener for the added service is stopped.
// Access to this method is not synchronized. It is the caller's responsibility
// to ensure this method is called in a thread-safe manner.
func (s *ServiceHealthServer) UpsertService(svcID lb.ID, ns, name string, localEndpoints int, port uint16) {
	oldPort, foundSvc := s.portByServiceID[svcID]
	if foundSvc && oldPort != port {
		// HealthCheckNodePort has changed, we treat this as a DeleteService
		// followed by an Insert.
		s.removeHTTPListener(oldPort)
		delete(s.portByServiceID, svcID)
		foundSvc = false
	}

	// Nothing to do for services without a health check port
	if port == 0 {
		return
	}

	// Since we have one lb.SVC per frontend, we may end up receiving
	// multiple identical services per port. The following code assumes that
	// two services with the same port also have the same name and amount of
	// endpoints. We reference count the listeners to make sure we only have
	// a single listener per port.

	svc := NewService(ns, name, localEndpoints)
	if !foundSvc {
		// We only bump the reference count if this is a service ID we have
		// not seen before
		if s.portRefCount.Add(int(port)) {
			s.healthHTTPServerByPort[port] = s.healthHTTPServerFactory.newHTTPHealthServer(port, svc)
		}
	}

	srv, foundSrv := s.healthHTTPServerByPort[port]
	if !foundSrv {
		s.logger.Warn(
			"Unable to find service health check listener",
			logfields.ServiceID, svcID,
			logfields.ServiceNamespace, ns,
			logfields.ServiceName, name,
			logfields.ServiceHealthCheckNodePort, port,
		)
		return
	}

	srv.updateService(svc)
	s.portByServiceID[svcID] = port
}

// DeleteService stops the health server for the given service with 'svcID'.
// Access to this method is not synchronized. It is the caller's responsibility
// to ensure this method is called in a thread-safe manner.
func (s *ServiceHealthServer) DeleteService(svcID lb.ID) {
	if port, ok := s.portByServiceID[svcID]; ok {
		s.removeHTTPListener(port)
		delete(s.portByServiceID, svcID)
	}
}

type httpHealthServer struct {
	http.Server
	service atomic.Value
}

type httpHealthHTTPServerFactory struct {
	logger *slog.Logger
}

func (h *httpHealthHTTPServerFactory) newHTTPHealthServer(port uint16, svc *Service) healthHTTPServer {
	srv := &httpHealthServer{}
	srv.service.Store(svc)
	srv.Server = http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: srv,
	}

	go func() {
		h.logger.Debug(
			"Starting new service health server",
			logfields.ServiceNamespace, svc.Service.Namespace,
			logfields.ServiceName, svc.Service.Name,
			logfields.ServiceHealthCheckNodePort, port,
		)

		if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			svc := srv.loadService()
			if errors.Is(err, unix.EADDRINUSE) {
				h.logger.Error(
					fmt.Sprintf("ListenAndServe failed for service health server, since the user might be running with kube-proxy. Please ensure that '--%s' option is set to false if kube-proxy is running.", lb.EnableHealthCheckNodePortName),
					logfields.Error, err,
					logfields.ServiceNamespace, svc.Service.Namespace,
					logfields.ServiceName, svc.Service.Name,
					logfields.ServiceHealthCheckNodePort, port,
				)
			}
			h.logger.Error(
				"ListenAndServe failed for service health server",
				logfields.Error, err,
				logfields.ServiceNamespace, svc.Service.Namespace,
				logfields.ServiceName, svc.Service.Name,
				logfields.ServiceHealthCheckNodePort, port,
			)
		}
	}()

	return srv
}

func (h *httpHealthServer) loadService() *Service {
	return h.service.Load().(*Service)
}

func (h *httpHealthServer) updateService(svc *Service) {
	h.service.Store(svc)
}

func (h *httpHealthServer) shutdown() {
	h.Server.Shutdown(context.Background())
}

func (h *httpHealthServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Use headers and JSON output compatible with kube-proxy
	svc := h.loadService()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Load-Balancing-Endpoint-Weight", strconv.Itoa(svc.LocalEndpoints))

	if svc.LocalEndpoints == 0 {
		w.WriteHeader(http.StatusServiceUnavailable)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	if err := json.NewEncoder(w).Encode(&svc); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
