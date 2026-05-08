// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package healthcheck

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

// Cell provides a [Healthchecker] for consumption with hive.
var Cell = cell.Module(
	"egressgateway-healthchecker",
	"Egress Gateway healthchecker",
	cell.Config(defaultConfig),
	cell.Provide(NewHealthchecker),
)

type Config struct {
	// Healthcheck timeout after which an egress gateway is marked not healthy.
	// This also configures the frequency of probes to a value of healthcheckTimeout / 2
	EgressGatewayHAHealthcheckTimeout time.Duration

	// EnableEgressGatewayHAICMPHealthProbe enables ICMP health probing of egress gateway nodes.
	// When enabled, the cilium-operator periodically sends ICMP echo requests to gateway nodes
	// to verify their availability.
	EnableEgressGatewayHAICMPHealthProbe bool `mapstructure:"enable-egress-gateway-ha-icmp-health-probe"`

	// EgressGatewayHAHealthcheckICMPHealthProbeInterval defines the interval at which
	// ICMP echo requests are sent to gateway nodes for health verification.
	EgressGatewayHAHealthcheckICMPHealthProbeInterval time.Duration `mapstructure:"egress-gateway-ha-icmp-health-probe-interval"`

	// EgressGatewayHAHealthcheckICMPHealthProbeFailureThreshold specifies the number
	// of consecutive failed ICMP probes after which a gateway node is considered unhealthy.
	EgressGatewayHAHealthcheckICMPHealthProbeFailureThreshold int `mapstructure:"egress-gateway-ha-icmp-health-probe-failure-threshold"`

	ClusterHealthPort int
}

var defaultConfig = Config{
	EgressGatewayHAHealthcheckTimeout:                         2 * time.Second,
	EnableEgressGatewayHAICMPHealthProbe:                      true,
	EgressGatewayHAHealthcheckICMPHealthProbeInterval:         100 * time.Millisecond,
	EgressGatewayHAHealthcheckICMPHealthProbeFailureThreshold: 3,
	ClusterHealthPort: defaults.ClusterHealthPort,
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Duration("egress-gateway-ha-healthcheck-timeout", def.EgressGatewayHAHealthcheckTimeout, "Healthcheck timeout after which an egress gateway is marked not healthy. This also configures the frequency of probes to a value of healthcheckTimeout / 2")
	flags.Bool("enable-egress-gateway-ha-icmp-health-probe", def.EnableEgressGatewayHAICMPHealthProbe, "Enables egress-gateway ha ICMP health probing of egress gateway nodes")
	flags.Duration("egress-gateway-ha-icmp-health-probe-interval", def.EgressGatewayHAHealthcheckICMPHealthProbeInterval, "The interval at which ICMP echo requests are sent to gateway nodes for health verification")
	flags.Int("egress-gateway-ha-icmp-health-probe-failure-threshold", def.EgressGatewayHAHealthcheckICMPHealthProbeFailureThreshold, "The number of consecutive failed ICMP probes after which a gateway node is considered unhealthy")
	flags.Int(option.ClusterHealthPort, defaultConfig.ClusterHealthPort, "")
	flags.MarkHidden(option.ClusterHealthPort)
}

// Event represents a healthchecking event such as a node becoming healthy/unhealthy
type Event struct {
	NodeName string
	Status   nodeHealth
}

// Healthchecker is the public interface exposed by the egress gateway healthchecker
type Healthchecker interface {
	UpdateNodeList(nodes map[string]nodeTypes.Node, healthy, active sets.Set[string])
	NodeHealth(nodeName string) NodeHealth
	Events() chan Event
}

type NodeHealth struct {
	Reachable bool
	AgentUp   bool
}

type probeMode int

const (
	HTTP probeMode = iota
	ICMP
)

type healthProber interface {
	runHealthcheckProbe() bool
	mode() probeMode
}

type nodeHealth int

const (
	NodeUnReachable nodeHealth = iota
	NodeReachableAgentDown
	NodeReachableAgentUp
)

func (n nodeHealth) String() string {
	switch n {
	case NodeUnReachable:
		return "unreachable"
	case NodeReachableAgentDown:
		return "reachable but agent down"
	case NodeReachableAgentUp:
		return "reachable and agent up"
	default:
		return "unknown"
	}
}

type nodeStatus struct {
	// lastSuccessfulProbeTimestamp is timestamp of the last successful probe
	lastSuccessfulProbeTimestamp time.Time

	// healthcheckerTickerCh is the channel used to stop the healthcheck goroutine for the node
	healthcheckerTickerCh *time.Ticker

	health nodeHealth
}

type healthchecker struct {
	logger *slog.Logger

	lock.RWMutex

	Config

	nodes    map[string]nodeTypes.Node
	statuses map[string]*nodeStatus
	events   chan Event
}

// NewHealthchecker returns a new Healthchecker
func NewHealthchecker(logger *slog.Logger, config Config) Healthchecker {
	return &healthchecker{
		logger:   logger,
		Config:   config,
		nodes:    make(map[string]nodeTypes.Node),
		statuses: make(map[string]*nodeStatus),
		events:   make(chan Event),
	}
}

// UpdateNodeList updates the internal list of nodes that the healthchecker
// should periodically check. The healthy parameter is a subset of node names
// that should be initialized as healthy even before the first health probe
// verdict is available.
func (h *healthchecker) UpdateNodeList(nodes map[string]nodeTypes.Node, healthy, active sets.Set[string]) {
	h.Lock()
	defer h.Unlock()

	for _, oldNode := range h.nodes {
		if _, ok := nodes[oldNode.Name]; !ok {
			h.stopNodeHealthcheck(oldNode)
		}
	}

	for _, newNode := range nodes {
		if _, ok := h.nodes[newNode.Name]; !ok {
			h.startNodeHealthcheck(newNode, healthy.Has(newNode.Name), active.Has(newNode.Name))
		}
	}

	h.nodes = nodes
}

// NodeIsHealthy returns whether a node is healthy (i.e. last successful probe
// is no older than `h.timeout`) or not
func (h *healthchecker) NodeIsHealthy(nodeName string) bool {
	h.RLock()
	defer h.RUnlock()

	status, ok := h.statuses[nodeName]

	return ok && h.probeTimestampIsFresh(status.lastSuccessfulProbeTimestamp)
}

func (h *healthchecker) NodeHealth(nodeName string) NodeHealth {
	h.RLock()
	defer h.RUnlock()

	status, ok := h.statuses[nodeName]
	if !ok {
		return NodeHealth{}
	}

	reachable := h.probeTimestampIsFresh(status.lastSuccessfulProbeTimestamp)

	return NodeHealth{
		Reachable: reachable,
		AgentUp:   reachable && status.health == NodeReachableAgentUp,
	}
}

// Events returns the healthchecker events channel
func (h *healthchecker) Events() chan Event {
	return h.events
}

func (h *healthchecker) createProber(node nodeTypes.Node, mode probeMode) healthProber {
	ip := node.GetCiliumTunnelIP()
	if ip == nil {
		ip = node.GetNodeIP(false)
	}

	switch mode {
	case HTTP:
		return h.createHttpProber(ip)
	case ICMP:
		return &icmpProber{
			logger:           h.logger,
			ip:               ip.String(),
			timeout:          h.EgressGatewayHAHealthcheckTimeout,
			failureThreshold: h.EgressGatewayHAHealthcheckICMPHealthProbeFailureThreshold,
			interval:         h.EgressGatewayHAHealthcheckICMPHealthProbeInterval,
		}
	default:
		return h.createHttpProber(ip)
	}
}

func (h *healthchecker) createHttpProber(ip net.IP) healthProber {
	return &httpProber{
		netClient: &http.Client{Timeout: h.EgressGatewayHAHealthcheckTimeout},
		url: fmt.Sprintf("http://%s/hello",
			net.JoinHostPort(ip.String(), strconv.Itoa(h.ClusterHealthPort))),
	}
}

func (h *healthchecker) probeTimestampIsFresh(probeTimestamp time.Time) bool {
	return time.Since(probeTimestamp) < h.EgressGatewayHAHealthcheckTimeout
}

// Caller must hold h.RwMutex
func (h *healthchecker) startNodeHealthcheck(node nodeTypes.Node, isHealthy bool, isActive bool) {
	var (
		tickerCh = time.NewTicker(h.EgressGatewayHAHealthcheckTimeout / 2)
		logger   = h.logger.With(logfields.NodeName, node.Name)
		probers  = func() []healthProber {
			ps := []healthProber{h.createProber(node, HTTP)}
			if h.EnableEgressGatewayHAICMPHealthProbe {
				ps = append(ps, h.createProber(node, ICMP))
			}

			return ps
		}()
	)

	logger.Info("Starting health check for node")

	status := &nodeStatus{
		healthcheckerTickerCh: tickerCh,
	}
	if isHealthy {
		status.lastSuccessfulProbeTimestamp = time.Now()
		if isActive {
			status.health = NodeReachableAgentUp
		} else {
			status.health = NodeReachableAgentDown
		}
		logger.Debug("Node health status is initialized as healthy", logfields.Status, status.health)
	} else {
		status.health = NodeUnReachable
	}
	h.statuses[node.Name] = status

	go func() {
		for range tickerCh.C {
			var event *Event

			nodeHealth := runHealthcheckProbe(probers)

			h.Lock()
			nodeStatus, ok := h.statuses[node.Name]
			if !ok {
				h.Unlock()
				continue
			}

			switch nodeHealth {
			case NodeUnReachable:
				if !h.probeTimestampIsFresh(nodeStatus.lastSuccessfulProbeTimestamp) &&
					!nodeStatus.lastSuccessfulProbeTimestamp.IsZero() {
					logger.Info("Node became unreachable", logfields.Status, nodeHealth)

					// When a node becomes unreachable, set its last successful probe TS to 0 so next
					// time we run this check we'll know the node was already unreachable (allowing us
					// to skip logging and emitting the event multiple times)
					nodeStatus.lastSuccessfulProbeTimestamp = time.Time{}
					nodeStatus.health = nodeHealth
					event = &Event{NodeName: node.Name, Status: nodeHealth}
				}
			case NodeReachableAgentUp, NodeReachableAgentDown:
				if !h.probeTimestampIsFresh(nodeStatus.lastSuccessfulProbeTimestamp) || nodeStatus.health != nodeHealth {
					logger.Info("Node became reachable", logfields.Status, nodeHealth)
					event = &Event{NodeName: node.Name, Status: nodeHealth}
				}

				nodeStatus.lastSuccessfulProbeTimestamp = time.Now()
				nodeStatus.health = nodeHealth
			}

			h.Unlock()

			if event != nil {
				h.events <- *event
			}
		}
	}()
}

type probeResult struct {
	mode probeMode
	ok   bool
}

func runHealthcheckProbe(probers []healthProber) nodeHealth {
	resCh := make(chan probeResult, len(probers))
	var wg sync.WaitGroup

	for _, p := range probers {
		wg.Go(func() {
			ok := p.runHealthcheckProbe()
			resCh <- probeResult{mode: p.mode(), ok: ok}
		})
	}

	go func() {
		wg.Wait()
		close(resCh)
	}()

	var (
		httpOK, icmpOK bool
		hasICMP        bool
	)

	for r := range resCh {
		switch r.mode {
		case HTTP:
			httpOK = r.ok
		case ICMP:
			hasICMP = true
			icmpOK = r.ok
		}
	}

	switch {
	case httpOK:
		return NodeReachableAgentUp
	case hasICMP && icmpOK:
		return NodeReachableAgentDown
	default:
		return NodeUnReachable
	}
}

// Caller must hold h.RwMutex
func (h *healthchecker) stopNodeHealthcheck(node nodeTypes.Node) {
	h.logger.Info("Stopping health check for node", logfields.NodeName, node.Name)

	h.statuses[node.Name].healthcheckerTickerCh.Stop()
	delete(h.statuses, node.Name)
}
