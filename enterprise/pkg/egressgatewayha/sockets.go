//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package egressgatewayha

import (
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path"

	"github.com/cilium/hive/cell"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/datapath/sockets"
	"github.com/cilium/cilium/pkg/logging/logfields"
	ciliumnetns "github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/tuple"
	ciliumTypes "github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

var netNSDir = "/var/run/cilium/netns"

type socketCloseStats struct {
	deleted int
	// note: skipped counts sockets that where attempted to be
	// destroyed but already appeared to be in TCP_CLOSE state.
	skipped  int
	failed   int
	cniNetns int
}

func toAddr4(ip net.IP) *netip.Addr {
	ip4 := ip.To4()
	// Ignore ip6 endpoint IPs.
	if ip4 == nil {
		return nil
	}
	addr4 := netip.AddrFrom4([4]byte(ip4[:]))
	return &addr4
}

type socketsActions interface {
	closeSockets(toClose sets.Set[tuple.TupleKey4]) (socketCloseStats, error)
}

// socketManager is a component used by the Agent manager to manage client sockets
// for gw connections.
type socketsManager struct {
	logger *slog.Logger
	health cell.Health
}

func (m *socketsManager) closeSockets(toClose sets.Set[tuple.TupleKey4]) (socketCloseStats, error) {
	var stats socketCloseStats

	if len(toClose) == 0 {
		return stats, nil
	}

	logger := m.logger.With(logfields.Path, netNSDir)
	var errs error

	_, err := os.Stat(netNSDir)
	if err != nil {
		m.health.Degraded(
			"netns directory not found (possibly not mounted?), egwha will not be able to terminate client socket connections upon GW termination",
			err)
		return stats, err
	}

	return stats, fs.WalkDir(os.DirFS(netNSDir), ".", func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			logger.Error("error while walking network namespaces dir",
				logfields.Error, err,
			)
			errs = errors.Join(errs, err)
			return nil
		}

		fi, err := d.Info()
		if err != nil {
			logger.Error("unexpected: could not retrieve netns file info",
				logfields.Error, err,
			)
			return nil
		}

		if fi.Name() != "." && d.IsDir() {
			logger.Warn("unexpected directory found in netns dir")
			return nil
		}

		nsName := d.Name()
		if d.Name() == "." {
			return nil
		}
		logger = m.logger.With(
			logfields.NetNSName, nsName,
			logfields.Path, netNSDir,
		)
		nsFile, err := ciliumnetns.OpenPinned(path.Join(netNSDir, nsName))
		if err != nil {
			logger.Error("could not open netns file to iterate sockets", logfields.Error, err)
			return nil
		}

		stats.cniNetns++

		iterateProto := func(proto uint8) {
			u8p, err := u8proto.FromNumber(proto)
			if err != nil {
				logger.Error("BUG: unexpected protocol used to iterate ns sockets (will skip)", logfields.Error, err)
				return
			}
			logger = logger.With(logfields.Protocol, u8p)
			logger.Debug("searching for protocol sockets to close")

			destroySocket := func(sock *netlink.Socket, err error) error {
				if err != nil {
					logger.Error("failed to receive valid socket data, live socket may "+
						"be missed for egwha socket termination resulting in hanging tcp connections.",
						logfields.Error, err,
					)
					return nil // still continue iteration to attempt next.
				}

				logger := logger.With(
					logfields.SourceIP, sock.ID.Source,
					logfields.SourcePort, sock.ID.SourcePort,
					logfields.DstIP, sock.ID.Destination,
					logfields.DstPort, sock.ID.DestinationPort,
				)
				sourceAddr := toAddr4(sock.ID.Source)
				destAddr := toAddr4(sock.ID.Destination)
				if sourceAddr == nil || destAddr == nil {
					logger.Warn("unexpected nil address in socket data (will skip)")
					return nil
				}

				if _, ok := toClose[tuple.TupleKey4{
					SourceAddr: ciliumTypes.IPv4(sourceAddr.AsSlice()),
					SourcePort: sock.ID.SourcePort,
					DestAddr:   ciliumTypes.IPv4(destAddr.AsSlice()),
					DestPort:   sock.ID.DestinationPort,
					NextHeader: u8p,
				}]; !ok {
					return nil
				}

				logger.Info("closing socket due to unavailable gatewayIP")
				if err := sockets.DestroySocket(slog.Default(), *sock, netlink.Proto(proto), stateFilter); err != nil {
					// Sockets that are already in the TCP_CLOSE state are expected to return ENOENT
					// This does not count towards stats.
					if errors.Is(err, unix.ENOENT) {
						stats.skipped++
						logger.Debug("failed to close socket as it was presumably already in TCP_CLOSE state", logfields.Error, err)
					} else {
						logger.Error("failed to destroy socket", logfields.Error, err)
						stats.failed++
						return nil
					}
				} else {
					stats.deleted++
				}

				return nil
			}

			nsFile.Do(func() error {
				sockets.Iterate(proto, unix.AF_INET, stateFilter, destroySocket)
				return nil
			})
		}

		iterateProto(unix.IPPROTO_TCP)
		iterateProto(unix.IPPROTO_UDP)

		// Explicitly close the netns handle here, preventing underlying fd from
		// become invalidated by gc close hooks while ns iteration is happening.
		nsFile.Close()
		return nil
	})
}

func stateMask(ms ...int) uint32 {
	var out uint32
	for _, m := range ms {
		out |= 1 << m
	}
	return out
}

// stateFilter is a mask of all states we consider for both socket iteration
// and destroys.
// Instead of destroying all states, we make some notable omissions
// which are documented below:
//
//   - TCP_CLOSE: Calls to close a socket in TCP_CLOSE state will
//     result in ENOENT, this is also confusing as it is the same
//     err code returned when a socket that doesn't exist is destroyed.
//
//   - TCP_TIME_WAIT: Socket may enter this state post close/fin-wait states
//     to catch any leftover traffic that may not have arrived yet.
//     This is security reasons, such as as well as avoiding late traffic
//     from entering a new socket bound to the same addr/port.
//     From an egwha perspective, there is also the potential for a race
//     condition where a socket with the same source addr/port created
//     immediately following socket close (i.e. in time_wait), but before
//     the egress-ct entry is purged, may have traffic incorrectly
//     matched via the egress-ct and wrongly sent to a egress-gateway.
var stateFilter = stateMask(
	// Note: The following states emit rst
	// Ref: https://elixir.bootlin.com/linux/v6.12.6/source/net/ipv4/tcp.c#L3228-L3235
	netlink.TCP_ESTABLISHED,
	netlink.TCP_CLOSE_WAIT,
	netlink.TCP_FIN_WAIT1,
	netlink.TCP_FIN_WAIT2,
	netlink.TCP_SYN_RECV,
	// Sockets in syn-recv state are simply removed from
	// request queue and freed in memory.
	// Ref: https://elixir.bootlin.com/linux/v6.12.6/source/net/ipv4/tcp.c#L4878-L4885
	netlink.TCP_NEW_SYN_REC,
	// Sockets in TCP_LISTEN are moved to closing state
	// Ref: https://elixir.bootlin.com/linux/v6.12.6/source/net/ipv4/tcp.c#L4908
	netlink.TCP_CLOSE,
	// Following are handled without any special consideration (i.e. closed):
	netlink.TCP_SYN_SENT,
	// These appear to be handled without special consideration.
	netlink.TCP_CLOSING,
	netlink.TCP_LAST_ACK,
	netlink.TCP_LISTEN,
)
