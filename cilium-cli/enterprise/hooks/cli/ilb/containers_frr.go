//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package ilb

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"

	"github.com/docker/docker/api/types/container"
	"k8s.io/apimachinery/pkg/util/sets"
)

type frrContainer struct {
	dockerContainer
}

type frrShowBGPRoutesOut struct {
	Routes map[string][]frrShowBGPRoutePeerOut `json:"routes"`
}

func (r *frrShowBGPRoutesOut) HasRoute(ip netip.Prefix) bool {
	for rip := range r.Routes {
		if netip.MustParsePrefix(rip).Overlaps(ip) {
			return true
		}
	}

	return false
}

func (r *frrShowBGPRoutesOut) HasRouteVia(ip netip.Prefix, peerIPAddr netip.Addr) bool {
	for rip, peers := range r.Routes {
		if netip.MustParsePrefix(rip).Overlaps(ip) {
			for _, checkPeer := range peers {
				for _, nh := range checkPeer.NextHops {
					if netip.MustParseAddr(nh.IP).Compare(peerIPAddr) == 0 {
						return true
					}
				}
			}
		}
	}

	return false
}

type frrShowBGPRoutePeerOut struct {
	PeerID   string                          `json:"peerId"`
	NextHops []frrShowBGPRoutePeerNextHopOut `json:"nexthops"`
}

type frrShowBGPRoutePeerNextHopOut struct {
	IP string `json:"ip"`
}

func (c *frrContainer) vty(ctx context.Context, cmd string) (string, string, error) {
	const vtyshPathLookup = `vtysh_path=""; for path in /bin/vtysh /usr/bin/vtysh /usr/lib/frr/vtysh; do if [ -x "$path" ]; then vtysh_path="$path"; break; fi; done; if [ -z "$vtysh_path" ]; then vtysh_path="$(command -v vtysh 2>/dev/null || true)"; fi; if [ -z "$vtysh_path" ]; then echo "vtysh not found" >&2; exit 127; fi`

	return c.Exec(ctx, fmt.Sprintf(`%s; "$vtysh_path" -c %q`, vtyshPathLookup, cmd))
}

func (c *frrContainer) bgpRoutes(ctx context.Context, afi, safi string) (*frrShowBGPRoutesOut, error) {
	stdout, stderr, err := c.vty(ctx, "show bgp "+afi+" "+safi+" json")
	if err != nil {
		// try to fetch docker logs of frr container to check for frr error
		frrContainerLog, err := c.dockerCli.ContainerLogs(ctx, c.id, container.LogsOptions{
			ShowStdout: true,
			ShowStderr: true,
			Timestamps: true,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to fetch frr docker logs after show bgp routes failed: %w", err)
		}
		io.Copy(os.Stdout, frrContainerLog)

		return nil, fmt.Errorf("failed to show bgp routes: stdout: %s stderr: %s err: %w", stdout, stderr, err)
	}

	out := frrShowBGPRoutesOut{}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		return nil, fmt.Errorf("failed to unmarshal show bgp output: %w", err)
	}

	return &out, nil
}

type ipRouteShowOut []struct {
	Dst string `json:"dst"`
}

func (c *frrContainer) ipRoutes(ctx context.Context, ipv6 bool) (sets.Set[netip.Prefix], error) {
	familyFlag := "-4"
	if ipv6 {
		familyFlag = "-6"
	}

	stdout, stderr, err := c.Exec(ctx, fmt.Sprintf("ip %s -j route show", familyFlag))
	if err != nil {
		return nil, fmt.Errorf("failed to show ip routes: stdout: %s stderr: %s err: %w", stdout, stderr, err)
	}

	out := ipRouteShowOut{}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ip route show output: %w", err)
	}

	prefixes := sets.New[netip.Prefix]()
	for _, r := range out {
		if r.Dst == "default" {
			continue
		}
		if !strings.Contains(r.Dst, "/") {
			if !ipv6 {
				r.Dst += "/32"
			} else {
				r.Dst += "/128"
			}
		}
		p, err := netip.ParsePrefix(r.Dst)
		if err != nil {
			return nil, fmt.Errorf("failed to parse prefix %q: %w", r.Dst, err)
		}
		prefixes.Insert(p)
	}

	return prefixes, nil
}

// EnsureRoute ensures that the given BGP prefix is present in the BGP
// routes and installed in the FRR container.
func (c *frrContainer) EnsureRoute(ctx context.Context, prefix string) error {
	p := netip.MustParsePrefix(prefix)
	family := "ipv4"
	if !p.Addr().Is4() {
		family = "ipv6"
	}

	ribPrefixes, err := c.bgpRoutes(ctx, family, "unicast")
	if err != nil {
		return err
	}

	if !ribPrefixes.HasRoute(p) {
		return fmt.Errorf("prefix %s not found in BGP routes", p)
	}

	fibPrefixes, err := c.ipRoutes(ctx, !p.Addr().Is4())
	if err != nil {
		return err
	}

	if !fibPrefixes.Has(p) {
		return fmt.Errorf("prefix %s not found in FIB routes", p)
	}

	return nil
}

// EnsureRoute ensures that the given BGP prefix is present in the BGP
// routes and installed in the FRR container.
func (c *frrContainer) EnsureRouteVia(ctx context.Context, prefix string, peerIP string) error {
	p := netip.MustParsePrefix(prefix)

	family := "ipv4"
	if !p.Addr().Is4() {
		family = "ipv6"
	}

	peerIPAddr := netip.MustParseAddr(peerIP)

	ribPrefixes, err := c.bgpRoutes(ctx, family, "unicast")
	if err != nil {
		return err
	}

	if !ribPrefixes.HasRouteVia(p, peerIPAddr) {
		return fmt.Errorf("prefix %s via %s not found in BGP routes", p, peerIPAddr)
	}

	fibPrefixes, err := c.ipRoutes(ctx, !p.Addr().Is4())
	if err != nil {
		return err
	}

	if !fibPrefixes.Has(p) {
		return fmt.Errorf("prefix %s not found in FIB routes", p)
	}

	return nil
}
