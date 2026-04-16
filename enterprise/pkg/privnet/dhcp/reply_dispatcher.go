// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package dhcp

import (
	"encoding/binary"
	"net"
	"slices"

	"github.com/insomniacslk/dhcp/dhcpv4"

	"github.com/cilium/cilium/pkg/lock"
)

type relayKey struct {
	ifindex int
	xid     dhcpv4.TransactionID
	chaddr  string
}

// replyDispatcher is used by the [Server] to dispatch DHCP replies to
// subscribers. Currently the only subscriber is the [broadcastRelay].
type replyDispatcher struct {
	mu      lock.Mutex
	pending map[relayKey][]chan *dhcpv4.DHCPv4
}

func newReplyDispatcher() *replyDispatcher {
	return &replyDispatcher{
		pending: make(map[relayKey][]chan *dhcpv4.DHCPv4),
	}
}

func newRelayKey(ifindex int, msg *dhcpv4.DHCPv4) (relayKey, bool) {
	if ifindex == 0 || msg == nil {
		return relayKey{}, false
	}

	return relayKey{
		ifindex: ifindex,
		xid:     msg.TransactionID,
		chaddr:  msg.ClientHWAddr.String(),
	}, true
}

func (d *replyDispatcher) add(key relayKey, ch chan *dhcpv4.DHCPv4) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.pending[key] = append(d.pending[key], ch)
}

func (d *replyDispatcher) remove(key relayKey, ch chan *dhcpv4.DHCPv4) {
	d.mu.Lock()
	defer d.mu.Unlock()

	chans := d.pending[key]
	for i := range chans {
		if chans[i] != ch {
			continue
		}

		chans = append(chans[:i], chans[i+1:]...)
		if len(chans) == 0 {
			delete(d.pending, key)
		} else {
			d.pending[key] = chans
		}
		return
	}
}

func (d *replyDispatcher) dispatch(ifindex int, msg *dhcpv4.DHCPv4) bool {
	key, ok := newRelayKey(ifindex, msg)
	if !ok {
		return false
	}

	d.mu.Lock()
	chans := slices.Clone(d.pending[key])
	d.mu.Unlock()

	if len(chans) == 0 {
		return false
	}

	for _, ch := range chans {
		select {
		case ch <- msg:
		default:
		}
	}

	return true
}

func decodeRelayIfindexSourceMAC(mac net.HardwareAddr) (int, bool) {
	ifindex := binary.BigEndian.Uint32(mac[2:6])
	if ifindex == 0 {
		return 0, false
	}

	return int(ifindex), true
}
