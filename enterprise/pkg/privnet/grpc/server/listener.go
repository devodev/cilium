//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/cilium/cilium/pkg/node"
)

// netListen is the [net.Listen] function. It can be overridden for testing purposes.
var netListen = net.Listen

// ListenerConfig captures the configuration needed to build a listener factory.
type ListenerConfig struct {
	Port          uint16
	Enabled       bool
	AnnotationKey string
}

// NewListenerFactory returns a ListenerFactory configured for the given port.
func NewListenerFactory(cfg ListenerConfig, lns *node.LocalNodeStore) ListenerFactory {
	if !cfg.Enabled {
		return func(ctx context.Context) ([]net.Listener, error) {
			return nil, nil
		}
	}

	port := strconv.FormatUint(uint64(cfg.Port), 10)

	if cfg.AnnotationKey != "" {
		// Set the node annotation to propagate the gRPC server port.
		lns.Update(func(ln *node.LocalNode) {
			if ln.Annotations == nil {
				ln.Annotations = make(map[string]string)
			}

			ln.Annotations[cfg.AnnotationKey] = port
		})
	}

	return func(ctx context.Context) ([]net.Listener, error) {
		ln, err := lns.Get(ctx)
		if err != nil {
			return nil, fmt.Errorf("retrieving local node: %w", err)
		}

		var listeners []net.Listener

		// Listen to the NodeInternalIP addresses (both IPv4 and IPv6 if available),
		// with a fallback to the NodeExternalIP ones. This matches the symmetric
		// logic to determine the address to use on the client side ([types.NewNode]).
		for _, ip := range []net.IP{ln.GetNodeIP(false), ln.GetNodeIP(true)} {
			if ip != nil {
				lis, err := netListen("tcp", net.JoinHostPort(ip.String(), port))
				if err != nil {
					return nil, err
				}

				listeners = append(listeners, lis)
			}
		}

		if len(listeners) == 0 {
			return nil, errors.New("no valid node IP address found")
		}

		return listeners, nil
	}
}
