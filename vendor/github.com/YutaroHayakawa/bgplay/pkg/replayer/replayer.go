package replayer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/YutaroHayakawa/bgplay/internal/bgputils"
	"github.com/YutaroHayakawa/bgplay/pkg/bgpcap"
)

var errField = "error"

// Replayer is a BGP message replayer that reads BGP messages from a bgpcap
// file and replays them to a BGP peer.
type Replayer struct {
	logger          *slog.Logger
	spec            ReplayerSpec
	peerOpenMsg     *bgp.BGPMessage
	cancelKeepAlive context.CancelFunc

	// KeepAlive and Update messages might be sent in parallel
	connMutex sync.Mutex
	conn      net.Conn
}

// ReplayerSpec is the specification for the Replayer.
type ReplayerSpec struct {
	// PeerAddr is the address of the BGP peer to connect to.
	PeerAddr string
	// PeerPort is the port of the BGP peer to connect to.
	PeerPort uint16
	// FileName is the path to the bgpcap file to read BGP messages from.
	FileName string

	// PostReplayFunc is called after replaying a message to the peer. This
	// is useful for implementing counting or logging of replayed BGP
	// messages. The CLI uses this to print the message to the stdout.
	PostReplayFunc func(msg *bgp.BGPMessage)
}

// New creates a new Replayer instance.
func New(logger *slog.Logger, spec ReplayerSpec) *Replayer {
	return &Replayer{
		logger: logger,
		spec:   spec,
	}
}

// Replay reads BGP messages from the bgpcap file and replays them to the BGP
// peer. It establishes a BGP session with the peer and sends the messages in
// the order they were read from the file.
//
// Once the replay is done, it returns nil. If an error occurs, it returns the
// error. After returning, it takes care of keeping the BGP session alive by
// sending KEEPALIVE messages to the peer at regular intervals. Users are
// responsible for closing the connection by calling the Close method.
func (r *Replayer) Replay() error {
	f, err := bgpcap.Open(r.spec.FileName)
	if err != nil {
		return fmt.Errorf("failed to open bgpcap file %s: %w", r.spec.FileName, err)
	}
	defer f.Close()

	if err := r.establish(f); err != nil {
		return fmt.Errorf("cannot establish BGP session: %w", err)
	}

	if err := r.replayUpdates(f); err != nil {
		return fmt.Errorf("failed to send updates: %w", err)
	}

	r.startKeepAlive()

	return nil
}

func (r *Replayer) establish(f *bgpcap.File) error {
	addr, err := netip.ParseAddr(r.spec.PeerAddr)
	if err != nil {
		return fmt.Errorf("invalid peer address: %w", err)
	}

	conn, err := net.Dial("tcp", netip.AddrPortFrom(addr, r.spec.PeerPort).String())
	if err != nil {
		return fmt.Errorf("failed to connect to peer: %w", err)
	}
	r.conn = conn

	// Read the first message from the file
	msg, err := f.ReadMsg()
	if err != nil {
		return fmt.Errorf("failed to read BGP message from file: %w", err)
	}

	// Check if the message is an OPEN message
	if msg.Header.Type != bgp.BGP_MSG_OPEN {
		return fmt.Errorf("bgpcap file must be started with OPEN message, got %d", msg.Header.Type)
	}

	// Send OPEN message.
	if err = bgputils.WriteBGPMessage(r.conn, msg); err != nil {
		return err
	}
	if r.spec.PostReplayFunc != nil {
		r.spec.PostReplayFunc(msg)
	}

	// Expect peer OPEN
	msg, err = bgputils.ExpectMessage(r.conn, bgp.BGP_MSG_OPEN)
	if err != nil {
		return err
	}
	r.peerOpenMsg = msg

	// Send out KEEPALIVE message to the peer.
	msg = bgp.NewBGPKeepAliveMessage()
	if err = bgputils.WriteBGPMessage(r.conn, msg); err != nil {
		return err
	}

	// Expect peer KEEPALIVE.
	msg, err = bgputils.ExpectMessage(r.conn, bgp.BGP_MSG_KEEPALIVE)
	if err != nil {
		return err
	}

	return nil
}

func (r *Replayer) replayUpdates(f *bgpcap.File) error {
	for {
		msg, err := f.ReadMsg()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("failed to read BGP message from file: %w", err)
		}

		if msg.Header.Type != bgp.BGP_MSG_UPDATE {
			// Skip non-UPDATE messages
			continue
		}

		r.connMutex.Lock()

		// Send UPDATE message to the peer
		if err := bgputils.WriteBGPMessage(r.conn, msg); err != nil {
			r.connMutex.Unlock()
			return fmt.Errorf("failed to send UPDATE message: %w", err)
		}
		if r.spec.PostReplayFunc != nil {
			r.spec.PostReplayFunc(msg)
		}

		r.connMutex.Unlock()
	}
}

func (r *Replayer) startKeepAlive() {
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		r.logger.Info("Start sending KEEPALIVE messages")
		defer r.logger.Info("Stop sending KEEPALIVE messages")

		interval := r.peerOpenMsg.Body.(*bgp.BGPOpen).HoldTime / 3
		for {
			ch := time.After(time.Duration(interval) * time.Second)
			select {
			case <-ctx.Done():
				return
			case <-ch:
			}

			r.connMutex.Lock()

			// Send KEEPALIVE message to the peer
			if err := bgputils.WriteBGPMessage(
				r.conn,
				bgp.NewBGPKeepAliveMessage(),
			); err != nil {
				r.logger.Error("Failed to send KEEPALIVE", errField, err)
				r.connMutex.Unlock()
				return
			}

			r.connMutex.Unlock()
		}
	}()

	r.cancelKeepAlive = cancel
}

// Close closes the connection to the BGP peer
func (r *Replayer) Close() error {
	if r.conn != nil {
		if err := r.conn.Close(); err != nil {
			return fmt.Errorf("failed to close connection: %w", err)
		}
	}
	if r.cancelKeepAlive != nil {
		r.cancelKeepAlive()
	}
	return nil
}
