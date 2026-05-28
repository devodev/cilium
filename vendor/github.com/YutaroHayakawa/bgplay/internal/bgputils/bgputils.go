package bgputils

import (
	"fmt"
	"io"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

type NotificationError struct {
	code bgp.NotificationErrorCode
}

func (e *NotificationError) Error() string {
	return "received notification: " + e.code.String()
}

func NewNotificationError(notif *bgp.BGPNotification) error {
	return &NotificationError{
		code: bgp.NewNotificationErrorCode(notif.ErrorCode, notif.ErrorSubcode),
	}
}

func MaybeNotificationError(msg *bgp.BGPMessage) (*bgp.BGPMessage, error) {
	notif, ok := msg.Body.(*bgp.BGPNotification)
	if !ok {
		return msg, nil
	}
	return nil, NewNotificationError(notif)
}

func ReadBGPMessage(r io.Reader) (*bgp.BGPMessage, error) {
	hdrBuf := make([]byte, bgp.BGP_HEADER_LENGTH)
	if _, err := io.ReadFull(r, hdrBuf); err != nil {
		return nil, fmt.Errorf("failed to read BGP header: %w", err)
	}
	hdr := &bgp.BGPHeader{}
	if err := hdr.DecodeFromBytes(hdrBuf); err != nil {
		return nil, fmt.Errorf("failed to decode BGP header: %w", err)
	}
	bodyBuf := make([]byte, hdr.Len-bgp.BGP_HEADER_LENGTH)
	if _, err := io.ReadFull(r, bodyBuf); err != nil {
		return nil, fmt.Errorf("failed to read BGP body: %w", err)
	}
	msg, err := bgp.ParseBGPBody(hdr, bodyBuf)
	if err != nil {
		return nil, fmt.Errorf("failed to parse BGP message: %w", err)
	}
	return msg, nil
}

func ExpectMessage(r io.Reader, msgType int) (*bgp.BGPMessage, error) {
	msg, err := ReadBGPMessage(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read BGP message: %w", err)
	}
	if msg.Header.Type != uint8(msgType) {
		return MaybeNotificationError(msg)
	}
	return msg, nil
}

func WriteBGPMessage(w io.Writer, msg *bgp.BGPMessage) error {
	buf, err := msg.Serialize()
	if err != nil {
		return fmt.Errorf("failed to serialize BGP message: %w", err)
	}
	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("failed to write BGP message: %w", err)
	}
	return nil
}

func PrintMessage(w io.Writer, m *bgp.BGPMessage) {
	switch b := m.Body.(type) {
	case *bgp.BGPOpen:
		fmt.Fprintf(w, "BGP Open:\n")
		fmt.Fprintf(w, "  Version: %d\n", b.Version)
		fmt.Fprintf(w, "  MyAS: %d\n", b.MyAS)
		fmt.Fprintf(w, "  HoldTime: %d\n", b.HoldTime)
		fmt.Fprintf(w, "  RouterID: %s\n", b.ID)
		fmt.Fprintf(w, "  Capabilities:\n")
		for _, opt := range b.OptParams {
			capOpt, ok := opt.(*bgp.OptionParameterCapability)
			if !ok {
				continue
			}
			fmt.Fprintf(w, "    Option Capability:\n")
			for _, c := range capOpt.Capability {
				fmt.Fprintf(w, "        %s\n", c.Code().String())
			}
		}

	case *bgp.BGPUpdate:
		isEoR, family := b.IsEndOfRib()
		if !isEoR {
			fmt.Fprintf(w, "BGP Update:\n")
			fmt.Fprintf(w, "  Updated Routes:\n")
			for _, prefix := range b.NLRI {
				fmt.Fprintf(w, "    %s\n", prefix)
			}
			fmt.Fprintf(w, "  Withdrawn Routes:\n")
			for _, prefix := range b.WithdrawnRoutes {
				fmt.Fprintf(w, "    %s\n", prefix)
			}
			fmt.Fprintf(w, "  Path Attributes:\n")
			for _, attr := range b.PathAttributes {
				fmt.Fprintf(w, "    %s\n", attr)
			}
			fmt.Fprintf(w, "  Path Attribute Flags:\n")
		} else {
			fmt.Fprintf(w, "BGP Update (End of RIB):\n")
			fmt.Fprintf(w, "  Family: %s\n", family)
		}
	}
}
