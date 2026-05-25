package bgpcap

import (
	"errors"
	"io"
	"os"

	"github.com/YutaroHayakawa/bgplay/internal/bgputils"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// BGPCAP file is a file format for storing BGP messages. It is a simple format
// that consists of a header and a series of BGP messages. The header contains
// version number for extensibility. The BGP messages are stored in the same
// format as they are sent over the wire. So that they can be easily parsed by
// BGP implementations.
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   Version (8) |               Reserved (56 bits)             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// |                    BGP Messages (variable)                    |
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//

type File struct {
	f *os.File
	h *HeaderV1
}

type HeaderCommon struct {
	version  uint8
	reserved [7]uint8
}

var (
	HeaderCommonLen = 8

	ErrUnknownVersion = errors.New("unknown version")
)

func (h *HeaderCommon) Deserialize(data []byte) error {
	if len(data) < 8 {
		return io.ErrShortBuffer
	}
	h.version = data[0]
	copy(h.reserved[:], data[1:8])
	return nil
}

type HeaderV1 struct {
	HeaderCommon
}

func (h *HeaderV1) Serialize() []byte {
	data := make([]byte, 8)
	data[0] = 1 // version
	return data
}

func Create(filename string) (*File, error) {
	f, err := os.Create(filename)
	if err != nil {
		return nil, err
	}
	h := &HeaderV1{
		HeaderCommon: HeaderCommon{
			version: 1,
		},
	}
	if _, err := f.Write(h.Serialize()); err != nil {
		f.Close()
		return nil, err
	}
	return &File{f: f, h: h}, nil
}

func Open(filename string) (*File, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, HeaderCommonLen)
	if _, err := f.Read(buf); err != nil {
		f.Close()
		return nil, err
	}

	h := &HeaderCommon{}
	if err := h.Deserialize(buf); err != nil {
		f.Close()
		return nil, err
	}

	ret := &File{f: f}
	switch h.version {
	case 1:
		ret.h = &HeaderV1{HeaderCommon: *h}
	default:
		f.Close()
		return nil, ErrUnknownVersion
	}

	return ret, nil
}

func (f *File) WriteMsg(msg *bgp.BGPMessage) error {
	if f.f == nil {
		return os.ErrClosed
	}
	if msg == nil {
		return nil
	}
	return bgputils.WriteBGPMessage(f.f, msg)
}

func (f *File) ReadMsg() (*bgp.BGPMessage, error) {
	if f.f == nil {
		return nil, os.ErrClosed
	}
	return bgputils.ReadBGPMessage(f.f)
}

func (f *File) Close() error {
	if f.f != nil {
		err := f.f.Close()
		f.f = nil
		return err
	}
	return nil
}
