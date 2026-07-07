// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package migration

import (
	"net/netip"

	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/timestamp"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/u8proto"
)

type ctTimestampConverter struct {
	toSec       timestamp.TimestampConverter
	clockSource *models.ClockSource
}

const bpfMonoScaler = 8

type ctTime uint64

func newCTTimestampConverter() (*ctTimestampConverter, error) {
	clockSource := timestamp.GetClockSourceFromOptions()
	toSec, err := timestamp.NewCTTimeToSecConverter(clockSource)
	if err != nil {
		return nil, err
	}
	return &ctTimestampConverter{
		clockSource: clockSource,
		toSec:       toSec,
	}, nil
}

func (ct *ctTimestampConverter) ctNow() (ctTime, error) {
	now, err := timestamp.GetCTCurTime(ct.clockSource)
	return ctTime(now), err
}

func (ct *ctTimestampConverter) toDuration(ctNow ctTime, ctLifetime uint32) *durationpb.Duration {
	duration := time.Duration(ct.toSec(uint64(ctLifetime))-ct.toSec(uint64(ctNow))) * time.Second
	return durationpb.New(duration)
}

func (ct *ctTimestampConverter) toLifetime(ctNow ctTime, duration *durationpb.Duration) uint32 {
	offset := uint32(duration.GetSeconds())

	// based on bpf_sec_to_mono
	if ct.clockSource.Mode == models.ClockSourceModeJiffies {
		offset = (offset * uint32(ct.clockSource.Hertz)) >> bpfMonoScaler
	}

	return uint32(ctNow) + offset
}

// ctKey is an IP family agnostic interface to read CT key addresses
type ctKey[T any] interface {
	bpf.MapKey
	GetDestAddr() netip.Addr
	GetSourceAddr() netip.Addr
	GetDestPort() uint16
	GetSourcePort() uint16
	GetNextHeader() u8proto.U8proto
	GetFlags() uint8
	*T
}

// ctKeyWritable is an IP family agnostic interface to read and write the CT key addresses
type ctKeyWritable[T any] interface {
	ctKey[T]
	SetDestAddr(addr netip.Addr)
	SetSourceAddr(addr netip.Addr)
}

// ctKey4 wraps ctmap.CtKey4Global to implement the ctKeyWritable interface
type ctKey4 struct {
	ctmap.CtKey4Global
}

func (c *ctKey4) SetSourceAddr(addr netip.Addr) {
	c.SourceAddr.FromAddr(addr)
}

func (c *ctKey4) SetDestAddr(addr netip.Addr) {
	c.DestAddr.FromAddr(addr)
}

// ctKey6 wraps ctmap.CtKey6Global to implement the ctKeyWritable interface
type ctKey6 struct {
	ctmap.CtKey6Global
}

func (c *ctKey6) SetSourceAddr(addr netip.Addr) {
	c.SourceAddr.FromAddr(addr)
}

func (c *ctKey6) SetDestAddr(addr netip.Addr) {
	c.DestAddr.FromAddr(addr)
}
