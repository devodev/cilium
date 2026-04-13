//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package diagnostics

import (
	"math"
	"slices"
	"testing"

	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/time"
)

func TestHistogramSampler(t *testing.T) {
	const interval = 5 * time.Minute
	var now time.Time
	sampler := newHistogramSampler(now)

	// Without samples we get 0.0
	avg24h, avg4h, avg1h, avgLatest := sampler.Averages()
	assert.Zero(t, avg24h)
	assert.Zero(t, avg4h)
	assert.Zero(t, avg1h)
	assert.Zero(t, avgLatest)

	f := func(v float64) *float64 { return &v }
	pi := func(v float64) *uint64 { x := uint64(v); return &x }

	count := 0.0
	count2 := 0.0
	count5 := 0.0
	sum := 0.0

	buckets := func(x float64) []*dto.Bucket {
		if x <= 5.0 {
			count5++
		}
		if x <= 2.0 {
			count2++
		}
		return []*dto.Bucket{
			{
				CumulativeCount: pi(count2),
				UpperBound:      f(2.0),
			},
			{
				CumulativeCount: pi(count5),
				UpperBound:      f(5.0),
			},
			{
				CumulativeCount: pi(count),
				UpperBound:      f(10.0),
			},
		}

	}

	feed := func(hours int, x float64, asFloat bool) {
		for range int((time.Duration(hours) * time.Hour) / interval) {
			count++
			sum += x
			hs := &dto.Histogram{
				SampleCount: pi(count),
				SampleSum:   f(sum),
				Bucket:      buckets(x),
			}
			if asFloat {
				hs.SampleCountFloat = f(count)
			}
			sampler.observe(now, Metric{
				Name:  "foo",
				Value: 0,
				Raw:   &dto.Metric{Histogram: hs},
			})
			now = now.Add(interval + time.Second)
		}
	}

	feed(21, 8.0, true) // 21 hours of ~8.0
	feed(3, 4.0, false) // 4 hours of ~4.0
	feed(2, 1.0, true)  // 2 hours of ~1.0

	avg24h, avg4h, avg1h, avgLatest = sampler.Averages()

	expected24h := (19*8.0 + 3*4.0 + 2*1.0) / 24.0
	assert.Less(t, math.Abs(expected24h-avg24h), 0.1, "24h %f %f", expected24h, avg24h)

	expected4h := (2*4.0 + 2*1.0) / 4.0
	assert.Less(t, math.Abs(expected4h-avg4h), 0.1, "4h %f %f", expected4h, avg4h)

	expected1h := 1.0
	assert.Less(t, math.Abs(expected1h-avg1h), 0.1, "1h %f %f", expected1h, avg1h)

	assert.Equal(t, 1.0, avgLatest, "latest")

	p50_24h, p50_4h, p50_1h, p50_latest := sampler.Percentiles(0.5)
	// For percentiles this test uses 3 buckets with upper bounds 2.0, 5.0 and 10.0.
	// Compare that we're somewhat close to the averages.
	assert.Less(t, math.Abs(p50_24h-expected24h), 1.0)
	assert.Less(t, math.Abs(p50_4h-expected4h), 1.0)
	assert.Less(t, math.Abs(p50_1h-expected1h), 0.5)
	assert.Less(t, math.Abs(p50_latest-expected1h), 0.5)
}

func TestGaugeSampler(t *testing.T) {
	const interval = 5 * time.Minute
	var now time.Time
	sampler := newGaugeSampler(now)

	// Without samples we get 0.0
	avg24h, avg4h, avg1h, avgLatest := sampler.Averages()
	assert.Zero(t, avg24h)
	assert.Zero(t, avg4h)
	assert.Zero(t, avg1h)
	assert.Zero(t, avgLatest)

	f := func(v float64) *float64 { return &v }

	feed := func(hours int, x float64) {
		samplesPerHour := int((time.Duration(hours) * time.Hour) / interval)
		for range samplesPerHour {
			sampler.observe(now, Metric{
				Name:  "foo",
				Value: 0,
				Raw: &dto.Metric{
					Gauge: &dto.Gauge{
						Value: f(x),
					},
				},
			})
			now = now.Add(interval + time.Second)
		}
	}

	feed(21, 8.0) // 21 hours of ~8.0
	feed(3, 4.0)  // 3 hours of ~4.0
	feed(2, 1.0)  // 2 hour of ~1.0 (must do >1h to push it in)

	avg24h, avg4h, avg1h, avgLatest = sampler.Averages()

	expected24h := (20*8.0 + 3*4.0 + 1.0) / 24.0
	assert.Less(t, math.Abs(expected24h-avg24h), 0.1, "24h %f %f", expected24h, avg24h)

	expected4h := (3*4.0 + 1.0) / 4.0
	assert.Less(t, math.Abs(expected4h-avg4h), 0.1, "4h %f %f", expected4h, avg4h)

	// The 1h average is the average between the last two samples, e.g. one taken
	// ~2h ago and ~1h ago.
	expected1h := (4.0 + 1.0) / 2.0
	assert.Less(t, math.Abs(expected1h-avg1h), 0.1, "1h %f %f", expected1h, avg1h)

	assert.Equal(t, 1.0, avgLatest, "latest")
}

func TestCounterSampler(t *testing.T) {
	now := time.Now()
	sampler := newCounterSampler(now)
	now = now.Add(1 * time.Second)

	f := func(v float64) *float64 { return &v }

	val := 0.0
	feed := func(hours int, x float64) {
		for range hours {
			val += x
			sampler.observe(now, Metric{
				Name:  "foo",
				Value: val,
				Raw:   &dto.Metric{Counter: &dto.Counter{Value: f(val)}},
			})
			now = now.Add(time.Hour + time.Second)
		}
	}

	verifyCounterIncrements := func(countH24, countH4, countH1, countLatest int64) {
		h24, h4, h1, latest := sampler.Increments()
		assert.Equal(t, countH24, h24)
		assert.Equal(t, countH4, h4)
		assert.Equal(t, countH1, h1)
		assert.Equal(t, countLatest, latest)
	}

	// Non-counter observations should be ignored.
	sampler.observe(now, Metric{
		Name: "foo",
		Raw:  &dto.Metric{Gauge: &dto.Gauge{Value: f(999.0)}},
	})
	assert.Equal(t, float64(0), sampler.count)
	verifyCounterIncrements(0, 0, 0, 0)

	feed(21, 8.0)
	verifyCounterIncrements(168, 32, 16, 8)

	feed(3, 4.0)
	verifyCounterIncrements(180, 20, 8, 4)

	feed(2, 1.0)
	verifyCounterIncrements(166, 10, 2, 1)

	feed(1, 5.0)
	verifyCounterIncrements(163, 11, 6, 5)
}

func TestRing(t *testing.T) {
	var r ring[int]
	r.init(5)
	xs := slices.Collect(r.all())
	assert.Equal(t, 0, r.count)
	assert.Empty(t, xs)
	for i := range 20 {
		r.push(i)
	}
	xs = slices.Collect(r.all())
	assert.Len(t, xs, 5)
	assert.Equal(t, []int{19, 18, 17, 16, 15}, xs)
	assert.Equal(t, 5, r.count)
}
