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
	"encoding/json"
	"fmt"
	"iter"
	"math"
	"slices"
	"sort"

	"github.com/cilium/cilium/pkg/time"
)

// The samplers defined here exists to have access to recent averages
// and quantiles in order to derive a threshold for conditions. These
// are invoked by [Environment.Histogram] or [Environment.Gauge] and
// work under the assumption that these methods are invoked every time
// the condition is evaluated.
//
// The samplers hold a ring buffer of 24 samples to which a sample is
// added every hour. This gives us historical averages with very minimal
// memory usage.

type histogramSampler struct {
	// ring of samples taken every hour.
	samples ring[Metric]

	latest [2]Metric

	next time.Time
}

func newHistogramSampler(now time.Time) *histogramSampler {
	// Keep a ring of 24 "histogram snapshots" to which we push once an hour
	hs := &histogramSampler{}
	hs.samples.init(24)
	hs.next = now
	return hs
}

func (hs *histogramSampler) observe(now time.Time, x Metric) {
	if x.Raw.Histogram == nil && x.Raw.Summary == nil {
		return
	}
	if now.After(hs.next) {
		hs.next = now.Add(time.Hour)
		hs.samples.push(x)
	}
	hs.latest[0], hs.latest[1] = x, hs.latest[0]
}

// Averages returns the 24 hour, 4 hour and 1 hour averages.
// Returns 0.0 if not enough samples exist for the given time period.
func (hs *histogramSampler) Averages() (h24, h4, h1, latest float64) {
	// Do nothing if we have not seen at least 2 samples.
	if hs.latest[0].Raw == nil || hs.latest[1].Raw == nil {
		return
	}

	var currentSum, currentCount float64
	samples := slices.Collect(hs.samples.all())

	getCount := func(x Metric) float64 {
		switch {
		case x.Raw.Histogram != nil:
			if x.Raw.Histogram.GetSampleCountFloat() == 0 {
				return float64(x.Raw.Histogram.GetSampleCount())
			}
			return x.Raw.Histogram.GetSampleCountFloat()
		case x.Raw.Summary != nil:
			return float64(x.Raw.Summary.GetSampleCount())
		default:
			return 0.0
		}
	}
	currentCount = getCount(hs.latest[0])

	getSum := func(x Metric) float64 {
		switch {
		case x.Raw.Histogram != nil:
			return x.Raw.Histogram.GetSampleSum()
		case x.Raw.Summary != nil:
			return float64(x.Raw.Summary.GetSampleSum())
		default:
			return 0.0
		}
	}
	currentSum = getSum(hs.latest[0])

	avg := func(x Metric) float64 {
		count := currentCount - getCount(x)
		if count < 1 {
			return 0.0
		}
		sum := currentSum - getSum(x)
		return sum / count
	}

	if len(samples) == 24 {
		h24 = avg(samples[23])
	}
	if len(samples) >= 4 {
		h4 = avg(samples[3])
	}
	if len(samples) >= 2 {
		h1 = avg(samples[1])
	}

	// The latest average is between the latest two observed samples.
	latest = avg(hs.latest[1])

	return
}

func (hs *histogramSampler) Status() string {
	h24, h4, h1, latest := hs.Averages()
	return fmt.Sprintf("%d/%d (24h:%s 4h:%s 1h:%s 0h:%s)", hs.samples.count, len(hs.samples.ring),
		prettyValue(h24), prettyValue(h4), prettyValue(h1), prettyValue(latest))
}

func (hs *histogramSampler) MarshalJSON() ([]byte, error) {
	var out struct {
		Type  string
		Count int
		HistogramStats
	}
	out.Type = "Histogram"
	out.Count = hs.samples.count
	out.Avg_24h, out.Avg_4h, out.Avg_1h, out.Avg_Latest = hs.Averages()
	out.P50_24h, out.P50_4h, out.P50_1h, out.P50_Latest = hs.Percentiles(0.5)
	out.P90_24h, out.P90_4h, out.P90_1h, out.P90_Latest = hs.Percentiles(0.9)
	out.P99_24h, out.P99_4h, out.P99_1h, out.P99_Latest = hs.Percentiles(0.99)
	return json.Marshal(&out)
}

func (hs *histogramSampler) Percentiles(p float64) (h24, h4, h1, latest float64) {
	// Do nothing if we have not seen at least 2 samples.
	if hs.latest[0].Raw == nil || hs.latest[1].Raw == nil {
		return
	}
	samples := slices.Collect(hs.samples.all())

	getBuckets := func(x Metric) []bucket {
		if x.Raw.Histogram != nil {
			b := x.Raw.Histogram.Bucket
			out := make([]bucket, len(b))
			for i := range b {
				out[i] = bucket{
					cumulativeCount: b[i].GetCumulativeCount(),
					upperBound:      b[i].GetUpperBound(),
				}
			}
			return out
		}
		return nil
	}

	latestBucket := getBuckets(hs.latest[0])

	// Reuse this for the calculations to avoid further allocations.
	latestBucketBuffer := slices.Clone(latestBucket)

	getPercentile := func(x Metric) float64 {
		// Subtract counts from the starting bucket to end up
		// with counts for the target period.
		target := getBuckets(x)
		if target == nil || len(latestBucketBuffer) != len(target) {
			return 0.0
		}
		for i := range latestBucketBuffer {
			latestBucketBuffer[i].cumulativeCount -= target[i].cumulativeCount
		}

		result := getHistogramPercentile(latestBucketBuffer, p)

		// Restore the buffer
		copy(latestBucketBuffer, latestBucket)

		return result
	}

	if len(samples) == 24 {
		h24 = getPercentile(samples[23])
	}
	if len(samples) >= 4 {
		h4 = getPercentile(samples[3])
	}
	if len(samples) >= 2 {
		h1 = getPercentile(samples[1])
	}
	latest = getPercentile(hs.latest[1])

	return
}

type bucket struct {
	cumulativeCount uint64
	upperBound      float64
}

func getHistogramPercentile(buckets []bucket, p float64) float64 {
	if len(buckets) < 1 {
		return 0.0
	}
	if p < 0.0 {
		return math.Inf(-1)
	} else if p > 1.0 {
		return math.Inf(+1)
	}

	totalCount := buckets[len(buckets)-1].cumulativeCount
	if totalCount == 0 {
		return 0.0
	}

	// Find the bucket onto which the quantile falls
	rank := p * float64(totalCount)
	index := sort.Search(
		len(buckets)-1,
		func(i int) bool {
			return float64(buckets[i].cumulativeCount) >= rank
		})

	if index == 0 {
		// Sample in first bucket, interpolate between 0.0..UpperBound within the bucket.
		return buckets[0].upperBound * (rank / float64(buckets[0].cumulativeCount))
	}

	// Return the linearly interpolated value between the upper bounds of the
	// two buckets in between which the quantile falls.
	start := buckets[index-1].upperBound
	end := buckets[index].upperBound
	relativeCount := float64(buckets[index].cumulativeCount - buckets[index-1].cumulativeCount)
	if relativeCount == 0 {
		// No new samples in the next bucket, just return the starting upper bound.
		return start
	}
	relativeRank := rank - float64(buckets[index-1].cumulativeCount)
	return start + (end-start)*(relativeRank/relativeCount)
}

type gaugeSampler struct {
	// ring of samples taken every hour.
	samples ring[float64]

	// keep a running sum&count over observations made in a 1 hour
	// window
	count int
	sum   float64

	next time.Time
}

func newGaugeSampler(now time.Time) *gaugeSampler {
	// Keep a ring of 24 "gauge snapshots" to which we push once an hour
	gs := &gaugeSampler{}
	gs.samples.init(24)
	gs.next = now.Add(time.Hour)
	return gs
}

func (gs *gaugeSampler) observe(now time.Time, x Metric) {
	if x.Raw.Gauge == nil {
		return
	}
	val := x.Raw.Gauge.GetValue()
	if now.After(gs.next) {
		gs.next = now.Add(time.Hour)
		if gs.count == 0 {
			gs.samples.push(val)
		} else {
			gs.samples.push(gs.sum / float64(gs.count))
		}
		gs.sum = 0
		gs.count = 0
	}
	gs.count++
	gs.sum += val
}

// Averages returns the 24 hour, 4 hour and 1 hour averages.
// Returns 0.0 if not enough samples exist for the given time period.
func (gs *gaugeSampler) Averages() (h24, h4, h1, latest float64) {
	samples := slices.Collect(gs.samples.all())
	avg := func(start, end int) float64 {
		sum := float64(0)
		count := end - start + 1
		for i := start; i <= end; i++ {
			sum += samples[i]
		}
		return sum / float64(count)
	}
	if len(samples) == 24 {
		h24 = avg(0, 23)
	}
	if len(samples) >= 4 {
		h4 = avg(0, 3)
	}
	if len(samples) >= 2 {
		h1 = avg(0, 1)
	}
	if gs.count > 0 {
		latest = gs.sum / float64(gs.count)
	}
	return
}

func (gs *gaugeSampler) Status() string {
	h24, h4, h1, latest := gs.Averages()
	return fmt.Sprintf("%d/%d (24h:%s 4h:%s 1h:%s 0h:%s)", gs.samples.count, len(gs.samples.ring),
		prettyValue(h24), prettyValue(h4), prettyValue(h1), prettyValue(latest))
}

func (gs *gaugeSampler) MarshalJSON() ([]byte, error) {
	var out struct {
		Type  string
		Count int
		GaugeStats
	}
	out.Type = "Gauge"
	out.Count = gs.samples.count
	out.Avg_24h, out.Avg_4h, out.Avg_1h, out.Avg_Latest = gs.Averages()
	return json.Marshal(&out)
}

type counterSampler struct {
	// ring of samples taken every hour.
	samples ring[float64]

	// Keep the last count observed by the sampler.
	count float64
	next  time.Time
}

func newCounterSampler(now time.Time) *counterSampler {
	// Keep a ring of 24 "counter snapshots" to which we push once an hour
	cs := &counterSampler{}
	cs.samples.init(24)
	cs.next = now.Add(time.Hour)
	return cs
}

func (cs *counterSampler) observe(now time.Time, x Metric) {
	if x.Raw.Counter == nil {
		return
	}
	val := x.Raw.Counter.GetValue()
	if now.After(cs.next) {
		cs.next = now.Add(time.Hour)
		cs.samples.push(cs.count)
	}
	cs.count = val
}

// Increments return the increments on counter metric over last 24, 4, 1 hours.
func (cs *counterSampler) Increments() (h24, h4, h1, latest int64) {
	samples := slices.Collect(cs.samples.all())
	if len(samples) == 24 {
		h24 = int64(cs.count - samples[23])
	} else {
		h24 = int64(cs.count)
	}
	if len(samples) >= 4 {
		h4 = int64(cs.count - samples[3])
	} else {
		h4 = int64(cs.count)
	}
	if len(samples) >= 2 {
		h1 = int64(cs.count - samples[1])
	} else {
		h1 = int64(cs.count)
	}
	if len(samples) > 0 {
		latest = int64(cs.count - samples[0])
	} else {
		latest = int64(cs.count)
	}
	return
}

func (cs *counterSampler) Status() string {
	h24, h4, h1, latest := cs.Increments()
	return fmt.Sprintf("%d/%d (24h:%d 4h:%d 1h:%d 0h:%d)",
		cs.samples.count, len(cs.samples.ring),
		h24, h4, h1, latest)
}

func (cs *counterSampler) MarshalJSON() ([]byte, error) {
	var out struct {
		Type  string
		Count int
		CounterStats
	}
	out.Type = "Counter"
	out.Count = cs.samples.count
	out.Count_24h, out.Count_4h, out.Count_1h, out.Count_Latest = cs.Increments()
	return json.Marshal(&out)
}

type ring[T any] struct {
	ring  []T
	count int
	pos   int
}

func (r *ring[T]) init(n int) {
	r.ring = make([]T, n)
	r.pos = 0
	r.count = 0
}

func (r *ring[T]) push(x T) {
	r.ring[r.pos] = x
	r.pos = (r.pos + 1) % len(r.ring)
	if r.count < len(r.ring) {
		r.count++
	}
}

// all iterates through the elements from newest (last push()'d) to oldest.
func (r *ring[T]) all() iter.Seq[T] {
	return func(yield func(T) bool) {
		pos := r.pos - 1
		if pos < 0 {
			pos = len(r.ring) - 1
		}
		for range r.count {
			if !yield(r.ring[pos]) {
				return
			}
			pos = pos - 1
			if pos < 0 {
				pos = len(r.ring) - 1
			}
		}
	}
}
