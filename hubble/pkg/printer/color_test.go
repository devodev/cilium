package printer

import (
	"testing"
)

func BenchmarkColorerSequences(b *testing.B) {
	c := New()
	for b.Loop() {
		_ = c.color.sequences()
	}
}

func BenchmarkColorerSequencesStaticSlice(b *testing.B) {
	c := New()
	for b.Loop() {
		_ = c.color.sequencesStaticSlice()
	}
}
