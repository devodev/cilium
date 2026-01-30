// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package printer

import (
	"bytes"
	"fmt"
	"testing"

	observerpb "github.com/cilium/cilium/api/v1/observer"
	"github.com/stretchr/testify/assert"
)

func TestTerminalEscaperWriter(t *testing.T) {
	colorer := newColorer("always")
	allowedSequences := colorer.sequencesStaticSlice()
	builder := newTerminalEscaperBuilder(allowedSequences)

	testCases := []struct {
		name   string
		format string
		args   []any
		want   string
	}{
		{name: "control", args: []any{"\x1b"}, want: "^["},
		{name: "control", args: []any{"\033"}, want: "^["},
		{name: "carriage return", args: []any{"\r"}, want: "\\r"},
		{name: "both", args: []any{"\x1b \r"}, want: "^[ \\r"},
		{name: "formatted args", format: "%d%s%d%s%d", args: []any{1, "\x1b", 3, "\r", 5}, want: "1^[3\\r5"},
		{name: "formatted args split sequence", format: "%s%s", args: []any{"\\", "x1b"}, want: "\\x1b"},
		{name: "formatted args split sequence", format: "%s%s", args: []any{"\\", "033"}, want: "\\033"},
		{
			name: "allowed colors",
			args: []any{
				colorer.red.Sprint("red"),
				colorer.green.Sprint("green"),
				colorer.blue.Sprint("blue"),
				colorer.cyan.Sprint("cyan"),
				colorer.magenta.Sprint("magenta"),
				colorer.yellow.Sprint("yellow"),
			},
			want: "\x1b[31mred\x1b[0m\x1b[32mgreen\x1b[0m\x1b[34mblue\x1b[0m\x1b[36mcyan\x1b[0m\x1b[35mmagenta\x1b[0m\x1b[33myellow\x1b[0m",
		},
	}

	for idx, tc := range testCases {
		t.Run(fmt.Sprintf("%d.%s", idx, tc.name), func(t *testing.T) {
			var buf bytes.Buffer
			tew := builder.NewWriter(&buf)
			if tc.format != "" {
				tew.Printf(tc.format, tc.args...)
			} else {
				tew.Print(tc.args...)
			}
			got := buf.String()
			assert.Equal(t, tc.want, got)
		})
	}
}

func BenchmarkTerminalEscaperWriter(b *testing.B) {
	var buf bytes.Buffer
	p := New(Writer(&buf), Dict(), WithColor("always"))
	res := &observerpb.GetFlowsResponse{
		ResponseTypes: &observerpb.GetFlowsResponse_Flow{Flow: &f},
	}

	b.Run("terminalEscapeWriter=without", func(b *testing.B) {
		p.writerBuilder = &dummyWriterBuilder{}
		b.ReportAllocs()
		for b.Loop() {
			buf.Reset()
			p.WriteProtoFlow(res)
		}
	})
	b.Run("terminalEscapeWriter=with-static-slice", func(b *testing.B) {
		p.writerBuilder = newTerminalEscaperBuilder(p.color.sequencesStaticSlice())
		b.Logf("sequences: %v (static)", p.color.sequencesStaticSlice())
		b.ReportAllocs()
		for b.Loop() {
			buf.Reset()
			p.WriteProtoFlow(res)
		}
	})
	b.Run("terminalEscapeWriter=with", func(b *testing.B) {
		p.writerBuilder = newTerminalEscaperBuilder(p.color.sequences())
		b.Logf("sequences: %v", p.color.sequences())
		b.ReportAllocs()
		for b.Loop() {
			buf.Reset()
			p.WriteProtoFlow(res)
		}
	})
}
