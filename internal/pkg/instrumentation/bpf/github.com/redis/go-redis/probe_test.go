package go_redis

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/auto/internal/pkg/instrumentation/context"
	"go.opentelemetry.io/auto/internal/pkg/instrumentation/kernel"
	"go.opentelemetry.io/auto/internal/pkg/instrumentation/pdataconv"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
	"go.opentelemetry.io/otel/trace"
)

func TestProbeConvertEvent(t *testing.T) {
	start := time.Unix(0, time.Now().UnixNano()) // No wall clock.
	end := start.Add(1 * time.Second)

	startOffset := kernel.TimeToBootOffset(start)
	endOffset := kernel.TimeToBootOffset(end)

	traceID := trace.TraceID{1}
	spanID := trace.SpanID{1}

	tests := []struct {
		name      string
		event     *event
		wantName  string
		wantAttrs func(ptrace.Span)
	}{
		{
			name: "SET command",
			event: &event{
				BaseSpanProperties: context.BaseSpanProperties{
					StartTime:   startOffset,
					EndTime:     endOffset,
					SpanContext: context.EBPFSpanContext{TraceID: traceID, SpanID: spanID},
				},
				Operation: [64]byte{0x53, 0x45, 0x54},
				Key:       [64]byte{0x74, 0x65, 0x73, 0x74, 0x2d, 0x6b, 0x65, 0x79},
				Address:   [64]byte{0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x3a, 0x36, 0x33, 0x37, 0x39},
				Namespace: 0,
			},
			wantName: "SET",
			wantAttrs: func(span ptrace.Span) {
				pdataconv.Attributes(
					span.Attributes(),
					semconv.DBSystemNameRedis,
					semconv.DBNamespace("0"),
					semconv.DBOperationName("SET"),
					semconv.DBQueryText("SET test-key"),
					attribute.String("network.peer.address", "localhost"),
					attribute.Int("network.peer.port", 6379),
				)
			},
		},
		{
			name: "GET command",
			event: &event{
				BaseSpanProperties: context.BaseSpanProperties{
					StartTime:   startOffset,
					EndTime:     endOffset,
					SpanContext: context.EBPFSpanContext{TraceID: traceID, SpanID: spanID},
				},
				// "GET"
				Operation: [64]byte{0x47, 0x45, 0x54},
				// "test-key"
				Key: [64]byte{0x74, 0x65, 0x73, 0x74, 0x2d, 0x6b, 0x65, 0x79},
				// "localhost:6379"
				Address:   [64]byte{0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x3a, 0x36, 0x33, 0x37, 0x39},
				Namespace: 0,
			},
			wantName: "GET",
			wantAttrs: func(span ptrace.Span) {
				pdataconv.Attributes(
					span.Attributes(),
					semconv.DBSystemNameRedis,
					semconv.DBNamespace("0"),
					semconv.DBOperationName("GET"),
					semconv.DBQueryText("GET test-key"),
					attribute.String("network.peer.address", "localhost"),
					attribute.Int("network.peer.port", 6379),
				)
			},
		},
		{
			name: "GET command with non-zero namespace",
			event: &event{
				BaseSpanProperties: context.BaseSpanProperties{
					StartTime:   startOffset,
					EndTime:     endOffset,
					SpanContext: context.EBPFSpanContext{TraceID: traceID, SpanID: spanID},
				},
				// "GET"
				Operation: [64]byte{0x47, 0x45, 0x54},
				// "test-key"
				Key: [64]byte{0x74, 0x65, 0x73, 0x74, 0x2d, 0x6b, 0x65, 0x79},
				// "localhost:6379"
				Address:   [64]byte{0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x3a, 0x36, 0x33, 0x37, 0x39},
				Namespace: 3,
			},
			wantName: "GET",
			wantAttrs: func(span ptrace.Span) {
				pdataconv.Attributes(
					span.Attributes(),
					semconv.DBSystemNameRedis,
					semconv.DBNamespace("3"),
					semconv.DBOperationName("GET"),
					semconv.DBQueryText("GET test-key"),
					attribute.String("network.peer.address", "localhost"),
					attribute.Int("network.peer.port", 6379),
				)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := processFn(tt.event)
			want := func() ptrace.SpanSlice {
				spans := ptrace.NewSpanSlice()
				span := spans.AppendEmpty()
				span.SetName(tt.wantName)
				span.SetKind(ptrace.SpanKindClient)
				span.SetStartTimestamp(kernel.BootOffsetToTimestamp(startOffset))
				span.SetEndTimestamp(kernel.BootOffsetToTimestamp(endOffset))
				span.SetTraceID(pcommon.TraceID(traceID))
				span.SetSpanID(pcommon.SpanID(spanID))
				span.SetFlags(uint32(trace.FlagsSampled))
				tt.wantAttrs(span)
				return spans
			}()
			assert.Equal(t, want, got)
		})
	}
}
