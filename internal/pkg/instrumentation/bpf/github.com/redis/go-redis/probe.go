// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package redis provides an instrumentation probe for database clients using the
// [database/redis] package.
package go_redis

import (
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"

	"go.opentelemetry.io/auto/internal/pkg/instrumentation/context"
	"go.opentelemetry.io/auto/internal/pkg/instrumentation/kernel"
	"go.opentelemetry.io/auto/internal/pkg/instrumentation/probe"
	"go.opentelemetry.io/auto/internal/pkg/structfield"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 bpf ./bpf/probe.bpf.c

const (
	// pkg is the package being instrumented.
	pkg = "github.com/redis/go-redis/v9"
)

func New(logger *slog.Logger, version string) probe.Probe {
	id := probe.ID{
		SpanKind:        trace.SpanKindClient,
		InstrumentedPkg: pkg,
	}
	return &probe.SpanProducer[bpfObjects, event]{
		Base: probe.Base[bpfObjects, event]{
			ID:     id,
			Logger: logger,
			Consts: []probe.Const{
				probe.StructFieldConst{
					Key: "base_cmd_args_pos",
					ID:  structfield.NewID("github.com/redis/go-redis/v9", "github.com/redis/go-redis/v9", "baseCmd", "args"),
				},
				probe.StructFieldConst{
					Key: "options_db_pos",
					ID:  structfield.NewID("github.com/redis/go-redis/v9", "github.com/redis/go-redis/v9", "Options", "DB"),
				},
				probe.StructFieldConst{
					Key: "options_addr_pos",
					ID:  structfield.NewID("github.com/redis/go-redis/v9", "github.com/redis/go-redis/v9", "Options", "Addr"),
				},
			},
			Uprobes: []*probe.Uprobe{
				{
					Sym:         "github.com/redis/go-redis/v9.(*baseClient).process",
					EntryProbe:  "uprobe_process",
					ReturnProbe: "uprobe_process_Returns",
					FailureMode: probe.FailureModeIgnore,
				},
			},
			SpecFn: loadBpf,
		},
		Version:   version,
		SchemaURL: semconv.SchemaURL,
		ProcessFn: processFn,
	}
}

// event represents an event in a redis command execution
type event struct {
	context.BaseSpanProperties
	Operation [64]byte
	Key       [64]byte
	Address   [64]byte
	Namespace uint64
}

func processFn(e *event) ptrace.SpanSlice {
	spans := ptrace.NewSpanSlice()
	span := spans.AppendEmpty()
	span.SetKind(ptrace.SpanKindClient)
	span.SetStartTimestamp(kernel.BootOffsetToTimestamp(e.StartTime))
	span.SetEndTimestamp(kernel.BootOffsetToTimestamp(e.EndTime))
	span.SetTraceID(pcommon.TraceID(e.SpanContext.TraceID))
	span.SetSpanID(pcommon.SpanID(e.SpanContext.SpanID))
	span.SetFlags(uint32(trace.FlagsSampled))

	if e.ParentSpanContext.SpanID.IsValid() {
		span.SetParentSpanID(pcommon.SpanID(e.ParentSpanContext.SpanID))
	}

	// setting db.system.name as redis
	span.Attributes().PutStr(string(semconv.DBSystemNameKey), "redis")

	// setting db.namespace
	namespace := e.Namespace
	span.Attributes().PutStr(string(semconv.DBNamespaceKey), strconv.FormatUint(namespace, 10))

	// setting db.operation.name attribute and the span name
	operation := strings.ToUpper(unix.ByteSliceToString(e.Operation[:]))
	span.SetName(operation)
	span.Attributes().PutStr(string(semconv.DBOperationNameKey), operation)

	// setting db.query.text constructed using operation and key
	key := unix.ByteSliceToString(e.Key[:])
	query := fmt.Sprintf("%s %s", operation, key)
	span.Attributes().PutStr(string(semconv.DBQueryTextKey), query)

	// setting network.peer.address and network.peer.port using address
	address := unix.ByteSliceToString(e.Address[:])
	if host, portStr, err := net.SplitHostPort(address); err == nil {
		span.Attributes().PutStr(string(semconv.NetworkPeerAddressKey), host)
		if port, err := strconv.Atoi(portStr); err == nil {
			span.Attributes().PutInt(string(semconv.NetworkPeerPortKey), int64(port))
		}
	}

	return spans
}
