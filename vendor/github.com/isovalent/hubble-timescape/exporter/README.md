# Timescape exporter

This module provides a reusable gRPC client for the Timescape ingestion API. It
supports direct typed batches and bounded internal batching without exposing
gRPC messages through either export method.

Use `Exporter` when the caller already owns a batch:

```go
client, err := exporter.NewExporter(log, target)
if err != nil {
	return err
}
go client.Run(ctx)

batch := exporter.NewFlowBatch(flows)
if err := client.Export(ctx, batch); err != nil {
	return err
}
```

Use `BatchingExporter` for per-event admission:

```go
client, err := exporter.NewBatchingExporter(
	log,
	target,
	exporter.DefaultBatchingConfig(),
)
if err != nil {
	return err
}
go client.Run(ctx)

event := exporter.NewFlowEvent(flow)
if err := client.Export(ctx, event); err != nil {
	return err
}
```

Constructors do not copy protobuf messages, copy batch slices, scan rows, or
perform semantic validation. Callers must keep admitted messages immutable. A
successful direct `Export` consumes its batch; capacity, stopped, and context
rejections leave it reusable. An `Event` remains reusable across batching
exporters after admission.

`IngestModeAuto` uses reflection to prefer `IngestBatch` and falls back to the
deprecated flow-only `Ingest` endpoint when required. `IngestModeBatch` skips
reflection. `IngestModeSingle` remains available only for migration.

Timescape API v1.19 currently exposes only the `flow_batch` ingestion arm. A
new arm adds a typed event constructor, a typed batch constructor, and private
accumulation and wire mapping inside this module. The two `Export` method
signatures and existing consumers do not change. Cross-family isolation can be
exercised only when the API exposes its first additional batch arm and must be
covered by that change.

## Dependency compatibility

Timescape API v1.19 references protobuf types from the enterprise Cilium
module. Go does not propagate `replace` directives to consumers. A consumer
whose main module is not the Isovalent Cilium module must mirror the exporter
module's replacement until the API dependency is removed:

```go
replace github.com/cilium/cilium => github.com/isovalent/cilium v1.19.5-cee.1
```

## Performance characteristics

Event and batch construction are constant-time and allocation-free when the
values do not otherwise escape. The batching path uses a bounded typed MPSC
channel and a single owner per event family, preserving per-family FIFO without
boxing events or cloning protobuf messages.

Each detached batch currently allocates a new typed slice. The slice is not
pooled because gRPC permits tracing and stats handlers to retain sent messages
lazily; recycling it after `SendMsg` would risk mutating an in-flight request.
Under highly concurrent producers, bounded-channel synchronization is the
remaining exporter-controlled contention point.

Run the permanent microbenchmarks with:

```console
GOWORK=off go test -run '^$' -bench . -benchmem -count 5 -cpu 1,2,4,8 ./...
```
