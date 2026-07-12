# Protobuf generation

`proto/muninn/v1/service.proto` is the source of truth for MuninnDB's gRPC v1
wire contract. The Go message and service files under `proto/gen/go` must be
canonical generator output; handwritten protobuf reflection adapters are not a
supported compatibility path.

Generation is deliberately hosted because this repository does not require a
local `protoc`, `protoc-gen-go`, `protoc-gen-go-grpc`, or Buf installation:

- Buf CLI `1.71.0`, verified by its Linux x86-64 release checksum.
- `bufbuild/buf-action` pinned to the `v1.4.0` commit.
- `buf.build/protocolbuffers/go:v1.36.11`, revision 1.
- `buf.build/grpc/go:v1.6.2`, revision 1.

The `gRPC protobuf contract` workflow runs on the isolated bootstrap branch as
well as pull requests. It generates both Go files, uploads the complete output
as the `canonical-go-stubs` artifact whenever committed files drift, exercises
the real grpc-go default codec over TCP, and fails until the canonical files are
committed. The first bootstrap run is therefore expected to fail the drift gate
while still producing the artifact needed for the replacement commit.
`scripts/generate-proto.sh` exists for maintainers who already have the exact
Buf version; it does not install tools.

The `grpcwire` tests freeze all message field numbers, message kinds and
cardinality, service method names, streaming shapes, and full RPC paths. Any
intentional v1 wire change must update those expectations explicitly and pass
independent compatibility review.

## Go source compatibility gate

Canonical generation preserves protobuf field numbers and RPC paths, but it
changes the exported Go source API that the handwritten files accidentally
defined. Initialisms follow generator naming (`ID` becomes `Id`, `TTL` becomes
`Ttl`, and `OK` becomes `Ok`), and repeated message fields become pointer slices
such as `[]*Association`, `[]*Filter`, and `[]*ActivationItem`.

The in-repository gRPC transport and tests are migrated in this bootstrap.

TODO before this work can be marked ready:

- Inventory every downstream consumer of
  `github.com/scrypster/muninndb/proto/gen/go/muninn/v1`.
- Decide whether a source-compatibility wrapper or a versioned breaking-change
  release note is required.
- Record and independently review the migration plan.
