# zopp-proto

gRPC protocol definitions for zopp.

## How it works

The `build.rs` script runs at compile time and uses `tonic-prost-build` to generate Rust code from `proto/zopp.proto`. The generated code is automatically included via `tonic::include_proto!("zopp")`.

## Modifying the proto file

1. Edit `proto/zopp.proto`
2. Run `cargo build -p zopp-proto`
3. Generated Rust code is automatically updated

## Using in other crates

```rust
use zopp_proto::{JoinRequest, JoinResponse, ZoppServiceClient, ZoppServiceServer};
```

The generated code includes:
- Message types (requests/responses)
- `ZoppServiceClient` for client-side usage
- `ZoppServiceServer` for server-side implementation

