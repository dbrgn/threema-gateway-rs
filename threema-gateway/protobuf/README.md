# Protocol Buffers

This directory contains the Protocol Buffer definitions used by the
`threema-gateway` crate.

## Structure

- `csp-e2e.proto` -- Protocol Buffer definitions for chat server protocol
  end-to-end messages.
- `codegen/` -- Standalone helper crate that generates Rust bindings from the
  `.proto` files.

## Regenerating Bindings

The generated Rust bindings are checked into the repository at
`src/protobuf/csp_e2e.rs`. Whenever a `.proto` file is modified, the bindings
must be regenerated:

    cd protobuf/codegen
    cargo run

This will overwrite `src/protobuf/csp_e2e.rs` with freshly generated code.
Commit the updated bindings alongside the `.proto` changes.
