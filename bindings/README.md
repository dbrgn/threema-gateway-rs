# Language Bindings

This directory contains generated language bindings for the Threema Gateway SDK.

## Prerequisites

Build the FFI shared library:

    cargo build -p threema-gateway-ffi

Build the standalone `uniffi-bindgen` tool (first time only):

    cargo build --manifest-path uniffi-bindgen/Cargo.toml

## Generating Bindings

### Python

    cargo run --manifest-path uniffi-bindgen/Cargo.toml -- \
        generate --library target/debug/libthreema_gateway_ffi.so \
        --language python \
        --out-dir bindings/python/

## Usage

### Python

Make sure the generated shared library (`libthreema_gateway_ffi.so`) is
discoverable (e.g. via `LD_LIBRARY_PATH`) and then import the generated
module:

```python
import asyncio
from threema_gateway_ffi import SimpleApi, Recipient

async def main():
    api = SimpleApi("*MYID123", "mysecret")
    msg_id = await api.send(Recipient.ID(id="ECHOECHO"), "Hello!")
    print(f"Sent message: {msg_id}")

asyncio.run(main())
```
