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
from threema_gateway_ffi import ApiError, Recipient, SimpleApi

async def main():
    # The constructor parses the Threema ID and raises ApiError.InvalidThreemaId
    # if the ID is malformed (wrong length, invalid characters).
    api = SimpleApi("*MYID123", "mysecret")

    try:
        msg_id = await api.send(Recipient.ID(id="ECHOECHO"), "Hello!")
        print(f"Sent message: {msg_id}")
    except ApiError.NoCredits:
        print("Gateway account is out of credits")
    except ApiError.RateLimitReached:
        print("Rate limited; back off and retry")
    except ApiError.InvalidThreemaId as e:
        print(f"Bad recipient ID: {e.message}")
    except ApiError.Transport as e:
        print(f"Network problem: {e.message}")
    except ApiError as e:
        # Catch-all for variants not handled above.
        print(f"API error: {e}")

asyncio.run(main())
```

#### Calling from non-asyncio threads

The bindings run async calls on the asyncio event loop of the thread that
issued the call. If you call into the SDK from a thread that does not have
an event loop set (e.g. inside `loop.run_in_executor`, or from a worker
thread the SDK didn't create), register the loop explicitly once at
start-up:

```python
import asyncio
from threema_gateway_ffi import uniffi_set_event_loop

uniffi_set_event_loop(asyncio.get_event_loop())
```

For the typical `asyncio.run(main())` case above, this is not needed.
