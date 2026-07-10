# Threema Gateway SDK for Python

Official Python bindings for the [Threema Gateway](https://gateway.threema.ch/)
SDK, generated from the Rust SDK with [UniFFI](https://mozilla.github.io/uniffi-rs/)
and packaged as a native wheel with [maturin](https://www.maturin.rs/).

The package ships a compiled extension, so no Rust toolchain is required to
install it:

```bash
pip install threema-gateway
```

## Usage

```python
import asyncio
from threema_gateway import ApiError, Recipient, SimpleApi, ThreemaId


async def main():
    # ThreemaId(...) validates the input once and raises ApiError.InvalidThreemaId
    # on a wrong length or invalid characters. Once constructed, the value can be
    # passed to API methods without re-validation.
    sender = ThreemaId("*MYID123")
    recipient = ThreemaId("ECHOECHO")

    api = SimpleApi(sender, "mysecret")

    try:
        msg_id = await api.send(Recipient.ID(id=recipient), "Hello!")
        print(f"Sent message: {msg_id}")
    except ApiError.NoCredits:
        print("Gateway account is out of credits")
    except ApiError.RateLimitReached:
        print("Rate limited; back off and retry")
    except ApiError.Transport as e:
        print(f"Network problem: {e.message}")
    except ApiError as e:
        # Catch-all for variants not handled above.
        print(f"API error: {e}")


asyncio.run(main())
```

### Calling from non-asyncio threads

The bindings run async calls on the asyncio event loop of the thread that
issued the call. If you call into the SDK from a thread that does not have an
event loop set (e.g. inside `loop.run_in_executor`, or from a worker thread the
SDK didn't create), register the loop explicitly once at start-up:

```python
import asyncio
from threema_gateway import uniffi_set_event_loop

uniffi_set_event_loop(asyncio.get_event_loop())
```

For the typical `asyncio.run(main())` case above, this is not needed.

## Building from source

End users don't need this — `pip install threema-gateway` installs a
precompiled wheel. Build it yourself only for an unsupported platform or for
local development. You need a Rust toolchain plus two tools:

1. **maturin** - the build backend:

   ```bash
   cargo install maturin   # or: pipx install maturin / uv tool install maturin
   ```

2. **uniffi-bindgen** on your `PATH` - maturin shells out to it to generate the
   Python module. Install _this repository's_ pinned copy so its UniFFI version
   matches the crate; a mismatch builds fine but fails at import with a checksum
   error:

   ```bash
   cargo install --path uniffi-bindgen --locked   # run from the repository root
   ```

   maturin has no option to point at the binary by path; it resolves the bare
   command `uniffi-bindgen` through `PATH`. To avoid a global install, build the
   pinned binary and put only its directory on `PATH` for the build command:

   ```bash
   cargo build --release --manifest-path uniffi-bindgen/Cargo.toml
   export PATH="$PWD/uniffi-bindgen/target/release:$PATH"   # from the repository root
   ```

Then build a wheel from this directory:

```bash
cd bindings/python
maturin build --release   # writes target/wheels/threema_gateway-*.whl
```

Or, for a development install into the active virtualenv:

```bash
cd bindings/python
python3 -m venv .venv && . .venv/bin/activate
maturin develop --release   # add --uv if you use a uv-managed venv
```

The wheel is tagged `py3-none-<platform>`: Python-version-agnostic (the bindings
use `ctypes`, not the CPython API) but specific to the build machine's OS, libc
and architecture.

## License

Licensed under either of [MIT](https://opensource.org/licenses/MIT) or
[Apache-2.0](https://opensource.org/licenses/Apache-2.0) at your option.
