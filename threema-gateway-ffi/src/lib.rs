//! `UniFFI` bindings for the Threema Gateway SDK.
//!
//! # Expanding the bindings
//!
//! Notes for future contributors adding to the FFI surface:
//!
//! ## Async runtime
//!
//! All async methods on exported objects are polled inside a tokio runtime context via
//! `#[uniffi::export(async_runtime = "tokio")]`. Apply the same attribute to any new exported
//! `impl` block whose methods touch `reqwest` or otherwise need a tokio context - without it,
//! polling from a non-tokio thread (e.g. Python's asyncio loop) panics with
//! "there is no reactor running".
//!
//! ## Async traits - pin-locked caveat
//!
//! `UniFFI` 0.31.2 does NOT propagate `async_runtime = "tokio"` to async methods on
//! foreign-implemented traits (`uniffi-rs#2576`). A fix is on uniffi's `main` (CHANGELOG
//! "Unreleased": traits get their FFI scaffolding wrapped in `async_compat::Compat`) but
//! has not been released as of 0.31.2.
//!
//! Until uniffi is bumped past the fix, async trait methods must wrap their bodies in
//! `async_compat::Compat::new(...)` manually, e.g.:
//!
//! ```ignore
//! async fn on_message(&self, msg: IncomingMessage) -> Result<(), ApiError> {
//!     async_compat::Compat::new(async move { /* reqwest calls here */ }).await
//! }
//! ```
//!
//! When uniffi is bumped, remove the manual wrappers.
//!
//! ## Foreign-language callback traits and Swift 6 `Sendable`
//!
//! `UniFFI` ≥ 0.29.1 marks generated Swift protocols as `Sendable`. If we introduce a
//! foreign-implemented trait (e.g. for incoming-message callbacks), Swift 6 consumers
//! with strict concurrency enabled must mark their conforming class `@unchecked Sendable`
//! or arrange for actual `Sendable` correctness. Surface this in the README example for
//! the trait when it lands, then remove this note.
//!
//! ## Regenerating bindings
//!
//! Every change to the FFI surface (new method, signature change, new variant) changes
//! the per-function checksums embedded on both sides. The checked-in Python file in
//! `bindings/python/` must be regenerated, otherwise foreign-side import fails at runtime
//! with a checksum mismatch - `cargo check` will not catch this.

mod errors;
mod lookup;
mod recipient;
mod simple_api;
mod threema_id;

uniffi::setup_scaffolding!();

pub use crate::{
    errors::ApiError,
    lookup::{Capabilities, LookupCriterion},
    recipient::{Recipient, RecipientKey},
    simple_api::SimpleApi,
    threema_id::ThreemaId,
};
