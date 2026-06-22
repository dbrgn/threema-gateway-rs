//! `UniFFI` bindings for the Threema Gateway SDK.

mod errors;
mod lookup;
mod recipient;
mod simple_api;

uniffi::setup_scaffolding!();

pub use crate::{
    errors::ApiError,
    lookup::{Capabilities, LookupCriterion},
    recipient::{Recipient, RecipientKey},
    simple_api::SimpleApi,
};
