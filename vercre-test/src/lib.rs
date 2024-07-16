//! # [OpenID for Verifiable Credential Issuance]

mod builder;
mod provider;
mod simple;

use openid::endpoint::{ClientMetadata, IssuerMetadata, ServerMetadata, StateManager, Subject};
use proof::signature::Signer;

/// Test request.
#[derive(Clone, Debug, Default)]
pub struct TestRequest {
    /// Return OK.
    pub return_ok: bool,
}

/// Test response.
pub struct TestResponse {}

/// Issuer Provider trait.
pub trait IssuerProvider:
    ClientMetadata + IssuerMetadata + ServerMetadata + Subject + StateManager + Signer + Clone
{
}
