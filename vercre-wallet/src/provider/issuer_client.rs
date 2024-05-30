//! # Issuer Client provider
//!
//! This provider allows the wallet to interact with an issuer's services that are compliant with
//! OpenID for VC Issuance. While the specification is oriented towards HTTP, the trait allows the
//! wallet (and issuance services) to be transport layer agnostic.
use std::future::Future;

use vercre_core::vci::{
    CredentialRequest, CredentialResponse, MetadataRequest, MetadataResponse, TokenRequest,
    TokenResponse,
};

use crate::credential::Logo;
use crate::Result;

/// `IssuerClient` is a provider that implements the wallet side of the OpenID for VC Issuance
/// interactions with an issuance service.
pub trait IssuerClient {
    /// Get issuer metadata. If an error is returned, the wallet will cancel the issuance flow.
    fn get_metadata(
        &self, flow_id: &str, req: &MetadataRequest,
    ) -> impl Future<Output = Result<MetadataResponse>> + Send;

    /// Get an access token. If an error is returned, the wallet will cancel the issuance flow.
    fn get_token(
        &self, flow_id: &str, req: &TokenRequest,
    ) -> impl Future<Output = Result<TokenResponse>> + Send;

    /// Get a credential. If an error is returned, the wallet will cancel the issuance flow.
    fn get_credential(
        &self, flow_id: &str, req: &CredentialRequest,
    ) -> impl Future<Output = Result<CredentialResponse>> + Send;

    /// Get a base64 encoded form of the credential logo. If an error is returned the wallet
    /// library will ignore.
    fn get_logo(&self, flow_id: &str, logo_url: &str) -> impl Future<Output = Result<Logo>> + Send;
}
