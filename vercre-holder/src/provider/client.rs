//! # Client providers
//!
//! This module defines the client provider traits for issuers and verifiers. The wallet crate
//! uses these traits to interact with the issuer and verifier services.
use std::future::Future;

use openid4vc::issuance::{
    CredentialRequest, CredentialResponse, MetadataRequest, MetadataResponse, TokenRequest,
    TokenResponse,
};
use openid4vc::presentation::{RequestObjectResponse, ResponseRequest, ResponseResponse};

use crate::credential::Logo;

/// This provider allows the wallet to interact with an issuer's services that are compliant with
/// OpenID for VC Issuance. While the specification is oriented towards HTTP, the trait allows the
/// wallet (and issuance services) to be transport layer agnostic.
#[allow(clippy::module_name_repetitions)]
pub trait IssuerClient {
    /// Get issuer metadata. If an error is returned, the wallet will cancel the issuance flow.
    fn get_metadata(
        &self, flow_id: &str, req: &MetadataRequest,
    ) -> impl Future<Output = anyhow::Result<MetadataResponse>> + Send;

    /// Get an access token. If an error is returned, the wallet will cancel the issuance flow.
    fn get_token(
        &self, flow_id: &str, req: &TokenRequest,
    ) -> impl Future<Output = anyhow::Result<TokenResponse>> + Send;

    /// Get a credential. If an error is returned, the wallet will cancel the issuance flow.
    fn get_credential(
        &self, flow_id: &str, req: &CredentialRequest,
    ) -> impl Future<Output = anyhow::Result<CredentialResponse>> + Send;

    /// Get a base64 encoded form of the credential logo. If an error is returned the wallet
    /// library will ignore.
    fn get_logo(
        &self, flow_id: &str, logo_url: &str,
    ) -> impl Future<Output = anyhow::Result<Logo>> + Send;
}

/// This provider allows the wallet to interact with a verifier's services that are compliant with
/// OpenID for Verifiable Presentations. While the specification is oriented towards HTTP, the trait
/// allows the wallet (and verifier's services) to be transport layer agnostic.
#[allow(clippy::module_name_repetitions)]
pub trait VerifierClient {
    /// Get a request object. If an error is returned, the wallet will cancel the presentation flow.
    fn get_request_object(
        &self, flow_id: &str, req: &str,
    ) -> impl Future<Output = anyhow::Result<RequestObjectResponse>> + Send;

    /// Send the presentation to the verifier.
    fn present(
        &self, flow_id: &str, uri: Option<&str>, presentation: &ResponseRequest,
    ) -> impl Future<Output = anyhow::Result<ResponseResponse>> + Send;
}
