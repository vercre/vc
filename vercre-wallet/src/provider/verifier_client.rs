//! # Verifier Client provider
//!
//! This provider allows the wallet to interact with a verifier's services that are compliant with
//! OpenID for Verifiable Presentations. While the specification is oriented towards HTTP, the trait
//! allows the wallet (and verifier's services) to be transport layer agnostic.
use std::future::Future;

use vercre_core::vp::{RequestObjectResponse, ResponseRequest};

use crate::Result;

/// `VerifierClient` is a provider that implements the wallet side of the OpenID for Verifiable
/// Presentations.
pub trait VerifierClient {
    /// Get a request object. If an error is returned, the wallet will cancel the presentation flow.
    fn get_request_object(
        &self, flow_id: &str, req: &str,
    ) -> impl Future<Output = Result<RequestObjectResponse>> + Send;

    /// Send the presentation to the verifier.
    fn present(
        &self, flow_id: &str, uri: &str, presentation: &ResponseRequest,
    ) -> impl Future<Output = Result<()>> + Send;
}
