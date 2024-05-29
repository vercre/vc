//! # Token Response endpoint.
//!
//! Call this endpoint on receipt of a token response from the issuance service to stash the token
//! in issuance state and get a set of credential requests to send to the issuance service - one for
//! each credential in the offer. Uses the signer provider to construct the proof needed in the
//! credential request.

use std::fmt::Debug;

use tracing::instrument;
use vercre_core::error::Err;
use vercre_core::jwt::{Header, Jwt};
use vercre_core::vci::{CredentialRequest, Proof, ProofClaims, TokenResponse};
use vercre_core::{err, Result};

use crate::issuance::{Issuance, Status};
use crate::provider::{Callback, CredentialStorer, Signer, StateManager};
use crate::{Endpoint, Flow};

impl<P> Endpoint<P>
where
    P: Callback + Signer + StateManager + Clone + Debug + CredentialStorer,
{
    /// Token response endpoint receives a token response from the issuance service and stashes the
    /// token in state. It then constructs a set of credential requests to send to the
    /// issuance service.
    #[instrument(level = "debug", skip(self))]
    pub async fn credential_request(
        &self, request: &TokenResponse,
    ) -> Result<Vec<CredentialRequest>> {
        let ctx = Context {
            _p: std::marker::PhantomData,
            issuance: Issuance::default(),
        };

        vercre_core::Endpoint::handle_request(self, request, ctx).await
    }
}

#[derive(Debug, Default)]
struct Context<P> {
    _p: std::marker::PhantomData<P>,
    issuance: Issuance,
}

impl<P> vercre_core::Context for Context<P>
where
    P: StateManager + Signer + Debug,
{
    type Provider = P;
    type Request = TokenResponse;
    type Response = Vec<CredentialRequest>;

    async fn verify(&mut self, provider: &P, _req: &Self::Request) -> Result<&Self> {
        tracing::debug!("Context::verify");

        // Check we are processing an offer and we are at the expected point in the flow.
        let Some(stashed) = provider.get_opt(&Flow::Issuance.to_string()).await? else {
            err!(Err::InvalidRequest, "no issuance in progress");
        };
        let issuance: Issuance = serde_json::from_slice(&stashed)?;
        if issuance.status != Status::Accepted {
            err!(Err::InvalidRequest, "invalid issuance status");
        }
        self.issuance = issuance;

        Ok(self)
    }

    async fn process(&self, provider: &P, req: &Self::Request) -> Result<Self::Response> {
        tracing::debug!("Context::process");

         let mut issuance = self.issuance.clone();
        issuance.token = req.clone();

        // Construct a proof.
        let kid = provider.verification_method().clone();
        let holder_did = kid.split('#').collect::<Vec<&str>>()[0];
        let jwt = Jwt {
            header: Header {
                typ: String::from("vercre-vci-proof+jwt"),
                alg: provider.algorithm().to_string(),
                kid: kid.clone(),
            },
            claims: ProofClaims {
                iss: holder_did.to_string(),
                aud: issuance.offer.credential_issuer.clone(),
                iat: chrono::Utc::now().timestamp(),
                nonce: issuance.token.c_nonce.clone().unwrap_or_default(),
            },
        };

        // Sign the proof.
        let jwt_bytes = serde_json::to_vec(&jwt).map_err(|e| Err::ServerError(e.into()))?;
        let signed_jwt = provider.sign(&jwt_bytes).await;
        let signed_jwt_str =
            String::from_utf8(signed_jwt).map_err(|e| Err::ServerError(e.into()))?;
        let proof = Proof {
            proof_type: jwt.to_string(),
            jwt: Some(signed_jwt_str),
            cwt: None,
        };

        // Update status (assuming client will actually make the request).
        issuance.status = Status::Requested;
        provider.put_opt(&Flow::Issuance.to_string(), serde_json::to_vec(&issuance)?, None).await?;

        // Construct an array of credential requests - one for each credential in the offer.
        let mut requests = Vec::new();
        for (id, cfg) in issuance.offered {
            let request = CredentialRequest {
                credential_issuer: issuance.offer.credential_issuer.clone(),
                access_token: req.access_token.clone(),
                format: Some(cfg.format.clone()),
                proof: Some(proof.clone()),
                credential_identifier: Some(id),
                credential_definition: Some(cfg.credential_definition.clone()),
                credential_response_encryption: None,
            };
            requests.push(request);
        }

        Ok(requests)
    }
}
