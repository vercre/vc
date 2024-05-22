//! # Token Response endpoint.
//! 
//! Call this endpoint on receipt of a token response from the issuance service to stash the token
//! in issuance state and get a set of credential requests to send to the issuance service - one for
//! each credential in the offer. Uses the signer provider to construct the proof needed in the
//! credential request.

use std::fmt::Debug;

use tracing::instrument;
use vercre_core::error::Err;
use vercre_core::provider::{Callback, Client, Signer, StateManager, Storer};
use vercre_core::vci::{CredentialRequest, Proof, ProofClaims, TokenResponse};
use vercre_core::{err, Result};
use vercre_core::jwt::{Header, Jwt};

use crate::issuance::{Issuance, Status};
use crate::Endpoint;

impl<P> Endpoint<P>
where
    P: Callback + Client + Signer + StateManager + Storer + Clone + Debug,
{
    /// Token response endpoint receives a token response from the issuance service and stashes the
    /// token in state. It then constructs a set of serialized credential requests to send to the
    /// issuance service.
    #[instrument(level = "debug", skip(self))]
    pub async fn token_response(&self, request: &TokenResponse) -> Result<String> {
        let ctx = Context {
            _p: std::marker::PhantomData,
        };

        vercre_core::Endpoint::handle_request(self, request, ctx).await
    }
}

#[derive(Debug, Default)]
struct Context<P> {
    _p: std::marker::PhantomData<P>,
}

impl<P> vercre_core::Context for Context<P>
where
    P: StateManager + Signer + Debug,
{
    type Provider = P;
    type Request = TokenResponse;
    type Response = String;

    fn callback_id(&self) -> Option<String> {
        None
    }

    async fn verify(&mut self, provider: &P, _req: &Self::Request) -> Result<&Self> {
        tracing::debug!("Context::verify");

        // Check we are processing an offer and we are at the expected point in the flow.
        let Some(stashed) = provider.get_opt("issuance").await? else {
            err!(Err::InvalidRequest, "no issuance in progress");
        };
        let issuance: Issuance = serde_json::from_slice(&stashed)?;
        if issuance.status != Status::Accepted {
            err!(Err::InvalidRequest, "invalid issuance status");
        }

        Ok(self)
    }

    async fn process(&self, provider: &P, req: &Self::Request) -> Result<Self::Response> {
        tracing::debug!("Context::process");

        // Stash the token in state.
        let mut issuance: Issuance = serde_json::from_slice(&provider.get("issuance").await?)?;
        issuance.token = req.clone();
        issuance.status = Status::Requested;
        provider.put_opt("issuance", serde_json::to_vec(&issuance)?, None).await?;

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
        let signed_jwt_str = String::from_utf8(signed_jwt).map_err(|e| Err::ServerError(e.into()))?;
        let proof = Proof {
            proof_type: jwt.to_string(),
            jwt: Some(signed_jwt_str),
            cwt: None,
        };

        // Construct an array of credential requests - one for each credential in the offer.
        let mut requests = Vec::new();
        for (id, cfg) in issuance.offered.into_iter() {
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

        // Serialize
        let requests_str = serde_json::to_string(&requests).map_err(|e| Err::ServerError(e.into()))?;
        Ok(requests_str)
    }
}


//     pub(super) fn credential_request(
//         &mut self, cfg_id: &str, signed_jwt: &str,
//     ) -> anyhow::Result<Value> {
//         self.status = Status::Requested;

//         let Some(cred_cfg) = self.offered.get(cfg_id) else {
//             return Err(anyhow!("Credential configuration not found"));
//         };

//         // TODO: build credential subject from metadata
//         // "credentialSubject": &metadata.credential_definition.credential_subject,

//         Ok(json!({
//             "format": cred_cfg.format.clone(),
//             "credential_definition": {
//                 "type": cred_cfg.credential_definition.type_.clone(),
//             },
//             "proof":{
//                 "proof_type": "jwt",
//                 "jwt": signed_jwt
//             }
//         }))
//     }


//for cfg_id in model.offered.clone().keys() {
    //                     let Ok(request) = model.credential_request(cfg_id, &signed_jwt) else {
    //                         let msg = String::from("Issue building credential request");
    //                         self.update(Event::Fail(msg), model, caps);
    //                         return;
    //                     };
    //                     #[cfg(feature = "wasm")]
    //                     web_sys::console::debug_2(&"model:".into(), &format!("{model:?}").into());
    
    //                     caps.http
    //                         .post(format!("{}/credential", model.offer.credential_issuer))
    //                         .header("authorization", format!("Bearer {}", model.token.access_token))
    //                         .body(request)
    //                         .expect_json()
    //                         .send(Event::Credential);
    //                 }