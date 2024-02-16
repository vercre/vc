//! # Credential Handler
//!
//! The Credential Handler issues a Credential as approved by the End-User upon
//! presentation of a valid Access Token representing this approval.
//!
//! The Wallet sends one Credential Request per individual Credential to the
//! Credential Handler. The Wallet MAY use the same Access Token to send
//! multiple Credential Requests to request issuance of multiple Credentials of
//! different types bound to the same proof, or multiple Credentials of the same
//! type bound to different proofs.

use std::fmt::Debug;

use anyhow::anyhow;
use tracing::{instrument, trace};
use vercre_core::vci::{BatchCredentialRequest, CredentialRequest, CredentialResponse};
use vercre_core::{err, Callback, Client, Holder, Issuer, Result, Server, Signer, StateManager};

use super::Handler;

/// Credential request handler.
impl<P> Handler<P, CredentialRequest>
where
    P: Client + Issuer + Server + Holder + StateManager + Signer + Callback + Clone,
{
    /// Call the request for the Request Object endpoint.
    #[instrument]
    pub async fn call(&self) -> Result<CredentialResponse> {
        trace!("Handler::call");
        self.handle_request(Context::new()).await
    }
}

#[derive(Debug)]
struct Context<P>
where
    P: Client + Issuer + Server + Holder + StateManager + Callback + Clone,
{
    provider: Option<P>,
}

impl<P> Context<P>
where
    P: Client + Issuer + Server + Holder + StateManager + Callback + Clone,
{
    #[instrument]
    pub fn new() -> Self {
        trace!("Context::new");
        Self { provider: None }
    }
}

impl<P> vercre_core::Context for Context<P>
where
    P: Client + Issuer + Server + Holder + StateManager + Signer + Callback + Clone + Debug,
{
    type Provider = P;
    type Request = CredentialRequest;
    type Response = CredentialResponse;

    #[instrument]
    async fn init(&mut self, _: &Self::Request, provider: Self::Provider) -> Result<&Self> {
        trace!("Context::prepare");

        self.provider = Some(provider);
        Ok(self)
    }

    #[instrument]
    async fn process(&self, req: &Self::Request) -> Result<Self::Response> {
        trace!("Context::process");

        let Some(provider) = self.provider.clone() else {
            err!("Provider not set")
        };

        let batch_req = BatchCredentialRequest {
            credential_issuer: req.credential_issuer.clone(),
            access_token: req.access_token.clone(),
            credential_requests: vec![req.clone()],
        };
        let batch_res = Handler::new(provider, batch_req).call().await?;

        // set c_nonce and c_nonce_expires_at - batch endpoint sets them in the
        // top-level response, not each credential response
        let mut cred_res = batch_res.credential_responses[0].clone();
        cred_res.c_nonce = batch_res.c_nonce;
        cred_res.c_nonce_expires_in = batch_res.c_nonce_expires_in;

        Ok(cred_res)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use assert_let_bind::assert_let;
    use base64ct::{Base64UrlUnpadded, Encoding};
    use chrono::Utc;
    use insta::assert_yaml_snapshot as assert_snapshot;
    use serde_json::json;
    use test_utils::vci_provider::{Provider, ISSUER, NORMAL_USER};
    use test_utils::wallet;
    use vercre_core::jwt::{self, Jwt};
    use vercre_core::vci::ProofClaims;
    use vercre_core::w3c::vc::VcClaims;

    use super::*;
    use crate::state::{Expire, State, TokenState};

    #[tokio::test]
    async fn credential_ok() {
        test_utils::init_tracer();

        let provider = &Provider::new();
        let access_token = "ABCDEF";
        let c_nonce = "1234ABCD";
        let credentials = vec!["EmployeeID_JWT".to_string()];

        // set up state
        let mut state = State::builder()
            .credential_issuer(ISSUER.to_string())
            .expires_at(Utc::now() + Expire::AuthCode.duration())
            .credentials(credentials)
            .holder_id(Some(NORMAL_USER.to_string()))
            .build();

        state.token = Some(TokenState {
            access_token: access_token.to_string(),
            token_type: "Bearer".to_string(),
            c_nonce: c_nonce.to_string(),
            c_nonce_expires_at: Utc::now() + Expire::Nonce.duration(),
            ..Default::default()
        });

        StateManager::put(&provider, access_token, state.to_vec(), state.expires_at)
            .await
            .expect("state saved");

        // create CredentialRequest to 'send' to the app
        let jwt_enc = Jwt {
            header: jwt::Header {
                typ: "vercre-vci-proof+jwt".to_string(),
                alg: wallet::alg(),
                kid: wallet::kid(),
            },
            claims: ProofClaims {
                iss: wallet::did(),
                aud: ISSUER.to_string(),
                iat: Utc::now().timestamp(),
                nonce: c_nonce.to_string(),
            },
        }
        .to_string();
        let sig = wallet::sign(jwt_enc.as_bytes());
        let sig_enc = Base64UrlUnpadded::encode_string(&sig);
        let signed_jwt = format!("{jwt_enc}.{sig_enc}");

        let body = json!({
            "credential_identifier": "EmployeeID_JWT",
            "proof":{
                "proof_type": "jwt",
                "jwt": signed_jwt
            }
        });

        let mut request =
            serde_json::from_value::<CredentialRequest>(body).expect("request should deserialize");
        request.credential_issuer = ISSUER.to_string();
        request.access_token = access_token.to_string();

        let response = Handler::new(provider, request).call().await.expect("response is valid");
        assert_snapshot!("response", response, {
            ".credential" => "[credential]",
            ".c_nonce" => "[c_nonce]",
            ".c_nonce_expires_in" => "[c_nonce_expires_in]"
        });

        // verify credential
        let vc_val = response.credential.expect("VC is present");
        let vc_b64 = serde_json::from_value::<String>(vc_val).expect("base64 encoded string");
        let vc_jwt = Jwt::<VcClaims>::from_str(&vc_b64).expect("VC as JWT");
        assert_snapshot!("vc_jwt", vc_jwt, {
            ".claims.iat" => "[iat]",
            ".claims.nbf" => "[nbf]",
            ".claims.vc.issuanceDate" => "[issuanceDate]",
            ".claims.vc.credentialSubject" => insta::sorted_redaction()
        });

        // token state should remain unchanged
        assert_let!(Ok(buf), StateManager::get(&provider, access_token).await);
        let state = State::try_from(buf).expect("state is valid");
        assert_snapshot!("state", state, {
            ".expires_at" => "[expires_at]",
            ".token.c_nonce"=>"[c_nonce]",
            ".token.c_nonce_expires_at" => "[c_nonce_expires_at]"
        });
    }
}
