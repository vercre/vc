//! # Credential Endpoint
//!
//! The Credential Handler issues a Credential as approved by the End-User upon
//! presentation of a valid Access Token representing this approval.
//!
//! The Wallet sends one Credential Request per individual Credential to the
//! Credential Handler. The Wallet MAY use the same Access Token to send
//! multiple Credential Requests to request issuance of multiple Credentials of
//! different types bound to the same proof, or multiple Credentials of the same
//! type bound to different proofs.
//!
//! ## Credential Requests
//!
//! - One (and only one) of `credential_identifier` or `format` is REQUIRED.
//! - `credential_identifier` is REQUIRED when `credential_identifiers` parameter
//!   was returned from the Token Response. MUST NOT be used otherwise.
//! - When `format` is set, `credential_definition` is REQUIRED.
//!
//! **VC Signed as a JWT, Not Using JSON-LD**
//!
//! - `format` is `"jwt_vc_json"`. REQUIRED.
//! - `credential_definition`. REQUIRED.
//!   - `type`. REQUIRED.
//!   - `credentialSubject`. OPTIONAL.
//!
//! ## Example
//!
//! ```json
// ! {
// !    "format": "jwt_vc_json",
// !    "credential_definition": {
// !       "type": [
// !          "VerifiableCredential",
// !          "UniversityDegreeCredential"
// !       ],
// !       "credentialSubject": {
// !          "given_name": {},
// !          "family_name": {},
// !          "degree": {}
// !       }
// !    },
// !    ...
// ! }
//! ```

use openid::issuer::{BatchCredentialRequest, CredentialRequest, CredentialResponse, Provider};
use openid::Result;
use tracing::instrument;

use crate::batch::batch;
// use crate::shell;

/// Credential request handler.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
#[instrument(level = "debug", skip(provider))]
pub async fn credential(
    provider: impl Provider, request: &CredentialRequest,
) -> Result<CredentialResponse> {
    process(provider, request).await
}

async fn process(
    provider: impl Provider, request: &CredentialRequest,
) -> Result<CredentialResponse> {
    tracing::debug!("Context::process");

    let request = BatchCredentialRequest {
        credential_issuer: request.credential_issuer.clone(),
        access_token: request.access_token.clone(),
        credential_requests: vec![request.clone()],
    };
    let batch = batch(provider.clone(), &request).await.expect("msg");

    // set c_nonce and c_nonce_expires_at - batch endpoint sets them in the
    // top-level response, not each credential response
    let mut response = batch.credential_responses[0].clone();
    response.c_nonce = batch.c_nonce;
    response.c_nonce_expires_in = batch.c_nonce_expires_in;

    Ok(response)
}

#[cfg(test)]
mod tests {
    use assert_let_bind::assert_let;
    use chrono::Utc;
    use insta::assert_yaml_snapshot as assert_snapshot;
    use openid::issuer::ProofClaims;
    use openid::provider::StateManager;
    use proof::jose::jws::{self, Type};
    use serde_json::json;
    use test_utils::holder;
    use test_utils::issuer::{Provider, CLIENT_ID, CREDENTIAL_ISSUER, NORMAL_USER};
    use w3c_vc::proof::{Payload, Verify};

    use super::*;
    use crate::state::{Expire, State, Token};

    #[tokio::test]
    async fn credential_ok() {
        test_utils::init_tracer();

        let provider = Provider::new();
        let access_token = "ABCDEF";
        let c_nonce = "1234ABCD";
        let credentials = vec!["EmployeeID_JWT".into()];

        // set up state
        let mut state = State::builder()
            .credential_issuer(CREDENTIAL_ISSUER.into())
            .expires_at(Utc::now() + Expire::AuthCode.duration())
            .credential_identifiers(credentials)
            .subject_id(Some(NORMAL_USER.into()))
            .build()
            .expect("should build state");

        state.token = Some(Token {
            access_token: access_token.into(),
            token_type: "Bearer".into(),
            c_nonce: c_nonce.into(),
            c_nonce_expires_at: Utc::now() + Expire::Nonce.duration(),
            ..Default::default()
        });

        StateManager::put(&provider, access_token, state.to_vec(), state.expires_at)
            .await
            .expect("state saved");

        // create CredentialRequest to 'send' to the app
        let claims = ProofClaims {
            iss: Some(CLIENT_ID.into()),
            aud: CREDENTIAL_ISSUER.into(),
            iat: Utc::now().timestamp(),
            nonce: Some(c_nonce.into()),
        };
        let jwt = jws::encode(Type::Proof, &claims, holder::Provider).await.expect("should encode");

        let body = json!({
            "format": "jwt_vc_json",
            "credential_definition": {
                "type": [
                    "VerifiableCredential",
                    "EmployeeIDCredential"
                ]
            },
            "proof":{
                "proof_type": "jwt",
                "jwt": jwt
            }
        });

        let mut request =
            serde_json::from_value::<CredentialRequest>(body).expect("request should deserialize");
        request.credential_issuer = CREDENTIAL_ISSUER.into();
        request.access_token = access_token.into();

        let response = credential(provider.clone(), &request).await.expect("response is valid");
        assert_snapshot!("response", &response, {
            ".credential" => "[credential]",
            ".c_nonce" => "[c_nonce]",
            ".c_nonce_expires_in" => "[c_nonce_expires_in]"
        });

        // verify credential
        let Some(vc_kind) = &response.credential else {
            panic!("VC is not base64 encoded string");
        };
        let Payload::Vc(vc) =
            w3c_vc::proof::verify(Verify::Vc(vc_kind), &provider).await.expect("should decode")
        else {
            panic!("should be VC");
        };

        assert_snapshot!("vc", vc, {
            ".issuanceDate" => "[issuanceDate]",
            ".credentialSubject" => insta::sorted_redaction()
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
