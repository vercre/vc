//! # Batch Credential Endpoint
//!
//! The Batch Credential Endpoint issues multiple Credentials in one Batch Credential
//! Response as approved by the End-User upon presentation of a valid Access Token
//! representing this approval.
//!
//! A Wallet can request issuance of multiple Credentials of certain types and formats
//! in one Batch Credential Request. This includes Credentials of the same type and
//! multiple formats, different types and one format, or both.

use std::fmt::Debug;

use chrono::Utc;
use core_utils::gen;
use core_utils::jws::{self, Type};
use openid4vc::error::Err;
#[allow(clippy::module_name_repetitions)]
pub use openid4vc::issuance::{
    BatchCredentialRequest, BatchCredentialResponse, CredentialRequest, CredentialResponse,
    CredentialType, ProofType,
};
use openid4vc::issuance::{CredentialDefinition, Issuer, ProofClaims};
use openid4vc::Result;
use provider::{
    Callback, ClientMetadata, IssuerMetadata, ServerMetadata, Signer, StateManager, Subject,
    Verifier,
};
use tracing::instrument;
use w3c_vc::model::{self, CredentialSubject, VerifiableCredential};
use w3c_vc::proof::{self, Format, Payload};

use super::Endpoint;
use crate::state::{Deferred, Expire, State};

impl<P> Endpoint<P>
where
    P: ClientMetadata
        + IssuerMetadata
        + ServerMetadata
        + Subject
        + StateManager
        + Signer
        + Verifier
        + Callback
        + Clone
        + Debug,
{
    /// Batch credential request handler.
    ///
    /// # Errors
    ///
    /// Returns an `OpenID4VP` error if the request is invalid or if the provider is
    /// not available.
    #[instrument(level = "debug", skip(self))]
    pub async fn batch(&self, request: &BatchCredentialRequest) -> Result<BatchCredentialResponse> {
        let Ok(buf) = StateManager::get(&self.provider, &request.access_token).await else {
            return Err(Err::AccessDenied("invalid access token".into()));
        };
        let Ok(state) = State::try_from(buf) else {
            return Err(Err::AccessDenied("invalid state for access token".into()));
        };

        let ctx = Context {
            callback_id: state.callback_id.clone(),
            state,
            issuer_meta: IssuerMetadata::metadata(&self.provider, &request.credential_issuer)
                .await
                .map_err(|e| Err::ServerError(format!("metadata issue: {e}")))?,
            holder_did: String::new(),
            _p: std::marker::PhantomData,
        };

        core_utils::Endpoint::handle_request(self, request, ctx).await
    }
}

#[derive(Debug)]
struct Context<P> {
    callback_id: Option<String>,
    issuer_meta: Issuer,
    state: State,
    holder_did: String,
    _p: std::marker::PhantomData<P>,
}

impl<P> core_utils::Context for Context<P>
where
    P: IssuerMetadata + Subject + StateManager + Signer + Verifier + Clone + Debug,
{
    type Provider = P;
    type Request = BatchCredentialRequest;
    type Response = BatchCredentialResponse;

    fn callback_id(&self) -> Option<String> {
        self.callback_id.clone()
    }

    async fn verify(&mut self, provider: &P, request: &Self::Request) -> Result<&Self> {
        tracing::debug!("Context::verify");

        let Some(token_state) = &self.state.token else {
            return Err(Err::AccessDenied("invalid access token state".into()));
        };

        // c_nonce expiry
        if token_state.c_nonce_expired() {
            return Err(Err::AccessDenied("c_nonce has expired".into()));
        }

        // TODO: add support for `credential_identifier`
        // verify each credential request
        for request in &request.credential_requests {
            // format and type request
            if let CredentialType::Format(format) = &request.credential_type {
                let Some(cred_def) = &request.credential_definition else {
                    return Err(Err::InvalidCredentialRequest(
                        "credential definition not set".into(),
                    ));
                };

                // check request has been authorized:
                //   - match format + type against authorized items in state
                let mut authorized = false;

                for (k, v) in &self.issuer_meta.credential_configurations_supported {
                    if (&v.format == format) && (v.credential_definition.type_ == cred_def.type_) {
                        authorized = self.state.credential_configuration_ids.contains(k);
                        break;
                    }
                }
                if !authorized {
                    return Err(Err::InvalidCredentialRequest(
                        "Requested credential has not been authorized".into(),
                    ));
                }
            };

            // ----------------------------------------------------------------
            // TODO: check `proof_types_supported` param in `credential_configurations_supported`
            // is non-empty
            // ----------------------------------------------------------------
            let Some(proof) = &request.proof else {
                return Err(Err::InvalidCredentialRequest("proof not set".into()));
            };
            // ----------------------------------------------------------------

            let ProofType::Jwt(proof_jwt) = &proof.proof else {
                let (c_nonce, c_nonce_expires_in) = self.err_nonce(provider).await?;
                return Err(Err::InvalidProof {
                    hint: "Proof not set".into(),
                    c_nonce,
                    c_nonce_expires_in,
                });
            };
            let jwt: jws::Jwt<ProofClaims> = match jws::decode(proof_jwt, provider).await {
                Ok(jwt) => jwt,
                Err(e) => {
                    let (c_nonce, c_nonce_expires_in) = self.err_nonce(provider).await?;
                    return Err(Err::InvalidProof {
                        hint: format!("issue decoding jwt: {e}"),
                        c_nonce,
                        c_nonce_expires_in,
                    });
                }
            };
            // proof type
            if jwt.header.typ != Type::Proof {
                let (c_nonce, c_nonce_expires_in) = self.err_nonce(provider).await?;
                return Err(Err::InvalidProof {
                    hint: format!("Proof JWT 'typ' is not {}", Type::Proof),
                    c_nonce,
                    c_nonce_expires_in,
                });
            }

            // previously issued c_nonce
            if jwt.claims.nonce.as_ref() != Some(&token_state.c_nonce) {
                let (c_nonce, c_nonce_expires_in) = self.err_nonce(provider).await?;
                return Err(Err::InvalidProof {
                    hint: "Proof JWT nonce claim is invalid".into(),
                    c_nonce,
                    c_nonce_expires_in,
                });
            }

            // TODO: use `decode` method in w3c-vc
            // Key ID
            let Some(kid) = jwt.header.kid else {
                let (c_nonce, c_nonce_expires_in) = self.err_nonce(provider).await?;

                return Err(Err::InvalidProof {
                    hint: "Proof JWT 'kid' is missing".into(),
                    c_nonce,
                    c_nonce_expires_in,
                });
            };
            // HACK: save extracted DID for later use when issuing credential
            let Some(did) = kid.split('#').next() else {
                let (c_nonce, c_nonce_expires_in) = self.err_nonce(provider).await?;

                return Err(Err::InvalidProof {
                    hint: "Proof JWT DID is invalid".into(),
                    c_nonce,
                    c_nonce_expires_in,
                });
            };
            self.holder_did = did.into();
        }

        Ok(self)
    }

    async fn process(&self, provider: &P, request: &Self::Request) -> Result<Self::Response> {
        tracing::debug!("Context::process");

        // process credential requests
        let mut responses = Vec::<CredentialResponse>::new();
        for c_req in request.credential_requests.clone() {
            responses.push(self.create_response(provider, &c_req).await?);
        }

        // generate nonce and update state
        let Some(token_state) = &self.state.token else {
            return Err(Err::ServerError(format!("Invalid token state")));
        };

        // --------------------------------------------------------------------
        // TODO: refresh c_nonce and c_nonce_expires_at
        // -> requires c_nonce HashMap in State to cater for deferred requests
        //    with proof based on an older c_nonce
        // --------------------------------------------------------------------
        // let Some(provider) = &self.provider else {
        //     return Err(Err::ServerError(format!("provider not set"))));
        // };

        // let c_nonce = gen::nonce();
        // token_state.c_nonce = c_nonce.into();
        // token_state.c_nonce_expires_at = Utc::now() + Expire::Nonce.duration();
        // state.token = Some(token_state.clone());
        // let buf = serde_json::to_vec(&state)?;
        // StateManager::put(provider, &token_state.access_token, buf, state.expires_at).await?;

        Ok(BatchCredentialResponse {
            credential_responses: responses.clone(),
            c_nonce: Some(token_state.c_nonce.clone()),
            c_nonce_expires_in: Some(token_state.c_nonce_expires_in()),
        })
    }
}

impl<P> Context<P>
where
    P: Subject + StateManager + Signer + Clone,
{
    // Processes the Credential Request to generate a Credential Response.
    async fn create_response(
        &self, provider: &P, request: &CredentialRequest,
    ) -> Result<CredentialResponse> {
        tracing::debug!("Context::create_response");

        // Try to create a VC. If None, then return a deferred issuance response.
        let Some(vc) = self.create_vc(provider, request).await? else {
            //--------------------------------------------------
            // Defer credential issuance
            //--------------------------------------------------
            let mut state = self.state.clone();
            let txn_id = gen::transaction_id();

            // save credential request in state for later use in a deferred request.
            state.deferred = Some(Deferred {
                transaction_id: txn_id.clone(),
                credential_request: request.clone(),
            });
            state.token = None;

            let buf = serde_json::to_vec(&state)
                .map_err(|e| Err::ServerError(format!("issue serializing state: {e}")))?;
            StateManager::put(provider, &txn_id, buf, state.expires_at)
                .await
                .map_err(|e| Err::ServerError(format!("issue saving state: {e}")))?;

            // only need to return transaction_id
            return Ok(CredentialResponse {
                transaction_id: Some(txn_id),

                // TODO: add `c_nonce` and `c_nonce_expires_in` to CredentialResponse
                ..CredentialResponse::default()
            });
        };

        // generate proof for the credential
        let jwt = proof::create(Format::JwtVcJson, Payload::Vc(vc), provider.clone())
            .await
            .map_err(|e| Err::ServerError(format!("issue creating proof: {e}")))?;

        Ok(CredentialResponse {
            credential: Some(serde_json::Value::String(jwt)),

            // TODO: add `c_nonce` and `c_nonce_expires_in` to CredentialResponse
            ..CredentialResponse::default()
        })
    }

    // Attempt to generate a Verifiable Credential from information provided in the Credential
    // Request. May return `None` if the credential is not ready to be issued because the request
    // for Subject is pending.
    async fn create_vc(
        &self, provider: &P, request: &CredentialRequest,
    ) -> Result<Option<VerifiableCredential>> {
        tracing::debug!("Context::create_vc");

        let cred_def = self.credential_definition(request)?;
        let Some(holder_id) = &self.state.holder_id else {
            return Err(Err::AccessDenied("holder not found".into()));
        };

        // claim values
        let holder_claims = Subject::claims(provider, holder_id, &cred_def)
            .await
            .map_err(|e| Err::ServerError(format!("issue populating claims: {e}")))?;
        if holder_claims.pending {
            return Ok(None);
        }

        // check mandatory claims are populated
        let Some(cred_subj) = cred_def.credential_subject.clone() else {
            return Err(Err::ServerError(format!("Credential subject not set")));
        };
        for (name, claim) in &cred_subj {
            if claim.mandatory.unwrap_or_default() && !holder_claims.claims.contains_key(name) {
                return Err(Err::InvalidCredentialRequest(
                    "mandatory claim {name} not populated".into(),
                ));
            }
        }

        let credential_issuer = &self.issuer_meta.credential_issuer;

        // HACK: fix this
        let Some(types) = cred_def.type_ else {
            return Err(Err::ServerError(format!("Credential type not set")));
        };

        let vc_id = format!("{credential_issuer}/credentials/{}", types[1].clone());

        let vc = VerifiableCredential::builder()
            .add_context(model::Context::Url(credential_issuer.clone() + "/credentials/v1"))
            // TODO: generate credential id
            .id(vc_id)
            .add_type(types[1].clone())
            .issuer(credential_issuer.clone())
            .add_subject(CredentialSubject {
                id: Some(self.holder_did.clone()),
                claims: holder_claims.claims,
            })
            .build()
            .map_err(|e| Err::ServerError(format!("issue building VC: {e}")))?;

        Ok(Some(vc))
    }

    // Get the request's credential definition. If it does not exist, create it.
    fn credential_definition(&self, request: &CredentialRequest) -> Result<CredentialDefinition> {
        tracing::debug!("Context::credential_definition");

        if let Some(mut cred_def) = request.credential_definition.clone() {
            // add credential subject when not present
            if cred_def.credential_subject.is_none() {
                let find_supported = match &request.credential_type {
                    CredentialType::Identifier(id) => {
                        self.issuer_meta.credential_configurations_supported.get(id)
                    }
                    CredentialType::Format(format) => {
                        self.issuer_meta.credential_configurations_supported.values().find(|v| {
                            &v.format == format && v.credential_definition.type_ == cred_def.type_
                        })
                    }
                };

                let Some(supported) = find_supported else {
                    return Err(Err::InvalidCredentialRequest(
                        "credential is not supported".into(),
                    ));
                };

                // copy credential subject
                cred_def
                    .credential_subject
                    .clone_from(&supported.credential_definition.credential_subject);
            };

            Ok(cred_def)
        } else {
            let CredentialType::Identifier(id) = &request.credential_type else {
                return Err(Err::InvalidCredentialRequest("no credential identifier".into()));
            };
            let Some(supported) = self.issuer_meta.credential_configurations_supported.get(id)
            else {
                return Err(Err::InvalidCredentialRequest(format!(
                    "no supported credential for identifier {id}"
                )));
            };

            Ok(CredentialDefinition {
                context: None,
                type_: supported.credential_definition.type_.clone(),
                credential_subject: supported.credential_definition.credential_subject.clone(),
            })
        }
    }

    /// Creates, stores, and returns new `c_nonce` and `c_nonce_expires`_in values
    /// for use in `Err::InvalidProof` errors, as per specification.
    async fn err_nonce(&self, provider: &P) -> Result<(String, i64)> {
        // generate nonce and update state
        let mut state = self.state.clone();
        let Some(mut token_state) = state.token else {
            return Err(Err::ServerError("token state not set".into()));
        };

        let c_nonce = gen::nonce();
        token_state.c_nonce.clone_from(&c_nonce);
        token_state.c_nonce_expires_at = Utc::now() + Expire::Nonce.duration();
        state.token = Some(token_state.clone());

        StateManager::put(provider, &token_state.access_token, state.to_vec(), state.expires_at)
            .await
            .map_err(|e| Err::ServerError(format!("issue saving state: {e}")))?;

        Ok((c_nonce, Expire::Nonce.duration().num_seconds()))
    }
}

#[cfg(test)]
mod tests {
    use assert_let_bind::assert_let;
    use insta::assert_yaml_snapshot as assert_snapshot;
    use serde_json::json;
    use test_utils::holder;
    use test_utils::issuer::{Provider, CLIENT_ID, CREDENTIAL_ISSUER, NORMAL_USER};
    use w3c_vc::proof::Verify;

    use super::*;
    use crate::state::Token;

    #[tokio::test]
    async fn authorization_details() {
        test_utils::init_tracer();

        let provider = Provider::new();
        let access_token = "ABCDEF";
        let c_nonce = "1234ABCD";
        let credentials = vec!["EmployeeID_JWT".into()];

        // set up state
        let mut state = State::builder()
            .credential_issuer(CREDENTIAL_ISSUER.into())
            .expires_at(Utc::now() + Expire::AuthCode.duration())
            .credential_configuration_ids(credentials)
            .holder_id(Some(NORMAL_USER.into()))
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
            .expect("state exists");

        let claims = ProofClaims {
            iss: Some(CLIENT_ID.into()),
            aud: CREDENTIAL_ISSUER.into(),
            iat: Utc::now().timestamp(),
            nonce: Some(c_nonce.into()),
        };
        let jwt = jws::encode(Type::Proof, &claims, holder::Provider).await.expect("should encode");

        let body = json!({
            "credential_requests":[{
                "format": "jwt_vc_json",
                "credential_definition": {
                    "type": ["VerifiableCredential", "EmployeeIDCredential"],
                    "credentialSubject": {
                        "givenName": {},
                        "familyName": {},
                    }
                },
                "proof":{
                    "proof_type": "jwt",
                    "jwt": jwt
                }
            }]
        });

        let mut request = serde_json::from_value::<BatchCredentialRequest>(body)
            .expect("request should deserialize");
        request.credential_issuer = CREDENTIAL_ISSUER.into();
        request.access_token = access_token.into();

        let response =
            Endpoint::new(provider.clone()).batch(&request).await.expect("response is valid");
        assert_snapshot!("ad-response", &response, {
            ".credential_responses[0]" => "[credential]",
            ".c_nonce" => "[c_nonce]",
            ".c_nonce_expires_in" => "[c_nonce_expires_in]"
        });

        // verify credential
        assert!(response.credential_responses.len() == 1);
        let credential = response.credential_responses[0].credential.clone();

        let vc_val = credential.expect("VC is present");
        let token = serde_json::from_value::<String>(vc_val).expect("base64 encoded string");
        let Payload::Vc(vc) =
            proof::verify(&token, Verify::Vc, &provider).await.expect("should decode")
        else {
            panic!("should be VC");
        };

        assert_snapshot!("ad-vc", vc, {
            ".issuanceDate" => "[issuanceDate]",
            ".credentialSubject" => insta::sorted_redaction()
        });

        // token state should remain unchanged
        assert_let!(Ok(buf), StateManager::get(&provider, access_token).await);
        let state = State::try_from(buf).expect("state is valid");
        assert_snapshot!("ad-state", state, {
            ".expires_at" => "[expires_at]",
            ".token.c_nonce"=>"[c_nonce]",
            ".token.c_nonce_expires_at" => "[c_nonce_expires_at]"
        });
    }

    // #[tokio::test]
    // async fn credential_identifiers() {
    //     test_utils::init_tracer();

    //     let provider = Provider::new();
    //     let access_token = "ABCDEF";
    //     let c_nonce = "1234ABCD";
    //     let identifiers = vec!["EmployeeID_JWT".into()];

    //     // set up state
    //     let mut state = State::builder()
    //         .credential_issuer(CREDENTIAL_ISSUER.into())
    //         .expires_at(Utc::now() + Expire::AuthCode.duration())
    //         .holder_id(Some(NORMAL_USER.into()))
    //         .build()
    //         .expect("should build state");

    //     state.token = Some(Token {
    //         access_token: access_token.into(),
    //         token_type: "Bearer".into(),
    //         c_nonce: c_nonce.into(),
    //         c_nonce_expires_at: Utc::now() + Expire::Nonce.duration(),
    //         ..Default::default()
    //     });

    //     StateManager::put(&provider, access_token, state.to_vec(), state.expires_at)
    //         .await
    //         .expect("state exists");

    //     // create BatchCredentialRequest to 'send' to the app

    //     let claims = ProofClaims {
    //         iss: holder_provider::CLIENT_ID,
    //         aud: CREDENTIAL_ISSUER.into(),
    //         iat: Utc::now().timestamp(),
    //         nonce: c_nonce.into(),
    //     };
    //  let jwt = jose::encode(jose::Payload::Proof, &claims, holder_provider::Provider::new())
    //         .await
    //         .expect("should encode");

    //     let body = json!({
    //         "credential_requests":[{
    //             "credential_identifier": "EmployeeID_JWT",
    //             "proof":{
    //                 "proof_type": "jwt",
    //                 "jwt": signed_jwt
    //             }
    //         }]
    //     });

    //     let mut request = serde_json::from_value::<BatchCredentialRequest>(body)
    //         .expect("request should deserialize");
    //     request.credential_issuer = CREDENTIAL_ISSUER.into();
    //     request.access_token = access_token.into();

    //     let response =
    //         Endpoint::new(provider.clone()).batch(&request).await.expect("response is valid");
    //     assert_snapshot!("ci-response", response, {
    //         ".credential_responses[0]" => "[credential]",
    //         ".c_nonce" => "[c_nonce]",
    //         ".c_nonce_expires_in" => "[c_nonce_expires_in]"
    //     });

    //     // verify credential
    //     assert!(response.credential_responses.len() == 1);
    //     let credential = response.credential_responses[0].credential.clone();

    //     let vc_val = credential.expect("VC is present");
    //     let token = serde_json::from_value::<String>(vc_val).expect("base64 encoded string");
    //     let Payload::Vc(vc) = proof::verify(&token, Verify::Vc).await.expect("should decode")
    //     else {
    //         panic!("should be VC");
    //     };

    //     assert_snapshot!("ci-vc_jwt", vc_jwt, {
    //         ".claims.iat" => "[iat]",
    //         ".claims.nbf" => "[nbf]",
    //         ".claims.vc.issuanceDate" => "[issuanceDate]",
    //         ".claims.vc.credentialSubject" => insta::sorted_redaction()
    //     });

    //     // token state should remain unchanged
    //     assert_let!(Ok(buf), StateManager::get(&provider, access_token).await);
    //     let state = State::try_from(buf).expect("state is valid");
    //     assert_snapshot!("ci-state", state, {
    //         ".expires_at" => "[expires_at]",
    //         ".token.c_nonce"=>"[c_nonce]",
    //         ".token.c_nonce_expires_at" => "[c_nonce_expires_at]"
    //     });
    // }
}
