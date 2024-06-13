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

use anyhow::anyhow;
use chrono::Utc;
use tracing::instrument;
use vercre_core::error::{Ancillary as _, Err};
use vercre_core::metadata::{CredentialDefinition, Issuer};
use vercre_core::provider::{
    Callback, ClientMetadata, IssuerMetadata, ServerMetadata, StateManager, Subject,
};
use vercre_core::vci::ProofClaims;
#[allow(clippy::module_name_repetitions)]
pub use vercre_core::vci::{
    BatchCredentialRequest, BatchCredentialResponse, CredentialRequest, CredentialResponse,
};
use vercre_core::{err, gen, Result};
use vercre_vc::model::{CredentialSubject, VerifiableCredential};
use vercre_vc::proof::{self, Signer, Type};

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
            err!(Err::AccessDenied, "invalid access token");
        };
        let Ok(state) = State::try_from(buf) else {
            err!(Err::AccessDenied, "invalid state for access token");
        };

        let ctx = Context {
            callback_id: state.callback_id.clone(),
            state,
            issuer_meta: IssuerMetadata::metadata(&self.provider, &request.credential_issuer)
                .await?,
            holder_did: String::new(),
            _p: std::marker::PhantomData,
        };

        vercre_core::Endpoint::handle_request(self, request, ctx).await
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

impl<P> vercre_core::Context for Context<P>
where
    P: IssuerMetadata + Subject + StateManager + Signer + Clone + Debug,
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
            err!(Err::AccessDenied, "invalid access token state");
        };

        // c_nonce expiry
        if token_state.c_nonce_expired() {
            err!(Err::AccessDenied, "c_nonce has expired");
        }

        // TODO: add support for `credential_identifier`
        // verify each credential request
        for request in &request.credential_requests {
            if request.format.is_some() && request.credential_identifier.is_some() {
                return Err(Err::InvalidCredentialRequest)
                    .hint("format and credential_identifier cannot both be set");
            };
            if request.format.is_none() && request.credential_identifier.is_none() {
                return Err(Err::InvalidCredentialRequest)
                    .hint("format or credential_identifier must be set");
            };

            // format and type request
            if let Some(format) = &request.format {
                let Some(cred_def) = &request.credential_definition else {
                    err!(Err::InvalidCredentialRequest, "credential definition not set");
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
                    return Err(Err::InvalidCredentialRequest)
                        .hint("Requested credential has not been authorized");
                }
            };

            // ----------------------------------------------------------------
            // TODO: check `proof_types_supported` param in `credential_configurations_supported`
            // is non-empty
            // ----------------------------------------------------------------
            let Some(proof) = &request.proof else {
                err!(Err::InvalidCredentialRequest, "proof not set");
            };
            // ----------------------------------------------------------------

            let Some(proof_jwt) = &proof.jwt else {
                let (nonce, expires_in) = self.err_nonce(provider).await?;
                err!(Err::InvalidProof(nonce, expires_in), "Proof not set");
            };

            // TODO: allow passing verifier into this method
            let jwt: vercre_proof::jose::Jwt<ProofClaims> =
                match vercre_proof::jose::decode(proof_jwt) {
                    Ok(jwt) => jwt,
                    Err(e) => {
                        let (nonce, expires_in) = self.err_nonce(provider).await?;
                        err!(Err::InvalidProof(nonce, expires_in), "{}", e.to_string());
                    }
                };
            // proof type
            if jwt.header.typ != vercre_proof::jose::Typ::Proof {
                let (nonce, expires_in) = self.err_nonce(provider).await?;
                err!(
                    Err::InvalidProof(nonce, expires_in),
                    "Proof JWT 'typ' is not {}",
                    vercre_proof::jose::Typ::Proof
                );
            }

            // previously issued c_nonce
            if jwt.claims.nonce.as_ref() != Some(&token_state.c_nonce) {
                let (nonce, expires_in) = self.err_nonce(provider).await?;
                err!(Err::InvalidProof(nonce, expires_in), "Proof JWT nonce claim is invalid");
            }

            // TODO: use `decode` method in vercre-vc
            // Key ID
            let Some(kid) = jwt.header.kid else {
                let (nonce, expires_in) = self.err_nonce(provider).await?;
                err!(Err::InvalidProof(nonce, expires_in), "Proof JWT 'kid' is missing");
            };
            // HACK: save extracted DID for later use when issuing credential
            let Some(did) = kid.split('#').next() else {
                let (nonce, expires_in) = self.err_nonce(provider).await?;
                err!(Err::InvalidProof(nonce, expires_in), "Proof JWT DID is invalid");
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
            err!("Invalid token state");
        };

        // --------------------------------------------------------------------
        // TODO: refresh c_nonce and c_nonce_expires_at
        // -> requires c_nonce HashMap in State to cater for deferred requests
        //    with proof based on an older c_nonce
        // --------------------------------------------------------------------
        // let Some(provider) = &self.provider else {
        //     err!("provider not set");
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

            let buf = serde_json::to_vec(&state)?;
            StateManager::put(provider, &txn_id, buf, state.expires_at).await?;

            // only need to return transaction_id
            return Ok(CredentialResponse {
                transaction_id: Some(txn_id),

                // TODO: add `c_nonce` and `c_nonce_expires_in` to CredentialResponse
                ..CredentialResponse::default()
            });
        };

        // generate proof for the credential
        let proof = Type::Vc(vc);
        let jwt = proof::create(proof, provider.clone()).await?;

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
            err!(Err::AccessDenied, "holder not found");
        };

        // claim values
        let holder_claims = Subject::claims(provider, holder_id, &cred_def).await?;
        if holder_claims.pending {
            return Ok(None);
        }

        // check mandatory claims are populated
        let Some(cred_subj) = cred_def.credential_subject.clone() else {
            err!("Credential subject not set");
        };
        for (name, claim) in &cred_subj {
            if claim.mandatory.unwrap_or_default() && !holder_claims.claims.contains_key(name) {
                err!(Err::InvalidCredentialRequest, "mandatory claim {name} not populated");
            }
        }

        let credential_issuer = &self.issuer_meta.credential_issuer;

        // HACK: fix this
        let Some(types) = cred_def.type_ else {
            err!("Credential type not set");
        };

        let vc_id = format!("{credential_issuer}/credentials/{}", types[1].clone());

        let vc = VerifiableCredential::builder()
            .add_context(credential_issuer.clone() + "/credentials/v1")
            // TODO: generate credential id
            .id(vc_id)
            .add_type(types[1].clone())
            .issuer(credential_issuer.clone())
            .add_subject(CredentialSubject {
                id: Some(self.holder_did.clone()),
                claims: holder_claims.claims,
            })
            // .add_proof(proof)
            .build()?;

        Ok(Some(vc))
    }

    // Get the request's credential definition. If it does not exist, create it.
    fn credential_definition(&self, request: &CredentialRequest) -> Result<CredentialDefinition> {
        tracing::debug!("Context::credential_definition");

        if let Some(mut cred_def) = request.credential_definition.clone() {
            // add credential subject when not present
            if cred_def.credential_subject.is_none() {
                let maybe_supported = request.credential_identifier.as_ref().map_or_else(
                    || {
                        self.issuer_meta.credential_configurations_supported.values().find(|v| {
                            Some(&v.format) == request.format.as_ref()
                                && v.credential_definition.type_ == cred_def.type_
                        })
                    },
                    |id| self.issuer_meta.credential_configurations_supported.get(id),
                );

                let Some(supported) = maybe_supported else {
                    err!(Err::InvalidCredentialRequest, "credential is not supported");
                };

                // copy credential subject
                cred_def
                    .credential_subject
                    .clone_from(&supported.credential_definition.credential_subject);
            };

            Ok(cred_def)
        } else {
            let Some(id) = &request.credential_identifier else {
                err!(Err::InvalidCredentialRequest, "no credential identifier");
            };
            let Some(supported) = self.issuer_meta.credential_configurations_supported.get(id)
            else {
                err!(Err::InvalidCredentialRequest, "no supported credential for identifier {id}");
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
            err!("token state not set");
        };

        let c_nonce = gen::nonce();
        token_state.c_nonce.clone_from(&c_nonce);
        token_state.c_nonce_expires_at = Utc::now() + Expire::Nonce.duration();
        state.token = Some(token_state.clone());

        StateManager::put(provider, &token_state.access_token, state.to_vec(), state.expires_at)
            .await?;

        Ok((c_nonce, Expire::Nonce.duration().num_seconds()))
    }
}

#[cfg(test)]
mod tests {
    use assert_let_bind::assert_let;
    use insta::assert_yaml_snapshot as assert_snapshot;
    use providers::issuance::{Provider, CREDENTIAL_ISSUER, NORMAL_USER};
    use providers::wallet;
    use serde_json::json;

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
            iss: Some(wallet::CLIENT_ID.into()),
            aud: CREDENTIAL_ISSUER.into(),
            iat: Utc::now().timestamp(),
            nonce: Some(c_nonce.into()),
        };
        let jwt = vercre_proof::jose::encode(
            vercre_proof::jose::Typ::Proof,
            &claims,
            wallet::Provider::new(),
        )
        .await
        .expect("should encode");

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
        let proof::Type::Vc(vc) =
            proof::verify(&token, proof::DataType::Vc).await.expect("should decode")
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
    //         iss: wallet::CLIENT_ID,
    //         aud: CREDENTIAL_ISSUER.into(),
    //         iat: Utc::now().timestamp(),
    //         nonce: c_nonce.into(),
    //     };
    //     let jwt = proof::create(Type::ProofJwt(claims), wallet::Provider::new())

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
    //     let vc_b64 = serde_json::from_value::<String>(vc_val).expect("base64 encoded string");
    //     let vc_jwt = Jwt::<VcClaims>::from_str(&vc_b64).expect("should encode");
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
