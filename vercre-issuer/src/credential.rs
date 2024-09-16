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
use tracing::instrument;
use vercre_core::{gen, Kind};
use vercre_datasec::jose::jws::{self, KeyType, Type};
use vercre_datasec::SecOps;
use vercre_openid::issuer::{
    CredentialConfiguration, CredentialRequest, CredentialResponse, CredentialResponseType,
    CredentialSpec, Format, Issuer, Metadata, MultipleProofs, Proof, ProofClaims, Provider,
    SingleProof, StateStore, Subject,
};
use vercre_openid::{Error, Result};
use vercre_status::issuer::Status;
use vercre_w3c_vc::model::{CredentialSubject, VerifiableCredential};
use vercre_w3c_vc::proof::{self, Payload};
use vercre_w3c_vc::verify_key;

use crate::state::{Deferred, Expire, State, Step};

/// Credential request handler.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
#[instrument(level = "debug", skip(provider))]
pub async fn credential(
    provider: impl Provider, request: CredentialRequest,
) -> Result<CredentialResponse> {
    // get token state
    let Ok(state) = StateStore::get::<State>(&provider, &request.access_token).await else {
        return Err(Error::AccessDenied("invalid access token".into()));
    };

    let mut ctx = Context {
        state,
        issuer: Metadata::issuer(&provider, &request.credential_issuer)
            .await
            .map_err(|e| Error::ServerError(format!("metadata issue: {e}")))?,
        ..Context::default()
    };
    ctx.credential_config = ctx.configuration(&request.specification)?;

    ctx.verify(&provider, &request).await?;
    ctx.process(&provider, request).await
}

#[derive(Debug, Default)]
struct Context {
    issuer: Issuer,
    credential_config: CredentialConfiguration,
    state: State,
    holder_did: String,
}

impl Context {
    // TODO: check this list for compliance
    // To validate a key proof, ensure that:
    //   - the header parameter does not contain a private key
    //   - the creation time of the JWT, as determined by either the issuance time, or a server managed
    //     timestamp via the nonce claim, is within an acceptable window (see Section 11.5).

    // Verify the credential request
    async fn verify(
        &mut self, provider: &impl Provider, request: &CredentialRequest,
    ) -> Result<()> {
        tracing::debug!("credential::verify");

        if self.state.is_expired() {
            return Err(Error::InvalidRequest("state expired".into()));
        }

        let Step::Token(token_state) = &self.state.current_step else {
            return Err(Error::AccessDenied("invalid access token state".into()));
        };

        // c_nonce expiry
        if token_state.c_nonce_expired() {
            return Err(Error::AccessDenied("c_nonce has expired".into()));
        }

        // TODO: refactor into separate function.
        if let Some(supported_types) = &self.credential_config.proof_types_supported {
            let Some(proof) = &request.proof else {
                return Err(Error::InvalidCredentialRequest("proof not set".into()));
            };

            // TODO: cater for non-JWT proofs - use w3c-vc::decode method
            let _ = supported_types.get("jwt").ok_or_else(|| {
                Error::InvalidCredentialRequest("proof type not supported".into())
            })?;

            // extract proof JWT(s) from request
            let proof_jwts = match proof {
                Proof::Single { proof_type } => match proof_type {
                    SingleProof::Jwt { jwt } => &vec![jwt.clone()],
                },
                Proof::Multiple(proofs_type) => match proofs_type {
                    MultipleProofs::Jwt(proof_jwts) => proof_jwts,
                },
            };

            for proof_jwt in proof_jwts {
                // TODO: check proof is signed with supported algorithm (from proof_type)
                let jwt: jws::Jwt<ProofClaims> =
                    match jws::decode(proof_jwt, verify_key!(provider)).await {
                        Ok(jwt) => jwt,
                        Err(e) => {
                            let (c_nonce, c_nonce_expires_in) = self.err_nonce(provider).await?;
                            return Err(Error::InvalidProof {
                                hint: format!("issue decoding JWT: {e}"),
                                c_nonce,
                                c_nonce_expires_in,
                            });
                        }
                    };

                // proof type
                if jwt.header.typ != Type::Proof {
                    let (c_nonce, c_nonce_expires_in) = self.err_nonce(provider).await?;
                    return Err(Error::InvalidProof {
                        hint: format!("Proof JWT 'typ' is not {}", Type::Proof),
                        c_nonce,
                        c_nonce_expires_in,
                    });
                }

                // previously issued c_nonce
                if jwt.claims.nonce.as_ref() != Some(&token_state.c_nonce) {
                    let (c_nonce, c_nonce_expires_in) = self.err_nonce(provider).await?;
                    return Err(Error::InvalidProof {
                        hint: "Proof JWT nonce claim is invalid".into(),
                        c_nonce,
                        c_nonce_expires_in,
                    });
                }

                // Key ID
                let KeyType::KeyId(kid) = &jwt.header.key else {
                    let (c_nonce, c_nonce_expires_in) = self.err_nonce(provider).await?;

                    return Err(Error::InvalidProof {
                        hint: "Proof JWT 'kid' is missing".into(),
                        c_nonce,
                        c_nonce_expires_in,
                    });
                };

                // HACK: save extracted DID for later use when issuing credential
                let Some(did) = kid.split('#').next() else {
                    let (c_nonce, c_nonce_expires_in) = self.err_nonce(provider).await?;

                    return Err(Error::InvalidProof {
                        hint: "Proof JWT DID is invalid".into(),
                        c_nonce,
                        c_nonce_expires_in,
                    });
                };

                // TODO: support multiple DID bindings
                self.holder_did = did.into();
            }
        }

        Ok(())
    }

    // Process the credential request.
    async fn process(
        &self, provider: &impl Provider, request: CredentialRequest,
    ) -> Result<CredentialResponse> {
        tracing::debug!("credential::process");

        // attempt to generate VC
        let maybe_vc = self.generate_vc(provider, &request).await?;

        // sign and return VC (**OR** defer issuance)
        if let Some(vc) = maybe_vc {
            let signer = SecOps::signer(provider, &request.credential_issuer)
                .map_err(|e| Error::ServerError(format!("issue  resolving signer: {e}")))?;

            // TODO: add support for other formats
            let jwt =
                vercre_w3c_vc::proof::create(proof::Format::JwtVcJson, Payload::Vc(vc), signer)
                    .await
                    .map_err(|e| Error::ServerError(format!("issue creating proof: {e}")))?;

            // update state
            let mut state = self.state.clone();
            state.expires_at = Utc::now() + Expire::Access.duration();

            let Step::Token(mut token_state) = state.current_step else {
                return Err(Error::AccessDenied("invalid access token state".into()));
            };
            token_state.c_nonce = gen::nonce();
            token_state.c_nonce_expires_at = Utc::now() + Expire::Nonce.duration();
            state.current_step = Step::Token(token_state.clone());

            // TODO: save this into state
            let notification_id = gen::notification_id();

            StateStore::put(provider, &token_state.access_token, &state, state.expires_at)
                .await
                .map_err(|e| Error::ServerError(format!("issue saving state: {e}")))?;

            return Ok(CredentialResponse {
                response: CredentialResponseType::Credential(Kind::String(jwt)),
                c_nonce: Some(token_state.c_nonce.clone()),
                c_nonce_expires_in: Some(token_state.c_nonce_expires_in()),
                notification_id: Some(notification_id),
            });
        }

        // defer issuance
        let txn_id = gen::transaction_id();

        let state = State {
            expires_at: Utc::now() + Expire::Access.duration(),
            current_step: Step::Deferred(Deferred {
                transaction_id: txn_id.clone(),
                credential_request: request,
            }),
            ..State::default()
        };
        StateStore::put(provider, &txn_id, &state, state.expires_at)
            .await
            .map_err(|e| Error::ServerError(format!("issue saving state: {e}")))?;

        Ok(CredentialResponse {
            response: CredentialResponseType::TransactionId(txn_id),
            ..CredentialResponse::default()
        })
    }

    // Attempt to generate a Verifiable Credential from information provided in
    // the Credential Request. May return `None` if the credential is not ready
    // to be issued because the request for Subject is pending.
    async fn generate_vc(
        &self, provider: &impl Provider, request: &CredentialRequest,
    ) -> Result<Option<VerifiableCredential>> {
        tracing::debug!("credential::generate_vc");

        // let Some(credential_identifier) = &request.specification.as_identifier() else {
        //     return Err(Error::InvalidCredentialRequest("invalid credential request".into()));
        // };

        // --------------------------------------------------------------------
        // Get dataset
        //   TODO: support request by credential format (e.g. jwt_vc_json, etc.)
        //   need to get dataset by credential_configuration_id??
        // --------------------------------------------------------------------
        // get credential identifier and configuration
        let CredentialSpec::Identifier {
            credential_identifier,
        } = &request.specification
        else {
            return Err(Error::InvalidCredentialRequest("invalid credential request".into()));
        };

        // get claims dataset for `credential_identifier`
        let Some(subject_id) = &self.state.subject_id else {
            return Err(Error::AccessDenied("invalid subject id".into()));
        };
        let dataset = Subject::dataset(provider, subject_id, credential_identifier)
            .await
            .map_err(|e| Error::ServerError(format!("issue populating claims: {e}")))?;
        // --------------------------------------------------------------------

        // defer issuance if claims are pending (approval),
        if dataset.pending {
            return Ok(None);
        }

        let credential_issuer = &request.credential_issuer.clone();

        // TODO: improve `types` handling
        let definition = &self.credential_config.credential_definition;
        let Some(types) = &definition.type_ else {
            return Err(Error::ServerError("Credential type not set".into()));
        };
        let Some(credential_type) = types.get(1) else {
            return Err(Error::ServerError("Credential type not set".into()));
        };

        // Provider supplies status lookup information
        let status = Status::status(provider, subject_id, credential_identifier)
            .await
            .map_err(|e| Error::ServerError(format!("issue populating credential status: {e}")))?;

        let vc = VerifiableCredential::builder()
            .add_context(Kind::String(format!("{credential_issuer}/credentials/v1")))
            // TODO: generate credential id
            .id(format!("{credential_issuer}/credentials/{credential_type}"))
            .add_type(credential_type)
            .issuer(credential_issuer)
            .add_subject(CredentialSubject {
                id: Some(self.holder_did.clone()),
                claims: dataset.claims,
            })
            .status(status)
            .build()
            .map_err(|e| Error::ServerError(format!("issue building VC: {e}")))?;

        Ok(Some(vc))
    }

    // Get configuration metadata for requested credential
    fn configuration(&self, specification: &CredentialSpec) -> Result<CredentialConfiguration> {
        match specification {
            CredentialSpec::Identifier {
                credential_identifier,
            } => {
                let Some(credentials) = &self.state.credentials else {
                    return Err(Error::InvalidCredentialRequest(
                        "no authorized credentials".into(),
                    ));
                };
                let Some(config_id) = credentials.get(credential_identifier) else {
                    return Err(Error::InvalidCredentialRequest(
                        "unauthorized credential requested".into(),
                    ));
                };

                self.issuer.credential_configurations_supported.get(config_id).cloned().ok_or_else(
                    || Error::InvalidCredentialRequest("unsupported credential requested".into()),
                )
            }

            CredentialSpec::Format(Format::JwtVcJson { .. }) => {
                todo!("Format::JwtVcJson");
            }
            CredentialSpec::Format(Format::LdpVc { .. }) => {
                todo!("Format::LdpVc");
            }
            CredentialSpec::Format(Format::JwtVcJsonLd { .. }) => {
                todo!("Format::JwtVcJsonLd");
            }
            CredentialSpec::Format(Format::MsoDoc { .. }) => {
                todo!("Format::MsoDoc");
            }
            CredentialSpec::Format(Format::VcSdJwt { .. }) => {
                todo!("Format::VcSdJwt");
            }
        }
    }

    // Creates, stores, and returns new `c_nonce` and `c_nonce_expires`_in values
    // for use in `Error::InvalidProof` errors, as per specification.
    async fn err_nonce(&self, provider: &impl Provider) -> Result<(String, i64)> {
        // generate nonce and update state
        let c_nonce = gen::nonce();

        let mut state = self.state.clone();
        state.expires_at = Utc::now() + Expire::Access.duration();

        let Step::Token(mut token_state) = state.current_step else {
            return Err(Error::AccessDenied("invalid access token state".into()));
        };
        token_state.c_nonce.clone_from(&c_nonce);
        token_state.c_nonce_expires_at = Utc::now() + Expire::Nonce.duration();
        state.current_step = Step::Token(token_state.clone());

        StateStore::put(provider, &token_state.access_token, &state, state.expires_at)
            .await
            .map_err(|e| Error::ServerError(format!("issue saving state: {e}")))?;

        Ok((c_nonce, Expire::Nonce.duration().num_seconds()))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use assert_let_bind::assert_let;
    use insta::assert_yaml_snapshot as assert_snapshot;
    use vercre_macros::credential_request;
    use vercre_test_utils::issuer::{Provider, CLIENT_ID, CREDENTIAL_ISSUER, NORMAL_USER};
    use vercre_test_utils::{holder, snapshot};
    use vercre_w3c_vc::proof::{self, Verify};

    use super::*;
    use crate::state::Token;

    #[tokio::test]
    async fn identifier() {
        vercre_test_utils::init_tracer();
        snapshot!("");

        let provider = Provider::new();
        let access_token = "ABCDEF";
        let c_nonce = "1234ABCD";

        // set up state
        let state = State {
            expires_at: Utc::now() + Expire::Authorized.duration(),
            subject_id: Some(NORMAL_USER.into()),
            credentials: Some(HashMap::from([("PHLEmployeeID".into(), "EmployeeID_JWT".into())])),
            current_step: Step::Token(Token {
                access_token: access_token.into(),
                c_nonce: c_nonce.into(),
                c_nonce_expires_at: Utc::now() + Expire::Nonce.duration(),
            }),
            ..State::default()
        };

        StateStore::put(&provider, access_token, &state, state.expires_at)
            .await
            .expect("state exists");

        let claims = ProofClaims {
            iss: Some(CLIENT_ID.into()),
            aud: CREDENTIAL_ISSUER.into(),
            iat: Utc::now().timestamp(),
            nonce: Some(c_nonce.into()),
        };
        let jwt = jws::encode(Type::Proof, &claims, holder::Provider).await.expect("should encode");

        let request = credential_request!({
            "credential_issuer": CREDENTIAL_ISSUER,
            "access_token": access_token,
            "credential_identifier": "PHLEmployeeID",
            "proof":{
                "proof_type": "jwt",
                "jwt": jwt
            }
        });
        let response = credential(provider.clone(), request).await.expect("response is valid");
        assert_snapshot!("credential:identifier:response", &response, {
            ".credential" => "[credential]",
            ".c_nonce" => "[c_nonce]",
        });

        // verify credential
        let CredentialResponseType::Credential(vc_kind) = &response.response else {
            panic!("expected a single credential");
        };
        let Payload::Vc(vc) =
            proof::verify(Verify::Vc(&vc_kind), &provider).await.expect("should decode")
        else {
            panic!("should be VC");
        };

        assert_snapshot!("credential:identifier:vc", vc, {
            ".issuanceDate" => "[issuanceDate]",
            ".credentialSubject" => insta::sorted_redaction()
        });

        // token state should remain unchanged
        assert_let!(Ok(state), StateStore::get::<State>(&provider, access_token).await);
        assert_snapshot!("credential:identifier:state", state, {
            ".expires_at" => "[expires_at]",
            ".current_step.c_nonce"=>"[c_nonce]",
            ".current_step.c_nonce_expires_at" => "[c_nonce_expires_at]"
        });
    }

    #[tokio::test]
    #[ignore]
    async fn format() {
        vercre_test_utils::init_tracer();
        snapshot!("");

        let provider = Provider::new();
        let access_token = "ABCDEF";
        let c_nonce = "1234ABCD";

        // set up state
        let state = State {
            expires_at: Utc::now() + Expire::Authorized.duration(),
            subject_id: Some(NORMAL_USER.into()),
            credentials: Some(HashMap::from([("PHLEmployeeID".into(), "EmployeeID_JWT".into())])),
            current_step: Step::Token(Token {
                access_token: access_token.into(),
                c_nonce: c_nonce.into(),
                c_nonce_expires_at: Utc::now() + Expire::Nonce.duration(),
            }),
            ..State::default()
        };

        StateStore::put(&provider, access_token, &state, state.expires_at)
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

        let request = credential_request!({
            "credential_issuer": CREDENTIAL_ISSUER,
            "access_token": access_token,
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
        let response = credential(provider.clone(), request).await.expect("response is valid");

        assert_snapshot!("credential:format:response", &response, {
            ".credential" => "[credential]",
            ".c_nonce" => "[c_nonce]",
        });

        // verify credential
        let CredentialResponseType::Credential(vc_kind) = &response.response else {
            panic!("expected a single credential");
        };
        let Payload::Vc(vc) = vercre_w3c_vc::proof::verify(Verify::Vc(&vc_kind), &provider)
            .await
            .expect("should decode")
        else {
            panic!("should be VC");
        };

        assert_snapshot!("vc", vc, {
            ".issuanceDate" => "[issuanceDate]",
            ".credentialSubject" => insta::sorted_redaction()
        });

        // token state should remain unchanged
        assert_let!(Ok(state), StateStore::get::<State>(&provider, access_token).await);
        assert_snapshot!("credential:format:state", state, {
            ".expires_at" => "[expires_at]",
            ".current_step.c_nonce"=>"[c_nonce]",
            ".current_step.c_nonce_expires_at" => "[c_nonce_expires_at]"
        });
    }
}
