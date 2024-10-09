//! # Batch Credential Endpoint
//!
//! The Batch Credential Endpoint issues multiple Credentials in one Batch
//! Credential Response as approved by the End-User upon presentation of a valid
//! Access Token representing this approval.
//!
//! A Wallet can request issuance of multiple Credentials of certain types and
//! formats in one Batch Credential Request. This includes Credentials of the
//! same type and multiple formats, different types and one format, or both.

use std::fmt::Debug;

use chrono::Utc;
use tracing::instrument;
use vercre_core::{gen, Kind};
use vercre_datasec::jose::jws::{self, KeyType, Type};
use vercre_datasec::SecOps;
use vercre_openid::issuer::{
    CredentialIssuance, CredentialRequest, CredentialResponse, CredentialResponseType, Dataset,
    FormatIdentifier, Issuer, Metadata, MultipleProofs, ProfileW3c, Proof, ProofClaims, Provider,
    SingleProof, StateStore, Subject,
};
use vercre_openid::{Error, Result};
use vercre_status::issuer::Status;
use vercre_w3c_vc::model::{CredentialSubject, VerifiableCredential};
use vercre_w3c_vc::proof::{self, Payload};
use vercre_w3c_vc::verify_key;

use crate::state::{Authorized, Credential, Deferrance, Expire, Stage, State};

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
    let Ok(state) = StateStore::get::<State>(&provider, &request.access_token).await else {
        return Err(Error::AccessDenied("invalid access token".into()));
    };
    let issuer = Metadata::issuer(&provider, &request.credential_issuer)
        .await
        .map_err(|e| Error::ServerError(format!("metadata issue: {e}")))?;

    // save data accessed more than once for later use
    let mut ctx = Context {
        state,
        issuer,
        ..Context::default()
    };
    ctx.authorized = ctx.authorized(&request)?;

    ctx.verify(&provider, &request).await?;
    ctx.process(&provider, request).await
}

#[derive(Debug, Default)]
struct Context {
    state: State,
    issuer: Issuer,
    authorized: Authorized,
    holder_did: String,
}

impl Context {
    // TODO: check this list for compliance
    // To validate a key proof, ensure that:
    //   - the header parameter does not contain a private key
    //   - the creation time of the JWT, as determined by either the issuance time,
    //     or a server managed timestamp via the nonce claim, is within an
    //     acceptable window (see Section 11.5).

    // Verify the credential request
    async fn verify(
        &mut self, provider: &impl Provider, request: &CredentialRequest,
    ) -> Result<()> {
        tracing::debug!("credential::verify");

        if self.state.is_expired() {
            return Err(Error::InvalidCredentialRequest("token state expired".into()));
        }

        let Stage::Validated(token_state) = &self.state.stage else {
            return Err(Error::AccessDenied("invalid access token state".into()));
        };

        // c_nonce expiry
        if token_state.c_nonce_expired() {
            return Err(Error::AccessDenied("c_nonce has expired".into()));
        }

        // TODO: refactor into separate function.
        let config_id = &self.authorized.credential_configuration_id;
        let config =
            self.issuer.credential_configurations_supported.get(config_id).ok_or_else(|| {
                Error::InvalidCredentialRequest("unsupported credential requested".into())
            })?;

        if let Some(supported_types) = &config.proof_types_supported {
            let Some(proof) = &request.proof else {
                return Err(self.invalid_proof(provider, "proof not set").await?);
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
                            return Err(self
                                .invalid_proof(provider, format!("issue decoding JWT: {e}"))
                                .await?);
                        }
                    };

                // proof type
                if jwt.header.typ != Type::Proof {
                    return Err(self
                        .invalid_proof(provider, format!("Proof JWT 'typ' is not {}", Type::Proof))
                        .await?);
                }

                // previously issued c_nonce
                if jwt.claims.nonce.as_ref() != Some(&token_state.c_nonce) {
                    return Err(self
                        .invalid_proof(provider, "Proof JWT nonce claim is invalid")
                        .await?);
                }

                // Key ID
                let KeyType::KeyId(kid) = &jwt.header.key else {
                    return Err(self.invalid_proof(provider, "Proof JWT 'kid' is missing").await?);
                };

                // HACK: save extracted DID for later use when issuing credential
                let Some(did) = kid.split('#').next() else {
                    return Err(self.invalid_proof(provider, "Proof JWT DID is invalid").await?);
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

        // sign and return VC or defer issuance
        if let Some(vc) = self.issue_vc(provider, &request).await? {
            self.issue_response(provider, request, vc).await
        } else {
            self.defer_response(provider, request).await
        }
    }

    // Attempt to generate a Verifiable Credential from information provided in
    // the Credential Request. May return `None` if the credential is not ready
    // to be issued because the request for Subject is pending.
    async fn issue_vc(
        &self, provider: &impl Provider, request: &CredentialRequest,
    ) -> Result<Option<VerifiableCredential>> {
        tracing::debug!("credential::generate_vc");

        let dataset = self.dataset(provider, request).await?;

        // defer issuance if claims are pending (approval),
        if dataset.pending {
            return Ok(None);
        }

        let credential_issuer = &request.credential_issuer.clone();

        // TODO: improve `types` handling
        let config_id = &self.authorized.credential_configuration_id;
        let config =
            self.issuer.credential_configurations_supported.get(config_id).ok_or_else(|| {
                Error::InvalidCredentialRequest("unsupported credential requested".into())
            })?;

        let FormatIdentifier::JwtVcJson(ProfileW3c {
            credential_definition,
        }) = &config.format
        else {
            return Err(Error::InvalidCredentialRequest(
                "unsupported credential_definition".into(),
            ));
        };

        let Some(types) = &credential_definition.type_ else {
            return Err(Error::ServerError("Credential type not set".into()));
        };
        let Some(credential_type) = types.get(1) else {
            return Err(Error::ServerError("Credential type not set".into()));
        };

        // Provider supplies status lookup information
        let Some(subject_id) = &self.state.subject_id else {
            return Err(Error::AccessDenied("invalid subject id".into()));
        };
        let status = Status::status(provider, subject_id, "credential_identifier")
            .await
            .map_err(|e| Error::ServerError(format!("issue populating credential status: {e}")))?;

        let vc = VerifiableCredential::builder()
            .add_context(Kind::String(format!("{credential_issuer}/credentials/v1")))
            // TODO: generate credential id, configurable by issuer. ID may be omitted.
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

    // Issue the requested credential.
    async fn issue_response(
        &self, provider: &impl Provider, request: CredentialRequest, vc: VerifiableCredential,
    ) -> Result<CredentialResponse> {
        let signer = SecOps::signer(provider, &request.credential_issuer)
            .map_err(|e| Error::ServerError(format!("issue  resolving signer: {e}")))?;

        // TODO: add support for other formats
        let jwt =
            vercre_w3c_vc::proof::create(proof::Format::JwtVcJson, Payload::Vc(vc.clone()), signer)
                .await
                .map_err(|e| Error::ServerError(format!("issue creating proof: {e}")))?;

        // update token state with new `c_nonce`
        let mut state = self.state.clone();
        state.expires_at = Utc::now() + Expire::Access.duration();

        let Stage::Validated(mut token_state) = state.stage else {
            return Err(Error::AccessDenied("invalid access token state".into()));
        };
        token_state.c_nonce = gen::nonce();
        token_state.c_nonce_expires_at = Utc::now() + Expire::Nonce.duration();
        state.stage = Stage::Validated(token_state.clone());

        StateStore::put(provider, &token_state.access_token, &state, state.expires_at)
            .await
            .map_err(|e| Error::ServerError(format!("issue saving state: {e}")))?;

        // create issuance state for notification endpoint
        state.stage = Stage::Issued(Credential { credential: vc });
        let notification_id = gen::notification_id();

        StateStore::put(provider, &notification_id, &state, state.expires_at)
            .await
            .map_err(|e| Error::ServerError(format!("issue saving state: {e}")))?;

        Ok(CredentialResponse {
            response: CredentialResponseType::Credential(Kind::String(jwt)),
            c_nonce: Some(token_state.c_nonce.clone()),
            c_nonce_expires_in: Some(token_state.c_nonce_expires_in()),
            notification_id: Some(notification_id),
        })
    }

    // Defer issuance of the requested credential.
    async fn defer_response(
        &self, provider: &impl Provider, request: CredentialRequest,
    ) -> Result<CredentialResponse> {
        let txn_id = gen::transaction_id();

        let state = State {
            subject_id: None,
            stage: Stage::Deferred(Deferrance {
                transaction_id: txn_id.clone(),
                credential_request: request,
            }),
            expires_at: Utc::now() + Expire::Access.duration(),
        };
        StateStore::put(provider, &txn_id, &state, state.expires_at)
            .await
            .map_err(|e| Error::ServerError(format!("issue saving state: {e}")))?;

        Ok(CredentialResponse {
            response: CredentialResponseType::TransactionId(txn_id),
            ..CredentialResponse::default()
        })
    }

    // Get `Authorized` for `credential_identifier` and
    // `credential_configuration_id`.
    fn authorized(&self, request: &CredentialRequest) -> Result<Authorized> {
        let Stage::Validated(token) = &self.state.stage else {
            return Err(Error::AccessDenied("invalid access token state".into()));
        };

        match &request.credential {
            CredentialIssuance::Identifier {
                credential_identifier,
            } => token.credentials.get(credential_identifier),
            CredentialIssuance::Format(f) => {
                let config_id = self.issuer.credential_configuration_id(f).map_err(|e| {
                    Error::UnsupportedFormat(format!("invalid credential format: {e}"))
                })?;
                token.credentials.values().find(|c| &c.credential_configuration_id == config_id)
            }
        }
        .ok_or_else(|| Error::InvalidCredentialRequest("unauthorized credential requested".into()))
        .cloned()
    }

    // Get credential dataset for the request
    async fn dataset(
        &self, provider: &impl Provider, request: &CredentialRequest,
    ) -> Result<Dataset> {
        let identifier = &self.authorized.credential_identifier;

        // get claims dataset for `credential_identifier`
        let Some(subject_id) = &self.state.subject_id else {
            return Err(Error::AccessDenied("invalid subject id".into()));
        };
        let mut dataset = Subject::dataset(provider, subject_id, identifier)
            .await
            .map_err(|e| Error::ServerError(format!("issue populating claims: {e}")))?;

        // narrow claimset to those previously authorized
        if let Some(claim_ids) = &self.authorized.claim_ids {
            dataset.claims.retain(|k, _| claim_ids.contains(k));
        }

        // narrow of claimset from format/credential_definition
        if let CredentialIssuance::Format(fmt) = &request.credential {
            let claim_ids = match &fmt {
                FormatIdentifier::JwtVcJson(w3c)
                | FormatIdentifier::JwtVcJsonLd(w3c)
                | FormatIdentifier::LdpVc(w3c) => w3c
                    .credential_definition
                    .credential_subject
                    .as_ref()
                    .map(|subj| subj.keys().cloned().collect::<Vec<String>>()),
                FormatIdentifier::IsoMdl(_) => {
                    todo!("ProfileClaims::IsoMdl");
                }
                FormatIdentifier::VcSdJwt(_) => {
                    todo!("ProfileClaims::SdJwt");
                }
            };

            if let Some(claim_ids) = &claim_ids {
                dataset.claims.retain(|k, _| claim_ids.contains(k));
            }
        };

        Ok(dataset)
    }

    // Creates, stores, and returns new `c_nonce` and `c_nonce_expires`_in values
    // for use in `Error::InvalidProof` errors, as per specification.
    async fn invalid_proof(
        &self, provider: &impl Provider, hint: impl Into<String> + Send,
    ) -> Result<Error> {
        // generate nonce and update token state
        let c_nonce = gen::nonce();
        let mut state = self.state.clone();
        state.expires_at = Utc::now() + Expire::Access.duration();

        let Stage::Validated(mut token_state) = state.stage else {
            return Err(Error::AccessDenied("invalid access token state".into()));
        };
        token_state.c_nonce.clone_from(&c_nonce);
        token_state.c_nonce_expires_at = Utc::now() + Expire::Nonce.duration();
        state.stage = Stage::Validated(token_state.clone());

        StateStore::put(provider, &token_state.access_token, &state, state.expires_at)
            .await
            .map_err(|e| Error::ServerError(format!("issue saving state: {e}")))?;

        Ok(Error::InvalidProof {
            hint: hint.into(),
            c_nonce,
            c_nonce_expires_in: Expire::Nonce.duration().num_seconds(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use assert_let_bind::assert_let;
    use insta::assert_yaml_snapshot as assert_snapshot;
    use serde_json::json;
    use vercre_test_utils::issuer::{Provider, CLIENT_ID, CREDENTIAL_ISSUER, NORMAL_USER};
    use vercre_test_utils::{holder, snapshot};
    use vercre_w3c_vc::proof::{self, Verify};

    use super::*;
    use crate::state::{Authorized, Token};

    #[tokio::test]
    async fn identifier() {
        vercre_test_utils::init_tracer();
        snapshot!("");

        let provider = Provider::new();
        let access_token = "ABCDEF";
        let c_nonce = "1234ABCD";

        // set up state
        let state = State {
            stage: Stage::Validated(Token {
                access_token: access_token.into(),
                credentials: HashMap::from([(
                    "PHLEmployeeID".into(),
                    Authorized {
                        credential_identifier: "PHLEmployeeID".into(),
                        credential_configuration_id: "EmployeeID_JWT".into(),
                        claim_ids: None,
                    },
                )]),
                c_nonce: c_nonce.into(),
                c_nonce_expires_at: Utc::now() + Expire::Nonce.duration(),
            }),
            subject_id: Some(NORMAL_USER.into()),
            expires_at: Utc::now() + Expire::Authorized.duration(),
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

        let value = json!({
            "credential_issuer": CREDENTIAL_ISSUER,
            "access_token": access_token,
            "credential_identifier": "PHLEmployeeID",
            "proof":{
                "proof_type": "jwt",
                "jwt": jwt
            }
        });
        let request = serde_json::from_value(value).expect("request is valid");

        let response = credential(provider.clone(), request).await.expect("response is valid");
        assert_snapshot!("credential:identifier:response", &response, {
            ".credential" => "[credential]",
            ".c_nonce" => "[c_nonce]",
            ".notification_id" => "[notification_id]",
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
            ".credentialSubject" => insta::sorted_redaction(),
            ".credentialSubject.address" => insta::sorted_redaction()
        });

        // token state should remain unchanged
        assert_let!(Ok(state), StateStore::get::<State>(&provider, access_token).await);
        assert_snapshot!("credential:identifier:state", state, {
            ".expires_at" => "[expires_at]",
            ".stage.c_nonce"=>"[c_nonce]",
            ".stage.c_nonce_expires_at" => "[c_nonce_expires_at]"
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
            stage: Stage::Validated(Token {
                access_token: access_token.into(),
                credentials: HashMap::from([(
                    "PHLEmployeeID".into(),
                    Authorized {
                        credential_identifier: "PHLEmployeeID".into(),
                        credential_configuration_id: "EmployeeID_JWT".into(),
                        claim_ids: None,
                    },
                )]),
                c_nonce: c_nonce.into(),
                c_nonce_expires_at: Utc::now() + Expire::Nonce.duration(),
            }),
            subject_id: Some(NORMAL_USER.into()),
            expires_at: Utc::now() + Expire::Authorized.duration(),
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

        let value = json!({
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
        let request = serde_json::from_value(value).expect("request is valid");
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
            ".stage.c_nonce"=>"[c_nonce]",
            ".stage.c_nonce_expires_at" => "[c_nonce_expires_at]"
        });
    }
}
