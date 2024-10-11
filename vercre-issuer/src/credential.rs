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
use vercre_datasec::{SecOps, Signer};
use vercre_openid::issuer::{
    CredentialConfiguration, CredentialDefinition, CredentialDisplay, CredentialIssuance,
    CredentialRequest, CredentialResponse, CredentialResponseType, Dataset, FormatIdentifier,
    Issuer, Metadata, MultipleProofs, Proof, ProofClaims, Provider, SingleProof, StateStore,
    Subject,
};
use vercre_openid::{Error, Result};
use vercre_status::issuer::Status;
use vercre_w3c_vc::model::types::{LangString, LangValue};
use vercre_w3c_vc::model::{CredentialSubject, VerifiableCredential};
use vercre_w3c_vc::proof::{self, Format, Payload};
use vercre_w3c_vc::verify_key;

use crate::state::{Authorized, Deferrance, Expire, Stage, State};

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

    // create a request context with data accessed more than once
    let mut ctx = Context {
        state,
        issuer,
        ..Context::default()
    };

    // ...authorized credential
    ctx.authorized = ctx.authorized(&request)?;

    // ...credential configuration
    let config_id = &ctx.authorized.credential_configuration_id;
    let Some(config) = ctx.issuer.credential_configurations_supported.get(config_id) else {
        return Err(Error::ServerError("credential configuration unable to be found".into()));
    };
    ctx.configuration = config.clone();

    ctx.verify(&provider, &request).await?;
    ctx.process(&provider, request).await
}

#[derive(Debug, Default)]
struct Context {
    state: State,
    issuer: Issuer,
    authorized: Authorized,
    configuration: CredentialConfiguration,
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

        if token_state.c_nonce_expired() {
            return Err(Error::AccessDenied("c_nonce has expired".into()));
        }

        // TODO: refactor into separate function.
        if let Some(supported_types) = &self.configuration.proof_types_supported {
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

        let dataset = self.dataset(provider, &request).await?;

        // defer issuance as claims are pending (approval)
        if dataset.pending {
            return self.defer_response(provider, request).await;
        }

        // issue VC
        self.issue_response(provider, request, dataset).await
    }

    // Issue the requested credential.
    async fn issue_response(
        &self, provider: &impl Provider, request: CredentialRequest, dataset: Dataset,
    ) -> Result<CredentialResponse> {
        let signer = SecOps::signer(provider, &request.credential_issuer)
            .map_err(|e| Error::ServerError(format!("issue  resolving signer: {e}")))?;

        // determine credential format
        let response = match &self.configuration.format {
            FormatIdentifier::JwtVcJson(w3c) => {
                let vc = self.w3c_vc(provider, &w3c.credential_definition, dataset).await?;
                self.jwt_vc_json(vc, signer).await?
            }
            FormatIdentifier::IsoMdl(_) => self.mso_mdoc(dataset, signer).await?,

            // TODO: remaining credential formats
            FormatIdentifier::JwtVcJsonLd(_) => todo!(),
            FormatIdentifier::LdpVc(_) => todo!(),
            FormatIdentifier::VcSdJwt(_) => todo!(),
        };

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
        // TODO: save credential in state !!
        // state.stage = Stage::Issued(Credential { credential: vc });
        let notification_id = gen::notification_id();

        StateStore::put(provider, &notification_id, &state, state.expires_at)
            .await
            .map_err(|e| Error::ServerError(format!("issue saving state: {e}")))?;

        Ok(CredentialResponse {
            response,
            c_nonce: Some(token_state.c_nonce.clone()),
            c_nonce_expires_in: Some(token_state.c_nonce_expires_in()),
            notification_id: Some(notification_id),
        })
    }

    // Generate a W3C Verifiable Credential.
    // async fn w3c_vc(&self, issuer: String, type_: String,dataset: Map<String, Value>,
    //     status: Option<Quota<CredentialStatus>>) -> Result<VerifiableCredential> {

    async fn w3c_vc(
        &self, provider: &impl Provider, credential_definition: &CredentialDefinition,
        dataset: Dataset,
    ) -> Result<VerifiableCredential> {
        // credential type
        let Some(types) = &credential_definition.type_ else {
            return Err(Error::ServerError("Credential type not set".into()));
        };
        let Some(credential_type) = types.get(1) else {
            return Err(Error::ServerError("Credential type not set".into()));
        };

        // credential's status lookup information
        let Some(subject_id) = &self.state.subject_id else {
            return Err(Error::AccessDenied("invalid subject id".into()));
        };
        let status = Status::status(provider, subject_id, "credential_identifier")
            .await
            .map_err(|e| Error::ServerError(format!("issue populating credential status: {e}")))?;

        let credential_issuer = &self.issuer.credential_issuer;
        let (name, description) =
            self.configuration.display.as_ref().map_or((None, None), create_names);

        VerifiableCredential::builder()
            .add_context(Kind::String(format!("{credential_issuer}/credentials/v1")))
            // TODO: generate credential id
            .id(format!("{credential_issuer}/credentials/{credential_type}"))
            .add_type(credential_type)
            .add_name(name)
            .add_description(description)
            .issuer(credential_issuer)
            .add_subject(CredentialSubject {
                id: Some(self.holder_did.clone()),
                claims: dataset.claims,
            })
            .status(status)
            .build()
            .map_err(|e| Error::ServerError(format!("issue building VC: {e}")))
    }

    // Generate a `jwt_vc_json` format credential .
    async fn jwt_vc_json(
        &self, vc: VerifiableCredential, signer: impl Signer,
    ) -> Result<CredentialResponseType> {
        // sign and return JWT
        let jwt = proof::create(Format::JwtVcJson, Payload::Vc(vc.clone()), signer).await.map_err(
            |e| Error::ServerError(format!("issue generating `jwt_vc_json` credential: {e}")),
        )?;
        Ok(CredentialResponseType::Credential(Kind::String(jwt)))
    }

    // Generate a `mso_mdoc` format credential.
    async fn mso_mdoc(
        &self, dataset: Dataset, signer: impl Signer,
    ) -> Result<CredentialResponseType> {
        let mdl = vercre_iso_mdl::to_credential(dataset.claims, signer).await.map_err(|e| {
            Error::ServerError(format!("issue generating `mso_mdoc` credential: {e}"))
        })?;
        Ok(CredentialResponseType::Credential(Kind::String(mdl)))
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
                FormatIdentifier::IsoMdl(mdl) => mdl
                    .claims
                    .as_ref()
                    .map(|claimset| claimset.keys().cloned().collect::<Vec<String>>()),
                FormatIdentifier::VcSdJwt(sd_jwt) => sd_jwt
                    .claims
                    .as_ref()
                    .map(|claimset| claimset.keys().cloned().collect::<Vec<String>>()),
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

// Extract language object name and description from a `CredentialDisplay`
// vector.
fn create_names(display: &Vec<CredentialDisplay>) -> (Option<LangString>, Option<LangString>) {
    let mut name: Option<LangString> = None;
    let mut description: Option<LangString> = None;
    for d in display {
        let n = LangValue {
            value: d.name.clone(),
            language: d.locale.clone(),
            ..LangValue::default()
        };
        if let Some(nm) = &mut name {
            nm.add(n);
        } else {
            name = Some(LangString::new_object(n));
        }
        if d.description.is_some() {
            let d = LangValue {
                value: d.description.clone().unwrap(),
                language: d.locale.clone(),
                ..LangValue::default()
            };
            if let Some(desc) = &mut description {
                desc.add(d);
            } else {
                description = Some(LangString::new_object(d));
            }
        }
    }
    (name, description)
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
            ".validFrom" => "[validFrom]",
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
            ".validFrom" => "[validFrom]",
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

    #[tokio::test]
    #[ignore]
    async fn iso_mdl() {
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
                    "DriverLicence".into(),
                    Authorized {
                        credential_identifier: "DriverLicence".into(),
                        credential_configuration_id: "org.iso.18013.5.1.mDL".into(),
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
            "credential_identifier": "DriverLicence",
            "proof":{
                "proof_type": "jwt",
                "jwt": jwt
            }
        });
        let request = serde_json::from_value(value).expect("request is valid");

        let response = credential(provider.clone(), request).await.expect("response is valid");
        assert_snapshot!("credential:iso_mdl:response", &response, {
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

        assert_snapshot!("credential:iso_mdl:vc", vc, {
            ".validFrom" => "[validFrom]",
            ".credentialSubject" => insta::sorted_redaction(),
            ".credentialSubject.address" => insta::sorted_redaction()
        });

        // token state should remain unchanged
        assert_let!(Ok(state), StateStore::get::<State>(&provider, access_token).await);
        assert_snapshot!("credential:iso_mdl:state", state, {
            ".expires_at" => "[expires_at]",
            ".stage.c_nonce"=>"[c_nonce]",
            ".stage.c_nonce_expires_at" => "[c_nonce_expires_at]"
        });
    }
}
