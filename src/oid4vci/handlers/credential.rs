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

use chrono::{DateTime, Utc};
use credibil_infosec::Signer;
use credibil_infosec::jose::jws::{self, Key};
use tracing::instrument;

use crate::core::{Kind, generate};
use crate::oid4vci::endpoint::Request;
use crate::oid4vci::provider::{Metadata, Provider, StateStore, Subject};
use crate::oid4vci::state::{Deferrance, Expire, Stage, State};
use crate::oid4vci::types::{
    AuthorizedDetail, Credential, CredentialConfiguration, CredentialDefinition, CredentialDisplay,
    CredentialRequest, CredentialResponse, Dataset, Format, Issuer, MultipleProofs, Proof,
    ProofClaims, RequestBy, ResponseType, SingleProof,
};
use crate::oid4vci::{Error, Result};
use crate::status::issuer::Status;
use crate::verify_key;
use crate::w3c_vc::model::types::{LangString, LangValue};
use crate::w3c_vc::model::{CredentialSubject, VerifiableCredential};
use crate::w3c_vc::proof::{self, Payload, Type, W3cFormat};

/// Credential request handler.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
#[instrument(level = "debug", skip(provider))]
pub async fn credential(
    credential_issuer: &str, provider: impl Provider, request: CredentialRequest,
) -> Result<CredentialResponse> {
    let Ok(state) = StateStore::get::<State>(&provider, &request.access_token).await else {
        return Err(Error::AccessDenied("invalid access token".into()));
    };
    let issuer = Metadata::issuer(&provider, credential_issuer)
        .await
        .map_err(|e| Error::ServerError(format!("metadata issue: {e}")))?;

    // create a request context with data accessed more than once
    let mut ctx = Context {
        state,
        issuer,
        ..Context::default()
    };

    // authorized credential
    ctx.authorized = ctx.authorized_detail(&request)?;

    // credential configuration
    let Some(config_id) = ctx.authorized.credential_configuration_id() else {
        return Err(Error::InvalidCredentialRequest("no credential_configuration_id".to_string()));
    };
    let Some(config) = ctx.issuer.credential_configurations_supported.get(config_id) else {
        return Err(Error::ServerError("credential configuration unable to be found".into()));
    };
    ctx.configuration = config.clone();

    ctx.verify(&provider, &request).await?;
    ctx.process(&provider, request).await
}

impl Request for CredentialRequest {
    type Response = CredentialResponse;

    fn handle(
        self, credential_issuer: &str, provider: &impl Provider,
    ) -> impl Future<Output = Result<Self::Response>> + Send {
        credential(credential_issuer, provider.clone(), self)
    }
}

#[derive(Debug, Default)]
struct Context {
    state: State,
    issuer: Issuer,
    authorized: AuthorizedDetail,
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

        // TODO: refactor into separate function.
        if let Some(supported_types) = &self.configuration.proof_types_supported {
            let Some(proof) = &request.proof else {
                return Err(Error::InvalidProof("proof not set".to_string()));
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
                            return Err(Error::InvalidProof(format!("issue decoding JWT: {e}")));
                        }
                    };

                // proof type
                if jwt.header.typ != Type::Openid4VciProofJwt.to_string() {
                    return Err(Error::InvalidProof(format!(
                        "Proof JWT 'typ' ({}) is not {}",
                        jwt.header.typ,
                        Type::Openid4VciProofJwt
                    )));
                }

                // FIXME: check nonce in state
                // previously issued c_nonce
                // if jwt.claims.nonce.as_ref() != Some(&token_state.c_nonce) {
                //     return Err(Error::InvalidProof(
                //         "Proof JWT nonce claim is invalid".to_string(),
                //     ));
                // }

                // Key ID
                let Key::KeyId(kid) = &jwt.header.key else {
                    return Err(Error::InvalidProof("Proof JWT 'kid' is missing".to_string()));
                };

                // HACK: save extracted DID for later use when issuing credential
                let Some(did) = kid.split('#').next() else {
                    return Err(Error::InvalidProof("Proof JWT DID is invalid".to_string()));
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
        self.issue_response(provider, dataset).await
    }

    // Issue the requested credential.
    async fn issue_response(
        &self, provider: &impl Provider, dataset: Dataset,
    ) -> Result<CredentialResponse> {
        // generate the issuance time stamp
        let issuance_date = Utc::now();

        // determine credential format
        let response = match &self.configuration.format {
            Format::JwtVcJson(w3c) => {
                let vc = self.w3c_vc(provider, &w3c.credential_definition, dataset).await?;
                self.jwt_vc_json(vc, provider.clone(), issuance_date).await?
            }
            Format::IsoMdl(_) => self.mso_mdoc(dataset, provider.clone()).await?,

            // TODO: remaining credential formats
            Format::JwtVcJsonLd(_) => todo!(),
            Format::LdpVc(_) => todo!(),
            Format::VcSdJwt(_) => todo!(),
        };

        // update token state with new `c_nonce`
        let mut state = self.state.clone();
        state.expires_at = Utc::now() + Expire::Access.duration();

        let Stage::Validated(token_state) = state.stage else {
            return Err(Error::AccessDenied("invalid access token state".into()));
        };
        state.stage = Stage::Validated(token_state.clone());

        StateStore::put(provider, &token_state.access_token, &state, state.expires_at)
            .await
            .map_err(|e| Error::ServerError(format!("issue saving state: {e}")))?;

        // create issuance state for notification endpoint
        // TODO: save credential in state !!
        // state.stage = Stage::Issued(Credential { credential: vc, issuance: issuance_dt });
        let notification_id = generate::notification_id();

        StateStore::put(provider, &notification_id, &state, state.expires_at)
            .await
            .map_err(|e| Error::ServerError(format!("issue saving state: {e}")))?;

        Ok(CredentialResponse {
            response,
            notification_id: Some(notification_id),
        })
    }

    // Generate a W3C Verifiable Credential.
    async fn w3c_vc(
        &self, provider: &impl Provider, credential_definition: &CredentialDefinition,
        dataset: Dataset,
    ) -> Result<VerifiableCredential> {
        // credential type
        let Some(credential_type) = credential_definition.type_.get(1) else {
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
        &self, vc: VerifiableCredential, signer: impl Signer, issuance_date: DateTime<Utc>,
    ) -> Result<ResponseType> {
        // sign and return JWT
        let jwt = proof::create(
            W3cFormat::JwtVcJson,
            Payload::Vc {
                vc: vc.clone(),
                issued_at: issuance_date.timestamp(),
            },
            &signer,
        )
        .await
        .map_err(|e| {
            Error::ServerError(format!("issue generating `jwt_vc_json` credential: {e}"))
        })?;

        Ok(ResponseType::Credentials {
            credentials: vec![Credential {
                credential: Kind::String(jwt),
            }],
            notification_id: None,
        })
    }

    // Generate a `mso_mdoc` format credential.
    async fn mso_mdoc(&self, dataset: Dataset, signer: impl Signer) -> Result<ResponseType> {
        let mdl = crate::iso_mdl::to_credential(dataset.claims, signer).await.map_err(|e| {
            Error::ServerError(format!("issue generating `mso_mdoc` credential: {e}"))
        })?;

        Ok(ResponseType::Credentials {
            credentials: vec![Credential {
                credential: Kind::String(mdl),
            }],
            notification_id: None,
        })
    }

    // Defer issuance of the requested credential.
    async fn defer_response(
        &self, provider: &impl Provider, request: CredentialRequest,
    ) -> Result<CredentialResponse> {
        let txn_id = generate::transaction_id();

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
            response: ResponseType::TransactionId {
                transaction_id: txn_id,
            },
            notification_id: None,
        })
    }

    // Get `Authorized` for `credential_identifier` and
    // `credential_configuration_id`.
    fn authorized_detail(&self, request: &CredentialRequest) -> Result<AuthorizedDetail> {
        let Stage::Validated(token) = &self.state.stage else {
            return Err(Error::AccessDenied("invalid access token state".into()));
        };

        match &request.credential {
            RequestBy::Identifier(ident) => {
                for ad in &token.details {
                    if ad.credential_identifiers.contains(ident) {
                        return Ok(ad.clone());
                    }
                }
            }
            RequestBy::ConfigurationId(id) => {
                for ad in &token.details {
                    if Some(id.as_str()) == ad.credential_configuration_id() {
                        return Ok(ad.clone());
                    }
                }
            }
        }

        Err(Error::InvalidCredentialRequest("unauthorized credential requested".into()))
    }

    // Get credential dataset for the request
    async fn dataset(
        &self, provider: &impl Provider, request: &CredentialRequest,
    ) -> Result<Dataset> {
        let RequestBy::Identifier(identifier) = &request.credential else {
            return Err(Error::InvalidCredentialRequest(
                "requesting credentials by `credential_configuration_id` is unsupported"
                    .to_string(),
            ));
        };

        // get claims dataset for `credential_identifier`
        let Some(subject_id) = &self.state.subject_id else {
            return Err(Error::AccessDenied("invalid subject id".into()));
        };
        let dataset = Subject::dataset(provider, subject_id, identifier)
            .await
            .map_err(|e| Error::ServerError(format!("issue populating claims: {e}")))?;

        // FIXME: narrow claim set
        // only include previously requested/authorized claims
        // if let Some(claims) = &self.authorized.authorization_detail.claims {
        //     //dataset.claims.retain(|k, _| claims.iter().any(|c|c.path));
        // }

        Ok(dataset)
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
