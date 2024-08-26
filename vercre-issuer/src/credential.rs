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
use vercre_core::{gen, Kind, Quota};
use vercre_datasec::jose::jws::{self, KeyType, Type};
use vercre_datasec::SecOps;
use vercre_openid::issuer::{
    AuthorizationSpec, CredentialConfiguration, CredentialRequest, CredentialResponse,
    CredentialSpec, Issuer, Metadata, ProofClaims, ProofOption, ProofType, ProofsType, Provider,
    StateStore, Subject,
};
use vercre_openid::{Error, Result};
use vercre_w3c_vc::model::{CredentialSubject, VerifiableCredential};
use vercre_w3c_vc::proof::{Format, Payload};
use vercre_w3c_vc::verify_key;

use crate::state::{Deferred, Expire, State, Step, Token};

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
    // get token state
    let Ok(state) = StateStore::get::<State>(&provider, &request.access_token).await else {
        return Err(Error::AccessDenied("invalid access token".into()));
    };
    let Step::Token(token_state) = state.current_step else {
        return Err(Error::AccessDenied("invalid access token state".into()));
    };

    let mut ctx = Context {
        state: token_state,
        issuer_config: Metadata::issuer(&provider, &request.credential_issuer)
            .await
            .map_err(|e| Error::ServerError(format!("metadata issue: {e}")))?,
        holder_did: String::new(),
    };

    ctx.verify(provider.clone(), request).await?;
    ctx.process(provider, request).await
}

#[derive(Debug)]
struct Context {
    issuer_config: Issuer,
    state: Token,
    holder_did: String,
}

impl Context {
    #[allow(clippy::too_many_lines)]
    async fn verify(&mut self, provider: impl Provider, request: &CredentialRequest) -> Result<()> {
        tracing::debug!("credential::verify");

        // c_nonce expiry
        if self.state.c_nonce_expired() {
            return Err(Error::AccessDenied("c_nonce has expired".into()));
        }

        let mut credential_config = &CredentialConfiguration::default();

        match &request.specification {
            CredentialSpec::Identifier {
                credential_identifier,
            } => {
                // check request has been authorized
                let auth_details = self.state.authorized.as_ref().ok_or_else(|| {
                    Error::InvalidCredentialRequest("request not authorized".into())
                })?;

                let mut authorized = false;
                for authzd in auth_details {
                    if authzd.credential_identifiers.contains(credential_identifier) {
                        let AuthorizationSpec::ConfigurationId(config_id) =
                            &authzd.authorization_detail.credential_type
                        else {
                            return Err(Error::InvalidCredentialRequest(
                                "credential configuration not found".into(),
                            ));
                        };
                        let Some(config) =
                            self.issuer_config.credential_configurations_supported.get(config_id)
                        else {
                            return Err(Error::InvalidCredentialRequest(
                                "credential configuration not found".into(),
                            ));
                        };

                        credential_config = config;
                        authorized = true;
                        break;
                    }
                }

                if !authorized {
                    return Err(Error::InvalidCredentialRequest(
                        "requested credential has not been authorized".into(),
                    ));
                }
            }
            CredentialSpec::Definition {
                format,
                credential_definition,
            } => {
                // check request has been authorized:
                //   - match format + type against authorized items in state
                let authorized = false;

                for config in self.issuer_config.credential_configurations_supported.values() {
                    if (&config.format == format)
                        && (config.credential_definition.type_ == credential_definition.type_)
                    {
                        credential_config = config;

                        // FIXME: get credential identifiers from current_step
                        // authorized =
                        break;
                    }
                }

                if !authorized {
                    return Err(Error::InvalidCredentialRequest(
                        "requested credential has not been authorized".into(),
                    ));
                }
            }
        };

        let supported_proofs = credential_config.proof_types_supported.as_ref();

        // TODO: refactor into separate function.
        if let Some(supported_types) = supported_proofs {
            let Some(proof) = &request.proof else {
                return Err(Error::InvalidCredentialRequest("proof not set".into()));
            };

            // TODO: recheck this list for compliance
            // To validate a key proof, ensure that:
            //   - all required claims for that proof type are contained as defined in Section 7.2.1
            //   - the key proof is explicitly typed using header parameters as defined for that proof type
            //   - the header parameter indicates a registered asymmetric digital signature algorithm, alg
            //     parameter value is not none, is supported by the application, and is acceptable per local policy
            //   - the signature on the key proof verifies with the public key contained in the header parameter
            //   - the header parameter does not contain a private key
            //   - the nonce claim (or Claim Key 10) matches the server-provided c_nonce value, if the server
            //     had previously provided a c_nonce
            //   - the creation time of the JWT, as determined by either the issuance time, or a server managed
            //     timestamp via the nonce claim, is within an acceptable window (see Section 11.5).

            // TODO: cater for non-JWT proofs
            let _ = supported_types.get("jwt").ok_or_else(|| {
                Error::InvalidCredentialRequest("proof type not supported".into())
            })?;

            // extract proof JWT(s) from request
            let proof_jwts = match proof {
                ProofOption::Single { proof_type } => match proof_type {
                    ProofType::Jwt { jwt } => &vec![jwt.clone()],
                },
                ProofOption::Multiple(proofs_type) => match proofs_type {
                    ProofsType::Jwt(proof_jwts) => proof_jwts,
                },
            };

            for proof_jwt in proof_jwts {
                // TODO: check proof is signed with supported algorithm (from proof_type)
                let jwt: jws::Jwt<ProofClaims> =
                    match jws::decode(proof_jwt, verify_key!(&provider)).await {
                        Ok(jwt) => jwt,
                        Err(e) => {
                            let (c_nonce, c_nonce_expires_in) = self.err_nonce(&provider).await?;
                            return Err(Error::InvalidProof {
                                hint: format!("issue decoding JWT: {e}"),
                                c_nonce,
                                c_nonce_expires_in,
                            });
                        }
                    };
                // proof type
                if jwt.header.typ != Type::Proof {
                    let (c_nonce, c_nonce_expires_in) = self.err_nonce(&provider).await?;
                    return Err(Error::InvalidProof {
                        hint: format!("Proof JWT 'typ' is not {}", Type::Proof),
                        c_nonce,
                        c_nonce_expires_in,
                    });
                }

                // previously issued c_nonce
                if jwt.claims.nonce.as_ref() != Some(&self.state.c_nonce) {
                    let (c_nonce, c_nonce_expires_in) = self.err_nonce(&provider).await?;
                    return Err(Error::InvalidProof {
                        hint: "Proof JWT nonce claim is invalid".into(),
                        c_nonce,
                        c_nonce_expires_in,
                    });
                }

                // TODO: use `decode` method in w3c-vc
                // Key ID
                let KeyType::KeyId(kid) = &jwt.header.key else {
                    let (c_nonce, c_nonce_expires_in) = self.err_nonce(&provider).await?;

                    return Err(Error::InvalidProof {
                        hint: "Proof JWT 'kid' is missing".into(),
                        c_nonce,
                        c_nonce_expires_in,
                    });
                };
                // HACK: save extracted DID for later use when issuing credential
                let Some(did) = kid.split('#').next() else {
                    let (c_nonce, c_nonce_expires_in) = self.err_nonce(&provider).await?;

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

    async fn process(
        &self, provider: impl Provider, request: &CredentialRequest,
    ) -> Result<CredentialResponse> {
        tracing::debug!("credential::process");

        // update token state
        let mut token_state = self.state.clone();
        token_state.c_nonce = gen::nonce();
        token_state.c_nonce_expires_at = Utc::now() + Expire::Nonce.duration();

        let state = State {
            expires_at: Utc::now() + Expire::Access.duration(),
            current_step: Step::Token(token_state.clone()),
            ..State::default()
        };
        StateStore::put(&provider, &token_state.access_token, &state, state.expires_at)
            .await
            .map_err(|e| Error::ServerError(format!("issue saving state: {e}")))?;

        // generate response
        let mut response = CredentialResponse {
            c_nonce: Some(token_state.c_nonce.clone()),
            c_nonce_expires_in: Some(token_state.c_nonce_expires_in()),
            ..CredentialResponse::default()
        };

        // attempt to generate VC
        let maybe_vc = self.generate_vc(provider.clone(), request).await?;

        // sign and return VC **OR** defer issuance
        if let Some(vc) = maybe_vc {
            let signer = SecOps::signer(&provider, &request.credential_issuer)
                .map_err(|e| Error::ServerError(format!("issue  resolving signer: {e}")))?;

            // FIXME: add supprt for other formats
            let jwt = vercre_w3c_vc::proof::create(Format::JwtVcJson, Payload::Vc(vc), signer)
                .await
                .map_err(|e| Error::ServerError(format!("issue creating proof: {e}")))?;

            response.credential = Some(Quota::One(Kind::String(jwt)));
        } else {
            // if no VC, defer issuance
            let txn_id = gen::transaction_id();

            let state = State {
                expires_at: Utc::now() + Expire::Access.duration(),
                current_step: Step::Deferred(Deferred {
                    transaction_id: txn_id.clone(),
                    credential_request: request.clone(),
                }),
                ..State::default()
            };
            StateStore::put(&provider, &txn_id.clone(), &state, state.expires_at)
                .await
                .map_err(|e| Error::ServerError(format!("issue saving state: {e}")))?;

            response.transaction_id = Some(txn_id);
        }

        Ok(response)
    }

    // Attempt to generate a Verifiable Credential from information provided in the Credential
    // Request. May return `None` if the credential is not ready to be issued because the request
    // for Subject is pending.
    async fn generate_vc(
        &self, provider: impl Provider, request: &CredentialRequest,
    ) -> Result<Option<VerifiableCredential>> {
        tracing::debug!("credential::generate_vc");

        // get credential identifier and configuration
        let (identifier, config) = self.configuration(request)?;

        // get ALL claims for holder/credential
        let dataset = Subject::dataset(&provider, &self.state.subject_id, &identifier)
            .await
            .map_err(|e| Error::ServerError(format!("issue populating claims: {e}")))?;

        // defer issuance if claims are pending (approval?),
        if dataset.pending {
            return Ok(None);
        }

        // FIXME: add support for CredentialSpec::Definition
        // TODO: need to check authorized claims (claims in credential offer or authorization request)

        // let definition = credential_definition(request, &config);

        // retain ONLY requested (and mandatory) claims
        // let cred_subj = &definition.credential_subject.unwrap_or_default();
        // if let Some(req_cred_def) = &request.credential_definition {
        //     if let Some(req_cred_subj) = &req_cred_def.credential_subject {
        //         let mut claims = dataset.claims;
        //         claims.retain(|key, _| {
        //             req_cred_subj.get(key).is_some() || cred_subj.get(key).is_some()
        //         });
        //         dataset.claims = claims;
        //     }
        // }

        let credential_issuer = &self.issuer_config.credential_issuer;
        let definition = config.credential_definition;
        let Some(types) = definition.type_ else {
            return Err(Error::ServerError("Credential type not set".into()));
        };

        let vc_id = format!("{credential_issuer}/credentials/{}", types[1].clone());

        let vc = VerifiableCredential::builder()
            .add_context(Kind::String(credential_issuer.clone() + "/credentials/v1"))
            // TODO: generate credential id
            .id(vc_id)
            .add_type(types[1].clone())
            .issuer(credential_issuer.clone())
            .add_subject(CredentialSubject {
                // FIXME: holder_did is not populated
                id: Some(self.holder_did.clone()),
                claims: dataset.claims,
            })
            .build()
            .map_err(|e| Error::ServerError(format!("issue building VC: {e}")))?;

        Ok(Some(vc))
    }

    fn configuration(
        &self, request: &CredentialRequest,
    ) -> Result<(String, CredentialConfiguration)> {
        // get credential configuration from request

        match &request.specification {
            CredentialSpec::Identifier {
                credential_identifier,
            } => {
                // look up credential_identifier in state::Authorized
                let all_authorized = self.state.authorized.as_ref().ok_or_else(|| {
                    Error::InvalidCredentialRequest("credential is not authorized".into())
                })?;

                // find match
                let Some(authorized) = all_authorized
                    .iter()
                    .find(|auth| auth.credential_identifiers.contains(credential_identifier))
                else {
                    return Err(Error::InvalidCredentialRequest(
                        "credential is not authorized".into(),
                    ));
                };

                // get `credential_configuration_id` from `authorization_detail`
                let AuthorizationSpec::ConfigurationId(config_id) =
                    &authorized.authorization_detail.credential_type
                else {
                    return Err(Error::InvalidCredentialRequest(
                        "no matching `credential_configuration_id`".into(),
                    ));
                };

                // get credential configuration
                let Some(config) =
                    self.issuer_config.credential_configurations_supported.get(config_id)
                else {
                    return Err(Error::InvalidCredentialRequest(
                        "credential is not supported".into(),
                    ));
                };

                Ok((credential_identifier.clone(), config.clone()))
            }
            CredentialSpec::Definition {
                format,
                credential_definition,
            } => {
                let Some(id_config) =
                    self.issuer_config.credential_configurations_supported.iter().find(|(_, v)| {
                        &v.format == format
                            && v.credential_definition.type_ == credential_definition.type_
                    })
                else {
                    return Err(Error::InvalidCredentialRequest(
                        "credential is not supported".into(),
                    ));
                };
                Ok((id_config.0.clone(), id_config.1.clone()))
            }
        }
    }

    // Creates, stores, and returns new `c_nonce` and `c_nonce_expires`_in values
    // for use in `Error::InvalidProof` errors, as per specification.
    async fn err_nonce(&self, provider: &impl Provider) -> Result<(String, i64)> {
        // generate nonce and update state
        let c_nonce = gen::nonce();

        let mut token_state = self.state.clone();
        token_state.c_nonce.clone_from(&c_nonce);
        token_state.c_nonce_expires_at = Utc::now() + Expire::Nonce.duration();

        let state = State {
            expires_at: Utc::now() + Expire::Access.duration(),
            current_step: Step::Token(token_state.clone()),
            ..State::default()
        };

        StateStore::put(provider, &token_state.access_token, &state, state.expires_at)
            .await
            .map_err(|e| Error::ServerError(format!("issue saving state: {e}")))?;

        Ok((c_nonce, Expire::Nonce.duration().num_seconds()))
    }
}

#[cfg(test)]
mod tests {
    use assert_let_bind::assert_let;
    use insta::assert_yaml_snapshot as assert_snapshot;
    use serde_json::json;
    use vercre_openid::issuer::{
        AuthorizationDetail, AuthorizationDetailType, AuthorizationSpec, Authorized,
    };
    use vercre_test_utils::issuer::{Provider, CLIENT_ID, CREDENTIAL_ISSUER, NORMAL_USER};
    use vercre_test_utils::{holder, snapshot};
    use vercre_w3c_vc::proof::Verify;

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
        let mut state = State {
            expires_at: Utc::now() + Expire::Authorized.duration(),
            ..State::default()
        };

        state.current_step = Step::Token(Token {
            access_token: access_token.into(),
            c_nonce: c_nonce.into(),
            c_nonce_expires_at: Utc::now() + Expire::Nonce.duration(),
            subject_id: NORMAL_USER.into(),
            authorized: Some(vec![Authorized {
                authorization_detail: AuthorizationDetail {
                    type_: AuthorizationDetailType::OpenIdCredential,
                    credential_type: AuthorizationSpec::ConfigurationId("EmployeeID_JWT".into()),
                    ..AuthorizationDetail::default()
                },
                credential_identifiers: vec!["PHLEmployeeID".into()],
            }]),
            scope: None,
        });

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

        let mut request =
            serde_json::from_value::<CredentialRequest>(value).expect("request should deserialize");
        request.credential_issuer = CREDENTIAL_ISSUER.into();
        request.access_token = access_token.into();

        let response = credential(provider.clone(), &request).await.expect("response is valid");
        assert_snapshot!("credential:identifier:response", &response, {
            ".credential" => "[credential]",
            ".c_nonce" => "[c_nonce]",
        });

        // verify credential
        let vc_quota = response.credential.expect("credential is present");
        let Quota::One(vc_kind) = vc_quota else {
            panic!("expected one credential")
        };

        let Payload::Vc(vc) = vercre_w3c_vc::proof::verify(Verify::Vc(&vc_kind), &provider)
            .await
            .expect("should decode")
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
    async fn format() {
        vercre_test_utils::init_tracer();
        snapshot!("");

        let provider = Provider::new();
        let access_token = "ABCDEF";
        let c_nonce = "1234ABCD";

        // set up state
        let mut state = State {
            expires_at: Utc::now() + Expire::Authorized.duration(),
            ..State::default()
        };

        state.current_step = Step::Token(Token {
            access_token: access_token.into(),
            c_nonce: c_nonce.into(),
            c_nonce_expires_at: Utc::now() + Expire::Nonce.duration(),
            // FIXME: use authorization_details to hold credential identifiers
            // credential_identifiers: credentials,
            subject_id: NORMAL_USER.into(),
            authorized: Some(vec![Authorized {
                authorization_detail: AuthorizationDetail {
                    type_: AuthorizationDetailType::OpenIdCredential,
                    credential_type: AuthorizationSpec::ConfigurationId("EmployeeID_JWT".into()),
                    ..AuthorizationDetail::default()
                },
                credential_identifiers: vec!["PHLEmployeeID".into()],
            }]),
            scope: None,
        });

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

        let request =
            serde_json::from_value::<CredentialRequest>(value).expect("request should deserialize");
        let response = credential(provider.clone(), &request).await.expect("response is valid");

        assert_snapshot!("credential:format:response", &response, {
            ".credential" => "[credential]",
            ".c_nonce" => "[c_nonce]",
        });

        // verify credential
        let vc_quota = response.credential.expect("credential is present");
        let Quota::One(vc_kind) = vc_quota else {
            panic!("expected one credential")
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
