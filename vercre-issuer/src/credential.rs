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
    CredentialConfiguration, CredentialDefinition, CredentialRequest, CredentialResponse,
    CredentialType, Issuer, Metadata, ProofClaims, ProofOption, ProofType, ProofsType, Provider,
    StateStore, Subject,
};
use vercre_openid::{Error, Result};
use vercre_w3c_vc::model::{CredentialSubject, VerifiableCredential};
use vercre_w3c_vc::proof::{Format, Payload};
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
    provider: impl Provider, request: &CredentialRequest,
) -> Result<CredentialResponse> {
    let Ok(buf) = StateStore::get(&provider, &request.access_token).await else {
        return Err(Error::AccessDenied("invalid access token".into()));
    };
    let Ok(state) = State::try_from(buf) else {
        return Err(Error::AccessDenied("invalid state for access token".into()));
    };

    let mut ctx = Context {
        state,
        issuer_config: Metadata::issuer(&provider, &request.credential_issuer)
            .await
            .map_err(|e| Error::ServerError(format!("metadata issue: {e}")))?,
        holder_did: String::new(),
    };

    verify(&mut ctx, provider.clone(), request).await?;
    process(&ctx, provider, request).await
}

#[derive(Debug)]
struct Context {
    issuer_config: Issuer,
    state: State,
    holder_did: String,
}

#[allow(clippy::too_many_lines)]
async fn verify(
    context: &mut Context, provider: impl Provider, request: &CredentialRequest,
) -> Result<()> {
    tracing::debug!("credential::verify");

    let Step::Token(token_state) = &context.state.current_step else {
        return Err(Error::AccessDenied("invalid access token state".into()));
    };

    // c_nonce expiry
    if token_state.c_nonce_expired() {
        return Err(Error::AccessDenied("c_nonce has expired".into()));
    }

    let mut supported_proofs = None;

    // TODO: add support for `credential_identifier`

    // format and type request
    if let CredentialType::Format(format) = &request.credential_type {
        let Some(definition) = &request.credential_definition else {
            return Err(Error::InvalidCredentialRequest("credential definition not set".into()));
        };

        // check request has been authorized:
        //   - match format + type against authorized items in state
        let mut authorized = false;

        for (identifier, config) in &context.issuer_config.credential_configurations_supported {
            if (&config.format == format)
                && (config.credential_definition.type_ == definition.type_)
            {
                supported_proofs = config.proof_types_supported.as_ref();
                authorized = context.state.credential_identifiers.contains(identifier);
                break;
            }
        }

        if !authorized {
            return Err(Error::InvalidCredentialRequest(
                "Requested credential has not been authorized".into(),
            ));
        }
    };

    // TODO: refactor into separate function.
    if let Some(supported_types) = supported_proofs {
        let Some(proof_option) = &request.proof_option else {
            return Err(Error::InvalidCredentialRequest("proof not set".into()));
        };

        // TODO: recheck this list for compliance
        // To validate a key proof, ensure that:
        //   - all required claims for that proof type are contained as defined
        //     in Section 7.2.1
        //   - the key proof is explicitly typed using header parameters as
        //     defined for that proof type
        //   - the header parameter indicates a registered asymmetric digital
        //     signature algorithm, alg parameter value is not none, is supported
        //     by the application, and is acceptable per local policy
        //   - the signature on the key proof verifies with the public key
        //     contained in the header parameter
        //   - the header parameter does not contain a private key
        //   - the nonce claim (or Claim Key 10) matches the server-provided
        //     c_nonce value, if the server had previously provided a c_nonce
        //   - the creation time of the JWT, as determined by either the issuance
        //      time, or a server managed timestamp via the nonce claim, is within
        //      an acceptable window (see Section 11.5).

        // TODO: cater for non-JWT proofs
        let _ = supported_types
            .get("jwt")
            .ok_or_else(|| Error::InvalidCredentialRequest("proof type not supported".into()))?;

        // extract proof JWT(s) from request
        let proof_jwts = match proof_option {
            ProofOption::Proof { proof_type } => match proof_type {
                ProofType::Jwt { jwt } => &vec![jwt.clone()],
            },
            ProofOption::Proofs(proofs_type) => match proofs_type {
                ProofsType::Jwt(proof_jwts) => proof_jwts,
            },
        };

        for proof_jwt in proof_jwts {
            // TODO: check proof is signed with supported algorithm (from proof_type)
            let jwt: jws::Jwt<ProofClaims> =
                match jws::decode(proof_jwt, verify_key!(&provider)).await {
                    Ok(jwt) => jwt,
                    Err(e) => {
                        let (c_nonce, c_nonce_expires_in) = err_nonce(context, &provider).await?;
                        return Err(Error::InvalidProof {
                            hint: format!("issue decoding JWT: {e}"),
                            c_nonce,
                            c_nonce_expires_in,
                        });
                    }
                };
            // proof type
            if jwt.header.typ != Type::Proof {
                let (c_nonce, c_nonce_expires_in) = err_nonce(context, &provider).await?;
                return Err(Error::InvalidProof {
                    hint: format!("Proof JWT 'typ' is not {}", Type::Proof),
                    c_nonce,
                    c_nonce_expires_in,
                });
            }

            // previously issued c_nonce
            if jwt.claims.nonce.as_ref() != Some(&token_state.c_nonce) {
                let (c_nonce, c_nonce_expires_in) = err_nonce(context, &provider).await?;
                return Err(Error::InvalidProof {
                    hint: "Proof JWT nonce claim is invalid".into(),
                    c_nonce,
                    c_nonce_expires_in,
                });
            }

            // TODO: use `decode` method in w3c-vc
            // Key ID
            let KeyType::KeyId(kid) = &jwt.header.key else {
                let (c_nonce, c_nonce_expires_in) = err_nonce(context, &provider).await?;

                return Err(Error::InvalidProof {
                    hint: "Proof JWT 'kid' is missing".into(),
                    c_nonce,
                    c_nonce_expires_in,
                });
            };
            // HACK: save extracted DID for later use when issuing credential
            let Some(did) = kid.split('#').next() else {
                let (c_nonce, c_nonce_expires_in) = err_nonce(context, &provider).await?;

                return Err(Error::InvalidProof {
                    hint: "Proof JWT DID is invalid".into(),
                    c_nonce,
                    c_nonce_expires_in,
                });
            };

            // TODO: support multiple DID bindings
            context.holder_did = did.into();
        }
    }

    Ok(())
}

async fn process(
    context: &Context, provider: impl Provider, request: &CredentialRequest,
) -> Result<CredentialResponse> {
    tracing::debug!("credential::process");

    // generate new nonce
    let mut state = context.state.clone();
    let Step::Token(mut token_state) = state.current_step else {
        return Err(Error::ServerError("Invalid token state".into()));
    };
    token_state.c_nonce = gen::nonce();
    token_state.c_nonce_expires_at = Utc::now() + Expire::Nonce.duration();
    state.current_step = Step::Token(token_state.clone());

    let mut response = CredentialResponse {
        c_nonce: Some(token_state.c_nonce.clone()),
        c_nonce_expires_in: Some(token_state.c_nonce_expires_in()),
        ..CredentialResponse::default()
    };
    let state_key: String;

    // if no VC is returned, issuance is deferred
    if let Some(credential) = create_vc(context, provider.clone(), request).await? {
        // sign credential (as jwt)
        let signer = SecOps::signer(&provider, &request.credential_issuer)
            .map_err(|e| Error::ServerError(format!("issue  resolving signer: {e}")))?;
        let jwt = vercre_w3c_vc::proof::create(Format::JwtVcJson, Payload::Vc(credential), signer)
            .await
            .map_err(|e| Error::ServerError(format!("issue creating proof: {e}")))?;

        state_key = token_state.access_token;
        response.credential = Some(Quota::One(Kind::String(jwt)));
    } else {
        let txn_id = gen::transaction_id();
        state.current_step = Step::Deferred(Deferred {
            transaction_id: txn_id.clone(),
            credential_request: request.clone(),
        });

        state_key = txn_id.clone();
        response.transaction_id = Some(txn_id);
    }

    // update state
    StateStore::put(&provider, &state_key, state.to_vec()?, state.expires_at)
        .await
        .map_err(|e| Error::ServerError(format!("issue saving state: {e}")))?;

    Ok(response)
}

// Attempt to generate a Verifiable Credential from information provided in the Credential
// Request. May return `None` if the credential is not ready to be issued because the request
// for Subject is pending.
async fn create_vc(
    context: &Context, provider: impl Provider, request: &CredentialRequest,
) -> Result<Option<VerifiableCredential>> {
    tracing::debug!("credential::create_vc");

    // get credential identifier and configuration
    let (identifier, config) = credential_configuration(context, request)?;
    let definition = credential_definition(request, &config);

    let Some(subject_id) = &context.state.subject_id else {
        return Err(Error::AccessDenied("holder not found".into()));
    };

    // get ALL claims for holder/credential
    let mut claims_resp = Subject::claims(&provider, subject_id, &identifier)
        .await
        .map_err(|e| Error::ServerError(format!("issue populating claims: {e}")))?;

    // defer issuance if claims are pending (approval?),
    if claims_resp.pending {
        return Ok(None);
    }

    // TODO: need to check authorized claims (claims in credential offer or authorization request)
    // retain ONLY requested (and mandatory) claims
    let cred_subj_def = &definition.credential_subject.unwrap_or_default();
    if let Some(req_cred_def) = &request.credential_definition {
        if let Some(req_cred_subj) = &req_cred_def.credential_subject {
            let mut claims = claims_resp.claims;
            claims.retain(|key, _| {
                req_cred_subj.get(key).is_some() || cred_subj_def.get(key).is_some()
            });
            claims_resp.claims = claims;
        }
    }

    let credential_issuer = &context.issuer_config.credential_issuer;

    // HACK: fix this (AW: why is this a hack?)
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
            id: Some(context.holder_did.clone()),
            claims: claims_resp.claims,
        })
        .build()
        .map_err(|e| Error::ServerError(format!("issue building VC: {e}")))?;

    Ok(Some(vc))
}

fn credential_configuration(
    context: &Context, request: &CredentialRequest,
) -> Result<(String, CredentialConfiguration)> {
    match &request.credential_type {
        CredentialType::Identifier(identifier) => {
            let Some(config) =
                context.issuer_config.credential_configurations_supported.get(identifier)
            else {
                return Err(Error::InvalidCredentialRequest("credential is not supported".into()));
            };
            Ok((identifier.clone(), config.clone()))
        }
        CredentialType::Format(format) => {
            let Some(definition) = &request.credential_definition else {
                return Err(Error::InvalidCredentialRequest(
                    "credential definition not set".into(),
                ));
            };
            let Some(id_config) =
                context.issuer_config.credential_configurations_supported.iter().find(|(_, v)| {
                    &v.format == format && v.credential_definition.type_ == definition.type_
                })
            else {
                return Err(Error::InvalidCredentialRequest("credential is not supported".into()));
            };
            Ok((id_config.0.clone(), id_config.1.clone()))
        }
    }
}

/// Creates, stores, and returns new `c_nonce` and `c_nonce_expires`_in values
/// for use in `Error::InvalidProof` errors, as per specification.
async fn err_nonce(context: &Context, provider: &impl Provider) -> Result<(String, i64)> {
    // generate nonce and update state
    let mut state = context.state.clone();
    let Step::Token(mut token_state) = state.current_step else {
        return Err(Error::ServerError("token state not set".into()));
    };

    let c_nonce = gen::nonce();
    token_state.c_nonce.clone_from(&c_nonce);
    token_state.c_nonce_expires_at = Utc::now() + Expire::Nonce.duration();
    state.current_step = Step::Token(token_state.clone());

    StateStore::put(provider, &token_state.access_token, state.to_vec()?, state.expires_at)
        .await
        .map_err(|e| Error::ServerError(format!("issue saving state: {e}")))?;

    Ok((c_nonce, Expire::Nonce.duration().num_seconds()))
}

// Get the request's credential definition. If it does not exist, create it.
fn credential_definition(
    request: &CredentialRequest, config: &CredentialConfiguration,
) -> CredentialDefinition {
    tracing::debug!("credential::credential_definition");

    let mut definition =
        request.credential_definition.clone().unwrap_or_else(|| CredentialDefinition {
            context: None,
            type_: config.credential_definition.type_.clone(),
            credential_subject: config.credential_definition.credential_subject.clone(),
        });

    // add credential subject when not present
    if definition.credential_subject.is_none() {
        definition.credential_subject.clone_from(&config.credential_definition.credential_subject);
    };

    definition
}

#[cfg(test)]
mod tests {
    use assert_let_bind::assert_let;
    use insta::assert_yaml_snapshot as assert_snapshot;
    use serde_json::json;
    use vercre_test_utils::holder;
    use vercre_test_utils::issuer::{Provider, CLIENT_ID, CREDENTIAL_ISSUER, NORMAL_USER};
    use vercre_w3c_vc::proof::Verify;

    use super::*;
    use crate::state::Token;

    #[tokio::test]
    async fn credential_ok() {
        vercre_test_utils::init_tracer();

        let provider = Provider::new();
        let access_token = "ABCDEF";
        let c_nonce = "1234ABCD";
        let credentials = vec!["EmployeeID_JWT".into()];

        // set up state
        let mut state = State {
            expires_at: Utc::now() + Expire::Authorized.duration(),
            credential_identifiers: credentials,
            subject_id: Some(NORMAL_USER.into()),
            ..State::default()
        };

        state.current_step = Step::Token(Token {
            access_token: access_token.into(),
            c_nonce: c_nonce.into(),
            c_nonce_expires_at: Utc::now() + Expire::Nonce.duration(),
        });

        let ser = state.to_vec().expect("should serialize");
        StateStore::put(&provider, access_token, ser, state.expires_at).await.expect("state saved");

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
        assert_let!(Ok(buf), StateStore::get(&provider, access_token).await);
        let state = State::try_from(buf).expect("state is valid");
        assert_snapshot!("state", state, {
            ".expires_at" => "[expires_at]",
            ".current_step.c_nonce"=>"[c_nonce]",
            ".current_step.c_nonce_expires_at" => "[c_nonce_expires_at]"
        });
    }

    #[tokio::test]
    async fn authorization_details() {
        vercre_test_utils::init_tracer();

        let provider = Provider::new();
        let access_token = "ABCDEF";
        let c_nonce = "1234ABCD";
        let credentials = vec!["EmployeeID_JWT".into()];

        // set up state
        let mut state = State {
            expires_at: Utc::now() + Expire::Authorized.duration(),
            credential_identifiers: credentials,
            subject_id: Some(NORMAL_USER.into()),
            ..State::default()
        };

        state.current_step = Step::Token(Token {
            access_token: access_token.into(),
            c_nonce: c_nonce.into(),
            c_nonce_expires_at: Utc::now() + Expire::Nonce.duration(),
        });

        let ser = state.to_vec().expect("should serialize");
        StateStore::put(&provider, access_token, ser, state.expires_at)
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
        });

        let mut request =
            serde_json::from_value::<CredentialRequest>(body).expect("request should deserialize");
        request.credential_issuer = CREDENTIAL_ISSUER.into();
        request.access_token = access_token.into();

        let response = credential(provider.clone(), &request).await.expect("response is valid");
        assert_snapshot!("ad-response", &response, {
            ".credential" => "[credential]",
            ".c_nonce" => "[c_nonce]",
            ".c_nonce_expires_in" => "[c_nonce_expires_in]"
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

        assert_snapshot!("ad-vc", vc, {
            ".issuanceDate" => "[issuanceDate]",
            ".credentialSubject" => insta::sorted_redaction()
        });

        // token state should remain unchanged
        assert_let!(Ok(buf), StateStore::get(&provider, access_token).await);
        let state = State::try_from(buf).expect("state is valid");
        assert_snapshot!("ad-state", state, {
            ".expires_at" => "[expires_at]",
            ".current_step.c_nonce"=>"[c_nonce]",
            ".current_step.c_nonce_expires_at" => "[c_nonce_expires_at]"
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
    //         .expires_at(Utc::now() + Expire::Authorized.duration())
    //         .subject_id(Some(NORMAL_USER.into()))
    //         .build()
    //         .expect("should build state");

    //     state.token = Some(Token {
    //         access_token: access_token.into(),
    //         token_type: "Bearer".into(),
    //         c_nonce: c_nonce.into(),
    //         c_nonce_expires_at: Utc::now() + Expire::Nonce.duration(),
    //         ..Default::default()
    //     });

    //     StateStore::put(&provider, access_token, state.to_vec(), state.expires_at)
    //         .await
    //         .expect("state exists");

    //     // create CredentialRequest to 'send' to the app

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

    //     let mut request = serde_json::from_value::<CredentialRequest>(body)
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
    //     assert_let!(Ok(buf), StateStore::get(&provider, access_token).await);
    //     let state = State::try_from(buf).expect("state is valid");
    //     assert_snapshot!("ci-state", state, {
    //         ".expires_at" => "[expires_at]",
    //         ".token.c_nonce"=>"[c_nonce]",
    //         ".token.c_nonce_expires_at" => "[c_nonce_expires_at]"
    //     });
    // }
}
