//! # Response Endpoint
//!
//! This endpoint is where the Wallet **redirects** to when returning an [RFC6749](https://www.rfc-editor.org/rfc/rfc6749.html).
//! Authorization Response when both Wallet and Verifier interact on the same
//! device. That is, during a 'same-device flow'.
//!
//! The Wallet only returns a VP Token if the corresponding Authorization
//! Request contained a `presentation_definition` parameter, a
//! `presentation_definition_uri` parameter, or a `scope` parameter representing
//! a Presentation Definition.
//!
//! The VP Token can be returned in the Authorization Response or the Token
//! Response depending on the Response Type used.
//!
//! If the Authorization Request's Response Type value is "`vp_token`", the VP
//! Token is returned in the Authorization Response. When the Response Type
//! value is "`vp_token id_token`" and the scope parameter contains "openid",
//! the VP Token is returned in the Authorization Response alongside a
//! Self-Issued ID Token as defined in [SIOPv2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html).
//!
//! If the Response Type value is "code" (Authorization Code Grant Type), the VP
//! Token is provided in the Token Response.

use serde_json::Value;
use serde_json_path::JsonPath;
use tracing::instrument;
use vercre_core::Kind;
use vercre_openid::verifier::{Provider, ResponseRequest, ResponseResponse, StateStore};
use vercre_openid::{Error, Result};
use vercre_w3c_vc::model::VerifiableCredential;
use vercre_w3c_vc::proof::{Payload, Verify};

use crate::state::State;

/// Endpoint for the Wallet to respond Verifier's Authorization Request.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
#[instrument(level = "debug", skip(provider))]
pub async fn response(
    provider: impl Provider, request: &ResponseRequest,
) -> Result<ResponseResponse> {
    // TODO: handle case where Wallet returns error instead of submission
    verify(provider.clone(), request).await?;
    process(provider, request).await
}

// TODO: validate  Verifiable Presentation by format
// Check integrity, authenticity, and holder binding of each Presentation
// in the VP Token according to the rules for the Presentation's format.

// Verfiy the vp_token and presentation subm
#[allow(clippy::too_many_lines)]
async fn verify(provider: impl Provider, request: &ResponseRequest) -> Result<()> {
    tracing::debug!("response::verify");

    // get state by client state key
    let Some(state_key) = &request.state else {
        return Err(Error::InvalidRequest("client state not found".into()));
    };
    let Ok(state) = StateStore::get::<State>(&provider, state_key).await else {
        return Err(Error::InvalidRequest("state not found".into()));
    };
    let saved_req = &state.request_object;

    let Some(vp_token) = request.vp_token.clone() else {
        return Err(Error::InvalidRequest("vp_token not founnd".into()));
    };

    let mut vps = vec![];

    // check nonce matches
    for vp_val in &vp_token {
        let (vp, nonce) = match vercre_w3c_vc::proof::verify(Verify::Vp(vp_val), &provider).await {
            Ok(Payload::Vp { vp, nonce, .. }) => (vp, nonce),
            Ok(_) => return Err(Error::InvalidRequest("proof payload is invalid".into())),
            Err(e) => return Err(Error::ServerError(format!("issue verifying VP proof: {e}"))),
        };

        // else {
        //     return Err(Error::InvalidRequest("invalid vp_token".into()));
        // };
        if nonce != saved_req.nonce {
            return Err(Error::InvalidRequest("nonce does not match".into()));
        }
        vps.push(vp);
    }

    let Some(subm) = &request.presentation_submission else {
        return Err(Error::InvalidRequest("no presentation_submission".into()));
    };
    let def = match &saved_req.presentation_definition {
        Kind::Object(def) => def,
        Kind::String(_) => {
            return Err(Error::InvalidRequest("presentation_definition_uri is unsupported".into()));
        }
    };

    // verify presentation subm matches definition
    // N.B. technically, this is redundant as it is done when looking up state
    if subm.definition_id != def.id {
        return Err(Error::InvalidRequest("definition_ids do not match".into()));
    }

    let input_descs = &def.input_descriptors;
    let desc_map = &subm.descriptor_map;

    // convert VP Token to JSON Value for JSONPath querying
    // N.B. because of Mapping path syntax, we need to convert single entry
    // Vec to an req_obj

    let vp_val: Value = match vps.len() {
        1 => serde_json::to_value(vps[0].clone())
            .map_err(|e| Error::ServerError(format!("issue converting VP to Value: {e}")))?,
        _ => serde_json::to_value(vps)
            .map_err(|e| Error::ServerError(format!("issue aggregating vp values: {e}")))?,
    };

    // Verify request has been fulfilled for each credential requested:
    //  - use the Input Descriptor Mapping Object(s) in the Submission to identify
    //    the matching VC in the VP Token, and verify the VC.
    for input in input_descs {
        // find Input Descriptor Mapping Object
        let Some(mapping) = desc_map.iter().find(|idmo| idmo.id == input.id) else {
            return Err(Error::InvalidRequest(format!(
                "input descriptor mapping req_obj not found for {}",
                input.id
            )));
        };

        // check VC format matches a requested format
        if let Some(fmt) = input.format.as_ref() {
            if !fmt.contains_key(&mapping.path_nested.format) {
                return Err(Error::InvalidRequest(format!(
                    "invalid format {}",
                    mapping.path_nested.format
                )));
            }
        }

        // search VP Token for VC specified by mapping path
        let jpath = JsonPath::parse(&mapping.path_nested.path)
            .map_err(|e| Error::ServerError(format!("issue parsing JSON Path: {e}")))?;
        let Ok(vc_node) = jpath.query(&vp_val).exactly_one() else {
            return Err(Error::InvalidRequest(format!(
                "no match for path_nested {}",
                mapping.path_nested.path
            )));
        };

        let vc_kind: Kind<VerifiableCredential> = match vc_node {
            Value::String(token) => Kind::String(token.to_string()),
            Value::Object(_) => {
                let vc: VerifiableCredential = serde_json::from_value(vc_node.clone())
                    .map_err(|e| Error::ServerError(format!("issue deserializing vc: {e}")))?;
                Kind::Object(vc)
            }
            _ => return Err(Error::InvalidRequest(format!("unexpected VC format: {vc_node}"))),
        };

        let Payload::Vc(vc) =
            vercre_w3c_vc::proof::verify(Verify::Vc(&vc_kind), &provider)
                .await
                .map_err(|e| Error::InvalidRequest(format!("invalid VC proof: {e}")))?
        else {
            return Err(Error::InvalidRequest("proof payload is invalid".into()));
        };

        // verify input constraints have been met
        if !input
            .constraints
            .satisfied(&vc)
            .map_err(|e| Error::ServerError(format!("issue matching constraints: {e}")))?
        {
            return Err(Error::InvalidRequest("input constraints not satisfied".into()));
        }

        // check VC is valid (hasn't expired, been revoked, etc)
        if vc.valid_until.is_some_and(|exp| exp < chrono::Utc::now()) {
            return Err(Error::InvalidRequest("credential has expired".into()));
        }

        // TODO: look up credential status using status.id
        // if let Some(_status) = &vc.credential_status {
        //     // TODO: look up credential status using status.id
        // }
    }

    // TODO: perform Verifier policy checks
    // Checks based on the set of trust requirements such as trust frameworks
    // it belongs to (i.e., revocation checks), if applicable.

    Ok(())
}

// Process the authorization request
async fn process(provider: impl Provider, request: &ResponseRequest) -> Result<ResponseResponse> {
    tracing::debug!("response::process");

    // clear state
    let Some(state_key) = &request.state else {
        return Err(Error::InvalidRequest("client state not found".into()));
    };
    StateStore::purge(&provider, state_key)
        .await
        .map_err(|e| Error::ServerError(format!("issue purging state: {e}")))?;

    Ok(ResponseResponse {
        // TODO: add response to state using `response_code` so Wallet can fetch full response
        // TODO: align redirct_uri to spec
        // redirect_uri: Some(format!("http://localhost:3000/cb#response_code={}", "1234")),
        redirect_uri: Some("http://localhost:3000/cb".into()),
        response_code: None,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;

    use chrono::Utc;
    use serde_json::json;
    use vercre_dif_exch::PresentationDefinition;
    use vercre_openid::verifier::{
        ClientIdScheme, RequestObject, ResponseRequest, ResponseType, Verifier,
    };
    use vercre_test_utils::verifier::Provider;

    use super::*;
    use crate::state::Expire;

    const CLIENT_ID: &str = "http://vercre.io";

    #[tokio::test]
    async fn send_response() {
        vercre_test_utils::init_tracer();

        let provider = Provider::new();
        let pres_def = serde_json::from_value::<PresentationDefinition>(DEFINITION.to_owned())
            .expect("definition to deserialize");
        let state_key = "1234ABCD".to_string();
        let nonce = "ABCDEFG".to_string();

        let req_obj = RequestObject {
            response_type: ResponseType::VpToken,
            client_id: CLIENT_ID.to_string(),
            redirect_uri: None,
            scope: None,
            state: Some(state_key.clone()),
            nonce: nonce.clone(),
            response_mode: Some("direct_post.jwt".into()),
            response_uri: Some(format!("{CLIENT_ID}/direct_post.jwt")),
            presentation_definition: Kind::Object(pres_def.clone()),
            client_id_scheme: Some(ClientIdScheme::Did),
            client_metadata: Verifier::default(),
        };

        // set up state
        let state = State {
            expires_at: Utc::now() + Expire::Request.duration(),
            request_object: req_obj,
        };
        StateStore::put(&provider, &state_key, &state, state.expires_at)
            .await
            .expect("state exists");

        // replace placeholders with actual values
        let mut vp_token = VP_TOKEN.to_owned();
        let mut submission = SUBMISSION.to_owned();

        // replace placeholders with actual values
        *vp_token.get_mut(0).unwrap().get_mut("proof").unwrap().get_mut("challenge").unwrap() =
            json!(nonce);
        *submission.get_mut("definition_id").unwrap() = json!(pres_def.id);

        let body = json!({
            "vp_token":  vp_token,
            "presentation_submission": submission,
            "state": state_key,
        });

        let request = serde_json::from_value::<ResponseRequest>(body).expect("should deserialize");
        let response = response(provider, &request).await.expect("response is ok");

        let redirect = response.redirect_uri.as_ref().expect("has redirect_uri");
        assert_eq!(redirect, "http://localhost:3000/cb");
    }

    static DEFINITION: LazyLock<Value> = LazyLock::new(|| {
        json!({
            "id": "2d1691c1-2daa-4416-9d10-bc6790e72fad",
            "input_descriptors": [
                {
                    "id": "EmployeeIDCredential",
                    "constraints":  {
                        "fields": [ {
                            "path": ["$.type"],
                            "filter": {
                                "type": "string",
                                "const": "EmployeeIDCredential"
                            }
                        }],
                    }
                }
            ],
            "format": {
                "jwt_vc":  {
                    "alg": ["EdDSA"],
                }
            }
        })
    });

    static VP_TOKEN: LazyLock<Value> = LazyLock::new(|| {
        json!([{
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1"
            ],
            "proof": {
                "challenge": "<replace me!>",
            },
            "type": [
                "VerifiablePresentation",
                "EmployeeIDPresentation"
            ],
            "verifiableCredential": [
                "eyJhbGciOiJFZERTQSIsInR5cCI6Imp3dCIsImtpZCI6ImRpZDp3ZWI6ZGVtby5jcmVkaWJpbC5pbyNrZXktMCJ9.eyJzdWIiOiJkaWQ6a2V5Ono2TWtqOEpyMXJnM1lqVldXaGc3YWhFWUppYnFoakJnWnQxcERDYlQ0THY3RDRIWCIsIm5iZiI6MTcyMTcwMjg5MSwiaXNzIjoiaHR0cDovL3ZlcmNyZS5pbyIsImlhdCI6MTcyMTcwMjg5MSwianRpIjoiaHR0cDovL3ZlcmNyZS5pby9jcmVkZW50aWFscy9FbXBsb3llZUlEQ3JlZGVudGlhbCIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cDovL3ZlcmNyZS5pby9jcmVkZW50aWFscy92MSJdLCJpZCI6Imh0dHA6Ly92ZXJjcmUuaW8vY3JlZGVudGlhbHMvRW1wbG95ZWVJRENyZWRlbnRpYWwiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiRW1wbG95ZWVJRENyZWRlbnRpYWwiXSwiaXNzdWVyIjoiaHR0cDovL3ZlcmNyZS5pbyIsImlzc3VhbmNlRGF0ZSI6IjIwMjQtMDctMjNUMDI6NDg6MTEuMjgyOTg5WiIsImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmtleTp6Nk1rajhKcjFyZzNZalZXV2hnN2FoRVlKaWJxaGpCZ1p0MXBEQ2JUNEx2N0Q0SFgiLCJmYW1pbHlOYW1lIjoiUGVyc29uIiwiZ2l2ZW5OYW1lIjoiTm9ybWFsIn19fQ.HQHedefAHp1PM3lKugM7nQ-ogzV1Qs4eO0QvMP5vfSVb0wT1GJ425-j_zUSSPkhAslSC4aeNosnS_3dRet7wAQ"
            ]
        }])
    });
    static SUBMISSION: LazyLock<Value> = LazyLock::new(|| {
        json!({
            "id": "fcc96706-b20f-4aa7-b34d-c1f0b630c8cb",
            "definition_id": "<replace me!>",
            "descriptor_map": [
                {
                    "id": "EmployeeIDCredential",
                    "format": "jwt_vc_json",
                    "path": "$",
                    "path_nested": {
                        "format": "jwt_vc_json",
                        "path": "$.verifiableCredential[0]"
                    }
                },
                {
                    "id": "CitizenshipCredential",
                    "format": "jwt_vc_json",
                    "path": "$",
                    "path_nested": {
                        "format": "jwt_vc_json",
                        "path": "$.verifiableCredential[0]"
                    }
                }
            ]
        })
    });
}
