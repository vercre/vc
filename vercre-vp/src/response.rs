//! # Response Redirect Endpoint
//!
//! This endpoint is where the Wallet **redirects** to when returning an [RFC6749](https://www.rfc-editor.org/rfc/rfc6749.html).
//! Authorization Response when both Wallet and Verifier interact on the same device.
//! That is, during a 'same-device flow'.
//!
//! The Wallet only returns a VP Token if the corresponding Authorization Request
//! contained a `presentation_definition` parameter, a `presentation_definition_uri`
//! parameter, or a `scope` parameter representing a Presentation Definition.
//!
//! The VP Token can be returned in the Authorization Response or the Token
//! Response depending on the Response Type used.
//!
//! If the Authorization Request's Response Type value is "`vp_token`", the VP Token
//! is returned in the Authorization Response. When the Response Type value is
//! "`vp_token id_token`" and the scope parameter contains "openid", the VP Token is
//! returned in the Authorization Response alongside a Self-Issued ID Token as defined
//! in [SIOPv2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html).
//!
//! If the Response Type value is "code" (Authorization Code Grant Type), the VP
//! Token is provided in the Token Response.

use std::fmt::Debug;
use std::str::FromStr;

use serde_json::Value;
use serde_json_path::JsonPath;
use tracing::{instrument, trace};
use vercre_core::error::Err;
use vercre_core::provider::{Callback, Client, Signer, StateManager};
#[allow(clippy::module_name_repetitions)]
pub use vercre_core::vp::{ResponseRequest, ResponseResponse};
use vercre_core::w3c::{Claims as VpClaims, VerifiableCredential};
use vercre_core::{err, jwt, Result};

use super::Endpoint;
use crate::state::State;

/// Authorization Response request handler.
impl<P> Endpoint<P>
where
    P: Client + StateManager + Signer + Callback + Clone + Debug,
{
    /// Endpoint for the Wallet to respond Verifier's Authorization Request.
    ///
    /// # Errors
    ///
    /// Returns an `OpenID4VP` error if the request is invalid or if the provider is
    /// not available.
    pub async fn response(&self, request: &ResponseRequest) -> Result<ResponseResponse> {
        // TODO: handle case where Wallet returns error instead of subm

        // get state by client state key
        let Some(state_key) = &request.state else {
            err!(Err::InvalidRequest, "client state not found");
        };
        let Ok(buf) = StateManager::get(&self.provider, state_key).await else {
            err!(Err::InvalidRequest, "state not found");
        };

        let ctx = Context {
            state: State::try_from(buf)?,
            _p: std::marker::PhantomData,
        };

        vercre_core::Endpoint::handle_request(self, request, ctx).await
    }
}

#[derive(Debug)]
struct Context<P> {
    state: State,
    _p: std::marker::PhantomData<P>,
}

impl<P> vercre_core::Context for Context<P>
where
    P: Client + StateManager + Signer + Callback + Clone + Debug,
{
    type Provider = P;
    type Request = ResponseRequest;
    type Response = ResponseResponse;

    fn callback_id(&self) -> Option<String> {
        self.state.callback_id.clone()
    }

    // Verfiy the vp_token and presentation subm
    #[instrument]
    async fn verify(
        &mut self, provider: &Self::Provider, request: &Self::Request,
    ) -> Result<&Self> {
        trace!("Context::verify");

        // TODO:
        // Validate the integrity, authenticity, and holder binding of each Verifiable
        // Presentation in the VP Token according to the rules of the respective
        // Presentation format.

        let saved_req = &self.state.request_object;

        // TODO: no token == error response, we should have already checked for an error
        let Some(vp_token) = request.vp_token.clone() else {
            err!(Err::InvalidRequest, "client state not found");
        };

        // use serde::de::{self, Deserialize, Deserializer, SeqAccess, Visitor};
        // use vercre_core::vp::vp_token as deser;

        let mut vp_values = vec![];

        // check nonce matches
        for vp_val in vp_token {
            let value = match vp_val {
                Value::Object(_) => {
                    let Some(proof) = vp_val["proof"].as_object() else {
                        err!(Err::InvalidRequest, "proof not found");
                    };
                    if proof["challenge"].as_str() != Some(&saved_req.nonce) {
                        err!(Err::InvalidRequest, "nonce does not match");
                    }
                    vp_val
                }
                Value::String(string) => {
                    let Ok(jwt) = jwt::Jwt::<VpClaims>::from_str(&string) else {
                        err!(Err::InvalidRequest, "invalid vp_token format");
                    };
                    if jwt.claims.nonce != saved_req.nonce {
                        err!(Err::InvalidRequest, "nonce does not match");
                    }
                    serde_json::to_value(jwt.claims.vp)?
                }
                _ => {
                    err!(Err::InvalidRequest, "invalid vp_token format");
                }
            };

            vp_values.push(value);
        }

        let Some(subm) = &request.presentation_submission else {
            err!(Err::InvalidRequest, "no presentation_submission");
        };

        let Some(def) = &saved_req.presentation_definition else {
            err!(Err::InvalidRequest, "no presentation_definition");
        };

        // verify presentation subm matches definition
        // N.B. technically, this is redundant as it is done when looking up state
        if subm.definition_id != def.id {
            err!(Err::InvalidRequest, "definition_ids do not match");
        }

        let input_descs = &def.input_descriptors;
        let desc_map = &subm.descriptor_map;

        // convert VP Token to JSON Value for JSONPath querying
        // N.B. because of Mapping path syntax, we need to convert single entry
        // Vec to an req_obj

        let vp_val: Value = match vp_values.len() {
            1 => serde_json::to_value(&vp_values[0])?,
            _ => serde_json::to_value(vp_values)?,
        };

        // Verify request has been fulfilled for each credential requested:
        //  - use the Input Descriptor Mapping Object(s) in the Submission to identify
        //    the matching VC in the VP Token, and verify the VC.
        for input in input_descs {
            // find Input Descriptor Mapping Object
            let Some(mapping) = desc_map.iter().find(|idmo| idmo.id == input.id) else {
                err!(
                    Err::InvalidRequest,
                    "input descriptor mapping req_obj not found for {}",
                    input.id
                );
            };

            // check VC format matches a requested format
            if let Some(fmt) = input.format.as_ref() {
                if !fmt.contains_key(&mapping.path_nested.format) {
                    err!(Err::InvalidRequest, "invalid format {}", mapping.path_nested.format);
                }
            }

            // search VP Token for VC specified by mapping path
            let jpath = JsonPath::parse(&mapping.path_nested.path)?;
            let Ok(vc_node) = jpath.query(&vp_val).exactly_one() else {
                err!(Err::InvalidRequest, "no match for path_nested {}", mapping.path_nested.path);
            };

            // convert Value (req_obj or base64url string) to VerifiableCredential
            let vc = match vc_node {
                Value::String(s) => VerifiableCredential::from_str(s)?,
                Value::Object(_) => serde_json::from_value(vc_node.clone())?,
                _ => err!(Err::InvalidRequest, "unexpected VC format: {}", vc_node),
            };

            // verify input constraints have been met
            if !input.constraints.satisfied(&vc)? {
                err!(Err::InvalidRequest, "input constraints not satisfied");
            }

            // check VC is valid (hasn't expired, been revoked, etc)
            if vc.expiration_date.is_some_and(|exp| exp < chrono::Utc::now()) {
                err!(Err::InvalidRequest, "credential has expired");
            }

            // TODO: look up credential status using status.id
            // if let Some(_status) = &vc.credential_status {
            //     // TODO: look up credential status using status.id
            // }
        }

        // TODO:
        // Perform the checks required by the Verifier's policy based on the set of
        // trust requirements such as trust frameworks it belongs to (i.e.,
        // revocation checks), if applicable.

        Ok(self)
    }

    // Process the authorization request
    #[instrument]
    async fn process(
        &self, provider: &Self::Provider, request: &Self::Request,
    ) -> Result<Self::Response> {
        trace!("Context::process");

        // clear state
        let Some(state_key) = &request.state else {
            err!(Err::InvalidRequest, "client state not found");
        };
        StateManager::purge(provider, state_key).await?;

        // TODO: use callback to advise client of result
        Ok(ResponseResponse {
            // TODO: add response to state using `response_code` so Wallet can fetch full response
            // TODO: align redirct_uri to spec
            // redirect_uri: Some(format!("http://localhost:3000/cb#response_code={}", "1234")),
            redirect_uri: Some(String::from("http://localhost:3000/cb")),
            response_code: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use lazy_static::lazy_static;
    use serde_json::json;
    use test_utils::vp_provider::Provider;
    use vercre_core::vp::RequestObject;
    use vercre_core::w3c::vp::PresentationDefinition;

    use super::*;

    const CLIENT_ID: &str = "http://vercre.io";

    #[tokio::test]
    async fn send_response() {
        test_utils::init_tracer();

        let provider = Provider::new();
        let pres_def = serde_json::from_value::<PresentationDefinition>(DEFINITION.to_owned())
            .expect("definition to deserialize");
        let state_key = String::from("1234ABCD");
        let nonce = String::from("ABCDEFG");

        let req_obj = RequestObject {
            response_type: String::from("vp_token"),
            client_id: CLIENT_ID.to_string(),
            redirect_uri: None,
            scope: None,
            state: Some(state_key.clone()),
            nonce: nonce.clone(),
            response_mode: Some(String::from("direct_post.jwt")),
            response_uri: Some(format!("{CLIENT_ID}/direct_post.jwt")),
            presentation_definition: Some(pres_def.clone()),
            presentation_definition_uri: None,
            client_id_scheme: Some(String::from("did")),
            client_metadata: None,
            client_metadata_uri: None,
        };

        // set up state
        let state = State::builder().request_object(req_obj).build().expect("should build state");
        StateManager::put(&provider, &state_key, state.to_vec(), state.expires_at)
            .await
            .expect("state exists");

        // replace placeholders with actual values
        let mut vp_token = VP_TOKEN.to_owned();
        let mut subm = SUBMISSION.to_owned();

        // replace placeholders with actual values
        *vp_token.get_mut(0).unwrap().get_mut("proof").unwrap().get_mut("challenge").unwrap() =
            json!(nonce);
        *subm.get_mut("definition_id").unwrap() = json!(pres_def.id);

        let body = json!({
            "vp_token":  serde_json::to_string(&vp_token).expect("should serialize to string"),
            "presentation_submission": serde_json::to_string(&subm).expect("should serialize to string"),
            "state": state_key,
        });

        let request = serde_json::from_value::<ResponseRequest>(body).expect("should deserialize");
        let response = Endpoint::new(provider).response(&request).await.expect("response is ok");

        let redirect = response.redirect_uri.as_ref().expect("has redirect_uri");
        assert_eq!(redirect, "http://localhost:3000/cb");
    }

    lazy_static! {
        static ref DEFINITION: Value = json!({
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
                },
                // {
                //     "id": "CitizenshipCredential",
                //     "constraints":  {
                //         "fields": [ {
                //             "path": ["$.type"],
                //             "filter": {
                //                 "type": "string",
                //                 "const": "CitizenshipCredential"
                //             }
                //         }],
                //     }
                // }
            ],
            "format": {
                "jwt_vc":  {
                    "alg": ["ES256K"],
                }
            }
        });
        static ref VP_TOKEN: Value = json!([{
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
                "eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6aW9uOkVpRHlPUWJiWkFhM2FpUnplQ2tWN0xPeDNTRVJqakg5M0VYb0lNM1VvTjRvV2c6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKd2RXSnNhV05MWlhsTmIyUmxiREZKWkNJc0luQjFZbXhwWTB0bGVVcDNheUk2ZXlKamNuWWlPaUp6WldOd01qVTJhekVpTENKcmRIa2lPaUpGUXlJc0luZ2lPaUowV0ZOTFFsOXlkV0pZVXpkelEycFljWFZ3VmtwRmVsUmpWek5OYzJwdFJYWnhNVmx3V0c0NU5scG5JaXdpZVNJNkltUlBhV05ZY1dKcVJuaHZSMG90U3pBdFIwb3hhMGhaU25GcFkxOUVYMDlOZFZWM2ExRTNUMncyYm1zaWZTd2ljSFZ5Y0c5elpYTWlPbHNpWVhWMGFHVnVkR2xqWVhScGIyNGlMQ0pyWlhsQlozSmxaVzFsYm5RaVhTd2lkSGx3WlNJNklrVmpaSE5oVTJWamNESTFObXN4Vm1WeWFXWnBZMkYwYVc5dVMyVjVNakF4T1NKOVhTd2ljMlZ5ZG1salpYTWlPbHQ3SW1sa0lqb2ljMlZ5ZG1salpURkpaQ0lzSW5ObGNuWnBZMlZGYm1Sd2IybHVkQ0k2SW1oMGRIQTZMeTkzZDNjdWMyVnlkbWxqWlRFdVkyOXRJaXdpZEhsd1pTSTZJbk5sY25acFkyVXhWSGx3WlNKOVhYMTlYU3dpZFhCa1lYUmxRMjl0YldsMGJXVnVkQ0k2SWtWcFJFdEphM2R4VHpZNVNWQkhNM0JQYkVoclpHSTRObTVaZERCaFRuaFRTRnAxTW5JdFltaEZlbTVxWkVFaWZTd2ljM1ZtWm1sNFJHRjBZU0k2ZXlKa1pXeDBZVWhoYzJnaU9pSkZhVU5tUkZkU2JsbHNZMFE1UlVkQk0yUmZOVm94UVVoMUxXbFpjVTFpU2psdVptbHhaSG8xVXpoV1JHSm5JaXdpY21WamIzWmxjbmxEYjIxdGFYUnRaVzUwSWpvaVJXbENaazlhWkUxMFZUWlBRbmM0VUdzNE56bFJkRm90TWtvdE9VWmlZbXBUV25sdllVRmZZbkZFTkhwb1FTSjlmUSNwdWJsaWNLZXlNb2RlbDFJZCIsInR5cCI6Imp3dCJ9.eyJzdWIiOiJkaWQ6aW9uOkVpRHlPUWJiWkFhM2FpUnplQ2tWN0xPeDNTRVJqakg5M0VYb0lNM1VvTjRvV2c6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKd2RXSnNhV05MWlhsTmIyUmxiREZKWkNJc0luQjFZbXhwWTB0bGVVcDNheUk2ZXlKamNuWWlPaUp6WldOd01qVTJhekVpTENKcmRIa2lPaUpGUXlJc0luZ2lPaUowV0ZOTFFsOXlkV0pZVXpkelEycFljWFZ3VmtwRmVsUmpWek5OYzJwdFJYWnhNVmx3V0c0NU5scG5JaXdpZVNJNkltUlBhV05ZY1dKcVJuaHZSMG90U3pBdFIwb3hhMGhaU25GcFkxOUVYMDlOZFZWM2ExRTNUMncyYm1zaWZTd2ljSFZ5Y0c5elpYTWlPbHNpWVhWMGFHVnVkR2xqWVhScGIyNGlMQ0pyWlhsQlozSmxaVzFsYm5RaVhTd2lkSGx3WlNJNklrVmpaSE5oVTJWamNESTFObXN4Vm1WeWFXWnBZMkYwYVc5dVMyVjVNakF4T1NKOVhTd2ljMlZ5ZG1salpYTWlPbHQ3SW1sa0lqb2ljMlZ5ZG1salpURkpaQ0lzSW5ObGNuWnBZMlZGYm1Sd2IybHVkQ0k2SW1oMGRIQTZMeTkzZDNjdWMyVnlkbWxqWlRFdVkyOXRJaXdpZEhsd1pTSTZJbk5sY25acFkyVXhWSGx3WlNKOVhYMTlYU3dpZFhCa1lYUmxRMjl0YldsMGJXVnVkQ0k2SWtWcFJFdEphM2R4VHpZNVNWQkhNM0JQYkVoclpHSTRObTVaZERCaFRuaFRTRnAxTW5JdFltaEZlbTVxWkVFaWZTd2ljM1ZtWm1sNFJHRjBZU0k2ZXlKa1pXeDBZVWhoYzJnaU9pSkZhVU5tUkZkU2JsbHNZMFE1UlVkQk0yUmZOVm94UVVoMUxXbFpjVTFpU2psdVptbHhaSG8xVXpoV1JHSm5JaXdpY21WamIzWmxjbmxEYjIxdGFYUnRaVzUwSWpvaVJXbENaazlhWkUxMFZUWlBRbmM0VUdzNE56bFJkRm90TWtvdE9VWmlZbXBUV25sdllVRmZZbkZFTkhwb1FTSjlmUSIsImp0aSI6IkVtcGxveWVlSURfSldUIiwiaXNzIjoiaHR0cDovL2NyZWRpYmlsLmlvIiwibmJmIjoxNzAwNTIyNTE1LCJpYXQiOjE3MDA1MjI1MTUsImV4cCI6bnVsbCwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwOi8vY3JlZGliaWwuaW8vY3JlZGVudGlhbHMvdjEiXSwiaWQiOiJFbXBsb3llZUlEX0pXVCIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJFbXBsb3llZUlEQ3JlZGVudGlhbCJdLCJpc3N1ZXIiOiJodHRwOi8vY3JlZGliaWwuaW8iLCJpc3N1YW5jZURhdGUiOiIyMDIzLTExLTIwVDIzOjIxOjU1LjQ4ODY1OVoiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJpZCI6ImRpZDppb246RWlEeU9RYmJaQWEzYWlSemVDa1Y3TE94M1NFUmpqSDkzRVhvSU0zVW9ONG9XZzpleUprWld4MFlTSTZleUp3WVhSamFHVnpJanBiZXlKaFkzUnBiMjRpT2lKeVpYQnNZV05sSWl3aVpHOWpkVzFsYm5RaU9uc2ljSFZpYkdsalMyVjVjeUk2VzNzaWFXUWlPaUp3ZFdKc2FXTkxaWGxOYjJSbGJERkpaQ0lzSW5CMVlteHBZMHRsZVVwM2F5STZleUpqY25ZaU9pSnpaV053TWpVMmF6RWlMQ0pyZEhraU9pSkZReUlzSW5naU9pSjBXRk5MUWw5eWRXSllVemR6UTJwWWNYVndWa3BGZWxSalZ6Tk5jMnB0UlhaeE1WbHdXRzQ1Tmxwbklpd2llU0k2SW1SUGFXTlljV0pxUm5odlIwb3RTekF0UjBveGEwaFpTbkZwWTE5RVgwOU5kVlYzYTFFM1QydzJibXNpZlN3aWNIVnljRzl6WlhNaU9sc2lZWFYwYUdWdWRHbGpZWFJwYjI0aUxDSnJaWGxCWjNKbFpXMWxiblFpWFN3aWRIbHdaU0k2SWtWalpITmhVMlZqY0RJMU5tc3hWbVZ5YVdacFkyRjBhVzl1UzJWNU1qQXhPU0o5WFN3aWMyVnlkbWxqWlhNaU9sdDdJbWxrSWpvaWMyVnlkbWxqWlRGSlpDSXNJbk5sY25acFkyVkZibVJ3YjJsdWRDSTZJbWgwZEhBNkx5OTNkM2N1YzJWeWRtbGpaVEV1WTI5dElpd2lkSGx3WlNJNkluTmxjblpwWTJVeFZIbHdaU0o5WFgxOVhTd2lkWEJrWVhSbFEyOXRiV2wwYldWdWRDSTZJa1ZwUkV0SmEzZHhUelk1U1ZCSE0zQlBiRWhyWkdJNE5tNVpkREJoVG5oVFNGcDFNbkl0WW1oRmVtNXFaRUVpZlN3aWMzVm1abWw0UkdGMFlTSTZleUprWld4MFlVaGhjMmdpT2lKRmFVTm1SRmRTYmxsc1kwUTVSVWRCTTJSZk5Wb3hRVWgxTFdsWmNVMWlTamx1Wm1seFpIbzFVemhXUkdKbklpd2ljbVZqYjNabGNubERiMjF0YVhSdFpXNTBJam9pUldsQ1prOWFaRTEwVlRaUFFuYzRVR3M0TnpsUmRGb3RNa290T1VaaVltcFRXbmx2WVVGZlluRkVOSHBvUVNKOWZRIn0sInByb29mIjp7InR5cGUiOiIiLCJjcnlwdG9zdWl0ZSI6IkVjZHNhU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOSIsInByb29mUHVycG9zZSI6IiIsInZlcmlmaWNhdGlvbk1ldGhvZCI6ImRpZDppb246RWlEeU9RYmJaQWEzYWlSemVDa1Y3TE94M1NFUmpqSDkzRVhvSU0zVW9ONG9XZzpleUprWld4MFlTSTZleUp3WVhSamFHVnpJanBiZXlKaFkzUnBiMjRpT2lKeVpYQnNZV05sSWl3aVpHOWpkVzFsYm5RaU9uc2ljSFZpYkdsalMyVjVjeUk2VzNzaWFXUWlPaUp3ZFdKc2FXTkxaWGxOYjJSbGJERkpaQ0lzSW5CMVlteHBZMHRsZVVwM2F5STZleUpqY25ZaU9pSnpaV053TWpVMmF6RWlMQ0pyZEhraU9pSkZReUlzSW5naU9pSjBXRk5MUWw5eWRXSllVemR6UTJwWWNYVndWa3BGZWxSalZ6Tk5jMnB0UlhaeE1WbHdXRzQ1Tmxwbklpd2llU0k2SW1SUGFXTlljV0pxUm5odlIwb3RTekF0UjBveGEwaFpTbkZwWTE5RVgwOU5kVlYzYTFFM1QydzJibXNpZlN3aWNIVnljRzl6WlhNaU9sc2lZWFYwYUdWdWRHbGpZWFJwYjI0aUxDSnJaWGxCWjNKbFpXMWxiblFpWFN3aWRIbHdaU0k2SWtWalpITmhVMlZqY0RJMU5tc3hWbVZ5YVdacFkyRjBhVzl1UzJWNU1qQXhPU0o5WFN3aWMyVnlkbWxqWlhNaU9sdDdJbWxrSWpvaWMyVnlkbWxqWlRGSlpDSXNJbk5sY25acFkyVkZibVJ3YjJsdWRDSTZJbWgwZEhBNkx5OTNkM2N1YzJWeWRtbGpaVEV1WTI5dElpd2lkSGx3WlNJNkluTmxjblpwWTJVeFZIbHdaU0o5WFgxOVhTd2lkWEJrWVhSbFEyOXRiV2wwYldWdWRDSTZJa1ZwUkV0SmEzZHhUelk1U1ZCSE0zQlBiRWhyWkdJNE5tNVpkREJoVG5oVFNGcDFNbkl0WW1oRmVtNXFaRUVpZlN3aWMzVm1abWw0UkdGMFlTSTZleUprWld4MFlVaGhjMmdpT2lKRmFVTm1SRmRTYmxsc1kwUTVSVWRCTTJSZk5Wb3hRVWgxTFdsWmNVMWlTamx1Wm1seFpIbzFVemhXUkdKbklpd2ljbVZqYjNabGNubERiMjF0YVhSdFpXNTBJam9pUldsQ1prOWFaRTEwVlRaUFFuYzRVR3M0TnpsUmRGb3RNa290T1VaaVltcFRXbmx2WVVGZlluRkVOSHBvUVNKOWZRI3B1YmxpY0tleU1vZGVsMUlkIiwicHJvb2ZWYWx1ZSI6IiJ9fX0.yUsvBJDMk5rS7BjGlOT4TwUeI4IczC5RihwNSm4ErRgd8CfSdf0aEIzMGcHxxYNVaMHPV0yzM8VgC0jLsv14aQ"
            ]
        }]);
        static ref SUBMISSION: Value = json!({
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
        });
    }
}
