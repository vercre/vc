//! # Token Endpoint
//!
//! The Token Endpoint issues an Access Token and, optionally, a Refresh Token
//! in exchange for the Authorization Code that client obtained in a successful
//! Authorization Response. It is used in the same manner as defined in
//! [RFC6749](https://tools.ietf.org/html/rfc6749#section-5.1) and follows the
//! recommendations given in [I-D.ietf-oauth-security-topics].
//!
//! The authorization server MUST include the HTTP "Cache-Control" response
//! header field [RFC2616](https://www.rfc-editor.org/rfc/rfc2616) with a value of "no-store" in any response containing tokens,
//! credentials, or other sensitive information, as well as the "Pragma"
//! response header field [RFC2616](https://www.rfc-editor.org/rfc/rfc2616) with a value of "no-cache".

// TODO: verify `client_assertion` JWT, when set

use std::collections::HashMap;
use std::fmt::Debug;

use chrono::Utc;
use tracing::instrument;
use vercre_core::{gen, pkce};
use vercre_openid::issuer::{
    AuthorizedDetail, CredentialAuthorization, Issuer, Metadata, ProfileClaims, Provider,
    StateStore, TokenGrantType, TokenRequest, TokenResponse, TokenType,
};
use vercre_openid::oauth::GrantType;
use vercre_openid::{Error, Result};

use crate::state::{Authorized, AuthorizedItem, Expire, ItemType, Stage, State, Token};

/// Token request handler.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
#[instrument(level = "debug", skip(provider))]
pub async fn token(provider: impl Provider, request: TokenRequest) -> Result<TokenResponse> {
    // restore state
    let state_key = match &request.grant_type {
        TokenGrantType::AuthorizationCode { code, .. } => code,
        TokenGrantType::PreAuthorizedCode {
            pre_authorized_code, ..
        } => pre_authorized_code,
    };

    // RFC 6749 requires a particular error here
    let Ok(state) = StateStore::get(&provider, state_key).await else {
        return Err(Error::InvalidGrant("authorization code is invalid".into()));
    };

    // authorization code is one-time use
    StateStore::purge(&provider, state_key)
        .await
        .map_err(|e| Error::ServerError(format!("issue purging authorizaiton state: {e}")))?;

    let ctx = Context { state };

    ctx.verify(&provider, &request).await?;
    ctx.process(&provider, request).await
}

#[derive(Debug)]
struct Context {
    state: State,
}

impl Context {
    // Verify the token request.
    async fn verify(&self, provider: &impl Provider, request: &TokenRequest) -> Result<()> {
        tracing::debug!("token::verify");

        if self.state.is_expired() {
            return Err(Error::InvalidRequest("authorization state expired".into()));
        }

        // TODO: support optional authorization issuers
        let Ok(server) = Metadata::server(provider, &request.credential_issuer, None).await else {
            return Err(Error::InvalidRequest("unknown authorization server".into()));
        };
        let Some(grant_types_supported) = &server.oauth.grant_types_supported else {
            return Err(Error::ServerError("authorization server grant types not set".into()));
        };

        // grant_type
        match &request.grant_type {
            TokenGrantType::PreAuthorizedCode { tx_code, .. } => {
                let Stage::Offered(auth_state) = &self.state.stage else {
                    return Err(Error::ServerError("pre-authorized state not set".into()));
                };
                // grant_type supported?
                if !grant_types_supported.contains(&GrantType::PreAuthorizedCode) {
                    return Err(Error::InvalidGrant("unsupported `grant_type`".into()));
                }

                // anonymous access allowed?
                if request.client_id.as_ref().is_none()
                    || request.client_id.as_ref().is_some_and(String::is_empty)
                        && !server.pre_authorized_grant_anonymous_access_supported
                {
                    return Err(Error::InvalidClient("anonymous access is not supported".into()));
                }

                // tx_code (PIN)
                if tx_code != &auth_state.tx_code {
                    return Err(Error::InvalidGrant("invalid `tx_code` provided".into()));
                }
            }
            TokenGrantType::AuthorizationCode {
                redirect_uri,
                code_verifier,
                ..
            } => {
                let Stage::Authorized(auth_state) = &self.state.stage else {
                    return Err(Error::ServerError("authorization state not set".into()));
                };

                // grant_type supported?
                if !grant_types_supported.contains(&GrantType::AuthorizationCode) {
                    return Err(Error::InvalidGrant("unsupported `grant_type`".into()));
                }

                // client_id is the same as the one used to obtain the authorization code
                if request.client_id.is_none() {
                    return Err(Error::InvalidRequest("`client_id` is missing".into()));
                }
                if request.client_id.as_ref() != Some(&auth_state.client_id) {
                    return Err(Error::InvalidClient(
                        "`client_id` differs from authorized one".into(),
                    ));
                }

                // redirect_uri is the same as the one provided in authorization request
                // i.e. either 'None' or 'Some(redirect_uri)'
                if redirect_uri != &auth_state.redirect_uri {
                    return Err(Error::InvalidGrant(
                        "`redirect_uri` differs from authorized one".into(),
                    ));
                }

                // code_verifier
                let Some(verifier) = &code_verifier else {
                    return Err(Error::AccessDenied("`code_verifier` is missing".into()));
                };

                // code_verifier matches code_challenge
                let challenge = pkce::code_challenge(verifier);

                if challenge != auth_state.code_challenge {
                    return Err(Error::AccessDenied("`code_verifier` is invalid".into()));
                }
            }
        }

        if let Some(client_id) = &request.client_id {
            // client metadata
            let Ok(client) = Metadata::client(provider, client_id).await else {
                return Err(Error::InvalidClient("invalid `client_id`".into()));
            };
            // Client and server must support the same scopes.
            if let Some(client_scope) = &client.oauth.scope {
                if let Some(server_scopes) = &server.oauth.scopes_supported {
                    let scopes: Vec<&str> = client_scope.split_whitespace().collect();
                    if !scopes.iter().all(|s| server_scopes.contains(&(*s).to_string())) {
                        return Err(Error::InvalidRequest("client scope not supported".into()));
                    }
                } else {
                    return Err(Error::InvalidRequest("server supported scopes not set".into()));
                }
            } else {
                return Err(Error::InvalidRequest("client scope not set".into()));
            }
        }

        Ok(())
    }

    // TODO: add `client_assertion` JWT verification

    // Exchange authorization/pre-authorized code for access token.
    async fn process(
        &self, provider: &impl Provider, request: TokenRequest,
    ) -> Result<TokenResponse> {
        tracing::debug!("token::process");

        let (authorization_details, authorized) = match &request.grant_type {
            TokenGrantType::PreAuthorizedCode { .. } => {
                let Stage::Offered(auth_state) = &self.state.stage else {
                    return Err(Error::ServerError("pre-authorized state not set".into()));
                };
                let Some(auth_items) = &auth_state.items else {
                    return Err(Error::ServerError("no authorized items".into()));
                };

                // get the subset of requested credentials from those previously authorized
                let retained_items = retain_details(provider, &request, auth_items).await?;
                let authorized_details = authorized_details(&retained_items);
                let authorized = authorized_credentials(&retained_items);
                (authorized_details, authorized)
            }
            TokenGrantType::AuthorizationCode { .. } => {
                let Stage::Authorized(auth_state) = &self.state.stage else {
                    return Err(Error::ServerError("authorization state not set".into()));
                };
                let authorized_details = authorized_details(&auth_state.items);
                let authorized = authorized_credentials(&auth_state.items);
                (authorized_details, authorized)
            }
        };

        let access_token = gen::token();
        let c_nonce = gen::nonce();

        // update state
        let mut state = self.state.clone();
        state.stage = Stage::Validated(Token {
            access_token: access_token.clone(),
            credentials: authorized,
            c_nonce: c_nonce.clone(),
            c_nonce_expires_at: Utc::now() + Expire::Nonce.duration(),
        });
        StateStore::put(provider, &access_token, &state, state.expires_at)
            .await
            .map_err(|e| Error::ServerError(format!("issue saving state: {e}")))?;

        // return response
        Ok(TokenResponse {
            access_token,
            token_type: TokenType::Bearer,
            expires_in: Expire::Access.duration().num_seconds(),
            c_nonce: Some(c_nonce),
            c_nonce_expires_in: Some(Expire::Nonce.duration().num_seconds()),
            authorization_details,
        })
    }
}

// Filter previously authorized DetailItems by requested
// `authorization_details`.
async fn retain_details(
    provider: &impl Provider, request: &TokenRequest, items: &[AuthorizedItem],
) -> Result<Vec<AuthorizedItem>> {
    // no `authorization_details` in request, return all previously authorized
    let Some(req_auth_dets) = request.authorization_details.as_ref() else {
        return Ok(items.to_vec());
    };

    let Ok(issuer) = Metadata::issuer(provider, &request.credential_issuer).await else {
        return Err(Error::InvalidRequest("unknown authorization server".into()));
    };

    // filter by requested authorization_details
    let mut retained = vec![];

    for auth_det in req_auth_dets {
        // check requested `authorization_detail` has been previously authorized
        let mut found = false;
        for item in items {
            if let ItemType::AuthorizationDetail(ad) = &item.item {
                if ad.credential == auth_det.credential {
                    verify_claims(&issuer, &auth_det.credential)?;
                    retained.push(item.clone());
                    found = true;
                    break;
                }
            }
        }

        if !found {
            // we're here if requested `authorization_detail` has not been authorized
            return Err(Error::AccessDenied("requested credential has not been authorized".into()));
        }
    }

    Ok(retained)
}

// Verify requested claims exist as supported claims and all mandatory claims
// have been requested.
fn verify_claims(issuer: &Issuer, credential: &CredentialAuthorization) -> Result<()> {
    // verify requested claims
    let (config_id, claims) = match credential {
        CredentialAuthorization::ConfigurationId {
            credential_configuration_id,
            claims: profile,
        } => (credential_configuration_id, profile.as_ref().and_then(ProfileClaims::claims)),
        CredentialAuthorization::Format(fmt) => {
            let credential_configuration_id = issuer
                .credential_configuration_id(fmt)
                .map_err(|e| Error::ServerError(format!("issuer issue: {e}")))?;
            (credential_configuration_id, fmt.claims())
        }
    };

    // check claims are supported and include all mandatory claims
    if let Some(requested) = claims {
        let config =
            issuer.credential_configurations_supported.get(config_id).ok_or_else(|| {
                Error::InvalidAuthorizationDetails("invalid `credential_configuration_id`".into())
            })?;
        config
            .verify_claims(&requested)
            .map_err(|e| Error::InvalidAuthorizationDetails(e.to_string()))?;
    }

    Ok(())
}

fn authorized_details(items: &[AuthorizedItem]) -> Option<Vec<AuthorizedDetail>> {
    // convert retained detail_items to Authorized token response
    // + state Authorized
    let mut authorization_details = vec![];

    for item in items {
        if let ItemType::AuthorizationDetail(ad) = &item.item {
            authorization_details.push(AuthorizedDetail {
                authorization_detail: ad.clone(),
                credential_identifiers: item.credential_identifiers.clone(),
            });
        }
    }

    if authorization_details.is_empty() {
        return None;
    }
    Some(authorization_details)
}

fn authorized_credentials(items: &[AuthorizedItem]) -> HashMap<String, Authorized> {
    let mut authorized = HashMap::new();

    for item in items {
        for identifier in &item.credential_identifiers {
            authorized.insert(
                identifier.clone(),
                Authorized {
                    credential_identifier: identifier.clone(),
                    credential_configuration_id: item.credential_configuration_id.clone(),
                    claim_ids: None,
                },
            );
        }
    }

    authorized
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use insta::assert_yaml_snapshot as assert_snapshot;
    use serde_json::json;
    use test_utils::issuer::{Provider, CLIENT_ID, CREDENTIAL_ISSUER, NORMAL_USER};
    use test_utils::snapshot;
    use vercre_openid::issuer::{
        AuthorizationDetail, AuthorizationDetailType, CredentialAuthorization,
        CredentialDefinition, Format, ProfileW3c,
    };

    use super::*;
    use crate::state::{Authorization, Offer};

    #[tokio::test]
    async fn pre_authorized() {
        test_utils::init_tracer();
        snapshot!("");

        let provider = Provider::new();

        // set up Offered state
        let state = State {
            stage: Stage::Offered(Offer {
                items: Some(vec![AuthorizedItem {
                    item: ItemType::AuthorizationDetail(AuthorizationDetail {
                        type_: AuthorizationDetailType::OpenIdCredential,
                        credential: CredentialAuthorization::ConfigurationId {
                            credential_configuration_id: "EmployeeID_JWT".into(),
                            claims: None,
                        },
                        locations: None,
                    }),
                    credential_configuration_id: "EmployeeID_JWT".into(),
                    credential_identifiers: vec!["PHLEmployeeID".into()],
                }]),
                tx_code: Some("1234".into()),
            }),
            subject_id: Some(NORMAL_USER.into()),
            expires_at: Utc::now() + Expire::Authorized.duration(),
        };

        let pre_auth_code = "ABCDEF";

        StateStore::put(&provider, pre_auth_code, &state, state.expires_at)
            .await
            .expect("state exists");

        // create TokenRequest to 'send' to the app
        let value = json!({
            "credential_issuer": CREDENTIAL_ISSUER,
            "client_id": CLIENT_ID,
            "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "pre-authorized_code": pre_auth_code,
            "tx_code": "1234"
        });
        let request = serde_json::from_value(value).expect("request is valid");

        let token_resp = token(provider.clone(), request).await.expect("response is valid");

        assert_snapshot!("token:pre_authorized:response", &token_resp, {
            ".access_token" => "[access_token]",
            ".c_nonce" => "[c_nonce]"
        });

        // pre-authorized state should be removed
        assert!(StateStore::get::<State>(&provider, pre_auth_code).await.is_err());

        // should be able to retrieve state using access token
        let state = StateStore::get::<State>(&provider, &token_resp.access_token)
            .await
            .expect("state exists");

        assert_snapshot!("token:pre_authorized:state", state, {
            ".expires_at" => "[expires_at]",
            ".stage.access_token" => "[access_token]",
            ".stage.c_nonce" => "[c_nonce]",
            ".stage.c_nonce_expires_at" => "[c_nonce_expires_at]",
        });
    }

    #[tokio::test]
    async fn authorized() {
        test_utils::init_tracer();
        snapshot!("");

        let provider = Provider::new();
        let verifier = "ABCDEF12345";

        // set up Authorization state
        let state = State {
            stage: Stage::Authorized(Authorization {
                code_challenge: pkce::code_challenge(verifier),
                code_challenge_method: "S256".into(),
                items: vec![AuthorizedItem {
                    item: ItemType::AuthorizationDetail(AuthorizationDetail {
                        type_: AuthorizationDetailType::OpenIdCredential,
                        credential: CredentialAuthorization::ConfigurationId {
                            credential_configuration_id: "EmployeeID_JWT".into(),
                            claims: None,
                        },
                        ..AuthorizationDetail::default()
                    }),
                    credential_configuration_id: "EmployeeID_JWT".into(),
                    credential_identifiers: vec!["PHLEmployeeID".into()],
                }],
                client_id: CLIENT_ID.into(),
                ..Authorization::default()
            }),
            subject_id: Some(NORMAL_USER.into()),
            expires_at: Utc::now() + Expire::Authorized.duration(),
        };

        let code = "ABCDEF";

        StateStore::put(&provider, code, &state, state.expires_at).await.expect("state exists");

        // create TokenRequest to 'send' to the app
        let value = json!({
            "credential_issuer": CREDENTIAL_ISSUER,
            "client_id": CLIENT_ID,
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
        });
        let request = serde_json::from_value(value).expect("request is valid");
        let token_resp = token(provider.clone(), request).await.expect("response is valid");

        assert_snapshot!("token:authorized:response", &token_resp, {
            ".access_token" => "[access_token]",
            ".c_nonce" => "[c_nonce]"
        });

        // authorization state should be removed
        assert!(StateStore::get::<State>(&provider, code).await.is_err());

        // should be able to retrieve state using access token
        let state = StateStore::get::<State>(&provider, &token_resp.access_token)
            .await
            .expect("state exists");

        assert_snapshot!("token:authorized:state", state, {
            ".expires_at" => "[expires_at]",
            ".stage.access_token" => "[access_token]",
            ".stage.c_nonce" => "[c_nonce]",
            ".stage.c_nonce_expires_at" => "[c_nonce_expires_at]",
        });
    }

    #[tokio::test]
    async fn authorization_details() {
        test_utils::init_tracer();
        snapshot!("");

        let provider = Provider::new();
        let verifier = "ABCDEF12345";

        // set up Authorization state
        let state = State {
            stage: Stage::Authorized(Authorization {
                client_id: CLIENT_ID.into(),
                redirect_uri: Some("https://example.com".into()),
                code_challenge: pkce::code_challenge(verifier),
                code_challenge_method: "S256".into(),
                items: vec![AuthorizedItem {
                    item: ItemType::AuthorizationDetail(AuthorizationDetail {
                        type_: AuthorizationDetailType::OpenIdCredential,
                        credential: CredentialAuthorization::Format(Format::JwtVcJson(
                            ProfileW3c {
                                credential_definition: CredentialDefinition {
                                    type_: Some(vec![
                                        "VerifiableCredential".into(),
                                        "EmployeeIDCredential".into(),
                                    ]),
                                    ..CredentialDefinition::default()
                                },
                            },
                        )),
                        ..AuthorizationDetail::default()
                    }),
                    credential_configuration_id: "EmployeeID_JWT".into(),
                    credential_identifiers: vec!["PHLEmployeeID".into()],
                }],
                ..Authorization::default()
            }),
            subject_id: Some(NORMAL_USER.into()),
            expires_at: Utc::now() + Expire::Authorized.duration(),
        };

        let code = "ABCDEF";

        StateStore::put(&provider, code, &state, state.expires_at).await.expect("state exists");

        // create TokenRequest to 'send' to the app
        let value = json!({
            "credential_issuer": CREDENTIAL_ISSUER,
            "client_id": CLIENT_ID,
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": "https://example.com",
            "authorization_details": [{
                "type": "openid_credential",
                "format": "jwt_vc_json",
                "credential_definition": {
                    "type": [
                        "VerifiableCredential",
                        "EmployeeIDCredential"
                    ]
                }
            }],
        });
        let request = serde_json::from_value(value).expect("request is valid");
        let response = token(provider.clone(), request).await.expect("response is valid");

        assert_snapshot!("token:authorization_details:response", &response, {
            ".access_token" => "[access_token]",
            ".c_nonce" => "[c_nonce]"
        });

        // auth_code state should be removed
        assert!(StateStore::get::<State>(&provider, code).await.is_err());

        // should be able to retrieve state using access token
        let state = StateStore::get::<State>(&provider, &response.access_token)
            .await
            .expect("state exists");

        assert_snapshot!("token:authorization_details:state", state, {
            ".expires_at" => "[expires_at]",
            ".stage.access_token" => "[access_token]",
            ".stage.c_nonce" => "[c_nonce]",
            ".stage.c_nonce_expires_at" => "[c_nonce_expires_at]",
        });
    }
}
