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

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::Utc;
use sha2::{Digest, Sha256};
use tracing::instrument;
use vercre_core::gen;
use vercre_openid::issuer::{
    AuthorizationDetail, AuthorizedDetail, Metadata, Provider, StateStore, TokenGrantType,
    TokenRequest, TokenResponse, TokenType,
};
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
            return Err(Error::InvalidRequest("state expired".into()));
        }

        let Ok(server) = Metadata::server(provider, &request.credential_issuer).await else {
            return Err(Error::InvalidRequest("unknown authorization server".into()));
        };

        // grant_type
        match &request.grant_type {
            TokenGrantType::PreAuthorizedCode { tx_code, .. } => {
                let Stage::PreAuthorized(auth_state) = &self.state.stage else {
                    return Err(Error::ServerError("pre-authorized state not set".into()));
                };

                // anonymous access allowed?
                if request.client_id.as_ref().is_none()
                    || request.client_id.as_ref().is_some_and(String::is_empty)
                        && !server.pre_authorized_grant_anonymous_access_supported
                {
                    return Err(Error::InvalidClient("anonymous access is not supported".into()));
                }
                // tx_code
                if tx_code != &auth_state.tx_code {
                    return Err(Error::InvalidGrant("invalid tx_code provided".into()));
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

                // client_id is the same as the one used to obtain the authorization code
                if request.client_id.as_ref() != Some(&auth_state.client_id) {
                    return Err(Error::InvalidGrant(
                        "client_id differs from authorized one".into(),
                    ));
                }

                // redirect_uri is the same as the one provided in authorization request
                // i.e. either 'None' or 'Some(redirect_uri)'
                if redirect_uri != &auth_state.redirect_uri {
                    return Err(Error::InvalidGrant(
                        "redirect_uri differs from authorized one".into(),
                    ));
                }

                // code_verifier
                let Some(verifier) = &code_verifier else {
                    return Err(Error::AccessDenied("code_verifier is missing".into()));
                };

                // code_verifier matches code_challenge
                let hash = Sha256::digest(verifier);
                let challenge = Base64UrlUnpadded::encode_string(&hash);

                if challenge != auth_state.code_challenge {
                    return Err(Error::AccessDenied("code_verifier is invalid".into()));
                }
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
                let Stage::PreAuthorized(auth_state) = &self.state.stage else {
                    return Err(Error::ServerError("pre-authorized state not set".into()));
                };

                // get the subset of requested credentials from those previously authorized
                let retained_items =
                    retain_details(&request.authorization_details, &auth_state.items)?;
                    
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
            authorization_details: Some(authorization_details),
            scope: None,
        })
    }
}

fn retain_details(
    requested: &Option<Vec<AuthorizationDetail>>, items: &[AuthorizedItem],
) -> Result<Vec<AuthorizedItem>> {
    // filter previously authorized DetailItems by requested authorization_details
    let Some(req_dets) = requested else { return Ok(items.to_vec()) };

    let filtered = items
        .iter()
        .filter(|item| {
            if let ItemType::AuthorizationDetail(ad) = &item.item {
                req_dets.iter().any(|reqd| ad.credential == reqd.credential)
            } else {
                false
            }
        })
        .cloned()
        .collect::<Vec<_>>();

    if filtered.is_empty() {
        return Err(Error::InvalidRequest("no matching authorization details".into()));
    }

    Ok(filtered)
}

fn authorized_details(items: &[AuthorizedItem]) -> Vec<AuthorizedDetail> {
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

    authorization_details
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
    use vercre_macros::token_request;
    use vercre_openid::issuer::{
        AuthorizationDetail, AuthorizationDetailType, CredentialAuthorization,
        CredentialDefinition, CredentialFormat, FormatIdentifier, ProfileW3c,
    };
    use vercre_test_utils::issuer::{Provider, CLIENT_ID, CREDENTIAL_ISSUER, NORMAL_USER};
    use vercre_test_utils::snapshot;

    use super::*;
    use crate::state::{Authorization, PreAuthorization};
    extern crate self as vercre_issuer;

    #[tokio::test]
    async fn pre_authorized() {
        vercre_test_utils::init_tracer();
        snapshot!("");

        let provider = Provider::new();

        // set up PreAuthorized state
        let state = State {
            stage: Stage::PreAuthorized(PreAuthorization {
                items: vec![AuthorizedItem {
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
                }],
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
        let request = token_request!({
            "credential_issuer": CREDENTIAL_ISSUER,
            "client_id": CLIENT_ID,
            "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "pre-authorized_code": pre_auth_code,
            "tx_code": "1234"
        });
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
        vercre_test_utils::init_tracer();
        snapshot!("");

        let provider = Provider::new();
        let verifier = "ABCDEF12345";

        // set up Authorization state
        let state = State {
            stage: Stage::Authorized(Authorization {
                code_challenge: Base64UrlUnpadded::encode_string(&Sha256::digest(verifier)),
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
        let request = token_request!({
            "credential_issuer": CREDENTIAL_ISSUER,
            "client_id": CLIENT_ID,
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
        });
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
        vercre_test_utils::init_tracer();
        snapshot!("");

        let provider = Provider::new();
        let verifier = "ABCDEF12345";

        // set up Authorization state
        let state = State {
            stage: Stage::Authorized(Authorization {
                client_id: CLIENT_ID.into(),
                redirect_uri: Some("https://example.com".into()),
                code_challenge: Base64UrlUnpadded::encode_string(&Sha256::digest(verifier)),
                code_challenge_method: "S256".into(),
                items: vec![AuthorizedItem {
                    item: ItemType::AuthorizationDetail(AuthorizationDetail {
                        type_: AuthorizationDetailType::OpenIdCredential,
                        credential: CredentialAuthorization::Format(CredentialFormat {
                            format: FormatIdentifier::JwtVcJson(ProfileW3c {
                                credential_definition: CredentialDefinition {
                                    type_: Some(vec![
                                        "VerifiableCredential".into(),
                                        "EmployeeIDCredential".into(),
                                    ]),
                                    ..CredentialDefinition::default()
                                },
                            }),
                        }),
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
        let request = token_request!({
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
