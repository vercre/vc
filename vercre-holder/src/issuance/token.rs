//! # Token Endpoint
//!
//! The token endpoint is used to request a token from the issuer. The token
//! response will contain the access token and a list of credential identifiers
//! that the holder can request from the issuer.

use anyhow::bail;
use vercre_issuer::{TokenGrantType, TokenRequest, TokenResponse};

use super::{FlowType, IssuanceState, Status};

impl IssuanceState {
    /// Construct a token request from current state.
    ///
    /// # Errors
    /// Will return an error if the current state is inconsistent with making a
    /// token request.
    pub fn token_request(
        &self, redirect_uri: Option<&str>, auth_code: Option<&str>,
    ) -> anyhow::Result<TokenRequest> {
        let Some(issuer) = &self.issuer else {
            bail!("no issuer metadata in issuance state");
        };
        let token_request = if matches!(&self.flow_type, FlowType::IssuerPreAuthorized) {
            let Some(offer) = &self.offer else {
                bail!("no offer in issuance state");
            };
            let Some(grants) = &offer.grants else {
                bail!("no grants in offer is not supported");
            };
            let Some(pre_auth_code) = &grants.pre_authorized_code else {
                bail!("no pre-authorized code in offer is not supported");
            };
            TokenRequest {
                credential_issuer: issuer.credential_issuer.clone(),
                client_id: Some(self.client_id.clone()),
                grant_type: TokenGrantType::PreAuthorizedCode {
                    pre_authorized_code: pre_auth_code.pre_authorized_code.clone(),
                    tx_code: self.pin.clone(),
                },
                authorization_details: self.accepted.clone(),
                // TODO: support this
                client_assertion: None,
            }
        } else {
            let Some(code) = &auth_code else {
                bail!("authorization code is required for a flow type other than pre-authorized");
            };
            TokenRequest {
                credential_issuer: issuer.credential_issuer.clone(),
                client_id: Some(self.client_id.clone()),
                grant_type: TokenGrantType::AuthorizationCode {
                    code: (*code).to_string(),
                    redirect_uri: redirect_uri.map(ToString::to_string),
                    code_verifier: self.code_verifier.clone(),
                },
                authorization_details: self.accepted.clone(),
                // TODO: support this
                client_assertion: None,
            }
        };
        Ok(token_request)
    }

    /// Add access token information to the issuance state.
    ///
    /// # Errors
    /// Will return an error if the current state is inconsistent with receiving
    /// an access token.
    pub fn token(&mut self, token: &TokenResponse) -> anyhow::Result<()> {
        if self.status != Status::Accepted {
            bail!("invalid issuance state status");
        }
        self.token = Some(token.clone());
        self.status = Status::TokenReceived;

        Ok(())
    }
}
