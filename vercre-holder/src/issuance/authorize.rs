//! # Authorize Endpoint
//!
//! The authorize endpoint is used by the holder when initiating an issuance
//! (that is, it is not initiated by the issuer). The endpoint is used to
//! request authorization for one or more credentials and, optionally, claims
//! contained by those credentials. If authorization is granted by the issuer,
//! the response can be used to request a token that can be exchanged for the
//! credentials.
//!
//! The endpoint is also used in the case where the issuer initiates the flow
//! but in the offer, inidicates to the holder that authorization is required.

use anyhow::bail;
use vercre_core::pkce;
use vercre_issuer::{AuthorizationRequest, GrantType, RequestObject};

use super::{IssuanceState, Status};
use crate::issuance::FlowType;

impl IssuanceState {
    /// Construct an authorization request from the current state.
    ///
    /// # Errors
    /// Will return an error if the current state is inconsistent with making an
    /// authorization request.
    pub fn authorization_request(
        &mut self, redirect_uri: Option<&str>,
    ) -> anyhow::Result<AuthorizationRequest> {
        if self.status != Status::Accepted {
            bail!("holder has not accepted an offer or set acceptable credentials from metadata so cannot authorize");
        }
        // Check issuer's authorization server metadata supports the
        // authorization code grant.
        let Some(issuer) = &self.issuer else {
            bail!("issuer metadata not set");
        };
        let Some(authorization_server) = &self.authorization_server else {
            bail!("authorization server metadata not set");
        };
        let Some(grant_types) = &authorization_server.oauth.grant_types_supported else {
            bail!("authorization server does not support any grant types");
        };
        if !grant_types.contains(&GrantType::AuthorizationCode) {
            bail!("authorization server does not support authorization code grant");
        }
        let Some(code_challenge_methods) =
            &authorization_server.oauth.code_challenge_methods_supported
        else {
            bail!("code challenge methods missing from authorization server metadata");
        };

        let mut issuer_state: Option<String> = None;

        // Validate state.
        match self.flow_type {
            FlowType::IssuerPreAuthorized => {
                bail!("cannot construct an authorization request for an issuer-initiated flow that is pre-authorized");
            }
            FlowType::IssuerAuthorized => {
                let Some(offer) = &self.offer else {
                    bail!("no offer on issuance state");
                };
                if let Some(grants) = &offer.grants {
                    if grants.authorization_code.is_none() {
                        bail!("offer does not support authorization code grant");
                    }
                    issuer_state = grants
                        .authorization_code
                        .as_ref()
                        .and_then(|auth_code| auth_code.issuer_state.clone());
                };
            }
            FlowType::HolderAuthDetail => {
                if self.accepted.is_none() {
                    bail!("authorization details are required for wallet-initiated issuance that doesn't use scope");
                }
                if self.scope.is_some() {
                    bail!("scope cannot be provided for wallet-initiated issuance that uses authorization details");
                }
            }
            FlowType::HolderScope => {
                if self.accepted.is_some() {
                    bail!("authorization details cannot be provided for wallet-initiated issuance that uses scope");
                }
                if self.scope.is_none() {
                    bail!("scope is required for wallet-initiated issuance that doesn't use authorization details");
                }
            }
        };

        // PKCE pair
        let verifier = pkce::code_verifier();
        let code_challenge = pkce::code_challenge(&verifier);
        self.code_challenge = Some(code_challenge.clone());
        self.code_verifier = Some(verifier);

        Ok(AuthorizationRequest::Object(RequestObject {
            credential_issuer: issuer.credential_issuer.clone(),
            response_type: authorization_server.oauth.response_types_supported[0].clone(),
            client_id: self.client_id.clone(),
            redirect_uri: redirect_uri.map(ToString::to_string),
            state: Some(self.id.clone()),
            code_challenge,
            code_challenge_method: code_challenge_methods[0].clone(),
            authorization_details: self.accepted.clone(),
            scope: self.scope.clone(),
            resource: Some(issuer.credential_issuer.clone()),
            subject_id: self.subject_id.clone(),
            wallet_issuer: None,
            user_hint: Some(self.id.clone()),
            issuer_state,
        }))
    }
}
