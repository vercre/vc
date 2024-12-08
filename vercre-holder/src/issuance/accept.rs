//! # Issuance Offer Acceptance
//!
//! The `accept` endpoint is used to register acceptance of a credential
//! issuance offer with the issuance flow. If a PIN is required, this endpoint
//! will simply update the state to indicate that, otherwise it will proceed
//! with the token request and credential requests.
//!
//! The holder is not obligated to accept all credentials offered. Use the
//! `accept` field to limit the scope of the acceptance. This will be used
//! downstream in the flow to specialize the access token and credential
//! requests which are honored by the respective `vercre-issuer` endpoints.

use std::collections::HashMap;

use anyhow::bail;
use serde::{Deserialize, Serialize};
use vercre_issuer::{
    AuthorizationDetail, Claim, CredentialAuthorization, CredentialDefinition, Format,
    ProfileClaims,
};

use super::{FlowType, IssuanceState, Status};

/// A configuration ID and a list of claims that can be used by the holder to
/// narrow the scope of the acceptance from the full set on offer.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthorizationSpec {
    /// The credential configuration ID to include.
    pub credential_configuration_id: String,

    /// The list of claims to include.
    ///
    /// If `None`, all claims are included.
    pub claims: Option<HashMap<String, Claim>>,
}

impl IssuanceState {
    /// Progresses the issuance flow triggered by a holder accepting a credential
    /// offer.
    ///
    /// # Errors
    /// Will return an error if the issuance state is not in a state consistent
    /// with accepting an offer.
    #[allow(clippy::cognitive_complexity)]
    pub fn accept(&mut self, accept: &Option<Vec<AuthorizationSpec>>) -> anyhow::Result<()> {
        if self.status != Status::Offered {
            bail!("invalid issuance state status");
        }
        let Some(offer) = &self.offer else {
            bail!("no offer found to accept");
        };
        if let Some(accepted) = &accept {
            if accepted.is_empty() {
                bail!("if accept is provided it cannot be empty. To accept all credentials, send `None`.");
            }
        };

        self.accepted = self.accept_filter(accept.as_ref())?;

        self.status = Status::Accepted;

        if let Some(grants) = &offer.grants {
            if let Some(pre_auth_code) = &grants.pre_authorized_code {
                if pre_auth_code.tx_code.is_some() {
                    self.status = Status::PendingPin;
                }
            }
        }

        Ok(())
    }

    /// Accept specified credentials. Pass `None` to accept all credentials on
    /// offer.
    fn accept_filter(
        &self, accept: Option<&Vec<AuthorizationSpec>>,
    ) -> anyhow::Result<Option<Vec<AuthorizationDetail>>> {
        let Some(issuer) = &self.issuer else {
            bail!("no issuer metadata on state");
        };
        let creds_supported = &issuer.credential_configurations_supported;
        let Some(offer) = &self.offer else {
            bail!("no offer found to accept");
        };
        let mut auth_details = Vec::new();
        for cfg_id in &offer.credential_configuration_ids {
            let Some(cred_config) = creds_supported.get(cfg_id) else {
                bail!("offer on state has credential configuration not found in metadata");
            };
            if let Some(accept) = &accept {
                if !accept.iter().any(|a| a.credential_configuration_id == *cfg_id) {
                    continue;
                }
            }
            let claims: Option<ProfileClaims> =
                cred_config.format.claims().map(|claims| match &cred_config.format {
                    Format::JwtVcJson(w3c) | Format::LdpVc(w3c) | Format::JwtVcJsonLd(w3c) => {
                        ProfileClaims::W3c(CredentialDefinition {
                            credential_subject: w3c
                                .credential_definition
                                .credential_subject
                                .clone(),
                            ..Default::default()
                        })
                    }
                    Format::IsoMdl(_) | Format::VcSdJwt(_) => ProfileClaims::Claims(claims),
                });
            // TODO: Support CredentialAuthorization::Format
            let detail = AuthorizationDetail {
                credential: CredentialAuthorization::ConfigurationId {
                    credential_configuration_id: cfg_id.clone(),
                    claims,
                },
                ..Default::default()
            };
            auth_details.push(detail);
        }
        Ok(Some(auth_details))
    }

    /// Set the accepted credentials by specification directly. Used for holder-
    /// initiated flows where there is no check against an offer from an issuer.
    ///
    /// # Errors
    /// Will return an error if the flow is not holder-initiated by
    /// authorization detail.
    pub fn accept_direct(&mut self, accepted: Vec<AuthorizationDetail>) -> anyhow::Result<()> {
        if !matches!(self.flow_type, FlowType::HolderAuthDetail) {
            bail!("accept_direct is only for holder-initiated flows by authorization detail");
        }
        self.accepted = Some(accepted);
        self.status = Status::Accepted;
        Ok(())
    }

    /// Set the scope directly on the issuance state.
    ///
    /// # Errors
    /// Will return an error if the flow type is not holder-initiated by scope.
    pub fn scope_direct(&mut self, scope: &str) -> anyhow::Result<()> {
        if !matches!(self.flow_type, FlowType::HolderScope) {
            bail!("scope can only be set for holder-initiated issuance by scope");
        }
        self.scope = Some(scope.to_string());
        self.status = Status::Accepted;
        Ok(())
    }
}
