//! # Create Offer Builder

use crate::openid::issuer::{CreateOfferRequest, SendType};
use crate::openid::oauth::GrantType;

/// Build a Credential Offer for a Credential Issuer.
#[derive(Default, Debug)]
pub struct CreateOfferRequestBuilder {
    credential_issuer: Option<String>,
    subject_id: Option<String>,
    credential_configuration_ids: Vec<String>,
    grant_types: Vec<GrantType>,
    tx_code_required: bool,
    send_type: SendType,
}

impl CreateOfferRequestBuilder {
    /// Create a new `CreateOfferRequestBuilder`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Specify the (previously authenticated) Holder for the Issuer to use
    /// when authorizing credential issuance.
    pub fn credential_issuer(mut self, credential_issuer: impl Into<String>) -> Self {
        self.credential_issuer = Some(credential_issuer.into());
        self
    }

    /// Specify the (previously authenticated) Holder for the Issuer to use
    /// when authorizing credential issuance.
    pub fn subject_id(mut self, subject_id: impl Into<String>) -> Self {
        self.subject_id = Some(subject_id.into());
        self
    }

    /// Specify one or more credentials to include in the offer using a
    /// key from `credential_configurations_supported` metadata attribute.
    pub fn with_credential(mut self, configuration_id: impl Into<String>) -> Self {
        self.credential_configuration_ids.push(configuration_id.into());
        self
    }

    /// Specify a grant to include in the offer.
    pub fn with_grant(mut self, grant: GrantType) -> Self {
        self.grant_types.push(grant);
        self
    }

    /// Specify whether a Transaction Code (PIN) is required by the `token`
    /// endpoint during the Pre-Authorized Code Flow.
    pub fn tx_code_required(mut self, tx_code_required: bool) -> Self {
        self.tx_code_required = tx_code_required;
        self
    }

    /// Specify whether Credential Offer should be an object or a URI.
    pub fn send_type(mut self, send_type: SendType) -> Self {
        self.send_type = send_type;
        self
    }

    /// Build the Create Offer request.
    pub fn build(self) -> CreateOfferRequest {
        let mut request = CreateOfferRequest {
            credential_issuer: self.credential_issuer.unwrap_or_default(),
            subject_id: self.subject_id,
            credential_configuration_ids: self.credential_configuration_ids,
            grant_types: None,
            tx_code_required: self.tx_code_required,
            send_type: self.send_type,
        };

        if !self.grant_types.is_empty() {
            request.grant_types = Some(self.grant_types)
        }

        request
    }
}
