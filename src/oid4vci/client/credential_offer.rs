//! # Create Offer Builder

use crate::oauth::GrantType;
use crate::oid4vci::types::{CreateOfferRequest, SendType};

/// Build a Credential Offer for a Credential Issuer.
#[derive(Default, Debug)]
pub struct CreateOfferRequestBuilder {
    subject_id: Option<String>,
    credential_configuration_ids: Vec<String>,
    grant_types: Vec<GrantType>,
    tx_code: bool,
    by_ref: bool,
}

impl CreateOfferRequestBuilder {
    /// Create a new `CreateOfferRequestBuilder`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            subject_id: None,
            credential_configuration_ids: Vec::new(),
            grant_types: vec![GrantType::PreAuthorizedCode],
            tx_code: true,
            by_ref: false,
        }
    }

    /// Specify the (previously authenticated) Holder for the Issuer to use
    /// when authorizing credential issuance.
    #[must_use]
    pub fn subject_id(mut self, subject_id: impl Into<String>) -> Self {
        self.subject_id = Some(subject_id.into());
        self
    }

    /// Specify one or more credentials to include in the offer using a
    /// key from `credential_configurations_supported` metadata attribute.
    #[must_use]
    pub fn with_credential(mut self, configuration_id: impl Into<String>) -> Self {
        self.credential_configuration_ids.push(configuration_id.into());
        self
    }

    /// Specify a grant to include in the offer.
    #[must_use]
    pub fn with_grant(mut self, grant: GrantType) -> Self {
        self.grant_types.push(grant);
        self
    }

    /// Specify whether a Transaction Code (PIN) is required by the `token`
    /// endpoint during the Pre-Authorized Code Flow.
    #[must_use]
    pub const fn use_tx_code(mut self, tx_code_required: bool) -> Self {
        self.tx_code = tx_code_required;
        self
    }

    /// Specify whether Credential Offer should be an object or a URI.
    #[must_use]
    pub const fn by_ref(mut self, by_ref: bool) -> Self {
        self.by_ref = by_ref;
        self
    }

    /// Build the Create Offer request.
    #[must_use]
    pub fn build(self) -> CreateOfferRequest {
        let send_type = if self.by_ref { SendType::ByRef } else { SendType::ByVal };

        let mut request = CreateOfferRequest {
            subject_id: self.subject_id,
            credential_configuration_ids: self.credential_configuration_ids,
            grant_types: None,
            tx_code_required: self.tx_code,
            send_type,
        };

        if !self.grant_types.is_empty() {
            request.grant_types = Some(self.grant_types);
        }

        request
    }
}
