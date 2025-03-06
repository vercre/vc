//! # Token Request Builder

use crate::oid4vci::types::{AuthorizationDetail, TokenGrantType, TokenRequest};

/// Build a Token Request.
#[derive(Default, Debug)]
pub struct TokenRequestBuilder {
    client_id: Option<String>,
    grant_type: Option<TokenGrantType>,
    authorization_details: Option<Vec<AuthorizationDetail>>,
}

impl TokenRequestBuilder {
    /// Create a new `CreateOfferRequestBuilder`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Specify the Wallet's Client ID.
    ///
    /// This is required if the client is not authenticating with the
    /// authorization server. For the Pre-Authorized Code Grant Type,
    /// client authentication is optional.
    #[must_use]
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Specify a grant to include in the offer.
    #[must_use]
    pub fn grant_type(mut self, grant_type: TokenGrantType) -> Self {
        self.grant_type = Some(grant_type);
        self
    }

    /// Specify Authorization Details when needing to request a specific
    /// credential configuration.
    #[must_use]
    pub fn with_authorization_detail(mut self, authorization_detail: AuthorizationDetail) -> Self {
        self.authorization_details.get_or_insert_with(Vec::new).push(authorization_detail);
        self
    }

    /// Build the Create Offer request.
    #[must_use]
    pub fn build(self) -> TokenRequest {
        let Some(grant_type) = self.grant_type else {
            // FIXME: use typestate pattern to enforce required fields
            panic!("grant_type is required");
        };

        let request = TokenRequest {
            client_id: self.client_id,
            grant_type,
            authorization_details: self.authorization_details,
            ..TokenRequest::default()
        };

        request
    }
}
