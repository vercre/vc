//! # Credential Request Builder

use core::panic;


use crate::oid4vci::types::{
     CredentialRequest, CredentialResponseEncryption, MultipleProofs, Proof,
    RequestBy, SingleProof,
};
// use crate::w3c_vc::proof::integrity::Proof;

/// Build a Credential Offer for a Credential Issuer.
#[derive(Default, Debug)]
pub struct CredentialRequestBuilder {
    credential_identifier: Option<String>,
    credential_configuration_id: Option<String>,
    proofs: Option<Vec<String>>,
    response_encryption: Option<CredentialResponseEncryption>,
    access_token: Option<String>,
}

impl CredentialRequestBuilder {
    /// Create a new `CreateOfferRequestBuilder`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Specify only when credential Authorization Details was returned in the
    /// Token Response.
    #[must_use]
    pub fn credential_identifier(mut self, credential_identifier: impl Into<String>) -> Self {
        self.credential_identifier = Some(credential_identifier.into());
        self
    }

    /// Specify only when credential Authorization Details was not returned in the
    /// Token Response.
    #[must_use]
    pub fn credential_configuration_id(
        mut self, credential_configuration_id: impl Into<String>,
    ) -> Self {
        self.credential_configuration_id = Some(credential_configuration_id.into());
        self
    }

    /// Specify the (previously authenticated) Holder for the Issuer to use
    /// when authorizing credential issuance.
    #[must_use]
    pub fn with_proof(mut self, proof_jwt: impl Into<String>) -> Self {
        self.proofs.get_or_insert_with(Vec::new).push(proof_jwt.into());
        self
    }

    /// Specify when the credential response is to be encrypted.
    #[must_use]
    pub fn response_encryption(
        mut self, response_encryption: CredentialResponseEncryption,
    ) -> Self {
        self.response_encryption = Some(response_encryption);
        self
    }

    /// Specify the access token to use for this credential request.
    #[must_use]
    pub fn access_token(mut self, access_token: impl Into<String>) -> Self {
        self.access_token = Some(access_token.into());
        self
    }

    /// Build the Create Offer request.
    #[must_use]
    pub fn build(self) -> CredentialRequest {
        // credential identifier
        let credential = if let Some(identifier) = self.credential_identifier {
            RequestBy::Identifier(identifier)
        } else if let Some(configuration_id) = self.credential_configuration_id {
            RequestBy::ConfigurationId(configuration_id)
        } else {
            // FIXME: use typestate pattern to enforce required fields
            panic!("credential_identifier or credential_configuration_id is required");
        };

        // proof
        let Some(proofs) = self.proofs else {
            panic!("at least one proof is required");
        };
        let proof = if proofs.len() == 1 {
            Some(Proof::Single {
                proof_type: SingleProof::Jwt {
                    jwt: proofs[0].clone(),
                },
            })
        } else {
            Some(Proof::Multiple(MultipleProofs::Jwt(proofs)))
        };

        let  request = CredentialRequest {
            credential,
            proof,
            credential_response_encryption: self.response_encryption,
            access_token: self.access_token.unwrap_or_default(),
        };

        request
    }
}
