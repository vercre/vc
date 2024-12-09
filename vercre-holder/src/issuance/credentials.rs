//! # Credentials Endpoint
//!
//! Use an access token to get the credentials accepted by the holder.

use anyhow::bail;
use chrono::DateTime;
use vercre_core::{Kind, Quota};
use vercre_issuer::{
    CredentialAuthorization, CredentialIssuance, Format, SingleProof, TokenResponse
};
use vercre_macros::credential_request;
use vercre_openid::issuer::{CredentialRequest, Issuer as IssuerMetadata, Proof, ProofClaims};
use vercre_w3c_vc::model::VerifiableCredential;

use super::{CredentialRequestType, IssuanceState, Status};
use crate::credential::Credential;

impl IssuanceState {
    /// Construct a proof to be used in the credential requests.
    ///
    /// # Errors
    /// Will return an error if the flow state is inconsistent with constructing
    /// credential requests.
    pub fn proof(&self) -> anyhow::Result<ProofClaims> {
        let Some(token_response) = &self.token else {
            bail!("no token response in issuance state");
        };
        let Some(issuer) = &self.issuer else {
            bail!("no issuer metadata in issuance state");
        };
        let claims = ProofClaims {
            iss: Some(self.client_id.clone()),
            aud: issuer.credential_issuer.clone(),
            iat: chrono::Utc::now().timestamp(),
            nonce: token_response.c_nonce.clone(),
        };
        Ok(claims)
    }

    /// Construct a set of credential requests from authorization details and
    /// specified scope.
    ///
    /// The tuple contains the credential configuration ID for ease of lookup in
    /// issuer metadata as well as the credential request itself.
    ///
    /// # Errors
    /// Will return an error if the flow state is inconsistent with constructing
    /// credential requests.
    pub fn credential_requests(
        &self, request_type: CredentialRequestType, jwt: &str,
    ) -> anyhow::Result<Vec<(String, CredentialRequest)>> {
        if self.status != Status::TokenReceived {
            bail!("invalid issuance state status");
        }
        let Some(token_response) = &self.token else {
            bail!("no token response in issuance state");
        };
        let Some(issuer) = &self.issuer else {
            bail!("no issuer metadata in issuance state");
        };

        // Shell out to a scope or identifier based request builder.
        match request_type {
            CredentialRequestType::Format(format) => {
                let Some(scope) = self.scope.clone() else {
                    bail!("can only make format-based requests for holder-initiated, scope-based issuance");
                };
                Self::credential_requests_by_format(&format, &scope, issuer, token_response, jwt)
            }
            CredentialRequestType::CredentialIdentifiers(identifiers) => {
                Self::credential_requests_by_identifier(&identifiers, issuer, token_response, jwt)
            }
        }
    }

    /// Construct a set of credential requests by format.
    ///
    /// # Errors
    /// Will return an error if the issuer metadata contains no credential
    /// configuration with the specified format and scope.
    fn credential_requests_by_format(
        format: &Format, scope: &str, issuer: &IssuerMetadata, token: &TokenResponse, jwt: &str,
    ) -> anyhow::Result<Vec<(String, CredentialRequest)>> {
        let config = issuer
            .credential_configurations_supported
            .iter()
            .find(|(_, cfg)| cfg.scope.as_deref() == Some(scope) && cfg.format == *format);
        let Some((cfg_id, config)) = config else {
            bail!("credential configuration not found for scope and format");
        };
        let request = CredentialRequest {
            credential_issuer: issuer.credential_issuer.clone(),
            access_token: token.access_token.clone(),
            credential: CredentialIssuance::Format(config.format.clone()),
            proof: Some(Proof::Single {
                proof_type: SingleProof::Jwt { jwt: jwt.into() },
            }),
            ..Default::default()
        };
        Ok(vec![(cfg_id.to_string(), request)])
    }

    /// Construct a set of credential requests by credential identifier.
    ///
    /// # Errors
    /// Will return an error if the issuer metadata does not contain one of the
    /// requested credential identifiers or if the authorization details are
    /// inconsistent with issuer metadata.
    fn credential_requests_by_identifier(
        identifiers: &[String], issuer: &IssuerMetadata, token: &TokenResponse, jwt: &str,
    ) -> anyhow::Result<Vec<(String, CredentialRequest)>> {
        let Some(authorized) = &token.authorization_details else {
            bail!("no authorization details in token response");
        };
        let mut requests = Vec::new();
        for auth in authorized {
            let cfg_id = match &auth.authorization_detail.credential {
                CredentialAuthorization::ConfigurationId {
                    credential_configuration_id,
                    ..
                } => credential_configuration_id,
                CredentialAuthorization::Format(format_identifier) => {
                    match issuer.credential_configuration_id(format_identifier) {
                        Ok(cfg_id) => cfg_id,
                        Err(e) => {
                            tracing::error!(target: "Endpoint::credentials", ?e);
                            return Err(e);
                        }
                    }
                }
            };
            // Check the issuer supports this credential configuration. This will only fail if the
            // wallet has messed with state outside of the intended mutation methods.
            let Some(_) = issuer.credential_configurations_supported.get(cfg_id) else {
                bail!("authorized credential configuration not found in issuer metadata");
            };
            for cred_id in &auth.credential_identifiers {
                // Check the holder wants this credential.
                if !identifiers.to_vec().contains(cred_id) {
                    continue;
                }
                let request = credential_request!({
                    "credential_issuer": issuer.credential_issuer.clone(),
                    "access_token": token.access_token.clone(),
                    "credential_identifier": cred_id.to_string(),
                    "proof": {
                        "proof_type": "jwt",
                        "jwt": jwt.to_string()
                    }
                });
                requests.push((cfg_id.to_string(), request));
            }
        }
        Ok(requests)
    }

    /// Add a credential to the issuance state, converting the W3C format to a
    /// convenient wallet format.
    ///
    /// # Errors
    /// Will return an error if the current state does not contain the metadata
    /// required to combine with the provided VC.
    pub fn add_credential(
        &mut self, vc: &VerifiableCredential, encoded: &Kind<VerifiableCredential>,
        issued_at: &i64, config_id: &str,
    ) -> anyhow::Result<()> {
        let Some(issuance_date) = DateTime::from_timestamp(*issued_at, 0) else {
            bail!("invalid issuance date");
        };

        let Some(issuer) = &self.issuer else {
            bail!("no issuer metadata in issuance state");
        };
        let issuer_id = issuer.credential_issuer.clone();

        // TODO: Locale support.
        let issuer_name = {
            if let Some(display) = issuer.display.clone() {
                display.name
            } else {
                issuer_id.clone()
            }
        };

        let Some(config) = issuer.credential_configurations_supported.get(config_id) else {
            bail!("credential configuration not found in issuer metadata");
        };

        // TODO: add support for embedded proof
        let Kind::String(token) = encoded else {
            bail!("credential is not a JWT");
        };

        // Turn a Quota of Strings into a Vec of Strings for the type of credential.
        let mut type_ = Vec::new();
        match &vc.type_ {
            Quota::One(t) => type_.push(t.clone()),
            Quota::Many(vc_types) => type_.extend(vc_types.clone()),
        }

        // Turn a Quota of credential subjects into a Vec of claim sets.
        let mut subject_claims = Vec::new();
        match vc.credential_subject.clone() {
            Quota::One(cs) => subject_claims.push(cs.into()),
            Quota::Many(vc_claims) => {
                for cs in vc_claims {
                    subject_claims.push(cs.into());
                }
            }
        }

        let storable_credential = Credential {
            id: vc.id.clone().unwrap_or_else(|| format!("urn:uuid:{}", uuid::Uuid::new_v4())),
            issuer: issuer_id,
            issuer_name,
            type_,
            format: config.format.to_string(),
            subject_claims,
            claim_definitions: config.format.claims(),
            issued: token.into(),
            issuance_date,
            valid_from: vc.valid_from,
            valid_until: vc.valid_until,
            display: config.display.clone(),
            logo: None,
            background: None,
        };

        self.credentials.push(storable_credential);
        Ok(())
    }
}
