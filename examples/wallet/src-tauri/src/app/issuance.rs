//! Application state implementation for issuance operations.

use anyhow::bail;
use test_utils::issuer::NORMAL_USER;
use vercre_holder::issuance::{CredentialRequestType, FlowType, IssuanceState};
use vercre_holder::provider::Issuer;
use vercre_holder::{CredentialOffer, CredentialResponseType, MetadataRequest, OAuthServerRequest};
use vercre_infosec::jose::{jws, Type};
use vercre_w3c_vc::proof::{Payload, Verify};

use super::{AppState, SubApp};
use crate::provider::Provider;
use crate::CLIENT_ID;

impl AppState {
    /// Process a credential issuance offer.
    pub async fn offer(&mut self, encoded_offer: &str, provider: Provider) -> anyhow::Result<()> {
        let offer_str = urlencoding::decode(encoded_offer)?;
        let offer = serde_json::from_str::<CredentialOffer>(&offer_str)?;

        // Check the offer has a pre-authorized grant. This is the only flow
        // type supported by this example.
        let Some(grants) = &offer.grants else {
            bail!("no grants in offer is not supported");
        };
        if grants.pre_authorized_code.is_none() {
            bail!("grant other than pre-authorized code is not supported");
        }

        // Initiate flow state.
        let mut state = IssuanceState::new(FlowType::IssuerPreAuthorized, CLIENT_ID, NORMAL_USER);

        // Add issuer metadata to flow state.
        let metadata_request = MetadataRequest {
            credential_issuer: offer.credential_issuer.clone(),
            languages: None,
        };
        let issuer_metadata = provider.metadata(metadata_request).await?;
        state.issuer(issuer_metadata.credential_issuer)?;

        // Add authorization server metadata to flow state.
        let auth_request = OAuthServerRequest {
            credential_issuer: offer.credential_issuer.clone(),
            issuer: None,
        };
        let auth_metadata = provider.oauth_server(auth_request).await?;
        state.authorization_server(auth_metadata.authorization_server)?;

        // Unpack the offer into the flow state.
        state.offer(&offer)?;

        self.issuance = state;
        self.sub_app = SubApp::Issuance;
        Ok(())
    }

    /// Accept a credential issuance offer.
    pub fn accept(&mut self) -> anyhow::Result<()> {
        // Just accept whatever is offered. In a real app, the user would need
        // to select which credentials to accept.
        self.issuance.accept(&None)
    }

    /// Set a PIN
    pub fn pin(&mut self, pin: &str) -> anyhow::Result<()> {
        self.issuance.pin(pin)
    }

    /// Get the credentials for the accepted issuance offer.
    pub async fn credentials(&mut self, provider: Provider) -> anyhow::Result<()> {
        log::info!("Getting an access token for issuance {}", self.issuance.id);
        let token_request = self.issuance.token_request(None, None)?;
        let token_response = provider.token(token_request).await?;
        self.issuance.token(&token_response)?;

        log::info!("Getting credentials for issuance {}", self.issuance.id);
        // In a real app, there may be multiple credentials to receive. We just
        // take the first one in this example.
        let Some(authorized) = &token_response.authorization_details else {
            bail!("no authorized credentials in token response");
        };
        let identifier = authorized[0].credential_identifiers[0].clone();
        let jws_claims = self.issuance.proof()?;
        let jwt = jws::encode(Type::Openid4VciProofJwt, &jws_claims, &provider).await?;
        let requests = self.issuance.credential_requests(
            CredentialRequestType::CredentialIdentifiers(vec![identifier]),
            &jwt,
        )?;
        let request = requests[0].clone();
        let credential_response = provider.credential(request.1).await?;
        match credential_response.response {
            CredentialResponseType::Credential(vc_kind) => {
                // Single credential in response.
                let Payload::Vc { vc, issued_at } =
                    vercre_w3c_vc::proof::verify(Verify::Vc(&vc_kind), provider.clone())
                        .await
                        .expect("should parse credential")
                else {
                    panic!("expected Payload::Vc");
                };
                self.issuance
                    .add_credential(&vc, &vc_kind, &issued_at, &request.0)
                    .expect("should add credential");
            }
            CredentialResponseType::Credentials(creds) => {
                // Multiple credentials in response.
                for vc_kind in creds {
                    let Payload::Vc { vc, issued_at } =
                        vercre_w3c_vc::proof::verify(Verify::Vc(&vc_kind), provider.clone())
                            .await
                            .expect("should parse credential")
                    else {
                        panic!("expected Payload::Vc");
                    };
                    self.issuance
                        .add_credential(&vc, &vc_kind, &issued_at, &request.0)
                        .expect("should add credential");
                }
            }
            CredentialResponseType::TransactionId(tx_id) => {
                // Deferred transaction ID.
                self.issuance.add_deferred(&tx_id, &request.0);
            }
        }
        Ok(())
    }

    /// Save the credential to storage.
    pub async fn save(&self, provider: Provider) -> anyhow::Result<()> {
        let request = vercre_holder::issuance::SaveRequest {
            issuance_id: self.issuance.id.clone(),
        };
        vercre_holder::issuance::save(provider, &request).await?;
        Ok(())
    }
}
