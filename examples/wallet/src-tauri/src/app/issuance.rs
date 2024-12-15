//! Application state implementation for issuance operations.

use anyhow::bail;
use test_utils::issuer::NORMAL_USER;
use vercre_holder::issuance::{
    Accepted, IssuanceFlow, NotAccepted, PreAuthorized, WithOffer, WithToken, WithoutToken,
};
use vercre_holder::jose::{jws, Type};
use vercre_holder::proof::{Payload, Verify};
use vercre_holder::provider::{CredentialStorer, Issuer};
use vercre_holder::{CredentialOffer, CredentialResponseType, MetadataRequest, OAuthServerRequest};

use super::{AppState, SubApp};
use crate::provider::Provider;
use crate::CLIENT_ID;

/// Issuance flow state.
#[derive(Clone, Debug, Default)]
pub enum IssuanceState {
    /// No issuance is in progress.
    #[default]
    Inactive,

    /// An offer has been received, has been combined with metadata and is
    /// ready to present to the user for acceptance.
    Offered(IssuanceFlow<WithOffer, PreAuthorized, NotAccepted, WithoutToken>),

    /// An offer has been accepted.
    /// A PIN may also be set on this state.
    Accepted(IssuanceFlow<WithOffer, PreAuthorized, Accepted, WithoutToken>),

    /// An offer has been accepted and a token has been received.
    Token(IssuanceFlow<WithOffer, PreAuthorized, Accepted, WithToken>),
}

impl AppState {
    /// Process a credential issuance offer.
    pub async fn offer(&mut self, encoded_offer: &str, provider: Provider) -> anyhow::Result<()> {
        let offer_str = urlencoding::decode(encoded_offer)?;
        let offer = serde_json::from_str::<CredentialOffer>(&offer_str)?;

        // Check the offer has a pre-authorized grant. This is the only flow
        // type supported by this example.
        let Some(pre_auth_code_grant) = offer.pre_authorized_code() else {
            bail!("grant other than pre-authorized code is not supported");
        };

        // Get issuer metadata.
        let metadata_request = MetadataRequest {
            credential_issuer: offer.credential_issuer.clone(),
            languages: None,
        };
        let issuer_metadata = provider.metadata(metadata_request).await?;

        // Get authorization server metadata.
        let auth_request = OAuthServerRequest {
            credential_issuer: offer.credential_issuer.clone(),
            issuer: None,
        };
        let auth_metadata = provider.oauth_server(auth_request).await?;

        // Initiate flow state with the offer and metadata.
        let state = IssuanceFlow::<WithOffer, PreAuthorized, NotAccepted, WithoutToken>::new(
            CLIENT_ID,
            NORMAL_USER,
            issuer_metadata.credential_issuer,
            auth_metadata.authorization_server,
            offer,
            pre_auth_code_grant,
        );

        self.issuance = IssuanceState::Offered(state);
        self.sub_app = SubApp::Issuance;
        Ok(())
    }

    /// Accept a credential issuance offer.
    pub fn accept(&mut self) -> anyhow::Result<()> {
        // Just accept whatever is offered. In a real app, the user would need
        // to select which credentials to accept.
        match &self.issuance {
            IssuanceState::Offered(state) => {
                let accepted = state.clone().accept(&None, None);
                self.issuance = IssuanceState::Accepted(accepted);
                Ok(())
            }
            _ => bail!("no offer to accept"),
        }
    }

    /// Set a PIN
    pub fn pin(&mut self, pin: &str) -> anyhow::Result<()> {
        match &self.issuance {
            IssuanceState::Accepted(accepted) => {
                let mut state = accepted.clone();
                state.set_pin(pin);
                self.issuance = IssuanceState::Accepted(state);
                Ok(())
            }
            _ => bail!("no offer to accept"),
        }
    }

    /// Get the credentials for the accepted issuance offer.
    pub async fn credentials(&mut self, provider: Provider) -> anyhow::Result<()> {
        let state = match &self.issuance {
            IssuanceState::Accepted(s) => s.clone(),
            _ => bail!("unexpected issuance state for constructing a token request"),
        };
        log::info!("Getting an access token for issuance {}", state.id());

        // Request an access token from the issuer.
        let token_request = state.clone().token_request();
        let token_response = provider.token(token_request).await?;
        let mut state = state.token(token_response.clone());

        log::info!("Getting credentials for issuance {}", state.id());
        // In a real app, there may be multiple credentials to receive. We just
        // take the first one in this example.
        let Some(authorized) = &token_response.authorization_details else {
            bail!("no authorized credentials in token response");
        };
        let identifier = authorized[0].credential_identifiers[0].clone();
        let jws_claims = state.proof();
        let jwt = jws::encode(Type::Openid4VciProofJwt, &jws_claims, &provider).await?;

        let requests = state.credential_requests(&[identifier], &jwt).clone();
        let request = requests[0].clone();
        let credential_response = provider.credential(request.1).await?;
        match credential_response.response {
            CredentialResponseType::Credential(vc_kind) => {
                // Single credential in response.
                let Payload::Vc { vc, issued_at } =
                    vercre_holder::proof::verify(Verify::Vc(&vc_kind), provider.clone())
                        .await
                        .expect("should parse credential")
                else {
                    panic!("expected Payload::Vc");
                };
                state.add_credential(&vc, &vc_kind, &issued_at, &request.0)?;
            }
            CredentialResponseType::Credentials(creds) => {
                // Multiple credentials in response.
                for vc_kind in creds {
                    let Payload::Vc { vc, issued_at } =
                        vercre_holder::proof::verify(Verify::Vc(&vc_kind), provider.clone())
                            .await
                            .expect("should parse credential")
                    else {
                        panic!("expected Payload::Vc");
                    };
                    state.add_credential(&vc, &vc_kind, &issued_at, &request.0)?;
                }
            }
            CredentialResponseType::TransactionId(tx_id) => {
                // Deferred transaction ID.
                state.add_deferred(&tx_id, &request.0);
            }
        }

        self.issuance = IssuanceState::Token(state);
        Ok(())
    }

    /// Save the credential to storage.
    // TODO: Notify issuer of completion or failure if the issuer has given us
    // a notification ID.
    pub async fn save(&self, provider: Provider) -> anyhow::Result<()> {
        let state = match &self.issuance {
            IssuanceState::Token(s) => s.clone(),
            _ => bail!("unexpected issuance state for saving credentials"),
        };
        let credentials = state.credentials();
        for credential in &credentials {
            provider.save(credential).await?;
        }
        Ok(())
    }
}
