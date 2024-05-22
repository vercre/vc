//! # Credential Response endpoint.
//!
//! Processes a credential response from the issuance service, uses the provider to store the
//! credential in persistent storage, and clears the issuance state.

use std::fmt::Debug;
use std::str::FromStr;

use tracing::instrument;
use vercre_core::error::Err;
use vercre_core::provider::{Callback, Signer, StateManager, Storer};
use vercre_core::vci::CredentialResponse;
use vercre_core::w3c::VerifiableCredential;
use vercre_core::{err, Result};

use crate::credential::Credential;
use crate::issuance::{Issuance, Status};
use crate::Endpoint;

impl<P> Endpoint<P>
where
    P: Callback + Signer + StateManager + Storer + Clone + Debug,
{
    /// Credential response endpoint receives a credential response and stores the credential in
    /// the wallet client's persistent storage.
    #[instrument(level = "debug", skip(self))]
    pub async fn credential_response(&self, request: &CredentialResponse) -> Result<Credential> {
        let ctx = Context {
            _p: std::marker::PhantomData,
            vc: VerifiableCredential::default(),
            vc_str: String::default(),
            issuance: Issuance::default(),
        };

        vercre_core::Endpoint::handle_request(self, request, ctx).await
    }
}

#[derive(Debug, Default)]
struct Context<P> {
    _p: std::marker::PhantomData<P>,
    vc: VerifiableCredential,
    vc_str: String,
    issuance: Issuance,
}

impl<P> vercre_core::Context for Context<P>
where
    P: StateManager + Storer + Debug,
{
    type Provider = P;
    type Request = CredentialResponse;
    type Response = Credential;

    async fn verify(&mut self, provider: &P, req: &Self::Request) -> Result<&Self> {
        tracing::debug!("Context::verify");

        // Check we are processing an offer and we are at the expected point in the flow.
        let Some(stashed) = provider.get_opt("issuance").await? else {
            err!(Err::InvalidRequest, "no issuance in progress");
        };
        let issuance: Issuance = serde_json::from_slice(&stashed)?;
        if issuance.status != Status::Requested {
            err!(Err::InvalidRequest, "invalid issuance status");
        }
        let Some(value) = req.credential.as_ref() else {
            err!(Err::InvalidRequest, "missing credential");
        };
        let Some(vc_str) = value.as_str() else {
            err!(Err::InvalidRequest, "credential is not a string");
        };
        let Ok(vc) = VerifiableCredential::from_str(vc_str) else {
            err!(Err::InvalidRequest, "could not parse credential");
        };
        self.vc = vc;
        self.vc_str = vc_str.to_string();
        self.issuance = issuance;

        Ok(self)
    }

    async fn process(&self, provider: &P, req: &Self::Request) -> Result<Self::Response> {
        tracing::debug!("Context::process");

        let mut credential = Credential::default();
        let mut issuance = self.issuance.clone();
        let mut cred_key: Option<String> = None;
        for (key, cfg) in issuance.offered.iter() {
            if cfg.credential_definition.type_.as_ref() == Some(&self.vc.type_) {
                // Store the credential in the wallet's persistent storage.
                credential.id = self.vc.id.clone();
                credential.issuer = issuance.offer.credential_issuer.clone();
                credential.metadata = cfg.clone();
                credential.vc = self.vc.clone();
                credential.issued = self.vc_str.clone();

                provider.save(key, serde_json::to_vec(&credential)?).await?;

                cred_key = Some(key.clone());
            }
        }

        if cred_key.is_none() {
            err!(Err::InvalidRequest, "credential type not found in offer");
        }

        // Update issuance state. Remove the offer for the credential.
        issuance.offered.remove(&cred_key.unwrap());

        // If there are no offers left, remove the entire state, otherwise update the nonce if
        // necessary.
        if issuance.offered.is_empty() {
            provider.purge("issuance").await?;
        } else {
            if req.c_nonce.is_some() {
                issuance.token.c_nonce = req.c_nonce.clone();
            }
            if req.c_nonce_expires_in.is_some() {
                issuance.token.c_nonce_expires_in = req.c_nonce_expires_in.clone();
            }
            provider.put_opt("issuance", serde_json::to_vec(&issuance)?, None).await?;
        }

        Ok(credential)
    }
}
