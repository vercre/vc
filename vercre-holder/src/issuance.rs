//! # Issuance
//!
//! The Issuance endpoints implement the vercre-holder's credential issuance
//! flow.
use std::collections::HashMap;
use std::fmt::Debug;

use anyhow::bail;
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vercre_core::{pkce, Kind, Quota};
use vercre_issuer::{
    AuthorizationDetail, AuthorizationRequest, Claim, CredentialAuthorization,
    CredentialConfiguration, CredentialDefinition, CredentialIssuance, CredentialOffer,
    CredentialRequest, DeferredCredentialRequest, Format, GrantType, PreAuthorizedCodeGrant,
    ProfileClaims, Proof, ProofClaims, RequestObject, SingleProof, TokenGrantType, TokenRequest,
    TokenResponse,
};
use vercre_macros::credential_request;
use vercre_openid::issuer::{Issuer, Server};
use vercre_w3c_vc::model::VerifiableCredential;

use crate::credential::Credential;

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

/// An issuance flow is used to orchestrate the change in state as the wallet
/// progresses through a credential issuance.
#[derive(Clone, Debug)]
pub struct IssuanceFlow<O, P, A, T> {
    offer: O,
    pre_authorized: P,
    accepted: A,
    token: T,

    /// Perhaps useful to the wallet for tracking a particular flow instance.
    id: String,
    
    client_id: String,
    subject_id: String,
    issuer: Issuer,
    authorization_server: Server,
    deferred: HashMap<String, String>,
    credentials: Vec<Credential>,
}

impl<O, P, A, T> IssuanceFlow<O, P, A, T> {
    /// Get the ID of the issuance flow.
    pub fn id(&self) -> String {
        self.id.clone()
    }

    /// Get the credential issuer metadata.
    pub fn issuer(&self) -> Issuer {
        self.issuer.clone()
    }
}

/// Type guard for `IssuanceFlow` typestate pattern for flows that are initiated
/// with an offer from the issuer.
#[derive(Clone, Debug)]
pub struct WithOffer(CredentialOffer);
/// Type guard for `IssuanceFlow` typestate pattern for flows that are initiated
/// without an offer from the issuer.
#[derive(Clone, Debug)]
pub struct WithoutOffer;

/// Type guard for `IssuanceFlow` typestate pattern for flows that have had an
/// offer fully or partly accepted and a PIN number (if required).
#[derive(Clone, Debug)]
pub struct Accepted(Vec<AuthorizationDetail>, Option<String>);
/// Type guard for `IssuanceFlow` typestate pattern for flows that have not had
/// any any offer or authorization details accepted.
#[derive(Clone, Debug)]
pub struct NotAccepted;

/// Type guard for `IssuanceFlow` typestate pattern for flows that have had been
/// pre-authorized by the issuer.
#[derive(Clone, Debug)]
pub struct PreAuthorized(PreAuthorizedCodeGrant);
/// Type guard for `IssuanceFlow` typestate pattern for flows that have not been
/// pre-authorized by the issuer.
#[derive(Clone, Debug)]
pub struct NotPreAuthorized;

/// Type guard for `IssuanceFlow` typestate pattern for flows that have had an
/// authorization token issued.
#[derive(Clone, Debug)]
pub struct WithToken(TokenResponse);
/// Type guard for `IssuanceFlow` typestate pattern for flows that have not had
/// an authorization token issued.
#[derive(Clone, Debug)]
pub struct WithoutToken;

impl IssuanceFlow<WithOffer, PreAuthorized, NotAccepted, WithoutToken> {
    /// Create a new issuance flow with an offer from the issuer.
    #[must_use]
    pub fn new(
        client_id: &str, subject_id: &str, issuer: Issuer, auth_server: Server,
        offer: CredentialOffer, pre_auth_code_grant: PreAuthorizedCodeGrant,
    ) -> Self {
        Self {
            offer: WithOffer(offer),
            accepted: NotAccepted,
            pre_authorized: PreAuthorized(pre_auth_code_grant),
            token: WithoutToken,

            id: Uuid::new_v4().to_string(),
            client_id: client_id.into(),
            subject_id: subject_id.into(),
            issuer,
            authorization_server: auth_server,
            deferred: HashMap::new(),
            credentials: Vec::new(),
        }
    }
}

impl IssuanceFlow<WithOffer, NotPreAuthorized, NotAccepted, WithoutToken> {
    /// Create a new issuance flow with an offer but no pre-authorization.
    #[must_use]
    pub fn new(
        client_id: &str, subject_id: &str, issuer: Issuer, auth_server: Server,
        offer: CredentialOffer,
    ) -> Self {
        Self {
            offer: WithOffer(offer),
            accepted: NotAccepted,
            pre_authorized: NotPreAuthorized,
            token: WithoutToken,

            id: Uuid::new_v4().to_string(),
            client_id: client_id.into(),
            subject_id: subject_id.into(),
            issuer,
            authorization_server: auth_server,
            deferred: HashMap::new(),
            credentials: Vec::new(),
        }
    }
}

impl<P> IssuanceFlow<WithOffer, P, NotAccepted, WithoutToken> {
    /// Accept the offer from the issuer.
    #[must_use]
    pub fn accept(
        self, accepted: &Option<Vec<AuthorizationSpec>>, pin: Option<String>,
    ) -> IssuanceFlow<WithOffer, P, Accepted, WithoutToken> {
        // If the accept parameter is `None`, all contents of the offer are
        // accepted. Otherwise transform the acceptance into authorization
        // detail format and store on the flow.
        let creds_supported = &self.issuer.credential_configurations_supported;
        let mut auth_details = Vec::new();
        for cfg_id in &self.offer.0.credential_configuration_ids {
            let Some(cred_config) = creds_supported.get(cfg_id) else {
                continue;
            };
            if let Some(accepted) = &accepted {
                if !accepted.iter().any(|a| a.credential_configuration_id == *cfg_id) {
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
            let detail = AuthorizationDetail {
                credential: CredentialAuthorization::ConfigurationId {
                    credential_configuration_id: cfg_id.clone(),
                    claims,
                },
                locations: Some(vec![self.issuer.credential_issuer.clone()]),
                ..Default::default()
            };
            auth_details.push(detail);
        }

        IssuanceFlow {
            offer: self.offer,
            accepted: Accepted(auth_details, pin),
            pre_authorized: self.pre_authorized,
            token: WithoutToken,

            id: self.id,
            client_id: self.client_id,
            subject_id: self.subject_id,
            issuer: self.issuer,
            authorization_server: self.authorization_server,
            deferred: self.deferred,
            credentials: self.credentials,
        }
    }
}

impl<P, A, T> IssuanceFlow<WithOffer, P, A, T> {
    /// Convenience method to get the offer back out that combines with some
    /// issuer metadata to make it easier to present to the holder so they can
    /// choose what credentials and claims to accept.
    #[must_use]
    pub fn offered(&self) -> HashMap<String, CredentialConfiguration> {
        // Explicitly extract the credential configurations from the issuer
        // metadata that match the credentials on offer to make it easier to
        // present to the holder.
        let mut offered = HashMap::<String, CredentialConfiguration>::new();
        let creds_supported = &self.issuer.credential_configurations_supported;
        for cfg_id in &self.offer.0.credential_configuration_ids {
            // find supported credential in metadata and copy to state object.
            let Some(found) = creds_supported.get(cfg_id) else {
                continue;
            };
            offered.insert(cfg_id.clone(), found.clone());
        }
        offered
    }

    /// Convenience method to get the original offer details.
    #[must_use]
    pub fn offer(&self) -> CredentialOffer {
        self.offer.0.clone()
    }
}

impl IssuanceFlow<WithOffer, PreAuthorized, Accepted, WithoutToken> {
    /// Add a PIN to an accepted offer.
    pub fn set_pin(&mut self, pin: &str) {
        self.accepted.1 = Some(pin.into());
    }

    /// Create a token request from the current state.
    #[must_use]
    pub fn token_request(&self) -> TokenRequest {
        TokenRequest {
            credential_issuer: self.issuer.credential_issuer.clone(),
            client_id: Some(self.client_id.clone()),
            grant_type: TokenGrantType::PreAuthorizedCode {
                pre_authorized_code: self.pre_authorized.0.pre_authorized_code.clone(),
                tx_code: self.accepted.1.clone(),
            },
            authorization_details: Some(self.accepted.0.clone()),
            client_assertion: None,
        }
    }
}

impl<T> IssuanceFlow<WithOffer, PreAuthorized, Accepted, T> {
    /// Get a copy of the entered PIN
    pub fn pin(&self) -> Option<String> {
        self.accepted.1.clone()
    }
}

impl IssuanceFlow<WithOffer, NotPreAuthorized, Accepted, WithoutToken> {
    /// Construct an authorization request, a PKCE code challenge and PKCE
    /// verifier from the current state and returns the request and verifier.
    ///
    /// # Errors
    /// Will return an error if the offer contains grants other than an
    /// authorization code grant (can have no grants), or if the authorization
    /// server does not support the authorization code grant.
    pub fn authorization_request(
        &self, redirect_uri: Option<&str>,
    ) -> anyhow::Result<(AuthorizationRequest, String)> {
        let Some(grant_types) = &self.authorization_server.oauth.grant_types_supported else {
            bail!("authorization server does not support any grant types");
        };
        if !grant_types.contains(&GrantType::AuthorizationCode) {
            bail!("authorization server does not support authorization code grant");
        }
        let Some(code_challenge_methods) =
            &self.authorization_server.oauth.code_challenge_methods_supported
        else {
            bail!("code challenge methods missing from authorization server metadata");
        };

        let issuer_state = match &self.offer.0.grants {
            Some(grants) => {
                if let Some(auth_code) = &grants.authorization_code {
                    auth_code.issuer_state.clone()
                } else {
                    bail!("offer does not support authorization code grant");
                }
            }
            None => None,
        };

        // PKCE pair
        let verifier = pkce::code_verifier();
        let code_challenge = pkce::code_challenge(&verifier);

        let request = AuthorizationRequest::Object(RequestObject {
            credential_issuer: self.offer.0.credential_issuer.clone(),
            response_type: self.authorization_server.oauth.response_types_supported[0].clone(),
            client_id: self.client_id.clone(),
            redirect_uri: redirect_uri.map(ToString::to_string),
            state: Some(self.id.clone()),
            code_challenge,
            code_challenge_method: code_challenge_methods[0].clone(),
            authorization_details: Some(self.accepted.0.clone()),
            scope: None,
            resource: Some(self.issuer.credential_issuer.clone()),
            subject_id: self.subject_id.clone(),
            wallet_issuer: None,
            user_hint: Some(self.id.clone()),
            issuer_state,
        });

        Ok((request, verifier))
    }
}

impl IssuanceFlow<WithoutOffer, NotPreAuthorized, NotAccepted, WithoutToken> {
    /// Create a new wallet-initiated issuance flow.
    /// Create a new issuance flow with an offer from the issuer.
    #[must_use]
    pub fn new(client_id: &str, subject_id: &str, issuer: Issuer, auth_server: Server) -> Self {
        Self {
            offer: WithoutOffer,
            accepted: NotAccepted,
            pre_authorized: NotPreAuthorized,
            token: WithoutToken,

            id: Uuid::new_v4().to_string(),
            client_id: client_id.into(),
            subject_id: subject_id.into(),
            issuer,
            authorization_server: auth_server,
            deferred: HashMap::new(),
            credentials: Vec::new(),
        }
    }

    /// Create an updated state with the credentials and claims to accept for
    /// a wallet-initiated issuance flow.
    #[must_use]
    pub fn accept(
        self, accepted: Vec<AuthorizationDetail>,
    ) -> IssuanceFlow<WithoutOffer, NotPreAuthorized, Accepted, WithoutToken> {
        IssuanceFlow {
            offer: WithoutOffer,
            accepted: Accepted(accepted, None),
            pre_authorized: NotPreAuthorized,
            token: WithoutToken,

            id: self.id,
            client_id: self.client_id,
            subject_id: self.subject_id,
            issuer: self.issuer,
            authorization_server: self.authorization_server,
            deferred: self.deferred,
            credentials: self.credentials,
        }
    }

    /// Create a scope-based authorization request. The request and a PKCE code
    /// verifier are returned.
    ///
    /// # Errors
    /// Will return an error if the authorization server does not support the
    /// authorization code grant.
    pub fn authorization_request(
        &self, scope: &str, redirect_uri: Option<&str>,
    ) -> anyhow::Result<(AuthorizationRequest, String)> {
        // Check issuer's authorization server metadata supports the
        // authorization code grant.
        let Some(grant_types) = &self.authorization_server.oauth.grant_types_supported else {
            bail!("authorization server does not support any grant types");
        };
        if !grant_types.contains(&GrantType::AuthorizationCode) {
            bail!("authorization server does not support authorization code grant");
        }
        let Some(code_challenge_methods) =
            &self.authorization_server.oauth.code_challenge_methods_supported
        else {
            bail!("code challenge methods missing from authorization server metadata");
        };

        // PKCE pair
        let verifier = pkce::code_verifier();
        let code_challenge = pkce::code_challenge(&verifier);

        let request = AuthorizationRequest::Object(RequestObject {
            credential_issuer: self.issuer.credential_issuer.clone(),
            response_type: self.authorization_server.oauth.response_types_supported[0].clone(),
            client_id: self.client_id.clone(),
            redirect_uri: redirect_uri.map(ToString::to_string),
            state: Some(self.id.clone()),
            code_challenge,
            code_challenge_method: code_challenge_methods[0].clone(),
            authorization_details: None,
            scope: Some(scope.into()),
            resource: Some(self.issuer.credential_issuer.clone()),
            subject_id: self.subject_id.clone(),
            wallet_issuer: None,
            user_hint: Some(self.id.clone()),
            issuer_state: None,
        });

        Ok((request, verifier))
    }

    /// Create a scope-based token request from the current state.
    #[must_use]
    pub fn token_request(
        &self, auth_code: &str, verifier: &str, redirect_uri: Option<&str>,
    ) -> TokenRequest {
        TokenRequest {
            credential_issuer: self.issuer.credential_issuer.clone(),
            client_id: Some(self.client_id.clone()),
            grant_type: TokenGrantType::AuthorizationCode {
                code: auth_code.to_string(),
                redirect_uri: redirect_uri.map(ToString::to_string),
                code_verifier: Some(verifier.into()),
            },
            authorization_details: None,
            client_assertion: None,
        }
    }
}

impl IssuanceFlow<WithoutOffer, NotPreAuthorized, Accepted, WithoutToken> {
    /// Create an authorization request from the current state. The request and
    /// a PKCE code verifier are returned.
    ///
    /// # Errors
    /// Will return an error if the authorization server does not support the
    /// authorization code grant.
    pub fn authorization_request(
        &self, redirect_uri: Option<&str>,
    ) -> anyhow::Result<(AuthorizationRequest, String)> {
        // Check issuer's authorization server metadata supports the
        // authorization code grant.
        let Some(grant_types) = &self.authorization_server.oauth.grant_types_supported else {
            bail!("authorization server does not support any grant types");
        };
        if !grant_types.contains(&GrantType::AuthorizationCode) {
            bail!("authorization server does not support authorization code grant");
        }
        let Some(code_challenge_methods) =
            &self.authorization_server.oauth.code_challenge_methods_supported
        else {
            bail!("code challenge methods missing from authorization server metadata");
        };

        // PKCE pair
        let verifier = pkce::code_verifier();
        let code_challenge = pkce::code_challenge(&verifier);

        let request = AuthorizationRequest::Object(RequestObject {
            credential_issuer: self.issuer.credential_issuer.clone(),
            response_type: self.authorization_server.oauth.response_types_supported[0].clone(),
            client_id: self.client_id.clone(),
            redirect_uri: redirect_uri.map(ToString::to_string),
            state: Some(self.id.clone()),
            code_challenge,
            code_challenge_method: code_challenge_methods[0].clone(),
            authorization_details: Some(self.accepted.0.clone()),
            scope: None,
            resource: Some(self.issuer.credential_issuer.clone()),
            subject_id: self.subject_id.clone(),
            wallet_issuer: None,
            user_hint: Some(self.id.clone()),
            issuer_state: None,
        });

        Ok((request, verifier))
    }
}

impl<O> IssuanceFlow<O, NotPreAuthorized, Accepted, WithoutToken> {
    /// Create a token request from the current state.
    #[must_use]
    pub fn token_request(
        &self, auth_code: &str, verifier: &str, redirect_uri: Option<&str>,
    ) -> TokenRequest {
        TokenRequest {
            credential_issuer: self.issuer.credential_issuer.clone(),
            client_id: Some(self.client_id.clone()),
            grant_type: TokenGrantType::AuthorizationCode {
                code: auth_code.to_string(),
                redirect_uri: redirect_uri.map(ToString::to_string),
                code_verifier: Some(verifier.into()),
            },
            authorization_details: Some(self.accepted.0.clone()),
            client_assertion: None,
        }
    }
}

impl<O, P, A> IssuanceFlow<O, P, A, WithoutToken> {
    /// Add the token response to the flow state.
    #[must_use]
    pub fn token(self, token: TokenResponse) -> IssuanceFlow<O, P, A, WithToken> {
        IssuanceFlow {
            offer: self.offer,
            accepted: self.accepted,
            pre_authorized: self.pre_authorized,
            token: WithToken(token),

            id: self.id,
            client_id: self.client_id,
            subject_id: self.subject_id,
            issuer: self.issuer,
            authorization_server: self.authorization_server,
            deferred: self.deferred,
            credentials: self.credentials,
        }
    }
}

impl<O, P> IssuanceFlow<O, P, Accepted, WithToken> {
    /// Create a set of credential requests from the current state for the
    /// given set of credential identifiers (allows the user to select a
    /// subset of accepted credentials) and a proof JWT.
    ///
    /// If any inconsistencies are found between the authorization details may
    /// result in an empty or partial set of credential requests.
    pub fn credential_requests(
        &self, identifiers: &[String], jwt: &str,
    ) -> Vec<(String, CredentialRequest)> {
        let mut requests = Vec::new();
        let Some(authorized) = &self.token.0.authorization_details else {
            return requests;
        };
        for auth in authorized {
            let cfg_id = match &auth.authorization_detail.credential {
                CredentialAuthorization::ConfigurationId {
                    credential_configuration_id,
                    ..
                } => credential_configuration_id,
                CredentialAuthorization::Format(format_identifier) => {
                    match &self.issuer.credential_configuration_id(format_identifier) {
                        Ok(cfg_id) => cfg_id,
                        Err(_) => continue,
                    }
                }
            };
            // Check the issuer supports this credential configuration. This will only fail if the
            // wallet has messed with state outside of the intended mutation methods.
            let Some(_) = &self.issuer.credential_configurations_supported.get(cfg_id) else {
                continue;
            };
            for cred_id in &auth.credential_identifiers {
                // Check the holder wants this credential.
                if !identifiers.to_vec().contains(cred_id) {
                    continue;
                }
                let credential_issuer = self.issuer.credential_issuer.clone();
                let access_token = &self.token.0.access_token.clone();
                let request = credential_request!({
                    "credential_issuer": credential_issuer,
                    "access_token": access_token,
                    "credential_identifier": cred_id.to_string(),
                    "proof": {
                        "proof_type": "jwt",
                        "jwt": jwt.to_string()
                    }
                });
                requests.push((cfg_id.to_string(), request));
            }
        }
        requests
    }
}

impl<O, P> IssuanceFlow<O, P, NotAccepted, WithToken> {
    /// Create a set of credential requests from the current state for the
    /// given format and a proof JWT.
    ///
    /// # Errors
    /// If no credential configuration can be found in the issuer metadata with
    /// the given scope and format an error is returned.
    pub fn credential_request(
        &self, scope: &str, format: &Format, jwt: &str,
    ) -> anyhow::Result<(String, CredentialRequest)> {
        let Some((cfg_id, _config)) = &self
            .issuer
            .credential_configurations_supported
            .iter()
            .find(|(_, cfg)| cfg.scope.as_deref() == Some(scope) && cfg.format == *format)
        else {
            bail!("credential configuration not found for scope and format");
        };
        let request = CredentialRequest {
            credential_issuer: self.issuer.credential_issuer.clone(),
            access_token: self.token.0.access_token.clone(),
            credential: CredentialIssuance::Format(format.clone()),
            proof: Some(Proof::Single {
                proof_type: SingleProof::Jwt { jwt: jwt.into() },
            }),
            ..Default::default()
        };
        Ok(((*cfg_id).to_string(), request))
    }
}

impl<O, P, A> IssuanceFlow<O, P, A, WithToken> {
    /// Convenience method to construct a proof so we can sign it and use it in
    /// credential requests.
    pub fn proof(&self) -> ProofClaims {
        ProofClaims {
            iss: Some(self.client_id.clone()),
            aud: self.issuer.credential_issuer.clone(),
            iat: chrono::Utc::now().timestamp(),
            nonce: self.token.0.c_nonce.clone(),
        }
    }

    /// Outstanding deferred credential transaction IDs (key) and corresponding
    /// credential configuration IDs (value).
    ///
    /// Will be empty if there are no outstanding deferred credentials.
    pub fn deferred(&self) -> HashMap<String, String> {
        self.deferred.clone()
    }

    /// The credentials received from the issuer, ready to be saved to storage.
    ///
    /// Will be empty until credentials have been issued.
    pub fn credentials(&self) -> Vec<Credential> {
        self.credentials.clone()
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

        let issuer_id = self.issuer.credential_issuer.clone();

        // TODO: Locale support.
        let issuer_name = self
            .issuer
            .display
            .as_ref()
            .map_or_else(|| issuer_id.clone(), |display| display.name.clone());

        let Some(config) = &self.issuer.credential_configurations_supported.get(config_id) else {
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

    /// Construct a deferred credential request.
    ///
    /// # Errors
    /// Will return an error if the issuance state is not consistent with
    /// constructing such a request.
    pub fn deferred_request(&self, transaction_id: &str) -> DeferredCredentialRequest {
        DeferredCredentialRequest {
            transaction_id: transaction_id.into(),
            credential_issuer: self.issuer.credential_issuer.clone(),
            access_token: self.token.0.access_token.clone(),
        }
    }

    /// Add a deferred transaction ID to the issuance state.
    pub fn add_deferred(&mut self, tx_id: &String, cfg_id: &String) {
        self.deferred.insert(tx_id.into(), cfg_id.into());
    }

    /// Remove a pending deferred credential transaction from state.
    pub fn remove_deferred(&mut self, transaction_id: &str) {
        self.deferred.remove(transaction_id);
    }
}
