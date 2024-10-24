//! View models for the credential sub-app

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use typeshare::typeshare;
use vercre_holder::credential::{self, Credential};
use vercre_holder::{CredentialConfiguration, Quota};

/// View model for the credential sub-app
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[typeshare]
#[allow(clippy::module_name_repetitions)]
pub struct CredentialView {
    /// List of credentials
    pub credentials: Vec<CredentialDisplay>,
}

/// Summary view for a verifiable credential
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[typeshare]
#[allow(clippy::module_name_repetitions)]
pub struct CredentialDisplay {
    /// Credential ID
    pub id: String,
    /// CSS color to use for the background of a credential display
    pub background_color: Option<String>,
    /// CSS color to use for the text of a credential display
    pub color: Option<String>,
    /// Label to display on the credential to indicate the issuer
    pub issuer: Option<String>,
    /// Logo to display on the credential
    pub logo: Option<Logo>,
    /// URL of the original source of the logo
    pub logo_url: Option<String>,
    /// Name of the credential
    pub name: Option<String>,
}

/// Logo to display on the credential
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[typeshare]
pub struct Logo {
    /// Base64 encoded image
    pub image: String,
    /// Image media type
    pub media_type: String,
}

impl From<credential::Image> for Logo {
    fn from(logo: credential::Image) -> Self {
        Self {
            image: logo.image,
            media_type: logo.media_type,
        }
    }
}

/// Detail view for a verifiable credential
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[typeshare]
#[allow(clippy::module_name_repetitions)]
pub struct CredentialDetail {
    /// Display
    display: CredentialDisplay,
    /// Issuance date
    valid_from: Option<String>,
    /// Expiry
    valid_until: Option<String>,
    /// Description
    description: Option<String>,
    /// Claims
    claims: HashMap<String, String>,
}

impl From<Vec<Credential>> for CredentialView {
    fn from(state: Vec<Credential>) -> Self {
        Self {
            credentials: state.iter().map(std::convert::Into::into).collect(),
        }
    }
}

impl From<&Credential> for CredentialDisplay {
    fn from(credential: &Credential) -> Self {
        let displays = credential.display.clone().unwrap_or_default();
        // TODO: locale
        let display = displays[0].clone();
        Self {
            id: credential.id.clone(),
            background_color: display.background_color.clone(),
            color: display.text_color.clone(),
            issuer: Some(credential.issuer.clone()),
            logo: credential.logo.as_ref().map(|logo| logo.clone().into()),
            logo_url: match display.logo {
                Some(image) => image.uri,
                None => None,
            },
            name: Some(display.name),
        }
    }
}

impl From<&CredentialConfiguration> for CredentialDisplay {
    fn from(config: &CredentialConfiguration) -> Self {
        let displays = config.display.clone().unwrap_or_default();
        // TODO: locale
        let display = displays[0].clone();
        Self {
            id: String::new(), // ID is not available in the configuration, only in the credential
            background_color: display.background_color.clone(),
            color: display.text_color.clone(),
            issuer: None,
            logo: None,
            logo_url: match display.logo {
                Some(image) => image.uri,
                None => None,
            },
            name: Some(display.name),
        }
    }
}

impl From<&Credential> for CredentialDetail {
    fn from(credential: &Credential) -> Self {
        let displays = credential.display.clone().unwrap_or_default();
        // TODO: locale
        let display = displays[0].clone();
        let vc = credential.vc.clone();
        let mut claims = HashMap::new();

        let subjects = match &vc.credential_subject {
            Quota::One(sub) => vec![sub.clone()],
            Quota::Many(subs) => subs.clone(),
        };

        for subject in subjects {
            let claims_map = subject.claims;
            for (key, value) in claims_map {
                let val = serde_json::to_string(&value).unwrap_or_default();
                claims.insert(key.clone(), val);
            }
        }

        Self {
            display: credential.into(),
            valid_from: vc.valid_from.map(|d| d.to_rfc2822()),
            valid_until: vc.valid_until.map(|d| d.to_rfc2822()),
            description: display.description,
            claims,
        }
    }
}
