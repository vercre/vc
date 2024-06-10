//! View models for the credential sub-app

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use typeshare::typeshare;

/// View model for the credential sub-app
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[typeshare]
pub struct CredentialView {
    /// List of credentials
    pub credentials: Vec<CredentialDisplay>,
    /// Current credential being viewed
    pub current: Option<CredentialDetail>,
}

/// Summary view for a verifiable credential
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[typeshare]
pub struct CredentialDisplay {
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

/// Detail view for a verifiable credential
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[typeshare]
pub struct CredentialDetail {
    /// Display
    display: CredentialDisplay,
    /// Claims
    claims: HashMap<String, String>,
}
