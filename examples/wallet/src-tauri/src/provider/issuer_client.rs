use base64ct::{Base64, Encoding};
use http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use vercre_holder::{
    CredentialRequest, CredentialResponse, Logo, MetadataRequest, MetadataResponse, TokenRequest,
    TokenResponse,
};
use vercre_holder::provider::IssuerClient;

use super::Provider;

impl IssuerClient for Provider {
    /// Get issuer metadata.
    async fn get_metadata(
        &self, _flow_id: &str, req: &MetadataRequest,
    ) -> anyhow::Result<MetadataResponse> {
        let client = reqwest::Client::new();
        let url = format!("{}/.well-known/openid-credential-issuer", req.credential_issuer);
        let result = client.get(&url).header(ACCEPT, "application/json").send().await?;
        let md = match result.json::<MetadataResponse>().await {
            Ok(md) => md,
            Err(e) => {
                log::error!("Error getting metadata: {}", e);
                return Err(e.into());
            }
        };
        Ok(md)
    }

    /// Get an access token.
    async fn get_token(&self, _flow_id: &str, req: &TokenRequest) -> anyhow::Result<TokenResponse> {
        let client = reqwest::Client::new();
        let url = format!("{}/token", req.credential_issuer);
        let result = client
            .post(&url)
            .header(CONTENT_TYPE, "multipart/form-data")
            .header(ACCEPT, "application/json")
            .form(req)
            .send()
            .await?;
        let token = result.json::<TokenResponse>().await?;
        Ok(token)
    }

    /// Get a credential.
    async fn get_credential(
        &self, _flow_id: &str, req: &CredentialRequest,
    ) -> anyhow::Result<CredentialResponse> {
        let client = reqwest::Client::new();
        let url = format!("{}/credential", req.credential_issuer);
        let result = client
            .post(&url)
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, &format!("Bearer {}", req.access_token))
            .json(&req)
            .send()
            .await?;
        let cred = result.json::<CredentialResponse>().await?;
        Ok(cred)
    }

    /// Get a base64 encoded form of the credential logo.
    async fn get_logo(&self, _flow_id: &str, logo_url: &str) -> anyhow::Result<Logo> {
        let client = reqwest::Client::new();
        let result = client.get(logo_url).header(ACCEPT, "image/*").send().await?;
        let headers = result.headers().clone();
        let media_type = match headers.get(CONTENT_TYPE) {
            Some(mt) => mt.to_str()?,
            None => "image/*",
        };
        let logo_bytes = result.bytes().await?;
        let logo_data = Base64::encode_string(&logo_bytes);
        Ok(Logo {
            image: logo_data,
            media_type: media_type.to_string(),
        })
    }
}
