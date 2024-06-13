use base64ct::{Base64, Encoding};
use http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use vercre_holder::credential::Logo;
use vercre_holder::issuance::{
    CredentialRequest, CredentialResponse, MetadataRequest, MetadataResponse, TokenRequest,
    TokenResponse,
};
use vercre_holder::provider::IssuerClient;

use crate::provider::Provider;

impl<R> IssuerClient for Provider<R>
where
    R: tauri::Runtime,
{
    /// Get issuer metadata.
    async fn get_metadata(
        &self, _flow_id: &str, req: &MetadataRequest,
    ) -> anyhow::Result<MetadataResponse> {
        let client = reqwest::Client::new();
        let result =
            client.get(&req.credential_issuer).header(ACCEPT, "application/json").send().await?;
        let md = result.json::<MetadataResponse>().await?;
        Ok(md)
    }

    /// Get an access token.
    async fn get_token(&self, _flow_id: &str, req: &TokenRequest) -> anyhow::Result<TokenResponse> {
        let client = reqwest::Client::new();
        let result = client
            .post(&req.credential_issuer)
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/json")
            .json(&req)
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
        let result = client
            .post(&req.credential_issuer)
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
