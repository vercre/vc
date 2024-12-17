use base64ct::{Base64, Encoding};
use http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use tauri_plugin_http::reqwest;
use vercre_holder::credential::ImageData;
use vercre_holder::provider::Issuer;
use vercre_holder::{
    AuthorizationRequest, AuthorizationResponse, CredentialRequest, CredentialResponse,
    DeferredCredentialRequest, DeferredCredentialResponse, MetadataRequest, MetadataResponse,
    NotificationRequest, NotificationResponse, OAuthServerRequest, OAuthServerResponse,
    TokenRequest, TokenResponse,
};

use super::Provider;

impl Issuer for Provider {
    /// Get issuer metadata.
    async fn metadata(&self, req: MetadataRequest) -> anyhow::Result<MetadataResponse> {
        let client = reqwest::Client::new();
        let url = format!("{}/.well-known/openid-credential-issuer", req.credential_issuer);
        let result = client.get(&url).header(ACCEPT, "application/json").send().await?;
        let mut md = match result.json::<MetadataResponse>().await {
            Ok(md) => md,
            Err(e) => {
                log::error!("Error getting metadata: {}", e);
                return Err(e.into());
            }
        };
        md.credential_issuer.credential_issuer.clone_from(&req.credential_issuer);
        Ok(md)
    }

    /// Get authorization server metadata.
    async fn oauth_server(&self, req: OAuthServerRequest) -> anyhow::Result<OAuthServerResponse> {
        let client = reqwest::Client::new();
        let url = format!("{}/.well-known/oauth-authorization-server", req.credential_issuer);
        let result = client.get(&url).header(ACCEPT, "application/json").send().await?;
        let md = match result.json::<OAuthServerResponse>().await {
            Ok(md) => md,
            Err(e) => {
                log::error!("Error getting OAuth server metadata: {}", e);
                return Err(e.into());
            }
        };
        Ok(md)
    }

    /// Get an authorization code. Not implemented for this example that assumes
    /// issuer-initiated pre-authorized issuance.
    async fn authorization(
        &self, _req: AuthorizationRequest,
    ) -> anyhow::Result<AuthorizationResponse> {
        unimplemented!()
    }

    /// Get an access token.
    async fn token(&self, req: TokenRequest) -> anyhow::Result<TokenResponse> {
        let client = reqwest::Client::new();
        let url = format!("{}/token", req.credential_issuer);
        let form = req.form_encode()?;
        let result = client
            .post(&url)
            .header(CONTENT_TYPE, "multipart/form-data")
            .header(ACCEPT, "application/json")
            .form(&form)
            .send()
            .await?;
        let token = match result.json::<TokenResponse>().await {
            Ok(token) => token,
            Err(e) => {
                log::error!("Error getting token: {}", e);
                return Err(e.into());
            }
        };
        Ok(token)
    }

    /// Get a credential.
    async fn credential(&self, req: CredentialRequest) -> anyhow::Result<CredentialResponse> {
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

    /// Get a deferred credential. Not implemented for this example.
    async fn deferred(
        &self, _req: DeferredCredentialRequest,
    ) -> anyhow::Result<DeferredCredentialResponse> {
        unimplemented!()
    }

    /// Get a base64 encoded form of the credential logo.
    async fn image(self, url: &str) -> anyhow::Result<ImageData> {
        let client = reqwest::Client::new();
        let result = client.get(url).header(ACCEPT, "image/*").send().await?;
        let headers = result.headers().clone();
        let media_type = match headers.get(CONTENT_TYPE) {
            Some(mt) => mt.to_str()?,
            None => "image/*",
        };
        let image_bytes = result.bytes().await?;
        let image_data = Base64::encode_string(&image_bytes);
        Ok(ImageData {
            data: image_data,
            media_type: media_type.to_string(),
        })
    }

    /// Notify the issuer of issuance progress. Not implemented for this
    /// example.
    async fn notification(
        &self, _req: NotificationRequest,
    ) -> anyhow::Result<NotificationResponse> {
        Ok(NotificationResponse::default())
    }
}
