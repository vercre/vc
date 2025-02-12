# Providers

In addition to implementing endpoints for a wallet or holder agent, the implementer must also provide a set of providers that the wallet can use to interact with the issuer and verifier, and get or store credentials from a repository.

_See Credibils's example [holder providers](https://github.com/credibil/vc/blob/main/examples/tauri-wallet/src-tauri/src/provider.rs) for more detail._

## Issuer Client

The `IssuerClient` provider allows the library to make calls to an issuer's API that implements the OpenID for Verifiable Credential Issuance specification - such as one based on Credibil VC. The provider is responsible for getting issuer metadata, getting an access token and retrieving the offered credentials.

In addition to the OpenID specification, the W3C data model for a Verifable Credential can contain URLs to logos that are suitable for visual display in, say, a wallet, so the provider should also have a method for retrieving such a logo.

```rust,ignore
pub trait IssuerClient {
    fn get_metadata(
        &self, flow_id: &str, req: &MetadataRequest,
    ) -> impl Future<Output = anyhow::Result<MetadataResponse>> + Send;

    fn get_token(
        &self, flow_id: &str, req: &TokenRequest,
    ) -> impl Future<Output = anyhow::Result<TokenResponse>> + Send;

    fn get_credential(
        &self, flow_id: &str, req: &CredentialRequest,
    ) -> impl Future<Output = anyhow::Result<CredentialResponse>> + Send;

    fn get_logo(
        &self, flow_id: &str, logo_url: &str,
    ) -> impl Future<Output = anyhow::Result<Logo>> + Send;
}
```

## Verifier Client

The `VerifierClient` provider allows the library to make calls to a verifier's API that implements the OpenID for Verifiable Presentations specification - such as one based on Credibil VC. The provider is responsible for retrieving a presentation request object from a URI if the library receives the request initiation in that format. It also sends the signed presentation submission to the verifier.

```rust,ignore
pub trait VerifierClient {
    fn get_request_object(
        &self, flow_id: &str, req: &str,
    ) -> impl Future<Output = anyhow::Result<RequestObjectResponse>> + Send;

    fn present(
        &self, flow_id: &str, uri: Option<&str>, presentation: &ResponseRequest,
    ) -> impl Future<Output = anyhow::Result<ResponseResponse>> + Send;
}
```

## Credential Storer

The `CredentialStorer` provider manages the storage and retrieval of credentials on behalf of the holder. In a wallet, this would be in the device's secure storage, for example.

```rust,ignore
pub trait CredentialStorer: Send + Sync {
    fn save(&self, credential: &Credential) -> impl Future<Output = anyhow::Result<()>> + Send;

    fn load(&self, id: &str) -> impl Future<Output = anyhow::Result<Option<Credential>>> + Send;

    fn find(
        &self, filter: Option<Constraints>,
    ) -> impl Future<Output = anyhow::Result<Vec<Credential>>> + Send;

    fn remove(&self, id: &str) -> impl Future<Output = anyhow::Result<()>> + Send;
}
```

## State Manager

As its name implies, `StateStore` is responsible for temporarily storing and managing state on behalf of the library.

```rust,ignore
pub trait StateStore: Send + Sync {
    fn put(&self, key: &str, data: Vec<u8>, expiry: DateTime<Utc>,
    ) -> impl Future<Output = Result<()>> + Send;

    fn get(&self, key: &str) -> impl Future<Output = Result<Vec<u8>>> + Send;

    fn purge(&self, key: &str) -> impl Future<Output = Result<()>> + Send;
}
```

## Signer

The `Signer` trait provides the library with signing functionality for signing presentation submissions.

```rust,ignore
pub trait Signer: Send + Sync {
    fn algorithm(&self) -> Algorithm;

    fn verification_method(&self) -> String;

    fn sign(&self, msg: &[u8]) -> impl Future<Output = Vec<u8>> + Send {
        let v = async { self.try_sign(msg).await.expect("should sign") };
        v.into_future()
    }

    fn try_sign(&self, msg: &[u8]) -> impl Future<Output = anyhow::Result<Vec<u8>>> + Send;
}
```

## Verifier

The `Verifier` trait provides the library with signing verification functionality for Verifiable Credential issuance.

```rust,ignore
pub trait Verifier: Send + Sync {
    fn deref_jwk(&self, did_url: &str)
        -> impl Future<Output = anyhow::Result<PublicKeyJwk>> + Send;
}
```
