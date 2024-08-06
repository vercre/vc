# Holder

The [vercre-holder](https://github.com/vercre/vercre/tree/main/vercre-holder) crate provides an API for participating in the issuance and presentation of Verifiable Credentials as an agent of the Holder. That is, it can provide the basis for a Wallet for example. It expects the issuer to provide an API that is based on the [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
specification and a verifier to provide an API based on the [OpenID for Verifiable Presentations](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) specification.

The vercre-holder crate is the third leg of the Verifiable Credential ecosystem alongside [vercre-issuer](https://github.com/vercre/vercre/tree/main/vercre-issuer) and [vercre-verifier](https://github.com/vercre/vercre/tree/main/vercre-verifier). It is recommended you familiarize yourself with these crates to understand how the Holder interacts with the respective issuance and verification flows.

## API

In the following sections, we will cover implementing the API, in particular [endpoints](./endpoints.md) and [providers](./providers.md).

### Working example
If you want to skip ahead there is a naive but complete [example implementation of a Wallet](https://github.com/vercre/vercre/tree/main/examples/wallet).