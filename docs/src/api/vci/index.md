# Issuance

Based on the [OpenID for Verifiable Credential Issuance] specification, the [vercre-vci]
library provides an API for issuing Verifiable Credentials.

The specification defines an API for Credential issuance provided by a Credential Issuer. 

The API is comprised of the following endpoints:

- `Create Offer` — for Issuer-initiated Credential issuance (Pre-Authorized Code flow).

- `Authorization` — for Wallet authorization and Wallet-initiated Credential issuance
  (Authorization Code flow).

- `Token` — for the Wallet to exchange an authorization code for an access token 
  during both pre-authorized code and authorization code flows.

- `Credential` — for Credential issuance.

- `Batch Credential` — for issuance of multiple Credentials in a single batch.

- `Deferred Credential` — for deferred issuance of Credentials.

- `Metadata` — publishes metadata about the Issuer and the Credentials they can issue.

- `Notification` — for the Issuer to receive Wallet notifications about the status of 
  issued Credentials.


## HTTP API



## Providers



[OpenID for Verifiable Credential Issuance]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
[vercre-vci]: https://github.com/vercre/vercre/tree/main/vercre-vci