# Issuance

Based on the [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
specification, the [vercre-vci](https://github.com/vercre/vercre/tree/main/vercre-vci) 
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

## Pre-Authorized Flow

The Pre-Authorized Code flow is initiated by the Issuer, who creates a Credential Offer
that includes a Pre-Authorized Code and sends to the Wallet. The Wallet exchanges the 
Pre-Authorized Code for an Access Token at the Token Endpoint. The Access Token is then
used to request Credential issuance at the Credential Endpoint.

Before initiating issuance, the Issuer prepares by authenticating and authorizing the 
End-User.

<div style="text-align:center;">
  <img src="../../images/pre-auth-flow.png" width="60%" alt="The Rust logo">
</div>

[OpenID for Verifiable Credential Issuance]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html