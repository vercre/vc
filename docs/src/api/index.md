# Using the Vercre API

<div class="warning">
    APIs listed here are still <strong>under development</strong>.

    The APIs are suitable for demonstration purposes but not yet intended for 
    production use!
</div>

The Vercre API comprises three top-level libraries that form the backbone of OpenID 
for Verifiable Credentials.

- [Issuance](./vci/index.md) — based on the [OpenID for Verifiable Credential Issuance]
  specification, the [vercre-vci] library provides an API for issuing Verifiable Credentials.

- [Presentation](./vp/index.md) — based on the [OpenID for VerifiablePresentations]
  specification, the [vercre-vp] library provides an API for  requesting and presenting Verifiable Credentials.

- [Wallet](./wallet/index.md) — the the [vercre-wallet] library is built against both specifications and 
  can be used to simplify interactions with the issuance and presentation APIs.

[OpenID for Verifiable Credential Issuance]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
[OpenID for VerifiablePresentations]: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
[vercre-vci]: https://github.com/vercre/vercre/tree/main/vercre-vci
[vercre-vp]: https://github.com/vercre/vercre/tree/main/vercre-vp
[vercre-wallet]: https://github.com/vercre/vercre/tree/main/vercre-wallet