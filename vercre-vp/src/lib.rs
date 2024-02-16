//! # `OpenID` for Verifiable Presentations
//!
//! A mechanism on top of OAuth 2.0 to request and present Verifiable Credentials as
//! Verifiable Presentations.
//!
//! `OpenID` for Verifiable Presentations introduces the VP Token as a container to enable
//! End-Users to present Verifiable Presentations to Verifiers using the Wallet.
//! A VP Token contains one or more Verifiable Presentations in the same or different
//! Credential formats.
//!
//! As per the `OpenID` for Verifiable Presentations specification [OpenID.VP], this
//! library supports the response being sent using either a redirect (same-device flow)
//! or an HTTPS POST request (cross-device flow). This enables the response to be sent
//! across devices, or when the response size exceeds the redirect URL character size
//! limitation.
//!
//! ## Same Device Flow
//!
//! The End-User presents a Credential to a Verifier interacting with the End-User on
//! the same device that the device the Wallet resides on.
//!
//! The flow utilizes simple redirects to pass Authorization Request and Response
//! between the Verifier and the Wallet. The Verifiable Presentations are returned to
//! the Verifier in the fragment part of the redirect URI, when Response Mode is fragment.
//!
//! ```text
//! +--------------+   +--------------+                                    +--------------+
//! |     User     |   |   Verifier   |                                    |    Wallet    |
//! +--------------+   +--------------+                                    +--------------+
//!         |                 |                                                   |
//!         |    Interacts    |                                                   |
//!         |---------------->|                                                   |
//!         |                 |  (1) Authorization Request                        |
//!         |                 |  (Presentation Definition)                        |
//!         |                 |-------------------------------------------------->|
//!         |                 |                                                   |
//!         |                 |                                                   |
//!         |   User Authentication / Consent                                     |
//!         |                 |                                                   |
//!         |                 |  (2)   Authorization Response                     |
//!         |                 |  (VP Token with Verifiable Presentation(s))       |
//!         |                 |<--------------------------------------------------|
//! ```
//!
//! ## Cross Device Flow
//!
//! The End-User presents a Credential to a Verifier interacting with the End-User on
//! a different device as the device the Wallet resides on (or where response size the
//! redirect URL character size).
//!
//! In this flow the Verifier prepares an Authorization Request and renders it as a
//! QR Code. The User then uses the Wallet to scan the QR Code. The Verifiable
//! Presentations are sent to the Verifier in a direct HTTPS POST request to a URL
//! controlled by the Verifier. The flow uses the Response Type "`vp_token`" in
//! conjunction with the Response Mode "`direct_post`". In order to keep the size of the
//! QR Code small and be able to sign and optionally encrypt the Request Object, the
//! actual Authorization Request contains just a Request URI, which the wallet uses to
//! retrieve the actual Authorization Request data.
//!
//! ```text
//! +--------------+   +--------------+                                    +--------------+
//! |     User     |   |   Verifier   |                                    |    Wallet    |
//! |              |   |  (device A)  |                                    |  (device B)  |
//! +--------------+   +--------------+                                    +--------------+
//!         |                 |                                                   |
//!         |    Interacts    |                                                   |
//!         |---------------->|                                                   |
//!         |                 |  (1) Authorization Request                        |
//!         |                 |      (Request URI)                                |
//!         |                 |-------------------------------------------------->|
//!         |                 |                                                   |
//!         |                 |  (2) Request the Request Object                   |
//!         |                 |<--------------------------------------------------|
//!         |                 |                                                   |
//!         |                 |  (2.5) Respond with the Request Object            |
//!         |                 |      (Presentation Definition)                    |
//!         |                 |-------------------------------------------------->|
//!         |                 |                                                   |
//!         |   User Authentication / Consent                                     |
//!         |                 |                                                   |
//!         |                 |  (3)   Authorization Response as HTTPS POST       |
//!         |                 |  (VP Token with Verifiable Presentation(s))       |
//!         |                 |<--------------------------------------------------|
//! ```
//!
//! ## JWT VC Presentation Profile
//!
//! The [JWT VC Presentation Profile] defines a set of requirements against existing
//! specifications to enable the interoperable presentation of Verifiable Credentials
//! (VCs) between Wallets and Verifiers.
//!
//! The `vercre-vp` library has been implemented to support the profile's
//! recommendations.
//!  
//! [OpenID.VP]: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
//! [JWT VC Presentation Profile]: https://identity.foundation/jwt-vc-presentation-profile

pub mod endpoint;
mod state;

// LATER: organise prelude exports
/// A convenience module appropriate for glob imports (`use
/// vercre_vp::prelude::*;`).
pub mod prelude {
    pub use crate::endpoint::*;
}

// LATER: use git replace to hide early development history (https://git-scm.com/book/en/v2/Git-Tools-Replace)
