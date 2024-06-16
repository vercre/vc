//! # `OpenID` Errors
//!
//! This module defines errors for `OpenID` for Verifiable Credential Issuance
//! and Verifiable Presentations.

use std::backtrace::Backtrace;
use std::fmt::{Debug, Display};

use serde::{Serialize, Serializer};
use thiserror::Error;

use crate::Result;

/// Context is used to decorate errors with useful hint information.
// pub trait Context<T, E>
pub trait Ancillary<T, E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    /// Adds hint to the error. This is used as the `error_description` in
    /// the public error response.
    ///
    /// # Errors
    ///
    /// This function will return an `Err::ServerError` error if the hint cannot
    /// be added to the error.
    fn hint<C>(self, hint: C) -> Result<T, Error>
    where
        C: Display + Send + Sync + 'static;

    /// Add client state to the error in compliance with OAuth 2.0 specification.
    ///
    /// # Errors
    ///
    /// This function will return an `Err::ServerError` error if the state cannot
    /// be added to the error.
    fn state<C>(self, state: C) -> Result<T, Error>
    where
        C: Display + Send + Sync + 'static;
}

/// Public error type for `OpenID` for Verifiable Credential Issuance and
/// Verifiable Presentations.
#[derive(Error, Debug)]
pub struct Error {
    source: Err,
    backtrace: Backtrace,
    hint: Option<String>,
    state: Option<String>,
}

impl Error {
    /// Returns the error code from `Err::xxx`.
    pub fn error(&self) -> String {
        self.source.to_string()
    }

    /// Returns the error description as provided by hint method.
    pub fn error_description(&self) -> Option<String> {
        self.hint.clone()
    }

    /// Returns the `c_nonce` and `c_nonce_expires_in` values for `Err::InvalidProof` errors.
    pub fn c_nonce(&self) -> Option<(String, i64)> {
        let Err::InvalidProof(nonce, expires_in) = &self.source else {
            return None;
        };
        Some((nonce.clone(), *expires_in))
    }

    /// Transfrom error to `OpenID` compatible json format.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }

    /// Transfrom error to `OpenID` compatible query string format.
    /// Does not include `c_nonce` as this is not required for in query
    /// string responses.
    pub fn to_querystring(&self) -> String {
        serde_qs::to_string(&self).unwrap_or_default()
    }
}

// Display error code and description.
impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = format!("{}", self.source);
        if let Some(hint) = &self.hint {
            s = format!("{s}: {hint}");
        }
        write!(f, "{s}")
    }
}

impl Serialize for Error {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Serializer {
            error: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            error_description: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            state: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            c_nonce: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            c_nonce_expires_in: Option<i64>,
        }

        let mut ser = Serializer {
            error: self.source.to_string(),
            error_description: self.hint.clone(),
            state: self.state.clone(),
            c_nonce: None,
            c_nonce_expires_in: None,
        };

        // add c_nonce if Err::InvalidProof
        if let Err::InvalidProof(nonce, expires_in) = &self.source {
            ser.c_nonce = Some(nonce.clone());
            ser.c_nonce_expires_in = Some(*expires_in);
        };

        ser.serialize(serializer)
    }
}

/// Internal error codes for `OpenID` for Verifiable Credential Issuance
#[derive(Error, Debug)]
pub enum Err {
    /// The request is missing a required parameter, includes an unsupported
    /// parameter value, repeats a parameter, includes multiple credentials,
    /// utilizes more than one mechanism for authenticating the client, or is
    /// otherwise malformed.
    #[error("invalid_request")]
    InvalidRequest,

    /// Client authentication failed (e.g., unknown client, no client
    /// authentication included, or unsupported authentication method).
    ///
    /// The client tried to send a Token Request with a Pre-Authorized Code
    /// without Client ID but the Authorization Server does not support
    /// anonymous access.
    ///
    /// For Verifiable Presentations:
    ///
    /// `client_metadata` or `client_metadata_uri` is set, but the Wallet
    /// recognizes Client Identifier and already knows metadata associated
    /// with it.
    ///
    /// Verifier's pre-registered metadata has been found based on the Client
    /// Identifier, but `client_metadata` parameter is also set.
    #[error("invalid_client")]
    InvalidClient,

    /// The provided authorization grant (e.g., authorization code,
    /// pre-authorized_code) or refresh token is invalid, expired, revoked,
    /// does not match the redirection URI used in the authorization
    /// request, or was issued to another client.
    ///
    /// The Authorization Server expects a PIN in the pre-authorized flow but
    /// the client provides the wrong PIN.
    #[error("invalid_grant")]
    InvalidGrant,

    /// The client is not authorized to request an authorization code using this
    /// method.
    #[error("unauthorized_client")]
    UnauthorizedClient,

    /// The authorization grant type is not supported by the authorization
    /// server.
    #[error("unsupported_grant_type")]
    UnsupportedGrantType,

    /// The requested scope is invalid, unknown, malformed, or exceeds the scope
    /// granted.
    #[error("invalid_scope")]
    InvalidScope,

    /// The resource owner or authorization server denied the request.
    #[error("access_denied")]
    AccessDenied,

    /// The authorization server does not support obtaining an authorization
    /// code using this method.
    #[error("unsupported_response_type")]
    UnsupportedResponseType,

    /// The authorization server encountered an unexpected condition that
    /// prevented it from fulfilling the request.
    #[error("server_error")]
    ServerError(#[from] anyhow::Error),

    /// The authorization server is unable to handle the request due to
    /// temporary overloading or maintenance.
    #[error("temporarily_unavailable")]
    TemporarilyUnavailable,

    /// ------------------------------
    /// Verifiable Credential Issuance
    /// ------------------------------

    /// Token Endpoint:

    /// Returned if the Authorization Server is waiting for an End-User interaction
    /// or downstream process to complete. The Wallet SHOULD repeat the access token
    /// request to the token endpoint (a process known as polling). Before each new
    /// request, the Wallet MUST wait at least the number of seconds specified by the
    /// interval claim of the Credential Offer or the authorization response, or 5
    /// seconds if none was provided, and respect any increase in the polling interval
    /// required by the "`slow_down`" error.
    #[error("authorization_pending")]
    AuthorizationPending,

    /// A variant of `authorization_pending` error code, the authorization request is
    /// still pending and polling should continue, but the interval MUST be increased
    /// by 5 seconds for this and all subsequent requests.
    #[error("slow_down")]
    SlowDown,

    /// Credential Endpoint:

    /// The Credential Request is missing a required parameter, includes an unsupported
    /// parameter or parameter value, repeats the same parameter, or is otherwise
    /// malformed.
    #[error("invalid_credential_request")]
    InvalidCredentialRequest,

    /// Requested credential type is not supported.
    #[error("unsupported_credential_type")]
    UnsupportedCredentialType,

    /// Requested credential format is not supported.
    #[error("unsupported_credential_format")]
    UnsupportedCredentialFormat,

    /// Credential Request did not contain a proof, or proof was invalid, i.e. it was
    /// not bound to a Credential Issuer provided `c_nonce`. The error response contains
    /// new `c_nonce` as well as `c_nonce_expires_in` values to be used by the Wallet
    /// when creating another proof of possession of key material.
    #[error("invalid_proof")]
    InvalidProof(String, i64),

    /// This error occurs when the encryption parameters in the Credential Request are
    /// either invalid or missing. In the latter case, it indicates that the Credential
    /// Issuer requires the Credential Response to be sent encrypted, but the Credential
    /// Request does not contain the necessary encryption parameters.
    #[error("invalid_encryption_parameters")]
    InvalidEncryptionParameters,

    /// Deferred Issuance Endpoint:

    /// The Credential issuance is still pending. The error response SHOULD also contain
    /// the interval member, determining the minimum amount of time in seconds that the
    /// Wallet needs to wait before providing a new request to the Deferred Credential
    /// Endpoint. If interval member is missing or its value is not provided, the Wallet
    /// MUST use 5 as the default value.
    #[error("issuance_pending")]
    IssuancePending,

    /// The Deferred Credential Request contains an invalid `transaction_id`. This error
    /// occurs when the `transaction_id` was not issued by the respective Credential
    /// Issuer or it was already used to obtain the Credential.
    #[error("invalid_transaction_id")]
    InvalidTransactionId,

    /// ------------------------------
    /// Verifiable Presentation
    /// ------------------------------

    /// The Wallet does not support any of the formats requested by the
    /// Verifier, such as those included in the `vp_formats` registration
    /// parameter.
    #[error("vp_formats_not_supported")]
    VpFormatsNotSupported,

    /// The Presentation Definition URL cannot be reached.
    #[error("invalid_presentation_definition_uri")]
    InvalidPresentationDefinitionUri,

    /// The Presentation Definition URL can be reached, but the specified
    /// `presentation_definition` cannot be found at the URL.
    #[error("invalid_presentation_definition_reference")]
    InvalidPresentationDefinitionReference,
}

/// Add hint and state to error Results
impl<T, E> Ancillary<T, E> for Result<T, E>
where
    E: std::error::Error + Send + Sync + 'static,
    Error: From<E>,
{
    fn hint<C>(self, hint: C) -> Result<T, Error>
    where
        C: Display + Send + Sync + 'static,
    {
        match self {
            Ok(ok) => Ok(ok),
            Err(e) => {
                let err: Error = e.into();
                Err(Error {
                    source: err.source,
                    backtrace: err.backtrace,
                    hint: Some(hint.to_string()),
                    state: err.state,
                })
            }
        }
    }

    fn state<C>(self, state: C) -> Result<T, Error>
    where
        C: Display + Send + Sync + 'static,
    {
        match self {
            Ok(ok) => Ok(ok),
            Err(e) => {
                let err: Error = e.into();
                Err(Error {
                    source: err.source,
                    backtrace: err.backtrace,
                    hint: err.hint,
                    state: Some(state.to_string()),
                })
            }
        }
    }
}

impl From<Err> for Error {
    fn from(err: Err) -> Self {
        Self {
            source: err,
            backtrace: Backtrace::capture(),
            hint: None,
            state: None,
        }
    }
}

impl From<anyhow::Error> for Error {
    fn from(err: anyhow::Error) -> Self {
        Self {
            source: Err::ServerError(err),
            backtrace: Backtrace::capture(),
            hint: None,
            state: None,
        }
    }
}

impl From<base64ct::Error> for Error {
    fn from(err: base64ct::Error) -> Self {
        Self {
            source: Err::ServerError(err.into()),
            backtrace: Backtrace::capture(),
            hint: None,
            state: None,
        }
    }
}

impl From<ecdsa::Error> for Error {
    fn from(err: ecdsa::Error) -> Self {
        Self {
            source: Err::ServerError(err.into()),
            backtrace: Backtrace::capture(),
            hint: None,
            state: None,
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Self {
            source: Err::ServerError(err.into()),
            backtrace: Backtrace::capture(),
            hint: None,
            state: None,
        }
    }
}

impl From<serde_json_path::ParseError> for Error {
    fn from(err: serde_json_path::ParseError) -> Self {
        Self {
            source: Err::ServerError(err.into()),
            backtrace: Backtrace::capture(),
            hint: None,
            state: None,
        }
    }
}

impl From<serde_qs::Error> for Error {
    fn from(err: serde_qs::Error) -> Self {
        Self {
            source: Err::ServerError(err.into()),
            backtrace: Backtrace::capture(),
            hint: None,
            state: None,
        }
    }
}

impl From<std::convert::Infallible> for Error {
    fn from(err: std::convert::Infallible) -> Self {
        Self {
            source: Err::ServerError(err.into()),
            backtrace: Backtrace::capture(),
            hint: None,
            state: None,
        }
    }
}

/// Simplify creation of errors with tracing.
///
/// # Example
///
/// ```rust,ignore
/// use openid4vc::error::Err;
/// use vercre_core::{err, error, Result};
///
/// fn with_hint() -> Result<()> {
///     err!(Err::InvalidRequest, "hint: {}", "some hint")
/// }
///
/// fn no_hint() -> Result<()> {
///     err!(Err::InvalidRequest)
/// }
/// ```
#[doc(hidden)]
#[macro_export]
macro_rules! err {
    // Err::<code> + hint + state
    ($code:expr, state: $state:expr, $($msg:tt)+) => {{
        use $crate::error::Ancillary as _;
        return Err($code).hint(format!($($msg)+)).state($state);
    }};

    // Err::<code> + hint
    ($code:expr, $($msg:tt)+) => {{
        use $crate::error::Ancillary as _;
        return Err($code).hint(format!($($msg)+));
    }};

    // Err::<code> + state
    ($code:expr, state: $state:expr) => {{
        return Err($code.into()).state($state);
    }};

    // Err::<code>
    (code: $code:expr) => {{
        return Err($code.into());
    }};

    // one or more tokens e.g. "error: {e}"
    ($($msg:tt)+) => {{
        use $crate::error::Err;
        use $crate::error::Ancillary as _;
        use anyhow::anyhow;
        return Err(Err::ServerError(anyhow!($($msg)+))).hint(format!($($msg)+));
    }};
}

#[cfg(test)]
mod test {
    use std::env;

    use serde_json::json;

    use super::*;

    // Test that error details are retuned as json.
    #[test]
    fn err_json() {
        let err: Error = Err::InvalidRequest.into();
        assert_eq!(err.to_json(), json!({"error":"invalid_request"}));
    }

    // Test that the error details are returned as an http query string.
    #[test]
    fn err_querystring() {
        let res: Result<()> = Err(Err::InvalidRequest).hint("Invalid request description");
        let err = res.expect_err("expected error");

        assert_eq!(
            err.to_querystring(),
            "error=invalid_request&error_description=Invalid+request+description"
        );
    }

    // Test hint is returned as error_description in the external response.
    #[test]
    fn err_context() {
        let res: Result<()> = Err(Err::InvalidRequest).hint("Invalid request description");
        let err = res.expect_err("expected error");

        assert_eq!(
            err.to_json(),
            json!({
                "error": "invalid_request",
                "error_description": "Invalid request description"
            })
        );
    }

    // Test hint and client state are returned in the external response.
    #[test]
    fn err_state() {
        let res: Result<()> = Err(Err::InvalidRequest).state("client-state").hint("Some hint");
        let err = res.expect_err("expected error");

        assert_eq!(
            err.to_json(),
            json!({
                "error": "invalid_request",
                "error_description": "Some hint",
                "state": "client-state"
            })
        );
    }

    // Test an InvalidProof error returns c_nonce and c_nonce_expires_in values
    // in the external response.
    #[test]
    fn proof_err() {
        let err: Error = Err::InvalidProof("c_nonce".into(), 10).into();

        assert_eq!(err.c_nonce(), Some(("c_nonce".into(), 10)));
        assert_eq!(
            err.to_json(),
            json!({
                "error": "invalid_proof",
                "c_nonce": "c_nonce",
                "c_nonce_expires_in": 10,
            })
        );
    }

    // Test that the error code generates the expected error.
    #[test]
    fn err_macro() {
        let f = || -> Result<()> { err!(Err::InvalidRequest, state: "1234", "test {}", "me") };
        let e = f().expect_err("should error");
        assert_eq!(
            e.to_querystring(),
            "error=invalid_request&error_description=test+me&state=1234"
        );

        let f = || -> Result<()> { err!(code: Err::InvalidRequest) };
        let e = f().expect_err("should error");
        assert_eq!(e.to_querystring(), "error=invalid_request");
    }

    // Test From<error type> for Error.
    #[test]
    fn test_from_err() {
        let error = from_err().expect_err("expected error");

        assert_eq!(&error.to_string(), "server_error");

        // check backtrace, if it is enabled
        if env::var("RUST_BACKTRACE").is_ok_and(|s| s == "1") {
            assert!(error.backtrace.to_string().contains(
                "<openid4vc::error::Error as core::convert::From<serde_qs::error::Error>"
            ));
        }
    }

    fn from_err() -> Result<String> {
        Ok(serde_qs::to_string(&"some data")?)
    }
}
