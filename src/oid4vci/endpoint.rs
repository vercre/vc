//! # Endpoint
//!
//! `Endpoint` provides the entry point for DWN messages. Messages are routed
//! to the appropriate handler for processing, returning a reply that can be
//! serialized to a JSON object.

use std::fmt::Debug;

use crate::invalid;
use crate::oid4vci::Result;
use crate::oid4vci::provider::Provider;

/// Handle incoming messages.
///
/// # Errors
///
/// This method can fail for a number of reasons related to the imcoming
/// message's viability. Expected failues include invalid authorization,
/// insufficient permissions, and invalid message content.
///
/// Implementers should look to the Error type and description for more
/// information on the reason for failure.
pub async fn handle<T>(
    owner: &str, message: impl Handler<Response = T>, provider: &impl Provider,
) -> Result<T> {
    message.validate(owner, provider).await?;
    message.handle(owner, provider).await
}

/// Methods common to all messages.
///
/// The primary role of this trait is to provide a common interface for
/// messages so they can be handled by [`handle`] method.
pub trait Handler: Clone + Debug + Send + Sync {
    /// The inner reply type specific to the implementing message.
    type Response;

    /// Routes the message to the concrete handler used to process the message.
    fn handle(
        self, credential_issuer: &str, provider: &impl Provider,
    ) -> impl Future<Output = Result<Self::Response>> + Send;

    /// Perform initial validation of the message.
    ///
    /// Validation undertaken here is common to all messages, with message-
    /// specific validation performed by the message's handler.
    fn validate(
        &self, credential_issuer: &str, _provider: &impl Provider,
    ) -> impl Future<Output = Result<()>> + Send {
        async {
            // if !tenant_gate.active(credential_issuer)? {
            //     return Err(Error::Unauthorized("tenant not active"));
            // }
            // `credential_issuer` required
            if credential_issuer.is_empty() {
                return Err(invalid!("no `credential_issuer` specified"));
            }

            // // validate the message schema during development
            // #[cfg(debug_assertions)]
            // schema::validate(self)?;

            // // authenticate the requestor
            // if let Some(authzn) = self.authorization() {
            //     if let Err(e) = authzn.verify(provider.clone()).await {
            //         return Err(unauthorized!("failed to authenticate: {e}"));
            //     }
            // }

            Ok(())
        }
    }
}
