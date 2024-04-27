//! Delay Capability
//!
//! This capability allows the application to delay the dispatch of an event by a
//!  specified amount of time.

use crux_core::capability::{CapabilityContext, Operation};
use crux_core::macros::Capability;
use serde::{Deserialize, Serialize};

/// Operations supported (by the Delay capability).
#[allow(clippy::module_name_repetitions)]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DelayOperation {
    /// Delay in milliseconds.
    pub delay_ms: u64,
}

/// Output.
impl Operation for DelayOperation {
    type Output = ();
}

/// Delay capability context.
#[derive(Capability)]
#[allow(clippy::module_name_repetitions)]
pub struct Delay<Ev> {
    context: CapabilityContext<DelayOperation, Ev>,
}

impl<Ev> Delay<Ev>
where
    Ev: 'static,
{
    /// Create a new Delay capability context.
    #[must_use]
    pub const fn new(context: CapabilityContext<DelayOperation, Ev>) -> Self {
        Self { context }
    }

    /// Dispatch the specified event after a timer delay.
    pub fn start(&self, ms: u64, event: Ev)
    where
        Ev: Send + 'static,
    {
        self.context.spawn({
            let ctx = self.context.clone();

            async move {
                ctx.request_from_shell(DelayOperation { delay_ms: ms }).await;
                ctx.update_app(event);
            }
        });
    }
}
