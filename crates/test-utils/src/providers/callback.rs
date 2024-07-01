use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use openid4vc::endpoint::{Payload, Result};

#[derive(Default, Clone, Debug)]
pub struct Hook {
    _clients: Arc<Mutex<HashMap<String, String>>>,
}

impl Hook {
    pub fn new() -> Self {
        Self {
            _clients: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[allow(clippy::unnecessary_wraps, clippy::unused_self, clippy::missing_const_for_fn)]
    pub fn callback(&self, _: &Payload) -> Result<()> {
        Ok(())
    }
}
