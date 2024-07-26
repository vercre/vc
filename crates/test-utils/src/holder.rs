use openid::provider::Result;
use jose::signature::{Algorithm, Signer};

use crate::store::keystore::HolderKeystore;

#[derive(Clone, Debug)]
pub struct Provider;
impl Provider {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for Provider {
    fn default() -> Self {
        Self::new()
    }
}

impl Signer for Provider {
    fn algorithm(&self) -> Algorithm {
        HolderKeystore::algorithm()
    }

    fn verification_method(&self) -> String {
        HolderKeystore::verification_method()
    }

    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        HolderKeystore::try_sign(msg)
    }
}
