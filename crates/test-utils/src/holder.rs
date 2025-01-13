use vercre_infosec::{Algorithm, Signer};
use vercre_openid::provider::Result;

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
    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        HolderKeystore::try_sign(msg)
    }

    async fn verifying_key(&self) -> Result<Vec<u8>> {
        HolderKeystore::public_key()
    }

    fn algorithm(&self) -> Algorithm {
        HolderKeystore::algorithm()
    }

    async fn verification_method(&self) -> Result<String> {
        Ok(HolderKeystore::verification_method())
    }
}
