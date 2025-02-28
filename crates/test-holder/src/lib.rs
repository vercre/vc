pub mod keystore;

use credibil_infosec::{Algorithm, Signer};
use credibil_vc::openid::provider::Result;
use keystore::Keystore;

#[derive(Clone, Debug)]
pub struct ProviderImpl;

impl ProviderImpl {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for ProviderImpl {
    fn default() -> Self {
        Self::new()
    }
}

impl Signer for ProviderImpl {
    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        Keystore::try_sign(msg)
    }

    async fn verifying_key(&self) -> Result<Vec<u8>> {
        Keystore::public_key()
    }

    fn algorithm(&self) -> Algorithm {
        Keystore::algorithm()
    }

    async fn verification_method(&self) -> Result<String> {
        Ok(Keystore::verification_method())
    }
}
