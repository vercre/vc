use anyhow::anyhow;
use stronghold::Stronghold;
use tauri::Manager;
use vercre_wallet::signer::{SignerRequest, SignerResponse};

use crate::error;

// initialise the Stronghold key store
pub fn init(handle: &tauri::AppHandle) -> anyhow::Result<()> {
    // FIXME: get passphrase from user and salt from file(?)
    let passphrase = b"pass-phrase";
    let salt = b"randomsalt";
    let hash = argon2::hash_raw(passphrase, salt, &argon2::Config::default())?;

    // open/initialize Stronghold snapshot
    let path = handle.path().app_local_data_dir()?.join("stronghold.bin");
    let stronghold = Stronghold::new(path, hash)?;
    handle.manage(stronghold);

    Ok(())
}

pub fn request<R>(
    op: &SignerRequest, app_handle: &tauri::AppHandle<R>,
) -> Result<SignerResponse, error::Error>
where
    R: tauri::Runtime,
{
    let stronghold = app_handle.state::<Stronghold>();

    match op {
        SignerRequest::Sign(msg) => {
            let signed = stronghold.sign(msg.clone()).unwrap();
            Ok(SignerResponse::Signature(signed))
        }
        SignerRequest::Verification => {
            // FIXME: implement
            let alg = String::from("EdDSA"); // String::from("ES256K");
            let Ok(kid) = stronghold.verifiction() else {
                return Err(error::Error::Other(anyhow!("verification failed")));
            };
            Ok(SignerResponse::Verification { alg, kid })
        }
    }
}

pub mod stronghold {
    use std::path::Path;

    use anyhow::Result;
    use base64ct::{Base64UrlUnpadded, Encoding};
    use iota_stronghold::engine::snapshot::KEY_SIZE;
    // use iota_stronghold::engine::vault::Base64Encodable;
    use iota_stronghold::procedures::{
        Ed25519Sign, GenerateKey, KeyType, PublicKey, StrongholdProcedure,
    };
    use iota_stronghold::{engine, Client, KeyProvider, Location, SnapshotPath};
    use zeroize::Zeroizing;

    const CLIENT: &[u8] = b"signing_client";
    const VAULT: &[u8] = b"signing_key_vault";
    const SIGNING_KEY: &[u8] = b"signing_key";

    pub struct Stronghold {
        key_location: Location,
        client: Client,
    }

    impl Stronghold {
        /// Create new Stronghold instance.
        /// The method will attempt to load a Stronghold snapshot from the given path,
        /// or create a new one if it does not exist.
        ///
        /// When creating a new snapshot, a signing key will be generated and saved to
        /// the vault.
        ///
        /// The snapshot is encrypted using the password provided.
        pub fn new(path: impl AsRef<Path>, password: Vec<u8>) -> Result<Self> {
            let stronghold = iota_stronghold::Stronghold::default();

            let keyprovider = KeyProvider::try_from(Zeroizing::new(password))?;
            let snapshot_path = SnapshotPath::from_path(path);
            let key_location = Location::generic(VAULT, SIGNING_KEY);

            let client = {
                if snapshot_path.exists() {
                    let client = stronghold.load_client_from_snapshot(
                        CLIENT,
                        &keyprovider,
                        &snapshot_path,
                    )?;

                    // --------------------------------------------------------
                    use lazy_static::__Deref;
                    let buffer = keyprovider.try_unlock().expect("should unlock");
                    let buffer_borrow = buffer.borrow();
                    let buffer_ref = buffer_borrow.deref().try_into().unwrap();
                    let _snapshot = iota_stronghold::Snapshot::read_from_snapshot(
                        &snapshot_path,
                        buffer_ref,
                        None,
                    )
                    .expect("should load");
                    // --------------------------------------------------------

                    client
                } else {
                    // --------------------------------------------------------
                    // HACK: Override encryption work factor
                    // --------------------------------------------------------
                    // ```rust
                    //  pub const RECOMMENDED_MAXIMUM_DECRYPT_WORK_FACTOR: u8 = 23;
                    // ```
                    //
                    // `iota_snapshot` uses a 'work factor' of 23 for password protected files.
                    // This means encryption/decrytion takes ~45 sec, so we override here for
                    // performance during development.
                    // N.B. (AW) actually can take more like 90 sec!!

                    // From `iota_snapshot` code comments:
                    //
                    // Work factor is used to strengthen weak low-entropy (password-based) keys.
                    // Recommended value for such keys is approx. 20, ie. key derivation should
                    // take approx. 1 second. Key derivation time grows exponentially with work
                    // factor.
                    //
                    // Strong keys generated with cryptographically secure RNG do not need
                    // strengthening and can use minimal (0) work factor.
                    // --------------------------------------------------------
                    engine::snapshot::try_set_encrypt_work_factor(0)?;

                    let client = stronghold.create_client(CLIENT)?;

                    // generate signing key
                    let proc = StrongholdProcedure::GenerateKey(GenerateKey {
                        // ty: KeyType::Secp256k1Ecdsa,
                        ty: KeyType::Ed25519,
                        output: key_location.clone(),
                    });
                    let _ = client.execute_procedure(proc)?;

                    // save snapshot (+ client and vault)
                    stronghold.commit_with_keyprovider(&snapshot_path, &keyprovider)?;
                    client
                }
            };

            Ok(Self { key_location, client })
        }

        /// Sign message using the snapshot's signing key.
        pub(super) fn sign(&self, msg: Vec<u8>) -> Result<Vec<u8>> {
            // let proc = StrongholdProcedure::Secp256k1EcdsaSign(Secp256k1EcdsaSign {
            //     flavor: Secp256k1EcdsaFlavor::Sha256,
            //     msg,
            //     private_key: self.key_location.clone(),
            // });
            // let output = self.client.execute_procedure(proc)?;

            // // remove trailing 0
            // let mut signed_bytes: Vec<u8> = output.into();
            // signed_bytes.truncate(signed_bytes.len() - 1);
            // Ok(signed_bytes)

            let proc = StrongholdProcedure::Ed25519Sign(Ed25519Sign {
                msg,
                private_key: self.key_location.clone(),
            });
            let output = self.client.execute_procedure(proc)?;
            Ok(output.into())
        }

        /// Get the signing key's public key from the snapshot.
        pub(super) fn verifiction(&self) -> Result<String> {
            // get public key
            let proc = StrongholdProcedure::PublicKey(PublicKey {
                ty: KeyType::Ed25519,
                private_key: self.key_location.clone(),
            });
            let output = self.client.execute_procedure(proc)?;

            // convert to did:jwk
            let x_bytes: Vec<u8> = output.into();

            let jwk = serde_json::json!({
                "kty": "OKP",
                "crv": "X25519",
                "use": "enc",
                "x": Base64UrlUnpadded::encode_string(&x_bytes),
            });
            let jwk_str = jwk.to_string();
            let jwk_b64 = Base64UrlUnpadded::encode_string(jwk_str.as_bytes());

            Ok(format!("did:jwk:{jwk_b64}#0"))
        }
    }
}

#[cfg(test)]
mod test {
    use assert_let_bind::assert_let;
    use lazy_static::lazy_static;
    use serde_json::json;
    use tauri::test::{mock_builder, mock_context, noop_assets};

    use super::*;

    #[tokio::test]
    async fn sign() {
        // set up store
        let app = create_app(mock_builder());

        let msg = String::from("hello world");
        let req = SignerRequest::Sign(msg.into_bytes());
        let resp = request(&req, app.app_handle()).expect("should be ok");

        // // check counts match
        assert_let!(SignerResponse::Signature(res), resp);
        println!("res: {:?}", res);
        // let vals = serde_json::from_slice::<Vec<Value>>(&res).expect("should deserialize");
        // assert_eq!(count, vals.len());
    }

    fn create_app<R: tauri::Runtime>(builder: tauri::Builder<R>) -> tauri::App<R> {
        builder
            // .plugin(tauri_plugin_store::Builder::<R>::default().build())
            .build(mock_context(noop_assets()))
            .expect("failed to build app")
    }

    lazy_static! {
        static ref ENTRIES: serde_json::Value = json!({
                "id": "https://credibil.io/credentials/3732",
        });
    }
}
