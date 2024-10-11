//! # COSE Key
//!
//! Support for `COSE_Key` as defined in [RFC9052]
//!
//! [RFC9052]: https://www.rfc-editor.org/rfc/rfc9052.html#name-key-objects

use std::collections::BTreeMap;

use anyhow::anyhow;
use ciborium::value::Integer;
use ciborium::Value;
use serde::{Deserialize, Serialize};

use crate::{Curve, KeyType};

const KEY_TYPE: i64 = 1;
const CURVE: i64 = -1;
const X: i64 = -2;
const Y: i64 = -3;

/// Implements [`COSE_Key`] as defined in [RFC9052].
///
/// [RFC9052]: https://www.rfc-editor.org/rfc/rfc9052.html#name-key-objects
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "Value", into = "Value")]
#[allow(clippy::module_name_repetitions)]
pub struct CoseKey {
    /// Key type
    pub kty: KeyType,

    /// Curve
    pub crv: Curve,

    /// Public key X
    pub x: Vec<u8>,

    /// Public key Y
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<Vec<u8>>,
}

/// Serialize `COSE_Key` to CBOR.
impl From<CoseKey> for Value {
    fn from(key: CoseKey) -> Self {
        let mut cbor = vec![
            (KEY_TYPE.into(), key.kty.clone().into()),
            (CURVE.into(), { key.crv.into() }),
            (X.into(), Self::Bytes(key.x)),
        ];

        if key.kty == KeyType::Ec {
            cbor.push((Y.into(), { key.y.unwrap_or_default().into() }));
        }

        Self::Map(cbor)
    }
}

/// Deserialize `COSE_Key` from CBOR.
impl TryFrom<Value> for CoseKey {
    type Error = anyhow::Error;

    fn try_from(v: Value) -> anyhow::Result<Self> {
        if let Value::Map(map) = v.clone() {
            let mut map: BTreeMap<Integer, Value> = map
                .into_iter()
                .map(|(k, v)| (k.as_integer().unwrap_or_else(|| 0.into()), v))
                .collect::<BTreeMap<_, _>>();

            let Some(kty) = map.remove(&Integer::from(KEY_TYPE)) else {
                return Err(anyhow!("key type not found"));
            };
            let Some(crv) = map.remove(&Integer::from(CURVE)) else {
                return Err(anyhow!("curve not found"));
            };
            let Some(Value::Bytes(x)) = map.remove(&Integer::from(X)) else {
                return Err(anyhow!("x coordinate not found"));
            };

            let y = if kty == KeyType::Ec.into() {
                let y = map
                    .remove(&Integer::from(Y))
                    .ok_or_else(|| anyhow!("y coordinate not found"))?;
                y.as_bytes().cloned()
            } else {
                None
            };

            Ok(Self {
                kty: kty.try_into()?,
                crv: crv.try_into()?,
                x,
                y,
            })
        } else {
            Err(anyhow!("Value is not a map: {v:?}"))
        }
    }
}

impl From<KeyType> for Value {
    fn from(k: KeyType) -> Self {
        match k {
            KeyType::Okp => Self::Integer(1.into()),
            KeyType::Ec => Self::Integer(2.into()),
            KeyType::Oct => Self::Integer(4.into()),
        }
    }
}

impl TryInto<KeyType> for Value {
    type Error = anyhow::Error;

    fn try_into(self) -> anyhow::Result<KeyType> {
        let Some(integer) = self.as_integer() else {
            return Err(anyhow!("issue deserializing key type"));
        };

        match integer.into() {
            1 => Ok(KeyType::Okp),
            2 => Ok(KeyType::Ec),
            4 => Ok(KeyType::Oct),
            _ => Err(anyhow!("unsupported key type")),
        }
    }
}

impl From<Curve> for Value {
    fn from(crv: Curve) -> Self {
        match crv {
            Curve::Ed25519 => Self::Integer(6.into()),
            Curve::Es256K => Self::Integer(8.into()),
        }
    }
}

impl TryInto<Curve> for Value {
    type Error = anyhow::Error;

    fn try_into(self) -> anyhow::Result<Curve> {
        let Some(integer) = self.as_integer() else {
            return Err(anyhow!("issue deserializing curve"));
        };

        match integer.into() {
            6 => Ok(Curve::Ed25519),
            8 => Ok(Curve::Es256K),
            _ => Err(anyhow!("unsupported curve: {integer:?}")),
        }
    }
}

#[cfg(test)]
mod test {
    use hex::FromHex;

    use super::*;
    use crate::cose::cbor;

    const ES256K_CBOR: &str = "a40102200821582065eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d2258201e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c";
    const X_HEX: &str = "65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d";
    const Y_HEX: &str = "1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c";

    #[test]
    fn serialize() {
        let cose_key = CoseKey {
            kty: KeyType::Ec,
            crv: Curve::Es256K,
            x: Vec::from_hex(X_HEX).unwrap(),
            y: Some(Vec::from_hex(Y_HEX).unwrap()),
        };

        let cbor = cbor::to_vec(&cose_key).expect("should serialize");
        let hex = hex::encode(cbor);

        assert_eq!(hex, ES256K_CBOR);
    }

    #[test]
    fn deserialize() {
        let bytes = hex::decode(ES256K_CBOR).expect("should decode");
        let key: CoseKey = cbor::from_slice(&bytes).expect("should serialize");

        let cose_key = CoseKey {
            kty: KeyType::Ec,
            crv: Curve::Es256K,
            x: Vec::from_hex(X_HEX).unwrap(),
            y: Some(Vec::from_hex(Y_HEX).unwrap()),
        };

        assert_eq!(key, cose_key);
    }
}
