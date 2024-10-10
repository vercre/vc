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
        let cbor = match key.kty {
            KeyType::Okp => {
                vec![
                    (KEY_TYPE.into(), KeyType::Okp.into()),
                    (CURVE.into(), { key.crv.into() }),
                    (X.into(), Self::Bytes(key.x)),
                ]
            }
            KeyType::Ec => {
                vec![
                    (KEY_TYPE.into(), KeyType::Ec.into()),
                    ((CURVE).into(), { key.crv.into() }),
                    (X.into(), Self::Bytes(key.x)),
                    (Y.into(), { key.y.unwrap_or_default().into() }),
                ]
            }
            KeyType::Oct => {
                vec![
                    (KEY_TYPE.into(), KeyType::Oct.into()),
                    (CURVE.into(), { key.crv.into() }),
                    (X.into(), Self::Bytes(key.x)),
                ]
            }
        };
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

            match (
                map.remove(&Integer::from(KEY_TYPE)),
                map.remove(&Integer::from(CURVE)),
                map.remove(&Integer::from(X)),
            ) {
                (Some(kty), Some(crv), Some(Value::Bytes(x))) if kty == KeyType::Okp.into() => {
                    Ok(Self {
                        kty: KeyType::Okp,
                        crv: crv.try_into()?,
                        x,
                        y: None,
                    })
                }
                (Some(kty), Some(crv), Some(Value::Bytes(x))) if kty == KeyType::Ec.into() => {
                    let y = map.remove(&Integer::from(Y)).ok_or_else(|| anyhow!("missing Y"))?;

                    Ok(Self {
                        kty: KeyType::Ec,
                        crv: crv.try_into()?,
                        x,
                        y: y.as_bytes().cloned(),
                    })
                }
                _ => Err(anyhow!("issue deserializing CoseKey")),
            }
        } else {
            Err(anyhow!("Value is not a map: {v:?}"))
        }
    }
}

const KEY_TYPE: i64 = 1;
const CURVE: i64 = -1;
const X: i64 = -2;
const Y: i64 = -3;

impl From<KeyType> for Value {
    fn from(k: KeyType) -> Self {
        match k {
            KeyType::Okp => Self::Integer(1.into()),
            KeyType::Ec => Self::Integer(2.into()),
            KeyType::Oct => Self::Integer(4.into()),
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
            return Err(anyhow!("unsupported curve"));
        };

        match integer.into() {
            6 => Ok(Curve::Ed25519),
            8 => Ok(Curve::Es256K),
            _ => Err(anyhow!("unsupported curve")),
        }
    }
}

// #[cfg(test)]
// mod test {
//     use hex::FromHex;

//     use super::*;
//     use crate::cbor;

//     static EC_P256: &str = include_str!("../data/ec_p256.cbor");

//     #[test]
//     fn ec_p256() {
//         let key_bytes = <Vec<u8>>::from_hex(EC_P256).expect("unable to convert cbor hex to bytes");
//         let key = crate::cbor::from_slice(&key_bytes).unwrap();
//         match &key {
//             CoseKey::Ec2 { crv, .. } => assert_eq!(crv, &Ec2Curve::P256K),
//             _ => panic!("expected an Ec2 cose key"),
//         };
//         assert_eq!(cbor::to_vec(&key).unwrap(), key_bytes, "cbor encoding roundtrip failed");
//     }
// }
