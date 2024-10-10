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

/// Implements [`COSE_Key`] as defined in [RFC9052].
///
/// [RFC9052]: https://www.rfc-editor.org/rfc/rfc9052.html#name-key-objects
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "Value", into = "Value")]
#[allow(clippy::module_name_repetitions)]
pub enum CoseKey {
    /// Octet Key Pair
    Okp {
        /// Curve
        crv: Curve,

        /// Public key
        x: Vec<u8>,
    },
}

/// Curve identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Curve {
    /// Ed25519 curve
    Ed25519,
}

/// Serialize `COSE_Key` to CBOR.
impl From<CoseKey> for Value {
    fn from(key: CoseKey) -> Self {
        let mut cbor = vec![];
        match key {
            CoseKey::Okp { crv, x } => {
                // kty: 1, Okp: 1
                cbor.push((Self::Integer(1.into()), Self::Integer(1.into())));
                // crv: -1
                cbor.push((Self::Integer((-1).into()), { crv.into() }));
                // x: -2
                cbor.push((Self::Integer((-2).into()), Self::Bytes(x)));
            }
        }
        Self::Map(cbor)
    }
}

/// Deserialize `COSE_Key` from CBOR.
impl TryFrom<Value> for CoseKey {
    type Error = anyhow::Error;

    fn try_from(v: Value) -> anyhow::Result<Self> {
        if let Value::Map(map) = v.clone() {
            let mut map: BTreeMap<i128, Value> = map
                .into_iter()
                .map(|(k, v)| {
                    let k =
                        k.into_integer().map_err(|e| anyhow!("issue deserializing: {e:?}"))?.into();
                    Ok((k, v))
                })
                .collect::<anyhow::Result<BTreeMap<_, _>>>()?;

            // kty: 1, Okp: 1, crv: -1, x: -2
            match (map.remove(&1), map.remove(&-1), map.remove(&-2)) {
                (Some(Value::Integer(i1)), Some(Value::Integer(crv_id)), Some(Value::Bytes(x)))
                    if i1 == Integer::from(1) =>
                {
                    let crv_id: i128 = crv_id.into();
                    let crv = crv_id.try_into()?;
                    Ok(Self::Okp { crv, x })
                }
                _ => Err(anyhow!("issue deserializing CoseKey")),
            }
        } else {
            Err(anyhow!("Value is not a map: {v:?}"))
        }
    }
}

impl From<Curve> for Value {
    fn from(crv: Curve) -> Self {
        match crv {
            Curve::Ed25519 => Self::Integer(6.into()),
        }
    }
}

impl TryFrom<i128> for Curve {
    type Error = anyhow::Error;

    fn try_from(crv_id: i128) -> anyhow::Result<Self> {
        match crv_id {
            6 => Ok(Self::Ed25519),
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
