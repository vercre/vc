//! An implementation of `RFC-8152` `COSE_Key` restricted to the requirements of `ISO/IEC 18013-5:2021`.
//!
//! This module provides the [`CoseKey`] enum, which represents a `COSE_Key` object as defined in `RFC-8152`.  
//! It supports two key types: `Ec2` (Elliptic Curve) and `Okp` (Octet Key Pair).
//!
//! # Examples
//!
//! ```ignore
//! use ssi_jwk::JWK;
//! use std::convert::TryInto;
//! use crate::CoseKey;
//!
//! let jwk: JWK = /* ... */;
//! let cose_key: Result<CoseKey, _> = jwk.try_into();
//!
//! match cose_key {
//!     Ok(key) => {
//!         // Perform operations with the COSE_Key
//!     }
//!     Err(err) => {
//!         // Handle the error
//!     }
//! }
//! ```
use std::collections::BTreeMap;

use aes::cipher::generic_array::typenum::U8;
use aes::cipher::generic_array::GenericArray;
use anyhow::anyhow;
use coset::iana::Algorithm;
use p256::EncodedPoint;
use serde::{Deserialize, Serialize};
use ssi_jwk::JWK;

/// An implementation of RFC-8152 [COSE_Key](https://datatracker.ietf.org/doc/html/rfc8152#section-13)
/// restricted to the requirements of ISO/IEC 18013-5:2021.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "ciborium::Value", into = "ciborium::Value")]
#[allow(clippy::module_name_repetitions)]
pub enum CoseKey {
    Ec2 { crv: Ec2Curve, x: Vec<u8>, y: Ec2y },
    Okp { crv: OkpCurve, x: Vec<u8> },
}

/// The sign bit or value of the y-coordinate for the EC point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ec2y {
    Value(Vec<u8>),
    SignBit(bool),
}

/// The RFC-8152 identifier of the curve, for Ec2 key type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ec2Curve {
    P256K,
}

/// The RFC-8152 identifier of the curve, for Okp key type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OkpCurve {
    Ed25519,
}

impl CoseKey {
    /// Returns the signature algorithm associated with the key.
    pub const fn signature_algorithm(&self) -> Algorithm {
        match self {
            Self::Ec2 {
                crv: Ec2Curve::P256K, ..
            } => Algorithm::ES256K,
            Self::Okp { .. } => Algorithm::EdDSA,
        }
    }
}

impl From<CoseKey> for ciborium::Value {
    fn from(key: CoseKey) -> Self {
        let mut map = vec![];
        match key {
            CoseKey::Ec2 { crv, x, y } => {
                // kty: 1, Ec2: 2
                map.push((Self::Integer(1.into()), Self::Integer(2.into())));
                // crv: -1
                map.push((Self::Integer((-1).into()), {
                    let cbor: Self = crv.into();
                    cbor
                }));
                // x: -2
                map.push((Self::Integer((-2).into()), Self::Bytes(x)));
                // y: -3
                map.push((Self::Integer((-3).into()), {
                    let cbor: Self = y.into();
                    cbor
                }));
            }
            CoseKey::Okp { crv, x } => {
                // kty: 1, Okp: 1
                map.push((Self::Integer(1.into()), Self::Integer(1.into())));
                // crv: -1
                map.push((Self::Integer((-1).into()), {
                    let cbor: Self = crv.into();
                    cbor
                }));
                // x: -2
                map.push((Self::Integer((-2).into()), Self::Bytes(x)));
            }
        }
        Self::Map(map)
    }
}

impl TryFrom<ciborium::Value> for CoseKey {
    type Error = anyhow::Error;

    fn try_from(v: ciborium::Value) -> anyhow::Result<Self> {
        if let ciborium::Value::Map(map) = v.clone() {
            let mut map: BTreeMap<i128, ciborium::Value> = map
                .into_iter()
                .map(|(k, v)| {
                    let k =
                        k.into_integer().map_err(|e| anyhow!("issue deserializing: {e:?}"))?.into();
                    Ok((k, v))
                })
                .collect::<anyhow::Result<BTreeMap<_, _>>>()?;
            match (map.remove(&1), map.remove(&-1), map.remove(&-2)) {
                (
                    Some(ciborium::Value::Integer(i2)),
                    Some(ciborium::Value::Integer(crv_id)),
                    Some(ciborium::Value::Bytes(x)),
                ) if <ciborium::value::Integer as Into<i128>>::into(i2) == 2 => {
                    let crv_id: i128 = crv_id.into();
                    let crv = crv_id.try_into()?;
                    let y = map
                        .remove(&-3)
                        .ok_or_else(|| anyhow!("issue deserializing Y"))?
                        .try_into()?;
                    Ok(Self::Ec2 { crv, x, y })
                }
                (
                    Some(ciborium::Value::Integer(i1)),
                    Some(ciborium::Value::Integer(crv_id)),
                    Some(ciborium::Value::Bytes(x)),
                ) if <ciborium::value::Integer as Into<i128>>::into(i1) == 1 => {
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

impl TryFrom<CoseKey> for EncodedPoint {
    type Error = anyhow::Error;

    fn try_from(value: CoseKey) -> anyhow::Result<Self> {
        match value {
            CoseKey::Ec2 {
                crv: Ec2Curve::P256K,
                x,
                y,
            } => {
                let x_generic_array = GenericArray::from_slice(x.as_ref());
                match y {
                    Ec2y::Value(y) => {
                        let y_generic_array = GenericArray::from_slice(y.as_ref());

                        Ok(Self::from_affine_coordinates(x_generic_array, y_generic_array, false))
                    }
                    Ec2y::SignBit(y) => {
                        let mut bytes = x.clone();
                        if y {
                            bytes.insert(0, 3);
                        } else {
                            bytes.insert(0, 2);
                        }

                        let encoded = Self::from_bytes(bytes)
                            .map_err(|e| anyhow!("issue constructing CoseKey: {e}"))?;
                        Ok(encoded)
                    }
                }
            }
            CoseKey::Okp { crv: _, x } => {
                let x_generic_array: GenericArray<_, U8> =
                    GenericArray::clone_from_slice(&x[0..42]);
                let encoded = Self::from_bytes(x_generic_array)
                    .map_err(|e| anyhow!("issue constructing CoseKey: {e}"))?;
                Ok(encoded)
            }
        }
    }
}

impl From<Ec2y> for ciborium::Value {
    fn from(y: Ec2y) -> Self {
        match y {
            Ec2y::Value(s) => Self::Bytes(s),
            Ec2y::SignBit(b) => Self::Bool(b),
        }
    }
}

impl TryFrom<ciborium::Value> for Ec2y {
    type Error = anyhow::Error;

    fn try_from(v: ciborium::Value) -> anyhow::Result<Self> {
        match v {
            ciborium::Value::Bytes(s) => Ok(Self::Value(s)),
            ciborium::Value::Bool(b) => Ok(Self::SignBit(b)),
            _ => Err(anyhow!("issue deserializing Y: {v:?}")),
        }
    }
}

impl From<Ec2Curve> for ciborium::Value {
    fn from(crv: Ec2Curve) -> Self {
        match crv {
            Ec2Curve::P256K => Self::Integer(8.into()),
        }
    }
}

impl TryFrom<i128> for Ec2Curve {
    type Error = anyhow::Error;

    fn try_from(crv_id: i128) -> anyhow::Result<Self> {
        match crv_id {
            8 => Ok(Self::P256K),
            _ => Err(anyhow!("unsupported curve")),
        }
    }
}

impl From<OkpCurve> for ciborium::Value {
    fn from(crv: OkpCurve) -> Self {
        match crv {
            OkpCurve::Ed25519 => Self::Integer(6.into()),
        }
    }
}

impl TryFrom<i128> for OkpCurve {
    type Error = anyhow::Error;

    fn try_from(crv_id: i128) -> anyhow::Result<Self> {
        match crv_id {
            6 => Ok(Self::Ed25519),
            _ => Err(anyhow!("unsupported curve")),
        }
    }
}

impl TryFrom<JWK> for CoseKey {
    type Error = anyhow::Error;

    fn try_from(jwk: JWK) -> anyhow::Result<Self> {
        match jwk.params {
            ssi_jwk::Params::EC(params) => {
                let x = params
                    .x_coordinate
                    .as_ref()
                    .ok_or_else(|| anyhow!("missing X coordinate"))?
                    .0
                    .clone();
                Ok(Self::Ec2 {
                    crv: (&params).try_into()?,
                    x,
                    y: params.try_into()?,
                })
            }
            ssi_jwk::Params::OKP(params) => Ok(Self::Okp {
                crv: (&params).try_into()?,
                x: params.public_key.0.clone(),
            }),
            _ => Err(anyhow!("unsupported key type")),
        }
    }
}

impl TryFrom<&ssi_jwk::ECParams> for Ec2Curve {
    type Error = anyhow::Error;

    fn try_from(params: &ssi_jwk::ECParams) -> anyhow::Result<Self> {
        match params.curve.as_ref() {
            Some(crv) if crv == "secp256k1" => Ok(Self::P256K),
            _ => Err(anyhow!("unsupported curve")),
        }
    }
}

impl TryFrom<ssi_jwk::ECParams> for Ec2y {
    type Error = anyhow::Error;

    fn try_from(params: ssi_jwk::ECParams) -> anyhow::Result<Self> {
        params
            .y_coordinate
            .as_ref()
            .map_or(Err(anyhow!("missing y coordinate")), |y| Ok(Self::Value(y.0.clone())))
    }
}

impl TryFrom<CoseKey> for JWK {
    type Error = anyhow::Error;

    fn try_from(cose: CoseKey) -> anyhow::Result<Self> {
        Ok(match cose {
            CoseKey::Ec2 { crv, x, y } => Self {
                params: ssi_jwk::Params::EC(ssi_jwk::ECParams {
                    curve: Some(match crv {
                        Ec2Curve::P256K => "secp256k1".to_string(),
                    }),
                    x_coordinate: Some(ssi_jwk::Base64urlUInt(x)),
                    y_coordinate: match y {
                        Ec2y::Value(vec) => Some(ssi_jwk::Base64urlUInt(vec)),
                        Ec2y::SignBit(_) => return Err(anyhow!("unsupported format")),
                    },
                    ecc_private_key: None,
                }),
                public_key_use: None,
                key_operations: None,
                algorithm: None,
                key_id: None,
                x509_url: None,
                x509_certificate_chain: None,
                x509_thumbprint_sha1: None,
                x509_thumbprint_sha256: None,
            },
            CoseKey::Okp { crv, x } => Self {
                params: ssi_jwk::Params::OKP(ssi_jwk::OctetParams {
                    curve: match crv {
                        OkpCurve::Ed25519 => "Ed25519".to_string(),
                    },
                    public_key: ssi_jwk::Base64urlUInt(x),
                    private_key: None,
                }),
                public_key_use: None,
                key_operations: None,
                algorithm: None,
                key_id: None,
                x509_url: None,
                x509_certificate_chain: None,
                x509_thumbprint_sha1: None,
                x509_thumbprint_sha256: None,
            },
        })
    }
}

impl TryFrom<&ssi_jwk::OctetParams> for OkpCurve {
    type Error = anyhow::Error;

    fn try_from(params: &ssi_jwk::OctetParams) -> anyhow::Result<Self> {
        match params.curve.as_str() {
            "Ed25519" => Ok(Self::Ed25519),
            _ => Err(anyhow!("unsupported curve")),
        }
    }
}

#[cfg(test)]
mod test {
    use hex::FromHex;

    use super::*;
    use crate::cbor;

    static EC_P256: &str = include_str!("../data/ec_p256.cbor");

    #[test]
    fn ec_p256() {
        let key_bytes = <Vec<u8>>::from_hex(EC_P256).expect("unable to convert cbor hex to bytes");
        let key = crate::cbor::from_slice(&key_bytes).unwrap();
        match &key {
            CoseKey::Ec2 { crv, .. } => assert_eq!(crv, &Ec2Curve::P256K),
            _ => panic!("expected an Ec2 cose key"),
        };
        assert_eq!(cbor::to_vec(&key).unwrap(), key_bytes, "cbor encoding roundtrip failed");
    }
}
