#![feature(prelude_import)]
#![feature(let_chains)]
//! # Data Security for Vercre
//!
//! This crate provides common utilities for the Vercre project and is not
//! intended to be used directly.
#[prelude_import]
use std::prelude::rust_2021::*;
#[macro_use]
extern crate std;
pub mod cose {
    //! # COSE
    //!
    //! This module provides types for working with CBOR Object Signing and Encryption (COSE) keys.
    pub mod cbor {
        //! # CBOR
        //!
        //! This module provides CBOR helper functions and types.
        use std::io::Cursor;
        use std::ops::Deref;
        use anyhow::anyhow;
        use ciborium::Value;
        use coset::CoseError;
        use serde::de::{self, DeserializeOwned, Deserializer};
        use serde::ser::Serializer;
        use serde::{Deserialize, Serialize};
        /// Serialize a value to a CBOR byte vector.
        ///
        /// # Errors
        /// TODO: Document errors
        pub fn to_vec<T>(value: &T) -> anyhow::Result<Vec<u8>>
        where
            T: Serialize,
        {
            let mut buf = Vec::new();
            ciborium::into_writer(value, &mut buf)?;
            Ok(buf)
        }
        /// Deserialize a value from a CBOR byte slice.
        ///
        /// # Errors
        /// TODO: Document errors
        pub fn from_slice<T>(slice: &[u8]) -> anyhow::Result<T>
        where
            T: DeserializeOwned,
        {
            ciborium::from_reader(Cursor::new(&slice))
                .map_err(|e| {
                    ::anyhow::__private::must_use({
                        use ::anyhow::__private::kind::*;
                        let error = match CoseError::DecodeFailed(
                            ciborium::de::Error::Semantic(None, e.to_string()),
                        ) {
                            error => (&error).anyhow_kind().new(error),
                        };
                        error
                    })
                })
        }
        /// Wrap types that require tagging with tag 24.
        pub struct Tag24<T>(pub T);
        #[automatically_derived]
        impl<T: ::core::fmt::Debug> ::core::fmt::Debug for Tag24<T> {
            #[inline]
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                ::core::fmt::Formatter::debug_tuple_field1_finish(f, "Tag24", &&self.0)
            }
        }
        #[automatically_derived]
        impl<T: ::core::clone::Clone> ::core::clone::Clone for Tag24<T> {
            #[inline]
            fn clone(&self) -> Tag24<T> {
                Tag24(::core::clone::Clone::clone(&self.0))
            }
        }
        #[automatically_derived]
        impl<T> ::core::marker::StructuralPartialEq for Tag24<T> {}
        #[automatically_derived]
        impl<T: ::core::cmp::PartialEq> ::core::cmp::PartialEq for Tag24<T> {
            #[inline]
            fn eq(&self, other: &Tag24<T>) -> bool {
                self.0 == other.0
            }
        }
        #[automatically_derived]
        impl<T: ::core::cmp::Eq> ::core::cmp::Eq for Tag24<T> {
            #[inline]
            #[doc(hidden)]
            #[coverage(off)]
            fn assert_receiver_is_total_eq(&self) -> () {
                let _: ::core::cmp::AssertParamIsEq<T>;
            }
        }
        impl<T> Deref for Tag24<T> {
            type Target = T;
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }
        impl<T: Serialize> Tag24<T> {
            /// Serialize the inner value to a CBOR byte vector.
            ///
            /// # Errors
            /// TODO: Document errors
            pub fn to_vec(&self) -> anyhow::Result<Vec<u8>> {
                to_vec(&self.0)
            }
        }
        impl<T: DeserializeOwned> TryFrom<Value> for Tag24<T> {
            type Error = anyhow::Error;
            fn try_from(v: Value) -> anyhow::Result<Self> {
                match v.clone() {
                    Value::Tag(24, value) => {
                        match value.as_ref() {
                            Value::Bytes(bytes) => {
                                let inner: T = from_slice(bytes)?;
                                Ok(Self(inner))
                            }
                            _ => {
                                Err(
                                    ::anyhow::__private::must_use({
                                        let error = ::anyhow::__private::format_err(
                                            format_args!("invalid tag: {0:?}", value),
                                        );
                                        error
                                    }),
                                )
                            }
                        }
                    }
                    _ => {
                        Err(
                            ::anyhow::__private::must_use({
                                let error = ::anyhow::__private::format_err(
                                    format_args!("not a tag24: {0:?}", v),
                                );
                                error
                            }),
                        )
                    }
                }
            }
        }
        impl<T: Serialize> Serialize for Tag24<T> {
            fn serialize<S: Serializer>(&self, s: S) -> anyhow::Result<S::Ok, S::Error> {
                Value::Tag(24, Box::new(Value::Bytes(to_vec(&self.0).unwrap())))
                    .serialize(s)
            }
        }
        impl<'de, T: DeserializeOwned> Deserialize<'de> for Tag24<T> {
            fn deserialize<D>(deserializer: D) -> anyhow::Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = Value::deserialize(deserializer)?;
                value.try_into().map_err(de::Error::custom)
            }
        }
    }
    mod key {
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
        #[automatically_derived]
        #[allow(clippy::module_name_repetitions)]
        impl ::core::fmt::Debug for CoseKey {
            #[inline]
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                ::core::fmt::Formatter::debug_struct_field4_finish(
                    f,
                    "CoseKey",
                    "kty",
                    &self.kty,
                    "crv",
                    &self.crv,
                    "x",
                    &self.x,
                    "y",
                    &&self.y,
                )
            }
        }
        #[automatically_derived]
        #[allow(clippy::module_name_repetitions)]
        impl ::core::clone::Clone for CoseKey {
            #[inline]
            fn clone(&self) -> CoseKey {
                CoseKey {
                    kty: ::core::clone::Clone::clone(&self.kty),
                    crv: ::core::clone::Clone::clone(&self.crv),
                    x: ::core::clone::Clone::clone(&self.x),
                    y: ::core::clone::Clone::clone(&self.y),
                }
            }
        }
        #[automatically_derived]
        #[allow(clippy::module_name_repetitions)]
        impl ::core::default::Default for CoseKey {
            #[inline]
            fn default() -> CoseKey {
                CoseKey {
                    kty: ::core::default::Default::default(),
                    crv: ::core::default::Default::default(),
                    x: ::core::default::Default::default(),
                    y: ::core::default::Default::default(),
                }
            }
        }
        #[doc(hidden)]
        #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
        const _: () = {
            #[allow(unused_extern_crates, clippy::useless_attribute)]
            extern crate serde as _serde;
            #[automatically_derived]
            impl _serde::Serialize for CoseKey {
                fn serialize<__S>(
                    &self,
                    __serializer: __S,
                ) -> _serde::__private::Result<__S::Ok, __S::Error>
                where
                    __S: _serde::Serializer,
                {
                    _serde::Serialize::serialize(
                        &_serde::__private::Into::<
                            Value,
                        >::into(_serde::__private::Clone::clone(self)),
                        __serializer,
                    )
                }
            }
        };
        #[doc(hidden)]
        #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
        const _: () = {
            #[allow(unused_extern_crates, clippy::useless_attribute)]
            extern crate serde as _serde;
            #[automatically_derived]
            impl<'de> _serde::Deserialize<'de> for CoseKey {
                fn deserialize<__D>(
                    __deserializer: __D,
                ) -> _serde::__private::Result<Self, __D::Error>
                where
                    __D: _serde::Deserializer<'de>,
                {
                    _serde::__private::Result::and_then(
                        <Value as _serde::Deserialize>::deserialize(__deserializer),
                        |v| {
                            _serde::__private::TryFrom::try_from(v)
                                .map_err(_serde::de::Error::custom)
                        },
                    )
                }
            }
        };
        #[automatically_derived]
        #[allow(clippy::module_name_repetitions)]
        impl ::core::marker::StructuralPartialEq for CoseKey {}
        #[automatically_derived]
        #[allow(clippy::module_name_repetitions)]
        impl ::core::cmp::PartialEq for CoseKey {
            #[inline]
            fn eq(&self, other: &CoseKey) -> bool {
                self.kty == other.kty && self.crv == other.crv && self.x == other.x
                    && self.y == other.y
            }
        }
        #[automatically_derived]
        #[allow(clippy::module_name_repetitions)]
        impl ::core::cmp::Eq for CoseKey {
            #[inline]
            #[doc(hidden)]
            #[coverage(off)]
            fn assert_receiver_is_total_eq(&self) -> () {
                let _: ::core::cmp::AssertParamIsEq<KeyType>;
                let _: ::core::cmp::AssertParamIsEq<Curve>;
                let _: ::core::cmp::AssertParamIsEq<Vec<u8>>;
                let _: ::core::cmp::AssertParamIsEq<Option<Vec<u8>>>;
            }
        }
        /// Serialize `COSE_Key` to CBOR.
        impl From<CoseKey> for Value {
            fn from(key: CoseKey) -> Self {
                let cbor = match key.kty {
                    KeyType::Okp => {
                        <[_]>::into_vec(
                            #[rustc_box]
                            ::alloc::boxed::Box::new([
                                (KEY_TYPE.into(), KeyType::Okp.into()),
                                (CURVE.into(), { key.crv.into() }),
                                (X.into(), Self::Bytes(key.x)),
                            ]),
                        )
                    }
                    KeyType::Ec => {
                        <[_]>::into_vec(
                            #[rustc_box]
                            ::alloc::boxed::Box::new([
                                (KEY_TYPE.into(), KeyType::Ec.into()),
                                ((CURVE).into(), { key.crv.into() }),
                                (X.into(), Self::Bytes(key.x)),
                                (Y.into(), { key.y.unwrap_or_default().into() }),
                            ]),
                        )
                    }
                    KeyType::Oct => {
                        <[_]>::into_vec(
                            #[rustc_box]
                            ::alloc::boxed::Box::new([
                                (KEY_TYPE.into(), KeyType::Oct.into()),
                                (CURVE.into(), { key.crv.into() }),
                                (X.into(), Self::Bytes(key.x)),
                            ]),
                        )
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
                        (
                            Some(kty),
                            Some(crv),
                            Some(Value::Bytes(x)),
                        ) if kty == KeyType::Okp.into() => {
                            Ok(Self {
                                kty: KeyType::Okp,
                                crv: crv.into(),
                                x,
                                y: None,
                            })
                        }
                        (
                            Some(kty),
                            Some(Value::Integer(crv)),
                            Some(Value::Bytes(x)),
                        ) if kty == KeyType::Ec.into() => {
                            let crvi128: i128 = crv.into();
                            let y = map
                                .remove(&Integer::from(-3))
                                .ok_or_else(|| ::anyhow::__private::must_use({
                                    let error = ::anyhow::__private::format_err(
                                        format_args!("missing Y"),
                                    );
                                    error
                                }))?;
                            Ok(Self {
                                kty: KeyType::Ec,
                                crv: crvi128.try_into()?,
                                x,
                                y: y.as_bytes().cloned(),
                            })
                        }
                        _ => {
                            Err(
                                ::anyhow::__private::must_use({
                                    let error = ::anyhow::__private::format_err(
                                        format_args!("issue deserializing CoseKey"),
                                    );
                                    error
                                }),
                            )
                        }
                    }
                } else {
                    Err(
                        ::anyhow::__private::must_use({
                            let error = ::anyhow::__private::format_err(
                                format_args!("Value is not a map: {0:?}", v),
                            );
                            error
                        }),
                    )
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
        impl TryFrom<i128> for Curve {
            type Error = anyhow::Error;
            fn try_from(crv_id: i128) -> anyhow::Result<Self> {
                match crv_id {
                    6 => Ok(Self::Ed25519),
                    8 => Ok(Self::Es256K),
                    _ => {
                        Err(
                            ::anyhow::__private::must_use({
                                let error = ::anyhow::__private::format_err(
                                    format_args!("unsupported curve"),
                                );
                                error
                            }),
                        )
                    }
                }
            }
        }
    }
    pub use cbor::Tag24;
    #[allow(clippy::module_name_repetitions)]
    pub use key::CoseKey;
}
pub mod jose {
    //! # JSON Object Signing and Encryption (JOSE) Proofs
    //!
    //! [JOSE] proofs are enveloping proofs for Credentials based on JWT [RFC7519],
    //! JWS [RFC7515], and JWK [RFC7517].
    //!
    //! The Securing Verifiable Credentials using JOSE and COSE [VC-JOSE-COSE]
    //! recommendation defines a "bridge" between these and the Verifiable
    //! Credentials Data Model v2.0, specifying the suitable header claims, media
    //! types, etc.
    //!
    //! In the case of JOSE, the Credential is the "payload". This is preceded by a
    //! suitable header whose details are specified by Securing Verifiable
    //! Credentials using JOSE and COSE for the usage of JWT. These are encoded,
    //! concatenated, and signed, to be transferred in a compact form by one entity
    //! to an other (e.g., sent by the holder to the verifier). All the intricate
    //! details on signatures, encryption keys, etc., are defined by the IETF
    //! specifications; see Example 6 for a specific case.
    //!
    //! ## Note
    //!
    //! If the JWT is only a JWE, iss, exp and aud MUST be omitted in the JWT Claims
    //! Set of the JWE, and the processing rules as per JARM Section 2.4 related to
    //! these claims do not apply. [OpenID4VP] JWT - JWE
    //!
    //! ```json
    //! {
    //!   "vp_token": "eyJI...",
    //!   "presentation_submission": {...}
    //! }
    //! ```
    //!
    //! [JOSE]: https://datatracker.ietf.org/wg/jose/about
    //! [RFC7515]: https://www.rfc-editor.org/rfc/rfc7515
    //! [RFC7517]: https://www.rfc-editor.org/rfc/rfc7517
    //! [RFC7519]: https://www.rfc-editor.org/rfc/rfc7519
    //! [VC-JOSE-COSE]: https://w3c.github.io/vc-jose-cose
    //! [OpenID4VP]: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
    pub mod jwa {
        //! # JSON Web Algorithms (JWA)
        //!
        //! JWA [RFC7518] defines a set of cryptographic algorithms for use with
        //! JWS ([RFC7515]), JWE ([RFC7516]), and JWK ([RFC7517]).
        //!
        //! See associated [IANA] registries for more information
        //!
        //! [RFC7515]: https://www.rfc-editor.org/rfc/rfc7515
        //! [RFC7516]: https://www.rfc-editor.org/rfc/rfc7516
        //! [RFC7517]: https://www.rfc-editor.org/rfc/rfc7517
        //! [RFC7518]: https://www.rfc-editor.org/rfc/rfc7518
        //! [IANA]: https://www.iana.org/assignments/jose/jose.xhtml
        use std::fmt::{Debug, Display};
        use serde::{Deserialize, Serialize};
        /// Algorithm is used to specify the signing algorithm used by the signer.
        pub enum Algorithm {
            /// Algorithm for the secp256k1 curve
            #[serde(rename = "ES256K")]
            ES256K,
            /// Algorithm for the Ed25519 curve
            #[default]
            #[serde(rename = "EdDSA")]
            EdDSA,
        }
        #[automatically_derived]
        impl ::core::clone::Clone for Algorithm {
            #[inline]
            fn clone(&self) -> Algorithm {
                match self {
                    Algorithm::ES256K => Algorithm::ES256K,
                    Algorithm::EdDSA => Algorithm::EdDSA,
                }
            }
        }
        #[automatically_derived]
        impl ::core::fmt::Debug for Algorithm {
            #[inline]
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                ::core::fmt::Formatter::write_str(
                    f,
                    match self {
                        Algorithm::ES256K => "ES256K",
                        Algorithm::EdDSA => "EdDSA",
                    },
                )
            }
        }
        #[automatically_derived]
        impl ::core::default::Default for Algorithm {
            #[inline]
            fn default() -> Algorithm {
                Self::EdDSA
            }
        }
        #[doc(hidden)]
        #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
        const _: () = {
            #[allow(unused_extern_crates, clippy::useless_attribute)]
            extern crate serde as _serde;
            #[automatically_derived]
            impl<'de> _serde::Deserialize<'de> for Algorithm {
                fn deserialize<__D>(
                    __deserializer: __D,
                ) -> _serde::__private::Result<Self, __D::Error>
                where
                    __D: _serde::Deserializer<'de>,
                {
                    #[allow(non_camel_case_types)]
                    #[doc(hidden)]
                    enum __Field {
                        __field0,
                        __field1,
                    }
                    #[doc(hidden)]
                    struct __FieldVisitor;
                    impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                        type Value = __Field;
                        fn expecting(
                            &self,
                            __formatter: &mut _serde::__private::Formatter,
                        ) -> _serde::__private::fmt::Result {
                            _serde::__private::Formatter::write_str(
                                __formatter,
                                "variant identifier",
                            )
                        }
                        fn visit_u64<__E>(
                            self,
                            __value: u64,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                0u64 => _serde::__private::Ok(__Field::__field0),
                                1u64 => _serde::__private::Ok(__Field::__field1),
                                _ => {
                                    _serde::__private::Err(
                                        _serde::de::Error::invalid_value(
                                            _serde::de::Unexpected::Unsigned(__value),
                                            &"variant index 0 <= i < 2",
                                        ),
                                    )
                                }
                            }
                        }
                        fn visit_str<__E>(
                            self,
                            __value: &str,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                "ES256K" => _serde::__private::Ok(__Field::__field0),
                                "EdDSA" => _serde::__private::Ok(__Field::__field1),
                                _ => {
                                    _serde::__private::Err(
                                        _serde::de::Error::unknown_variant(__value, VARIANTS),
                                    )
                                }
                            }
                        }
                        fn visit_bytes<__E>(
                            self,
                            __value: &[u8],
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                b"ES256K" => _serde::__private::Ok(__Field::__field0),
                                b"EdDSA" => _serde::__private::Ok(__Field::__field1),
                                _ => {
                                    let __value = &_serde::__private::from_utf8_lossy(__value);
                                    _serde::__private::Err(
                                        _serde::de::Error::unknown_variant(__value, VARIANTS),
                                    )
                                }
                            }
                        }
                    }
                    impl<'de> _serde::Deserialize<'de> for __Field {
                        #[inline]
                        fn deserialize<__D>(
                            __deserializer: __D,
                        ) -> _serde::__private::Result<Self, __D::Error>
                        where
                            __D: _serde::Deserializer<'de>,
                        {
                            _serde::Deserializer::deserialize_identifier(
                                __deserializer,
                                __FieldVisitor,
                            )
                        }
                    }
                    #[doc(hidden)]
                    struct __Visitor<'de> {
                        marker: _serde::__private::PhantomData<Algorithm>,
                        lifetime: _serde::__private::PhantomData<&'de ()>,
                    }
                    impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                        type Value = Algorithm;
                        fn expecting(
                            &self,
                            __formatter: &mut _serde::__private::Formatter,
                        ) -> _serde::__private::fmt::Result {
                            _serde::__private::Formatter::write_str(
                                __formatter,
                                "enum Algorithm",
                            )
                        }
                        fn visit_enum<__A>(
                            self,
                            __data: __A,
                        ) -> _serde::__private::Result<Self::Value, __A::Error>
                        where
                            __A: _serde::de::EnumAccess<'de>,
                        {
                            match _serde::de::EnumAccess::variant(__data)? {
                                (__Field::__field0, __variant) => {
                                    _serde::de::VariantAccess::unit_variant(__variant)?;
                                    _serde::__private::Ok(Algorithm::ES256K)
                                }
                                (__Field::__field1, __variant) => {
                                    _serde::de::VariantAccess::unit_variant(__variant)?;
                                    _serde::__private::Ok(Algorithm::EdDSA)
                                }
                            }
                        }
                    }
                    #[doc(hidden)]
                    const VARIANTS: &'static [&'static str] = &["ES256K", "EdDSA"];
                    _serde::Deserializer::deserialize_enum(
                        __deserializer,
                        "Algorithm",
                        VARIANTS,
                        __Visitor {
                            marker: _serde::__private::PhantomData::<Algorithm>,
                            lifetime: _serde::__private::PhantomData,
                        },
                    )
                }
            }
        };
        #[doc(hidden)]
        #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
        const _: () = {
            #[allow(unused_extern_crates, clippy::useless_attribute)]
            extern crate serde as _serde;
            #[automatically_derived]
            impl _serde::Serialize for Algorithm {
                fn serialize<__S>(
                    &self,
                    __serializer: __S,
                ) -> _serde::__private::Result<__S::Ok, __S::Error>
                where
                    __S: _serde::Serializer,
                {
                    match *self {
                        Algorithm::ES256K => {
                            _serde::Serializer::serialize_unit_variant(
                                __serializer,
                                "Algorithm",
                                0u32,
                                "ES256K",
                            )
                        }
                        Algorithm::EdDSA => {
                            _serde::Serializer::serialize_unit_variant(
                                __serializer,
                                "Algorithm",
                                1u32,
                                "EdDSA",
                            )
                        }
                    }
                }
            }
        };
        #[automatically_derived]
        impl ::core::marker::StructuralPartialEq for Algorithm {}
        #[automatically_derived]
        impl ::core::cmp::PartialEq for Algorithm {
            #[inline]
            fn eq(&self, other: &Algorithm) -> bool {
                let __self_discr = ::core::intrinsics::discriminant_value(self);
                let __arg1_discr = ::core::intrinsics::discriminant_value(other);
                __self_discr == __arg1_discr
            }
        }
        #[automatically_derived]
        impl ::core::cmp::Eq for Algorithm {
            #[inline]
            #[doc(hidden)]
            #[coverage(off)]
            fn assert_receiver_is_total_eq(&self) -> () {}
        }
        impl Display for Algorithm {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_fmt(format_args!("{0:?}", self))
            }
        }
    }
    pub mod jwe {
        //! # JSON Web Encryption (JWE)
        //!
        //! JWE ([RFC7516]) specifies how encrypted content can be represented using
        //! JSON. See JWA ([RFC7518]) for more on the cyptographic algorithms and
        //! identifiers used.
        //!
        //! See also:
        //!
        //! - <https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms>
        //! - CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JOSE ([ECDH])
        //!
        //! ## Note
        //!
        //! If the JWT is only a JWE, iss, exp and aud MUST be omitted in the JWT Claims
        //! of the JWE, and the processing rules as per JARM Section 2.4 related to
        //! these claims do not apply. [OpenID4VP] JWT - JWE
        //!
        //! [RFC7516]: https://www.rfc-editor.org/rfc/rfc7516
        //! [RFC7518]: https://www.rfc-editor.org/rfc/rfc7518
        //! [IANA]: https://www.iana.org/assignments/jose/jose.xhtml
        //! [ECDH]: https://tools.ietf.org/html/rfc8037
        //! # Example
        //!
        //! Reference JSON for ECDH/A128GCM from specification
        //! (<https://www.rfc-editor.org/rfc/rfc7518#appendix-C>):
        //!
        //!```json
        //! {
        //!     "alg":"ECDH-ES",
        //!     "enc":"A128GCM",
        //!     "apu":"QWxpY2U",
        //!     "apv":"Qm9i",
        //!     "epk": {
        //!          "kty":"EC",
        //!          "crv":"P-256",
        //!          "x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
        //!          "y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"
        //!     }
        //! }
        //! ```
        use std::fmt::{self, Display};
        use std::str::FromStr;
        use aes_gcm::aead::KeyInit;
        use aes_gcm::{AeadInPlace, Aes128Gcm, Key, Nonce};
        use anyhow::anyhow;
        use base64ct::{Base64UrlUnpadded as Base64, Encoding};
        use crypto_box::aead::{AeadCore, OsRng};
        use crypto_box::Tag;
        use serde::de::DeserializeOwned;
        use serde::{Deserialize, Serialize};
        use serde_json::Value;
        use crate::jose::jwk::PublicKeyJwk;
        use crate::{Curve, Decryptor, Encryptor, KeyType};
        /// Encrypt plaintext and return a JWE.
        ///
        /// N.B. We currently only support ECDH-ES key agreement and A128GCM
        /// content encryption.
        ///
        /// # Errors
        ///
        /// Returns an error if the plaintext cannot be encrypted.
        pub async fn encrypt<T: Serialize + Send>(
            plaintext: T,
            recipient_key: &[u8; 32],
            encryptor: &impl Encryptor,
        ) -> anyhow::Result<String> {
            let cek = Aes128Gcm::generate_key(&mut OsRng);
            let encrypted_cek = encryptor.encrypt(&cek, recipient_key).await?;
            let iv = Aes128Gcm::generate_nonce(&mut OsRng);
            let header = Header {
                alg: CekAlgorithm::EcdhEs,
                enc: EncryptionAlgorithm::A128Gcm,
                apu: Base64::encode_string(b"Alice"),
                apv: Base64::encode_string(b"Bob"),
                epk: PublicKeyJwk {
                    kty: KeyType::Okp,
                    crv: Curve::Ed25519,
                    x: Base64::encode_string(&encryptor.public_key()),
                    ..PublicKeyJwk::default()
                },
            };
            let aad = &Base64::encode_string(&serde_json::to_vec(&header)?);
            let mut buffer = serde_json::to_vec(&plaintext)?;
            let tag = Aes128Gcm::new(&cek)
                .encrypt_in_place_detached(&iv, aad.as_bytes(), &mut buffer)
                .map_err(|e| ::anyhow::__private::must_use({
                    let error = ::anyhow::__private::format_err(
                        format_args!("issue encrypting: {0}", e),
                    );
                    error
                }))?;
            let jwe = Jwe {
                protected: header,
                encrypted_key: Base64::encode_string(&encrypted_cek),
                iv: Base64::encode_string(&iv),
                ciphertext: Base64::encode_string(&buffer),
                tag: Base64::encode_string(&tag),
                ..Jwe::default()
            };
            Ok(jwe.to_string())
        }
        /// Decrypt the JWE and return the plaintext.
        ///
        /// N.B. We currently only support ECDH-ES key agreement and A128GCM
        ///
        /// # Errors
        ///
        /// Returns an error if the JWE cannot be decrypted.
        pub async fn decrypt<T: DeserializeOwned>(
            compact_jwe: &str,
            decryptor: &impl Decryptor,
        ) -> anyhow::Result<T> {
            let jwe = Jwe::from_str(compact_jwe)?;
            let encrypted_cek = Base64::decode_vec(&jwe.encrypted_key)
                .map_err(|e| ::anyhow::__private::must_use({
                    let error = ::anyhow::__private::format_err(
                        format_args!("issue decoding `encrypted_key`: {0}", e),
                    );
                    error
                }))?;
            let iv = Base64::decode_vec(&jwe.iv)
                .map_err(|e| ::anyhow::__private::must_use({
                    let error = ::anyhow::__private::format_err(
                        format_args!("issue decoding `iv`: {0}", e),
                    );
                    error
                }))?;
            let ciphertext = Base64::decode_vec(&jwe.ciphertext)
                .map_err(|e| ::anyhow::__private::must_use({
                    let error = ::anyhow::__private::format_err(
                        format_args!("issue decoding `ciphertext`: {0}", e),
                    );
                    error
                }))?;
            let tag = Base64::decode_vec(&jwe.tag)
                .map_err(|e| ::anyhow::__private::must_use({
                    let error = ::anyhow::__private::format_err(
                        format_args!("issue decoding `tag`: {0}", e),
                    );
                    error
                }))?;
            let sender_key = Base64::decode_vec(&jwe.protected.epk.x)
                .map_err(|e| ::anyhow::__private::must_use({
                    let error = ::anyhow::__private::format_err(
                        format_args!("issue decoding sender public key `x`: {0}", e),
                    );
                    error
                }))?;
            let sender_key: &[u8; crypto_box::KEY_SIZE] = sender_key
                .as_slice()
                .try_into()?;
            let cek = decryptor.decrypt(&encrypted_cek, sender_key).await?;
            let aad = jwe.protected.to_string();
            let mut buffer = ciphertext;
            let nonce = Nonce::from_slice(&iv);
            let tag = Tag::from_slice(&tag);
            Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&cek))
                .decrypt_in_place_detached(nonce, aad.as_bytes(), &mut buffer, tag)
                .map_err(|e| ::anyhow::__private::must_use({
                    let error = ::anyhow::__private::format_err(
                        format_args!("issue decrypting: {0}", e),
                    );
                    error
                }))?;
            Ok(serde_json::from_slice(&buffer)?)
        }
        /// In JWE JSON serialization, one or more of the JWE Protected Header, JWE
        /// Shared Unprotected Header, and JWE Per-Recipient Unprotected Header MUST be
        /// present.
        ///
        /// In this case, the members of the JOSE Header are the union of the members of
        /// the JWE Protected Header, JWE Shared Unprotected Header, and JWE
        /// Per-Recipient Unprotected Header values that are present.
        pub struct Jwe {
            /// JWE protected header.
            protected: Header,
            /// Shared unprotected header as a JSON object.
            #[serde(skip_serializing_if = "Option::is_none")]
            unprotected: Option<Value>,
            /// Encrypted key, as a base64Url encoded string.
            encrypted_key: String,
            /// AAD value, base64url encoded. Not used for JWE Compact Serialization.
            #[serde(skip_serializing_if = "Option::is_none")]
            aad: Option<String>,
            /// Initialization vector (nonce), as a base64Url encoded string.
            iv: String,
            /// Ciphertext, as a base64Url encoded string.
            ciphertext: String,
            /// Authentication tag resulting from the encryption, as a base64Url encoded
            /// string.
            tag: String,
        }
        #[automatically_derived]
        impl ::core::clone::Clone for Jwe {
            #[inline]
            fn clone(&self) -> Jwe {
                Jwe {
                    protected: ::core::clone::Clone::clone(&self.protected),
                    unprotected: ::core::clone::Clone::clone(&self.unprotected),
                    encrypted_key: ::core::clone::Clone::clone(&self.encrypted_key),
                    aad: ::core::clone::Clone::clone(&self.aad),
                    iv: ::core::clone::Clone::clone(&self.iv),
                    ciphertext: ::core::clone::Clone::clone(&self.ciphertext),
                    tag: ::core::clone::Clone::clone(&self.tag),
                }
            }
        }
        #[automatically_derived]
        impl ::core::fmt::Debug for Jwe {
            #[inline]
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                let names: &'static _ = &[
                    "protected",
                    "unprotected",
                    "encrypted_key",
                    "aad",
                    "iv",
                    "ciphertext",
                    "tag",
                ];
                let values: &[&dyn ::core::fmt::Debug] = &[
                    &self.protected,
                    &self.unprotected,
                    &self.encrypted_key,
                    &self.aad,
                    &self.iv,
                    &self.ciphertext,
                    &&self.tag,
                ];
                ::core::fmt::Formatter::debug_struct_fields_finish(
                    f,
                    "Jwe",
                    names,
                    values,
                )
            }
        }
        #[automatically_derived]
        impl ::core::default::Default for Jwe {
            #[inline]
            fn default() -> Jwe {
                Jwe {
                    protected: ::core::default::Default::default(),
                    unprotected: ::core::default::Default::default(),
                    encrypted_key: ::core::default::Default::default(),
                    aad: ::core::default::Default::default(),
                    iv: ::core::default::Default::default(),
                    ciphertext: ::core::default::Default::default(),
                    tag: ::core::default::Default::default(),
                }
            }
        }
        #[doc(hidden)]
        #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
        const _: () = {
            #[allow(unused_extern_crates, clippy::useless_attribute)]
            extern crate serde as _serde;
            #[automatically_derived]
            impl _serde::Serialize for Jwe {
                fn serialize<__S>(
                    &self,
                    __serializer: __S,
                ) -> _serde::__private::Result<__S::Ok, __S::Error>
                where
                    __S: _serde::Serializer,
                {
                    let mut __serde_state = _serde::Serializer::serialize_struct(
                        __serializer,
                        "Jwe",
                        false as usize + 1
                            + if Option::is_none(&self.unprotected) { 0 } else { 1 } + 1
                            + if Option::is_none(&self.aad) { 0 } else { 1 } + 1 + 1 + 1,
                    )?;
                    _serde::ser::SerializeStruct::serialize_field(
                        &mut __serde_state,
                        "protected",
                        &self.protected,
                    )?;
                    if !Option::is_none(&self.unprotected) {
                        _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "unprotected",
                            &self.unprotected,
                        )?;
                    } else {
                        _serde::ser::SerializeStruct::skip_field(
                            &mut __serde_state,
                            "unprotected",
                        )?;
                    }
                    _serde::ser::SerializeStruct::serialize_field(
                        &mut __serde_state,
                        "encrypted_key",
                        &self.encrypted_key,
                    )?;
                    if !Option::is_none(&self.aad) {
                        _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "aad",
                            &self.aad,
                        )?;
                    } else {
                        _serde::ser::SerializeStruct::skip_field(
                            &mut __serde_state,
                            "aad",
                        )?;
                    }
                    _serde::ser::SerializeStruct::serialize_field(
                        &mut __serde_state,
                        "iv",
                        &self.iv,
                    )?;
                    _serde::ser::SerializeStruct::serialize_field(
                        &mut __serde_state,
                        "ciphertext",
                        &self.ciphertext,
                    )?;
                    _serde::ser::SerializeStruct::serialize_field(
                        &mut __serde_state,
                        "tag",
                        &self.tag,
                    )?;
                    _serde::ser::SerializeStruct::end(__serde_state)
                }
            }
        };
        #[doc(hidden)]
        #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
        const _: () = {
            #[allow(unused_extern_crates, clippy::useless_attribute)]
            extern crate serde as _serde;
            #[automatically_derived]
            impl<'de> _serde::Deserialize<'de> for Jwe {
                fn deserialize<__D>(
                    __deserializer: __D,
                ) -> _serde::__private::Result<Self, __D::Error>
                where
                    __D: _serde::Deserializer<'de>,
                {
                    #[allow(non_camel_case_types)]
                    #[doc(hidden)]
                    enum __Field {
                        __field0,
                        __field1,
                        __field2,
                        __field3,
                        __field4,
                        __field5,
                        __field6,
                        __ignore,
                    }
                    #[doc(hidden)]
                    struct __FieldVisitor;
                    impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                        type Value = __Field;
                        fn expecting(
                            &self,
                            __formatter: &mut _serde::__private::Formatter,
                        ) -> _serde::__private::fmt::Result {
                            _serde::__private::Formatter::write_str(
                                __formatter,
                                "field identifier",
                            )
                        }
                        fn visit_u64<__E>(
                            self,
                            __value: u64,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                0u64 => _serde::__private::Ok(__Field::__field0),
                                1u64 => _serde::__private::Ok(__Field::__field1),
                                2u64 => _serde::__private::Ok(__Field::__field2),
                                3u64 => _serde::__private::Ok(__Field::__field3),
                                4u64 => _serde::__private::Ok(__Field::__field4),
                                5u64 => _serde::__private::Ok(__Field::__field5),
                                6u64 => _serde::__private::Ok(__Field::__field6),
                                _ => _serde::__private::Ok(__Field::__ignore),
                            }
                        }
                        fn visit_str<__E>(
                            self,
                            __value: &str,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                "protected" => _serde::__private::Ok(__Field::__field0),
                                "unprotected" => _serde::__private::Ok(__Field::__field1),
                                "encrypted_key" => _serde::__private::Ok(__Field::__field2),
                                "aad" => _serde::__private::Ok(__Field::__field3),
                                "iv" => _serde::__private::Ok(__Field::__field4),
                                "ciphertext" => _serde::__private::Ok(__Field::__field5),
                                "tag" => _serde::__private::Ok(__Field::__field6),
                                _ => _serde::__private::Ok(__Field::__ignore),
                            }
                        }
                        fn visit_bytes<__E>(
                            self,
                            __value: &[u8],
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                b"protected" => _serde::__private::Ok(__Field::__field0),
                                b"unprotected" => _serde::__private::Ok(__Field::__field1),
                                b"encrypted_key" => _serde::__private::Ok(__Field::__field2),
                                b"aad" => _serde::__private::Ok(__Field::__field3),
                                b"iv" => _serde::__private::Ok(__Field::__field4),
                                b"ciphertext" => _serde::__private::Ok(__Field::__field5),
                                b"tag" => _serde::__private::Ok(__Field::__field6),
                                _ => _serde::__private::Ok(__Field::__ignore),
                            }
                        }
                    }
                    impl<'de> _serde::Deserialize<'de> for __Field {
                        #[inline]
                        fn deserialize<__D>(
                            __deserializer: __D,
                        ) -> _serde::__private::Result<Self, __D::Error>
                        where
                            __D: _serde::Deserializer<'de>,
                        {
                            _serde::Deserializer::deserialize_identifier(
                                __deserializer,
                                __FieldVisitor,
                            )
                        }
                    }
                    #[doc(hidden)]
                    struct __Visitor<'de> {
                        marker: _serde::__private::PhantomData<Jwe>,
                        lifetime: _serde::__private::PhantomData<&'de ()>,
                    }
                    impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                        type Value = Jwe;
                        fn expecting(
                            &self,
                            __formatter: &mut _serde::__private::Formatter,
                        ) -> _serde::__private::fmt::Result {
                            _serde::__private::Formatter::write_str(
                                __formatter,
                                "struct Jwe",
                            )
                        }
                        #[inline]
                        fn visit_seq<__A>(
                            self,
                            mut __seq: __A,
                        ) -> _serde::__private::Result<Self::Value, __A::Error>
                        where
                            __A: _serde::de::SeqAccess<'de>,
                        {
                            let __field0 = match _serde::de::SeqAccess::next_element::<
                                Header,
                            >(&mut __seq)? {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            0usize,
                                            &"struct Jwe with 7 elements",
                                        ),
                                    );
                                }
                            };
                            let __field1 = match _serde::de::SeqAccess::next_element::<
                                Option<Value>,
                            >(&mut __seq)? {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            1usize,
                                            &"struct Jwe with 7 elements",
                                        ),
                                    );
                                }
                            };
                            let __field2 = match _serde::de::SeqAccess::next_element::<
                                String,
                            >(&mut __seq)? {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            2usize,
                                            &"struct Jwe with 7 elements",
                                        ),
                                    );
                                }
                            };
                            let __field3 = match _serde::de::SeqAccess::next_element::<
                                Option<String>,
                            >(&mut __seq)? {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            3usize,
                                            &"struct Jwe with 7 elements",
                                        ),
                                    );
                                }
                            };
                            let __field4 = match _serde::de::SeqAccess::next_element::<
                                String,
                            >(&mut __seq)? {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            4usize,
                                            &"struct Jwe with 7 elements",
                                        ),
                                    );
                                }
                            };
                            let __field5 = match _serde::de::SeqAccess::next_element::<
                                String,
                            >(&mut __seq)? {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            5usize,
                                            &"struct Jwe with 7 elements",
                                        ),
                                    );
                                }
                            };
                            let __field6 = match _serde::de::SeqAccess::next_element::<
                                String,
                            >(&mut __seq)? {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            6usize,
                                            &"struct Jwe with 7 elements",
                                        ),
                                    );
                                }
                            };
                            _serde::__private::Ok(Jwe {
                                protected: __field0,
                                unprotected: __field1,
                                encrypted_key: __field2,
                                aad: __field3,
                                iv: __field4,
                                ciphertext: __field5,
                                tag: __field6,
                            })
                        }
                        #[inline]
                        fn visit_map<__A>(
                            self,
                            mut __map: __A,
                        ) -> _serde::__private::Result<Self::Value, __A::Error>
                        where
                            __A: _serde::de::MapAccess<'de>,
                        {
                            let mut __field0: _serde::__private::Option<Header> = _serde::__private::None;
                            let mut __field1: _serde::__private::Option<Option<Value>> = _serde::__private::None;
                            let mut __field2: _serde::__private::Option<String> = _serde::__private::None;
                            let mut __field3: _serde::__private::Option<
                                Option<String>,
                            > = _serde::__private::None;
                            let mut __field4: _serde::__private::Option<String> = _serde::__private::None;
                            let mut __field5: _serde::__private::Option<String> = _serde::__private::None;
                            let mut __field6: _serde::__private::Option<String> = _serde::__private::None;
                            while let _serde::__private::Some(__key) = _serde::de::MapAccess::next_key::<
                                __Field,
                            >(&mut __map)? {
                                match __key {
                                    __Field::__field0 => {
                                        if _serde::__private::Option::is_some(&__field0) {
                                            return _serde::__private::Err(
                                                <__A::Error as _serde::de::Error>::duplicate_field(
                                                    "protected",
                                                ),
                                            );
                                        }
                                        __field0 = _serde::__private::Some(
                                            _serde::de::MapAccess::next_value::<Header>(&mut __map)?,
                                        );
                                    }
                                    __Field::__field1 => {
                                        if _serde::__private::Option::is_some(&__field1) {
                                            return _serde::__private::Err(
                                                <__A::Error as _serde::de::Error>::duplicate_field(
                                                    "unprotected",
                                                ),
                                            );
                                        }
                                        __field1 = _serde::__private::Some(
                                            _serde::de::MapAccess::next_value::<
                                                Option<Value>,
                                            >(&mut __map)?,
                                        );
                                    }
                                    __Field::__field2 => {
                                        if _serde::__private::Option::is_some(&__field2) {
                                            return _serde::__private::Err(
                                                <__A::Error as _serde::de::Error>::duplicate_field(
                                                    "encrypted_key",
                                                ),
                                            );
                                        }
                                        __field2 = _serde::__private::Some(
                                            _serde::de::MapAccess::next_value::<String>(&mut __map)?,
                                        );
                                    }
                                    __Field::__field3 => {
                                        if _serde::__private::Option::is_some(&__field3) {
                                            return _serde::__private::Err(
                                                <__A::Error as _serde::de::Error>::duplicate_field("aad"),
                                            );
                                        }
                                        __field3 = _serde::__private::Some(
                                            _serde::de::MapAccess::next_value::<
                                                Option<String>,
                                            >(&mut __map)?,
                                        );
                                    }
                                    __Field::__field4 => {
                                        if _serde::__private::Option::is_some(&__field4) {
                                            return _serde::__private::Err(
                                                <__A::Error as _serde::de::Error>::duplicate_field("iv"),
                                            );
                                        }
                                        __field4 = _serde::__private::Some(
                                            _serde::de::MapAccess::next_value::<String>(&mut __map)?,
                                        );
                                    }
                                    __Field::__field5 => {
                                        if _serde::__private::Option::is_some(&__field5) {
                                            return _serde::__private::Err(
                                                <__A::Error as _serde::de::Error>::duplicate_field(
                                                    "ciphertext",
                                                ),
                                            );
                                        }
                                        __field5 = _serde::__private::Some(
                                            _serde::de::MapAccess::next_value::<String>(&mut __map)?,
                                        );
                                    }
                                    __Field::__field6 => {
                                        if _serde::__private::Option::is_some(&__field6) {
                                            return _serde::__private::Err(
                                                <__A::Error as _serde::de::Error>::duplicate_field("tag"),
                                            );
                                        }
                                        __field6 = _serde::__private::Some(
                                            _serde::de::MapAccess::next_value::<String>(&mut __map)?,
                                        );
                                    }
                                    _ => {
                                        let _ = _serde::de::MapAccess::next_value::<
                                            _serde::de::IgnoredAny,
                                        >(&mut __map)?;
                                    }
                                }
                            }
                            let __field0 = match __field0 {
                                _serde::__private::Some(__field0) => __field0,
                                _serde::__private::None => {
                                    _serde::__private::de::missing_field("protected")?
                                }
                            };
                            let __field1 = match __field1 {
                                _serde::__private::Some(__field1) => __field1,
                                _serde::__private::None => {
                                    _serde::__private::de::missing_field("unprotected")?
                                }
                            };
                            let __field2 = match __field2 {
                                _serde::__private::Some(__field2) => __field2,
                                _serde::__private::None => {
                                    _serde::__private::de::missing_field("encrypted_key")?
                                }
                            };
                            let __field3 = match __field3 {
                                _serde::__private::Some(__field3) => __field3,
                                _serde::__private::None => {
                                    _serde::__private::de::missing_field("aad")?
                                }
                            };
                            let __field4 = match __field4 {
                                _serde::__private::Some(__field4) => __field4,
                                _serde::__private::None => {
                                    _serde::__private::de::missing_field("iv")?
                                }
                            };
                            let __field5 = match __field5 {
                                _serde::__private::Some(__field5) => __field5,
                                _serde::__private::None => {
                                    _serde::__private::de::missing_field("ciphertext")?
                                }
                            };
                            let __field6 = match __field6 {
                                _serde::__private::Some(__field6) => __field6,
                                _serde::__private::None => {
                                    _serde::__private::de::missing_field("tag")?
                                }
                            };
                            _serde::__private::Ok(Jwe {
                                protected: __field0,
                                unprotected: __field1,
                                encrypted_key: __field2,
                                aad: __field3,
                                iv: __field4,
                                ciphertext: __field5,
                                tag: __field6,
                            })
                        }
                    }
                    #[doc(hidden)]
                    const FIELDS: &'static [&'static str] = &[
                        "protected",
                        "unprotected",
                        "encrypted_key",
                        "aad",
                        "iv",
                        "ciphertext",
                        "tag",
                    ];
                    _serde::Deserializer::deserialize_struct(
                        __deserializer,
                        "Jwe",
                        FIELDS,
                        __Visitor {
                            marker: _serde::__private::PhantomData::<Jwe>,
                            lifetime: _serde::__private::PhantomData,
                        },
                    )
                }
            }
        };
        #[automatically_derived]
        impl ::core::marker::StructuralPartialEq for Jwe {}
        #[automatically_derived]
        impl ::core::cmp::PartialEq for Jwe {
            #[inline]
            fn eq(&self, other: &Jwe) -> bool {
                self.protected == other.protected
                    && self.unprotected == other.unprotected
                    && self.encrypted_key == other.encrypted_key && self.aad == other.aad
                    && self.iv == other.iv && self.ciphertext == other.ciphertext
                    && self.tag == other.tag
            }
        }
        #[automatically_derived]
        impl ::core::cmp::Eq for Jwe {
            #[inline]
            #[doc(hidden)]
            #[coverage(off)]
            fn assert_receiver_is_total_eq(&self) -> () {
                let _: ::core::cmp::AssertParamIsEq<Header>;
                let _: ::core::cmp::AssertParamIsEq<Option<Value>>;
                let _: ::core::cmp::AssertParamIsEq<String>;
                let _: ::core::cmp::AssertParamIsEq<Option<String>>;
            }
        }
        /// Compact Serialization
        ///     base64(JWE Protected Header) + '.'
        ///     + base64(JWE Encrypted Key) + '.'
        ///     + base64(JWE Initialization Vector) + '.'
        ///     + base64(JWE Ciphertext) + '.'
        ///     + base64(JWE Authentication Tag)
        impl Display for Jwe {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                let protected = &self.protected.to_string();
                let encrypted_key = &self.encrypted_key;
                let iv = &self.iv;
                let ciphertext = &self.ciphertext;
                let tag = &self.tag;
                f.write_fmt(
                    format_args!(
                        "{0}.{1}.{2}.{3}.{4}",
                        protected,
                        encrypted_key,
                        iv,
                        ciphertext,
                        tag,
                    ),
                )
            }
        }
        impl FromStr for Jwe {
            type Err = anyhow::Error;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let parts: Vec<&str> = s.split('.').collect();
                if parts.len() != 5 {
                    return Err(
                        ::anyhow::__private::must_use({
                            let error = ::anyhow::__private::format_err(
                                format_args!("invalid JWE"),
                            );
                            error
                        }),
                    );
                }
                Ok(Self {
                    protected: Header::from_str(parts[0])?,
                    encrypted_key: parts[1].to_string(),
                    iv: parts[2].to_string(),
                    ciphertext: parts[3].to_string(),
                    tag: parts[4].to_string(),
                    ..Self::default()
                })
            }
        }
        /// Represents the JWE header.
        pub struct Header {
            /// Identifies the algorithm used to encrypt or determine the value of the
            /// content encryption key (CEK).
            pub alg: CekAlgorithm,
            /// The algorithm used to perform authenticated encryption on the plaintext
            /// to produce the ciphertext and the Authentication Tag. MUST be an AEAD
            /// algorithm.
            pub enc: EncryptionAlgorithm,
            /// Key agreement `PartyUInfo` value, used to generate the shared key.
            /// Contains producer information as a base64url string.
            pub apu: String,
            /// Key agreement `PartyVInfo` value, used to generate the shared key.
            /// Contains producer information as a base64url string.
            pub apv: String,
            /// The ephemeral public key created by the originator for use in key
            /// agreement algorithms.
            pub epk: PublicKeyJwk,
        }
        #[automatically_derived]
        impl ::core::clone::Clone for Header {
            #[inline]
            fn clone(&self) -> Header {
                Header {
                    alg: ::core::clone::Clone::clone(&self.alg),
                    enc: ::core::clone::Clone::clone(&self.enc),
                    apu: ::core::clone::Clone::clone(&self.apu),
                    apv: ::core::clone::Clone::clone(&self.apv),
                    epk: ::core::clone::Clone::clone(&self.epk),
                }
            }
        }
        #[automatically_derived]
        impl ::core::fmt::Debug for Header {
            #[inline]
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                ::core::fmt::Formatter::debug_struct_field5_finish(
                    f,
                    "Header",
                    "alg",
                    &self.alg,
                    "enc",
                    &self.enc,
                    "apu",
                    &self.apu,
                    "apv",
                    &self.apv,
                    "epk",
                    &&self.epk,
                )
            }
        }
        #[automatically_derived]
        impl ::core::default::Default for Header {
            #[inline]
            fn default() -> Header {
                Header {
                    alg: ::core::default::Default::default(),
                    enc: ::core::default::Default::default(),
                    apu: ::core::default::Default::default(),
                    apv: ::core::default::Default::default(),
                    epk: ::core::default::Default::default(),
                }
            }
        }
        #[doc(hidden)]
        #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
        const _: () = {
            #[allow(unused_extern_crates, clippy::useless_attribute)]
            extern crate serde as _serde;
            #[automatically_derived]
            impl<'de> _serde::Deserialize<'de> for Header {
                fn deserialize<__D>(
                    __deserializer: __D,
                ) -> _serde::__private::Result<Self, __D::Error>
                where
                    __D: _serde::Deserializer<'de>,
                {
                    #[allow(non_camel_case_types)]
                    #[doc(hidden)]
                    enum __Field {
                        __field0,
                        __field1,
                        __field2,
                        __field3,
                        __field4,
                        __ignore,
                    }
                    #[doc(hidden)]
                    struct __FieldVisitor;
                    impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                        type Value = __Field;
                        fn expecting(
                            &self,
                            __formatter: &mut _serde::__private::Formatter,
                        ) -> _serde::__private::fmt::Result {
                            _serde::__private::Formatter::write_str(
                                __formatter,
                                "field identifier",
                            )
                        }
                        fn visit_u64<__E>(
                            self,
                            __value: u64,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                0u64 => _serde::__private::Ok(__Field::__field0),
                                1u64 => _serde::__private::Ok(__Field::__field1),
                                2u64 => _serde::__private::Ok(__Field::__field2),
                                3u64 => _serde::__private::Ok(__Field::__field3),
                                4u64 => _serde::__private::Ok(__Field::__field4),
                                _ => _serde::__private::Ok(__Field::__ignore),
                            }
                        }
                        fn visit_str<__E>(
                            self,
                            __value: &str,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                "alg" => _serde::__private::Ok(__Field::__field0),
                                "enc" => _serde::__private::Ok(__Field::__field1),
                                "apu" => _serde::__private::Ok(__Field::__field2),
                                "apv" => _serde::__private::Ok(__Field::__field3),
                                "epk" => _serde::__private::Ok(__Field::__field4),
                                _ => _serde::__private::Ok(__Field::__ignore),
                            }
                        }
                        fn visit_bytes<__E>(
                            self,
                            __value: &[u8],
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                b"alg" => _serde::__private::Ok(__Field::__field0),
                                b"enc" => _serde::__private::Ok(__Field::__field1),
                                b"apu" => _serde::__private::Ok(__Field::__field2),
                                b"apv" => _serde::__private::Ok(__Field::__field3),
                                b"epk" => _serde::__private::Ok(__Field::__field4),
                                _ => _serde::__private::Ok(__Field::__ignore),
                            }
                        }
                    }
                    impl<'de> _serde::Deserialize<'de> for __Field {
                        #[inline]
                        fn deserialize<__D>(
                            __deserializer: __D,
                        ) -> _serde::__private::Result<Self, __D::Error>
                        where
                            __D: _serde::Deserializer<'de>,
                        {
                            _serde::Deserializer::deserialize_identifier(
                                __deserializer,
                                __FieldVisitor,
                            )
                        }
                    }
                    #[doc(hidden)]
                    struct __Visitor<'de> {
                        marker: _serde::__private::PhantomData<Header>,
                        lifetime: _serde::__private::PhantomData<&'de ()>,
                    }
                    impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                        type Value = Header;
                        fn expecting(
                            &self,
                            __formatter: &mut _serde::__private::Formatter,
                        ) -> _serde::__private::fmt::Result {
                            _serde::__private::Formatter::write_str(
                                __formatter,
                                "struct Header",
                            )
                        }
                        #[inline]
                        fn visit_seq<__A>(
                            self,
                            mut __seq: __A,
                        ) -> _serde::__private::Result<Self::Value, __A::Error>
                        where
                            __A: _serde::de::SeqAccess<'de>,
                        {
                            let __field0 = match _serde::de::SeqAccess::next_element::<
                                CekAlgorithm,
                            >(&mut __seq)? {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            0usize,
                                            &"struct Header with 5 elements",
                                        ),
                                    );
                                }
                            };
                            let __field1 = match _serde::de::SeqAccess::next_element::<
                                EncryptionAlgorithm,
                            >(&mut __seq)? {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            1usize,
                                            &"struct Header with 5 elements",
                                        ),
                                    );
                                }
                            };
                            let __field2 = match _serde::de::SeqAccess::next_element::<
                                String,
                            >(&mut __seq)? {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            2usize,
                                            &"struct Header with 5 elements",
                                        ),
                                    );
                                }
                            };
                            let __field3 = match _serde::de::SeqAccess::next_element::<
                                String,
                            >(&mut __seq)? {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            3usize,
                                            &"struct Header with 5 elements",
                                        ),
                                    );
                                }
                            };
                            let __field4 = match _serde::de::SeqAccess::next_element::<
                                PublicKeyJwk,
                            >(&mut __seq)? {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            4usize,
                                            &"struct Header with 5 elements",
                                        ),
                                    );
                                }
                            };
                            _serde::__private::Ok(Header {
                                alg: __field0,
                                enc: __field1,
                                apu: __field2,
                                apv: __field3,
                                epk: __field4,
                            })
                        }
                        #[inline]
                        fn visit_map<__A>(
                            self,
                            mut __map: __A,
                        ) -> _serde::__private::Result<Self::Value, __A::Error>
                        where
                            __A: _serde::de::MapAccess<'de>,
                        {
                            let mut __field0: _serde::__private::Option<CekAlgorithm> = _serde::__private::None;
                            let mut __field1: _serde::__private::Option<
                                EncryptionAlgorithm,
                            > = _serde::__private::None;
                            let mut __field2: _serde::__private::Option<String> = _serde::__private::None;
                            let mut __field3: _serde::__private::Option<String> = _serde::__private::None;
                            let mut __field4: _serde::__private::Option<PublicKeyJwk> = _serde::__private::None;
                            while let _serde::__private::Some(__key) = _serde::de::MapAccess::next_key::<
                                __Field,
                            >(&mut __map)? {
                                match __key {
                                    __Field::__field0 => {
                                        if _serde::__private::Option::is_some(&__field0) {
                                            return _serde::__private::Err(
                                                <__A::Error as _serde::de::Error>::duplicate_field("alg"),
                                            );
                                        }
                                        __field0 = _serde::__private::Some(
                                            _serde::de::MapAccess::next_value::<
                                                CekAlgorithm,
                                            >(&mut __map)?,
                                        );
                                    }
                                    __Field::__field1 => {
                                        if _serde::__private::Option::is_some(&__field1) {
                                            return _serde::__private::Err(
                                                <__A::Error as _serde::de::Error>::duplicate_field("enc"),
                                            );
                                        }
                                        __field1 = _serde::__private::Some(
                                            _serde::de::MapAccess::next_value::<
                                                EncryptionAlgorithm,
                                            >(&mut __map)?,
                                        );
                                    }
                                    __Field::__field2 => {
                                        if _serde::__private::Option::is_some(&__field2) {
                                            return _serde::__private::Err(
                                                <__A::Error as _serde::de::Error>::duplicate_field("apu"),
                                            );
                                        }
                                        __field2 = _serde::__private::Some(
                                            _serde::de::MapAccess::next_value::<String>(&mut __map)?,
                                        );
                                    }
                                    __Field::__field3 => {
                                        if _serde::__private::Option::is_some(&__field3) {
                                            return _serde::__private::Err(
                                                <__A::Error as _serde::de::Error>::duplicate_field("apv"),
                                            );
                                        }
                                        __field3 = _serde::__private::Some(
                                            _serde::de::MapAccess::next_value::<String>(&mut __map)?,
                                        );
                                    }
                                    __Field::__field4 => {
                                        if _serde::__private::Option::is_some(&__field4) {
                                            return _serde::__private::Err(
                                                <__A::Error as _serde::de::Error>::duplicate_field("epk"),
                                            );
                                        }
                                        __field4 = _serde::__private::Some(
                                            _serde::de::MapAccess::next_value::<
                                                PublicKeyJwk,
                                            >(&mut __map)?,
                                        );
                                    }
                                    _ => {
                                        let _ = _serde::de::MapAccess::next_value::<
                                            _serde::de::IgnoredAny,
                                        >(&mut __map)?;
                                    }
                                }
                            }
                            let __field0 = match __field0 {
                                _serde::__private::Some(__field0) => __field0,
                                _serde::__private::None => {
                                    _serde::__private::de::missing_field("alg")?
                                }
                            };
                            let __field1 = match __field1 {
                                _serde::__private::Some(__field1) => __field1,
                                _serde::__private::None => {
                                    _serde::__private::de::missing_field("enc")?
                                }
                            };
                            let __field2 = match __field2 {
                                _serde::__private::Some(__field2) => __field2,
                                _serde::__private::None => {
                                    _serde::__private::de::missing_field("apu")?
                                }
                            };
                            let __field3 = match __field3 {
                                _serde::__private::Some(__field3) => __field3,
                                _serde::__private::None => {
                                    _serde::__private::de::missing_field("apv")?
                                }
                            };
                            let __field4 = match __field4 {
                                _serde::__private::Some(__field4) => __field4,
                                _serde::__private::None => {
                                    _serde::__private::de::missing_field("epk")?
                                }
                            };
                            _serde::__private::Ok(Header {
                                alg: __field0,
                                enc: __field1,
                                apu: __field2,
                                apv: __field3,
                                epk: __field4,
                            })
                        }
                    }
                    #[doc(hidden)]
                    const FIELDS: &'static [&'static str] = &[
                        "alg",
                        "enc",
                        "apu",
                        "apv",
                        "epk",
                    ];
                    _serde::Deserializer::deserialize_struct(
                        __deserializer,
                        "Header",
                        FIELDS,
                        __Visitor {
                            marker: _serde::__private::PhantomData::<Header>,
                            lifetime: _serde::__private::PhantomData,
                        },
                    )
                }
            }
        };
        #[doc(hidden)]
        #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
        const _: () = {
            #[allow(unused_extern_crates, clippy::useless_attribute)]
            extern crate serde as _serde;
            #[automatically_derived]
            impl _serde::Serialize for Header {
                fn serialize<__S>(
                    &self,
                    __serializer: __S,
                ) -> _serde::__private::Result<__S::Ok, __S::Error>
                where
                    __S: _serde::Serializer,
                {
                    let mut __serde_state = _serde::Serializer::serialize_struct(
                        __serializer,
                        "Header",
                        false as usize + 1 + 1 + 1 + 1 + 1,
                    )?;
                    _serde::ser::SerializeStruct::serialize_field(
                        &mut __serde_state,
                        "alg",
                        &self.alg,
                    )?;
                    _serde::ser::SerializeStruct::serialize_field(
                        &mut __serde_state,
                        "enc",
                        &self.enc,
                    )?;
                    _serde::ser::SerializeStruct::serialize_field(
                        &mut __serde_state,
                        "apu",
                        &self.apu,
                    )?;
                    _serde::ser::SerializeStruct::serialize_field(
                        &mut __serde_state,
                        "apv",
                        &self.apv,
                    )?;
                    _serde::ser::SerializeStruct::serialize_field(
                        &mut __serde_state,
                        "epk",
                        &self.epk,
                    )?;
                    _serde::ser::SerializeStruct::end(__serde_state)
                }
            }
        };
        #[automatically_derived]
        impl ::core::marker::StructuralPartialEq for Header {}
        #[automatically_derived]
        impl ::core::cmp::PartialEq for Header {
            #[inline]
            fn eq(&self, other: &Header) -> bool {
                self.alg == other.alg && self.enc == other.enc && self.apu == other.apu
                    && self.apv == other.apv && self.epk == other.epk
            }
        }
        #[automatically_derived]
        impl ::core::cmp::Eq for Header {
            #[inline]
            #[doc(hidden)]
            #[coverage(off)]
            fn assert_receiver_is_total_eq(&self) -> () {
                let _: ::core::cmp::AssertParamIsEq<CekAlgorithm>;
                let _: ::core::cmp::AssertParamIsEq<EncryptionAlgorithm>;
                let _: ::core::cmp::AssertParamIsEq<String>;
                let _: ::core::cmp::AssertParamIsEq<PublicKeyJwk>;
            }
        }
        /// Serialize Header to base64 encoded string
        impl Display for Header {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                let bytes = serde_json::to_vec(&self).map_err(|_| fmt::Error)?;
                f.write_fmt(format_args!("{0}", Base64::encode_string(&bytes)))
            }
        }
        impl FromStr for Header {
            type Err = anyhow::Error;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let bytes = Base64::decode_vec(s)
                    .map_err(|e| ::anyhow::__private::must_use({
                        let error = ::anyhow::__private::format_err(
                            format_args!("issue decoding header: {0}", e),
                        );
                        error
                    }))?;
                serde_json::from_slice(&bytes)
                    .map_err(|e| ::anyhow::__private::must_use({
                        let error = ::anyhow::__private::format_err(
                            format_args!("issue deserializing header: {0}", e),
                        );
                        error
                    }))
            }
        }
        /// Contains information specific to a single recipient.
        /// MUST be present with exactly one array element per recipient, even if some
        /// or all of the array element values are the empty JSON object "{}".
        pub struct Recipient {
            /// JWE Per-Recipient Unprotected Header.
            #[serde(skip_serializing_if = "Option::is_none")]
            header: Option<Header>,
            /// The recipient's JWE Encrypted Key, as a base64Url encoded string.
            #[serde(skip_serializing_if = "Option::is_none")]
            encrypted_key: Option<String>,
        }
        #[automatically_derived]
        impl ::core::clone::Clone for Recipient {
            #[inline]
            fn clone(&self) -> Recipient {
                Recipient {
                    header: ::core::clone::Clone::clone(&self.header),
                    encrypted_key: ::core::clone::Clone::clone(&self.encrypted_key),
                }
            }
        }
        #[automatically_derived]
        impl ::core::fmt::Debug for Recipient {
            #[inline]
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                ::core::fmt::Formatter::debug_struct_field2_finish(
                    f,
                    "Recipient",
                    "header",
                    &self.header,
                    "encrypted_key",
                    &&self.encrypted_key,
                )
            }
        }
        #[automatically_derived]
        impl ::core::default::Default for Recipient {
            #[inline]
            fn default() -> Recipient {
                Recipient {
                    header: ::core::default::Default::default(),
                    encrypted_key: ::core::default::Default::default(),
                }
            }
        }
        #[doc(hidden)]
        #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
        const _: () = {
            #[allow(unused_extern_crates, clippy::useless_attribute)]
            extern crate serde as _serde;
            #[automatically_derived]
            impl<'de> _serde::Deserialize<'de> for Recipient {
                fn deserialize<__D>(
                    __deserializer: __D,
                ) -> _serde::__private::Result<Self, __D::Error>
                where
                    __D: _serde::Deserializer<'de>,
                {
                    #[allow(non_camel_case_types)]
                    #[doc(hidden)]
                    enum __Field {
                        __field0,
                        __field1,
                        __ignore,
                    }
                    #[doc(hidden)]
                    struct __FieldVisitor;
                    impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                        type Value = __Field;
                        fn expecting(
                            &self,
                            __formatter: &mut _serde::__private::Formatter,
                        ) -> _serde::__private::fmt::Result {
                            _serde::__private::Formatter::write_str(
                                __formatter,
                                "field identifier",
                            )
                        }
                        fn visit_u64<__E>(
                            self,
                            __value: u64,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                0u64 => _serde::__private::Ok(__Field::__field0),
                                1u64 => _serde::__private::Ok(__Field::__field1),
                                _ => _serde::__private::Ok(__Field::__ignore),
                            }
                        }
                        fn visit_str<__E>(
                            self,
                            __value: &str,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                "header" => _serde::__private::Ok(__Field::__field0),
                                "encrypted_key" => _serde::__private::Ok(__Field::__field1),
                                _ => _serde::__private::Ok(__Field::__ignore),
                            }
                        }
                        fn visit_bytes<__E>(
                            self,
                            __value: &[u8],
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                b"header" => _serde::__private::Ok(__Field::__field0),
                                b"encrypted_key" => _serde::__private::Ok(__Field::__field1),
                                _ => _serde::__private::Ok(__Field::__ignore),
                            }
                        }
                    }
                    impl<'de> _serde::Deserialize<'de> for __Field {
                        #[inline]
                        fn deserialize<__D>(
                            __deserializer: __D,
                        ) -> _serde::__private::Result<Self, __D::Error>
                        where
                            __D: _serde::Deserializer<'de>,
                        {
                            _serde::Deserializer::deserialize_identifier(
                                __deserializer,
                                __FieldVisitor,
                            )
                        }
                    }
                    #[doc(hidden)]
                    struct __Visitor<'de> {
                        marker: _serde::__private::PhantomData<Recipient>,
                        lifetime: _serde::__private::PhantomData<&'de ()>,
                    }
                    impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                        type Value = Recipient;
                        fn expecting(
                            &self,
                            __formatter: &mut _serde::__private::Formatter,
                        ) -> _serde::__private::fmt::Result {
                            _serde::__private::Formatter::write_str(
                                __formatter,
                                "struct Recipient",
                            )
                        }
                        #[inline]
                        fn visit_seq<__A>(
                            self,
                            mut __seq: __A,
                        ) -> _serde::__private::Result<Self::Value, __A::Error>
                        where
                            __A: _serde::de::SeqAccess<'de>,
                        {
                            let __field0 = match _serde::de::SeqAccess::next_element::<
                                Option<Header>,
                            >(&mut __seq)? {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            0usize,
                                            &"struct Recipient with 2 elements",
                                        ),
                                    );
                                }
                            };
                            let __field1 = match _serde::de::SeqAccess::next_element::<
                                Option<String>,
                            >(&mut __seq)? {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            1usize,
                                            &"struct Recipient with 2 elements",
                                        ),
                                    );
                                }
                            };
                            _serde::__private::Ok(Recipient {
                                header: __field0,
                                encrypted_key: __field1,
                            })
                        }
                        #[inline]
                        fn visit_map<__A>(
                            self,
                            mut __map: __A,
                        ) -> _serde::__private::Result<Self::Value, __A::Error>
                        where
                            __A: _serde::de::MapAccess<'de>,
                        {
                            let mut __field0: _serde::__private::Option<
                                Option<Header>,
                            > = _serde::__private::None;
                            let mut __field1: _serde::__private::Option<
                                Option<String>,
                            > = _serde::__private::None;
                            while let _serde::__private::Some(__key) = _serde::de::MapAccess::next_key::<
                                __Field,
                            >(&mut __map)? {
                                match __key {
                                    __Field::__field0 => {
                                        if _serde::__private::Option::is_some(&__field0) {
                                            return _serde::__private::Err(
                                                <__A::Error as _serde::de::Error>::duplicate_field("header"),
                                            );
                                        }
                                        __field0 = _serde::__private::Some(
                                            _serde::de::MapAccess::next_value::<
                                                Option<Header>,
                                            >(&mut __map)?,
                                        );
                                    }
                                    __Field::__field1 => {
                                        if _serde::__private::Option::is_some(&__field1) {
                                            return _serde::__private::Err(
                                                <__A::Error as _serde::de::Error>::duplicate_field(
                                                    "encrypted_key",
                                                ),
                                            );
                                        }
                                        __field1 = _serde::__private::Some(
                                            _serde::de::MapAccess::next_value::<
                                                Option<String>,
                                            >(&mut __map)?,
                                        );
                                    }
                                    _ => {
                                        let _ = _serde::de::MapAccess::next_value::<
                                            _serde::de::IgnoredAny,
                                        >(&mut __map)?;
                                    }
                                }
                            }
                            let __field0 = match __field0 {
                                _serde::__private::Some(__field0) => __field0,
                                _serde::__private::None => {
                                    _serde::__private::de::missing_field("header")?
                                }
                            };
                            let __field1 = match __field1 {
                                _serde::__private::Some(__field1) => __field1,
                                _serde::__private::None => {
                                    _serde::__private::de::missing_field("encrypted_key")?
                                }
                            };
                            _serde::__private::Ok(Recipient {
                                header: __field0,
                                encrypted_key: __field1,
                            })
                        }
                    }
                    #[doc(hidden)]
                    const FIELDS: &'static [&'static str] = &["header", "encrypted_key"];
                    _serde::Deserializer::deserialize_struct(
                        __deserializer,
                        "Recipient",
                        FIELDS,
                        __Visitor {
                            marker: _serde::__private::PhantomData::<Recipient>,
                            lifetime: _serde::__private::PhantomData,
                        },
                    )
                }
            }
        };
        #[doc(hidden)]
        #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
        const _: () = {
            #[allow(unused_extern_crates, clippy::useless_attribute)]
            extern crate serde as _serde;
            #[automatically_derived]
            impl _serde::Serialize for Recipient {
                fn serialize<__S>(
                    &self,
                    __serializer: __S,
                ) -> _serde::__private::Result<__S::Ok, __S::Error>
                where
                    __S: _serde::Serializer,
                {
                    let mut __serde_state = _serde::Serializer::serialize_struct(
                        __serializer,
                        "Recipient",
                        false as usize
                            + if Option::is_none(&self.header) { 0 } else { 1 }
                            + if Option::is_none(&self.encrypted_key) { 0 } else { 1 },
                    )?;
                    if !Option::is_none(&self.header) {
                        _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "header",
                            &self.header,
                        )?;
                    } else {
                        _serde::ser::SerializeStruct::skip_field(
                            &mut __serde_state,
                            "header",
                        )?;
                    }
                    if !Option::is_none(&self.encrypted_key) {
                        _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "encrypted_key",
                            &self.encrypted_key,
                        )?;
                    } else {
                        _serde::ser::SerializeStruct::skip_field(
                            &mut __serde_state,
                            "encrypted_key",
                        )?;
                    }
                    _serde::ser::SerializeStruct::end(__serde_state)
                }
            }
        };
        #[automatically_derived]
        impl ::core::marker::StructuralPartialEq for Recipient {}
        #[automatically_derived]
        impl ::core::cmp::PartialEq for Recipient {
            #[inline]
            fn eq(&self, other: &Recipient) -> bool {
                self.header == other.header && self.encrypted_key == other.encrypted_key
            }
        }
        #[automatically_derived]
        impl ::core::cmp::Eq for Recipient {
            #[inline]
            #[doc(hidden)]
            #[coverage(off)]
            fn assert_receiver_is_total_eq(&self) -> () {
                let _: ::core::cmp::AssertParamIsEq<Option<Header>>;
                let _: ::core::cmp::AssertParamIsEq<Option<String>>;
            }
        }
        /// The algorithm used to encrypt or determine the value of the content
        /// encryption key (CEK).
        pub enum CekAlgorithm {
            /// Elliptic Curve Diffie-Hellman Ephemeral-Static key agreement
            /// (using Concat KDF).
            #[default]
            #[serde(rename = "ECDH-ES")]
            EcdhEs,
        }
        #[automatically_derived]
        impl ::core::clone::Clone for CekAlgorithm {
            #[inline]
            fn clone(&self) -> CekAlgorithm {
                CekAlgorithm::EcdhEs
            }
        }
        #[automatically_derived]
        impl ::core::fmt::Debug for CekAlgorithm {
            #[inline]
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                ::core::fmt::Formatter::write_str(f, "EcdhEs")
            }
        }
        #[automatically_derived]
        impl ::core::default::Default for CekAlgorithm {
            #[inline]
            fn default() -> CekAlgorithm {
                Self::EcdhEs
            }
        }
        #[doc(hidden)]
        #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
        const _: () = {
            #[allow(unused_extern_crates, clippy::useless_attribute)]
            extern crate serde as _serde;
            #[automatically_derived]
            impl<'de> _serde::Deserialize<'de> for CekAlgorithm {
                fn deserialize<__D>(
                    __deserializer: __D,
                ) -> _serde::__private::Result<Self, __D::Error>
                where
                    __D: _serde::Deserializer<'de>,
                {
                    #[allow(non_camel_case_types)]
                    #[doc(hidden)]
                    enum __Field {
                        __field0,
                    }
                    #[doc(hidden)]
                    struct __FieldVisitor;
                    impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                        type Value = __Field;
                        fn expecting(
                            &self,
                            __formatter: &mut _serde::__private::Formatter,
                        ) -> _serde::__private::fmt::Result {
                            _serde::__private::Formatter::write_str(
                                __formatter,
                                "variant identifier",
                            )
                        }
                        fn visit_u64<__E>(
                            self,
                            __value: u64,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                0u64 => _serde::__private::Ok(__Field::__field0),
                                _ => {
                                    _serde::__private::Err(
                                        _serde::de::Error::invalid_value(
                                            _serde::de::Unexpected::Unsigned(__value),
                                            &"variant index 0 <= i < 1",
                                        ),
                                    )
                                }
                            }
                        }
                        fn visit_str<__E>(
                            self,
                            __value: &str,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                "ECDH-ES" => _serde::__private::Ok(__Field::__field0),
                                _ => {
                                    _serde::__private::Err(
                                        _serde::de::Error::unknown_variant(__value, VARIANTS),
                                    )
                                }
                            }
                        }
                        fn visit_bytes<__E>(
                            self,
                            __value: &[u8],
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                b"ECDH-ES" => _serde::__private::Ok(__Field::__field0),
                                _ => {
                                    let __value = &_serde::__private::from_utf8_lossy(__value);
                                    _serde::__private::Err(
                                        _serde::de::Error::unknown_variant(__value, VARIANTS),
                                    )
                                }
                            }
                        }
                    }
                    impl<'de> _serde::Deserialize<'de> for __Field {
                        #[inline]
                        fn deserialize<__D>(
                            __deserializer: __D,
                        ) -> _serde::__private::Result<Self, __D::Error>
                        where
                            __D: _serde::Deserializer<'de>,
                        {
                            _serde::Deserializer::deserialize_identifier(
                                __deserializer,
                                __FieldVisitor,
                            )
                        }
                    }
                    #[doc(hidden)]
                    struct __Visitor<'de> {
                        marker: _serde::__private::PhantomData<CekAlgorithm>,
                        lifetime: _serde::__private::PhantomData<&'de ()>,
                    }
                    impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                        type Value = CekAlgorithm;
                        fn expecting(
                            &self,
                            __formatter: &mut _serde::__private::Formatter,
                        ) -> _serde::__private::fmt::Result {
                            _serde::__private::Formatter::write_str(
                                __formatter,
                                "enum CekAlgorithm",
                            )
                        }
                        fn visit_enum<__A>(
                            self,
                            __data: __A,
                        ) -> _serde::__private::Result<Self::Value, __A::Error>
                        where
                            __A: _serde::de::EnumAccess<'de>,
                        {
                            match _serde::de::EnumAccess::variant(__data)? {
                                (__Field::__field0, __variant) => {
                                    _serde::de::VariantAccess::unit_variant(__variant)?;
                                    _serde::__private::Ok(CekAlgorithm::EcdhEs)
                                }
                            }
                        }
                    }
                    #[doc(hidden)]
                    const VARIANTS: &'static [&'static str] = &["ECDH-ES"];
                    _serde::Deserializer::deserialize_enum(
                        __deserializer,
                        "CekAlgorithm",
                        VARIANTS,
                        __Visitor {
                            marker: _serde::__private::PhantomData::<CekAlgorithm>,
                            lifetime: _serde::__private::PhantomData,
                        },
                    )
                }
            }
        };
        #[doc(hidden)]
        #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
        const _: () = {
            #[allow(unused_extern_crates, clippy::useless_attribute)]
            extern crate serde as _serde;
            #[automatically_derived]
            impl _serde::Serialize for CekAlgorithm {
                fn serialize<__S>(
                    &self,
                    __serializer: __S,
                ) -> _serde::__private::Result<__S::Ok, __S::Error>
                where
                    __S: _serde::Serializer,
                {
                    match *self {
                        CekAlgorithm::EcdhEs => {
                            _serde::Serializer::serialize_unit_variant(
                                __serializer,
                                "CekAlgorithm",
                                0u32,
                                "ECDH-ES",
                            )
                        }
                    }
                }
            }
        };
        #[automatically_derived]
        impl ::core::marker::StructuralPartialEq for CekAlgorithm {}
        #[automatically_derived]
        impl ::core::cmp::PartialEq for CekAlgorithm {
            #[inline]
            fn eq(&self, other: &CekAlgorithm) -> bool {
                true
            }
        }
        #[automatically_derived]
        impl ::core::cmp::Eq for CekAlgorithm {
            #[inline]
            #[doc(hidden)]
            #[coverage(off)]
            fn assert_receiver_is_total_eq(&self) -> () {}
        }
        /// The algorithm used to perform authenticated encryption on the plaintext to
        /// produce the ciphertext and the Authentication Tag. MUST be an AEAD
        /// algorithm.
        pub enum EncryptionAlgorithm {
            /// AES in Galois/Counter Mode (GCM) using a 128-bit key.
            #[default]
            #[serde(rename = "A128GCM")]
            A128Gcm,
        }
        #[automatically_derived]
        impl ::core::clone::Clone for EncryptionAlgorithm {
            #[inline]
            fn clone(&self) -> EncryptionAlgorithm {
                EncryptionAlgorithm::A128Gcm
            }
        }
        #[automatically_derived]
        impl ::core::fmt::Debug for EncryptionAlgorithm {
            #[inline]
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                ::core::fmt::Formatter::write_str(f, "A128Gcm")
            }
        }
        #[automatically_derived]
        impl ::core::default::Default for EncryptionAlgorithm {
            #[inline]
            fn default() -> EncryptionAlgorithm {
                Self::A128Gcm
            }
        }
        #[doc(hidden)]
        #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
        const _: () = {
            #[allow(unused_extern_crates, clippy::useless_attribute)]
            extern crate serde as _serde;
            #[automatically_derived]
            impl<'de> _serde::Deserialize<'de> for EncryptionAlgorithm {
                fn deserialize<__D>(
                    __deserializer: __D,
                ) -> _serde::__private::Result<Self, __D::Error>
                where
                    __D: _serde::Deserializer<'de>,
                {
                    #[allow(non_camel_case_types)]
                    #[doc(hidden)]
                    enum __Field {
                        __field0,
                    }
                    #[doc(hidden)]
                    struct __FieldVisitor;
                    impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                        type Value = __Field;
                        fn expecting(
                            &self,
                            __formatter: &mut _serde::__private::Formatter,
                        ) -> _serde::__private::fmt::Result {
                            _serde::__private::Formatter::write_str(
                                __formatter,
                                "variant identifier",
                            )
                        }
                        fn visit_u64<__E>(
                            self,
                            __value: u64,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                0u64 => _serde::__private::Ok(__Field::__field0),
                                _ => {
                                    _serde::__private::Err(
                                        _serde::de::Error::invalid_value(
                                            _serde::de::Unexpected::Unsigned(__value),
                                            &"variant index 0 <= i < 1",
                                        ),
                                    )
                                }
                            }
                        }
                        fn visit_str<__E>(
                            self,
                            __value: &str,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                "A128GCM" => _serde::__private::Ok(__Field::__field0),
                                _ => {
                                    _serde::__private::Err(
                                        _serde::de::Error::unknown_variant(__value, VARIANTS),
                                    )
                                }
                            }
                        }
                        fn visit_bytes<__E>(
                            self,
                            __value: &[u8],
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                b"A128GCM" => _serde::__private::Ok(__Field::__field0),
                                _ => {
                                    let __value = &_serde::__private::from_utf8_lossy(__value);
                                    _serde::__private::Err(
                                        _serde::de::Error::unknown_variant(__value, VARIANTS),
                                    )
                                }
                            }
                        }
                    }
                    impl<'de> _serde::Deserialize<'de> for __Field {
                        #[inline]
                        fn deserialize<__D>(
                            __deserializer: __D,
                        ) -> _serde::__private::Result<Self, __D::Error>
                        where
                            __D: _serde::Deserializer<'de>,
                        {
                            _serde::Deserializer::deserialize_identifier(
                                __deserializer,
                                __FieldVisitor,
                            )
                        }
                    }
                    #[doc(hidden)]
                    struct __Visitor<'de> {
                        marker: _serde::__private::PhantomData<EncryptionAlgorithm>,
                        lifetime: _serde::__private::PhantomData<&'de ()>,
                    }
                    impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                        type Value = EncryptionAlgorithm;
                        fn expecting(
                            &self,
                            __formatter: &mut _serde::__private::Formatter,
                        ) -> _serde::__private::fmt::Result {
                            _serde::__private::Formatter::write_str(
                                __formatter,
                                "enum EncryptionAlgorithm",
                            )
                        }
                        fn visit_enum<__A>(
                            self,
                            __data: __A,
                        ) -> _serde::__private::Result<Self::Value, __A::Error>
                        where
                            __A: _serde::de::EnumAccess<'de>,
                        {
                            match _serde::de::EnumAccess::variant(__data)? {
                                (__Field::__field0, __variant) => {
                                    _serde::de::VariantAccess::unit_variant(__variant)?;
                                    _serde::__private::Ok(EncryptionAlgorithm::A128Gcm)
                                }
                            }
                        }
                    }
                    #[doc(hidden)]
                    const VARIANTS: &'static [&'static str] = &["A128GCM"];
                    _serde::Deserializer::deserialize_enum(
                        __deserializer,
                        "EncryptionAlgorithm",
                        VARIANTS,
                        __Visitor {
                            marker: _serde::__private::PhantomData::<
                                EncryptionAlgorithm,
                            >,
                            lifetime: _serde::__private::PhantomData,
                        },
                    )
                }
            }
        };
        #[doc(hidden)]
        #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
        const _: () = {
            #[allow(unused_extern_crates, clippy::useless_attribute)]
            extern crate serde as _serde;
            #[automatically_derived]
            impl _serde::Serialize for EncryptionAlgorithm {
                fn serialize<__S>(
                    &self,
                    __serializer: __S,
                ) -> _serde::__private::Result<__S::Ok, __S::Error>
                where
                    __S: _serde::Serializer,
                {
                    match *self {
                        EncryptionAlgorithm::A128Gcm => {
                            _serde::Serializer::serialize_unit_variant(
                                __serializer,
                                "EncryptionAlgorithm",
                                0u32,
                                "A128GCM",
                            )
                        }
                    }
                }
            }
        };
        #[automatically_derived]
        impl ::core::marker::StructuralPartialEq for EncryptionAlgorithm {}
        #[automatically_derived]
        impl ::core::cmp::PartialEq for EncryptionAlgorithm {
            #[inline]
            fn eq(&self, other: &EncryptionAlgorithm) -> bool {
                true
            }
        }
        #[automatically_derived]
        impl ::core::cmp::Eq for EncryptionAlgorithm {
            #[inline]
            #[doc(hidden)]
            #[coverage(off)]
            fn assert_receiver_is_total_eq(&self) -> () {}
        }
    }
    pub mod jwk {
        //! # JSON Web Key (JWK)
        //!
        //! A JWK ([RFC7517]) is a JSON representation of a cryptographic key.
        //! Additionally, a JWK Set (JWKS) is used to represent a set of JWKs.
        //!
        //! See [RFC7517] for more detail.
        //!
        //! TODO:
        //! Support:
        //! (key) type: `EcdsaSecp256k1VerificationKey2019` | `JsonWebKey2020` |
        //!     `Ed25519VerificationKey2020` | `Ed25519VerificationKey2018` |
        //!     `X25519KeyAgreementKey2019`
        //! crv: `Ed25519` | `secp256k1` | `P-256` | `P-384` | `P-521`
        //!
        //! JWK Thumbprint [RFC7638]
        //! It is RECOMMENDED that JWK kid values are set to the public key fingerprint:
        //!  - create SHA-256 hash of UTF-8 representation of JSON from {crv,kty,x,y}
        //!
        //! For example:
        //!  - JSON: `{"crv":"Ed25519","kty":"OKP","x":"
        //!    11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
        //!  - SHA-256: `90facafea9b1556698540f70c0117a22ea37bd5cf3ed3c47093c1707282b4b89`
        //!  - base64url JWK Thumbprint: `kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k`
        //!
        //! [RFC7638]: https://www.rfc-editor.org/rfc/rfc7638
        //! [RFC7517]: https://www.rfc-editor.org/rfc/rfc7517
        use serde::{Deserialize, Serialize};
        use crate::jose::jwe::EncryptionAlgorithm;
        use crate::{Curve, KeyType, KeyUse};
        /// Simplified JSON Web Key (JWK) key structure.
        #[allow(clippy::module_name_repetitions)]
        pub struct PublicKeyJwk {
            /// Key identifier.
            /// For example, "_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A".
            #[serde(skip_serializing_if = "Option::is_none")]
            pub kid: Option<String>,
            /// Key type.
            pub kty: KeyType,
            /// Cryptographic curve type.
            pub crv: Curve,
            /// X coordinate.
            pub x: String,
            /// Y coordinate. Not required for `EdDSA` verification keys.
            #[serde(skip_serializing_if = "Option::is_none")]
            pub y: Option<String>,
            /// Algorithm intended for use with the key.
            #[serde(skip_serializing_if = "Option::is_none")]
            pub alg: Option<EncryptionAlgorithm>,
            /// Use of the key.
            #[serde(rename = "use")]
            #[serde(skip_serializing_if = "Option::is_none")]
            pub use_: Option<KeyUse>,
        }
        #[automatically_derived]
        #[allow(clippy::module_name_repetitions)]
        impl ::core::clone::Clone for PublicKeyJwk {
            #[inline]
            fn clone(&self) -> PublicKeyJwk {
                PublicKeyJwk {
                    kid: ::core::clone::Clone::clone(&self.kid),
                    kty: ::core::clone::Clone::clone(&self.kty),
                    crv: ::core::clone::Clone::clone(&self.crv),
                    x: ::core::clone::Clone::clone(&self.x),
                    y: ::core::clone::Clone::clone(&self.y),
                    alg: ::core::clone::Clone::clone(&self.alg),
                    use_: ::core::clone::Clone::clone(&self.use_),
                }
            }
        }
        #[automatically_derived]
        #[allow(clippy::module_name_repetitions)]
        impl ::core::fmt::Debug for PublicKeyJwk {
            #[inline]
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                let names: &'static _ = &["kid", "kty", "crv", "x", "y", "alg", "use_"];
                let values: &[&dyn ::core::fmt::Debug] = &[
                    &self.kid,
                    &self.kty,
                    &self.crv,
                    &self.x,
                    &self.y,
                    &self.alg,
                    &&self.use_,
                ];
                ::core::fmt::Formatter::debug_struct_fields_finish(
                    f,
                    "PublicKeyJwk",
                    names,
                    values,
                )
            }
        }
        #[automatically_derived]
        #[allow(clippy::module_name_repetitions)]
        impl ::core::default::Default for PublicKeyJwk {
            #[inline]
            fn default() -> PublicKeyJwk {
                PublicKeyJwk {
                    kid: ::core::default::Default::default(),
                    kty: ::core::default::Default::default(),
                    crv: ::core::default::Default::default(),
                    x: ::core::default::Default::default(),
                    y: ::core::default::Default::default(),
                    alg: ::core::default::Default::default(),
                    use_: ::core::default::Default::default(),
                }
            }
        }
        #[doc(hidden)]
        #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
        const _: () = {
            #[allow(unused_extern_crates, clippy::useless_attribute)]
            extern crate serde as _serde;
            #[automatically_derived]
            impl<'de> _serde::Deserialize<'de> for PublicKeyJwk {
                fn deserialize<__D>(
                    __deserializer: __D,
                ) -> _serde::__private::Result<Self, __D::Error>
                where
                    __D: _serde::Deserializer<'de>,
                {
                    #[allow(non_camel_case_types)]
                    #[doc(hidden)]
                    enum __Field {
                        __field0,
                        __field1,
                        __field2,
                        __field3,
                        __field4,
                        __field5,
                        __field6,
                        __ignore,
                    }
                    #[doc(hidden)]
                    struct __FieldVisitor;
                    impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                        type Value = __Field;
                        fn expecting(
                            &self,
                            __formatter: &mut _serde::__private::Formatter,
                        ) -> _serde::__private::fmt::Result {
                            _serde::__private::Formatter::write_str(
                                __formatter,
                                "field identifier",
                            )
                        }
                        fn visit_u64<__E>(
                            self,
                            __value: u64,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                0u64 => _serde::__private::Ok(__Field::__field0),
                                1u64 => _serde::__private::Ok(__Field::__field1),
                                2u64 => _serde::__private::Ok(__Field::__field2),
                                3u64 => _serde::__private::Ok(__Field::__field3),
                                4u64 => _serde::__private::Ok(__Field::__field4),
                                5u64 => _serde::__private::Ok(__Field::__field5),
                                6u64 => _serde::__private::Ok(__Field::__field6),
                                _ => _serde::__private::Ok(__Field::__ignore),
                            }
                        }
                        fn visit_str<__E>(
                            self,
                            __value: &str,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                "kid" => _serde::__private::Ok(__Field::__field0),
                                "kty" => _serde::__private::Ok(__Field::__field1),
                                "crv" => _serde::__private::Ok(__Field::__field2),
                                "x" => _serde::__private::Ok(__Field::__field3),
                                "y" => _serde::__private::Ok(__Field::__field4),
                                "alg" => _serde::__private::Ok(__Field::__field5),
                                "use" => _serde::__private::Ok(__Field::__field6),
                                _ => _serde::__private::Ok(__Field::__ignore),
                            }
                        }
                        fn visit_bytes<__E>(
                            self,
                            __value: &[u8],
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                b"kid" => _serde::__private::Ok(__Field::__field0),
                                b"kty" => _serde::__private::Ok(__Field::__field1),
                                b"crv" => _serde::__private::Ok(__Field::__field2),
                                b"x" => _serde::__private::Ok(__Field::__field3),
                                b"y" => _serde::__private::Ok(__Field::__field4),
                                b"alg" => _serde::__private::Ok(__Field::__field5),
                                b"use" => _serde::__private::Ok(__Field::__field6),
                                _ => _serde::__private::Ok(__Field::__ignore),
                            }
                        }
                    }
                    impl<'de> _serde::Deserialize<'de> for __Field {
                        #[inline]
                        fn deserialize<__D>(
                            __deserializer: __D,
                        ) -> _serde::__private::Result<Self, __D::Error>
                        where
                            __D: _serde::Deserializer<'de>,
                        {
                            _serde::Deserializer::deserialize_identifier(
                                __deserializer,
                                __FieldVisitor,
                            )
                        }
                    }
                    #[doc(hidden)]
                    struct __Visitor<'de> {
                        marker: _serde::__private::PhantomData<PublicKeyJwk>,
                        lifetime: _serde::__private::PhantomData<&'de ()>,
                    }
                    impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                        type Value = PublicKeyJwk;
                        fn expecting(
                            &self,
                            __formatter: &mut _serde::__private::Formatter,
                        ) -> _serde::__private::fmt::Result {
                            _serde::__private::Formatter::write_str(
                                __formatter,
                                "struct PublicKeyJwk",
                            )
                        }
                        #[inline]
                        fn visit_seq<__A>(
                            self,
                            mut __seq: __A,
                        ) -> _serde::__private::Result<Self::Value, __A::Error>
                        where
                            __A: _serde::de::SeqAccess<'de>,
                        {
                            let __field0 = match _serde::de::SeqAccess::next_element::<
                                Option<String>,
                            >(&mut __seq)? {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            0usize,
                                            &"struct PublicKeyJwk with 7 elements",
                                        ),
                                    );
                                }
                            };
                            let __field1 = match _serde::de::SeqAccess::next_element::<
                                KeyType,
                            >(&mut __seq)? {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            1usize,
                                            &"struct PublicKeyJwk with 7 elements",
                                        ),
                                    );
                                }
                            };
                            let __field2 = match _serde::de::SeqAccess::next_element::<
                                Curve,
                            >(&mut __seq)? {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            2usize,
                                            &"struct PublicKeyJwk with 7 elements",
                                        ),
                                    );
                                }
                            };
                            let __field3 = match _serde::de::SeqAccess::next_element::<
                                String,
                            >(&mut __seq)? {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            3usize,
                                            &"struct PublicKeyJwk with 7 elements",
                                        ),
                                    );
                                }
                            };
                            let __field4 = match _serde::de::SeqAccess::next_element::<
                                Option<String>,
                            >(&mut __seq)? {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            4usize,
                                            &"struct PublicKeyJwk with 7 elements",
                                        ),
                                    );
                                }
                            };
                            let __field5 = match _serde::de::SeqAccess::next_element::<
                                Option<EncryptionAlgorithm>,
                            >(&mut __seq)? {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            5usize,
                                            &"struct PublicKeyJwk with 7 elements",
                                        ),
                                    );
                                }
                            };
                            let __field6 = match _serde::de::SeqAccess::next_element::<
                                Option<KeyUse>,
                            >(&mut __seq)? {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            6usize,
                                            &"struct PublicKeyJwk with 7 elements",
                                        ),
                                    );
                                }
                            };
                            _serde::__private::Ok(PublicKeyJwk {
                                kid: __field0,
                                kty: __field1,
                                crv: __field2,
                                x: __field3,
                                y: __field4,
                                alg: __field5,
                                use_: __field6,
                            })
                        }
                        #[inline]
                        fn visit_map<__A>(
                            self,
                            mut __map: __A,
                        ) -> _serde::__private::Result<Self::Value, __A::Error>
                        where
                            __A: _serde::de::MapAccess<'de>,
                        {
                            let mut __field0: _serde::__private::Option<
                                Option<String>,
                            > = _serde::__private::None;
                            let mut __field1: _serde::__private::Option<KeyType> = _serde::__private::None;
                            let mut __field2: _serde::__private::Option<Curve> = _serde::__private::None;
                            let mut __field3: _serde::__private::Option<String> = _serde::__private::None;
                            let mut __field4: _serde::__private::Option<
                                Option<String>,
                            > = _serde::__private::None;
                            let mut __field5: _serde::__private::Option<
                                Option<EncryptionAlgorithm>,
                            > = _serde::__private::None;
                            let mut __field6: _serde::__private::Option<
                                Option<KeyUse>,
                            > = _serde::__private::None;
                            while let _serde::__private::Some(__key) = _serde::de::MapAccess::next_key::<
                                __Field,
                            >(&mut __map)? {
                                match __key {
                                    __Field::__field0 => {
                                        if _serde::__private::Option::is_some(&__field0) {
                                            return _serde::__private::Err(
                                                <__A::Error as _serde::de::Error>::duplicate_field("kid"),
                                            );
                                        }
                                        __field0 = _serde::__private::Some(
                                            _serde::de::MapAccess::next_value::<
                                                Option<String>,
                                            >(&mut __map)?,
                                        );
                                    }
                                    __Field::__field1 => {
                                        if _serde::__private::Option::is_some(&__field1) {
                                            return _serde::__private::Err(
                                                <__A::Error as _serde::de::Error>::duplicate_field("kty"),
                                            );
                                        }
                                        __field1 = _serde::__private::Some(
                                            _serde::de::MapAccess::next_value::<KeyType>(&mut __map)?,
                                        );
                                    }
                                    __Field::__field2 => {
                                        if _serde::__private::Option::is_some(&__field2) {
                                            return _serde::__private::Err(
                                                <__A::Error as _serde::de::Error>::duplicate_field("crv"),
                                            );
                                        }
                                        __field2 = _serde::__private::Some(
                                            _serde::de::MapAccess::next_value::<Curve>(&mut __map)?,
                                        );
                                    }
                                    __Field::__field3 => {
                                        if _serde::__private::Option::is_some(&__field3) {
                                            return _serde::__private::Err(
                                                <__A::Error as _serde::de::Error>::duplicate_field("x"),
                                            );
                                        }
                                        __field3 = _serde::__private::Some(
                                            _serde::de::MapAccess::next_value::<String>(&mut __map)?,
                                        );
                                    }
                                    __Field::__field4 => {
                                        if _serde::__private::Option::is_some(&__field4) {
                                            return _serde::__private::Err(
                                                <__A::Error as _serde::de::Error>::duplicate_field("y"),
                                            );
                                        }
                                        __field4 = _serde::__private::Some(
                                            _serde::de::MapAccess::next_value::<
                                                Option<String>,
                                            >(&mut __map)?,
                                        );
                                    }
                                    __Field::__field5 => {
                                        if _serde::__private::Option::is_some(&__field5) {
                                            return _serde::__private::Err(
                                                <__A::Error as _serde::de::Error>::duplicate_field("alg"),
                                            );
                                        }
                                        __field5 = _serde::__private::Some(
                                            _serde::de::MapAccess::next_value::<
                                                Option<EncryptionAlgorithm>,
                                            >(&mut __map)?,
                                        );
                                    }
                                    __Field::__field6 => {
                                        if _serde::__private::Option::is_some(&__field6) {
                                            return _serde::__private::Err(
                                                <__A::Error as _serde::de::Error>::duplicate_field("use"),
                                            );
                                        }
                                        __field6 = _serde::__private::Some(
                                            _serde::de::MapAccess::next_value::<
                                                Option<KeyUse>,
                                            >(&mut __map)?,
                                        );
                                    }
                                    _ => {
                                        let _ = _serde::de::MapAccess::next_value::<
                                            _serde::de::IgnoredAny,
                                        >(&mut __map)?;
                                    }
                                }
                            }
                            let __field0 = match __field0 {
                                _serde::__private::Some(__field0) => __field0,
                                _serde::__private::None => {
                                    _serde::__private::de::missing_field("kid")?
                                }
                            };
                            let __field1 = match __field1 {
                                _serde::__private::Some(__field1) => __field1,
                                _serde::__private::None => {
                                    _serde::__private::de::missing_field("kty")?
                                }
                            };
                            let __field2 = match __field2 {
                                _serde::__private::Some(__field2) => __field2,
                                _serde::__private::None => {
                                    _serde::__private::de::missing_field("crv")?
                                }
                            };
                            let __field3 = match __field3 {
                                _serde::__private::Some(__field3) => __field3,
                                _serde::__private::None => {
                                    _serde::__private::de::missing_field("x")?
                                }
                            };
                            let __field4 = match __field4 {
                                _serde::__private::Some(__field4) => __field4,
                                _serde::__private::None => {
                                    _serde::__private::de::missing_field("y")?
                                }
                            };
                            let __field5 = match __field5 {
                                _serde::__private::Some(__field5) => __field5,
                                _serde::__private::None => {
                                    _serde::__private::de::missing_field("alg")?
                                }
                            };
                            let __field6 = match __field6 {
                                _serde::__private::Some(__field6) => __field6,
                                _serde::__private::None => {
                                    _serde::__private::de::missing_field("use")?
                                }
                            };
                            _serde::__private::Ok(PublicKeyJwk {
                                kid: __field0,
                                kty: __field1,
                                crv: __field2,
                                x: __field3,
                                y: __field4,
                                alg: __field5,
                                use_: __field6,
                            })
                        }
                    }
                    #[doc(hidden)]
                    const FIELDS: &'static [&'static str] = &[
                        "kid",
                        "kty",
                        "crv",
                        "x",
                        "y",
                        "alg",
                        "use",
                    ];
                    _serde::Deserializer::deserialize_struct(
                        __deserializer,
                        "PublicKeyJwk",
                        FIELDS,
                        __Visitor {
                            marker: _serde::__private::PhantomData::<PublicKeyJwk>,
                            lifetime: _serde::__private::PhantomData,
                        },
                    )
                }
            }
        };
        #[doc(hidden)]
        #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
        const _: () = {
            #[allow(unused_extern_crates, clippy::useless_attribute)]
            extern crate serde as _serde;
            #[automatically_derived]
            impl _serde::Serialize for PublicKeyJwk {
                fn serialize<__S>(
                    &self,
                    __serializer: __S,
                ) -> _serde::__private::Result<__S::Ok, __S::Error>
                where
                    __S: _serde::Serializer,
                {
                    let mut __serde_state = _serde::Serializer::serialize_struct(
                        __serializer,
                        "PublicKeyJwk",
                        false as usize + if Option::is_none(&self.kid) { 0 } else { 1 }
                            + 1 + 1 + 1 + if Option::is_none(&self.y) { 0 } else { 1 }
                            + if Option::is_none(&self.alg) { 0 } else { 1 }
                            + if Option::is_none(&self.use_) { 0 } else { 1 },
                    )?;
                    if !Option::is_none(&self.kid) {
                        _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "kid",
                            &self.kid,
                        )?;
                    } else {
                        _serde::ser::SerializeStruct::skip_field(
                            &mut __serde_state,
                            "kid",
                        )?;
                    }
                    _serde::ser::SerializeStruct::serialize_field(
                        &mut __serde_state,
                        "kty",
                        &self.kty,
                    )?;
                    _serde::ser::SerializeStruct::serialize_field(
                        &mut __serde_state,
                        "crv",
                        &self.crv,
                    )?;
                    _serde::ser::SerializeStruct::serialize_field(
                        &mut __serde_state,
                        "x",
                        &self.x,
                    )?;
                    if !Option::is_none(&self.y) {
                        _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "y",
                            &self.y,
                        )?;
                    } else {
                        _serde::ser::SerializeStruct::skip_field(
                            &mut __serde_state,
                            "y",
                        )?;
                    }
                    if !Option::is_none(&self.alg) {
                        _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "alg",
                            &self.alg,
                        )?;
                    } else {
                        _serde::ser::SerializeStruct::skip_field(
                            &mut __serde_state,
                            "alg",
                        )?;
                    }
                    if !Option::is_none(&self.use_) {
                        _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "use",
                            &self.use_,
                        )?;
                    } else {
                        _serde::ser::SerializeStruct::skip_field(
                            &mut __serde_state,
                            "use",
                        )?;
                    }
                    _serde::ser::SerializeStruct::end(__serde_state)
                }
            }
        };
        #[automatically_derived]
        #[allow(clippy::module_name_repetitions)]
        impl ::core::cmp::Eq for PublicKeyJwk {
            #[inline]
            #[doc(hidden)]
            #[coverage(off)]
            fn assert_receiver_is_total_eq(&self) -> () {
                let _: ::core::cmp::AssertParamIsEq<Option<String>>;
                let _: ::core::cmp::AssertParamIsEq<KeyType>;
                let _: ::core::cmp::AssertParamIsEq<Curve>;
                let _: ::core::cmp::AssertParamIsEq<String>;
                let _: ::core::cmp::AssertParamIsEq<Option<String>>;
                let _: ::core::cmp::AssertParamIsEq<Option<EncryptionAlgorithm>>;
                let _: ::core::cmp::AssertParamIsEq<Option<KeyUse>>;
            }
        }
        #[automatically_derived]
        #[allow(clippy::module_name_repetitions)]
        impl ::core::marker::StructuralPartialEq for PublicKeyJwk {}
        #[automatically_derived]
        #[allow(clippy::module_name_repetitions)]
        impl ::core::cmp::PartialEq for PublicKeyJwk {
            #[inline]
            fn eq(&self, other: &PublicKeyJwk) -> bool {
                self.kid == other.kid && self.kty == other.kty && self.crv == other.crv
                    && self.x == other.x && self.y == other.y && self.alg == other.alg
                    && self.use_ == other.use_
            }
        }
        /// A set of JWKs.
        pub struct Jwks {
            /// The set of public key JWKs
            pub keys: Vec<PublicKeyJwk>,
        }
        #[automatically_derived]
        impl ::core::clone::Clone for Jwks {
            #[inline]
            fn clone(&self) -> Jwks {
                Jwks {
                    keys: ::core::clone::Clone::clone(&self.keys),
                }
            }
        }
        #[automatically_derived]
        impl ::core::fmt::Debug for Jwks {
            #[inline]
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                ::core::fmt::Formatter::debug_struct_field1_finish(
                    f,
                    "Jwks",
                    "keys",
                    &&self.keys,
                )
            }
        }
        #[automatically_derived]
        impl ::core::default::Default for Jwks {
            #[inline]
            fn default() -> Jwks {
                Jwks {
                    keys: ::core::default::Default::default(),
                }
            }
        }
        #[doc(hidden)]
        #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
        const _: () = {
            #[allow(unused_extern_crates, clippy::useless_attribute)]
            extern crate serde as _serde;
            #[automatically_derived]
            impl<'de> _serde::Deserialize<'de> for Jwks {
                fn deserialize<__D>(
                    __deserializer: __D,
                ) -> _serde::__private::Result<Self, __D::Error>
                where
                    __D: _serde::Deserializer<'de>,
                {
                    #[allow(non_camel_case_types)]
                    #[doc(hidden)]
                    enum __Field {
                        __field0,
                        __ignore,
                    }
                    #[doc(hidden)]
                    struct __FieldVisitor;
                    impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                        type Value = __Field;
                        fn expecting(
                            &self,
                            __formatter: &mut _serde::__private::Formatter,
                        ) -> _serde::__private::fmt::Result {
                            _serde::__private::Formatter::write_str(
                                __formatter,
                                "field identifier",
                            )
                        }
                        fn visit_u64<__E>(
                            self,
                            __value: u64,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                0u64 => _serde::__private::Ok(__Field::__field0),
                                _ => _serde::__private::Ok(__Field::__ignore),
                            }
                        }
                        fn visit_str<__E>(
                            self,
                            __value: &str,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                "keys" => _serde::__private::Ok(__Field::__field0),
                                _ => _serde::__private::Ok(__Field::__ignore),
                            }
                        }
                        fn visit_bytes<__E>(
                            self,
                            __value: &[u8],
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                b"keys" => _serde::__private::Ok(__Field::__field0),
                                _ => _serde::__private::Ok(__Field::__ignore),
                            }
                        }
                    }
                    impl<'de> _serde::Deserialize<'de> for __Field {
                        #[inline]
                        fn deserialize<__D>(
                            __deserializer: __D,
                        ) -> _serde::__private::Result<Self, __D::Error>
                        where
                            __D: _serde::Deserializer<'de>,
                        {
                            _serde::Deserializer::deserialize_identifier(
                                __deserializer,
                                __FieldVisitor,
                            )
                        }
                    }
                    #[doc(hidden)]
                    struct __Visitor<'de> {
                        marker: _serde::__private::PhantomData<Jwks>,
                        lifetime: _serde::__private::PhantomData<&'de ()>,
                    }
                    impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                        type Value = Jwks;
                        fn expecting(
                            &self,
                            __formatter: &mut _serde::__private::Formatter,
                        ) -> _serde::__private::fmt::Result {
                            _serde::__private::Formatter::write_str(
                                __formatter,
                                "struct Jwks",
                            )
                        }
                        #[inline]
                        fn visit_seq<__A>(
                            self,
                            mut __seq: __A,
                        ) -> _serde::__private::Result<Self::Value, __A::Error>
                        where
                            __A: _serde::de::SeqAccess<'de>,
                        {
                            let __field0 = match _serde::de::SeqAccess::next_element::<
                                Vec<PublicKeyJwk>,
                            >(&mut __seq)? {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            0usize,
                                            &"struct Jwks with 1 element",
                                        ),
                                    );
                                }
                            };
                            _serde::__private::Ok(Jwks { keys: __field0 })
                        }
                        #[inline]
                        fn visit_map<__A>(
                            self,
                            mut __map: __A,
                        ) -> _serde::__private::Result<Self::Value, __A::Error>
                        where
                            __A: _serde::de::MapAccess<'de>,
                        {
                            let mut __field0: _serde::__private::Option<
                                Vec<PublicKeyJwk>,
                            > = _serde::__private::None;
                            while let _serde::__private::Some(__key) = _serde::de::MapAccess::next_key::<
                                __Field,
                            >(&mut __map)? {
                                match __key {
                                    __Field::__field0 => {
                                        if _serde::__private::Option::is_some(&__field0) {
                                            return _serde::__private::Err(
                                                <__A::Error as _serde::de::Error>::duplicate_field("keys"),
                                            );
                                        }
                                        __field0 = _serde::__private::Some(
                                            _serde::de::MapAccess::next_value::<
                                                Vec<PublicKeyJwk>,
                                            >(&mut __map)?,
                                        );
                                    }
                                    _ => {
                                        let _ = _serde::de::MapAccess::next_value::<
                                            _serde::de::IgnoredAny,
                                        >(&mut __map)?;
                                    }
                                }
                            }
                            let __field0 = match __field0 {
                                _serde::__private::Some(__field0) => __field0,
                                _serde::__private::None => {
                                    _serde::__private::de::missing_field("keys")?
                                }
                            };
                            _serde::__private::Ok(Jwks { keys: __field0 })
                        }
                    }
                    #[doc(hidden)]
                    const FIELDS: &'static [&'static str] = &["keys"];
                    _serde::Deserializer::deserialize_struct(
                        __deserializer,
                        "Jwks",
                        FIELDS,
                        __Visitor {
                            marker: _serde::__private::PhantomData::<Jwks>,
                            lifetime: _serde::__private::PhantomData,
                        },
                    )
                }
            }
        };
        #[doc(hidden)]
        #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
        const _: () = {
            #[allow(unused_extern_crates, clippy::useless_attribute)]
            extern crate serde as _serde;
            #[automatically_derived]
            impl _serde::Serialize for Jwks {
                fn serialize<__S>(
                    &self,
                    __serializer: __S,
                ) -> _serde::__private::Result<__S::Ok, __S::Error>
                where
                    __S: _serde::Serializer,
                {
                    let mut __serde_state = _serde::Serializer::serialize_struct(
                        __serializer,
                        "Jwks",
                        false as usize + 1,
                    )?;
                    _serde::ser::SerializeStruct::serialize_field(
                        &mut __serde_state,
                        "keys",
                        &self.keys,
                    )?;
                    _serde::ser::SerializeStruct::end(__serde_state)
                }
            }
        };
        #[automatically_derived]
        impl ::core::marker::StructuralPartialEq for Jwks {}
        #[automatically_derived]
        impl ::core::cmp::PartialEq for Jwks {
            #[inline]
            fn eq(&self, other: &Jwks) -> bool {
                self.keys == other.keys
            }
        }
        #[automatically_derived]
        impl ::core::cmp::Eq for Jwks {
            #[inline]
            #[doc(hidden)]
            #[coverage(off)]
            fn assert_receiver_is_total_eq(&self) -> () {
                let _: ::core::cmp::AssertParamIsEq<Vec<PublicKeyJwk>>;
            }
        }
    }
    pub mod jws {
        //! # JSON Web Signature (JWS)
        //!
        //! JWS ([RFC7515]) represents content secured with digital signatures using
        //! JSON-based data structures. Cryptographic algorithms and identifiers for use
        //! with this specification are described in the JWA ([RFC7518]) specification.
        //!
        //! [RFC7515]: https://www.rfc-editor.org/rfc/rfc7515
        //! [RFC7518]: https://www.rfc-editor.org/rfc/rfc7518
        use anyhow::{anyhow, bail};
        use base64ct::{Base64UrlUnpadded, Encoding};
        use ecdsa::signature::Verifier as _;
        use futures::Future;
        use serde::de::DeserializeOwned;
        use serde::Serialize;
        use crate::jose::jwk::PublicKeyJwk;
        pub use crate::jose::jwt::{Header, Jwt, KeyType, Type};
        use crate::{Algorithm, Curve, Signer};
        /// Encode the provided header and claims and sign, returning a JWT in compact
        /// JWS form.
        ///
        /// # Errors
        /// TODO: document errors
        pub async fn encode<T>(
            typ: Type,
            claims: &T,
            signer: impl Signer,
        ) -> anyhow::Result<String>
        where
            T: Serialize + Send + Sync,
        {
            {
                use ::tracing::__macro_support::Callsite as _;
                static __CALLSITE: ::tracing::callsite::DefaultCallsite = {
                    static META: ::tracing::Metadata<'static> = {
                        ::tracing_core::metadata::Metadata::new(
                            "event crates/datasec/src/jose/jws.rs:30",
                            "vercre_datasec::jose::jws",
                            ::tracing::Level::DEBUG,
                            ::core::option::Option::Some(
                                "crates/datasec/src/jose/jws.rs",
                            ),
                            ::core::option::Option::Some(30u32),
                            ::core::option::Option::Some("vercre_datasec::jose::jws"),
                            ::tracing_core::field::FieldSet::new(
                                &["message"],
                                ::tracing_core::callsite::Identifier(&__CALLSITE),
                            ),
                            ::tracing::metadata::Kind::EVENT,
                        )
                    };
                    ::tracing::callsite::DefaultCallsite::new(&META)
                };
                let enabled = ::tracing::Level::DEBUG
                    <= ::tracing::level_filters::STATIC_MAX_LEVEL
                    && ::tracing::Level::DEBUG
                        <= ::tracing::level_filters::LevelFilter::current()
                    && {
                        let interest = __CALLSITE.interest();
                        !interest.is_never()
                            && ::tracing::__macro_support::__is_enabled(
                                __CALLSITE.metadata(),
                                interest,
                            )
                    };
                if enabled {
                    (|value_set: ::tracing::field::ValueSet| {
                        let meta = __CALLSITE.metadata();
                        ::tracing::Event::dispatch(meta, &value_set);
                    })({
                        #[allow(unused_imports)]
                        use ::tracing::field::{debug, display, Value};
                        let mut iter = __CALLSITE.metadata().fields().iter();
                        __CALLSITE
                            .metadata()
                            .fields()
                            .value_set(
                                &[
                                    (
                                        &::core::iter::Iterator::next(&mut iter)
                                            .expect("FieldSet corrupted (this is a bug)"),
                                        ::core::option::Option::Some(
                                            &format_args!("encode") as &dyn Value,
                                        ),
                                    ),
                                ],
                            )
                    });
                } else {
                }
            };
            let header = Header {
                alg: signer.algorithm(),
                typ,
                key: KeyType::KeyId(signer.verification_method()),
                ..Header::default()
            };
            let header = Base64UrlUnpadded::encode_string(&serde_json::to_vec(&header)?);
            let claims = Base64UrlUnpadded::encode_string(&serde_json::to_vec(claims)?);
            let payload = ::alloc::__export::must_use({
                let res = ::alloc::fmt::format(format_args!("{0}.{1}", header, claims));
                res
            });
            let sig = signer.try_sign(payload.as_bytes()).await?;
            let sig_enc = Base64UrlUnpadded::encode_string(&sig);
            Ok(
                ::alloc::__export::must_use({
                    let res = ::alloc::fmt::format(
                        format_args!("{0}.{1}", payload, sig_enc),
                    );
                    res
                }),
            )
        }
        /// Decode the JWT token and return the claims.
        ///
        /// # Errors
        /// TODO: document errors
        pub async fn decode<F, Fut, T>(token: &str, pk_cb: F) -> anyhow::Result<Jwt<T>>
        where
            T: DeserializeOwned + Send,
            F: FnOnce(String) -> Fut + Send + Sync,
            Fut: Future<Output = anyhow::Result<PublicKeyJwk>> + Send + Sync,
        {
            let parts = token.split('.').collect::<Vec<&str>>();
            if parts.len() != 3 {
                return ::anyhow::__private::Err({
                    let error = ::anyhow::__private::format_err(
                        format_args!("invalid Compact JWS format"),
                    );
                    error
                });
            }
            let decoded = Base64UrlUnpadded::decode_vec(parts[0])
                .map_err(|e| ::anyhow::__private::must_use({
                    let error = ::anyhow::__private::format_err(
                        format_args!("issue decoding header: {0}", e),
                    );
                    error
                }))?;
            let header: Header = serde_json::from_slice(&decoded)
                .map_err(|e| ::anyhow::__private::must_use({
                    let error = ::anyhow::__private::format_err(
                        format_args!("issue deserializing header: {0}", e),
                    );
                    error
                }))?;
            let decoded = Base64UrlUnpadded::decode_vec(parts[1])
                .map_err(|e| ::anyhow::__private::must_use({
                    let error = ::anyhow::__private::format_err(
                        format_args!("issue decoding claims: {0}", e),
                    );
                    error
                }))?;
            let claims = serde_json::from_slice(&decoded)
                .map_err(|e| ::anyhow::__private::must_use({
                    let error = ::anyhow::__private::format_err(
                        format_args!("issue deserializing claims:{0}", e),
                    );
                    error
                }))?;
            let sig = Base64UrlUnpadded::decode_vec(parts[2])
                .map_err(|e| ::anyhow::__private::must_use({
                    let error = ::anyhow::__private::format_err(
                        format_args!("issue decoding signature: {0}", e),
                    );
                    error
                }))?;
            if !(header.alg == Algorithm::ES256K || header.alg == Algorithm::EdDSA) {
                return ::anyhow::__private::Err({
                    let error = ::anyhow::__private::format_err(
                        format_args!("\'alg\' is not recognised"),
                    );
                    error
                });
            }
            let KeyType::KeyId(kid) = header.key.clone() else {
                return ::anyhow::__private::Err({
                    let error = ::anyhow::__private::format_err(
                        format_args!("\'kid\' is not set"),
                    );
                    error
                });
            };
            let jwk = pk_cb(kid).await?;
            verify(
                &jwk,
                &::alloc::__export::must_use({
                    let res = ::alloc::fmt::format(
                        format_args!("{0}.{1}", parts[0], parts[1]),
                    );
                    res
                }),
                &sig,
            )?;
            Ok(Jwt { header, claims })
        }
        /// Verify the signature of the provided message using the JWK.
        ///
        /// # Errors
        ///
        /// Will return an error if the signature is invalid, the JWK is invalid, or the
        /// algorithm is unsupported.
        pub fn verify(jwk: &PublicKeyJwk, msg: &str, sig: &[u8]) -> anyhow::Result<()> {
            match jwk.crv {
                Curve::Es256K => verify_es256k(jwk, msg, sig),
                Curve::Ed25519 => verify_eddsa(jwk, msg, sig),
            }
        }
        fn verify_es256k(
            jwk: &PublicKeyJwk,
            msg: &str,
            sig: &[u8],
        ) -> anyhow::Result<()> {
            use ecdsa::{Signature, VerifyingKey};
            use k256::Secp256k1;
            let y = jwk
                .y
                .as_ref()
                .ok_or_else(|| ::anyhow::__private::must_use({
                    let error = ::anyhow::__private::format_err(
                        format_args!("Proof JWT \'y\' is invalid"),
                    );
                    error
                }))?;
            let mut sec1 = <[_]>::into_vec(
                #[rustc_box]
                ::alloc::boxed::Box::new([0x04]),
            );
            sec1.append(&mut Base64UrlUnpadded::decode_vec(&jwk.x)?);
            sec1.append(&mut Base64UrlUnpadded::decode_vec(y)?);
            let verifying_key = VerifyingKey::<Secp256k1>::from_sec1_bytes(&sec1)?;
            let signature: Signature<Secp256k1> = Signature::from_slice(sig)?;
            let normalised = signature.normalize_s().unwrap_or(signature);
            Ok(verifying_key.verify(msg.as_bytes(), &normalised)?)
        }
        fn verify_eddsa(
            jwk: &PublicKeyJwk,
            msg: &str,
            sig_bytes: &[u8],
        ) -> anyhow::Result<()> {
            use ed25519_dalek::{Signature, VerifyingKey};
            let x_bytes = Base64UrlUnpadded::decode_vec(&jwk.x)
                .map_err(|e| ::anyhow::__private::must_use({
                    let error = ::anyhow::__private::format_err(
                        format_args!("unable to base64 decode proof JWK \'x\': {0}", e),
                    );
                    error
                }))?;
            let bytes = &x_bytes
                .try_into()
                .map_err(|_| ::anyhow::__private::must_use({
                    let error = ::anyhow::__private::format_err(
                        format_args!("invalid public key length"),
                    );
                    error
                }))?;
            let verifying_key = VerifyingKey::from_bytes(bytes)
                .map_err(|e| ::anyhow::__private::must_use({
                    let error = ::anyhow::__private::format_err(
                        format_args!("unable to build verifying key: {0}", e),
                    );
                    error
                }))?;
            let signature = Signature::from_slice(sig_bytes)
                .map_err(|e| ::anyhow::__private::must_use({
                    let error = ::anyhow::__private::format_err(
                        format_args!("unable to build signature: {0}", e),
                    );
                    error
                }))?;
            verifying_key
                .verify(msg.as_bytes(), &signature)
                .map_err(|e| ::anyhow::__private::must_use({
                    let error = ::anyhow::__private::format_err(
                        format_args!("unable to verify signature: {0}", e),
                    );
                    error
                }))
        }
    }
    pub mod jwt {
        //! # JSON Web Token (JWT)
        //!
        //! JSON Web Token (JWT) is a compact, URL-safe means of representing
        //! claims to be transferred between two parties.  The claims in a JWT
        //! are encoded as a JSON object that is used as the payload of a JSON
        //! Web Signature (JWS) structure or as the plaintext of a JSON Web
        //! Encryption (JWE) structure, enabling the claims to be digitally
        //! signed or integrity protected with a Message Authentication Code
        //! (MAC) and/or encrypted.
        use std::fmt::{Debug, Display};
        use serde::{Deserialize, Serialize};
        use crate::jose::jwk::PublicKeyJwk;
        use crate::Algorithm;
        /// Represents a JWT as used for proof and credential presentation.
        pub struct Jwt<T> {
            /// The JWT header.
            pub header: Header,
            /// The JWT claims.
            pub claims: T,
        }
        #[automatically_derived]
        impl<T: ::core::clone::Clone> ::core::clone::Clone for Jwt<T> {
            #[inline]
            fn clone(&self) -> Jwt<T> {
                Jwt {
                    header: ::core::clone::Clone::clone(&self.header),
                    claims: ::core::clone::Clone::clone(&self.claims),
                }
            }
        }
        #[automatically_derived]
        impl<T: ::core::fmt::Debug> ::core::fmt::Debug for Jwt<T> {
            #[inline]
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                ::core::fmt::Formatter::debug_struct_field2_finish(
                    f,
                    "Jwt",
                    "header",
                    &self.header,
                    "claims",
                    &&self.claims,
                )
            }
        }
        #[automatically_derived]
        impl<T: ::core::default::Default> ::core::default::Default for Jwt<T> {
            #[inline]
            fn default() -> Jwt<T> {
                Jwt {
                    header: ::core::default::Default::default(),
                    claims: ::core::default::Default::default(),
                }
            }
        }
        #[doc(hidden)]
        #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
        const _: () = {
            #[allow(unused_extern_crates, clippy::useless_attribute)]
            extern crate serde as _serde;
            #[automatically_derived]
            impl<T> _serde::Serialize for Jwt<T>
            where
                T: _serde::Serialize,
            {
                fn serialize<__S>(
                    &self,
                    __serializer: __S,
                ) -> _serde::__private::Result<__S::Ok, __S::Error>
                where
                    __S: _serde::Serializer,
                {
                    let mut __serde_state = _serde::Serializer::serialize_struct(
                        __serializer,
                        "Jwt",
                        false as usize + 1 + 1,
                    )?;
                    _serde::ser::SerializeStruct::serialize_field(
                        &mut __serde_state,
                        "header",
                        &self.header,
                    )?;
                    _serde::ser::SerializeStruct::serialize_field(
                        &mut __serde_state,
                        "claims",
                        &self.claims,
                    )?;
                    _serde::ser::SerializeStruct::end(__serde_state)
                }
            }
        };
        #[automatically_derived]
        impl<T> ::core::marker::StructuralPartialEq for Jwt<T> {}
        #[automatically_derived]
        impl<T: ::core::cmp::PartialEq> ::core::cmp::PartialEq for Jwt<T> {
            #[inline]
            fn eq(&self, other: &Jwt<T>) -> bool {
                self.header == other.header && self.claims == other.claims
            }
        }
        #[automatically_derived]
        impl<T: ::core::cmp::Eq> ::core::cmp::Eq for Jwt<T> {
            #[inline]
            #[doc(hidden)]
            #[coverage(off)]
            fn assert_receiver_is_total_eq(&self) -> () {
                let _: ::core::cmp::AssertParamIsEq<Header>;
                let _: ::core::cmp::AssertParamIsEq<T>;
            }
        }
        /// Represents the JWT header.
        pub struct Header {
            /// Digital signature algorithm identifier as per IANA "JSON Web Signature
            /// and Encryption Algorithms" registry.
            pub alg: Algorithm,
            /// Used to declare the media type [IANA.MediaTypes](http://www.iana.org/assignments/media-types)
            /// of the JWS.
            pub typ: Type,
            /// The key material for the public key.
            #[serde(flatten)]
            pub key: KeyType,
            /// Contains a certificate (or certificate chain) corresponding to the key
            /// used to sign the JWT. This element MAY be used to convey a key
            /// attestation. In such a case, the actual key certificate will contain
            /// attributes related to the key properties.
            #[serde(skip_serializing_if = "Option::is_none")]
            pub x5c: Option<String>,
            /// Contains an OpenID.Federation Trust Chain. This element MAY be used to
            /// convey key attestation, metadata, metadata policies, federation
            /// Trust Marks and any other information related to a specific
            /// federation, if available in the chain.
            ///
            /// When used for signature verification, `kid` MUST be set.
            #[serde(skip_serializing_if = "Option::is_none")]
            pub trust_chain: Option<String>,
        }
        #[automatically_derived]
        impl ::core::clone::Clone for Header {
            #[inline]
            fn clone(&self) -> Header {
                Header {
                    alg: ::core::clone::Clone::clone(&self.alg),
                    typ: ::core::clone::Clone::clone(&self.typ),
                    key: ::core::clone::Clone::clone(&self.key),
                    x5c: ::core::clone::Clone::clone(&self.x5c),
                    trust_chain: ::core::clone::Clone::clone(&self.trust_chain),
                }
            }
        }
        #[automatically_derived]
        impl ::core::fmt::Debug for Header {
            #[inline]
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                ::core::fmt::Formatter::debug_struct_field5_finish(
                    f,
                    "Header",
                    "alg",
                    &self.alg,
                    "typ",
                    &self.typ,
                    "key",
                    &self.key,
                    "x5c",
                    &self.x5c,
                    "trust_chain",
                    &&self.trust_chain,
                )
            }
        }
        #[automatically_derived]
        impl ::core::default::Default for Header {
            #[inline]
            fn default() -> Header {
                Header {
                    alg: ::core::default::Default::default(),
                    typ: ::core::default::Default::default(),
                    key: ::core::default::Default::default(),
                    x5c: ::core::default::Default::default(),
                    trust_chain: ::core::default::Default::default(),
                }
            }
        }
        #[doc(hidden)]
        #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
        const _: () = {
            #[allow(unused_extern_crates, clippy::useless_attribute)]
            extern crate serde as _serde;
            #[automatically_derived]
            impl<'de> _serde::Deserialize<'de> for Header {
                fn deserialize<__D>(
                    __deserializer: __D,
                ) -> _serde::__private::Result<Self, __D::Error>
                where
                    __D: _serde::Deserializer<'de>,
                {
                    #[allow(non_camel_case_types)]
                    #[doc(hidden)]
                    enum __Field<'de> {
                        __field0,
                        __field1,
                        __field3,
                        __field4,
                        __other(_serde::__private::de::Content<'de>),
                    }
                    #[doc(hidden)]
                    struct __FieldVisitor;
                    impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                        type Value = __Field<'de>;
                        fn expecting(
                            &self,
                            __formatter: &mut _serde::__private::Formatter,
                        ) -> _serde::__private::fmt::Result {
                            _serde::__private::Formatter::write_str(
                                __formatter,
                                "field identifier",
                            )
                        }
                        fn visit_bool<__E>(
                            self,
                            __value: bool,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            _serde::__private::Ok(
                                __Field::__other(
                                    _serde::__private::de::Content::Bool(__value),
                                ),
                            )
                        }
                        fn visit_i8<__E>(
                            self,
                            __value: i8,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            _serde::__private::Ok(
                                __Field::__other(
                                    _serde::__private::de::Content::I8(__value),
                                ),
                            )
                        }
                        fn visit_i16<__E>(
                            self,
                            __value: i16,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            _serde::__private::Ok(
                                __Field::__other(
                                    _serde::__private::de::Content::I16(__value),
                                ),
                            )
                        }
                        fn visit_i32<__E>(
                            self,
                            __value: i32,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            _serde::__private::Ok(
                                __Field::__other(
                                    _serde::__private::de::Content::I32(__value),
                                ),
                            )
                        }
                        fn visit_i64<__E>(
                            self,
                            __value: i64,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            _serde::__private::Ok(
                                __Field::__other(
                                    _serde::__private::de::Content::I64(__value),
                                ),
                            )
                        }
                        fn visit_u8<__E>(
                            self,
                            __value: u8,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            _serde::__private::Ok(
                                __Field::__other(
                                    _serde::__private::de::Content::U8(__value),
                                ),
                            )
                        }
                        fn visit_u16<__E>(
                            self,
                            __value: u16,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            _serde::__private::Ok(
                                __Field::__other(
                                    _serde::__private::de::Content::U16(__value),
                                ),
                            )
                        }
                        fn visit_u32<__E>(
                            self,
                            __value: u32,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            _serde::__private::Ok(
                                __Field::__other(
                                    _serde::__private::de::Content::U32(__value),
                                ),
                            )
                        }
                        fn visit_u64<__E>(
                            self,
                            __value: u64,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            _serde::__private::Ok(
                                __Field::__other(
                                    _serde::__private::de::Content::U64(__value),
                                ),
                            )
                        }
                        fn visit_f32<__E>(
                            self,
                            __value: f32,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            _serde::__private::Ok(
                                __Field::__other(
                                    _serde::__private::de::Content::F32(__value),
                                ),
                            )
                        }
                        fn visit_f64<__E>(
                            self,
                            __value: f64,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            _serde::__private::Ok(
                                __Field::__other(
                                    _serde::__private::de::Content::F64(__value),
                                ),
                            )
                        }
                        fn visit_char<__E>(
                            self,
                            __value: char,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            _serde::__private::Ok(
                                __Field::__other(
                                    _serde::__private::de::Content::Char(__value),
                                ),
                            )
                        }
                        fn visit_unit<__E>(
                            self,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            _serde::__private::Ok(
                                __Field::__other(_serde::__private::de::Content::Unit),
                            )
                        }
                        fn visit_str<__E>(
                            self,
                            __value: &str,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                "alg" => _serde::__private::Ok(__Field::__field0),
                                "typ" => _serde::__private::Ok(__Field::__field1),
                                "x5c" => _serde::__private::Ok(__Field::__field3),
                                "trust_chain" => _serde::__private::Ok(__Field::__field4),
                                _ => {
                                    let __value = _serde::__private::de::Content::String(
                                        _serde::__private::ToString::to_string(__value),
                                    );
                                    _serde::__private::Ok(__Field::__other(__value))
                                }
                            }
                        }
                        fn visit_bytes<__E>(
                            self,
                            __value: &[u8],
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                b"alg" => _serde::__private::Ok(__Field::__field0),
                                b"typ" => _serde::__private::Ok(__Field::__field1),
                                b"x5c" => _serde::__private::Ok(__Field::__field3),
                                b"trust_chain" => _serde::__private::Ok(__Field::__field4),
                                _ => {
                                    let __value = _serde::__private::de::Content::ByteBuf(
                                        __value.to_vec(),
                                    );
                                    _serde::__private::Ok(__Field::__other(__value))
                                }
                            }
                        }
                        fn visit_borrowed_str<__E>(
                            self,
                            __value: &'de str,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                "alg" => _serde::__private::Ok(__Field::__field0),
                                "typ" => _serde::__private::Ok(__Field::__field1),
                                "x5c" => _serde::__private::Ok(__Field::__field3),
                                "trust_chain" => _serde::__private::Ok(__Field::__field4),
                                _ => {
                                    let __value = _serde::__private::de::Content::Str(__value);
                                    _serde::__private::Ok(__Field::__other(__value))
                                }
                            }
                        }
                        fn visit_borrowed_bytes<__E>(
                            self,
                            __value: &'de [u8],
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                b"alg" => _serde::__private::Ok(__Field::__field0),
                                b"typ" => _serde::__private::Ok(__Field::__field1),
                                b"x5c" => _serde::__private::Ok(__Field::__field3),
                                b"trust_chain" => _serde::__private::Ok(__Field::__field4),
                                _ => {
                                    let __value = _serde::__private::de::Content::Bytes(
                                        __value,
                                    );
                                    _serde::__private::Ok(__Field::__other(__value))
                                }
                            }
                        }
                    }
                    impl<'de> _serde::Deserialize<'de> for __Field<'de> {
                        #[inline]
                        fn deserialize<__D>(
                            __deserializer: __D,
                        ) -> _serde::__private::Result<Self, __D::Error>
                        where
                            __D: _serde::Deserializer<'de>,
                        {
                            _serde::Deserializer::deserialize_identifier(
                                __deserializer,
                                __FieldVisitor,
                            )
                        }
                    }
                    #[doc(hidden)]
                    struct __Visitor<'de> {
                        marker: _serde::__private::PhantomData<Header>,
                        lifetime: _serde::__private::PhantomData<&'de ()>,
                    }
                    impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                        type Value = Header;
                        fn expecting(
                            &self,
                            __formatter: &mut _serde::__private::Formatter,
                        ) -> _serde::__private::fmt::Result {
                            _serde::__private::Formatter::write_str(
                                __formatter,
                                "struct Header",
                            )
                        }
                        #[inline]
                        fn visit_map<__A>(
                            self,
                            mut __map: __A,
                        ) -> _serde::__private::Result<Self::Value, __A::Error>
                        where
                            __A: _serde::de::MapAccess<'de>,
                        {
                            let mut __field0: _serde::__private::Option<Algorithm> = _serde::__private::None;
                            let mut __field1: _serde::__private::Option<Type> = _serde::__private::None;
                            let mut __field3: _serde::__private::Option<
                                Option<String>,
                            > = _serde::__private::None;
                            let mut __field4: _serde::__private::Option<
                                Option<String>,
                            > = _serde::__private::None;
                            let mut __collect = _serde::__private::Vec::<
                                _serde::__private::Option<
                                    (
                                        _serde::__private::de::Content,
                                        _serde::__private::de::Content,
                                    ),
                                >,
                            >::new();
                            while let _serde::__private::Some(__key) = _serde::de::MapAccess::next_key::<
                                __Field,
                            >(&mut __map)? {
                                match __key {
                                    __Field::__field0 => {
                                        if _serde::__private::Option::is_some(&__field0) {
                                            return _serde::__private::Err(
                                                <__A::Error as _serde::de::Error>::duplicate_field("alg"),
                                            );
                                        }
                                        __field0 = _serde::__private::Some(
                                            _serde::de::MapAccess::next_value::<Algorithm>(&mut __map)?,
                                        );
                                    }
                                    __Field::__field1 => {
                                        if _serde::__private::Option::is_some(&__field1) {
                                            return _serde::__private::Err(
                                                <__A::Error as _serde::de::Error>::duplicate_field("typ"),
                                            );
                                        }
                                        __field1 = _serde::__private::Some(
                                            _serde::de::MapAccess::next_value::<Type>(&mut __map)?,
                                        );
                                    }
                                    __Field::__field3 => {
                                        if _serde::__private::Option::is_some(&__field3) {
                                            return _serde::__private::Err(
                                                <__A::Error as _serde::de::Error>::duplicate_field("x5c"),
                                            );
                                        }
                                        __field3 = _serde::__private::Some(
                                            _serde::de::MapAccess::next_value::<
                                                Option<String>,
                                            >(&mut __map)?,
                                        );
                                    }
                                    __Field::__field4 => {
                                        if _serde::__private::Option::is_some(&__field4) {
                                            return _serde::__private::Err(
                                                <__A::Error as _serde::de::Error>::duplicate_field(
                                                    "trust_chain",
                                                ),
                                            );
                                        }
                                        __field4 = _serde::__private::Some(
                                            _serde::de::MapAccess::next_value::<
                                                Option<String>,
                                            >(&mut __map)?,
                                        );
                                    }
                                    __Field::__other(__name) => {
                                        __collect
                                            .push(
                                                _serde::__private::Some((
                                                    __name,
                                                    _serde::de::MapAccess::next_value(&mut __map)?,
                                                )),
                                            );
                                    }
                                }
                            }
                            let __field0 = match __field0 {
                                _serde::__private::Some(__field0) => __field0,
                                _serde::__private::None => {
                                    _serde::__private::de::missing_field("alg")?
                                }
                            };
                            let __field1 = match __field1 {
                                _serde::__private::Some(__field1) => __field1,
                                _serde::__private::None => {
                                    _serde::__private::de::missing_field("typ")?
                                }
                            };
                            let __field3 = match __field3 {
                                _serde::__private::Some(__field3) => __field3,
                                _serde::__private::None => {
                                    _serde::__private::de::missing_field("x5c")?
                                }
                            };
                            let __field4 = match __field4 {
                                _serde::__private::Some(__field4) => __field4,
                                _serde::__private::None => {
                                    _serde::__private::de::missing_field("trust_chain")?
                                }
                            };
                            let __field2: KeyType = _serde::de::Deserialize::deserialize(
                                _serde::__private::de::FlatMapDeserializer(
                                    &mut __collect,
                                    _serde::__private::PhantomData,
                                ),
                            )?;
                            _serde::__private::Ok(Header {
                                alg: __field0,
                                typ: __field1,
                                key: __field2,
                                x5c: __field3,
                                trust_chain: __field4,
                            })
                        }
                    }
                    _serde::Deserializer::deserialize_map(
                        __deserializer,
                        __Visitor {
                            marker: _serde::__private::PhantomData::<Header>,
                            lifetime: _serde::__private::PhantomData,
                        },
                    )
                }
            }
        };
        #[doc(hidden)]
        #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
        const _: () = {
            #[allow(unused_extern_crates, clippy::useless_attribute)]
            extern crate serde as _serde;
            #[automatically_derived]
            impl _serde::Serialize for Header {
                fn serialize<__S>(
                    &self,
                    __serializer: __S,
                ) -> _serde::__private::Result<__S::Ok, __S::Error>
                where
                    __S: _serde::Serializer,
                {
                    let mut __serde_state = _serde::Serializer::serialize_map(
                        __serializer,
                        _serde::__private::None,
                    )?;
                    _serde::ser::SerializeMap::serialize_entry(
                        &mut __serde_state,
                        "alg",
                        &self.alg,
                    )?;
                    _serde::ser::SerializeMap::serialize_entry(
                        &mut __serde_state,
                        "typ",
                        &self.typ,
                    )?;
                    _serde::Serialize::serialize(
                        &&self.key,
                        _serde::__private::ser::FlatMapSerializer(&mut __serde_state),
                    )?;
                    if !Option::is_none(&self.x5c) {
                        _serde::ser::SerializeMap::serialize_entry(
                            &mut __serde_state,
                            "x5c",
                            &self.x5c,
                        )?;
                    }
                    if !Option::is_none(&self.trust_chain) {
                        _serde::ser::SerializeMap::serialize_entry(
                            &mut __serde_state,
                            "trust_chain",
                            &self.trust_chain,
                        )?;
                    }
                    _serde::ser::SerializeMap::end(__serde_state)
                }
            }
        };
        #[automatically_derived]
        impl ::core::marker::StructuralPartialEq for Header {}
        #[automatically_derived]
        impl ::core::cmp::PartialEq for Header {
            #[inline]
            fn eq(&self, other: &Header) -> bool {
                self.alg == other.alg && self.typ == other.typ && self.key == other.key
                    && self.x5c == other.x5c && self.trust_chain == other.trust_chain
            }
        }
        #[automatically_derived]
        impl ::core::cmp::Eq for Header {
            #[inline]
            #[doc(hidden)]
            #[coverage(off)]
            fn assert_receiver_is_total_eq(&self) -> () {
                let _: ::core::cmp::AssertParamIsEq<Algorithm>;
                let _: ::core::cmp::AssertParamIsEq<Type>;
                let _: ::core::cmp::AssertParamIsEq<KeyType>;
                let _: ::core::cmp::AssertParamIsEq<Option<String>>;
                let _: ::core::cmp::AssertParamIsEq<Option<String>>;
            }
        }
        /// The JWT `typ` claim.
        pub enum Type {
            /// JWT `typ` for Verifiable Credential.
            #[default]
            #[serde(rename = "jwt")]
            Credential,
            /// JWT `typ` for Verifiable Presentation.
            #[serde(rename = "jwt")]
            Presentation,
            /// JWT `typ` for Authorization Request Object.
            #[serde(rename = "oauth-authz-req+jwt")]
            Request,
            /// JWT `typ` for Wallet's Proof of possession of key material.
            #[serde(rename = "openid4vci-proof+jwt")]
            Proof,
        }
        #[automatically_derived]
        impl ::core::clone::Clone for Type {
            #[inline]
            fn clone(&self) -> Type {
                match self {
                    Type::Credential => Type::Credential,
                    Type::Presentation => Type::Presentation,
                    Type::Request => Type::Request,
                    Type::Proof => Type::Proof,
                }
            }
        }
        #[automatically_derived]
        impl ::core::fmt::Debug for Type {
            #[inline]
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                ::core::fmt::Formatter::write_str(
                    f,
                    match self {
                        Type::Credential => "Credential",
                        Type::Presentation => "Presentation",
                        Type::Request => "Request",
                        Type::Proof => "Proof",
                    },
                )
            }
        }
        #[automatically_derived]
        impl ::core::default::Default for Type {
            #[inline]
            fn default() -> Type {
                Self::Credential
            }
        }
        #[doc(hidden)]
        #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
        const _: () = {
            #[allow(unused_extern_crates, clippy::useless_attribute)]
            extern crate serde as _serde;
            #[automatically_derived]
            impl<'de> _serde::Deserialize<'de> for Type {
                fn deserialize<__D>(
                    __deserializer: __D,
                ) -> _serde::__private::Result<Self, __D::Error>
                where
                    __D: _serde::Deserializer<'de>,
                {
                    #[allow(non_camel_case_types)]
                    #[doc(hidden)]
                    enum __Field {
                        __field0,
                        __field1,
                        __field2,
                        __field3,
                    }
                    #[doc(hidden)]
                    struct __FieldVisitor;
                    impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                        type Value = __Field;
                        fn expecting(
                            &self,
                            __formatter: &mut _serde::__private::Formatter,
                        ) -> _serde::__private::fmt::Result {
                            _serde::__private::Formatter::write_str(
                                __formatter,
                                "variant identifier",
                            )
                        }
                        fn visit_u64<__E>(
                            self,
                            __value: u64,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                0u64 => _serde::__private::Ok(__Field::__field0),
                                1u64 => _serde::__private::Ok(__Field::__field1),
                                2u64 => _serde::__private::Ok(__Field::__field2),
                                3u64 => _serde::__private::Ok(__Field::__field3),
                                _ => {
                                    _serde::__private::Err(
                                        _serde::de::Error::invalid_value(
                                            _serde::de::Unexpected::Unsigned(__value),
                                            &"variant index 0 <= i < 4",
                                        ),
                                    )
                                }
                            }
                        }
                        fn visit_str<__E>(
                            self,
                            __value: &str,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                "jwt" => _serde::__private::Ok(__Field::__field0),
                                "jwt" => _serde::__private::Ok(__Field::__field1),
                                "oauth-authz-req+jwt" => {
                                    _serde::__private::Ok(__Field::__field2)
                                }
                                "openid4vci-proof+jwt" => {
                                    _serde::__private::Ok(__Field::__field3)
                                }
                                _ => {
                                    _serde::__private::Err(
                                        _serde::de::Error::unknown_variant(__value, VARIANTS),
                                    )
                                }
                            }
                        }
                        fn visit_bytes<__E>(
                            self,
                            __value: &[u8],
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                b"jwt" => _serde::__private::Ok(__Field::__field0),
                                b"jwt" => _serde::__private::Ok(__Field::__field1),
                                b"oauth-authz-req+jwt" => {
                                    _serde::__private::Ok(__Field::__field2)
                                }
                                b"openid4vci-proof+jwt" => {
                                    _serde::__private::Ok(__Field::__field3)
                                }
                                _ => {
                                    let __value = &_serde::__private::from_utf8_lossy(__value);
                                    _serde::__private::Err(
                                        _serde::de::Error::unknown_variant(__value, VARIANTS),
                                    )
                                }
                            }
                        }
                    }
                    impl<'de> _serde::Deserialize<'de> for __Field {
                        #[inline]
                        fn deserialize<__D>(
                            __deserializer: __D,
                        ) -> _serde::__private::Result<Self, __D::Error>
                        where
                            __D: _serde::Deserializer<'de>,
                        {
                            _serde::Deserializer::deserialize_identifier(
                                __deserializer,
                                __FieldVisitor,
                            )
                        }
                    }
                    #[doc(hidden)]
                    struct __Visitor<'de> {
                        marker: _serde::__private::PhantomData<Type>,
                        lifetime: _serde::__private::PhantomData<&'de ()>,
                    }
                    impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                        type Value = Type;
                        fn expecting(
                            &self,
                            __formatter: &mut _serde::__private::Formatter,
                        ) -> _serde::__private::fmt::Result {
                            _serde::__private::Formatter::write_str(
                                __formatter,
                                "enum Type",
                            )
                        }
                        fn visit_enum<__A>(
                            self,
                            __data: __A,
                        ) -> _serde::__private::Result<Self::Value, __A::Error>
                        where
                            __A: _serde::de::EnumAccess<'de>,
                        {
                            match _serde::de::EnumAccess::variant(__data)? {
                                (__Field::__field0, __variant) => {
                                    _serde::de::VariantAccess::unit_variant(__variant)?;
                                    _serde::__private::Ok(Type::Credential)
                                }
                                (__Field::__field1, __variant) => {
                                    _serde::de::VariantAccess::unit_variant(__variant)?;
                                    _serde::__private::Ok(Type::Presentation)
                                }
                                (__Field::__field2, __variant) => {
                                    _serde::de::VariantAccess::unit_variant(__variant)?;
                                    _serde::__private::Ok(Type::Request)
                                }
                                (__Field::__field3, __variant) => {
                                    _serde::de::VariantAccess::unit_variant(__variant)?;
                                    _serde::__private::Ok(Type::Proof)
                                }
                            }
                        }
                    }
                    #[doc(hidden)]
                    const VARIANTS: &'static [&'static str] = &[
                        "jwt",
                        "jwt",
                        "oauth-authz-req+jwt",
                        "openid4vci-proof+jwt",
                    ];
                    _serde::Deserializer::deserialize_enum(
                        __deserializer,
                        "Type",
                        VARIANTS,
                        __Visitor {
                            marker: _serde::__private::PhantomData::<Type>,
                            lifetime: _serde::__private::PhantomData,
                        },
                    )
                }
            }
        };
        #[doc(hidden)]
        #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
        const _: () = {
            #[allow(unused_extern_crates, clippy::useless_attribute)]
            extern crate serde as _serde;
            #[automatically_derived]
            impl _serde::Serialize for Type {
                fn serialize<__S>(
                    &self,
                    __serializer: __S,
                ) -> _serde::__private::Result<__S::Ok, __S::Error>
                where
                    __S: _serde::Serializer,
                {
                    match *self {
                        Type::Credential => {
                            _serde::Serializer::serialize_unit_variant(
                                __serializer,
                                "Type",
                                0u32,
                                "jwt",
                            )
                        }
                        Type::Presentation => {
                            _serde::Serializer::serialize_unit_variant(
                                __serializer,
                                "Type",
                                1u32,
                                "jwt",
                            )
                        }
                        Type::Request => {
                            _serde::Serializer::serialize_unit_variant(
                                __serializer,
                                "Type",
                                2u32,
                                "oauth-authz-req+jwt",
                            )
                        }
                        Type::Proof => {
                            _serde::Serializer::serialize_unit_variant(
                                __serializer,
                                "Type",
                                3u32,
                                "openid4vci-proof+jwt",
                            )
                        }
                    }
                }
            }
        };
        #[automatically_derived]
        impl ::core::marker::StructuralPartialEq for Type {}
        #[automatically_derived]
        impl ::core::cmp::PartialEq for Type {
            #[inline]
            fn eq(&self, other: &Type) -> bool {
                let __self_discr = ::core::intrinsics::discriminant_value(self);
                let __arg1_discr = ::core::intrinsics::discriminant_value(other);
                __self_discr == __arg1_discr
            }
        }
        #[automatically_derived]
        impl ::core::cmp::Eq for Type {
            #[inline]
            #[doc(hidden)]
            #[coverage(off)]
            fn assert_receiver_is_total_eq(&self) -> () {}
        }
        impl Display for Type {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_fmt(format_args!("{0:?}", self))
            }
        }
        /// The type of public key material for the JWT.
        pub enum KeyType {
            /// Contains the key ID. If the Credential is bound to a DID, the kid refers
            /// to a DID URL which identifies a particular key in the DID Document
            /// that the Credential should bound to. Alternatively, may refer to a
            /// key inside a JWKS.
            #[serde(rename = "kid")]
            KeyId(String),
            /// Contains the key material the new Credential shall be bound to.
            #[serde(rename = "jwk")]
            Jwk(PublicKeyJwk),
        }
        #[automatically_derived]
        impl ::core::clone::Clone for KeyType {
            #[inline]
            fn clone(&self) -> KeyType {
                match self {
                    KeyType::KeyId(__self_0) => {
                        KeyType::KeyId(::core::clone::Clone::clone(__self_0))
                    }
                    KeyType::Jwk(__self_0) => {
                        KeyType::Jwk(::core::clone::Clone::clone(__self_0))
                    }
                }
            }
        }
        #[automatically_derived]
        impl ::core::fmt::Debug for KeyType {
            #[inline]
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                match self {
                    KeyType::KeyId(__self_0) => {
                        ::core::fmt::Formatter::debug_tuple_field1_finish(
                            f,
                            "KeyId",
                            &__self_0,
                        )
                    }
                    KeyType::Jwk(__self_0) => {
                        ::core::fmt::Formatter::debug_tuple_field1_finish(
                            f,
                            "Jwk",
                            &__self_0,
                        )
                    }
                }
            }
        }
        #[doc(hidden)]
        #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
        const _: () = {
            #[allow(unused_extern_crates, clippy::useless_attribute)]
            extern crate serde as _serde;
            #[automatically_derived]
            impl<'de> _serde::Deserialize<'de> for KeyType {
                fn deserialize<__D>(
                    __deserializer: __D,
                ) -> _serde::__private::Result<Self, __D::Error>
                where
                    __D: _serde::Deserializer<'de>,
                {
                    #[allow(non_camel_case_types)]
                    #[doc(hidden)]
                    enum __Field {
                        __field0,
                        __field1,
                    }
                    #[doc(hidden)]
                    struct __FieldVisitor;
                    impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                        type Value = __Field;
                        fn expecting(
                            &self,
                            __formatter: &mut _serde::__private::Formatter,
                        ) -> _serde::__private::fmt::Result {
                            _serde::__private::Formatter::write_str(
                                __formatter,
                                "variant identifier",
                            )
                        }
                        fn visit_u64<__E>(
                            self,
                            __value: u64,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                0u64 => _serde::__private::Ok(__Field::__field0),
                                1u64 => _serde::__private::Ok(__Field::__field1),
                                _ => {
                                    _serde::__private::Err(
                                        _serde::de::Error::invalid_value(
                                            _serde::de::Unexpected::Unsigned(__value),
                                            &"variant index 0 <= i < 2",
                                        ),
                                    )
                                }
                            }
                        }
                        fn visit_str<__E>(
                            self,
                            __value: &str,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                "kid" => _serde::__private::Ok(__Field::__field0),
                                "jwk" => _serde::__private::Ok(__Field::__field1),
                                _ => {
                                    _serde::__private::Err(
                                        _serde::de::Error::unknown_variant(__value, VARIANTS),
                                    )
                                }
                            }
                        }
                        fn visit_bytes<__E>(
                            self,
                            __value: &[u8],
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                b"kid" => _serde::__private::Ok(__Field::__field0),
                                b"jwk" => _serde::__private::Ok(__Field::__field1),
                                _ => {
                                    let __value = &_serde::__private::from_utf8_lossy(__value);
                                    _serde::__private::Err(
                                        _serde::de::Error::unknown_variant(__value, VARIANTS),
                                    )
                                }
                            }
                        }
                    }
                    impl<'de> _serde::Deserialize<'de> for __Field {
                        #[inline]
                        fn deserialize<__D>(
                            __deserializer: __D,
                        ) -> _serde::__private::Result<Self, __D::Error>
                        where
                            __D: _serde::Deserializer<'de>,
                        {
                            _serde::Deserializer::deserialize_identifier(
                                __deserializer,
                                __FieldVisitor,
                            )
                        }
                    }
                    #[doc(hidden)]
                    struct __Visitor<'de> {
                        marker: _serde::__private::PhantomData<KeyType>,
                        lifetime: _serde::__private::PhantomData<&'de ()>,
                    }
                    impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                        type Value = KeyType;
                        fn expecting(
                            &self,
                            __formatter: &mut _serde::__private::Formatter,
                        ) -> _serde::__private::fmt::Result {
                            _serde::__private::Formatter::write_str(
                                __formatter,
                                "enum KeyType",
                            )
                        }
                        fn visit_enum<__A>(
                            self,
                            __data: __A,
                        ) -> _serde::__private::Result<Self::Value, __A::Error>
                        where
                            __A: _serde::de::EnumAccess<'de>,
                        {
                            match _serde::de::EnumAccess::variant(__data)? {
                                (__Field::__field0, __variant) => {
                                    _serde::__private::Result::map(
                                        _serde::de::VariantAccess::newtype_variant::<
                                            String,
                                        >(__variant),
                                        KeyType::KeyId,
                                    )
                                }
                                (__Field::__field1, __variant) => {
                                    _serde::__private::Result::map(
                                        _serde::de::VariantAccess::newtype_variant::<
                                            PublicKeyJwk,
                                        >(__variant),
                                        KeyType::Jwk,
                                    )
                                }
                            }
                        }
                    }
                    #[doc(hidden)]
                    const VARIANTS: &'static [&'static str] = &["kid", "jwk"];
                    _serde::Deserializer::deserialize_enum(
                        __deserializer,
                        "KeyType",
                        VARIANTS,
                        __Visitor {
                            marker: _serde::__private::PhantomData::<KeyType>,
                            lifetime: _serde::__private::PhantomData,
                        },
                    )
                }
            }
        };
        #[doc(hidden)]
        #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
        const _: () = {
            #[allow(unused_extern_crates, clippy::useless_attribute)]
            extern crate serde as _serde;
            #[automatically_derived]
            impl _serde::Serialize for KeyType {
                fn serialize<__S>(
                    &self,
                    __serializer: __S,
                ) -> _serde::__private::Result<__S::Ok, __S::Error>
                where
                    __S: _serde::Serializer,
                {
                    match *self {
                        KeyType::KeyId(ref __field0) => {
                            _serde::Serializer::serialize_newtype_variant(
                                __serializer,
                                "KeyType",
                                0u32,
                                "kid",
                                __field0,
                            )
                        }
                        KeyType::Jwk(ref __field0) => {
                            _serde::Serializer::serialize_newtype_variant(
                                __serializer,
                                "KeyType",
                                1u32,
                                "jwk",
                                __field0,
                            )
                        }
                    }
                }
            }
        };
        #[automatically_derived]
        impl ::core::marker::StructuralPartialEq for KeyType {}
        #[automatically_derived]
        impl ::core::cmp::PartialEq for KeyType {
            #[inline]
            fn eq(&self, other: &KeyType) -> bool {
                let __self_discr = ::core::intrinsics::discriminant_value(self);
                let __arg1_discr = ::core::intrinsics::discriminant_value(other);
                __self_discr == __arg1_discr
                    && match (self, other) {
                        (KeyType::KeyId(__self_0), KeyType::KeyId(__arg1_0)) => {
                            __self_0 == __arg1_0
                        }
                        (KeyType::Jwk(__self_0), KeyType::Jwk(__arg1_0)) => {
                            __self_0 == __arg1_0
                        }
                        _ => unsafe { ::core::intrinsics::unreachable() }
                    }
            }
        }
        #[automatically_derived]
        impl ::core::cmp::Eq for KeyType {
            #[inline]
            #[doc(hidden)]
            #[coverage(off)]
            fn assert_receiver_is_total_eq(&self) -> () {
                let _: ::core::cmp::AssertParamIsEq<String>;
                let _: ::core::cmp::AssertParamIsEq<PublicKeyJwk>;
            }
        }
        impl Default for KeyType {
            fn default() -> Self {
                Self::KeyId(String::new())
            }
        }
    }
}
use std::future::{Future, IntoFuture};
use serde::{Deserialize, Serialize};
pub use crate::jose::jwa::Algorithm;
pub use crate::jose::jwk::PublicKeyJwk;
pub use crate::jose::jwt::Jwt;
/// The `SecOps` trait is used to provide methods needed for signing,
/// encrypting, verifying, and decrypting data.
///
/// Implementers of this trait are expected to provide the necessary
/// cryptographic functionality to support Verifiable Credential issuance and
/// Verifiable Presentation submissions.
pub trait SecOps: Send + Sync {
    /// Signer provides digital signing-related funtionality.
    /// The `identifier` parameter is one of `credential_issuer` or
    /// `verifier_id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the signer cannot be created.
    fn signer(&self, identifier: &str) -> anyhow::Result<impl Signer>;
    /// Encryptor provides data encryption functionality.
    ///
    /// # Errors
    ///
    /// Returns an error if the encryptor cannot be created.
    fn encryptor(&self, identifier: &str) -> anyhow::Result<impl Encryptor>;
    /// Decryptor provides data decryption functionality.
    ///
    /// # Errors
    ///
    /// Returns an error if the decryptor cannot be created.
    fn decryptor(&self, identifier: &str) -> anyhow::Result<impl Decryptor>;
}
/// Signer is used by implementers to provide signing functionality for
/// Verifiable Credential issuance and Verifiable Presentation submissions.
pub trait Signer: Send + Sync {
    /// Sign is a convenience method for infallible Signer implementations.
    fn sign(&self, msg: &[u8]) -> impl Future<Output = Vec<u8>> + Send {
        let v = async { self.try_sign(msg).await.expect("should sign") };
        v.into_future()
    }
    /// `TrySign` is the fallible version of Sign.
    fn try_sign(
        &self,
        msg: &[u8],
    ) -> impl Future<Output = anyhow::Result<Vec<u8>>> + Send;
    /// The public key of the key pair used in signing. The possibility of key
    /// rotation mean this key should only be referenced at the point of signing.
    fn public_key(&self) -> impl Future<Output = anyhow::Result<Vec<u8>>> + Send;
    /// Algorithm returns the algorithm used by the signer.
    fn algorithm(&self) -> Algorithm;
    /// The verification method the verifier should use to verify the signer's
    /// signature. This is typically a DID URL + # + verification key ID.
    fn verification_method(&self) -> String;
}
/// Encryptor is used by implementers to provide encryption functionality for
/// Verifiable Credential issuance and Verifiable Presentation submissions.
pub trait Encryptor: Send + Sync {
    /// Encrypt the plaintext using the recipient's public key.
    fn encrypt(
        &self,
        plaintext: &[u8],
        recipient_public_key: &[u8],
    ) -> impl Future<Output = anyhow::Result<Vec<u8>>> + Send;
    /// The public key of the encryptor.
    fn public_key(&self) -> Vec<u8>;
}
/// Decryptor is used by implementers to provide decryption functionality for
/// Verifiable Credential issuance and Verifiable Presentation submissions.
pub trait Decryptor: Send + Sync {
    /// Decrypt the ciphertext using the sender's public key.
    fn decrypt(
        &self,
        ciphertext: &[u8],
        sender_public_key: &[u8],
    ) -> impl Future<Output = anyhow::Result<Vec<u8>>> + Send;
}
/// Cryptographic key type.
pub enum KeyType {
    /// Octet key pair (Edwards curve)
    #[default]
    #[serde(rename = "OKP")]
    Okp,
    /// Elliptic curve key pair
    #[serde(rename = "EC")]
    Ec,
    /// Octet string
    #[serde(rename = "oct")]
    Oct,
}
#[automatically_derived]
impl ::core::clone::Clone for KeyType {
    #[inline]
    fn clone(&self) -> KeyType {
        match self {
            KeyType::Okp => KeyType::Okp,
            KeyType::Ec => KeyType::Ec,
            KeyType::Oct => KeyType::Oct,
        }
    }
}
#[automatically_derived]
impl ::core::fmt::Debug for KeyType {
    #[inline]
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        ::core::fmt::Formatter::write_str(
            f,
            match self {
                KeyType::Okp => "Okp",
                KeyType::Ec => "Ec",
                KeyType::Oct => "Oct",
            },
        )
    }
}
#[automatically_derived]
impl ::core::default::Default for KeyType {
    #[inline]
    fn default() -> KeyType {
        Self::Okp
    }
}
#[doc(hidden)]
#[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
const _: () = {
    #[allow(unused_extern_crates, clippy::useless_attribute)]
    extern crate serde as _serde;
    #[automatically_derived]
    impl<'de> _serde::Deserialize<'de> for KeyType {
        fn deserialize<__D>(
            __deserializer: __D,
        ) -> _serde::__private::Result<Self, __D::Error>
        where
            __D: _serde::Deserializer<'de>,
        {
            #[allow(non_camel_case_types)]
            #[doc(hidden)]
            enum __Field {
                __field0,
                __field1,
                __field2,
            }
            #[doc(hidden)]
            struct __FieldVisitor;
            impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                type Value = __Field;
                fn expecting(
                    &self,
                    __formatter: &mut _serde::__private::Formatter,
                ) -> _serde::__private::fmt::Result {
                    _serde::__private::Formatter::write_str(
                        __formatter,
                        "variant identifier",
                    )
                }
                fn visit_u64<__E>(
                    self,
                    __value: u64,
                ) -> _serde::__private::Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        0u64 => _serde::__private::Ok(__Field::__field0),
                        1u64 => _serde::__private::Ok(__Field::__field1),
                        2u64 => _serde::__private::Ok(__Field::__field2),
                        _ => {
                            _serde::__private::Err(
                                _serde::de::Error::invalid_value(
                                    _serde::de::Unexpected::Unsigned(__value),
                                    &"variant index 0 <= i < 3",
                                ),
                            )
                        }
                    }
                }
                fn visit_str<__E>(
                    self,
                    __value: &str,
                ) -> _serde::__private::Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        "OKP" => _serde::__private::Ok(__Field::__field0),
                        "EC" => _serde::__private::Ok(__Field::__field1),
                        "oct" => _serde::__private::Ok(__Field::__field2),
                        _ => {
                            _serde::__private::Err(
                                _serde::de::Error::unknown_variant(__value, VARIANTS),
                            )
                        }
                    }
                }
                fn visit_bytes<__E>(
                    self,
                    __value: &[u8],
                ) -> _serde::__private::Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        b"OKP" => _serde::__private::Ok(__Field::__field0),
                        b"EC" => _serde::__private::Ok(__Field::__field1),
                        b"oct" => _serde::__private::Ok(__Field::__field2),
                        _ => {
                            let __value = &_serde::__private::from_utf8_lossy(__value);
                            _serde::__private::Err(
                                _serde::de::Error::unknown_variant(__value, VARIANTS),
                            )
                        }
                    }
                }
            }
            impl<'de> _serde::Deserialize<'de> for __Field {
                #[inline]
                fn deserialize<__D>(
                    __deserializer: __D,
                ) -> _serde::__private::Result<Self, __D::Error>
                where
                    __D: _serde::Deserializer<'de>,
                {
                    _serde::Deserializer::deserialize_identifier(
                        __deserializer,
                        __FieldVisitor,
                    )
                }
            }
            #[doc(hidden)]
            struct __Visitor<'de> {
                marker: _serde::__private::PhantomData<KeyType>,
                lifetime: _serde::__private::PhantomData<&'de ()>,
            }
            impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                type Value = KeyType;
                fn expecting(
                    &self,
                    __formatter: &mut _serde::__private::Formatter,
                ) -> _serde::__private::fmt::Result {
                    _serde::__private::Formatter::write_str(__formatter, "enum KeyType")
                }
                fn visit_enum<__A>(
                    self,
                    __data: __A,
                ) -> _serde::__private::Result<Self::Value, __A::Error>
                where
                    __A: _serde::de::EnumAccess<'de>,
                {
                    match _serde::de::EnumAccess::variant(__data)? {
                        (__Field::__field0, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            _serde::__private::Ok(KeyType::Okp)
                        }
                        (__Field::__field1, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            _serde::__private::Ok(KeyType::Ec)
                        }
                        (__Field::__field2, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            _serde::__private::Ok(KeyType::Oct)
                        }
                    }
                }
            }
            #[doc(hidden)]
            const VARIANTS: &'static [&'static str] = &["OKP", "EC", "oct"];
            _serde::Deserializer::deserialize_enum(
                __deserializer,
                "KeyType",
                VARIANTS,
                __Visitor {
                    marker: _serde::__private::PhantomData::<KeyType>,
                    lifetime: _serde::__private::PhantomData,
                },
            )
        }
    }
};
#[doc(hidden)]
#[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
const _: () = {
    #[allow(unused_extern_crates, clippy::useless_attribute)]
    extern crate serde as _serde;
    #[automatically_derived]
    impl _serde::Serialize for KeyType {
        fn serialize<__S>(
            &self,
            __serializer: __S,
        ) -> _serde::__private::Result<__S::Ok, __S::Error>
        where
            __S: _serde::Serializer,
        {
            match *self {
                KeyType::Okp => {
                    _serde::Serializer::serialize_unit_variant(
                        __serializer,
                        "KeyType",
                        0u32,
                        "OKP",
                    )
                }
                KeyType::Ec => {
                    _serde::Serializer::serialize_unit_variant(
                        __serializer,
                        "KeyType",
                        1u32,
                        "EC",
                    )
                }
                KeyType::Oct => {
                    _serde::Serializer::serialize_unit_variant(
                        __serializer,
                        "KeyType",
                        2u32,
                        "oct",
                    )
                }
            }
        }
    }
};
#[automatically_derived]
impl ::core::cmp::Eq for KeyType {
    #[inline]
    #[doc(hidden)]
    #[coverage(off)]
    fn assert_receiver_is_total_eq(&self) -> () {}
}
#[automatically_derived]
impl ::core::marker::StructuralPartialEq for KeyType {}
#[automatically_derived]
impl ::core::cmp::PartialEq for KeyType {
    #[inline]
    fn eq(&self, other: &KeyType) -> bool {
        let __self_discr = ::core::intrinsics::discriminant_value(self);
        let __arg1_discr = ::core::intrinsics::discriminant_value(other);
        __self_discr == __arg1_discr
    }
}
/// Cryptographic curve type.
pub enum Curve {
    /// Ed25519 curve
    #[default]
    Ed25519,
    /// secp256k1 curve
    #[serde(rename = "ES256K", alias = "secp256k1")]
    Es256K,
}
#[automatically_derived]
impl ::core::clone::Clone for Curve {
    #[inline]
    fn clone(&self) -> Curve {
        match self {
            Curve::Ed25519 => Curve::Ed25519,
            Curve::Es256K => Curve::Es256K,
        }
    }
}
#[automatically_derived]
impl ::core::fmt::Debug for Curve {
    #[inline]
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        ::core::fmt::Formatter::write_str(
            f,
            match self {
                Curve::Ed25519 => "Ed25519",
                Curve::Es256K => "Es256K",
            },
        )
    }
}
#[automatically_derived]
impl ::core::default::Default for Curve {
    #[inline]
    fn default() -> Curve {
        Self::Ed25519
    }
}
#[doc(hidden)]
#[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
const _: () = {
    #[allow(unused_extern_crates, clippy::useless_attribute)]
    extern crate serde as _serde;
    #[automatically_derived]
    impl<'de> _serde::Deserialize<'de> for Curve {
        fn deserialize<__D>(
            __deserializer: __D,
        ) -> _serde::__private::Result<Self, __D::Error>
        where
            __D: _serde::Deserializer<'de>,
        {
            #[allow(non_camel_case_types)]
            #[doc(hidden)]
            enum __Field {
                __field0,
                __field1,
            }
            #[doc(hidden)]
            struct __FieldVisitor;
            impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                type Value = __Field;
                fn expecting(
                    &self,
                    __formatter: &mut _serde::__private::Formatter,
                ) -> _serde::__private::fmt::Result {
                    _serde::__private::Formatter::write_str(
                        __formatter,
                        "variant identifier",
                    )
                }
                fn visit_u64<__E>(
                    self,
                    __value: u64,
                ) -> _serde::__private::Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        0u64 => _serde::__private::Ok(__Field::__field0),
                        1u64 => _serde::__private::Ok(__Field::__field1),
                        _ => {
                            _serde::__private::Err(
                                _serde::de::Error::invalid_value(
                                    _serde::de::Unexpected::Unsigned(__value),
                                    &"variant index 0 <= i < 2",
                                ),
                            )
                        }
                    }
                }
                fn visit_str<__E>(
                    self,
                    __value: &str,
                ) -> _serde::__private::Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        "Ed25519" => _serde::__private::Ok(__Field::__field0),
                        "ES256K" | "secp256k1" => {
                            _serde::__private::Ok(__Field::__field1)
                        }
                        _ => {
                            _serde::__private::Err(
                                _serde::de::Error::unknown_variant(__value, VARIANTS),
                            )
                        }
                    }
                }
                fn visit_bytes<__E>(
                    self,
                    __value: &[u8],
                ) -> _serde::__private::Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        b"Ed25519" => _serde::__private::Ok(__Field::__field0),
                        b"ES256K" | b"secp256k1" => {
                            _serde::__private::Ok(__Field::__field1)
                        }
                        _ => {
                            let __value = &_serde::__private::from_utf8_lossy(__value);
                            _serde::__private::Err(
                                _serde::de::Error::unknown_variant(__value, VARIANTS),
                            )
                        }
                    }
                }
            }
            impl<'de> _serde::Deserialize<'de> for __Field {
                #[inline]
                fn deserialize<__D>(
                    __deserializer: __D,
                ) -> _serde::__private::Result<Self, __D::Error>
                where
                    __D: _serde::Deserializer<'de>,
                {
                    _serde::Deserializer::deserialize_identifier(
                        __deserializer,
                        __FieldVisitor,
                    )
                }
            }
            #[doc(hidden)]
            struct __Visitor<'de> {
                marker: _serde::__private::PhantomData<Curve>,
                lifetime: _serde::__private::PhantomData<&'de ()>,
            }
            impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                type Value = Curve;
                fn expecting(
                    &self,
                    __formatter: &mut _serde::__private::Formatter,
                ) -> _serde::__private::fmt::Result {
                    _serde::__private::Formatter::write_str(__formatter, "enum Curve")
                }
                fn visit_enum<__A>(
                    self,
                    __data: __A,
                ) -> _serde::__private::Result<Self::Value, __A::Error>
                where
                    __A: _serde::de::EnumAccess<'de>,
                {
                    match _serde::de::EnumAccess::variant(__data)? {
                        (__Field::__field0, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            _serde::__private::Ok(Curve::Ed25519)
                        }
                        (__Field::__field1, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            _serde::__private::Ok(Curve::Es256K)
                        }
                    }
                }
            }
            #[doc(hidden)]
            const VARIANTS: &'static [&'static str] = &["Ed25519", "ES256K"];
            _serde::Deserializer::deserialize_enum(
                __deserializer,
                "Curve",
                VARIANTS,
                __Visitor {
                    marker: _serde::__private::PhantomData::<Curve>,
                    lifetime: _serde::__private::PhantomData,
                },
            )
        }
    }
};
#[doc(hidden)]
#[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
const _: () = {
    #[allow(unused_extern_crates, clippy::useless_attribute)]
    extern crate serde as _serde;
    #[automatically_derived]
    impl _serde::Serialize for Curve {
        fn serialize<__S>(
            &self,
            __serializer: __S,
        ) -> _serde::__private::Result<__S::Ok, __S::Error>
        where
            __S: _serde::Serializer,
        {
            match *self {
                Curve::Ed25519 => {
                    _serde::Serializer::serialize_unit_variant(
                        __serializer,
                        "Curve",
                        0u32,
                        "Ed25519",
                    )
                }
                Curve::Es256K => {
                    _serde::Serializer::serialize_unit_variant(
                        __serializer,
                        "Curve",
                        1u32,
                        "ES256K",
                    )
                }
            }
        }
    }
};
#[automatically_derived]
impl ::core::cmp::Eq for Curve {
    #[inline]
    #[doc(hidden)]
    #[coverage(off)]
    fn assert_receiver_is_total_eq(&self) -> () {}
}
#[automatically_derived]
impl ::core::marker::StructuralPartialEq for Curve {}
#[automatically_derived]
impl ::core::cmp::PartialEq for Curve {
    #[inline]
    fn eq(&self, other: &Curve) -> bool {
        let __self_discr = ::core::intrinsics::discriminant_value(self);
        let __arg1_discr = ::core::intrinsics::discriminant_value(other);
        __self_discr == __arg1_discr
    }
}
/// The intended usage of the public `KeyType`. This enum is serialized
/// `untagged`
pub enum KeyUse {
    /// Public key is to be used for signature verification
    #[default]
    #[serde(rename = "sig")]
    Signature,
    /// Public key is to be used for encryption
    #[serde(rename = "enc")]
    Encryption,
}
#[automatically_derived]
impl ::core::clone::Clone for KeyUse {
    #[inline]
    fn clone(&self) -> KeyUse {
        match self {
            KeyUse::Signature => KeyUse::Signature,
            KeyUse::Encryption => KeyUse::Encryption,
        }
    }
}
#[automatically_derived]
impl ::core::fmt::Debug for KeyUse {
    #[inline]
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        ::core::fmt::Formatter::write_str(
            f,
            match self {
                KeyUse::Signature => "Signature",
                KeyUse::Encryption => "Encryption",
            },
        )
    }
}
#[automatically_derived]
impl ::core::default::Default for KeyUse {
    #[inline]
    fn default() -> KeyUse {
        Self::Signature
    }
}
#[doc(hidden)]
#[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
const _: () = {
    #[allow(unused_extern_crates, clippy::useless_attribute)]
    extern crate serde as _serde;
    #[automatically_derived]
    impl<'de> _serde::Deserialize<'de> for KeyUse {
        fn deserialize<__D>(
            __deserializer: __D,
        ) -> _serde::__private::Result<Self, __D::Error>
        where
            __D: _serde::Deserializer<'de>,
        {
            #[allow(non_camel_case_types)]
            #[doc(hidden)]
            enum __Field {
                __field0,
                __field1,
            }
            #[doc(hidden)]
            struct __FieldVisitor;
            impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                type Value = __Field;
                fn expecting(
                    &self,
                    __formatter: &mut _serde::__private::Formatter,
                ) -> _serde::__private::fmt::Result {
                    _serde::__private::Formatter::write_str(
                        __formatter,
                        "variant identifier",
                    )
                }
                fn visit_u64<__E>(
                    self,
                    __value: u64,
                ) -> _serde::__private::Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        0u64 => _serde::__private::Ok(__Field::__field0),
                        1u64 => _serde::__private::Ok(__Field::__field1),
                        _ => {
                            _serde::__private::Err(
                                _serde::de::Error::invalid_value(
                                    _serde::de::Unexpected::Unsigned(__value),
                                    &"variant index 0 <= i < 2",
                                ),
                            )
                        }
                    }
                }
                fn visit_str<__E>(
                    self,
                    __value: &str,
                ) -> _serde::__private::Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        "sig" => _serde::__private::Ok(__Field::__field0),
                        "enc" => _serde::__private::Ok(__Field::__field1),
                        _ => {
                            _serde::__private::Err(
                                _serde::de::Error::unknown_variant(__value, VARIANTS),
                            )
                        }
                    }
                }
                fn visit_bytes<__E>(
                    self,
                    __value: &[u8],
                ) -> _serde::__private::Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        b"sig" => _serde::__private::Ok(__Field::__field0),
                        b"enc" => _serde::__private::Ok(__Field::__field1),
                        _ => {
                            let __value = &_serde::__private::from_utf8_lossy(__value);
                            _serde::__private::Err(
                                _serde::de::Error::unknown_variant(__value, VARIANTS),
                            )
                        }
                    }
                }
            }
            impl<'de> _serde::Deserialize<'de> for __Field {
                #[inline]
                fn deserialize<__D>(
                    __deserializer: __D,
                ) -> _serde::__private::Result<Self, __D::Error>
                where
                    __D: _serde::Deserializer<'de>,
                {
                    _serde::Deserializer::deserialize_identifier(
                        __deserializer,
                        __FieldVisitor,
                    )
                }
            }
            #[doc(hidden)]
            struct __Visitor<'de> {
                marker: _serde::__private::PhantomData<KeyUse>,
                lifetime: _serde::__private::PhantomData<&'de ()>,
            }
            impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                type Value = KeyUse;
                fn expecting(
                    &self,
                    __formatter: &mut _serde::__private::Formatter,
                ) -> _serde::__private::fmt::Result {
                    _serde::__private::Formatter::write_str(__formatter, "enum KeyUse")
                }
                fn visit_enum<__A>(
                    self,
                    __data: __A,
                ) -> _serde::__private::Result<Self::Value, __A::Error>
                where
                    __A: _serde::de::EnumAccess<'de>,
                {
                    match _serde::de::EnumAccess::variant(__data)? {
                        (__Field::__field0, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            _serde::__private::Ok(KeyUse::Signature)
                        }
                        (__Field::__field1, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            _serde::__private::Ok(KeyUse::Encryption)
                        }
                    }
                }
            }
            #[doc(hidden)]
            const VARIANTS: &'static [&'static str] = &["sig", "enc"];
            _serde::Deserializer::deserialize_enum(
                __deserializer,
                "KeyUse",
                VARIANTS,
                __Visitor {
                    marker: _serde::__private::PhantomData::<KeyUse>,
                    lifetime: _serde::__private::PhantomData,
                },
            )
        }
    }
};
#[doc(hidden)]
#[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
const _: () = {
    #[allow(unused_extern_crates, clippy::useless_attribute)]
    extern crate serde as _serde;
    #[automatically_derived]
    impl _serde::Serialize for KeyUse {
        fn serialize<__S>(
            &self,
            __serializer: __S,
        ) -> _serde::__private::Result<__S::Ok, __S::Error>
        where
            __S: _serde::Serializer,
        {
            match *self {
                KeyUse::Signature => {
                    _serde::Serializer::serialize_unit_variant(
                        __serializer,
                        "KeyUse",
                        0u32,
                        "sig",
                    )
                }
                KeyUse::Encryption => {
                    _serde::Serializer::serialize_unit_variant(
                        __serializer,
                        "KeyUse",
                        1u32,
                        "enc",
                    )
                }
            }
        }
    }
};
#[automatically_derived]
impl ::core::marker::StructuralPartialEq for KeyUse {}
#[automatically_derived]
impl ::core::cmp::PartialEq for KeyUse {
    #[inline]
    fn eq(&self, other: &KeyUse) -> bool {
        let __self_discr = ::core::intrinsics::discriminant_value(self);
        let __arg1_discr = ::core::intrinsics::discriminant_value(other);
        __self_discr == __arg1_discr
    }
}
#[automatically_derived]
impl ::core::cmp::Eq for KeyUse {
    #[inline]
    #[doc(hidden)]
    #[coverage(off)]
    fn assert_receiver_is_total_eq(&self) -> () {}
}
