//! # DID Document
//!
//! A DID Document is a JSON-LD document that contains information related to a DID.

use std::collections::HashMap;
use std::fmt::{self, Display, Formatter};

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use multibase::Base;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use vercre_core_utils::{Kind, Quota};

use crate::did::{self, Error};
use crate::jose::jwk::{Curve, KeyType, PublicKeyJwk};

const ED25519_CODEC: [u8; 2] = [0xed, 0x01];

/// DID Document
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Document {
    /// The context of the DID document.
    #[serde(rename = "@context")]
    pub context: Vec<Kind<Value>>,

    /// The DID for a particular DID subject.
    ///
    /// The subject is defined as the entity identified by the DID and described by the
    /// DID document. Anything can be a DID subject: person, group, organization,
    /// physical thing, digital thing, logical thing, etc.
    pub id: String,

    /// A set of URIs taht are other identifiers for the subject of the above DID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub also_known_as: Option<Vec<String>>,

    /// One or more strings that conform to the rules DID Syntax. The corresponding
    /// DID document(s) SHOULD contain verification relationships that explicitly
    /// permit the use of certain verification methods for specific purposes.
    ///
    /// Any verification methods contained in the related DID documents
    /// SHOULD be accepted as authoritative, such that proofs that satisfy those
    /// verification methods are to be considered equivalent to proofs provided by the
    /// DID subject.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller: Option<Quota<String>>,

    /// A set of services, that express ways of communicating with the DID subject
    /// or related entities.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<Vec<Service>>,

    /// If set, MUST be a set of verification methods for the DID subject.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_method: Option<Vec<VerificationMethod>>,

    /// -----------------------------------------------------------------------
    /// Verification Relationships
    ///
    /// A verification relationship expresses the relationship between the DID subject
    /// and a verification method.
    /// -----------------------------------------------------------------------

    /// The `authentication` verification relationship is used to specify how the DID
    /// subject is expected to be authenticated, for purposes such as logging into
    /// a website or engaging in any sort of challenge-response protocol.
    /// <https://www.w3.org/TR/did-core/#authentication>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<Vec<Kind<VerificationMethod>>>,

    /// The `assertion_method` verification relationship is used to specify how the DID
    /// subject is expected to express claims, such as for the purposes of issuing a
    /// Verifiable Credential.
    /// <https://www.w3.org/TR/did-core/#assertion>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assertion_method: Option<Vec<Kind<VerificationMethod>>>,

    /// The `key_agreement` verification relationship is used to specify how an entity
    /// can generate encryption material in order to transmit confidential information
    /// intended for the DID subject, such as for the purposes of establishing a secure
    /// communication channel with the recipient.
    /// <https://www.w3.org/TR/did-core/#key-agreement>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_agreement: Option<Vec<Kind<VerificationMethod>>>,

    /// The `capability_invocation` verification relationship is used to specify a
    /// verification method that might be used by the DID subject to invoke a
    /// cryptographic capability, such as the authorization to update the DID Document.
    /// <https://www.w3.org/TR/did-core/#capability-invocation>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_invocation: Option<Vec<Kind<VerificationMethod>>>,

    /// The `capability_delegation` verification relationship is used to specify a
    /// mechanism that might be used by the DID subject to delegate a cryptographic
    /// capability to another party, such as delegating the authority to access a
    /// specific HTTP API to a subordinate.
    /// <https://www.w3.org/TR/did-core/#capability-delegation>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_delegation: Option<Vec<Kind<VerificationMethod>>>,

    /// If resolution is successful, this MUST be metadata about the DID document.
    /// This typically does not change between invocations of the resolve and
    /// resolveRepresentation functions unless the DID document changes.
    /// If resolution is unsuccessful, this output MUST be an empty.
    /// <https://w3c.github.io/did-core/#dfn-diddocumentmetadata>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_document_metadata: Option<DocumentMetadata>,
}

/// Services are used to express ways of communicating with the DID subject or
/// associated entities. They can be any type of service the DID subject wants
/// to advertise, including decentralized identity management services for further
/// discovery, authentication, authorization, or interaction.
///
/// Service information is often service specific. For example, a reference to an
/// encrypted messaging service can detail how to initiate the encrypted link before
/// messaging begins.
///
/// Due to privacy concerns, revealing public information through services, such as
/// social media accounts, personal websites, and email addresses, is discouraged.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    /// A URI unique to the service.
    pub id: String,

    /// The service type. SHOULD be registered in the DID Specification Registries.
    #[serde(rename = "type")]
    pub type_: String,

    /// One or more endpoints for the service.
    #[allow(clippy::struct_field_names)]
    pub service_endpoint: Quota<Kind<Value>>,
}

/// A DID document can express verification methods, such as cryptographic public keys,
/// which can be used to authenticate or authorize interactions with the DID subject or
/// associated parties. For example, a cryptographic public key can be used as a
/// verification method with respect to a digital signature; in such usage, it verifies
/// that the signer could use the associated cryptographic private key. Verification
/// methods might take many parameters. An example of this is a set of five
/// cryptographic keys from which any three are required to contribute to a
/// cryptographic threshold signature.
///
/// MAY include additional properties which can be determined from the verification
/// method as registered in the
/// [DID Specification Registries](https://www.w3.org/TR/did-spec-registries/).
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VerificationMethod {
    /// Only used when the verification method uses terms not defined in the containing
    /// document.
    #[serde(rename = "@context")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<Kind<Value>>,

    /// A DID that identifies the verification method.
    pub id: String,

    /// The DID of the controller of the verification method.
    pub controller: String,

    /// The verification method type. SHOULD be a registered type (in DID Specification
    /// Registries).
    #[serde(flatten)]
    pub method_type: MethodType,
}

/// Verification method types. SHOULD be registered in the [DID Specification
/// Registries](https://www.w3.org/TR/did-spec-registries).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type")]
#[serde(rename_all_fields = "camelCase")]
pub enum MethodType {
    /// Key is encoded as a Multibase. The Multikey data model is a specific type of
    /// verification method that encodes key types into a single binary stream that
    /// is then encoded as a Multibase value.
    /// <https://w3c.github.io/controller-document/#multikey>
    #[serde(alias = "Ed25519VerificationKey2020")]
    Multikey {
        /// The public key encoded as a Multibase.
        public_key_multibase: String,
    },

    /// Key is JWK. The JSON Web Key (JWK) data model is a specific type of
    /// verification method that uses the JWK specification [RFC7517] to encode
    /// key types into a set of parameters.
    /// <https://w3c.github.io/controller-document/#jsonwebkey>
    #[serde(alias = "JsonWebKey2020")]
    #[serde(alias = "EcdsaSecp256k1VerificationKey2019")]
    JsonWebKey {
        /// The public key encoded as a JWK.
        public_key_jwk: PublicKeyJwk,
    },
    //
    // #[serde(alias = "Ed25519VerificationKey2018")]
    // Base58 { public_key_base58: String },
}

impl Default for MethodType {
    fn default() -> Self {
        Self::Multikey {
            public_key_multibase: String::new(),
        }
    }
}

impl MethodType {
    /// Converts a Multibase public key to JWK format.
    ///
    /// # Errors
    pub fn jwk(&self) -> did::Result<PublicKeyJwk> {
        match self {
            Self::JsonWebKey { public_key_jwk } => Ok(public_key_jwk.clone()),
            Self::Multikey { public_key_multibase } => {
                let (_, key_bytes) = multibase::decode(public_key_multibase)
                    .map_err(|e| Error::InvalidPublicKey(format!("issue decoding key: {e}")))?;
                if key_bytes.len() - 2 != 32 {
                    return Err(Error::InvalidPublicKeyLength("key is not 32 bytes long".into()));
                }
                if key_bytes[0..2] != ED25519_CODEC {
                    return Err(Error::InvalidPublicKey("not Ed25519".into()));
                }

                Ok(PublicKeyJwk {
                    kty: KeyType::Okp,
                    crv: Curve::Ed25519,
                    x: Base64UrlUnpadded::encode_string(&key_bytes[2..]),
                    ..PublicKeyJwk::default()
                })
            }
        }
    }

    /// Converts a JWK public key to Multibase format.
    ///
    /// # Errors
    pub fn multibase(&self) -> did::Result<String> {
        match self {
            Self::Multikey { public_key_multibase } => Ok(public_key_multibase.clone()),
            Self::JsonWebKey { public_key_jwk } => {
                let key_bytes = Base64UrlUnpadded::decode_vec(&public_key_jwk.x)
                    .map_err(|e| Error::InvalidPublicKey(format!("issue decoding key: {e}")))?;
                let mut multi_bytes = vec![];
                multi_bytes.extend_from_slice(&ED25519_CODEC);
                multi_bytes.extend_from_slice(&key_bytes);
                let multibase = multibase::encode(Base::Base58Btc, &multi_bytes);

                Ok(multibase)
            }
        }
    }
}

/// Verification method types. SHOULD be registered in the [DID Specification
/// Registries](https://www.w3.org/TR/did-spec-registries).
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum PublicKeyFormat {
    /// Key is encoded as a Multibase. The Multikey data model is a specific type of
    /// verification method that encodes key types into a single binary stream that
    /// is then encoded as a Multibase value.
    /// <https://w3c.github.io/controller-document/#multikey>
    #[default]
    Multikey,

    /// Key is JWK. The JSON Web Key (JWK) data model is a specific type of
    /// verification method that uses the JWK specification [RFC7517] to encode
    /// key types into a set of parameters.
    /// <https://w3c.github.io/controller-document/#jsonwebkey>
    JsonWebKey,

    /// Key is ED2559 Verification Key
    /// <https://w3id.org/security/suites/ed25519-2020/v1>
    Ed25519VerificationKey2020,

    /// X25519 Key Agreement Key, 2020 version
    X25519KeyAgreementKey2020,
}

// TODO: set context based on key format:
// - Ed25519VerificationKey2020	https://w3id.org/security/suites/ed25519-2020/v1
// - JsonWebKey2020	https://w3id.org/security/suites/jws-2020/v1

impl Display for PublicKeyFormat {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Multikey => write!(f, "Multikey"),
            Self::Ed25519VerificationKey2020 => write!(f, "Ed25519VerificationKey2020"),
            Self::X25519KeyAgreementKey2020 => write!(f, "X25519KeyAgreementKey2020"),
            Self::JsonWebKey => write!(f, "JsonWebKey"),
        }
    }
}

/// Cryptographic curve type.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum PublicKey {
    /// Public key encoded as a Multibase.
    #[serde(rename = "publicKeyMultibase")]
    Multibase(String),

    /// Public key encoded as a JWK.
    #[serde(rename = "publicKeyJwk")]
    Jwk(PublicKeyJwk),
}

impl Default for PublicKey {
    fn default() -> Self {
        Self::Multibase(String::new())
    }
}

impl PublicKey {
    /// Converts a Multibase public key to JWK format.
    ///
    /// # Errors
    pub fn jwk(&self) -> did::Result<PublicKeyJwk> {
        match self {
            Self::Jwk(jwk) => Ok(jwk.clone()),
            Self::Multibase(multi_key) => {
                let (_, key_bytes) = multibase::decode(multi_key)
                    .map_err(|e| Error::InvalidPublicKey(format!("issue decoding key: {e}")))?;
                if key_bytes.len() - 2 != 32 {
                    return Err(Error::InvalidPublicKeyLength("key is not 32 bytes long".into()));
                }
                if key_bytes[0..2] != ED25519_CODEC {
                    return Err(Error::InvalidPublicKey("not Ed25519".into()));
                }

                Ok(PublicKeyJwk {
                    kty: KeyType::Okp,
                    crv: Curve::Ed25519,
                    x: Base64UrlUnpadded::encode_string(&key_bytes[2..]),
                    ..PublicKeyJwk::default()
                })
            }
        }
    }

    /// Converts a JWK public key to Multibase format.
    ///
    /// # Errors
    pub fn multibase(&self) -> did::Result<String> {
        match self {
            Self::Multibase(multibase) => Ok(multibase.clone()),
            Self::Jwk(jwk) => {
                let key_bytes = Base64UrlUnpadded::decode_vec(&jwk.x)
                    .map_err(|e| Error::InvalidPublicKey(format!("issue decoding key: {e}")))?;
                let mut multi_bytes = vec![];
                multi_bytes.extend_from_slice(&ED25519_CODEC);
                multi_bytes.extend_from_slice(&key_bytes);
                let multibase = multibase::encode(Base::Base58Btc, &multi_bytes);

                Ok(multibase)
            }
        }
    }
}

/// DID document metadata. This typically does not change unless the DID document
/// changes.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::module_name_repetitions)]
pub struct DocumentMetadata {
    /// Timestamp of the Create operation.
    /// An XMLSCHEMA11-2 (RFC3339) e.g. 2010-01-01T19:23:24Z.
    created: DateTime<Utc>,

    /// Timestamp of the last Update operation. Omitted if an Update operation has
    /// never been performed. May be the same value as the `created` property when
    /// the difference between the two timestamps is less than one second.
    /// An XMLSCHEMA11-2 (RFC3339) e.g. 2010-01-01T19:23:24Z.
    #[serde(skip_serializing_if = "Option::is_none")]
    updated: Option<DateTime<Utc>>,

    /// MUST be set to true if the DID has been deactivated. Optional if the DID
    /// has not been deactivated.
    #[serde(skip_serializing_if = "Option::is_none")]
    deactivated: Option<bool>,

    /// May be set if the document version is not the latest. Indicates the timestamp
    /// of the next Update operation as an XMLSCHEMA11-2 (RFC3339).
    next_update: Option<DateTime<Utc>>,

    /// Used to indicate the version of the last Update operation. SHOULD be set.
    #[serde(skip_serializing_if = "Option::is_none")]
    version_id: Option<String>,

    /// MAY be set if the document version is not the latest. It indicates the version
    /// of the next Update operation.
    #[serde(skip_serializing_if = "Option::is_none")]
    next_version_id: Option<String>,

    /// Used when a DID method needs to define different forms of a DID that are
    /// logically equivalent. For example, when a DID takes one form prior to
    /// registration in a verifiable data registry and another form after such
    /// registration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub equivalent_id: Option<Vec<String>>,

    /// Identical to the `equivalent_id` property except that it is a single value
    /// AND the DID is the canonical ID for the DID subject within the containing
    /// DID document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canonical_id: Option<String>,
}

/// Options that can be provided when creating a DID document.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateOptions {
    /// Format to use for the the public key.
    pub public_key_format: PublicKeyFormat,

    /// Default context for the DID document. SHOULD be set to
    /// `"https://www.w3.org/ns/did/v1"`.
    pub default_context: String,

    /// Enable experimental public key types. SHOULD be set to "false".
    pub enable_experimental_public_key_types: bool,

    /// Will add a `keyAgreement` object to the DID document.
    pub enable_encryption_key_derivation: bool,

    // service_endpoints: Vec<Value>,
    // verification_methods: Vec<Value>,
    // authentication: Vec<Value>,
    //
    /// Additional options.
    #[serde(flatten)]
    pub additional: Option<HashMap<String, String>>,
}

impl Default for CreateOptions {
    fn default() -> Self {
        Self {
            public_key_format: PublicKeyFormat::default(),
            enable_experimental_public_key_types: false,
            default_context: "https://www.w3.org/ns/did/v1".to_string(),
            enable_encryption_key_derivation: false,
            additional: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_jwk() {
        let jwk = PublicKeyJwk {
            kty: KeyType::Okp,
            crv: Curve::Ed25519,
            x: "q6rjRnEH_XK72jvB8FNBJtOl9_gDs6NW49cAz6p2sW4".to_string(),
            ..PublicKeyJwk::default()
        };

        let public_key =
            PublicKey::Multibase("z6Mkr1NtupNezZtcUAMxJ79HPex6ZTR9RnGh8xfV257ZQdss".into());

        assert_eq!(
            "z6Mkr1NtupNezZtcUAMxJ79HPex6ZTR9RnGh8xfV257ZQdss",
            public_key.multibase().unwrap()
        );
        assert_eq!(jwk, public_key.jwk().unwrap());
    }
}
