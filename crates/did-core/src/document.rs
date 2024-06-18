//! # DID Document
//!
//! A DID Document is a JSON-LD document that contains information related to a DID.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DidDocument {
    #[serde(rename = "@context")]
    pub context: Vec<Context>,

    /// The DID URI for the document
    pub id: String,

    /// A set of URI other identifiers for the subject of the DID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub also_known_as: Option<Vec<String>>,

    /// a string or a set of strings that conform to the rules in 3.1 DID Syntax. The corresponding DID document(s) SHOULD contain verification relationships that explicitly permit the use of certain verification methods for specific purposes.
    // When a controller property is present in a DID document, its value expresses one or more DIDs. Any verification methods contained in the DID documents for those DIDs SHOULD be accepted as authoritative, such that proofs that satisfy those verification methods are to be considered equivalent to proofs provided by the DID subject.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller: Option<Controller<String>>,

    // #[serde(with = "str_obj")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<Vec<Service>>,

    /// A set of objects containing claims about credential subjects(s).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_method: Option<Vec<VerificationMethod>>,

    // #[serde(with = "str_obj")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<Vec<Method>>,

    // #[serde(with = "str_obj")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assertion_method: Option<Vec<Method>>,

    // #[serde(with = "str_obj")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_delegation: Option<Vec<Method>>,

    // #[serde(with = "str_obj")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_invocation: Option<Vec<Method>>,

    // #[serde(with = "str_obj")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_agreement: Option<Vec<Method>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_document_metadata: Option<DidDocumentMetadata>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    pub id: String,

    #[serde(rename = "type")]
    pub type_: String,

    pub service_endpoint: ServiceEndpoint,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ServiceEndpoint {
    pub origins: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VerificationMethod {
    pub id: String,

    #[serde(rename = "type")]
    pub type_: String,

    pub controller: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_multibase: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<PublicKeyJwk>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct PublicKeyJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DidDocumentMetadata {
    pub method: MethodMetadata,
    pub equivalent_id: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MethodMetadata {
    pub published: bool,
    pub recovery_commitment: String,
    pub update_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Method {
    String(String),
    Map(VerificationMethod),
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Context {
    String(String),
    Map(Value),
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
// #[serde(try_from = "String")]
// #[serde(into = "String")]
pub enum Controller<T> {
    One(T),
    Set(Vec<T>),
}

#[cfg(test)]
mod test {

    use std::sync::LazyLock;

    use serde_json::{json, Value};

    use super::*;

    #[test]
    fn serialize() {}

    #[test]
    fn deserialize_key() {
        let de: DidDocument =
            serde_json::from_value(DID_KEY.to_owned()).expect("should deserialize");
        println!("de: {de:?}");

        let ser = serde_json::to_value(de).expect("should serialize");
        assert_eq!(DID_KEY.to_owned(), ser)
    }

    static DID_KEY: LazyLock<Value> = LazyLock::new(|| {
        json!({
          "@context": [
            "https://www.w3.org/ns/did/v1",
            {
              "Ed25519VerificationKey2018": "https://w3id.org/security#Ed25519VerificationKey2018",
              "publicKeyJwk": {
                "@id": "https://w3id.org/security#publicKeyJwk",
                "@type": "@json"
              }
            }
          ],
          "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
          "verificationMethod": [
            {
              "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
              "type": "Ed25519VerificationKey2018",
              "controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
              "publicKeyJwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "Lm_M42cB3HkUiODQsXRcweM6TByfzEHGO9ND274JcOY"
              }
            }
          ],
          "authentication": [
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
          ],
          "assertionMethod": [
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
          ]
        })
    });
}
