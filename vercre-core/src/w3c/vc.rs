//! # W3C Verifiable Credentials Data Model
//!
//! An implementation of W3C Verifiable Credentials Data Model v1.1.
//!
//! See [specification] and[implementation guidelines].
//!
//! [Verifiable Credentials Data Model v1.1]: https://www.w3.org/TR/vc-data-model
//! [specification]: (https://www.w3.org/TR/vc-data-model)
//! [implementation guidelines]: (https://w3c.github.io/vc-imp-guide)

use std::collections::HashMap;
use std::convert::Infallible;
use std::str::FromStr;

use anyhow::anyhow;
use chrono::{DateTime, Utc};
use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, instrument, span, trace, Level};

use crate::jwt::{self, Jwt};
use crate::w3c::serde::{flexobj, flexvec, option_flexvec};
use crate::{err, error, Result};

/// `VerifiableCredential` represents a naive implementation of the W3C Verifiable
/// Credential data model v1.1.
/// See <https://www.w3.org/TR/vc-data-model>.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct VerifiableCredential {
    // LATER: add support for @context objects
    #[allow(rustdoc::bare_urls)]
    /// The @context property is used to map property URIs into short-form aliases.
    /// It is an ordered set where the first item is "`https://www.w3.org/2018/credentials/v1`".
    /// Subsequent items MUST express context information and can be either URIs or
    /// objects. Each URI, if dereferenced, should result in a document containing
    /// machine-readable information about the @context.
    #[cfg_attr(not(feature = "typegen"), serde(rename = "@context"))]
    pub context: Vec<String>,

    #[allow(rustdoc::bare_urls)]
    /// The credential's URI. It is RECOMMENDED that if dereferenced, the URI
    /// results in a document containing machine-readable information about
    /// the id (a schema). For example, "`http://example.edu/credentials/3732`".
    pub id: String,

    /// The type property is used to uniquely identify the type of the credential.
    /// That is, to indicate the set of claims the credential contains. It is an
    /// unordered set of URIs (full or relative to @context). It is RECOMMENDED that
    /// each URI, if dereferenced, will result in a document containing machine-readable
    /// information about the type. Syntactic conveniences, such as JSON-LD, SHOULD
    /// be used to ease developer usage.
    #[serde(rename = "type")]
    pub type_: Vec<String>,

    /// A URI or object with an id property. It is RECOMMENDED that the
    /// URI/object id, dereferences to machine-readable information about
    /// the issuer that can be used to verify credential information.
    #[serde(with = "flexobj")]
    pub issuer: Issuer,

    /// An XMLSCHEMA11-2 (RFC3339) date-time the credential becomes valid.
    /// e.g. 2010-01-01T19:23:24Z.
    #[serde(rename = "issuanceDate")]
    pub issuance_date: DateTime<Utc>,

    /// A set of objects containing claims about credential subjects(s).
    #[serde(rename = "credentialSubject")]
    #[serde(with = "flexvec")]
    pub credential_subject: Vec<CredentialSubject>,

    /// One or more cryptographic proofs that can be used to detect tampering
    /// and verify authorship of a credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "option_flexvec")]
    pub proof: Option<Vec<Proof>>,

    /// An XMLSCHEMA11-2 (RFC3339) date-time the credential ceases to be valid.
    /// e.g. 2010-06-30T19:23:24Z
    #[serde(rename = "expirationDate")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_date: Option<DateTime<Utc>>,

    /// Used to determine the status of the credential, such as whether it is
    /// suspended or revoked.
    #[serde(rename = "credentialStatus")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_status: Option<CredentialStatus>,

    /// The credentialSchema defines the structure and datatypes of the
    /// credential. Consists of one or more schemas that can be used to
    /// check credential data conformance.
    #[serde(rename = "credentialSchema")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "option_flexvec")]
    pub credential_schema: Option<Vec<CredentialSchema>>,

    /// `RefreshService` can be used to provide a link to the issuer's refresh
    /// service so Holder's can refresh (manually or automatically) an
    /// expired credential.
    #[serde(rename = "refreshService")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_service: Option<RefreshService>,

    /// Terms of use can be utilized by an issuer or a holder to communicate the
    /// terms under which a verifiable credential or verifiable presentation
    /// was issued.
    #[serde(rename = "termsOfUse")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terms_of_use: Option<Vec<Term>>,

    /// Evidence can be included by an issuer to provide the verifier with
    /// additional supporting information in a credential. This could be
    /// used by the verifier to establish the confidence with which it
    /// relies on credential claims.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Vec<Evidence>>,
}

impl VerifiableCredential {
    /// Returns a new [`VerifiableCredential`] configured with defaults.
    ///
    /// # Errors
    ///
    /// Fails with `Err::ServerError` if any of the VC's mandatory fields are not set.
    pub fn new() -> Result<Self> {
        Self::builder().try_into()
    }

    /// Returns a new [`VcBuilder`], which can be used to build a [`VerifiableCredential`]
    #[must_use]
    pub fn builder() -> VcBuilder {
        VcBuilder::new()
    }

    /// Transforms the `VerifiableCredential` into its JWT equivalent.
    #[instrument]
    pub fn to_jwt(&mut self) -> Result<Jwt<VcClaims>> {
        trace!("VerifiableCredential::to_jwt");

        let Some(proofs) = self.proof.clone() else {
            err!("proof is missing");
        };
        let proof = &proofs[0];

        // clear vc proof
        self.proof = None;

        // convert proof type to JWT alg
        let alg = match proof.type_.as_str() {
            "JsonWebKey2020" => "EdDSA",
            _ => "ES256K",
        };

        Ok(jwt::Jwt {
            // TODO: build Header in signing module
            header: jwt::Header {
                typ: String::from("JWT"),
                alg: alg.to_string(),
                kid: proof.verification_method.clone(),
            },
            claims: VcClaims::from(self.clone()),
        })
    }

    /// Returns a sample [`VerifiableCredential`] for use in type generation
    #[must_use]
    pub fn sample() -> Self {
        use chrono::TimeZone;

        VerifiableCredential {
            context: vec![
                String::from("https://www.w3.org/2018/credentials/v1"),
                String::from("http://credibil.io/credentials/v1"),
            ],
            type_: vec![String::from("VerifiableCredential"), String::from("EmployeeIDCredential")],
            issuer: Issuer {
                id: String::from("http://credibil.io"),
                extra: None,
            },
            id: String::from("http://credibil.io/credentials/1234"),
            issuance_date: Utc.with_ymd_and_hms(2023, 11, 20, 23, 21, 55).unwrap(),
            credential_subject: vec![CredentialSubject {
                id: Some(String::from("did:ion:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJwdWJsaWNLZXlNb2RlbDFJZCIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJzZWNwMjU2azEiLCJrdHkiOiJFQyIsIngiOiJ0WFNLQl9ydWJYUzdzQ2pYcXVwVkpFelRjVzNNc2ptRXZxMVlwWG45NlpnIiwieSI6ImRPaWNYcWJqRnhvR0otSzAtR0oxa0hZSnFpY19EX09NdVV3a1E3T2w2bmsifSwicHVycG9zZXMiOlsiYXV0aGVudGljYXRpb24iLCJrZXlBZ3JlZW1lbnQiXSwidHlwZSI6IkVjZHNhU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOSJ9XSwic2VydmljZXMiOlt7ImlkIjoic2VydmljZTFJZCIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHA6Ly93d3cuc2VydmljZTEuY29tIiwidHlwZSI6InNlcnZpY2UxVHlwZSJ9XX19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpREtJa3dxTzY5SVBHM3BPbEhrZGI4Nm5ZdDBhTnhTSFp1MnItYmhFem5qZEEifSwic3VmZml4RGF0YSI6eyJkZWx0YUhhc2giOiJFaUNmRFdSbllsY0Q5RUdBM2RfNVoxQUh1LWlZcU1iSjluZmlxZHo1UzhWRGJnIiwicmVjb3ZlcnlDb21taXRtZW50IjoiRWlCZk9aZE10VTZPQnc4UGs4NzlRdFotMkotOUZiYmpTWnlvYUFfYnFENHpoQSJ9fQ")),
                claims: HashMap::from([(String::from("claim1"), serde_json::json!("claim"))]),
            }],
            proof: Some(vec![Proof{
                type_:String::from("Ed25519Signature2020"),
                cryptosuite: Some(String::from("EcdsaSecp256k1VerificationKey2019")),
                proof_purpose: String::from("assertionMethod"),
                verification_method:String::from("did:ion:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJwdWJsaWNLZXlNb2RlbDFJZCIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJzZWNwMjU2azEiLCJrdHkiOiJFQyIsIngiOiJ0WFNLQl9ydWJYUzdzQ2pYcXVwVkpFelRjVzNNc2ptRXZxMVlwWG45NlpnIiwieSI6ImRPaWNYcWJqRnhvR0otSzAtR0oxa0hZSnFpY19EX09NdVV3a1E3T2w2bmsifSwicHVycG9zZXMiOlsiYXV0aGVudGljYXRpb24iLCJrZXlBZ3JlZW1lbnQiXSwidHlwZSI6IkVjZHNhU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOSJ9XSwic2VydmljZXMiOlt7ImlkIjoic2VydmljZTFJZCIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHA6Ly93d3cuc2VydmljZTEuY29tIiwidHlwZSI6InNlcnZpY2UxVHlwZSJ9XX19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpREtJa3dxTzY5SVBHM3BPbEhrZGI4Nm5ZdDBhTnhTSFp1MnItYmhFem5qZEEifSwic3VmZml4RGF0YSI6eyJkZWx0YUhhc2giOiJFaUNmRFdSbllsY0Q5RUdBM2RfNVoxQUh1LWlZcU1iSjluZmlxZHo1UzhWRGJnIiwicmVjb3ZlcnlDb21taXRtZW50IjoiRWlCZk9aZE10VTZPQnc4UGs4NzlRdFotMkotOUZiYmpTWnlvYUFfYnFENHpoQSJ9fQ#publicKeyModel1Id"),
                ..Default::default()
            }]),

            expiration_date: Some(Utc.with_ymd_and_hms(2023, 12, 20, 23, 21, 55).unwrap()),
            credential_status: Some(CredentialStatus::default()),
            credential_schema: Some(vec![CredentialSchema::default()]),
            refresh_service: Some(RefreshService::default()),
            terms_of_use: Some(vec![Term {
                obligation: Some(vec![Policy {
                    action: vec![String::new()],
                    ..Default::default()
                }]),
                prohibition: Some(vec![Policy::default()]),
                permission: Some(vec![Policy::default()]),
                ..Default::default()
            }]),
            evidence: Some(vec![Evidence {
                type_: vec![String::new()],
                ..Default::default()
            }]),
        }
    }
}

impl FromStr for VerifiableCredential {
    type Err = error::Error;

    #[instrument]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        trace!("VerifiableCredential::from_str");
        let vc_jwt = Jwt::<VcClaims>::from_str(s)?;
        Ok(vc_jwt.claims.vc)
    }
}

/// Issuer identifies the issuer of the credential.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Issuer {
    /// The issuer URI. If dereferenced, it should result in a machine-readable
    /// document that can be used to verify the credential.
    pub id: String,

    /// Issuer-specific fields that may be used to express additional
    /// information about the issuer.
    #[cfg_attr(not(feature = "typegen"), serde(flatten))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<HashMap<String, Value>>,
}

/// Derserialize Issuer from string or object. If a string, then it is the issuer's
/// id, else deserialize as object.
impl FromStr for Issuer {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Issuer {
            id: s.to_string(),
            extra: None,
        })
    }
}

/// Serialize `Issuer` to string or object. If only the `id` field is set,
/// serialize to string, otherwise serialize to object.
impl Serialize for Issuer {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let _ = span!(Level::TRACE, "Issuer::serialize").entered();

        if let Some(extra) = &self.extra {
            // serialize the entire object, flattening any 'extra' fields.
            debug!("serializing issuer to object: {:?}", &self);
            let mut map = serializer.serialize_map(None)?;
            map.serialize_entry("id", &self.id)?;
            for (k, v) in extra {
                map.serialize_entry(&k, &v)?;
            }
            map.end()
        } else {
            // serialize to string when no extra fields are present
            debug!("serializing issuer to string: {}", &self.id);
            serializer.serialize_str(&self.id)
        }
    }
}

/// `CredentialSubject` holds claims about the subject(s) referenced by the credential.
/// Or, more correctly: a set of objects containing one or more properties related to
/// a subject of the credential.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct CredentialSubject {
    /// A URI that uniquely identifies the subject of the claims. if set, it
    /// MUST be the identifier used by others to identify the subject.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Claims about the subject.
    #[cfg_attr(not(feature = "typegen"), serde(flatten))]
    pub claims: HashMap<String, Value>,
}

// Unused, but required by 'flexvec' deserializer FromStr trait
impl FromStr for CredentialSubject {
    type Err = Infallible;

    fn from_str(_: &str) -> Result<Self, Self::Err> {
        unimplemented!("CredentialSubject::from_str")
    }
}

/// To be verifiable, a credential must contain at least one proof mechanism,
/// and details necessary to evaluate that proof. A proof may be external, for
/// instance a JWT-based credential using JWS as a proof.
///
/// <https://w3c.github.io/vc-data-integrity/#proofs>
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct Proof {
    /// An optional identifier for the proof. MUST be a URL, such as a UUID as a
    /// URN e.g. "`urn:uuid:6a1676b8-b51f-11ed-937b-d76685a20ff5`".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// The specific proof type. MUST map to a URL. Examples include
    /// "`DataIntegrityProof`" and "`Ed25519Signature2020`". The type determines the
    /// other fields required to secure and verify the proof.
    ///
    /// When set to "`DataIntegrityProof`", the `cryptosuite` and the `proofValue`
    /// properties MUST be set.
    #[serde(rename = "type")]
    pub type_: String,

    /// The value of the cryptosuite property identifies the cryptographic
    /// suite. If subtypes are supported, it MUST be the <https://w3id.org/security#cryptosuiteString>
    /// subtype of string.
    ///
    /// For example, 'ecdsa-rdfc-2019', 'eddsa-2022'
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptosuite: Option<String>,

    /// The reason for the proof. MUST map to a URL. The proof purpose acts as a
    /// safeguard to prevent the proof from being misused.
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,

    /// Used to verify the proof. MUST map to a URL. For example, a link to a
    /// public key that is used by a verifier during the verification
    /// process. e.g did:example:123456789abcdefghi#keys-1.
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,

    /// The date-time the proof was created. MUST be an XMLSCHEMA11-2 date-time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<DateTime<Utc>>,

    /// The date-time the proof expires. MUST be an XMLSCHEMA11-2 date-time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<DateTime<Utc>>,

    /// One or more security domains in which the proof is meant to be used.
    /// MUST be either a string, or a set of strings. SHOULD be used by the
    /// verifier to ensure the proof is used in the correct security domain.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "option_flexvec")]
    pub domain: Option<Vec<String>>,

    /// Used to mitigate replay attacks. SHOULD be included if a domain is
    /// specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,

    /// Contains the data needed to verify the proof using the
    /// verificationMethod specified. MUST be a MULTIBASE-encoded binary
    /// value.
    #[serde(rename = "proofValue")]
    pub proof_value: String,

    /// Each value identifies another data integrity proof that MUST verify
    /// before the current proof is processed.
    #[serde(rename = "previousProof")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "option_flexvec")]
    pub previous_proof: Option<Vec<String>>,

    /// Supplied by the proof creator. Can be used to increase privacy by
    /// decreasing linkability that results from deterministically generated
    /// signatures.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    //---
    // /// Proof-specific additional fields.
    // #[cfg_attr(not(feature = "typegen"), serde(flatten))]
    // #[serde(skip_serializing_if = "Option::is_none")]
    // pub extra: Option<HashMap<String, Value>>,
}

// Unused, but required by 'option_flexvec' deserializer FromStr trait
impl FromStr for Proof {
    type Err = Infallible;

    fn from_str(_: &str) -> Result<Self, Self::Err> {
        unimplemented!("Proof::from_str")
    }
}

/// `CredentialStatus` can be used for the discovery of information about the
/// current status of a credential, such as whether it is suspended or revoked.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct CredentialStatus {
    /// A URI where credential status information can be retrieved.
    pub id: String,

    /// Refers to the status method used to provide the (machine readable)
    /// status of the credential.
    #[serde(rename = "type")]
    pub type_: String,
}

/// `CredentialSchema` defines the structure of the credential and the datatypes
/// of each property contained. It can be used to verify if credential data is
/// syntatically correct. The precise contents of each data schema is determined
/// by the specific type definition.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct CredentialSchema {
    /// A URI identifying the schema file.
    pub id: String,

    /// Refers to the status method used to provide the (machine readable)
    /// status of the credential. e.g. "`JsonSchemaValidator2018`"
    #[serde(rename = "type")]
    pub type_: String,
}

// Unused, but required by 'option_flexvec' deserializer FromStr trait
impl FromStr for CredentialSchema {
    type Err = Infallible;

    fn from_str(_: &str) -> Result<Self, Self::Err> {
        unimplemented!("CredentialSchema::from_str")
    }
}

/// `RefreshService` can be used to provide a link to the issuer's refresh service
/// so Holder's can refresh (manually or automatically) an expired credential.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct RefreshService {
    /// A URI where credential status information can be retrieved.
    pub id: String,

    /// Refers to the status method used to provide the (machine readable)
    /// status of the credential.
    #[serde(rename = "type")]
    pub type_: String,
}

/// Term is a single term used in defining the issuers terms of use.
/// In aggregate, the termsOfUse property tells the verifier what actions it is
/// required to perform (an obligation), not allowed to perform (a prohibition),
/// or allowed to perform (a permission) if it is to accept the verifiable
/// credential or verifiable presentation.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct Term {
    /// Refers to the status method used to provide the (machine readable)
    /// status of the credential.
    #[serde(rename = "type")]
    pub type_: String,

    /// A URI where credential policy information can be retrieved.
    pub id: String,

    /// A human-readable description of the term.
    pub profile: String,

    /// An obligation tells the verifier what actions it is required to perform
    /// if it is to accept the verifiable credential or verifiable presentation.
    pub obligation: Option<Vec<Policy>>,

    /// A prohibition tells the verifier what actions it is not allowed to
    /// perform if it is to accept the verifiable credential or verifiable
    /// presentation.
    pub prohibition: Option<Vec<Policy>>,

    /// A permission tells the verifier what actions it is allowed to perform
    /// if it is to accept the verifiable credential or verifiable presentation.
    pub permission: Option<Vec<Policy>>,
}

/// Prohibition defines what actions a verifier is not allowed to perform.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct Policy {
    ///  A URI identifying the credential issuer.
    assigner: String,

    /// A URI identifying the credential verifier.
    assignee: String,

    /// A URI identifying the credential (the credential `id`).
    target: String,

    /// A list of prohibited actions
    action: Vec<String>,
}

/// Evidence can be included by an issuer to provide the verifier with
/// additional supporting information in a credential. This could be used by the
/// verifier to establish the confidence with which it relies on credential
/// claims.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct Evidence {
    /// A URL pointing to where more information about this instance of evidence
    /// can be found.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Type identifies the evidence scheme used for the instance of evidence.
    /// For example, "`DriversLicense`" or "`Passport`".
    #[serde(rename = "type")]
    pub type_: Vec<String>,

    /// A URI identifying the credential issuer (i.e. verifier of evidence).
    pub verifier: String,

    /// Tyupe identifies the evidence scheme.
    #[serde(rename = "evidenceDocument")]
    pub evidence_document: String,

    /// Whether the subject was present when the evidence was collected.
    /// For example, "Physical".
    #[serde(rename = "subjectPresence")]
    pub subject_presence: String,

    /// Whether the evidence document was present when the evidence was
    /// collected. For example, "Physical".
    #[serde(rename = "documentPresence")]
    pub document_presence: String,

    /// A list of schema-specific evidence fields.
    #[cfg_attr(not(feature = "typegen"), serde(flatten))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<HashMap<String, String>>,
}

/// [`VcBuilder`] is used to build a [`VerifiableCredential`]
#[derive(Clone, Debug, Default)]
#[allow(clippy::module_name_repetitions)]
pub struct VcBuilder {
    vc: VerifiableCredential,
}

impl VcBuilder {
    /// Returns a new [`VcBuilder`]
    #[instrument]
    pub fn new() -> Self {
        trace!("VcBuilder::new");

        let mut builder: Self = VcBuilder::default();

        // set some sensibile defaults
        builder.vc.context.push(String::from("https://www.w3.org/2018/credentials/v1"));
        builder.vc.type_.push(String::from("VerifiableCredential"));
        builder.vc.issuance_date = chrono::Utc::now(); //.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

        builder
    }

    /// Sets the `@context` property
    #[must_use]
    pub fn add_context(mut self, context: String) -> Self {
        self.vc.context.push(context);
        self
    }

    /// Sets the `id` property
    #[must_use]
    pub fn id(mut self, id: String) -> Self {
        self.vc.id = id;
        self
    }

    /// Sets the `type_` property
    #[must_use]
    pub fn add_type(mut self, type_: String) -> Self {
        self.vc.type_.push(type_);
        self
    }

    /// Sets the `issuer` property
    #[must_use]
    pub fn issuer(mut self, issuer: String) -> Self {
        self.vc.issuer = Issuer {
            id: issuer,
            extra: None,
        };
        self
    }

    /// Adds one or more `credential_subject` properties.
    #[must_use]
    pub fn add_subject(mut self, subj: CredentialSubject) -> Self {
        self.vc.credential_subject.push(subj);
        self
    }

    /// Adds one or more `proof` properties.
    #[must_use]
    pub fn add_proof(mut self, proof: Proof) -> Self {
        if let Some(proofs) = self.vc.proof.as_mut() {
            proofs.push(proof);
        } else {
            self.vc.proof = Some(vec![proof]);
        }
        self
    }

    /// Turns this builder into a [`VerifiableCredential`]
    ///
    /// # Errors
    ///
    /// Fails with `Err::ServerError` if any of the VC's mandatory fields are not set.
    #[instrument]
    pub fn build(self) -> Result<VerifiableCredential> {
        trace!("VcBuilder::build");

        if self.vc.context.len() < 2 {
            err!("no context set");
        }
        if self.vc.id.is_empty() {
            err!("no id set");
        }
        if self.vc.type_.len() < 2 {
            err!("no type set");
        }
        if self.vc.issuer.id.is_empty() {
            err!("no issuer.id set");
        }
        if self.vc.credential_subject.is_empty() {
            err!("no credential_subject set");
        }

        Ok(self.vc)
    }
}

impl TryFrom<VcBuilder> for VerifiableCredential {
    type Error = error::Error;

    #[instrument]
    fn try_from(builder: VcBuilder) -> Result<Self, Self::Error> {
        trace!("VerifiableCredential::try_from");
        builder.build()
    }
}

/// Claims used for Verifiable Credential issuance when format is "`jwt_vc_json`".
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct VcClaims {
    /// MUST be the `id` property contained in the `credentialSubject`.
    /// That is, the Holder ID the credential is intended for. Unused in
    /// verifiable presentations.
    ///
    /// For example, "did:example:ebfeb1f712ebc6f1c276e12ec21".
    pub sub: String,

    /// MUST be the verifiable credential's `issuanceDate`, encoded as a
    /// UNIX timestamp ([RFC7519](https://www.rfc-editor.org/rfc/rfc7519) `NumericDate`).
    pub nbf: i64,

    /// MUST be the `issuer` property of a verifiable credential or the `holder`
    /// property of a verifiable presentation.
    ///
    /// For example, "did:example:123456789abcdefghi#keys-1".
    pub iss: String,

    /// MUST be the verifiable credential's `issuanceDate`, encoded as a
    /// UNIX timestamp ([RFC7519](https://www.rfc-editor.org/rfc/rfc7519) `NumericDate`).
    pub iat: i64,

    /// MUST be the `id` property of the verifiable credential or verifiable
    /// presentation.
    pub jti: String,

    /// MUST be the verifiable credential's `expirationDate`, encoded as a
    /// UNIX timestamp ([RFC7519](https://www.rfc-editor.org/rfc/rfc7519) `NumericDate`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,

    /// The verifiable credential.
    pub vc: VerifiableCredential,
}

impl From<VerifiableCredential> for VcClaims {
    fn from(vc: VerifiableCredential) -> Self {
        Self {
            // TODO: find better way to set sub (shouldn't need to be in vc)
            sub: vc.credential_subject[0].id.clone().unwrap_or_default(),
            nbf: vc.issuance_date.timestamp(),
            iss: vc.issuer.id.clone(),
            iat: vc.issuance_date.timestamp(),
            jti: vc.id.clone(),
            exp: vc.expiration_date.map(|exp| exp.timestamp()),
            vc,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Once;

    use serde_json::json;
    use tracing_subscriber::FmtSubscriber;

    use super::*;

    // initalise tracing once for all tests
    static INIT: Once = Once::new();

    // Initialise tracing for tests.
    fn init_tracer() {
        INIT.call_once(|| {
            let subscriber = FmtSubscriber::builder().with_max_level(Level::ERROR).finish();
            tracing::subscriber::set_global_default(subscriber).expect("subscriber set");
        });
    }

    #[test]
    fn test_builder() {
        init_tracer();

        let vc = build_vc().expect("should build vc");

        // serialize
        let vc_json = serde_json::to_value(&vc).expect("should serialize to json");

        assert_eq!(
            *vc_json.get("@context").expect("@context should be set"),
            json!([
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1"
            ])
        );
        assert_eq!(
            *vc_json.get("id").expect("id should be set"),
            json!("https://example.com/credentials/3732")
        );
        assert_eq!(
            *vc_json.get("type").expect("type should be set"),
            json!(["VerifiableCredential", "EmployeeIDCredential"])
        );
        assert_eq!(
            *vc_json.get("credentialSubject").expect("credentialSubject should be set"),
            json!({"employeeID":"1234567890","id":"did:example:ebfeb1f712ebc6f1c276e12ec21"})
        );
        assert_eq!(
            *vc_json.get("issuer").expect("issuer should be set"),
            json!("https://example.com/issuers/14")
        );

        assert_eq!(
            *vc_json.get("issuanceDate").expect("issuanceDate should be set"),
            json!(vc.issuance_date)
        );

        // deserialize
        let vc_de: VerifiableCredential =
            serde_json::from_value(vc_json).expect("should deserialize");
        assert_eq!(vc_de.context, vc.context);
        assert_eq!(vc_de.id, vc.id);
        assert_eq!(vc_de.type_, vc.type_);
        assert_eq!(vc_de.credential_subject, vc.credential_subject);
        assert_eq!(vc_de.issuer, vc.issuer);
    }

    #[test]
    fn test_flexvec() {
        init_tracer();

        let mut vc = build_vc().expect("should build vc");

        vc.proof = Some(vec![Proof { ..Default::default() }]);

        vc.credential_schema = Some(vec![
            CredentialSchema { ..Default::default() },
            CredentialSchema { ..Default::default() },
        ]);

        // serialize
        let vc_json = serde_json::to_value(&vc).expect("should serialize to json");
        assert_eq!(
            *vc_json.get("proof").expect("proof should be set"),
            json!({"proofPurpose": "", "proofValue": "", "type": "", "verificationMethod": ""}),
            "Vec with len() == 1 should serialize to object"
        );
        assert_eq!(
            *vc_json.get("credentialSchema").expect("credentialSchema should be set"),
            json!([{"id":"","type":""},{"id":"","type":""}]),
            "Vec with len() > 1 should serialize to array"
        );

        // deserialize
        let vc_de: VerifiableCredential =
            serde_json::from_value(vc_json).expect("should deserialize");
        assert_eq!(vc_de.proof, vc.proof, "should deserialize to Vec");
        assert_eq!(
            vc_de.credential_schema, vc.credential_schema,
            "array should deserialize to Vec"
        );
    }

    #[test]
    fn test_flexobj() {
        init_tracer();

        let mut vc = build_vc().expect("should build vc");

        // serialize with just issuer 'id' field set
        let vc_json = serde_json::to_value(&vc).expect("should serialize to json");
        assert_eq!(
            *vc_json.get("issuer").expect("issuer should be set"),
            json!("https://example.com/issuers/14")
        );

        // deserialize from issuer as string,  e.g."issuer":"<value>"
        let vc_de: VerifiableCredential =
            serde_json::from_value(vc_json).expect("should deserialize");
        assert_eq!(vc_de.issuer, vc.issuer);
        vc.issuer.extra = Some(HashMap::from([(
            String::from("name"),
            Value::String(String::from("Example University")),
        )]));

        // serialize
        let vc_json = serde_json::to_value(&vc).expect("should serialize to json");
        assert_eq!(
            *vc_json.get("issuer").expect("issuer should be set"),
            json!({"id": "https://example.com/issuers/14", "name": "Example University"}),
            "issuer 'extra' fields should flatten on serialization"
        );

        // deserialize
        let vc_de: VerifiableCredential =
            serde_json::from_value(vc_json).expect("should deserialize");
        assert_eq!(vc_de.issuer, vc.issuer, "issuer 'extra' fields should be populated");
    }

    fn build_vc() -> Result<VerifiableCredential> {
        let mut subj = CredentialSubject::default();
        subj.id = Some(String::from("did:example:ebfeb1f712ebc6f1c276e12ec21"));
        subj.claims.insert(String::from("employeeID"), json!("1234567890"));

        VerifiableCredential::builder()
            .add_context(String::from("https://www.w3.org/2018/credentials/examples/v1"))
            .id(String::from("https://example.com/credentials/3732"))
            .add_type(String::from("EmployeeIDCredential"))
            .issuer(String::from("https://example.com/issuers/14"))
            .add_subject(subj)
            .build()
    }
}
