//! # Verifiable Presentations
//!
//! [Verifiable Presentations](https://www.w3.org/TR/vc-data-model/#presentations-0)
//!
//! Specifications:
//! - <https://identity.foundation/presentation-exchange/spec/v2.0.0>
//! - <https://identity.foundation/jwt-vc-presentation-profile>
//! - <https://identity.foundation/claim-format-registry>

pub mod constraints;

use std::collections::HashMap;
use std::str::FromStr;

use anyhow::anyhow;
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::Utc;
// pub use matcher::VcMatcher;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{instrument, trace};

use crate::jwt::{self, Jwt}; //::JwsBuilder;
use crate::w3c::serde::option_flexvec;
pub use crate::w3c::vc::Proof;
use crate::{err, error, Result};

/// A Verifiable Presentation is used to combine and present credentials to a
/// Verifer.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct VerifiablePresentation {
    // LATER: add support for @context objects
    /// The @context property is used to map property URIs into short-form
    /// aliases. It is an ordered set where the first item is https://www.w3.org/2018/credentials/v1.
    /// Subsequent items MUST express context information and can be either URIs
    /// or objects. Each URI, if dereferenced, should result in a document
    /// containing machine-readable information about the @context.
    #[serde(rename = "@context")]
    pub context: Vec<String>,

    /// MAY be used to provide a unique identifier for the presentation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// The type property is required and expresses the type of presentation,
    /// such as VerifiablePresentation. Consists of 'VerifiablePresentation'
    /// and, optionally, a more specific verifiable presentation type.
    /// e.g. `"type": ["VerifiablePresentation",
    /// "CredentialManagerPresentation"]`
    #[serde(rename = "type")]
    pub type_: Vec<String>, // TODO: deserialize from string or array

    /// The verifiableCredential property MUST be constructed from one or more
    /// verifiable credentials, or of data derived from verifiable
    /// credentials in a cryptographically verifiable format.
    #[serde(rename = "verifiableCredential")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifiable_credential: Option<Vec<Value>>,

    /// Holder is a URI for the entity that is generating the presentation.
    /// For example, did:example:ebfeb1f712ebc6f1c276e12ec21.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,

    /// An embedded proof ensures that the presentation is verifiable.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "option_flexvec")]
    pub proof: Option<Vec<Proof>>,
}

/// A Presentation Definition is used by a Verifier to articulate proofs
/// required. The proofs help the Verifier decide how to interact with the
/// Holder providing the proofs.
///
/// <https://identity.foundation/presentation-exchange/spec/v2.0.0/#presentation-definition>
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct PresentationDefinition {
    /// A unique ID for the desired context. For example, a UUID is unique in a
    /// global context, while a simple string could be suitably unique in a
    /// local context.
    pub id: String,

    /// Input Descriptors describe the information a Verifier requires from the
    /// Holder.
    pub input_descriptors: Vec<InputDescriptor>,

    /// If present, a human-friendly, distinctive designation for the
    /// Presentation Definition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// If present, it MUST describe the purpose for which the Presentation
    /// Definition is being used for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,

    /// One or more registered Claim Format Designation objects (e.g., jwt,
    /// jwt_vc, jwt_vp, etc.). Used to inform the Holder of the Claim
    /// formats the Verifier can process. For example,
    ///   "jwt": {
    ///     "alg": ["EdDSA", "ES256K", "ES384"]
    ///   },
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<HashMap<String, Format>>,
}

/// Input Descriptors describe the information a Verifier requires from the
/// Holder. All Input Descriptors MUST be satisfied, unless otherwise specified.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct InputDescriptor {
    /// An identifier that does not conflict with the id of any other Input
    /// Descriptor in the same Presentation Definition.
    pub id: String,

    /// If set, it SHOULD be a human-friendly name that describes what the
    /// target schema represents.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// If present, its value MUST describe the purpose for which the Claim's
    /// data is being requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,

    /// If present, its MUST be an object with one or more properties matching
    /// registered Claim Format Designations (e.g., `jwt`, `jwt_vc`, `jwt_vp`,
    /// etc.). This property can be used to specifically constrain
    /// submission of a single input to a subset of the top-level formats or
    /// algorithms specified in the Presentation Definition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<HashMap<String, Format>>,

    /// Contraints specify constraints on data values, and an explanation why a
    /// certain item or set of data is being requested.
    pub constraints: Constraints,
}

/// A registered Claim Format Designation object (e.g., `jwt`, `jwt_vc`, `jwt_vp`,
/// etc.) used to inform the Holder of a Claim format the Verifier can process.
/// A Format object MUST include one of the format-specific properties (i.e.,
/// `alg`, `proof_type`) that specify which algorithms the Verifier supports for the
/// format.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Format {
    /// An array of one or more algorithmic identifiers, e.g. `["Ed2219",
    /// "ES256K"]`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<Vec<String>>,

    /// An array of one or more proof type identifiers,
    /// e.g. `["JsonWebSignature2020", "EcdsaSecp256k1Signature2019"]`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_type: Option<Vec<String>>,
}

/// Contraints specify constraints on data values, and an explanation why a
/// certain item or set of data is being requested.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Constraints {
    /// Fields are used to specify attributes of credential data the Verifier
    /// requires. They are processed in order, meaning processing can be
    /// reduced by checking the most defining characteristics of a
    /// credential (e.g the type or schema of a credential) earlier.
    /// Implementers SHOULD order field checks to ensure earliest termination of
    /// evaluation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<Field>>,

    ///If present, limit_disclosure MUST be one of the following strings:
    /// "required" - indicates that the Conformant Consumer MUST limit submitted
    /// fields  to those listed in the fields array (if present). Conformant
    /// Consumers are not required  to implement support for this value, but
    /// they MUST understand this value sufficiently  to return nothing (or
    /// cease the interaction with the Verifier) if they do not implement it.
    ///
    /// "preferred" - indicates that the Conformant Consumer SHOULD limit
    /// submitted fields to those listed in the fields array (if present).
    ///
    /// Omission of this property indicates the Conformant Consumer MAY submit a
    /// response that contains more than the data described in the fields
    /// array.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit_disclosure: Option<String>,
}

/// Fields are used to specify attributes of credential data the Verifier
/// requires.
/// See <https://identity.foundation/presentation-exchange/spec/v2.0.0/#presentation-definition-in-an-envelope>
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Field {
    /// If present, it MUST be unique from every other field object’s id
    /// property, including those contained in other Input Descriptor
    /// Objects.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// One or more JSONPath expressions that select a target value from the
    /// input. The array MUST be evaluated in order, breaking as soon as a
    /// Field Query Result is found. The ability to use multiple expressions
    /// allows the Verifier to account for differences in credential
    /// formats.
    /// see <https://identity.foundation/presentation-exchange/spec/v2.0.0/#jsonpath-syntax-definition>
    pub path: Vec<String>,

    /// If present, it MUST be a JSON Schema descriptor used to filter against
    /// the values returned from evaluation of the JSONPath expressions in
    /// the path array.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<Filter>,

    /// The predicate Feature enables the Verifier to request that Wallet apply a
    /// predicate and return a boolean rather than the matching credential.
    ///
    /// If `predicate` is present:
    ///  - it MUST be one of "required" or "preferred"
    ///  - the `filter` field containing the predicate MUST also be present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub predicate: Option<String>,

    /// If present, its MUST describe the purpose for which the field is being
    /// requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,

    /// If present, it SHOULD be a human-friendly name that describes what the
    /// target field represents.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// If present, it MUST indicate whether the field is optional or not. Defaults
    /// to false. Even when set to `true`, the path value MUST validate against the
    /// JSON Schema filter, if a filter is present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,

    /// If present, MUST be a boolean that indicates the Verifier intends to retain
    /// the Claim's data being requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent_to_retain: Option<bool>,
}

/// A JSON Schema descriptor used to filter against the values returned from evaluation
/// of the `JSONPath` expressions in the path array.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Filter {
    /// The type of filter to apply.
    #[serde(rename = "type")]
    pub type_: String,

    /// The value of the filter to apply.
    #[serde(flatten)]
    pub value: FilterValue,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FilterValue {
    Const(String),
    Pattern(String),
    Format(String),
}

impl Default for FilterValue {
    fn default() -> Self {
        FilterValue::Const(String::new())
    }
}

/// A Presentation Submission expresses how proofs presented to the Verifier are
/// provided in accordance with the requirements specified in a Presentation
/// Definition.
///
/// <https://identity.foundation/presentation-exchange/spec/v2.0.0/#presentation-submission>
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct PresentationSubmission {
    /// The `id` MUST be a unique identifier, such as a UUID.
    pub id: String,

    /// The value of this property MUST be the id value of the Presentation
    /// Definition this submission fulfills.
    pub definition_id: String,

    /// An array of Input Descriptor Mapping Objects.
    pub descriptor_map: Vec<DescriptorMap>,
}

impl FromStr for PresentationSubmission {
    type Err = error::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(serde_json::from_str::<PresentationSubmission>(s)?)
    }
}

/// An Input Descriptor Mapping Object is used to map an Input Descriptor to a
/// Verifiable Credential or a JSON Web Token.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct DescriptorMap {
    /// MUST match the Input Descriptor id in the Presentation Definition this
    /// Presentation Submission is related to.
    pub id: String,

    /// Denotes the data format of the Claim. MUST match one of the Claim Format
    /// Designations specified in the Input Descriptor.
    pub format: String,

    /// A JSONPath string expression that indicates the Claim submitted in
    /// relation to the Input Descriptor, when executed against the
    /// top-level of the object the Presentation Submission.
    /// For the OpenID.VP specification, this value MUST be:
    ///  - $ when only one Verifiable Presentation
    ///  - $[n] when there are multiple Verifiable Presentations, where n is the
    ///    vp's index.
    pub path: String,

    /// Refers to the actual Credential carried in the respective Verifiable
    /// Presentation. Used to describe how to find a returned Credential
    /// within a Verifiable Presentation.
    pub path_nested: PathNested, // Option<Box<DescriptorMap>>,
}

/// A nested path object is used to describe how to find a returned Credential
/// within the Verifiable Presentation.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct PathNested {
    /// Format of the credential returned in the Verifiable Presentation.
    pub format: String,

    /// Describes how to find a returned Credential within a Verifiable
    /// Presentation. The value depends on the credential format.
    pub path: String,
}

impl VerifiablePresentation {
    /// Returns a new [`VerifiablePresentation`] configured with defaults
    ///
    /// # Errors
    ///
    /// Fails with `Err::ServerError` if any of the VP's mandatory fields
    /// are not set.
    pub fn new() -> Result<Self> {
        Self::builder().try_into()
    }

    /// Returns a new [`VpBuilder`], which can be used to build a
    /// [`VerifiablePresentation`]
    #[must_use]
    pub fn builder() -> VpBuilder {
        VpBuilder::new()
    }

    /// Transforms the VerifiableCredential into a signed, base64 encoded JWT.
    #[instrument]
    pub fn to_jwt(&mut self) -> Result<Jwt<Claims>> {
        trace!("VerifiablePresentation::to_jwt");

        let Some(proofs) = self.proof.clone() else {
            err!("proof is missing");
        };
        let proof = &proofs[0];

        let alg = match proof.type_.as_str() {
            "JsonWebKey2020" => "EdDSA",
            _ => "ES256K",
        };

        let jwt = jwt::Jwt {
            // TODO: build Header in signing module
            header: jwt::Header {
                typ: "openid-vci-proof+jwt".to_string(),
                alg: alg.to_string(),
                kid: proof.verification_method.clone(),
            },
            claims: Claims::try_from(self.clone())?,
        };

        Ok(jwt)
    }
}

impl TryFrom<VpBuilder> for VerifiablePresentation {
    type Error = error::Error;

    fn try_from(builder: VpBuilder) -> Result<Self, Self::Error> {
        builder.build()
    }
}

/// [`VpBuilder`] is used to build a [`VerifiablePresentation`]
#[derive(Clone, Default)]
#[allow(clippy::module_name_repetitions)]
pub struct VpBuilder {
    vp: VerifiablePresentation,
}

impl VpBuilder {
    /// Returns a new [`VpBuilder`]
    #[must_use]
    pub fn new() -> Self {
        let mut builder: Self = VpBuilder::default();

        // sensibile defaults
        builder.vp.context.push("https://www.w3.org/2018/credentials/v1".to_string());
        builder.vp.type_.push("VerifiablePresentation".to_string());
        builder
    }

    /// Sets the `@context` property
    #[must_use]
    pub fn add_context(mut self, context: String) -> Self {
        self.vp.context.push(context);
        self
    }

    /// Adds a type to the `type` property
    #[must_use]
    pub fn add_type(mut self, type_: String) -> Self {
        self.vp.type_.push(type_);
        self
    }

    /// Adds a `verifiable_credential`
    #[must_use]
    pub fn add_credential(mut self, vc: Value) -> Self {
        if let Some(verifiable_credential) = self.vp.verifiable_credential.as_mut() {
            verifiable_credential.push(vc);
        } else {
            self.vp.verifiable_credential = Some(vec![vc]);
        }
        self
    }

    /// Sets the `type_` property
    #[must_use]
    pub fn holder(mut self, holder: String) -> Self {
        self.vp.holder = Some(holder);
        self
    }

    /// Turns this builder into a [`VerifiablePresentation`]
    ///
    /// # Errors
    ///
    /// Fails if any of the VP's mandatory fields are not set.
    pub fn build(self) -> Result<VerifiablePresentation> {
        if self.vp.context.len() < 2 {
            err!("context is required");
        }
        if self.vp.type_.len() < 2 {
            err!("type is required");
        }

        Ok(self.vp)
    }
}

impl FromStr for VerifiablePresentation {
    type Err = error::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if &s[0..1] != "{" {
            // base64 encoded string
            let dec = Base64UrlUnpadded::decode_vec(s)?;
            return Ok(serde_json::from_slice(dec.as_slice())?);
        }

        // stringified JSON
        Ok(serde_json::from_str(s)?)
    }
}

/// To sign, or sign and encrypt the Authorization Response, implementations MAY
/// use JWT Secured Authorization Response Mode for OAuth 2.0
/// ([JARM](https://openid.net/specs/oauth-v2-jarm-final.html)).
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Claims {
    /// MUST be the verifiable credential's `expirationDate`, encoded as a
    /// UNIX timestamp ([RFC7519] NumericDate).
    pub exp: i64,

    /// MUST be the verifiable credential's `expirationDate`, encoded as a
    /// UNIX timestamp ([RFC7519] NumericDate).
    pub iat: i64,

    /// MUST be the `issuer` property of a verifiable credential or the `holder`
    /// property of a verifiable presentation.
    ///
    /// For example, "did:example:123456789abcdefghi#keys-1".
    pub iss: String,

    // /// MUST be the verifiable credential's `issuanceDate`, encoded as a
    // /// UNIX timestamp ([RFC7519] NumericDate).
    // pub nbf: i64,
    /// MUST be the `id` property of the verifiable credential or verifiable
    /// presentation.
    pub jti: String,

    /// MUST be the `id` property contained in the `credentialSubject`.
    /// That is, the Holder ID the credential is intended for. Unused in
    /// verifiable presentations.
    ///
    /// For example, "did:example:ebfeb1f712ebc6f1c276e12ec21".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,

    /// The `nonce` value from the Verifier's Authorization Request.
    pub nonce: String,

    /// The Verifiable Presentation.
    pub vp: VerifiablePresentation,
}

impl TryFrom<VerifiablePresentation> for Claims {
    type Error = error::Error;

    fn try_from(vp: VerifiablePresentation) -> Result<Self, Self::Error> {
        let mut vp = vp;

        let Some(proofs) = vp.proof.clone() else {
            err!("proof is missing");
        };
        let proof = &proofs[0];
        vp.proof = None;

        let mut claims = Claims {
            iat: Utc::now().timestamp(),
            vp: vp.clone(),
            ..Default::default()
        };
        if let Some(holder) = vp.holder.clone() {
            claims.iss = holder;
        }
        if let Some(id) = proof.id.clone() {
            claims.jti = id;
        }
        // if let Some(domain) = &proof.domain {
        //     claims.aud = domain[0].clone();
        // }
        if let Some(expires) = proof.expires {
            claims.exp = expires.timestamp();
        }
        if let Some(challenge) = proof.challenge.clone() {
            claims.nonce = challenge;
        }

        Ok(claims)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::w3c::vc::{CredentialSubject, VerifiableCredential};

    #[test]
    fn test_vp_build() {
        let vp = base_vp().expect("should build vp");

        // serialize
        let vp_json = serde_json::to_value(&vp).expect("should serialize");

        assert_eq!(
            *vp_json.get("@context").expect("@context should be set"),
            json!([
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1"
            ])
        );
        assert_eq!(
            *vp_json.get("type").expect("type should be set"),
            json!(["VerifiablePresentation", "EmployeeIDCredential"])
        );

        assert!(vp.verifiable_credential.is_some());

        let vc_field = vp.verifiable_credential.as_ref().expect("vc should be set");
        let vc = &vc_field[0];
        let vc_json = serde_json::to_value(vc).expect("should serialize");

        assert_eq!(
            *vc_json.get("credentialSubject").expect("credentialSubject should be set"),
            json!({"employeeID":"1234567890","id":"did:example:ebfeb1f712ebc6f1c276e12ec21"})
        );
        assert_eq!(
            *vc_json.get("issuer").expect("issuer should be set"),
            json!("https://example.com/issuers/14")
        );

        // deserialize
        let vp_de: VerifiablePresentation =
            serde_json::from_value(vp_json).expect("should deserialize");
        assert_eq!(vp_de.context, vp.context);
        assert_eq!(vp_de.type_, vp.type_);
        assert_eq!(vp_de.verifiable_credential, vp.verifiable_credential);
    }

    fn base_vp() -> Result<VerifiablePresentation> {
        let mut subj = CredentialSubject::default();
        subj.id = Some("did:example:ebfeb1f712ebc6f1c276e12ec21".to_string());
        subj.claims.insert("employeeID".to_string(), json!("1234567890"));

        let vc = VerifiableCredential::builder()
            .add_context("https://www.w3.org/2018/credentials/examples/v1".to_string())
            .id("https://example.com/credentials/3732".to_string())
            .add_type("EmployeeIDCredential".to_string())
            .issuer("https://example.com/issuers/14".to_string())
            .add_subject(subj)
            .build()?;

        VerifiablePresentation::builder()
            .add_context("https://www.w3.org/2018/credentials/examples/v1".to_string())
            .add_type("EmployeeIDCredential".to_string())
            .add_credential(serde_json::to_value(vc)?)
            .build()
    }
}
