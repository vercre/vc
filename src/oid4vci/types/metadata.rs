use std::collections::HashMap;
use std::fmt::Debug;

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

use crate::core::strings::title_case;
use crate::oauth::{OAuthClient, OAuthServer};
use crate::oid4vci::types::credential::{Claim, Format};

/// Request to retrieve the Credential Issuer's configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct MetadataRequest {
    /// The Credential Issuer Identifier for which the configuration is to be
    /// returned.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub credential_issuer: String,

    /// The language(s) set in HTTP Accept-Language Headers. MUST be values
    /// defined in [RFC3066].
    ///
    /// [RFC3066]: (https://www.rfc-editor.org/rfc/rfc3066)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub languages: Option<String>,
}

/// Response containing the Credential Issuer's configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct MetadataResponse {
    /// The Credential Issuer metadata for the specified Credential Issuer.
    #[serde(flatten)]
    pub credential_issuer: Issuer,
}

/// Request to retrieve the Credential Issuer's authorization server
/// configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct OAuthServerRequest {
    /// The Authorization Server identifier for which the configuration is to be
    /// returned.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub credential_issuer: String,

    /// Authorization issuer identifier.
    ///
    /// This identifier can be obtained from the `authorization_servers`
    /// parameter in the Credential Issuer metadata. If that parameter is
    /// not present, the `issuer` parameter should be `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
}

/// Response containing the Credential Issuer's authorization server
/// configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct OAuthServerResponse {
    /// The OAuth 2.0 Authorization Server metadata for the Issuer.
    pub authorization_server: Server,
}

/// The registration request.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RegistrationRequest {
    /// The Credential Issuer for which the client is being registered.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub credential_issuer: String,

    /// A previously issued Access Token, as extracted from the Authorization
    /// header of the Credential Request. Used to grant access to register a
    /// client.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub access_token: String,

    /// Metadata provided by the client undertaking registration.
    #[serde(flatten)]
    pub client_metadata: Client,
}

/// The registration response for a successful request.
#[derive(Debug, Deserialize, Serialize)]
pub struct RegistrationResponse {
    /// Registered Client metadata.
    #[serde(flatten)]
    pub client_metadata: Client,
}

/// The Credential Issuer's configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[allow(clippy::struct_field_names)]
pub struct Issuer {
    /// The Credential Issuer's identifier.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub credential_issuer: String,

    /// Authorization Server's identifier (metadata `issuer` parameter). If
    /// omitted, the Credential Issuer is acting as the AS. That is, the
    /// `credential_issuer` value is also used as the Authorization Server
    /// `issuer` value in metadata requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_servers: Option<Vec<String>>,

    /// URL of the Credential Issuer's Credential Endpoint. MAY contain port,
    /// path and query parameter components.
    pub credential_endpoint: String,

    /// URL of the Credential Issuer's Deferred Credential Endpoint. This URL
    /// MUST use the https scheme and MAY contain port, path, and query
    /// parameter components. If omitted, the Credential Issuer does not
    /// support the Deferred Credential Endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deferred_credential_endpoint: Option<String>,

    /// URL of the Credential Issuer's Notification Endpoint. This URL
    /// MUST use the https scheme and MAY contain port, path, and query
    /// parameter components.  If omitted, the Credential Issuer does not
    /// support the Notification Endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification_endpoint: Option<String>,

    /// Specifies whether (and how) the Credential Issuer supports encryption of
    /// the Credential and Batch Credential Response on top of TLS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_response_encryption: Option<SupportedCredentialResponseEncryption>,

    /// Information about the Issuer's support for batch issuance of
    /// Credentials. The presence of this parameter means that the issuer
    /// supports the proofs parameter in the Credential Request so can issue
    /// more than one Verifiable Credential for the same Credential Dataset in a
    /// single request/response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_credential_issuance: Option<BatchCredentialIssuance>,

    /// A signed JWT containing Credential Issuer metadata parameters as claims.
    /// The signed metadata MUST be secured using JSON Web Signature (JWS)
    /// [RFC7515] and MUST contain an iat (Issued At) claim, an iss (Issuer)
    /// claim denoting the party attesting to the claims in the signed
    /// metadata, and sub (Subject) claim matching the Credential Issuer
    /// identifier. If the Wallet supports signed metadata, metadata values
    /// conveyed in the signed JWT MUST take precedence over the
    /// corresponding values conveyed using plain JSON elements. If the
    /// Credential Issuer wants to enforce use of signed metadata, it omits
    /// the respective metadata parameters from the unsigned part of the
    /// Credential Issuer metadata. A signed_ metadata metadata value MUST
    /// NOT appear as a claim in the JWT. The Wallet MUST establish trust in
    /// the signer of the metadata, and obtain the keys to validate
    /// the signature before processing the metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_metadata: Option<String>,

    /// Credential Issuer display properties for supported languages.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<Display>,

    /// A list of name/value pairs of credentials supported by the Credential
    /// Issuer. Each name is a unique identifier for the supported
    /// credential described. The identifier is used in the Credential Offer
    /// to communicate to the Wallet which Credential is being offered. The
    /// value is a Credential object containing metadata about specific
    /// credential.
    pub credential_configurations_supported: HashMap<String, CredentialConfiguration>,
    //
    // // TODO: Ddo we want to support this??
    // /// The Client ID provided by the Issuer when a Wallet is not pre-registered.
    // /// with the Authorization Server.
    // ///
    // /// <https://identity.foundation/jwt-vc-issuance-profile/#using-of-public_client_id-as-a-client_id>
    // #[serde(skip_serializing_if = "Option::is_none")]
    // pub public_client_id: Option<String>,
}

impl Issuer {
    /// Returns the `credential_configuration_id` for a given format.
    ///
    /// # Errors
    ///
    /// TODO: add error handling
    pub fn credential_configuration_id(&self, fmt: &Format) -> Result<&String> {
        self.credential_configurations_supported
            .iter()
            .find(|(_, cfg)| &cfg.format == fmt)
            .map(|(id, _)| id)
            .ok_or_else(|| anyhow!("Credential Configuration not found"))
    }

    /// Convenience method to provide the issuer's display name (if configured).
    ///
    /// TODO: The field is optional and contains locale information but because
    /// it is not a vec, only one locale is possible. Keep an eye on the spec
    /// and implement locale support if needed.
    #[must_use]
    pub fn display_name(&self, _locale: Option<&str>) -> Option<String> {
        self.display.as_ref().map(|d| d.name.clone())
    }
}

/// Contains information about whether the Credential Issuer supports encryption
/// of the Credential and Batch Credential Response on top of TLS.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct SupportedCredentialResponseEncryption {
    /// JWE [RFC7516] alg algorithm [RFC7518] REQUIRED for encrypting Credential
    /// Responses.
    ///
    /// [RFC7516]: (https://www.rfc-editor.org/rfc/rfc7516)
    /// [RFC7518]: (https://www.rfc-editor.org/rfc/rfc7518)
    pub alg_values_supported: Vec<String>,

    /// JWE [RFC7516] enc algorithm [RFC7518] REQUIRED for encrypting Credential
    /// Responses. If `credential_response_encryption_alg` is specified, the
    /// default for this value is "`A256GCM`".
    ///
    /// [RFC7516]: (https://www.rfc-editor.org/rfc/rfc7516)
    /// [RFC7518]: (https://www.rfc-editor.org/rfc/rfc7518)
    pub enc_values_supported: Vec<String>,

    /// Specifies whether the Credential Issuer requires the additional
    /// encryption on top of TLS for the Credential Response. If the value
    /// is true, the Credential Issuer requires encryption for every
    /// Credential Response and therefore the Wallet MUST provide encryption
    /// keys in the Credential Request. If the value is false, the Wallet
    /// MAY chose whether it provides encryption keys or not.
    pub encryption_required: bool,
}

/// Contains information about the Credential Issuer's support for batch
/// issuance of Credentials on the Credential Endpoint.
///
/// The presence of this parameter means that the issuer supports the proofs
/// parameter in the Credential Request so can issue more than one Verifiable
/// Credential for the same Credential Dataset in a single request/response.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct BatchCredentialIssuance {
    /// The maximum array size for the proofs parameter in a Credential Request.
    pub batch_size: i64,
}

/// Language-based display properties for Issuer or Claim.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Display {
    /// The name to use when displaying the name of the `Issuer` or `Claim` for
    /// the specified locale. If no locale is set, then this value is the
    /// default value.
    pub name: String,

    /// A BCP47 [RFC5646] language tag identifying the display language.
    ///
    /// [RFC5646]: (https://www.rfc-editor.org/rfc/rfc5646)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
}

/// Credential configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct CredentialConfiguration {
    /// Identifies the format of the credential, e.g. "`jwt_vc_json`" or
    /// "`ldp_vc`". Each object will contain further elements defining the
    /// type and claims the credential MAY contain, as well as information
    /// on how to display the credential.
    ///
    /// See OpenID4VCI [Credential Format Profiles] for more detail.
    ///
    /// [Credential Format Profiles]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-format-profiles
    #[serde(flatten)]
    pub format: Format,

    /// The `scope` value that this Credential Issuer supports for this
    /// credential. The value can be the same accross multiple
    /// `credential_configurations_supported` objects. The Authorization
    /// Server MUST be able to uniquely identify the Credential Issuer based
    /// on the scope value. The Wallet can use this value in
    /// the Authorization Request Scope values in this Credential Issuer
    /// metadata MAY duplicate those in the `scopes_supported` parameter of
    /// the Authorization Server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// Identifies how the Credential should be bound to the identifier of the
    /// End-User who possesses the Credential. Is case sensitive.
    ///
    /// Support for keys in JWK format [RFC7517] is indicated by the value
    /// "`jwk`". Support for keys expressed as a COSE Key object [RFC8152]
    /// (for example, used in [ISO.18013-5]) is indicated by the value
    /// "`cose_key`".
    ///
    /// When Cryptographic Binding Method is a DID, valid values MUST be a
    /// "did:" prefix followed by a method-name using a syntax as defined in
    /// Section 3.1 of [DID-Core], but without a ":" and method-specific-id.
    /// For example, support for the DID method with a method-name "example"
    /// would be represented by "did:example". Support for all DID methods
    /// listed in Section 13 of [DID Specification Registries] is indicated
    /// by sending a DID without any method-name.
    ///
    /// [RFC7517]: (https://www.rfc-editor.org/rfc/rfc7517)
    /// [RFC8152]: (https://www.rfc-editor.org/rfc/rfc8152)
    /// [ISO.18013-5]: (https://www.iso.org/standard/69084.html)
    /// [DID-Core]: (https://www.w3.org/TR/did-core/)
    /// [DID Specification Registries]: (https://www.w3.org/TR/did-spec-registries/)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_binding_methods_supported: Option<Vec<String>>,

    /// Case sensitive strings that identify the cryptographic suites supported
    /// for the `cryptographic_binding_methods_supported`. Cryptographic
    /// algorithms for Credentials in `jwt_vc` format should use algorithm
    /// names defined in IANA JOSE Algorithms Registry. Cryptographic
    /// algorithms for Credentials in `ldp_vc` format should use signature
    /// suites names defined in Linked Data Cryptographic Suite Registry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_signing_alg_values_supported: Option<Vec<String>>,

    /// The key proof(s) that the Credential Issuer supports. This object
    /// contains a list of name/value pairs, where each name is a unique
    /// identifier of the supported proof type(s). Valid values are defined
    /// in Section 7.2.1, other values MAY be used. This identifier is also
    /// used by the Wallet in the Credential Request as defined in Section
    /// 7.2. The value in the name/value pair is an object that contains
    /// metadata about the key proof and contains the following parameters
    /// defined by this specification:
    ///
    ///  - `jwt`: A JWT [RFC7519] is used as proof of possession. A proof object
    ///    MUST include a jwt claim containing a JWT defined in Section 7.2.1.1.
    ///
    ///  - `cwt`: A CWT [RFC8392] is used as proof of possession. A proof object
    ///    MUST include a cwt claim containing a CWT defined in Section 7.2.1.3.
    ///
    ///  - `ldp_vp`: A W3C Verifiable Presentation object signed using the Data
    ///    Integrity Proof as defined in [VC_DATA_2.0] or [VC_DATA], and where
    ///    the proof of possession MUST be done in accordance with
    ///    [VC_Data_Integrity]. When `proof_type` is set to `ldp_vp`, the proof
    ///    object MUST include a `ldp_vp` claim containing a W3C Verifiable
    ///    Presentation defined in Section 7.2.1.2.
    ///
    /// # Example
    ///
    /// ```json
    /// "proof_types_supported": {
    ///     "jwt": {
    ///         "proof_signing_alg_values_supported": [
    ///             "ES256"
    ///         ]
    ///     }
    /// }
    /// ```
    ///
    /// [RFC7519]: (https://www.rfc-editor.org/rfc/rfc7519)
    /// [RFC8392]: (https://www.rfc-editor.org/rfc/rfc8392)
    /// [VC_DATA]: (https://www.w3.org/TR/vc-data-model/)
    /// [VC_DATA_2.0]: (https://www.w3.org/TR/vc-data-model-2.0/)
    /// [VC_Data_Integrity]: (https://www.w3.org/TR/vc-data-integrity/)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_types_supported: Option<HashMap<String, ProofTypesSupported>>,

    /// Language-based display properties of the supported credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<Vec<CredentialDisplay>>,
}

impl CredentialConfiguration {
    /// Verifies that the `claimset` contains required claims and they are
    /// supported for the Credential.
    ///
    /// # Errors
    ///
    /// Returns an error if the `claimset` contains unsupported claims or does
    /// not contain required (mandatory) claims.
    pub fn verify_claims(&self, claimset: &HashMap<String, Claim>) -> Result<()> {
        // ensure `claimset` claims exist in the supported claims
        if !claimset.is_empty() {
            if let Some(claims) = &self.format.claims() {
                let _ = Self::claims_supported(claimset, claims);
            }
        }

        // ensure all mandatory claims are present
        if let Some(claims) = &self.format.claims() {
            return Self::claims_required(claimset, claims);
        }

        Ok(())
    }

    /// Verifies `claimset` claims are supported by the Credential
    fn claims_supported(
        claimset: &HashMap<String, Claim>, supported: &HashMap<String, Claim>,
    ) -> Result<()> {
        for (key, entry) in claimset {
            if !supported.contains_key(key) {
                return Err(anyhow!("{key} claim is not supported"));
            }

            // check nested claims
            if let Claim::Set(req_nested) = &entry {
                if let Claim::Set(sup_nested) = &supported[key] {
                    Self::claims_supported(req_nested, sup_nested)?;
                } else {
                    return Err(anyhow!("{key} claimset is not supported "));
                }
            }
        }

        Ok(())
    }

    /// Verifies `claimset` contains all required claims
    fn claims_required(
        requested: &HashMap<String, Claim>, supported: &HashMap<String, Claim>,
    ) -> Result<()> {
        for (key, entry) in supported {
            match entry {
                Claim::Set(sup_nested) => {
                    #[allow(clippy::or_fun_call)]
                    if let Claim::Set(req_nested) =
                        requested.get(key).unwrap_or(&Claim::Set(HashMap::new()))
                    {
                        Self::claims_required(req_nested, sup_nested)?;
                    } else {
                        return Err(anyhow!("{key} claim is not supported"));
                    }
                }
                Claim::Entry(def) => {
                    if def.mandatory.unwrap_or_default() && requested.get(key).is_none() {
                        return Err(anyhow!("{key} claim is required"));
                    }
                }
            }
        }

        Ok(())
    }

    /// Convenience method to display the claims as a vector of strings.
    #[must_use]
    pub fn claims_display(&self, locale: Option<&str>) -> Vec<String> {
        let mut claim_set = Vec::new();

        if let Some(claims) = &self.format.claims() {
            for (name, claim) in claims {
                let prefix = "";
                Self::claim_label(&mut claim_set, prefix, name, claim, locale);
            }
        }

        claim_set
    }

    /// Recursively build claim labels from nested claim definitions.
    fn claim_label(
        claim_set: &mut Vec<String>, prefix: &str, name: &str, claim: &Claim, locale: Option<&str>,
    ) {
        match claim {
            Claim::Entry(def) => {
                let locale_display = def.display.as_ref().and_then(|display| {
                    locale.as_ref().map_or_else(
                        || {
                            Some(
                                display
                                    .iter()
                                    .find(|d| d.locale.is_none())
                                    .unwrap_or_else(|| &display[0]),
                            )
                        },
                        |loc| display.iter().find(|d| d.locale.as_deref() == Some(loc)),
                    )
                });
                match locale_display {
                    Some(display) => claim_set.push(prefix.to_owned() + &display.name),
                    None => claim_set.push(prefix.to_owned() + &title_case(name)),
                }
            }
            Claim::Set(set) => {
                let mut pre = prefix.to_string();
                pre.push_str(&title_case(name));
                pre.push('.');
                for (name, claim) in set {
                    Self::claim_label(claim_set, &pre, name, claim, locale);
                }
            }
        }
    }
}

/// `ProofTypesSupported` describes specifics of the key proof(s) that the
/// Credential Issuer supports.
///
/// This object contains a list of name/value pairs, where each name is a unique
/// identifier of the supported proof type(s). Valid values are defined in
/// Section 7.2.1, other values MAY be used. This identifier is also used by the
/// Wallet in the Credential Request as defined in Section 7.2. The value in the
/// name/value pair is an object that contains metadata about the key proof.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ProofTypesSupported {
    /// One or more case sensitive strings that identify the algorithms that the
    /// Issuer supports for this proof type. The Wallet uses one of them to
    /// sign the proof. Algorithm names used are determined by the key proof
    /// type.
    ///
    /// For example, for JWT, the algorithm names are defined in IANA JOSE
    /// Algorithms Registry.
    ///
    /// # Example
    ///
    /// ```json
    /// "proof_signing_alg_values_supported": ["ES256K", "EdDSA"]
    /// ```
    pub proof_signing_alg_values_supported: Vec<String>,
}

/// `CredentialDisplay` holds language-based display properties of the supported
/// credential.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct CredentialDisplay {
    /// The value to use when displaying the name of the `Credential` for the
    /// specified locale. If no locale is set, then this is the default value.
    pub name: String,

    /// A BCP47 [RFC5646] language tag identifying the display language.
    ///
    /// [RFC5646]: (https://www.rfc-editor.org/rfc/rfc5646)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,

    /// Information about the logo of the Credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo: Option<Image>,

    /// Description of the Credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Background color of the Credential using CSS Color Module Level 37
    /// values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub background_color: Option<String>,

    /// Information about the background image of the Credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub background_image: Option<Image>,

    /// Text color color of the Credential using CSS Color Module Level 37
    /// values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_color: Option<String>,
}

/// Image contains information about the logo of the Credential.
/// N.B. The list is non-exhaustive and may be extended in the future.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Image {
    /// URL where the Wallet can obtain a logo of the Credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,

    /// Alternative text of a logo image.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alt_text: Option<String>,
}

// TODO: split into 2 types or use enum for variations based on format

/// `CredentialDefinition` defines a Supported Credential that may requested by
/// Wallets.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct CredentialDefinition {
    /// The @context property is used to map property URIs into short-form
    /// aliases, in accordance with the W3C Verifiable Credentials Data
    /// Model.
    ///
    /// REQUIRED when `format` is "`jwt_vc_json-ld`" or "`ldp_vc`".
    #[serde(rename = "@context")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<Vec<String>>,

    /// Uniquely identifies the credential type the Credential Definition
    /// display properties are for, in accordance with the W3C Verifiable
    /// Credentials Data Model.
    /// Contains the type values the Wallet requests authorization for at the
    /// Credential Issuer. It MUST be present if the claim format is present in
    /// the root of the authorization details object. It MUST not be present
    /// otherwise.
    #[serde(rename = "type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_: Option<Vec<String>>,

    /// A list of name/value pairs identifying claims offered in the Credential.
    /// A value can be another such object (nested data structures), or an array
    /// of objects. Each claim defines language-based display properties for
    /// `credentialSubject` fields.
    ///
    /// N.B. This property is used by the Wallet to specify which claims it is
    /// requesting to be issued out of all the claims the Credential Issuer is
    /// capable of issuing for this particular Credential (data minimization).
    #[serde(rename = "credentialSubject")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_subject: Option<HashMap<String, Claim>>,
}

/// Claim is used to hold language-based display properties for a
/// credentialSubject field.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ClaimDefinition {
    /// When true, indicates that the Credential Issuer will always include this
    /// claim in the issued Credential. When false, the claim is not
    /// included in the issued Credential if the wallet did not request the
    /// inclusion of the claim, and/or if the Credential Issuer chose to not
    /// include the claim. If the mandatory parameter is omitted, the
    /// default value is false. Defaults to false.
    //  #[serde(skip_serializing_if = "std::ops::Not::not")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mandatory: Option<bool>,

    /// The type of value of the claim. Defaults to string. Supported values
    /// include `string`, `number`, and `image` media types such as
    /// image/jpeg. See [IANA media type registry] for a complete list of
    /// media types.
    ///
    /// [IANA media type registry]: (https://www.iana.org/assignments/media-types/media-types.xhtml#image)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_type: Option<ValueType>,

    /// Language-based display properties of the field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<Vec<Display>>,
    //
    // /// Nested claims.
    // #[serde(flatten)]
    // #[serde(skip_serializing_if = "Option::is_none")]
    // pub nested: Option<HashMap<String, Claim>>,
}

/// `ValueType` is used to define a claim's value type.
#[derive(Default, Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ValueType {
    /// Value of type String. The default.
    #[default]
    String,

    /// Value of type Number.
    Number,

    /// Image media types such as `image/jpeg`. See [IANA media type registry]
    /// for a complete list of media types.
    ///
    ///[IANA media type registry]: (https://www.iana.org/assignments/media-types/media-types.xhtml#image)
    Image,
}

/// OAuth 2 client metadata used for registering clients of the issuance and
/// wallet authorization servers.
///
/// In the case of Issuance, the Wallet is the Client and the Issuer is the
/// Authorization Server.
///
/// In the case of Presentation, the Wallet is the Authorization Server and the
/// Verifier is the Client.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Client {
    /// OAuth 2.0 Client
    #[serde(flatten)]
    pub oauth: OAuthClient,

    /// Used by the Wallet to publish its Credential Offer endpoint. The
    /// Credential Issuer should use "`openid-credential-offer://`" if
    /// unable to perform discovery of the endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_offer_endpoint: Option<String>,
}

/// OAuth 2.0 Authorization Server metadata.
/// See RFC 8414 - Authorization Server Metadata
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Server {
    /// OAuth 2.0 Server
    #[serde(flatten)]
    pub oauth: OAuthServer,

    /// Indicates whether the issuer accepts a Token Request with a
    /// Pre-Authorized Code but without a client id. Defaults to false.
    #[serde(rename = "pre-authorized_grant_anonymous_access_supported")]
    pub pre_authorized_grant_anonymous_access_supported: bool,
}
