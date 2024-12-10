//! # Presentation Present Endpoint
//!
//! The `present` endpoint creates a presentation submission, signs it, and
//! sends it to the verifier.

use anyhow::bail;
use uuid::Uuid;
use vercre_core::Kind;
use vercre_dif_exch::{DescriptorMap, FilterValue, PathNested, PresentationSubmission};
use vercre_openid::verifier::ResponseRequest;
use vercre_w3c_vc::model::vp::VerifiablePresentation;
use vercre_w3c_vc::proof::Payload;

use super::{PresentationState, Status};

impl PresentationState {
    /// Construct a presentation submission from the current presentation flow
    /// state.
    ///
    /// # Errors
    /// If the presentation state is consistent with this step an error is
    /// returned.
    pub fn create_verifiable_presentation_payload(
        &mut self, key_identifier: &str,
    ) -> anyhow::Result<Payload> {
        if self.status != Status::Authorized {
            bail!("presentation is not authorized");
        }
        let request = self.request.clone();
        let pd = match &request.presentation_definition {
            Kind::Object(pd) => pd,
            Kind::String(_) => bail!("presentation_definition_uri is unsupported"),
        };

        let mut desc_map: Vec<DescriptorMap> = vec![];
        for n in 0..pd.input_descriptors.len() {
            let in_desc = &pd.input_descriptors[n];
            let dm = DescriptorMap {
                id: in_desc.id.clone(),
                path: "$".to_string(),
                path_nested: PathNested {
                    format: "jwt_vc_json".to_string(),
                    // URGENT: index matched VCs not input descriptors!!
                    path: "$.verifiableCredential[0]".to_string(),
                },
                format: "jwt_vc_json".to_string(),
            };
            desc_map.push(dm);
        }
        self.submission = PresentationSubmission {
            id: Uuid::new_v4().to_string(),
            definition_id: pd.id.clone(),
            descriptor_map: desc_map,
        };

        let holder_did = key_identifier.split('#').collect::<Vec<&str>>()[0];

        // presentation with 2 VCs: one as JSON, one as base64url encoded JWT
        let mut builder = VerifiablePresentation::builder()
            .add_context(Kind::String("https://www.w3.org/2018/credentials/examples/v1".into()))
            .holder(holder_did);

        let pd = match &self.request.presentation_definition {
            Kind::Object(pd) => pd,
            Kind::String(_) => bail!("presentation_definition_uri is unsupported"),
        };

        for input in &pd.input_descriptors {
            if let Some(fields) = &input.constraints.fields {
                for field in fields {
                    if let Some(filter) = &field.filter {
                        if let FilterValue::Const(val) = &filter.value {
                            builder = builder.add_type(val.clone());
                        }
                    }
                }
            }
        }

        for c in &self.credentials {
            builder = builder.add_credential(Kind::String(c.issued.clone()));
        }
        let vp = builder.build()?;

        let payload = Payload::Vp {
            vp,
            client_id: self.request.client_id.clone(),
            nonce: self.request.nonce.clone(),
        };

        Ok(payload)
    }

    /// Create a presentation response request and the presentation URI from the
    /// current flow state and the provided proof.
    #[must_use]
    pub fn create_response_request(&self, jwt: &str) -> (ResponseRequest, Option<String>) {
        let res_req = ResponseRequest {
            vp_token: Some(vec![Kind::String(jwt.into())]),
            presentation_submission: Some(self.submission.clone()),
            state: self.request.state.clone(),
        };
        let res_uri =
            self.request.response_uri.clone().map(|uri| uri.trim_end_matches('/').to_string());
        (res_req, res_uri)
    }
}
