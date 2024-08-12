//! # Presentation Present Endpoint
//!
//! The `present` endpoint creates a presentation submission, signs it, and sends it to the
//! verifier.

use anyhow::{anyhow, bail};
use tracing::instrument;
use uuid::Uuid;
use vercre_core::Kind;
use vercre_dif_exch::{DescriptorMap, FilterValue, PathNested, PresentationSubmission};
use vercre_openid::verifier::{PresentationDefinitionType, ResponseRequest, ResponseResponse};
use vercre_w3c_vc::model::vp::VerifiablePresentation;
use vercre_w3c_vc::proof::{self, Format, Payload};

use super::{Presentation, Status};
use crate::provider::{HolderProvider, Signer, Verifier};

/// Creates a presentation submission, signs it and sends it to the verifier. The `request`
/// parameter is the presentation flow ID of an authorized presentation request created in
/// prior steps.
#[instrument(level = "debug", skip(provider))]
pub async fn present(
    provider: impl HolderProvider, request: String,
) -> anyhow::Result<ResponseResponse> {
    tracing::debug!("Endpoint::present");

    let Ok(mut presentation) = super::get_presentation(provider.clone(), &request).await else {
        let e = anyhow!("unable to retrieve presentation state");
        tracing::error!(target: "Endpoint::present", ?e);
        return Err(e);
    };
    if presentation.status != Status::Authorized {
        let e = anyhow!("Invalid presentation state");
        tracing::error!(target: "Endpoint::present", ?e);
        return Err(e);
    }

    // Construct a presentation submission.
    let submission = match create_submission(&presentation) {
        Ok(submission) => submission,
        Err(e) => {
            tracing::error!(target: "Endpoint::present", ?e);
            return Err(e);
        }
    };
    presentation.submission.clone_from(&submission);

    // create vp
    let kid = Signer::verification_method(&provider);
    let holder_did = kid.split('#').collect::<Vec<&str>>()[0];

    let vp = match create_vp(&presentation, holder_did) {
        Ok(vp) => vp,
        Err(e) => {
            tracing::error!(target: "Endpoint::present", ?e);
            return Err(e);
        }
    };

    let payload = Payload::Vp {
        vp,
        client_id: presentation.request.client_id.clone(),
        nonce: presentation.request.nonce.clone(),
    };
    let jwt = match proof::create(Format::JwtVcJson, payload, provider.clone()).await {
        Ok(jwt) => jwt,
        Err(e) => {
            tracing::error!(target: "Endpoint::present", ?e);
            return Err(e);
        }
    };

    // Assemble the presentation response to the verifier and ask the wallet client to send it.
    let res_req = ResponseRequest {
        vp_token: Some(vec![Kind::String(jwt)]),
        presentation_submission: Some(submission),
        state: presentation.request.state.clone(),
    };
    let res_uri =
        presentation.request.response_uri.map(|uri| uri.trim_end_matches('/').to_string());
    let response =
        match Verifier::present(&provider, &presentation.id, res_uri.as_deref(), &res_req)
            .await
        {
            Ok(response) => response,
            Err(e) => {
                tracing::error!(target: "Endpoint::present", ?e);
                return Err(e);
            }
        };

    Ok(response)
}

/// Create a presentation submission from the presentation request and matched credentials.
fn create_submission(presentation: &Presentation) -> anyhow::Result<PresentationSubmission> {
    let request = presentation.request.clone();
    let pd = match &request.presentation_definition {
        PresentationDefinitionType::Object(pd) => pd,
        PresentationDefinitionType::Uri(_) => bail!("presentation_definition_uri is unsupported"),
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
    let submission = PresentationSubmission {
        id: Uuid::new_v4().to_string(),
        definition_id: pd.id.clone(),
        descriptor_map: desc_map,
    };
    Ok(submission)
}

/// Construct a Verifiable Presentation.
fn create_vp(
    presentation: &Presentation, holder_did: impl Into<String>,
) -> anyhow::Result<VerifiablePresentation> {
    // presentation with 2 VCs: one as JSON, one as base64url encoded JWT
    let mut builder = VerifiablePresentation::builder()
        .add_context(Kind::String("https://www.w3.org/2018/credentials/examples/v1".into()))
        .holder(holder_did);

    let pd = match &presentation.request.presentation_definition {
        PresentationDefinitionType::Object(pd) => pd,
        PresentationDefinitionType::Uri(_) => bail!("presentation_definition_uri is unsupported"),
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

    for c in &presentation.credentials {
        builder = builder.add_credential(Kind::String(c.issued.clone()));
    }
    builder.build()
}
