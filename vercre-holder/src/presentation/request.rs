//! # Presentation Request Endpoint
//!
//! The `request` endpoint can take a request for presentation in the form of a
//! URI to go get the request details or all of the details as a `RequestObject`
//! struct serialized to a URL query parameter.

use anyhow::{anyhow, bail};
use vercre_core::Kind;
use vercre_dif_exch::Constraints;
use vercre_infosec::jose::jws;
use vercre_openid::verifier::{RequestObject, RequestObjectResponse, RequestObjectType};
use vercre_w3c_vc::verify_key;

use super::{PresentationState, Status};
use crate::credential::Credential;
use crate::provider::DidResolver;

impl PresentationState {
    /// Update the presentation with a request object retrieved from the
    /// verifier's endpoint.
    /// 
    /// # Errors
    /// If a set of constraints cannot be built from the request object's
    /// presentation definition an error is returned.
    pub fn request(&mut self, request: &RequestObject) -> anyhow::Result<Constraints> {
        self.request.clone_from(request);
        self.status = Status::Requested;
        let filter = Self::build_filter(request).map_err(|e|
            anyhow!("issue building filter from RequestObject: {e}")
        )?;
        self.filter.clone_from(&filter);
        Ok(filter)
    }

    /// Utility to extract a presentation `RequestObject` from a
    /// `RequestObjectResponse`. Uses a DID resolver to verify the JWT.
    /// 
    /// # Errors
    /// If decoding or verifying the JWT fails an error is returned.
    pub async fn parse_request_object_response(
        res: &RequestObjectResponse, resolver: impl DidResolver,
    ) -> anyhow::Result<RequestObject> {
        let RequestObjectType::Jwt(token) = &res.request_object else {
            bail!("no serialized JWT found in response");
        };
        let jwt: jws::Jwt<RequestObject> = jws::decode(token, verify_key!(resolver))
            .await
            .map_err(|e| anyhow!("failed to parse JWT: {e}"))?;

        Ok(jwt.claims)
    }

    /// Update the presentation with a list of credentials that match the
    /// verifier's request.
    ///
    /// # Errors
    /// Will return an error if the presentation flow state is not consistent
    /// with adding credentials.
    pub fn credentials(&mut self, credentials: &Vec<Credential>) -> anyhow::Result<()> {
        if self.status != Status::Requested {
            bail!("cannot add credentials to a flow without a request");
        }
        self.credentials.clone_from(credentials);
        self.status = Status::CredentialsSet;
        Ok(())
    }

    fn build_filter(request: &RequestObject) -> anyhow::Result<Constraints> {
        let pd = match &request.presentation_definition {
            Kind::Object(pd) => pd,
            Kind::String(_) => bail!("presentation_definition_uri is unsupported"),
        };
        if pd.input_descriptors.is_empty() {
            bail!("no input descriptors found");
        }
        let constraints = pd.input_descriptors[0].constraints.clone();
    
        Ok(constraints)
    }    
}
