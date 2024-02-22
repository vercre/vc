// use anyhow::Context;
use serde::de::{Deserializer, Error};
use serde::Deserialize;

use crate::error::{Ancillary, Err};

impl<'de> Deserialize<'de> for super::InvokeRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let request = Self::deserialize(deserializer)?;

        // // must have credential issuer
        // if request.credential_issuer.is_empty() {
        //     return Err(Err::InvalidRequest)
        //         .hint(format!("no credential_issuer specified"))
        //         .map_err(D::Error::custom);
        // };

        // credentials required
        if request.credential_configuration_ids.is_empty() {
            return Err(Err::InvalidRequest)
                .hint("no credentials requested")
                .map_err(D::Error::custom);
        };

        // holder_id is required
        if request.holder_id.is_none() {
            return Err(Err::InvalidRequest)
                .hint("no holder_id specified")
                .map_err(D::Error::custom);
        };

        Ok(request)
    }
}
