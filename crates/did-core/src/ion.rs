use crate::document::{DidDocument, DidDocumentMetadata};
use crate::{DidResolution, DidResolutionMetadata, DidResolver, ResolutionOptions};

pub struct DidIon;

impl DidResolver for DidIon {
    fn resolve(&self, did: &str, opts: impl ResolutionOptions) -> anyhow::Result<DidResolution> {
        unimplemented!()
    }

    fn resolve_representation(
        &self, did: &str, opts: impl ResolutionOptions,
    ) -> anyhow::Result<DidResolution> {
        unimplemented!()
    }
}
