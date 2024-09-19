/// DID resolution error codes
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// The DID method is not supported.
    #[error("methodNotSupported")]
    MethodNotSupported(String),

    /// The DID supplied to the DID resolution function does not conform to
    /// valid syntax.
    #[error("invalidDid")]
    InvalidDid(String),

    /// The DID resolver was unable to find the DID document resulting from
    /// this resolution request.
    #[error("notFound")]
    NotFound(String),

    /// The representation requested via the accept input metadata property is
    /// not supported by the DID method and/or DID resolver.
    #[error("representationNotSupported")]
    RepresentationNotSupported(String),

    /// The DID URL is invalid
    #[error("invalidDidUrl")]
    InvalidDidUrl(String),

    // ---- Creation Errors ----  //
    /// The byte length of raw public key does not match that expected for the
    /// associated multicodecValue.
    #[error("invalidPublicKeyLength")]
    InvalidPublicKeyLength(String),

    /// The public key is invalid
    #[error("invalidPublicKey")]
    InvalidPublicKey(String),

    /// Public key format is not known to the implementation.
    #[error("unsupportedPublicKeyType")]
    UnsupportedPublicKeyType(String),

    /// Other, unspecified errors.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl Error {
    /// Returns the error code.
    #[must_use]
    pub fn code(&self) -> String {
        self.to_string()
    }

    /// Returns the associated error message.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::MethodNotSupported(msg)
            | Self::InvalidDid(msg)
            | Self::NotFound(msg)
            | Self::InvalidDidUrl(msg)
            | Self::RepresentationNotSupported(msg)
            | Self::InvalidPublicKeyLength(msg)
            | Self::InvalidPublicKey(msg)
            | Self::UnsupportedPublicKeyType(msg) => msg.clone(),
            Self::Other(err) => err.to_string(),
        }
    }
}

// impl From<anyhow::Error> for Error {
//     fn from(err: anyhow::Error) -> Self {
//         Self
//     }
// }

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn error_code() {
        let err = Error::MethodNotSupported("Method not supported".into());
        assert_eq!(err.message(), "Method not supported");
    }
}
