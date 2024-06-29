use thiserror::Error;

#[allow(clippy::module_name_repetitions)]
#[derive(Error, Debug)]
pub enum OpenIdError {
    #[allow(dead_code)]
    #[error("invalid_request")]
    InvalidRequest,
}

#[cfg(test)]
mod test {
    use anyhow::{ensure, Context};

    use super::*;

    #[test]
    fn test_ensure() {
        if let Err(e) = ensure() {
            println!("error: {:?}", e.to_string());

            let my_error = e.downcast_ref::<OpenIdError>();
            println!("my_error: {:?}", my_error);
        }
    }

    fn ensure() -> anyhow::Result<()> {
        ensure!(1 == 2, OpenIdError::InvalidRequest);
        Ok(())
    }

    #[test]
    fn test_regular() {
        if let Err(e) = regular() {
            println!("error: {} {}", e, e.source().unwrap());

            let my_error = e.downcast_ref::<OpenIdError>();
            println!("my_error: {:?}", my_error);
        }
    }

    fn regular() -> anyhow::Result<()> {
        return Err(OpenIdError::InvalidRequest).context("context");
    }
}
