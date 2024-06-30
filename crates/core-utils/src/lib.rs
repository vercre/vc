//! # `OpenID` Core

// generic member access API on the error trait
// https://github.com/rust-lang/rust/issues/99301
#![feature(error_generic_member_access)]

pub mod endpoint;
pub mod gen;
pub mod jws;

pub use self::endpoint::{Context, Endpoint};
