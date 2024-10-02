pub mod de;
pub mod ser;

#[doc(inline)]
pub use crate::urlencode::de::{from_bytes, from_reader, from_str, Deserializer};
#[doc(inline)]
pub use crate::urlencode::ser::{to_string, Serializer};
