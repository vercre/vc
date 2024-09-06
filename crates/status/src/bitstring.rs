//! # Bitstring Status List
//!
//! Types and helpers for implementing a status list using a bitstring. Follows
//! the specification [Bitstring Status List v1.0](https://www.w3.org/TR/vc-bitstring-status-list/).

use std::io::Write;

use anyhow::anyhow;
use base64ct::{Base64UrlUnpadded, Encoding};
use bitvec::{bits, view::BitView};
use bitvec::order::Lsb0;
use flate2::write::GzEncoder;
use vercre_w3c_vc::model::StatusPurpose;

use crate::{config::ListConfig, log::StatusLogEntry};

// TODO: Configurable.
// TODO: This is minimum length as per spec. May need to be configurable
// for data VCs where potentially huge numbers of credentials of a type
// can be issued. Or we need to use a more sophisticated list sharding.
// (Currently assumes one list per credential type.) Business requirements
// for short-lived data credentials may not require status lists anyway and
// we could just bump up this limit to something large but practical and
// only support lists up to that length. Alternatively, we can re-use list
// entries once a credential expires.
const MAX_ENTRIES: usize = 131_072;

/// Generates a compressed, encoded bitstring representing the status list for
/// the given issued credentials and the purpose implied by a list configuration.
///
/// #Errors
///
/// Returns an error if there is a compression or encoding problem, or the
/// provided status position is out of range of the bitstring size.
///
/// Must be a multi-base encoded base64 url without padding. It is the
/// encoded representation of the GZIP-compressed bitstring values for
/// the associated range of verifiable credential status values. The
/// uncompressed bitstring must be at least 16KB in size. The bitstring
/// must be encoded such that the first index, with a value of zero, is
/// located at the left-most bit in the bitstring, and the last index, with
/// a value of one less than the length of the bitstring, is located at the
/// right-most bit in the bitstring.
///
/// Note: This function scans the entire status log presented to construct a
/// bitstring from scratch which will be inefficient compared to a method for
/// processing a known update to the status of an individual credential. (A new
/// credential issued or an update to the status of an existing one).
//
// TODO: Provide methods for updating the bitstring incrementally.
pub fn generate_bitstring(
    config: &ListConfig, issued: &[StatusLogEntry],
) -> anyhow::Result<String> {
    let bits = bits![mut 0; MAX_ENTRIES];
    for entry in issued {
        for status in &entry.status {
            if status.purpose != config.purpose {
                continue;
            }

            let position = status.list_index * config.size;
            if position >= bits.len() {
                return Err(anyhow!("status index out of range"));
            }
            match config.purpose {
                StatusPurpose::Revocation | StatusPurpose::Suspension => {
                    bits.set(position, status.value != 0);
                }
                StatusPurpose::Message => {
                    let value = status.value.view_bits::<Lsb0>();
                    for (i, bit) in value.iter().enumerate() {
                        bits.set(position + i, *bit);
                    }
                }
            }
        }
    }

    let uncompressed = bits.into_iter().map(|b| if *b { '1' } else { '0' }).collect::<String>();

    let mut gz_encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz_encoder.write_all(uncompressed.as_bytes())?;
    let compressed = gz_encoder.finish()?;

    let encoded = Base64UrlUnpadded::encode_string(&compressed);

    Ok(encoded)
}
