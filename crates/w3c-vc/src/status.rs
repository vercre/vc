//! # Bitstring Status List
//!
//! It is often useful for an issuer of Verifiable Credentials to link to a location
//! where a verifier can check to see if a credential has been suspended or revoked.
//! This additional resource is referred to as a "status list".
//!
//! The simplest approach for a status list, where there is a one-to-one mapping
//! between a Verifiable Credential and a URL where the status is published, raises
//! privacy as well as performance issues. In order to meet privacy expectations, it
//! is useful to bundle the status of large sets of credentials into a single list.
//! However, doing so can place an impossible burden on both the server and client if
//! the status information is as much as a few hundred bytes per credential across
//! hundreds of thousands of holders.
//!  
//! The [Bitstring Status List v1.0] specification defines a
//! highly compressible, highly space-efficient bitstring-based status list mechanism.
//!
//! Conceptually, a bitstring status list is a sequence of bits. When a single bit
//! specifies a status, such as "revoked" or "suspended", then that status is expected
//! to be true when the bit is set and false when unset. One of the benefits of using a
//! bitstring is that it is a highly compressible data format since, in the average
//! case, large numbers of credentials will remain unrevoked. If compressed using
//! run-length compression techniques such as GZIP [RFC1952] the result is a
//! significantly smaller set of data: the default status list size is 131,072 entries,
//! equivalent to 16 KB of single bit values and, when only a handful of verifiable
//! credentials are revoked, GZIP compresses the bitstring down to a few hundred bytes.
//!
//! [Bitstring Status List v1.0]: https://www.w3.org/TR/vc-bitstring-status-list
//! [RFC1952]: https://www.rfc-editor.org/rfc/rfc1952

// TODO: implement BitstringStatusList
