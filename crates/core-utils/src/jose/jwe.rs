//! # JSON Web Encryption (JWE)
//!
//! JWE ([RFC7516]) specifies how encrypted content can be represented using JSON.
//!
//! See JWA ([RFC7518]) for more on the cyptographic algorithms and identifiers
//! used.
//!
//! ## Note
//!
//! If the JWT is only a JWE, iss, exp and aud MUST be omitted in the JWT Claims
//! Set of the JWE, and the processing rules as per JARM Section 2.4 related to
//! these claims do not apply. [OpenID4VP] JWT - JWE
//!
//! [RFC7516]: https://www.rfc-editor.org/rfc/rfc7516
//! [RFC7518]: https://www.rfc-editor.org/rfc/rfc7518
//! [IANA]: https://www.iana.org/assignments/jose/jose.xhtml

// Compact:
// BASE64URL(UTF8(JWE Protected Header)) + '.' +
// BASE64URL(JWE Encrypted Key) + '.' +
// BASE64URL(JWE Initialization Vector) + '.' +
// BASE64URL(JWE Ciphertext) + '.' +
// BASE64URL(JWE Authentication Tag)

// https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms

// https://www.rfc-editor.org/rfc/rfc7516.html (JSON Web Encryption (JWE))
// https://www.rfc-editor.org/rfc/rfc7518.html (JSON Web Algorithms (JWA))

// "alg_values_supported" : [
// 	"ECDH-ES" // <- Diffie-Hellman Ephemeral Static key agreement using Concat KDF
// ],
// "enc_values_supported" : [
// 	"A128GCM" // <- 128-bit AES-GCM
// ],

// https://www.rfc-editor.org/rfc/rfc7518#appendix-C:

// {
// 	"alg":"ECDH-ES",
// 	"enc":"A128GCM",
// 	"apu":"QWxpY2U",
// 	"apv":"Qm9i",
// 	"epk": {
// 		"kty":"EC",
//         "crv":"P-256",
//         "x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
//         "y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"
// 	}
// }
