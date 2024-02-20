# Draft 13 Changes

- [x] change the structure of `proof_types` from an array to a `proof_types_supported` map that contains a required `proof_signing_alg_values_supported` parameter
- [x] renamed `cryptographic_suites_supported` to `credential_signing_alg_values_supported` to clarify the purpose of the parameter
- [x] renamed `credential_configurations` Credential Offer parameter to `credential_configuration_ids`
- [x] remove `format` from the Credential Response
- [x] added `signed_metadata` parameter
- [x] clarified that logo can is a uri and not a url only
- [x] clarified description of a mandatory claim
- [x] added an option in `authorization_details` to use `credential_configuration_id` pointing to the name of a `credential_configurations_supported` object in the Credential Issuer's Metadata; in addition to an option to use format and type.
- [x] renamed `credentials` Credential Offer parameter to `credential_configuration_ids`
- [x] renamed `credentials_supported` Credential Issuer metadata parameter to `credential_configurations_supported`
- [x] replaced `user_pin_required` in Credential Offer with a `tx_code` object that also now contains description and length
- [x] reworked flow description in Overview section
- [x] added support for HTTP Accept-Language Header in the request for Credential Issuer Metadata to request a subset for display data
- [x] clarified how the Credential Issuer indicates that it requires proof of possession of the cryptographic key material in the Credential Request
- [x] added an option to use data integrity proofs as proof of possession of the cryptographic key material in the Credential Request
- [x] added privacy considerations
- [x] clarifed that AS that only supports pre-auth grant can omit `response_types_supported` metadata
- [x] added `background_image` credential issuer metadata

- [ ] grouped `credential_encryption_jwk`, `credential_response_encryption_alg` and `credential_response_encryption_enc` from Credential Request into a single `credential_response_encryption` object
- [ ] added a Notification Endpoint used by the Wallet to notify the Credential Issuer of certain events for issued Credentials

# TODOs

- [ ] check proof_types_supported in credential request verification
- [ ] Credential format vc+sd-jwt?
- [ ] test `credential_configuration_id` in `authorization_details`
- [ ] analyse `credential_identifiers` use in `authorization_details`
