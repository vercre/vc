# Introduction

Vercre comprises a collection of libraries for issuing, holding, and verifying 
Verifiable Credentials. It is designed to be modular and flexible, allowing 
implementers to use only the modules needed.

## Libraries

The three top-level Vercre libraries can be used independently or work together for an
end-to-end Verifiable Data solution:

- [`vercre-holder`] — greatly simplifies building cross-platform wallets.
- [`vercre-issuer`] — for building credential issuance APIs.
- [`vercre-verifier`] — for building verifiable presentation APIs.

[`vercre-holder`]: https://github.com/vercre/vercre/tree/main/vercre-holder
[`vercre-issuer`]: https://github.com/vercre/vercre/tree/main/vercre-issuer
[`vercre-verifier`]: https://github.com/vercre/vercre/tree/main/vercre-verifier

## Shell

Each library requires a 'shell' to wrap and expose functionality. The shell is 
responsible for handling the application's specific requirements, such as user 
interface, storage, and network communication.

In the case of the server-side libraries (`vercre-issuer` and `vercre-verifier`), the shell is
typically an HTTP server. While in the case of the holder's agent library 
(`vercre-holder`), the shell is typically a mobile or web application.

Example 'shell' implementations can be found in the `examples` directory.

## Implementation

The libraries are written in Rust and are designed to be used in a variety of 
environments, including WebAssembly, mobile, and server-side applications.
