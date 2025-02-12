# Introduction

Credibil VC is a library for issuing, holding, and verifying 
Verifiable Credentials. It is designed to be modular and flexible, allowing 
implementers to use only the modules needed.

## Features

The Credibil VC library has two feature flags that can be used independently or work together for an
end-to-end Verifiable Data solution:

- `issuer` — for building credential issuance APIs.
- `verifier` — for building verifiable presentation APIs.

## Holder

In addition to the Credibil VC library is an opinionated SDK for developing applications that act as a holder's agent in the issuance, presentation and storage of Verifiable Credentials. This is found in a separate repository:

- [`credibil-holder`] — greatly simplifies building cross-platform wallets.

[`credibil-holder`](https://github.com/credibil/holder)

## Shell

Each library requires a 'shell' to wrap and expose functionality. The shell is 
responsible for handling the application's specific requirements, such as user 
interface, storage, and network communication.

In the case of the server-side features (`issuer` and `verifier`), the shell is
typically an HTTP server. While in the case of the holder's agent library 
(`credibil-holder`), the shell is typically a mobile or web application.

Example 'shell' implementations can be found in the `examples` directory.

## Implementation

The libraries are written in Rust and are designed to be used in a variety of 
environments, including WebAssembly, mobile, and server-side applications.
