# Overview

Vercre comprises a collection of libraries for issuing, holding, and verifying Verifiable Credentials. It is designed to be modular and flexible, allowing implementers to use only the modules needed.

Each top-level library is intended to as near feature complete as possible, requiring minimal code to deliver a working application. The libraries are designed can be used independently, but work together for an end-to-end Verifiable Data solution.

The three primary libraries are:

- [`vercre-wallet`](<https://github.com/vercre/vercre/tree/main/vercre-wallet/>) — greatly simplifies building cross-platform wallets.
- [`vercre-vci`](<https://github.com/vercre/vercre/tree/main/vercre-vci/>) — for building credential issuance APIs.
- [`vercre-vp`](<https://github.com/vercre/vercre/tree/main/vercre-vp/>) — for building verifiable presentation APIs.

## Implementation

The libraries are written in Rust and are designed to be used in a variety of environments, including WebAssembly, mobile, and server-side applications.
