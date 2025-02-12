# Architecture

At its most simple, Credibil VC is a library that support 
developers in building Verifiable Credential-based applications. That is, applications
that can issue, present, and verify credentials — all underpinned by OpenID for 
Verifiable Credential specifications.

Users bring their own HTTP server(s) and implement provider traits for each library.

![overview](../images/architecture.png)

## Issuer-Holder-Verifier

Credibil VC is modelled around the _Issuer-Holder-Verifier_ model — a means of exchanging 
Verifiable Credential claims, where claim issuance is independent of the process of 
presenting them to Verifiers.

The library has two feature flags that map to the model's _Issuer_ and _Verifier_ components:

- [issuer](../using/issuer/index.md) to the _Issuer_
- [verifier](../using/verifier/index.md) to the _Verifier_

A separate repository provides an opinionated set of data structures and examples that can build _Holder_ agent components:

- [credibil-holder](../using/holder/index.md) to the _Holder_.

## Providers

Each library has a numer of provider traits that users must implement to use the 
library. Providers allow users to customize the behavior of the library to their 
needs by bringing their own persistence, state management, secure signing, etc..

We'll cover providers in more depth in the user guides for each library.