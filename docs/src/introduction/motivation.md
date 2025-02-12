# Motivation

When initially exposed to the concepts underpinning decentralized identity, we were excited about its potential to create 'trust-less' digital ecosystems. Privacy-respecting, cryptographically-provable digital credentials would revolutionize the way we interact online.

Immediately after that, we were struck by the range of protocols and the dearth of easy-to-use open-source libraries available to integrate into our applications. Decentralized identity needed to be more accessible for average developers like us.

With the introduction of the OpenID for [Verifiable Credential Issuance](<https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html>) and [Verifiable Presentations](<https://openid.net/specs/openid-4-verifiable-presentations-1_0.html>) standards we believe there is an opportunity to redress this lack and bring Verifiable Credentials further into the mainstream.

## Our Contribution

So we thought: why not? Let's see if we can create something for ourselves and others to use to integrate Verifiable Credentials into applications.

We are hoping to contribute to the emergence of decentralized digital trust ecosystems by providing a set of easy-to-use, open-source libraries.

By settling on the OpenID standards, we are making a (safe-ish) bet on the not-inconsiderable base of OpenID-based systems and libraries developed over the years. We want to leverage this existing infrastructure to make it easier for developers to integrate Verifiable Credentials into their applications.

## Why Rust?

One of the benefits of a systems programming language like Rust is the ability to control low-level details.

Rust's small binary footprint and efficient memory usage make it well-suited for deployment on small, low-spec devices for a truly distributed infrastructure. And while we have yet to optimize for either, we are confident Rust will be up to the task.

Also, without the need for garbage collection, Rust libraries are eminently well-suited for use by other programming languages via foreign-function interfaces. Non-Rust applications can integrate Credibil VC without the memory safety risks inherent with other systems programming languages.
