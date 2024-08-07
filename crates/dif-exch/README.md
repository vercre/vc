# Presentation Exchange

>This crate is a higher order crate to support the Vercre suite of crates. It is not intended to be used directly. See
>
>* [vercre-issuer](https://crates.io/crates/vercre-issuer)
>* [vercre-verifier](https://crates.io/crates/vercre-verifier)
>* [vercre-holder](https://crates.io/crates/vercre-holder)

Created to support the DIF [Presentation Exchange 2.0.0] this crate contains building
blocks for articulating identity proof requirements (`Presentation Definition`) and 
the proofs or Claims, submitted in accordance with those requirements 
(`Presentation Submission`).

As the specification only requires Claims to be serializable as JSON, this crate
provides a `serde`-compatible `Claim` trait that can be implemented for a variety of
Claim formats. This could include JSON Web Tokens (JWTs), Verifiable Credentials (VCs),
JWT-VCs, etc..

```rust,ignore
use dif_exch::Claim;

impl Claims for VerifiableCredential {
    fn to_json(&self) -> anyhow::Result<serde_json::Value> {
        serde_json::to_value(self).map_err(Into::into)
    }
}
```

## Presentation Definition

Presentation Definitions are objects that articulate what proofs a Verifier requires. 
These help the Verifier to decide how or whether to interact with a Holder. Presentation
Definitions are composed of inputs, which describe the forms and details of the proofs 
they require, and optional sets of selection rules, to allow Holders flexibility in 
cases where many different types of proofs may satisfy an input requirement. 

The Presentation Exchange specification codifies a Presentation Definition data format 
Verifiers can use to articulate proof requirements, and a Presentation Submission data 
format Holders can use to describe proofs submitted in accordance with them.

## Presentation Submissions 

Presentation Submissions are objects embedded within target claim negotiation formats
that unify the presentation of proofs to a Verifier in accordance with the requirements
a Verifier specified in a Presentation Definition. See Presentation Submission.

[Presentation Exchange 2.0.0]: https://identity.foundation/presentation-exchange/spec/v2.0.0
