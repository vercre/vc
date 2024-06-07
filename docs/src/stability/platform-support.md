# Platform Support

This page is intended to give a high-level overview of Vercre's platform support along
with a few Vercre aspirations. For more detail, see the [support tiers](./support-tiers.md)
which has more detail on what is supported and to what extent.

Vercre strives to support hardware that anyone wants to run WebAssembly on. Vercre
maintainers support a number of "major" platforms but porting work may be required
to support platforms that maintainers are not familiar with. 

Out-of-the box Vercre supports:

* **Linux**: x86\_64, aarch64
* **MacOS**: x86\_64, aarch64
* **Windows**: x86\_64

Other platforms such as Android, iOS, and the BSD family of OSes are not yet supported. 
PRs for porting are welcome and maintainers are happy to add more entries to the CI 
matrix for these platforms.

<div class="hidden">

TODO: complete this section

## Support for `#![no_std]`

The `vercre-issuer` crate supports being build on no\_std platforms in Rust, but
only for a subset of its compile-time Cargo features. Currently supported features 
are:

* `runtime`
* `gc`
* `component-model`

Notably, this does not include the `default` feature which means that when depending on
Vercre you'll need to set `default-features = false`.

Vercre's support for no\_std requires the embedder to implement the equivalent of a C 
header file to indicate how to perform basic OS operations such as allocating virtual 
memory. This API can be found as `vercre-platform.h` in Vercre's release artifacts or at
`examples/min-platform/embedding/vercre-platform.h` in the source tree. Note that this 
API is not guaranteed to be stable at this time, it'll need to be updated when Vercre 
is updated.

Vercre's runtime will use the symbols defined in this file meaning that if they're not
defined then a link-time error will be generated. Embedders are required to implement 
these functions in accordance with their documentation to enable Vercre to run on custom
platforms.
</div>