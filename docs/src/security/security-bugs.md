# Security Bugs

**If you are still unsure whether an issue you are filing is a security
vulnerability or not after reading this page, always err on the side of caution
and report it as a security vulnerability!**

Bugs must affect [a tier 1 platform or feature](../stability/support-tiers.md) to be
considered a security vulnerability.

The security of the host and integrity of the sandbox when executing Wasm is
paramount. Anything that undermines the Wasm execution sandbox is a security
vulnerability.

On the other hand, execution that diverges from Wasm semantics (such as
computing incorrect values) are not considered security vulnerabilities so long
as they remain confined within the sandbox. This has a couple repercussions that
are worth highlighting:

* Even though it is safe from the *host's* point of view, an incorrectly
  computed value could lead to classic memory unsafety bugs from the *Wasm
  guest's* point of view, such as corruption of its `malloc`'s free list or
  reading past the end of a source-level array.

* Vercre embedders should never blindly trust values from the guest &mdash; no
  matter how trusted the guest program is, even if it was written by the
  embedders themselves &mdash; and should always validate these values before
  performing unsafe operations on behalf of the guest.

Denials of service when *executing* are considered security
vulnerabilities. For example, if a Vercre endpoint goes into an infinite loop 
that never yields, that is considered a security vulnerability.

Any kind of memory unsafety (e.g. use-after-free bugs, out-of-bounds memory
accesses, etc...) in the host is always a security vulnerability.

### Cheat Sheet: Is this bug considered a security vulnerability?

TODO: clist common bug types below

<div class="hidden">
| Type of bug                                     | At Wasm Compile Time | At Wasm Execution Time |
|-------------------------------------------------------------------------------------|-----|-----|
| Sandbox escape                                                                      | -   | Yes |
| <ul>Uncaught out-of-bounds memory access                                            | -   | Yes |
| <ul>Uncaught out-of-bounds table access                                             | -   | Yes |
| <ul>Failure to uphold Wasm's control-flow integrity                                 | -   | Yes |
| <ul>File system access outside of the WASI file system's mapped directories         | -   | Yes |
| <ul>Use of a WASI resource without having been given the associated WASI capability | -   | Yes |
| <ul>Etc...                                                                          | -   | Yes |
| Divergence from Wasm semantics (without escaping the sandbox)                       | -   | No  |
| <ul>Computing incorrect value                                                       | -   | No  |
| <ul>Raising errant trap                                                             | -   | No  |
| <ul>Etc...                                                                          | -   | No  |
| Memory unsafety                                                                     | Yes | Yes |
| <ul>Use-after-free                                                                  | Yes | Yes |
| <ul>Out-of-bounds memory access                                                     | Yes | Yes |
| <ul>Use of uninitialized memory                                                     | Yes | Yes |
| <ul>Etc...                                                                          | Yes | Yes |
| Denial of service                                                                   | No  | Yes |
| <ul>Panic                                                                           | No  | Yes |
| <ul>Process abort                                                                   | No  | Yes |
| <ul>Uninterruptible infinite loops                                                  | No  | Yes |
| <ul>User-controlled memory exhaustion                                               | No  | Yes |
| <ul>Uncontrolled recursion over user-supplied input                                 | No  | Yes |
| <ul>Etc...                                                                          | No  | Yes |
</div>

Note that we still want to fix every bug mentioned above even if it is not a
security vulnerability! We appreciate when issues are filed for
non-vulnerability bugs, particularly when they come with test cases and steps to
reproduce!
