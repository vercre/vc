# KeyOps Bugs

**If you are unsure whether an issue is a security vulnerability, always err on the side
of caution and report it as a security vulnerability!**

Bugs must affect a [tier 1](../stability/support-tiers.md) platform or feature to be
considered a security vulnerability.

KeyOps of the core libraries is paramount. Anything that undermines their ability to
function correctly and securely is a security vulnerability.

On the other hand, execution that diverges from OpenID semantics (such as
naming, lack of support for a particular RFC, etc.) are not considered security 
vulnerabilities so long as they do not guarantees implied by the existing 
implementation. 

Denials of service when *executing* are considered security vulnerabilities. For
example, an endpoint that goes into an infinite loop that never yields is
considered a security vulnerability.

Any kind of memory unsafety (e.g. use-after-free bugs, out-of-bounds memory accesses,
etc...) is always a security vulnerability.

### Cheat Sheet: Is it a security vulnerability?

| Type of bug                                         |     |
| --------------------------------------------------- | --- |
| <ul>Uncaught out-of-bounds memory access            | Yes |
| <ul>Uncaught out-of-bounds table access             | Yes |
| <ul>Failure to uphold an OpenID flow integrity      | Yes |
| <ul>File system access                              | Yes |
| <ul>Memory unsafety                                 | Yes |
| <ul>Use-after-free                                  | Yes |
| <ul>Out-of-bounds memory access                     | Yes |
| <ul>Use of uninitialized memory                     | Yes |
| <ul>Denial of service                               | Yes |
| <ul>Panic                                           | Yes |
| <ul>Process abort                                   | Yes |
| <ul>Uninterruptible infinite loops                  | Yes |
| <ul>User-controlled memory exhaustion               | Yes |
| <ul>Uncontrolled recursion over user-supplied input | Yes |
| <ul>Divergence from OpenID semantics                | No  |
| <ul>Computing incorrect value                       | No  |
| <ul>Raising errant trap                             | No  |

N.B. We still want to fix every bug mentioned above even if it is not a security 
vulnerability! We appreciate when issues are filed for non-vulnerability bugs,
particularly when they come with test cases and steps to reproduce!
