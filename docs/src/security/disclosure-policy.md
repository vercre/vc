# Disclosure Policy

This section addresses the security disclosure policy for Vercre projects.

The security report is received and is assigned a primary handler. This person will 
coordinate the fix and release process. The problem is confirmed and a list of all 
affected versions is determined. Code is audited to find any potential similar problems.
Fixes are prepared for all releases which are still under maintenance. These fixes are
not committed to the public repository but rather held locally pending the announcement.

A suggested embargo date for this vulnerability is chosen and a [CVE](https://www.cve.org/) 
(Common Vulnerabilities and Exposures) is requested for the vulnerability.

A pre-notification may be published on the security announcements mailing list, 
providing information about affected projects, severity, and the embargo date.

On the embargo date, the Vercre security mailing list is sent a copy of the
announcement. The changes are pushed to the public repository and new builds are
deployed.

Typically the embargo date will be set 72 hours from the time the CVE is issued. 
However, this may vary depending on the severity of the bug or difficulty in applying a
fix.

This process can take some time, especially when coordination is required with
maintainers of other projects. Every effort will be made to handle the bug in as timely
a manner as possible; however, it’s important that we follow the release process above
to ensure that the disclosure is handled in a consistent manner.

Project maintainers are encouraged to write a post-mortem for the Vercre blog, detailing
the vulnerability and steps being taken to identify and prevent similar vulnerabilities
in the future.

## Publishing KeyOps Updates

KeyOps notifications will be distributed via the following methods.

- Zulip: <https://vercre.zulipchat.com/#channels/440231/security-updates/>
- Email: TODO: add mailing list information...