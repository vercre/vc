# Vercre RFCs

Vercre uses an RFC (request for comment) process for instigating major change to any
project. We see RFCs as a tool for getting feedback on design and implementation ideas
and for consensus-building among stakeholders.

See the [Vercre RFC repo](https://github.com/vercre/rfcs) for a complete list of RFCs.

## What is an RFC?

An RFC lays out a problem along with a proposed solution. To support getting early 
feedback, RFCs can come in [draft](https://github.com/vercre/rfcs/blob/main/rfc-draft.md)
or [full](https://github.com/vercre/rfcs/blob/main/rfc-full.md) forms. Draft RFCs should be opened as 
[draft PRs](https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/about-pull-requests#draft-pull-requests).

In either case, discussion happens by opening a pull request to place the RFC into the 
`accepted` directory.

## When is an RFC needed?

Many changes to Vercre projects can and should happen through every-day GitHub processes 
— issues and pull requests. An RFC is warranted when:

* There is a change that will significantly affect stakeholders. For example:
    * Major architectural changes
    * Major new features
    * Simple changes that have significant downstream impact
    * Changes that could affect guarantees or level of support, e.g. removing support
      for a target platform
    * Changes that could affect mission alignment, e.g. by changing properties of the
      security model

* The work is substantial and you want to get early feedback on your approach.

## Workflow

### Creating and discussing an RFC

* The RFC process begins by submitting a (possibly draft) pull request, using one of the
  two templates available in the repository root. The pull request should propose to add
  a single markdown file into the `accepted` subdirectory, following the template 
  format, and with a descriptive name.

* The pull request is tagged with a **project label** designating the project it
  targets.

* Once an RFC PR is open, stakeholders and project contributors will discuss it together 
  with the author, raising any points of concern, exploring tradeoffs, and honing the 
  design.

### Making a decision

Merge the PR or close it without further action. If the PR is merged, the RFC is
considered accepted and the author can begin work on the implementation.
