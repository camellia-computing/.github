# GitHub automation identities

GitHub Apps are short-lived machine identities. Actions are workflow code and
inherit the calling job's token. They are not interchangeable.

## Release Manager App

The Release Manager performs reviewed release PR and immutable publication
operations. Its Client ID and bot login are configuration, never hard-coded
policy:

- variable `RELEASE_APP_CLIENT_ID`;
- variable `RELEASE_APP_LOGIN`;
- secret `RELEASE_APP_PRIVATE_KEY`.

The three values are atomic. The installation and organization-level credential
visibility are limited to release-capable
repositories. Grant Contents, Issues and Pull requests read/write, with
Administration and Metadata read. Do not grant Actions, Workflows or
organization permissions. The governance repository does not receive these
credentials. Candidate builds do not receive the private key.

Product workflows verify the minted App identity and compare the authenticated
bot login with `RELEASE_APP_LOGIN`. Organization-scoped variables and secrets
are preferred; repository overrides are forbidden because they split identity
rotation. The policy audit compares their selected-repository scope by immutable
repository ID.

## Policy Auditor App

The dedicated read-oriented Policy Auditor is documented in
[`ORGANIZATION_POLICY_AUDIT.md`](ORGANIZATION_POLICY_AUDIT.md). Install it for
all organization repositories so a newly created repository becomes visible to
the next inventory audit. It is never reused for releases.

## Cross-repository Reader App

Public source contracts may use anonymous read access. For private-repository
readiness, configure the optional atomic pair:

- variable `CROSS_REPO_READ_APP_CLIENT_ID`;
- secret `CROSS_REPO_READ_APP_PRIVATE_KEY`.

The Reader receives only Contents and Metadata read on source repositories.
Fork and Dependabot contexts continue without its key. A partial pair fails.
The physical source and consumer repository names come from each product's
logical repository map.

## Local Actions and templates

Security-critical release logic remains local to each repository so a rename,
visibility change or central outage cannot silently alter a release. Shared
governance publishes reviewed templates and validation contracts; updates are
applied by pull request and checked for drift rather than fetched as mutable
code during a trusted job.

Each local Action documents inputs, outputs, permissions, trust boundary and
update procedure. Third-party Actions are pinned to full commit SHAs with a
version comment.

## Organization Actions boundary

The organization allows Actions in every managed repository and requires
server-side full-SHA pinning. Workflow tokens default to read-only, cannot
approve pull-request reviews, and elevate only at the consuming job. Allowing
all Action publishers does not permit mutable tags: repository workflows and
the organization control both require immutable references. Logs and temporary
workflow artifacts default to 30-day retention to preserve investigation
evidence without exhausting the GitHub Free storage allowance; durable release
evidence belongs in immutable Releases or registries.

## Permission rules

- Set top-level workflow permissions to read-only and elevate only the exact
  mutating job.
- Use `persist-credentials: false` unless a reviewed step must write through
  that checkout.
- Prefer OIDC and installation tokens over long-lived credentials.
- Treat identifiers and Client IDs as non-secret; private keys, signing
  containers, tokens and passwords are secrets.
- Validate optional credentials as atomic groups: wholly absent may select a
  documented lower mode, partially present is always an error.
- After changing an App permission, require owner approval and rerun every
  affected policy, contract and release-candidate check.
