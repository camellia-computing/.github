# GitHub automation identities

GitHub Apps are short-lived machine identities. Actions are workflow code and
inherit the calling job's token. They are not interchangeable.

## Release Manager App

The Release Manager performs reviewed release PR and immutable publication
operations. Its display name, slug and bot login are configuration, never
hard-coded policy:

- variable `RELEASE_APP_CLIENT_ID`;
- variable `RELEASE_APP_SLUG`;
- variable `RELEASE_APP_LOGIN`;
- secret `RELEASE_APP_PRIVATE_KEY`.

The four values are atomic. The installation is limited to release-capable
repositories. Grant Contents, Issues and Pull requests read/write, with
Administration and Metadata read. Do not grant Actions, Workflows or
organization permissions. Candidate builds do not receive its private key.

Product workflows compare both the minted App slug and authenticated bot login
with the configured values. Organization-scoped variables/secrets are
preferred; repository overrides are forbidden because they split identity
rotation.

## Policy Auditor App

The dedicated read-oriented Policy Auditor is documented in
[`ORGANIZATION_POLICY_AUDIT.md`](ORGANIZATION_POLICY_AUDIT.md). It is installed
on every managed repository and is never reused for releases.

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
