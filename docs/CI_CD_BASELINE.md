# CI/CD and release automation baseline

This baseline applies to both Camellia Nexus and Camellia Remote. Product
workflows may use different job names, languages and package matrices, but the
security and review outcomes are equivalent.

## Pull-request and main gates

- Protect the default branch. Require a pull request, current-head approval
  from a non-author, conversation resolution, CODEOWNERS review where
  applicable, and dismissal of stale approval after a push.
- Allow squash merges only. Use the pull-request title as the commit title, a
  blank squash body, automatic branch deletion, and no native auto-merge.
- Pin every third-party Action to a full commit. Disable persisted checkout
  credentials unless a narrowly scoped mutation step needs them.
- Default workflow permissions to read-only and grant write, OIDC,
  attestations, packages or pull-request access only at the consuming job.
- Separate inexpensive metadata/policy checks from product suites, but expose
  one stable required aggregate check that fails for failed, cancelled or
  unexpectedly skipped dependencies.
- Validate formatting, static analysis, unit/integration tests, dependency
  review, secret scanning, generated-code drift, license/security audits,
  platform package contracts and migrations proportional to the repository.
- Build platform-native packages on their owning runners. Windows automation
  uses current PowerShell Core (`pwsh`), never Windows PowerShell.

## Release state machine

```text
default-branch commit
  -> successful exact-SHA push CI
  -> immutable release proposal/candidate
  -> current-head human approval
  -> protected release environment approval
  -> build once on owning runners
  -> verify native identity and package structure
  -> checksum + SBOM + provenance/attestation
  -> draft Release / immutable image digest
  -> download and independently verify every public byte
  -> publish/finalize and retain evidence
```

All release jobs are serialized and idempotent. A retry observes remote state
before mutation, resumes a compatible draft, and fails on a conflicting tag,
asset, digest, identity or version. API errors are not interpreted as absence.
Existing published versions are never rebuilt, replaced, moved or re-signed.

## Shared controls and product-specific strengths

Nexus contributes:

- GitHub App installation identity rather than a personal token;
- exact-head release PR approval and SHA-guarded squash;
- repository merge/immutable-Release policy validation at multiple mutation
  boundaries;
- recoverable, explicit release states and post-publication proof;
- strict separation of policy, validation, merge, package and publication
  authority.

Remote contributes:

- Windows/macOS/Linux/Android/iOS/Web package matrices;
- explicit native signing/trust/delivery metadata per platform;
- unsigned and private-trust modes that never masquerade as public trust;
- cross-repository Web-client pinning to an exact successful client CI run;
- digest-only multi-architecture images with SBOM, provenance and keyless
  signing.

Both product lines must retain their own strengths and adopt the shared
outcomes. In particular, Remote release mutation moves behind the same App
identity/policy checks once its App group is configured, while Nexus native
package metadata adopts Remote's explicit trust and delivery vocabulary.

## Required hosted settings

- Organization Actions policy enables the reviewed repository inventory,
  requires full-SHA references, grants read-only workflow tokens by default,
  forbids workflow review approval, and retains logs/artifacts for 30 days.
- One enforced organization code-security configuration applies to every
  managed public repository and is the default for newly created public
  repositories. Repository-level CodeQL parameters remain explicit and
  audited.
- Immutable Releases enabled for every repository that creates a GitHub
  Release, with the exact release-capable repository ID set managed centrally
  at organization level.
- A `release` environment with non-self team review, protected branch/tag
  policies and no broad deployment token.
- Tag rules preventing update/deletion of release tags.
- Repository rules requiring the stable aggregate CI check and CodeQL/security
  checks.
- Release GitHub App installed only on release-capable repositories with
  Contents, Pull requests and Issues read/write plus Administration and
  Metadata read-only. It has no Actions or Workflows permission.
- Concurrency groups that serialize publication per component and cancel only
  stale pull-request validation, never a publication in progress.

## Audit and drift handling

Repository policy workflows verify merge settings, immutable Releases, App
identity, action pinning, permission boundaries, required secret-group shape
and release-environment assumptions. The reviewed expectations are machine
readable in
[`config/repository-policies.json`](../config/repository-policies.json).
`Organization Policy Audit` runs weekly or on demand with a dedicated
read-oriented App token, compares organization settings and all managed
repositories, retains JSON/Markdown evidence,
and creates or updates one central `policy-drift` issue. A compliant run closes
the resolved issue. The audit never changes repository protection, environment,
certificate or secret state silently. See the
[audit runbook](ORGANIZATION_POLICY_AUDIT.md).

Exceptions require an owner, reason, compensating control, expiry and linked
evidence. Source licensing, authorization, signature/attestation, immutable
release and recovery gates are not waivable.
