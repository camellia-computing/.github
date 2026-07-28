# Repository standards

Every active product repository must contain:

- a purpose-focused `README`, applicable `LICENSE`, third-party `NOTICE`, `SECURITY.md`, and machine-readable source provenance where copied source exists;
- pinned toolchain and lock files, deterministic build/test commands, Dependabot coverage, and least-privilege Actions permissions;
- issue/PR routing, ownership, release policy, deployment examples without secrets, and operational runbooks proportional to the service;
- a clean default branch, no tracked credentials/databases/build output, and no compatibility paths for unsupported pre-release state;
- immutable release inputs, checksums, SBOM/provenance, signing or attestation, and remote-state readback before publication.

Repositories that publish native artifacts must implement the organization
policy in [`ARTIFACT_SIGNING.md`](ARTIFACT_SIGNING.md). Publicly trusted,
privately trusted, ad-hoc, and unsigned outputs are supported product choices,
but the selected mode must be validated as a complete configuration group and
recorded in machine-readable release metadata. A partial signing configuration
must fail closed.

## Required checks

Required checks are repository-specific but must cover formatting, static analysis, unit/integration tests, dependency and secret review, build reproducibility, migration drift where applicable, and release-policy regression tests. Native packages are validated on their owning operating systems.

The common control outcomes, release state machine and the strengths adopted
between Nexus and Remote are defined in
[`CI_CD_BASELINE.md`](CI_CD_BASELINE.md). A repository may use different job
names only when its stable aggregate required check preserves those outcomes.

Production services additionally require a non-root/read-only deployment path, dropped capabilities, health/readiness checks, explicit migrations, bounded resources and inputs, structured observability, backup ownership, and a measured restore drill. The operating target is one region at 99.9% availability, RPO no greater than one hour, and RTO no greater than four hours until a later approved standard supersedes it.

## Branch and release policy

- Default branch: `main`.
- Merge method: squash merge; merge commits and rebase merging are disabled unless a documented repository constraint requires otherwise.
- Branch deletion after merge is enabled.
- Rules apply to administrators and disallow force pushes and deletions.
- A change needs an approving review, resolved conversations, required checks, and a current branch.
- Release environments require independent approval and do not permit self-review where the GitHub plan supports it.

Signed commits and tags are encouraged. They become mandatory only after every authorized contributor and automation identity has a registered, recoverable signing setup and the rule has been tested without creating a lockout.

GitHub Apps, reusable workflows, composite actions, their permissions, and
their repository locations are catalogued in
[`GITHUB_AUTOMATION.md`](GITHUB_AUTOMATION.md). New automation identities must
be added there before production use.
