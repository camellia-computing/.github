# Dependency maintenance and review

Keep supported tools and libraries current across the seven managed repositories.
Dependabot proposes updates; passing CI is necessary, not a substitute for
reviewing the resulting behavior and product requirements.

## Review decisions

Assess each proposal against the current default branch, not its original base:

| Decision | Required action |
| --- | --- |
| Compatible update | Review upstream changes and lockfile scope, then run the existing repository gates. |
| Coupled update | Update callers, generated code, peers and platform adapters together; validate every consumer of a public re-export or source pin. |
| Already incorporated | Identify the replacement commit and current version or digest; comment and close without merging an older graph. |
| Product constraint | Record the dependency path, concrete feature/platform requirement, owner, next review and testable removal condition. Do not force an unsupported override. |

A failing proposal is not automatically a product constraint. First check whether
a small behavior-preserving adapter enables both sides to advance. A successful
install alone does not prove compatible peers, generated code, platform floors,
wire formats or native linking.

## Update boundaries

- Group compatible routine updates by ecosystem. Keep a coupled test driver or
  code generator with its runtimes even for major proposals; unrelated majors
  remain separate review units.
- Align canonical runtime sources, matching type declarations, bindings,
  package-manager identity, image tags and immutable digests. Use maintained LTS
  runtimes where the product selects LTS, not newer types with an older runtime.
- Treat protocol updates and consumer source pins as one rollout. Preserve source
  provenance and pin the actual accepted source commit.
- Do not select alpha/beta dependencies or raise mobile platform floors merely
  to resolve another package. Routine cooldowns do not delay security response.
- Keep justified constraints beside their owning dependency or in the dependency
  register. A release on either side triggers another removal review. Never grow
  an audit exception just because the dependency graph changed.

## Shared TypeScript constraint

Both Nexus frontends use TypeScript 6 because the current stable Svelte tooling
does not declare support for TypeScript 7: `svelte-check` 4.7.7 accepts TypeScript
5 or 6, and `svelte2tsx` 0.7.62 accepts 4.9, 5 or 6. Their published
[checker manifest](https://registry.npmjs.org/svelte-check/4.7.7) and
[transformer manifest](https://registry.npmjs.org/svelte2tsx/0.7.62) are the
compatibility evidence, not the success of a standalone compiler installation.
Frontend maintainers own this constraint. Recheck it when either tool publishes;
advance the compiler, checker and transformer together once their peer ranges
agree, then require peer validation, application checks, generated types, browser
tests and the complete native/product gates. Do not override those peer ranges.

Routine freshness does not require restarting a validated batch whenever another
patch appears. Use each repository's committed cooldown and next grouped proposal
for a newly published non-security update. Review its source changes and record
the disposition; do not turn a short cooldown into a permanent version pin.
Security fixes and currently affected functionality require a separate urgency
decision rather than silently waiting for that cooldown.

## Efficient validation

Use deterministic narrow checks during adaptation, then run the complete existing
required matrix once at the proposed exact head. Independent repositories may
validate in parallel; dependent consumers follow their accepted source commit.
Do not rerun the full matrix for every lockfile edit in one batch.

Keep one stable aggregate gate that fails on failed, cancelled or unexpectedly
skipped prerequisites. A bot identity or small diff does not establish a safe
reduced test profile. Dependency and workflow changes retain their product,
native, security and integrity checks.

Diagnose the failed step before retrying. A known transient download failure may
receive one targeted retry; repeated failures require a bounded reliability fix,
not unlimited reruns or weaker assertions. For inconsistent platform status
metadata, inspect the exact workflow, suite, completed steps and retained logs,
and explicitly report any remaining discrepancy instead of rerunning good work.

## Merge, release and handoff

Review the latest head, security changes, native behavior and unresolved
conversations before a SHA-guarded merge. Preserve branch protection and stale
approval dismissal. Exceptional administrator authority is explicit and scoped;
automated review is never described as independent human review.

Maintenance approval does not approve a generated Release PR or public release.
Follow [the CI/CD baseline](CI_CD_BASELINE.md): an already validated exact parent,
a generated version-only proposal, required approval, focused delta validation,
then protected publication of verified bytes. Do not add per-package manual
approvals or repeat the complete parent suite merely for a generated version bump.
Signing, immutable identity, attestations, recovery and public readback stay
mandatory.

Before closing a batch, verify actual merged heads and main workflows. Give the
product maintainers accepted source pins, call-site changes, retained constraints
and remaining risks. Never switch a dirty business worktree or silently merge
maintenance into another task's feature branch.
