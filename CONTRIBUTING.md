# Contributing

Thank you for helping improve Camellia projects. Before starting substantial work, open a scoped proposal or discuss the intended change in an existing issue. Security vulnerabilities must not be reported in a public issue; use the process in [SECURITY.md](SECURITY.md).

## Engineering contract

- Target the repository's default branch and keep each pull request focused on one reviewable outcome.
- Preserve product boundaries. Camellia Remote and Camellia Nexus have independent runtime services, data, credentials, versions, releases, and incident domains.
- Do not add compatibility code for unreleased schemas, names, test data, or development builds unless a current specification explicitly requires it.
- Never commit secrets, private keys, production data, generated credentials, personal information, build caches, or local databases.
- Pin GitHub Actions by full commit SHA and container images by digest in production or release paths.
- Update tests, documentation, threat assumptions, configuration examples, and provenance records when behavior or dependencies change.
- Use the toolchain pinned by the repository. Windows automation must run with current PowerShell (`pwsh`); Windows PowerShell is unsupported.
- Keep changes compliant with the repository's own license. Camellia Remote components retain their open-source and upstream-notice obligations. Camellia Nexus repositories require express authorization under their proprietary terms.

## Pull-request evidence

A pull request should state:

1. the problem and the resulting behavior;
2. security, privacy, migration, compatibility, and operational impact;
3. exact local checks performed and any check that could only run in hosted CI;
4. rollback or recovery considerations for deployment and data changes;
5. documentation, release-note, and provenance impact.

Generated files must be reproducible from committed inputs. Database changes require deterministic migrations and a fresh-database test. Release changes require an immutable-version and artifact-readback test. An exception to a required gate needs a named owner, expiry, evidence, and compensating control; authorization, secret handling, migration integrity, artifact identity, and recovery gates are not waivable.

By contributing, you agree that your contribution is provided under the license of the repository receiving it and that you have the right to submit it.
