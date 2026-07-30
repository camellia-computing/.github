# Repository governance

Camellia Computing owns common repository policy while each product team owns its architecture, backlog, release record, deployment, credentials, and incident response.

## Decision boundaries

- The Remote team reviews the `remote-client`, `remote-management`, `remote-protocol`, and `remote-server` logical repositories.
- The Nexus team reviews the `nexus-client` and `nexus-management` logical repositories.
- Cross-product changes share patterns and review evidence, not databases, accounts, libraries, versions, secrets, release jobs, or runtime dependencies by default.
- Security-sensitive, licensing, identity, schema, signing, and release-policy changes require explicit owner review.

The default branch is the integration truth. Releases are created only from an exact protected commit that passed required checks. Tags and published artifacts are immutable. Emergency changes use the same review and readback requirements; urgency changes timing, not evidence.

## Repository lifecycle

New repositories require a clear owner, purpose, license, visibility decision, threat boundary, build/test path, archival criteria, and naming consistent with the organization standard. Temporary names such as `new`, `next`, `v2`, `common`, and `utils` are not acceptable repository boundaries.

Archival requires secret removal, package/release ownership review, final provenance, a replacement or end-of-life statement, and read-only settings. Deletion requires a separately approved retention decision and recoverable backup.
