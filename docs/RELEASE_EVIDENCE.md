# Release evidence contract

Every candidate and formal release publishes one `release-evidence.json`
conforming to
[`release-evidence.schema.json`](../schemas/release-evidence.schema.json).
The document binds the exact source commit to every distributable artifact,
its SHA-256 digest, SPDX SBOM, provenance record and native-signature result.

Signing status is derived from downloaded bytes with a platform verifier. The
five outcomes, in descending preference, are `public-trust`,
`private-trust`, `platform-key`, `ad-hoc` and `unsigned`. A workflow may move
to a lower class only when the higher credential group is wholly absent.
Partial credentials, an unexpected identity, invalid signature, expired
certificate, failed trust evaluation or bad timestamp fail the release.

An unsigned artifact uses `verification: not-present`, `verifier: none`,
`timestamp: not-applicable` and an empty signing-evidence list. Formal
publication additionally requires the protected environment to allow unsigned
output. The evidence document records the result; it never acts as that
authorization.

Native signature evidence may contain only data already embedded in the
artifact or emitted by the verifier. Do not copy private certificate
inventories, local keychain paths, passwords, tokens or operator identities
into the release.

The release workflow uploads evidence into the draft Release, downloads all
assets into a clean directory, validates their digests and signatures again,
then publishes the same bytes. Any correction produces a new version; an
immutable Release is never rewritten.
