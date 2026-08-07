# Release evidence contract

Every candidate and formal release produces and retains one `release-evidence.json`
in its CI evidence or attestation storage, conforming to
[`release-evidence.schema.json`](../schemas/release-evidence.schema.json).
It binds the logical repository and stable version to the exact source commit,
tag or candidate ref, successful validation run, reviewed policy revisions,
cross-repository dependencies, and every distributed file or OCI image.

The document is a release result, not a request. A formal file entry records its
SHA-256, size, platform, architecture, SPDX SBOM, provenance, native-signing
classification, verifier output and distribution limitation. A formal image
entry records the canonical index digest, every platform manifest digest,
SBOM, provenance, and an explicit result for both GHCR and Docker Hub:

- `published` includes the registry path, immutable digest, stable-version and
  full-source-SHA aliases, verified keyless Cosign identity, and readback;
- `skipped/not-configured` means the reviewed registry map has no target;
- a configured target with missing credentials, failed push, signature error,
  digest mismatch or failed readback is a release failure, never a skip.

At least one configured registry must receive every formal image. Candidate
images do not mutate registries and record `skipped/candidate-only`. Production
deployment consumes the recorded digest, never `latest`. A publication workflow
may move `latest` only to the highest completed stable SemVer; replaying an
older release must not roll it back.

## Native trust and distribution

Signing status is derived from the final downloaded bytes with the platform
verifier. The native outcomes, in descending preference, are `public-trust`,
`private-trust`, `platform-key`, `ad-hoc`, and `unsigned`; Web/source outputs
use `not-applicable`. A workflow may select a lower outcome only when every
stronger configured credential group is wholly absent. Partial credentials,
an unexpected identity, invalid signature, expired certificate, failed trust
evaluation, bad timestamp, or mismatched downloaded bytes fail the release.

Unsigned Android and iOS outputs are `re-signing-input`, not installable
releases. Ad-hoc output is restricted. Private trust is permitted for managed
distribution but must remain visibly classified as `private-trust`; no
configuration variable may promote native verifier output.

Native signature evidence may contain only data already embedded in the
artifact or emitted by the verifier. It must not contain private certificate
inventories, local keychain paths, passwords, tokens, deployment addresses,
customer data, or operator identities.

## Dependencies and exceptions

Dependencies use logical repository IDs and exact commits, with an evidence
reference for the relationship. This covers protocol source pins, embedded Web
clients, and independently versioned client/service compatibility without
coupling their version streams.

An exception is allowed only when the reviewed product policy permits it. It
records a generic owner role, expiry, reason, compensating control and evidence
reference, and must be valid when the release evidence is generated. Missing
credentials, signature failure, immutable-release failure, authorization
failure, or registry readback failure are not exceptions.

The workflow freezes and revalidates the complete evidence set before
publication. GitHub Release Assets are a separate product-facing surface:
downloadable products expose only their reviewed final distribution files,
file checksums, and narrowly required user-verification material; OCI-only
products may expose no file assets and instead bind their immutable registry
digest in the Release notes. Every public filename is selected by an exact
product allowlist, and publication fails closed on any additional file. SBOMs,
provenance, attestations, Sigstore bundles,
scans, metadata and internal evidence remain available through their CI,
attestation or evidence systems without being ordinary Release downloads.

Publication reads back the complete public file set or the exact OCI digest and
registry state, as applicable. Any correction produces a new version; an
immutable Release, protected tag or published stable alias is never rewritten.
