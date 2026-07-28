# Signing identity registry

[`config/signing-identities.json`](../config/signing-identities.json) is the
organization's single source of truth for non-secret native publisher
identities. It records the current consumers, GitHub secret/variable contract,
trust classification, public certificate or key fingerprint, expiry and
rotation state.

X.509 identities use a SHA-256 certificate fingerprint as their canonical
cross-platform identity. Windows additionally records the native SHA-1
certificate thumbprint consumed by Authenticode tooling; that reference is not
treated as the cryptographic integrity digest. Multiple entries for one
platform are allowed so an `active` and `retiring` identity can coexist during
a reviewed rotation.

The registry deliberately does not contain a PFX/P12, keystore, provisioning
profile, private key, password, passphrase, App private key, or recoverable
private material. Those values belong in an offline custody system or GitHub
organization secrets restricted to the exact client repositories that consume
them. Server-only repositories must not receive desktop or mobile signing
secrets.

## Synchronization contract

For publisher identities shared by Nexus and Remote Client:

1. Store one reviewed credential group as organization secrets with selected
   repository access to `nexus` and `remote-client`.
2. Store the non-secret expected identity and trust classification as selected
   organization variables using the names in the registry. Windows consumers
   validate both the canonical SHA-256 fingerprint and native SHA-1 thumbprint.
3. Remove same-named repository secrets/variables after the organization group
   is verified; repository values override organization values and can
   silently split identity continuity.
4. Update the registry in a reviewed pull request. Increase
   `registry_revision`, set the canonical SHA-256 fingerprint, applicable
   native reference and expiry, and link the rotation evidence.
5. Update product-specific release documentation only where its secret
   contract or platform behavior changed. Link back here for the current public
   identity rather than copying fingerprint text into multiple documents.
6. Run a non-publishing candidate in every consumer, followed by an approved
   formal package run. The workflow-derived identity must exactly equal the
   registry identity.
7. Read back the published bytes and compare the native signature, release
   metadata and registry. A mismatch is a release no-go.

Android and iOS identities are scoped only to `remote-client`. The Android key
is the application update identity. The iOS certificate must also be authorized
by the exact provisioning profile, Team ID, bundle ID and export method.

## State model

| State | Meaning |
| --- | --- |
| `not-configured` | No production credential is available to the target repository |
| `configured-unregistered` | Private material exists, but the reviewed public identity/expiry or every intended consumer is not registered |
| `active` | The complete secret group, public identity, workflows and intended consumers agree |
| `retiring` | Old and new identities overlap for a documented rotation window |
| `revoked` | The identity must no longer sign new artifacts |

Only `active` and an explicitly reviewed `retiring` identity may sign a public
release. An unconfigured platform may still produce the explicitly documented
unsigned/ad-hoc/re-signing mode allowed by
[`ARTIFACT_SIGNING.md`](ARTIFACT_SIGNING.md).

## Rotation evidence

Record, without secret values:

- old/new registry revision and fingerprint;
- certificate/key issuer, algorithm, usage and UTC validity;
- intended repositories and distribution trust;
- organization secret/variable update timestamps;
- candidate and formal workflow URLs;
- native verification output from downloaded bytes;
- revocation/distrust action and rollback point;
- operator and independent reviewer.

Never rewrite an old Release or claim that newly signed bytes are the same
artifact. Publish a new immutable version.
