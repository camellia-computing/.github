# Signing policy registry

[`signing-identities.json`](../config/signing-identities.json) is the
non-secret policy for native publisher identities. It defines logical
consumers, credential-group names, allowed outcomes, verification adapters,
rotation windows and the strongest-first trust order:

1. `public-trust`;
2. `private-trust`;
3. `platform-key`;
4. `ad-hoc`;
5. `unsigned`.

The registry does not claim that a credential is active and does not store a
certificate subject, fingerprint, expiry, local path or private material.
Expected identity values belong in protected environment variables or secrets.
Actual state is derived from the final downloaded artifact and recorded in
[`release-evidence.json`](RELEASE_EVIDENCE.md).

## Credential selection

Each identity has one or more atomic credential groups. The workflow inspects
every group without printing values:

- all fields absent: the group is unavailable;
- some fields present: fail before packaging;
- all fields present: import into an ephemeral store, derive its public
  identity and verify it against the protected expectation.

Complete groups are classified by the platform verifier and sorted by the
registry trust order. An invalid or partially configured stronger group blocks
the release; it is never bypassed in favor of a weaker group. If no native
credential exists, a formal unsigned artifact is allowed only when both the
registry and protected release environment permit it.

## Rotation

Desktop certificate rotation may configure `primary` and `secondary` groups
for at most `rotation_max_days`. Selection is based on verified trust, not the
group name. Remove the retired group after the overlap and publish a new
version if distributed bytes change.

Android update identity replacement is not an ordinary certificate rotation.
Its zero-day overlap policy requires a platform-supported signing lineage and
separate review.

## Custody

PFX/P12 data, keystores, provisioning profiles, private keys, passphrases,
GitHub App keys and tokens remain in offline custody or selected-repository
GitHub secrets. Server-only repositories never receive desktop/mobile signing
material. Generators and upload helpers must be dry-run-first, stream secret
files through standard input and never put secret values on a command line.
