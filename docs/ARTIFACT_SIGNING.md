# Artifact signing and distribution trust

This document is the Camellia Computing organization baseline for release
artifacts. It applies to every repository that publishes binaries, packages,
container images, mobile bundles, or installers.

Native publisher certificates are optional while products are pre-launch. A
formal release may use a publicly trusted identity, a company-controlled private
identity, ad-hoc signing, or no native signature. The workflow and release notes
must state the actual mode. Calling a private or unsigned artifact "trusted",
"notarized", or "store ready" is a release-blocking error.

## Two independent trust layers

Every formal release must retain the supply-chain evidence layer:

- an immutable source commit and version;
- SHA-256 checksums for downloadable files;
- an SBOM and provenance/attestation where the artifact type supports them;
- keyless Sigstore/Cosign signing or attestation for release assets and
  container images;
- digest readback after publication.

Operating-system publisher signing is a separate, optional layer. It improves
installation identity and platform policy integration, but it does not replace
the evidence above.

## Required signing and trust classifications

Native state and distribution trust are separate metadata fields. Native state
is one of `signed`, `notarized`, `ad-hoc`, `unsigned`, or `not-applicable`.
Distribution trust is classified as follows:

| Distribution trust | Meaning | Release requirement |
| --- | --- | --- |
| `public-trust` | A certificate or store identity chained to a platform-recognized publisher | Verify the exact identity, chain, timestamp/notarization, and expiry policy |
| `private-trust` | A Camellia-controlled private CA/key trusted only on managed devices | Publish the public root/fingerprint through a separate authenticated channel and warn that unmanaged devices will not trust it |
| `platform-key` | A self-controlled platform update identity, such as an Android app-signing key | Verify exact key continuity and protect its backup; do not imply a public CA chain |
| `ad-hoc` | A platform-local signature without an independently trusted publisher identity | Restrict distribution and state the installation limitations |
| `unsigned` | The artifact has no native publisher signature | Require protected-environment approval and state the installation or re-signing requirement |

Signing settings are atomic groups: all required values for a mode must be
present or the workflow must stop before packaging. Candidate builds must not
receive production signing secrets. Private keys are generated and backed up
offline, imported only into an ephemeral runner or managed signing service, and
removed in an always-run cleanup step.

## Standard GitHub Actions configuration bundles

All organization-owned signing generators and Apple identity preparation tools
produce the same protected local `github-actions/` directory. It keeps the
reviewed workflow contract synchronized across platforms without committing or
printing private material:

- `metadata.json`: public platform, trust classification, certificate/key
  identity, variable names and secret names;
- `variables.env`: directly copyable non-secret GitHub Actions variables;
- `secrets/<NAME>`: protected payload files for GitHub Actions Secrets;
- `upload.sh` and `Upload.ps1`: dry-run-first upload helpers for the current
  GitHub CLI.

Generation never contacts GitHub. The helpers only list names until invoked
with their explicit `--apply` or `-Apply` switch; they stream Secret files to
`gh` and never place their values on the command line. Review the public
metadata and variable file first, then select exactly one scope:

```bash
./github-actions/upload.sh --apply --repo OWNER/CLIENT_REPOSITORY
./github-actions/upload.sh --apply --org OWNER --repos CLIENT_ONE,CLIENT_TWO
```

```powershell
pwsh -NoProfile -File .\github-actions\Upload.ps1 -Apply `
  -Repository OWNER/CLIENT_REPOSITORY
pwsh -NoProfile -File .\github-actions\Upload.ps1 -Apply `
  -Organization OWNER -Repositories CLIENT_ONE,CLIENT_TWO
```

Use the selected-organization scope only for a reviewed desktop identity shared
by the `nexus-client` and `remote-client` logical repositories. Android and iOS
material belongs only to `remote-client`. A generated bundle does **not**
register, approve, or activate an identity: the registry, affected repository
documentation and a `publish=false` candidate must agree before release
promotion. Never commit the output directory or paste a file from `secrets/`
into chat.

## Platform expectations

### Windows

Authenticode is optional for `.exe`, `.dll`, and `.msi` files. A private-CA PFX
is suitable only for managed machines that trust the corresponding public root.
Public distribution should use a current Windows-trusted code-signing
certificate or managed signing service. SignTool verification must check the
embedded signature, exact leaf thumbprint, SHA-256 digest, and RFC 3161
timestamp when timestamping is configured.

The standard repository interface is:

- secret `WINDOWS_CODESIGN_PFX_BASE64`;
- secret `WINDOWS_CODESIGN_PFX_PASSWORD`;
- variable `WINDOWS_CODESIGN_CERTIFICATE_SHA256` containing the canonical
  uppercase 64-hexadecimal leaf fingerprint;
- variable `WINDOWS_CODESIGN_CERTIFICATE_THUMBPRINT` containing the
  Windows-native uppercase 40-hexadecimal SHA-1 leaf reference;
- optional variable `WINDOWS_TIMESTAMP_URL`.

Nexus and Remote Client reject a PFX whose derived SHA-256 fingerprint or
native thumbprint differs from the protected expected values. Authenticode
verification derives public/private trust from the final bytes; no configured
trust label can promote the result.

Generate a private test hierarchy on a controlled Windows workstation with
PowerShell 7.6 or later:

```powershell
pwsh -NoProfile -File .\scripts\New-CamelliaWindowsPrivateCodeSigningCertificate.ps1 `
  -OutputDirectory C:\Secure\camellia-windows-signing
```

The script exports a public root CER, a root backup PFX, a leaf public CER, and a
leaf code-signing PFX containing its verification chain. It also writes
`camellia-private-code-signing-identity.json` with only the public subject,
issuer, validity, canonical SHA-256 fingerprint and Windows-native SHA-1
thumbprint required by the signing registry, plus a standardized
`github-actions/` bundle with the exact Windows variables and Secret payloads.
Keep both PFX files and their passwords offline. Install only the public root
CER on explicitly managed test endpoints. This generated hierarchy is always
`private-trust`; a publicly trusted certificate must be packaged and reviewed
as a separate `public-trust` identity before it is enabled.

### macOS

The supported progression is unsigned, ad-hoc, certificate signed, then
Developer ID signed and notarized. A private CA proves identity only to managed
Macs that trust it; it cannot obtain Apple notarization or establish public
Gatekeeper trust.

The standard repository interface is:

- variable `APPLE_SIGNING_IDENTITY`;
- variable `APPLE_SIGNING_CERTIFICATE_SHA256` containing the canonical
  uppercase leaf fingerprint;
- secrets `APPLE_CERTIFICATE` and `APPLE_CERTIFICATE_PASSWORD`;
- for notarization only, variables `APPLE_API_ISSUER` and `APPLE_API_KEY` plus
  secret `APPLE_API_PRIVATE_KEY`.

Generate a private test identity with:

```bash
bash scripts/new-camellia-macos-private-code-signing-identity.sh \
  "$HOME/Secure/camellia-macos-signing"
```

It emits public identity metadata and the same `github-actions/` bundle as the
other platform tools. For an existing Apple-issued P12, prepare its exact
workflow values without duplicating it into the repository:

```bash
bash scripts/prepare-camellia-apple-signing-bundle.sh macos \
  "$HOME/Secure/camellia-macos-developer-id" \
  /controlled-inputs/developer-id.p12 \
  'Developer ID Application: Camellia Computing (TEAMID)' \
  public-trust
```

The preparation tool derives the certificate SHA-256 from the P12 and creates
the GitHub bundle. The macOS release workflow still imports it into an ephemeral
keychain and verifies the exact `APPLE_SIGNING_IDENTITY`; add notarization API
credentials separately only after public Developer ID enrollment is mature.

For public downloads, obtain a `Developer ID Application` identity through the
Apple Developer program and notarize the exact distributed bytes. A free or
private certificate can be used for controlled testing but must be recorded as
`private-trust`, not `public-trust`.

### Linux

Linux archives and packages may carry an OpenPGP detached signature. This is an
artifact publisher identity rather than general executable trust. The standard
repository interface is:

- variable `LINUX_GPG_FINGERPRINT`;
- secrets `LINUX_GPG_PRIVATE_KEY` and `LINUX_GPG_PASSPHRASE`.

Generate a private release key and signing subkey in an isolated keyring with:

```bash
bash scripts/new-camellia-linux-openpgp-key.sh \
  "$HOME/Secure/camellia-linux-signing" \
  "Camellia Computing Release <release@example.invalid>"
```

The output includes the public key, full signing-subkey fingerprint, public
identity metadata, and a `github-actions/` bundle carrying the exact OpenPGP
variable and protected Secret files. Keep the private subkey export and
passphrase in separate offline custody; the generated uploader is a transfer
mechanism, not a backup system.

Publish the full fingerprint through an authenticated channel independent of
the release download. A public key shipped beside its own signature is
verification material, not by itself a trust anchor.

### Android

An Android release keystore does not require a public CA, but its key continuity
is the application update identity. A debug keystore must never be the fallback
for a formal release.

When the release keystore group is absent, workflows may publish an explicitly
named `-unsigned.apk`/`-unsigned.aab` re-signing input. It is not an installable
public release. When enabled, the complete group is:

- secret `ANDROID_SIGNING_KEY`;
- secrets `ANDROID_KEY_STORE_PASSWORD`, `ANDROID_KEY_PASSWORD`, and
  `ANDROID_ALIAS`.
- variable `ANDROID_SIGNING_CERTIFICATE_SHA256` containing the canonical
  uppercase update-certificate fingerprint.

Back up the production keystore and passwords in separate controlled locations.
Losing the signing identity can prevent future updates.

For a genuinely new Android application/update lineage, generate a modern
PKCS#12 release keystore and its exact GitHub configuration bundle with:

```bash
bash scripts/new-camellia-android-release-keystore.sh \
  "$HOME/Secure/camellia-android-signing"
```

The script prints the public certificate SHA-256 and writes
`camellia-android-release-identity.json` plus `github-actions/`. It requires
one password for the PKCS#12 store and key, then emits both workflow Secret
names from that controlled value. It is **only** for a fresh update identity.
If an existing package has ever been signed, re-upload its original reviewed
keystore and credentials instead; generating a replacement key breaks update
continuity and must not be presented as a rotation.

For an existing Android update identity, prepare the original reviewed
keystore without modifying or replacing it:

```bash
bash scripts/prepare-camellia-android-release-keystore.sh \
  "$HOME/Secure/camellia-android-existing-update-key" \
  /controlled-inputs/original-release.keystore \
  original-release-alias
```

The preparation command verifies the supplied store and key passwords through
a non-mutating certificate request, derives the exact certificate SHA-256, and
writes public identity information plus the same protected `github-actions/`
bundle. It supports historical JKS and PKCS#12 stores, including distinct JKS
store and key passwords. The original keystore remains untouched; keep its
separate controlled backup before uploading the reviewed bundle only to
`remote-client`.

### iOS and iPadOS

An unsigned `.xcarchive` or `-unsigned.ipa` is a re-signing input only. Normal
device or App Store distribution requires an Apple distribution/development
identity, matching entitlements, and a provisioning profile. The release must
not describe an unsigned IPA as directly installable.

Remote Client implements a fail-closed signed path for App Store Connect,
release-testing/Ad Hoc, development and enterprise profiles. It verifies the
P12 identity against `IOS_SIGNING_CERTIFICATE_SHA256`, certificate/profile
membership, expiry, Team ID,
`com.camellia.remote` bundle ID, distribution type and final embedded
signature/profile/entitlements. The iOS group is independent from the macOS
Developer ID group.

Prepare an Apple-issued P12 and its matching provisioning profile as a
single, reviewed iOS configuration group:

```bash
bash scripts/prepare-camellia-apple-signing-bundle.sh ios \
  "$HOME/Secure/camellia-ios-signing" \
  /controlled-inputs/camellia-ios.p12 \
  /controlled-inputs/camellia-remote.mobileprovision \
  'Apple Distribution: Camellia Computing (TEAMID)' \
  TEAMID \
  release-testing
```

This command calculates the P12 fingerprint and produces the exact `IOS_*`
variables and protected Secret files, but it deliberately does not claim that a
profile is authorized. The hosted macOS release workflow performs the final
certificate, Team ID, bundle ID, entitlement and profile-type checks.

## Repository responsibility matrix

| Repository logical ID | Native outputs | Native secret groups |
| --- | --- | --- |
| `nexus-client` | Windows, macOS, Linux desktop packages | Windows PFX, Apple identity/P12/notary, Linux OpenPGP; all optional and independently fail-closed |
| `nexus-management` | OCI service image | None; use keyless Cosign/attestation |
| `remote-client` | Windows, macOS, Linux, Android, iOS, Web | Windows PFX, macOS Apple identity/P12/notary, Linux OpenPGP, Android keystore, and iOS P12/profile; all optional complete groups with explicit fallback modes |
| `remote-server` | Linux archives and OCI images | No native certificate in the current workflow; use checksums and keyless Cosign/attestation |
| `remote-management` | OCI service image | None; use keyless Cosign/attestation |
| `remote-protocol` | Source/library contract | None |

Do not duplicate a PFX, private key, or password into a repository that does not
consume it. In particular, Windows PFX values do not belong in server-only image
repositories.

The current non-secret policy, consumer list and GitHub credential-name
contract are maintained in the
[`signing identity registry`](SIGNING_IDENTITY_REGISTRY.md). Shared Nexus/Remote
desktop credentials should use organization secrets restricted to both client
repositories. Same-named repository values must be removed after migration
because they override organization values and can silently drift.

## Release metadata contract

Each release uses the organization
[`release-evidence.json`](RELEASE_EVIDENCE.md) contract. Native verifier output
may record an identity already embedded in the artifact, but must not copy a
private inventory, local keychain path, password, access token or raw secret.
Human-readable release notes summarize the same category and installation
limitations.

## Deployment and verification

Before promotion:

1. Download the published artifact by immutable release/digest reference.
2. Recompute its checksum and verify its Sigstore/Cosign evidence.
3. Verify the native signature on the target operating system and compare the
   exact identity with the reviewed release metadata.
4. For `private-trust`, test once without and once with the public root installed
   on an isolated managed endpoint. Only the latter should gain private trust.
5. For `unsigned` or `ad-hoc`, confirm that warnings and re-signing requirements
   match the release notes.
6. Record installation, upgrade, rollback, and uninstall results in the release
   approval evidence.

Rotate a signing identity as one atomic secret group. Revoke or distrust a
compromised identity before replacement, preserve valid timestamp/notarization
evidence, and never re-sign or relabel already-published immutable bytes.

## Public-program references

- Windows public distribution: the chosen Microsoft-trusted certificate or
  managed-signing provider's current issuance and hardware/cloud custody rules.
- macOS public distribution: Apple Developer ID signing and Apple notarization.
- Android store distribution: the selected store's current app-signing and key
  upgrade policy.
- iOS distribution: Apple certificates, provisioning profiles, entitlements,
  and export method for the selected channel.

Provider requirements change. Review the current official platform
documentation during every credential enrollment or rotation rather than
copying historical commands from a release ticket.
