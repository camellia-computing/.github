# Release checklist

Record this checklist in the release pull request for the exact candidate commit.

- [ ] Version is a new stable Semantic Version from the repository's single version source.
- [ ] Required CI, cross-repository contracts, security scans, and native package acceptance are green.
- [ ] Database migration and rollback/recovery implications were reviewed on a fresh database.
- [ ] Production configuration, TLS/origin/proxy boundaries, minimum-version policy, and secret references were reviewed without exposing values.
- [ ] Checksums, SBOM, provenance, vulnerability scan, signatures/attestations, and artifact identities agree.
- [ ] GitHub Release Assets contain only the product's reviewed public distribution files, public verification material, and file checksums; internal evidence remains in CI/attestation storage.
- [ ] Every native artifact records one verified category (`public-trust`, `private-trust`, `platform-key`, `ad-hoc`, or `unsigned`); no unsigned, ad-hoc, or privately trusted artifact is described as publicly trusted.
- [ ] Every configured identity matches its protected expected identity and the downloaded bytes; trust is derived by the native verifier rather than a configured label.
- [ ] Unsigned Android/iOS outputs are named and documented as re-signing inputs, not installable public releases.
- [ ] Release and registry artifacts were read back by immutable digest; tags and assets cannot be silently replaced.
- [ ] Every image records GHCR and Docker Hub independently; an unconfigured target is explicitly skipped and a configured target cannot be downgraded to a skip.
- [ ] `latest`, when published, still resolves to the highest completed stable SemVer and every deployment input uses the recorded digest.
- [ ] A recent isolated restore meets the default RPO ≤ 24 hours and RTO ≤ 4 hours, or a stricter product-specific target.
- [ ] Monitoring, incident owner, staged rollout, previous digest, and rollback decision point are recorded.
- [ ] License, corresponding-source, attribution, privacy, and jurisdiction-specific commercial obligations were reviewed.
- [ ] Protected release-environment approval was obtained after all other evidence was complete, with self-review and administrator bypass disabled.

The release pull request must link the validated
[`release-evidence.json`](RELEASE_EVIDENCE.md) from its retained CI evidence and the platform details in
[`ARTIFACT_SIGNING.md`](ARTIFACT_SIGNING.md). Native publisher signing is
optional, but its mode is never implicit. Supply-chain evidence remains
mandatory in every mode.
