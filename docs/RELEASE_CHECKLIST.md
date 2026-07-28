# Release checklist

Record this checklist in the release pull request for the exact candidate commit.

- [ ] Version is a new stable Semantic Version from the repository's single version source.
- [ ] Required CI, cross-repository contracts, security scans, and native package acceptance are green.
- [ ] Database migration and rollback/recovery implications were reviewed on a fresh database.
- [ ] Production configuration, TLS/origin/proxy boundaries, minimum-version policy, and secret references were reviewed without exposing values.
- [ ] Checksums, SBOM, provenance, vulnerability scan, signatures/attestations, and artifact identities agree.
- [ ] Release and registry artifacts were read back by immutable digest; tags and assets cannot be silently replaced.
- [ ] A recent isolated restore meets RPO ≤ 1 hour and RTO ≤ 4 hours for a production service.
- [ ] Monitoring, incident owner, staged rollout, previous digest, and rollback decision point are recorded.
- [ ] License, corresponding-source, attribution, privacy, and jurisdiction-specific commercial obligations were reviewed.
- [ ] Protected release-environment approval was obtained after all other evidence was complete.
