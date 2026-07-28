# Organization repository policy audit

`Organization Policy Audit` is the read-only hosted-settings control for the
five release-capable Camellia repositories. The workflow runs every Monday at
03:17 UTC and can also be dispatched manually.

## Authority

The workflow mints a short-lived token from the Camellia Nexus Release Manager
App. The token is limited to `.github`, `nexus`, `nexus-management-server`,
`remote-client`, `remote-management-server`, and `remote-server` with:

- Administration read;
- Contents read;
- Issues read/write, used only for the central drift record;
- Metadata read.

The App has no Actions or Workflows permission. Its successful multi-repository
token mint also proves that the selected-repository installation covers the
complete audited scope.

The `.github` repository requires variable `RELEASE_APP_CLIENT_ID` and secret
`RELEASE_APP_PRIVATE_KEY`. The workflow verifies the returned App slug is
exactly `camellia-nexus-release-manager`.

## Reviewed controls

[`config/repository-policies.json`](../config/repository-policies.json) is the
versioned expectation. For each target repository, automation verifies:

- the exact default branch and squash-only merge settings;
- Dependabot security updates, secret scanning, and push protection;
- enabled immutable Releases;
- enabled Actions, server-side full-SHA pinning, default read-only workflow
  permissions, and no workflow authority to approve pull requests;
- presence of CODEOWNERS, the default-branch policy monitor, and release
  workflows;
- active, bypass-free default-branch and release-tag rulesets;
- current-head approval, stale-review dismissal, CODEOWNERS, conversation
  resolution, strict required checks, linear history, and CodeQL thresholds;
- a `release` environment with non-self review by the product team and the
  exact allowed branch/tag policies.

Changing either the hosted policy or the expected configuration requires a
reviewed pull request and a `policy_revision` increment. A stricter hosted
setting is still surfaced as drift so it can be reviewed and made explicit
rather than silently changing the operational contract.

## Evidence and remediation

Each run retains `audit-report.json` and `audit-report.md` for 30 days. Drift
creates or updates one issue titled
`[automation] Repository policy drift` in `.github`; a later compliant run
closes it. The workflow then fails so the drift is visible in Actions and
monitoring.

The audit never edits rulesets, environments, repository settings, certificates
or secrets. Remediation is a separate reviewed action:

1. determine whether hosted state or the reviewed baseline is wrong;
2. update only the intended side;
3. record owner, reason and evidence in the pull request or drift issue;
4. rerun the audit;
5. close only after the machine report is compliant.

If the App token cannot be minted, treat it as authority/configuration drift.
Do not replace it with a personal token or grant broader App permissions.
