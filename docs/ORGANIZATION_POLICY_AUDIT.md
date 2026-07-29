# Organization policy audit

`Organization Policy Audit` is the read-only hosted-settings control for the
organization and every managed repository. It runs each Monday at 03:17 UTC
and may be dispatched manually.

## Authority

The workflow uses a dedicated Policy Auditor GitHub App. It is separate from
the Release Manager and has no Contents, Pull requests, Actions, Workflows,
environment, secret or repository-setting write permission. Configure the
complete group in the governance repository:

- variable `POLICY_AUDIT_APP_CLIENT_ID`;
- variable `POLICY_AUDIT_APP_SLUG`;
- secret `POLICY_AUDIT_APP_PRIVATE_KEY`.

The App needs repository Administration read, Contents read, Metadata read and
Issues write, plus Members read and Organization administration read. Issues
write is used only to maintain the central drift issue. Install it on every
repository resolved from the logical policy config. A partial credential group,
unexpected App slug or incomplete installation is a failed audit.

## Reviewed controls

[`repository-policies.json`](../config/repository-policies.json) is the
versioned expectation and the single physical repository-name map. It contains
organization controls and four repository profiles: governance, library,
release client and release service.

Organization checks cover:

- mandatory 2FA and a minimum of two owners without naming individuals;
- no default repository access;
- disabled member repository, Pages, deletion and visibility changes;
- no outside collaborators or pending invitations.

Every repository is checked for:

- visibility, default branch, squash-only merge and branch cleanup;
- exact team access;
- Dependabot security updates, secret scanning and push protection;
- read-only default Actions authority and server-side full-SHA pinning;
- required policy/workflow paths;
- bypass-free branch rules, current-head approval, CODEOWNERS, resolved
  conversations, linear history, strict required checks and CodeQL threshold.

Release profiles additionally require immutable Releases, protected release
tags and a `release` environment with non-self review and exact branch/tag
deployment policies. Governance and library profiles must not carry dormant
release controls.

## Portability and evidence

Repository names are resolved from logical IDs at runtime. Change a physical
name once in the policy file, update product-owned references through reviewed
pull requests, then run:

```bash
POLICY_AUDIT_ORGANIZATION=example-owner \
  python3 scripts/audit_repository_policies.py
```

The owner override is an audit aid; it does not mutate either organization.

Each hosted run retains machine-readable JSON and readable Markdown for 30
days. Drift creates or updates one issue in the governance repository; a later
compliant run closes it. Reports remain workflow artifacts and are not
committed.

The audit never remediates settings. Correct either hosted state or the
reviewed config in a separately reviewed action, rerun the audit, and retain
the pull request or issue as evidence. Do not substitute a personal token or
grant the auditor write access to make drift disappear.
