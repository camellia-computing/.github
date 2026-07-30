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

The App needs repository Administration, Contents and Metadata read, plus
Members, Organization administration, Variables and Secrets read at
organization level. It has no write permission. Variables and Secrets read are
used to inventory names, visibility and selected repository metadata; secret
values cannot be read, and variable values are discarded in memory without
being retained or reported. Install the App for all organization repositories.
The workflow scopes its ordinary audit token back to the reviewed logical map,
while a separate read-only token verifies the complete installation inventory.
A partial credential group, unexpected App slug, unmanaged repository or
incomplete installation is a failed audit.

Provision the App once from an authenticated organization-owner workstation:

```bash
python3 scripts/bootstrap_policy_auditor.py --apply
```

The local manifest bridge derives the owner, governance repository, immutable
organization identity and permissions from the reviewed policy. GitHub still
requires an owner to confirm registration and an all-repositories installation
in the browser. The returned private key is streamed directly into the
governance repository secret and is never written to disk or placed on a
command line. The bootstrap refuses to overwrite an existing credential group;
rotation therefore remains a separate reviewed operation.

The repository audit token explicitly requests its reduced permissions. A
separate short-lived scope-audit token inherits the App's reviewed read-only
permissions because the pinned installation-token action does not currently
expose organization Variables. That token is supplied only to inventory and
selected-repository GET requests. The governance repository's own
least-privilege `GITHUB_TOKEN` maintains the central drift issue, so the App
does not need Issues write. Revisit the documented inheritance exception when
the action exposes a Variables permission selector.

## Reviewed controls

[`repository-policies.json`](../config/repository-policies.json) is the
versioned expectation and the single logical-to-physical repository map. It
records immutable organization and repository IDs, stable artifact IDs,
reviewed automation credential scopes, and four repository profiles:
governance, library, release client and release service.

Organization checks cover:

- mandatory 2FA and a minimum of two owners without naming individuals;
- immutable organization identity, exact repository inventory and exact shared
  automation/signing credential scopes;
- no default repository access;
- disabled member repository, Pages, deletion and visibility changes;
- no outside collaborators or pending invitations;
- organization-wide Actions enablement, read-only default tokens, disabled
  workflow review approval, full-SHA pinning and 30-day log/artifact retention;
- the exact immutable-Release repository ID set derived from release profiles;
- one reviewed, enforced code-security configuration, its immutable ID and
  settings, its public-repository default, and no additional defaults.

Every repository is checked for:

- visibility, default branch, squash-only merge and branch cleanup;
- immutable repository identity and canonical owner/name mapping;
- exact team access;
- Dependabot security updates, secret scanning and push protection;
- weekly CodeQL default setup with the standard query suite and remote/local
  source analysis;
- attachment to the reviewed enforced organization code-security
  configuration;
- read-only default Actions authority and server-side full-SHA pinning;
- required policy/workflow paths;
- bypass-free branch rules, current-head approval, CODEOWNERS, resolved
  conversations, linear history, strict required checks and CodeQL threshold.

Release profiles additionally require immutable Releases, protected release
tags and a `release` environment with non-self review and exact branch/tag
deployment policies. Governance and library profiles must not carry dormant
release controls.

The organization code-security configuration is attached to every currently
managed public repository and is the default for future public repositories.
It enables the dependency graph, Dependabot alerts and security updates,
CodeQL default setup, secret scanning and push protection, validity checks, and
private vulnerability reporting. Automatic dependency submission remains
disabled because repositories already provide ecosystem-specific lockfiles and
build validation. Copilot generic-secret scanning remains `not_set`; enabling a
paid or preview capability is a separate reviewed decision. A future private
repository requires an explicit capability/profile review under the
organization's current GitHub plan.

## Portability and evidence

Repository names are resolved from logical IDs at runtime and lists are ordered
by logical ID, never by mutable physical name. Artifact IDs remain unchanged
across repository renames. The code-security configuration, organization and
repositories are also bound to immutable numeric IDs. Before changing a
physical name, update the policy mapping and product-owned references through
reviewed pull requests, then run:

```bash
POLICY_AUDIT_ORGANIZATION=example-owner \
  python3 scripts/audit_repository_policies.py
```

The owner override is an audit aid for an organization login rename; the
immutable organization ID must still match and no organization is mutated.
Transfers to a different organization require a reviewed ID migration.
That migration must create a replacement code-security configuration, attach
it to the complete managed repository inventory, set the intended new-repository
default, and record its returned immutable ID before the audit can pass.

`python3 scripts/audit_portability.py` also rejects mutable owner coordinates
outside the small set of GitHub surfaces that require them, rejects
machine-specific paths, verifies policy-derived links and CODEOWNERS, and runs a
mixed-case/dot/underscore rename fixture against GitHub's repository-name
rules.

All paginated organization, repository, credential and installation inventories
are consumed to completion; a truncated response fails closed. Each hosted run
retains machine-readable JSON and readable Markdown for 30 days. Drift creates
or updates one issue in the governance repository; a later
compliant run closes it. Reports remain workflow artifacts and are not
committed.

The audit never remediates settings. Correct either hosted state or the
reviewed config in a separately reviewed action, rerun the audit, and retain
the pull request or issue as evidence. Do not substitute a personal token or
grant the auditor write access to make drift disappear.
