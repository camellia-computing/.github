# GitHub automation identities and locations

This catalogue distinguishes GitHub Apps from GitHub Actions and records the
exact organization automation currently in use.

- A **GitHub App** is an independently installed machine identity. Its
  installation token is short-lived and limited by the App permissions and
  selected repositories.
- A **GitHub Action** is code executed inside a workflow. A local composite
  action lives under `.github/actions/<name>` in a repository and runs with the
  calling job's token and permissions. Creating a local action does not create a
  GitHub App in organization settings.

## Camellia Nexus Release Manager

This App is the machine identity for coordinated Nexus release management,
verified Remote publication, and the read-only organization policy audit.

| Setting | Required value |
| --- | --- |
| GitHub App display name | `Camellia Nexus Release Manager` |
| Current slug | `camellia-nexus-release-manager` |
| Owner | `camellia-computing` organization |
| Webhook | Disabled |
| Administration | Read-only |
| Contents | Read and write |
| Issues | Read and write |
| Pull requests | Read and write |
| Metadata | Read-only (GitHub-required) |
| Organization permissions | None |
| Installation scope | Selected repositories only: `.github`, `nexus`, `nexus-management-server`, `remote-client`, `remote-management-server`, `remote-server` |
| Actions / Workflows | None |

Each release repository needs:

- variable `RELEASE_APP_CLIENT_ID` containing the App **Client ID**, not its
  numeric App ID;
- variable `RELEASE_APP_LOGIN` containing the exact lowercase bot login
  `camellia-nexus-release-manager[bot]`;
- secret `RELEASE_APP_PRIVATE_KEY` containing one complete generated PEM private
  key.

The three values are an atomic group. Prefer selected-repository organization
variables/secrets over duplicated repository values. After the organization
group is verified, remove same-named repository overrides so all consumers
rotate together. The policy job rejects a partial group or an installation
token whose identity does not match `RELEASE_APP_LOGIN`.

The App is consumed by Nexus at:

- `.github/workflows/main.yml` for policy validation;
- `.github/workflows/merge.yml` for controlled merge operations;
- `.github/workflows/release-manager.yml` for the coordinated release state
  machine;
- `.github/workflows/publish-release.yml` for release publication.

Remote Client, Remote Server, and Remote Management consume it in
`.github/workflows/main.yml` for hosted-policy validation and
`.github/workflows/release.yml` for App-authored, read-back-verified immutable
Releases. Candidate mode never receives the App key or token.

The `.github` repository uses `RELEASE_APP_CLIENT_ID` and
`RELEASE_APP_PRIVATE_KEY` to run the weekly
[organization policy audit](ORGANIZATION_POLICY_AUDIT.md). It does not need the
bot-login variable because the workflow compares the minted token's slug to the
fixed reviewed identity.

Private keys are rotated in the GitHub App settings, then updated in the
selected-repository organization secret before the old key is revoked. Every
rotation ends with a successful `Main` run in all five release repositories and
a compliant organization audit.

## Prepared cross-repository reader

The current cross-repository sources are public, so the workflows deliberately
support public reads when the complete App credential pair is absent. The
organization may nevertheless create the reader in advance to obtain a
separately auditable, short-lived machine identity. A trusted workflow prefers
the App when the complete pair is configured; fork and Dependabot contexts
continue to use public access.

Configuration:

| Setting | Required value |
| --- | --- |
| GitHub App display name | `Camellia Cross Repository Reader` |
| Owner | `camellia-computing` organization |
| Webhook | Disabled |
| Contents | Read-only |
| Metadata | Read-only (GitHub-required) |
| Every other repository/organization permission | None |
| Installation scope | Selected source repositories only: `nexus`, `nexus-management-server` |

Create the complete pair at organization level and restrict its selected
repositories to the two current consumers, `nexus` and
`nexus-management-server`:

- variable `CROSS_REPO_READ_APP_CLIENT_ID` containing the App Client ID, not
  its numeric App ID;
- secret `CROSS_REPO_READ_APP_PRIVATE_KEY` containing one complete PEM private
  key.

Current consumers are the Nexus and Nexus Management cross-repository contract
checks in `.github/workflows/ci.yml`, `.github/workflows/contract-monitor.yml`,
and (for Nexus) `.github/workflows/native-e2e.yml`. Their resolvers deliberately
allow both values to be absent for public sources and reject a partial pair.
Do not create same-named repository overrides after the organization pair is
working.

The installation scope lists repositories being read, while the organization
variable/secret scope lists repositories running the consuming workflows. The
same two repositories currently serve both roles because Nexus and Nexus
Management validate each other.

Remote Management currently reads the public `remote-client` source with its
workflow token. Do not expose the reader private key to Remote Management until
its local Web-client Action has gained and passed review for the same atomic
App/public-fallback resolver. If that becomes necessary, first update the code,
then add `remote-client` to the App installation and
`remote-management-server` to the organization credential consumers.

Do not grant pull-request write, issue write, administration, Actions, or
organization permissions to this reader. An organization owner must create and
install the App in the GitHub web interface; the existing REST and `gh` flows
cannot substitute for that owner action. After configuration, run both Nexus
cross-repository contracts and native E2E and confirm that trusted contexts
selected App mode. Re-evaluate both selected-repository lists whenever a source
becomes private, a new consumer is added, or a repository is archived.

## Repository-local composite actions

| Action | Definition | Documentation | Current callers |
| --- | --- | --- | --- |
| Set up Flutter | `remote-client/.github/actions/setup-flutter/action.yaml` | `remote-client/.github/actions/setup-flutter/README.md` | Remote Client CI/release and the pinned Remote Management Web build |
| Build pinned Camellia Remote Web client | `remote-management-server/.github/actions/build-web-client/action.yml` | `remote-management-server/.github/actions/build-web-client/README.md` | Remote Management CI |

The second action checks out Remote Client at the exact revision stored by
Remote Management, verifies that the revision is reachable from the source
default branch and has a successful required push CI run, then builds and
records the Web runtime provenance.

A local composite action has no separate organization installation screen. Its
permissions come from the calling workflow. Each action must have a README that
documents its inputs, outputs, permissions, trust boundary, and update process.

## Workflow and third-party Action policy

- Declare top-level read-only permissions, then grant write permissions only on
  the exact job that publishes or mutates state.
- Keep `persist-credentials: false` on source checkouts unless a reviewed step
  must push through that checkout.
- Pin third-party Actions to a full commit SHA and retain a reviewed version
  comment.
- Use environment protection for production publication and do not expose
  production secrets to candidate/test builds.
- Treat App IDs, Client IDs, repository variables, and public fingerprints as
  non-secret; treat App private keys, PFX/P12 data, signing keys, passwords, and
  tokens as secrets.
- Validate optional credentials as complete groups: both absent means the
  documented fallback mode; a partial group is an error.
- Record the App/action name, owner, exact repository location, permissions,
  installation/callers, rotation owner, and failure mode in this file before
  production use.

After changing a GitHub App permission, an organization owner must approve the
new permission for the installation. Re-run the affected policy workflow and
inspect the token identity and effective repository scope before relying on the
new grant.
