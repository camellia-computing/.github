# Remote system E2E contract

The Remote product has four independently released repositories. A green
single-repository CI / Required job does not establish that a Client,
Protocol, Server and Management release can form one session. The organization
contract in config/remote-system-contract.json is the authority for the
cross-repository check.

## Candidate selection

The harness consumes one complete candidate template. It must contain the
physical names resolved from REMOTE_REPOSITORY_MAP and one full lowercase
commit for each logical repository:

| Logical repository | Required evidence |
| --- | --- |
| remote-protocol | source evidence and the exact commit |
| remote-server | linux/amd64 and linux/arm64 image digest plus source commit |
| remote-client | Web and controller artifacts plus the exact Protocol gitlink |
| remote-management | linux/amd64 and linux/arm64 image digest, source commit and exact web-client.lock commit |

The validator rejects a partial map, mutable tags, duplicate JSON keys,
unknown fields, protocol/Web pin drift, image/source drift, duplicate
artifacts, or a candidate workflow identity. The candidate workflow cannot
replace the organization-owned validator or scenario runner.

## Runtime layers

run_remote_system.py is the base-owned runner. It accepts a candidate
template, an organization-approved Compose model and an executable scenario
adapter from a trusted harness installation. It:

1. validates every candidate before starting a service;
2. checks that management, identity and relay resolve to the exact manifest
   image digests;
3. gives each run a unique Compose project, network, volume and credential
   namespace;
4. invokes the fixed scenario names with bounded per-scenario and total
   deadlines using argument arrays, never a shell string;
5. accepts only one passed result per attempt and canonical, bounded,
   credential-canary-free JSON evidence; and
6. always removes the exact Compose project, volumes and temporary workspace.

The adapter is not a candidate repository workflow. A platform runner installs
it from the reviewed harness package and it must be below the supplied
trusted-driver root. A missing Docker daemon, missing adapter, image mismatch,
timeout, malformed evidence or cleanup failure is a failed run.

The smoke mode is intended for PR required checks and covers authentication,
direct and forced-relay session setup, first-frame/input and reconnect/close.
The exhaustive mode adds file/clipboard/audit and is intended for protected
main and release eligibility. A scheduled exhaustive run and a separately
authorized Win11 host/controller probe are required before a formal release.

## Evidence

The final manifest is canonical JSON and its SHA-256 is the only stable join
key. Scenario evidence is limited to four MiB in total, contains no raw logs,
environment, database rows, credentials, tokens, IP addresses or PII, and is
retained for seven days. Run names and port ranges are unique to one run; the
cleanup job uses always() and verifies that no object with the run's Compose
label remains.

This repository currently provides the contract, validator and hermetic runner
tests. A WSL checkout without a Docker daemon or an attached Win11 adapter must
report the runtime layer as unavailable; it must never turn the contract-only
result into an E2E pass.
