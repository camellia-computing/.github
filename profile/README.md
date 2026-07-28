# Camellia Computing

Camellia Computing is the home of two independent, pre-release product lines:

- **Camellia Remote** — a cross-platform remote desktop client, rendezvous/relay server, and management service.
- **Camellia Nexus** — a cross-platform application declaration and lifecycle manager with a separate authorization and administration service.

The products share engineering and repository-governance standards. They do not share runtime services, databases, credentials, release versions, deployment lifecycles, or security boundaries.

## Repositories

| Product | Repository | Purpose |
| --- | --- | --- |
| Camellia Remote | [`remote-client`](https://github.com/camellia-computing/remote-client) | Cross-platform desktop and mobile client |
| Camellia Remote | [`remote-protocol`](https://github.com/camellia-computing/remote-protocol) | Pinned shared wire protocol |
| Camellia Remote | [`remote-server`](https://github.com/camellia-computing/remote-server) | Rendezvous, NAT traversal, and relay services |
| Camellia Remote | [`remote-management-server`](https://github.com/camellia-computing/remote-management-server) | Accounts, devices, policy, audit, and management API |
| Camellia Nexus | [`nexus`](https://github.com/camellia-computing/nexus) | Cross-platform desktop product |
| Camellia Nexus | [`nexus-management-server`](https://github.com/camellia-computing/nexus-management-server) | Authorization and administration service |

All repositories are under active pre-release development. A public repository or source-visible copy does not by itself imply production availability, support, warranty, or—where proprietary terms apply—a grant of rights.

Security reports must follow our [security policy](../SECURITY.md). General support and contribution expectations are documented in [SUPPORT.md](../SUPPORT.md) and [CONTRIBUTING.md](../CONTRIBUTING.md).
