# Security Policy

## Supported Version

Security fixes are applied to the latest commit on `main` while SentinelClarity is in active Build Week development.

## Reporting a Vulnerability

Do not open a public issue for suspected vulnerabilities, exposed credentials, or a bypass of SentinelClarity's security controls. Use GitHub's private vulnerability-reporting flow for this repository, or contact the maintainer privately through the contact details on the repository profile.

Please include:

- A clear description of the issue and its potential impact.
- Reproduction steps or a minimal proof of concept.
- Affected commit, workflow, command, or dependency version.
- Any suggested mitigation, if available.

We will acknowledge a good-faith report promptly, investigate it privately, and coordinate disclosure after a fix is available. Do not access data you do not own, disrupt services, or publish exploit details before coordination.

## Security Boundaries

SentinelClarity is a local-first static-analysis MVP. Its `serve` command intentionally binds only to `127.0.0.1`; it is not an authenticated multi-user service and must not be exposed directly to an untrusted network. Scanner findings are advisory and do not replace an independent smart-contract audit.
