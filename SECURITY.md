<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 André Manz -->
<!-- Purpose: Define supported versions, confidential reporting, and security boundaries. -->

# Security Policy

## Supported versions

`vm-dev-lab` is an early-development project. Security maintenance is not guaranteed.

| Version | Support status |
| --- | --- |
| 0.5.x | Early development; no guaranteed security updates |
| Older or otherwise unsupported versions | No promised maintenance |

This policy does not establish a long-term support commitment or response-time guarantee.

## Reporting a vulnerability

Do not report an exploitable vulnerability in a public issue, discussion, pull request, or log excerpt.

GitHub Private Vulnerability Reporting is the preferred confidential channel when it is enabled for this repository. Before sending sensitive details, open the repository's **Security** tab and verify that a private **Report a vulnerability** option is available.

The availability of that GitHub setting is not confirmed by this offline repository configuration. If the private reporting option is absent, no confidential reporting channel is currently confirmed. Do not disclose exploit details publicly; the repository owner must establish and document a confidential channel before accepting the report. No email or alternative private contact is implied by this policy.

When a confidential channel is available, provide a concise impact assessment, affected version or commit, safe reproduction steps, and any relevant redacted diagnostics. Do not include unrelated host data, credentials, keys, or private infrastructure details.

## Security model and limits

- `vm-dev-lab` manages local development and test virtual machines.
- It is not a security boundary for malicious guests.
- Ownership checks are intended to prevent accidental modification of unrelated resources; they are not a general containment guarantee.
- `host-setup` is in **Heavy Development / Experimental** status and has only offline fixture coverage.
- Fresh-host installation has not yet received an independent real-world acceptance test.
- Operators must review administrative plans, ownership evidence, affected resources, and requested operations before approval.
