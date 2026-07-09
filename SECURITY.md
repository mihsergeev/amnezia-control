# Security Policy

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue.

Use GitHub's **[private vulnerability reporting](https://github.com/mihsergeev/amnezia-control/security/advisories/new)**
("Report a vulnerability" under the repo's Security tab). Include a
description, affected version, and reproduction steps if possible.

You'll get an acknowledgement as soon as possible and a fix or mitigation
plan. Please allow reasonable time to address the issue before any public
disclosure.

## Scope

This panel holds SSH access (root-equivalent) to the VPN nodes it manages, so
auth, SSH handling, the deploy/restore paths, and secret storage are the most
sensitive areas. See the **Security** section of the README for hardening
guidance (strong secrets, edge IP allow-list, HTTPS, 2FA, host-key pinning).

## Supported versions

Only the latest release receives security fixes.
