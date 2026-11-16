# Security policy

## Reporting a vulnerability

Please report privately through GitHub's **"Report a vulnerability"** button
(Security → Advisories) on this repository. Do not open a public issue.

Include the affected version or commit, platform, steps to reproduce, and impact.
We aim to acknowledge reports within 7 days and to agree on a disclosure date
with you. Credit is given unless you prefer otherwise.

## Scope

In scope: key exposure, privilege escalation through the app or its helpers,
traffic or DNS leaks the app claims to prevent, unsafe handling of imported
profiles, IPC/permission bypasses, installer/updater issues.

Out of scope: vulnerabilities in WireGuard itself, NetworkManager, or the OS
(report those upstream), and attacks that require root on the machine.

## Status

Aegis VPN is pre-alpha and has not been independently audited. See
`docs/security/THREAT_MODEL.md` for what is and is not mitigated.
