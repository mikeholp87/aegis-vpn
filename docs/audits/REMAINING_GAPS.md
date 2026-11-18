# Remaining release gaps

| Priority | Finding | Needed evidence or implementation |
|---|---|---|
| P0 gate | A02 independent firewall replacement | Polling detects a missing or unreadable table. Prove policy identity and continuously enforced transitions before promising protection against external firewall changes. An administrator can remove a block before detection. |
| P1 | A04 Windows tunnel service | Implement and authenticate both IPC peers. Validate DPAPI and per-user ACLs, official DLLs, SCM and WFP lifecycle, routes, DNS, and real Windows 11 network traffic. Enable backend selection only after those gates pass. |
| P1 | A05 protected switch and Always On | Retain protection across profile changes and resolve failures without removing the block. Reboot persistence requires a separate explicit opt-in and authenticated recovery model. |
| P1 | A06 privileged Linux packaging | Build and test helper and matching Polkit policy installation, upgrade, removal and failure recovery using native DEB and RPM packages. Standard desktop DEB and RPM contents were inspected. |
| P1 | A07 platform lifecycle | Reproduce late activation, suspension, real link changes and the existing documented NetworkManager anti-spoofing-rule issue in disposable environments. Keep foreign profiles and rules untouched. |
| P1 | A08 DNS/IPv6 policy | Exercise resolved and plain resolv.conf, IPv6-only and dual-stack, custom policy rules and independently configured DNS on the native matrix. Forwarded container/VM traffic is outside the helper policy. |
| P2 | A13 persistence edge cases | Intentional delete can still leave a stale local record if backend deletion succeeds and the metadata volume fails. Crash-atomic coordination across NetworkManager and local files is not implemented. |
| P2 | A14 maintenance | Monitor the five unmaintained transitive dependencies and upstream migrations. Yanked-version checking was excluded from the offline RustSec audit. |
| P2 | A16/A17 measurement and matrix | Native startup and resource metrics, WebKit accessibility, tray, real Polkit prompts, reboot/suspend and network changes. Repeat Linux packet captures under each supported distro. |
| P2 | A15 native artifacts and supply chain | Run the manual preview workflow, verify hosted artifact integrity and inventory, and complete signing/release review. Keep automatic updates disabled until signed artifacts and rollback are verified. |

Use the [release checklist](../releases/RELEASE_CHECKLIST.md) and
[recorded results](../testing/TEST_RESULTS.md). No production release is ready.
