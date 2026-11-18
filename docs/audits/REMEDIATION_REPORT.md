# Remediation report

## 1. Executive summary

Aegis entered the audit with a working Linux NetworkManager backend, a
session-scoped Linux firewall helper, a desktop UI and an unfinished Windows
pipe client. The baseline working tree already held helper hardening and
tests. The audit preserved it and addressed the credential boundary, firewall
status, DNS probe routing, profile persistence and desktop integration.

## 2. Findings

The [gap register](FULL_GAP_AUDIT.md) tracks 20 findings: 3 P0, 7 P1, 9 P2 and
1 P3. A mitigation that disables an unfinished feature is listed separately
from its implementation and platform acceptance.

## 3. Changes

- A01: Windows production selection returns Unavailable before opening an
  unauthenticated pipe. The portable protocol and Windows compile checks stay.
- A02: protected activation checks kernel state before and after backend
  activation. Monitoring revokes the claim and stops the tunnel if the
  observed firewall block disappears or cannot be checked.
- A03/A08: Linux binds each DNS probe to the owned tunnel device and a tunnel
  source address. DNS verification checks the live resolved link's servers.
  The IPv6 fallback applies only to the intended IPv4-only profile case.
- A09/A10/A13: simulation uses isolated temporary metadata and in-memory
  credentials. Startup leaves untracked backend configurations intact.
  Profile edits restore the previous backend config after metadata write
  failure. Atomic writes use distinct temporary files.
- A11/A12: the tray exposes retained-block removal and respects preferred
  profile eligibility. Rust publishes authoritative settings changes.
- A20: NetworkManager caches handshake samples by activation and interface.
  Rust and the Dashboard distinguish a handshake from received tunnel data.
- A15/A19: the manual Linux preview workflow requires installer outputs and
  uploads verified checksums and the locked Cargo inventory. The desktop
  library uses the Rust library type it needs, avoiding extra link outputs.

## 4. Remaining issues

See [REMAINING_GAPS.md](REMAINING_GAPS.md) for priorities and ownership. Required
external work includes the Windows service, protected switching, Always On,
helper packaging and clean lifecycle tests, and complete native evidence.

## 5. Platform status

- **Linux:** NetworkManager path with Debian 13 VM coverage. Unsigned debug
  amd64 DEB and x86-64 RPM artifacts were built, inspected and checksummed.
  Native clean install/upgrade/removal, Ubuntu, Fedora, GNOME and physical
  suspend/roaming remain unverified.
- **Windows:** MSVC-target compile check and portable protocol tests. Production
  VPN backend unavailable pending an authenticated service and native validation.

## 6. VPN functionality

Linux tests separate activation, real WireGuard handshake, IPv4 and IPv6
sentinel routing, DNS/resolver checks, uplink captures, unprotected profile
switching, protected tunnel drop, reconnection and cleanup. See the per-run
results for exact scope. Country-labelled VM profiles use a controlled peer.
Protected switching remains refused.

## 7. Security results

Source review, deterministic regressions and isolated traffic tests are
recorded separately in [TEST_RESULTS.md](../testing/TEST_RESULTS.md).
No independent formal audit was conducted. Firewall polling detects loss
after it occurs. It cannot prevent or reverse administrator rule changes.
The release checklist requires direct verification of the claimed policy.

## 8. Performance

Pre- and post-remediation frontend gzip JavaScript output was 90.09 and
90.14 kB using the same Vite build information. This measures artifact size.
The isolated Xvfb desktop startup measurement timed out after eight seconds
waiting for a visible window, with desktop portal and runtime socket errors.
There is no valid startup, CPU, memory or native active-load comparison.
No performance improvement is claimed.

## 9. Build and test commands

See [TEST_RESULTS.md](../testing/TEST_RESULTS.md) for the exact commands,
counts, versions, advisory database revision and failures.

## 10. Release classification

**Development Preview.** Local regression checks and controlled Debian
network evidence support preview use. The required Windows, protected
transition and installation matrix remains open. Preview artifacts are
unsigned and publication remains a manual decision.

## 11. Remaining manual tests

Run the [native matrix](../testing/TEST_PLAN.md#release-evidence-matrix) with a
controlled VM console and, where required, administrator authorization and an
operator-controlled WireGuard peer. Include install, upgrade, uninstall, real
suspend, reboot, network changes and crash recovery.

## 12. Priority order

1. Validate or strengthen retained firewall policy identity and continuous
   protected transitions before claiming coverage for those modes.
2. Implement and verify the authenticated Windows service and installer.
3. Package the Linux helper safely and exercise clean lifecycle on Debian,
   Ubuntu and Fedora.
4. Retest unavailable native scenarios and record representative desktop
   resource measurements before promoting the preview.
