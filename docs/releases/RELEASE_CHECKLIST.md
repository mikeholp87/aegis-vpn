# Release checklist

Current classification: **Development Preview**. See the audit and test
results for evidence.

- [ ] Gate each claimed platform on a native install, upgrade, uninstall and
      controlled real WireGuard tunnel exercise.
- [ ] Verify handshake, transfer counters, IPv4 and IPv6 routing, DNS uplink
      captures, connection failure, safe switching, suspend/resume, service
      restart, reboot and recovery on every claimed release platform.
- [ ] Linux protected packaging installs the matching helper and Polkit policy
      and keeps recovery available if uninstall cleanup fails.
- [ ] Windows service authenticates both pipe endpoints and isolates credentials
      by authorized user. Verify official DLL provenance/search paths, service
      privileges, protected storage and full SCM/WFP cleanup in a Windows VM.
- [ ] All applicable locked builds/tests, advisory and license checks pass.
- [ ] Required security tests pass with no open release-blocking finding.
- [ ] Check installer contents, dependencies, architecture, SHA-256 checksums,
      dependency inventory, distribution notices and signing policy before
      publishing. Refresh [asset notices](ASSET_LICENSES.txt) when the pinned
      Atkinson fonts, Lucide icons or React versions change.
- [ ] Complete the required security review and publish manually after approval.
      Automatic updates require signed artifacts and a tested rollback path.

The manual GitHub Actions preview workflow prepares Linux DEB/RPM artifacts and
an inventory. Linux bundles include the matching helper and Polkit policy.
Removal hooks attempt cleanup before removal and preserve installed components
when cleanup fails. Upgrades retain the existing block. Native Windows CI checks
source and portable tests. Windows VPN installers
await a functioning service. See [remaining gaps](../audits/REMAINING_GAPS.md).
