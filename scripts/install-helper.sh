#!/usr/bin/env bash
# Install (or remove) the Aegis VPN kill-switch helper and its Polkit policy.
#
#   cargo build --release -p aegis-helper
#   sudo scripts/install-helper.sh install target/release/aegis-helper
#   sudo scripts/install-helper.sh uninstall
#
# Packages will ship the same two files; this script is for development and
# the test VM.
set -euo pipefail

BIN=/usr/libexec/aegis-vpn/aegis-helper
POLICY=/usr/share/polkit-1/actions/org.aegisvpn.helper.policy
SRC_POLICY="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/services/linux-helper/org.aegisvpn.helper.policy"

die() {
	echo "error: $*" >&2
	exit 1
}

uninstall() {
	"$BIN" remove || die "firewall cleanup failed; keeping the helper and policy installed so you can retry"
	rm -f "$BIN" "$POLICY"
	rmdir --ignore-fail-on-non-empty "$(dirname "$BIN")" 2>/dev/null || true
	echo "removed $BIN and $POLICY"
}

main() {
	[[ $EUID -eq 0 ]] || die "run as root (sudo)"
	case "${1:-}" in
	install)
		[[ -f ${2:-} ]] || die "usage: $0 install <path to built aegis-helper>"
		install -d -o root -g root -m 0755 "$(dirname "$BIN")"
		install -D -o root -g root -m 0755 "$2" "$BIN"
		install -D -o root -g root -m 0644 "$SRC_POLICY" "$POLICY"
		echo "installed $BIN and $POLICY"
		;;
	uninstall) uninstall ;;
	*) die "usage: $0 install <aegis-helper> | uninstall" ;;
	esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
