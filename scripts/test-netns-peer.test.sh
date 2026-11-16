#!/usr/bin/env bash
set -euo pipefail

test_dir="$(mktemp -d)"
trap 'command rm -rf "$test_dir"' EXIT

# Replace every networking/destructive command; this check needs no privileges.
ip() {
	if [[ $* == "netns pids aegis-peer" ]]; then printf '12345\n'; fi
}
# shellcheck source=scripts/test-netns-peer.sh
source "$(dirname "${BASH_SOURCE[0]}")/test-netns-peer.sh" status
DIR="$test_dir"
printf '99999\n' >"$DIR/dnsmasq.pid"
called=""
kill() { called="$*"; }
rm() { :; }
# Skip the EUID guard only: all privileged operations above are stubs.
die() { :; }
down >/dev/null
[[ $called == "-- 12345" ]] || {
	echo "cleanup trusted a writable PID file" >&2
	exit 1
}
echo "PASS: cleanup uses kernel namespace PIDs, not the writable PID file"
