#!/usr/bin/env bash
set -euo pipefail

test_dir="$(mktemp -d)"
trap 'rm -rf "$test_dir"' EXIT
# Sourcing defines functions; it does not install or run privileged code.
# shellcheck source=scripts/install-helper.sh
source "$(dirname "${BASH_SOURCE[0]}")/install-helper.sh"
python3 - "$SRC_POLICY" <<'PY'
import sys
import xml.etree.ElementTree as ET

actions = {a.attrib["id"]: a for a in ET.parse(sys.argv[1]).getroot().findall("action")}
for command in ("apply", "remove", "status", "handshake"):
    suffix = f"killswitch.{command}" if command in ("apply", "remove") else command
    action = actions[f"org.aegisvpn.helper.{suffix}"]
    assert action.findtext("defaults/allow_active") == ("auth_admin" if command in ("apply", "remove") else "yes")
    assert action.findtext("defaults/allow_any") == "auth_admin"
    assert action.findtext("defaults/allow_inactive") == "auth_admin"
    annotations = {a.attrib["key"]: a.text for a in action.findall("annotate")}
    assert annotations["org.freedesktop.policykit.exec.path"] == "/usr/libexec/aegis-vpn/aegis-helper"
    assert annotations["org.freedesktop.policykit.exec.argv1"] == command
print("PASS: only scoped read-only actions bypass administrator authentication")
PY
mkdir "$test_dir/package"
BIN="$test_dir/package/helper"
POLICY="$test_dir/policy"
printf '#!/usr/bin/env bash\nexit 1\n' >"$BIN"
chmod +x "$BIN"
touch "$POLICY"
if (uninstall) >"$test_dir/output" 2>&1; then
	echo "uninstall ignored failed firewall cleanup" >&2
	exit 1
fi
[[ -f $BIN && -f $POLICY ]]
# shellcheck disable=SC2016 # The generated helper checks its own argument.
printf '#!/usr/bin/env bash\n[[ $1 == remove ]]\n' >"$BIN"
uninstall >/dev/null
[[ ! -e $BIN && ! -e $POLICY ]]
echo "PASS: failed cleanup retains the helper; successful cleanup permits uninstall"
