#!/bin/sh
# $1 is 0 on a final uninstall and 1 or more on upgrade (see deb-prerm.sh).
if [ "$1" = 0 ]; then
	/usr/libexec/aegis-vpn/aegis-helper remove >/dev/null 2>&1 || true
fi
exit 0
