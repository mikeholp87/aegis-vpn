#!/bin/sh
# $1 is 0 on a final uninstall and 1 or more on upgrade (see deb-prerm.sh).
if [ "$1" = 0 ]; then
	/usr/libexec/aegis-vpn/aegis-helper remove || {
		echo "Aegis firewall cleanup failed. Retry removal after resolving the helper error." >&2
		exit 1
	}
fi
exit 0
