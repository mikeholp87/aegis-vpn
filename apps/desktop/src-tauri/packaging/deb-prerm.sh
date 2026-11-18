#!/bin/sh
# Never leave the kill switch blocking traffic after Aegis is uninstalled.
# Upgrades keep it: a running tunnel must not lose protection mid-upgrade.
set -e
case "$1" in
remove | purge)
	/usr/libexec/aegis-vpn/aegis-helper remove || {
		echo "Aegis firewall cleanup failed. Retry removal after resolving the helper error." >&2
		exit 1
	}
	;;
esac
