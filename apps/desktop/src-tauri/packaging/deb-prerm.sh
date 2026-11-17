#!/bin/sh
# Never leave the kill switch blocking traffic after Aegis is uninstalled.
# Upgrades keep it: a running tunnel must not lose protection mid-upgrade.
set -e
case "$1" in
remove | purge)
	/usr/libexec/aegis-vpn/aegis-helper remove >/dev/null 2>&1 || true
	;;
esac
