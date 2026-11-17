#!/usr/bin/env bash
# Isolated WireGuard test server for live Aegis VPN tests on Linux.
#
# Creates network namespace "aegis-peer" with a WireGuard server reachable over
# a private veth link, and writes a matching client profile.
#
#   sudo scripts/test-netns-peer.sh up [split|full|full4]   # prints the profile path
#   (or: pkexec "$PWD/scripts/test-netns-peer.sh" up  when no terminal is available)
#   sudo scripts/test-netns-peer.sh down                    # removes everything it created
#
# Modes:
#   split (default) routes only 10.99.0.0/24. Safe on a developer machine.
#   full            routes 0.0.0.0/0 and ::/0, DNS 10.99.0.1.        VM ONLY.
#   full4           routes 0.0.0.0/0 only (IPv6 deliberately leaks).  VM ONLY.
# The full modes add "internet" sentinel addresses inside the namespace
# (198.51.100.1, 2001:db8:99::1) and a DNS server on 10.99.0.1 that answers every
# name with the sentinel, so leak tests can tell which resolver answered.
# They refuse to run unless AEGIS_VM_TEST=1, because connecting a full-tunnel
# profile takes over the default route.
#
# Requires: iproute2, wireguard-tools (wg), kernel wireguard module;
# full modes also need dnsmasq (dnsmasq-base).
set -euo pipefail

NS=aegis-peer
HOST_IF=aegis-veth0
NS_IF=aegis-veth1
HOST_ADDR=10.200.0.1/30
NS_ADDR=10.200.0.2/30
SERVER_TUN4=10.99.0.1/24
SERVER_TUN6=fd99::1/64
SENTINEL4=198.51.100.1
SENTINEL6=2001:db8:99::1
PORT=51820
DIR=/run/aegis-test

die() {
	echo "error: $*" >&2
	exit 1
}

up() {
	local mode="${1:-split}"
	[[ $EUID -eq 0 ]] || die "run as root (sudo or pkexec)"
	case "$mode" in
	split) ;;
	full | full4)
		[[ ${AEGIS_VM_TEST:-} == 1 ]] || die "mode '$mode' is for disposable VMs only (set AEGIS_VM_TEST=1)"
		command -v dnsmasq >/dev/null || die "dnsmasq is required for mode '$mode'"
		;;
	*) die "unknown mode '$mode' (split|full|full4)" ;;
	esac
	command -v wg >/dev/null || die "wireguard-tools is not installed (apt install wireguard-tools)"
	# A distinct client address per mode, so leftovers from one mode's run (for
	# example NetworkManager's leaked anti-spoofing rules) cannot affect another.
	local host
	case "$mode" in split) host=2 ;; full) host=3 ;; full4) host=4 ;; esac
	CLIENT_TUN4="10.99.0.$host/32"
	CLIENT_TUN6="fd99::$host/128"
	ip netns list | grep -qw "$NS" && die "namespace $NS already exists; run '$0 down' first"

	[[ ! -e $DIR && ! -L $DIR ]] || die "runtime directory already exists; run '$0 down' first"
	install -d -m 0711 "$DIR"
	umask 077
	wg genkey >"$DIR/server.key"
	wg genkey >"$DIR/client.key"
	wg pubkey <"$DIR/server.key" >"$DIR/server.pub"
	wg pubkey <"$DIR/client.key" >"$DIR/client.pub"

	ip netns add "$NS"
	ip link add "$HOST_IF" type veth peer name "$NS_IF"
	ip link set "$NS_IF" netns "$NS"
	ip addr add "$HOST_ADDR" dev "$HOST_IF"
	ip link set "$HOST_IF" up
	ip -n "$NS" addr add "$NS_ADDR" dev "$NS_IF"
	ip -n "$NS" link set "$NS_IF" up
	ip -n "$NS" link set lo up

	ip -n "$NS" link add wg0 type wireguard
	ip netns exec "$NS" wg set wg0 private-key "$DIR/server.key" listen-port "$PORT" \
		peer "$(cat "$DIR/client.pub")" allowed-ips "${CLIENT_TUN4},${CLIENT_TUN6}"
	ip -n "$NS" addr add "$SERVER_TUN4" dev wg0
	ip -n "$NS" addr add "$SERVER_TUN6" dev wg0 nodad
	ip -n "$NS" link set wg0 up

	local address="$CLIENT_TUN4" allowed="10.99.0.0/24" dns=""
	if [[ $mode != split ]]; then
		# "Internet" endpoints that exist only behind the tunnel.
		ip -n "$NS" link add sentinel type dummy
		ip -n "$NS" addr add "$SENTINEL4/32" dev sentinel
		ip -n "$NS" addr add "$SENTINEL6/128" dev sentinel nodad
		ip -n "$NS" link set sentinel up
		ip netns exec "$NS" dnsmasq --conf-file=/dev/null --no-resolv --no-hosts \
			--listen-address="${SERVER_TUN4%/*}" --bind-interfaces \
			--address="/#/$SENTINEL4" --address="/#/$SENTINEL6" \
			--pid-file="$DIR/dnsmasq.pid"
		dns="DNS = ${SERVER_TUN4%/*}"
		if [[ $mode == full ]]; then
			address="$CLIENT_TUN4, $CLIENT_TUN6"
			allowed="0.0.0.0/0, ::/0"
		else
			allowed="0.0.0.0/0"
		fi
	fi

	# Invoking user: sudo sets SUDO_USER, pkexec sets PKEXEC_UID.
	local owner="${SUDO_USER:-}"
	if [[ -z $owner && -n ${PKEXEC_UID:-} ]]; then
		owner="$(id -nu "$PKEXEC_UID")"
	fi
	owner="${owner:-root}"
	local conf="$DIR/aegis-netns-test.conf"
	cat >"$conf" <<CONF
# Throwaway profile ($mode) for the isolated aegis-peer test namespace.
[Interface]
PrivateKey = $(cat "$DIR/client.key")
Address = ${address}
${dns}

[Peer]
PublicKey = $(cat "$DIR/server.pub")
Endpoint = ${NS_ADDR%/*}:${PORT}
AllowedIPs = ${allowed}
PersistentKeepalive = 25
CONF
	chown "$owner" "$conf"
	chmod 0600 "$conf"
	echo "$conf"
}

down() {
	[[ $EUID -eq 0 ]] || die "run as root (sudo or pkexec)"
	# Read process ids from the kernel, never from caller-controlled runtime files.
	local pid
	while read -r pid; do
		if [[ $pid =~ ^[0-9]+$ ]]; then kill -- "$pid" 2>/dev/null || true; fi
	done < <(ip netns pids "$NS" 2>/dev/null)
	ip netns del "$NS" 2>/dev/null || true # also removes the veth pair
	ip link del "$HOST_IF" 2>/dev/null || true
	rm -rf "$DIR"
	echo "removed namespace $NS and $DIR"
}

status() {
	ip netns exec "$NS" wg show wg0 2>/dev/null || echo "namespace $NS not running"
}

case "${1:-}" in
up) up "${2:-split}" ;;
down) down ;;
status) status ;;
*) die "usage: $0 up [split|full|full4] | down | status" ;;
esac
