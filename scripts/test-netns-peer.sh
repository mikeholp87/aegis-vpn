#!/usr/bin/env bash
# Isolated WireGuard test server for live Aegis VPN tests on Linux.
#
# Creates network namespace "aegis-peer" with a WireGuard server reachable from
# the host over a private veth link. The generated client profile routes ONLY
# 10.99.0.0/24 (split route), so host routing, DNS and other VPNs are untouched.
#
#   sudo scripts/test-netns-peer.sh up     # prints the client profile path
#   sudo scripts/test-netns-peer.sh down   # removes everything it created
#
# Requires: iproute2, wireguard-tools (wg), kernel wireguard module.
set -euo pipefail

NS=aegis-peer
HOST_IF=aegis-veth0
NS_IF=aegis-veth1
HOST_ADDR=10.200.0.1/30
NS_ADDR=10.200.0.2/30
SERVER_TUN=10.99.0.1/24
CLIENT_TUN=10.99.0.2/32
PORT=51820
DIR=/run/aegis-test

die() {
	echo "error: $*" >&2
	exit 1
}

up() {
	[[ $EUID -eq 0 ]] || die "run with sudo"
	command -v wg >/dev/null || die "wireguard-tools is not installed (apt install wireguard-tools)"
	ip netns list | grep -qw "$NS" && die "namespace $NS already exists; run '$0 down' first"

	install -d -m 0700 "$DIR"
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
		peer "$(cat "$DIR/client.pub")" allowed-ips "${CLIENT_TUN}"
	ip -n "$NS" addr add "$SERVER_TUN" dev wg0
	ip -n "$NS" link set wg0 up

	local owner="${SUDO_USER:-root}"
	local conf="$DIR/aegis-netns-test.conf"
	cat >"$conf" <<CONF
# Throwaway profile for the isolated aegis-peer test namespace.
[Interface]
PrivateKey = $(cat "$DIR/client.key")
Address = ${CLIENT_TUN}

[Peer]
PublicKey = $(cat "$DIR/server.pub")
Endpoint = ${NS_ADDR%/*}:${PORT}
AllowedIPs = 10.99.0.0/24
PersistentKeepalive = 25
CONF
	chown "$owner" "$DIR" "$conf"
	chmod 0600 "$conf"
	echo "$conf"
}

down() {
	[[ $EUID -eq 0 ]] || die "run with sudo"
	ip netns del "$NS" 2>/dev/null || true # also removes the veth pair
	ip link del "$HOST_IF" 2>/dev/null || true
	rm -rf "$DIR"
	echo "removed namespace $NS and $DIR"
}

status() {
	ip netns exec "$NS" wg show wg0 2>/dev/null || echo "namespace $NS not running"
}

case "${1:-}" in
up) up ;;
down) down ;;
status) status ;;
*) die "usage: $0 up|down|status" ;;
esac
