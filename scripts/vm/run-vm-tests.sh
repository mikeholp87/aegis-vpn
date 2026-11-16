#!/usr/bin/env bash
# Disposable QEMU/KVM VM for Aegis VPN tests that change routing and DNS
# (full tunnel, DNS/IPv6 leaks, reconnect, NetworkManager restart).
#
#   scripts/vm/run-vm-tests.sh            # run the suite (full + full4)
#   KEEP_VM=1 scripts/vm/run-vm-tests.sh  # leave the VM running afterwards for debugging
#
# Runs entirely as your normal user: needs /dev/kvm access, no root. The host
# network is untouched (QEMU user-mode networking), and the VM disk is opened
# with -snapshot so every run starts from the verified pristine image.
#
# Requires: qemu-system-x86_64, ssh, ssh-keygen, scp, python3, curl,
# sha512sum, genisoimage (or mkisofs), cargo with the x86_64-unknown-linux-musl target.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/aegis-vpn/vm"
IMG_NAME=debian-13-genericcloud-amd64.qcow2
IMG_BASE=https://cloud.debian.org/images/cloud/trixie/latest
IMG="$CACHE/$IMG_NAME"
MODES=(full full4)

die() {
	echo "error: $*" >&2
	exit 1
}
log() { echo "[vm] $*" >&2; }

for t in qemu-system-x86_64 ssh ssh-keygen scp python3 curl sha512sum cargo; do
	command -v "$t" >/dev/null || die "$t is required"
done
MKISO="$(command -v genisoimage || command -v mkisofs || true)"
[[ -n $MKISO ]] || die "genisoimage or mkisofs is required"
[[ -w /dev/kvm ]] || die "no write access to /dev/kvm (add yourself to the kvm group)"
[[ $EUID -ne 0 ]] || die "run as your normal user, not root"

# 1. Image: download once, verify against Debian's SHA512SUMS every run.
mkdir -p "$CACHE"
curl -fsSL "$IMG_BASE/SHA512SUMS" -o "$CACHE/SHA512SUMS"
want="$(awk -v n="$IMG_NAME" '$2 == n {print $1}' "$CACHE/SHA512SUMS")"
[[ -n $want ]] || die "$IMG_NAME not listed in SHA512SUMS"
if [[ ! -f $IMG ]] || [[ "$(sha512sum "$IMG" | cut -d' ' -f1)" != "$want" ]]; then
	log "downloading $IMG_NAME"
	curl -fL --progress-bar "$IMG_BASE/$IMG_NAME" -o "$IMG.part"
	mv "$IMG.part" "$IMG"
fi
[[ "$(sha512sum "$IMG" | cut -d' ' -f1)" == "$want" ]] || die "image checksum mismatch"
log "image verified (sha512 $(cut -c1-16 <<<"$want")…)"

# 2. Test binary: static musl so it runs on the VM's glibc.
log "building vm_suite (musl)"
cargo build --quiet --release --manifest-path "$ROOT/Cargo.toml" -p aegis-linux \
	--example vm_suite --target x86_64-unknown-linux-musl
SUITE="$ROOT/target/x86_64-unknown-linux-musl/release/examples/vm_suite"

# 3. Run directory, SSH key, cloud-init seed.
RUN="$(mktemp -d "${TMPDIR:-/tmp}/aegis-vm.XXXXXX")"
QEMU_PID=""
# shellcheck disable=SC2329 # invoked via trap
cleanup() {
	if [[ ${KEEP_VM:-} != 1 && -n $QEMU_PID ]]; then
		kill "$QEMU_PID" 2>/dev/null || true
	fi
	if [[ ${KEEP_VM:-} != 1 ]]; then rm -rf "$RUN"; fi
}
trap cleanup EXIT

ssh-keygen -q -t ed25519 -N '' -C aegis-test-vm -f "$RUN/id"
mkdir "$RUN/seed"
printf 'instance-id: aegis-test-%s\nlocal-hostname: aegis-test\n' "$RANDOM$RANDOM" >"$RUN/seed/meta-data"
sed "s|@SSH_PUBKEY@|$(cat "$RUN/id.pub")|" "$ROOT/scripts/vm/user-data.yaml" >"$RUN/seed/user-data"
cp "$ROOT/scripts/vm/network-config.yaml" "$RUN/seed/network-config"
# NoCloud seed disk: an ISO labelled CIDATA, read by cloud-init before networking.
"$MKISO" -quiet -output "$RUN/seed.iso" -volid CIDATA -joliet -rock \
	"$RUN/seed/user-data" "$RUN/seed/meta-data" "$RUN/seed/network-config"

free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
SSH_PORT="$(free_port)"

# 4. Boot. User-mode networking (slirp). Name BOTH ipv4=on and ipv6=on: giving
#    only one disables the other. SSH is forwarded to localhost only.
log "booting VM (console log: $RUN/console.log)"
qemu-system-x86_64 \
	-enable-kvm -cpu host -m 2048 -smp 2 \
	-drive "file=$IMG,if=virtio,format=qcow2" -snapshot \
	-netdev "user,id=n0,ipv4=on,ipv6=on,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22" \
	-device virtio-net-pci,netdev=n0 \
	-drive "file=$RUN/seed.iso,if=virtio,format=raw,readonly=on" \
	-display none -serial "file:$RUN/console.log" \
	-pidfile "$RUN/qemu.pid" -daemonize
QEMU_PID="$(cat "$RUN/qemu.pid")"

SSH=(ssh -i "$RUN/id" -p "$SSH_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
	-o LogLevel=ERROR -o ConnectTimeout=5 aegis@127.0.0.1)
log "waiting for SSH"
for _ in $(seq 1 120); do
	"${SSH[@]}" true 2>/dev/null && break
	sleep 3
done
"${SSH[@]}" true || die "VM did not come up; see $RUN/console.log"
log "waiting for cloud-init (installs NetworkManager, wireguard-tools, …)"
"${SSH[@]}" cloud-init status --wait >/dev/null || {
	"${SSH[@]}" sudo tail -n 40 /var/log/cloud-init-output.log || true
	die "cloud-init failed"
}

# 5. Copy and run.
scp -q -i "$RUN/id" -P "$SSH_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
	-o LogLevel=ERROR "$SUITE" "$ROOT/scripts/test-netns-peer.sh" aegis@127.0.0.1:
"${SSH[@]}" chmod +x vm_suite test-netns-peer.sh
# shellcheck disable=SC2016 # expands on the VM, not here
"${SSH[@]}" 'echo "VM: $(. /etc/os-release; echo $PRETTY_NAME), kernel $(uname -r), $(NetworkManager --version | sed "s/^/NetworkManager /"), $(systemctl --version | head -1)"'

status=0
for mode in "${MODES[@]}"; do
	log "suite: $mode"
	"${SSH[@]}" "./vm_suite $mode \$HOME/test-netns-peer.sh" || status=1
done

if [[ ${KEEP_VM:-} == 1 ]]; then
	log "VM left running: ${SSH[*]}   (stop: kill $QEMU_PID; files: $RUN)"
else
	"${SSH[@]}" sudo poweroff 2>/dev/null || true
fi
exit "$status"
