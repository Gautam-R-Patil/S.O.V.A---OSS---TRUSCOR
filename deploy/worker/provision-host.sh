#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Reviewable minimum host scaffold. It never downloads binaries, images, or secrets.

set -eu

MODE=check
ACK=no
for argument in "$@"; do
    case "$argument" in
        --check) MODE=check ;;
        --apply) MODE=apply ;;
        --ack-dedicated-host) ACK=yes ;;
        *) echo "unknown argument: $argument" >&2; exit 64 ;;
    esac
done

if [ "$(uname -s)" != Linux ]; then
    echo "SOVA workers require Linux" >&2
    exit 1
fi

if [ "$MODE" = apply ]; then
    if [ "$ACK" != yes ]; then
        echo "--apply also requires --ack-dedicated-host" >&2
        exit 64
    fi
    if [ "$(id -u)" -ne 0 ]; then
        echo "--apply requires root" >&2
        exit 1
    fi
    install -d -o root -g root -m 0755 /usr/local/lib/sova-worker
    install -d -o root -g root -m 0700 /srv/sova-worker/cas
    install -d -o root -g root -m 0700 /srv/sova-worker/jailer
    # Search-only access is required because the mediator drops privilege before
    # opening its immutable per-job policy. The directory cannot be listed or written.
    install -d -o root -g root -m 0711 /run/sova-worker/network
    install -d -o root -g root -m 0700 /run/sova-worker/leases
    echo "created only root-controlled SOVA directories"
    echo "per-job numeric VMM and mediator identities are compiled from reserved ranges"
    echo "no binary, image, firewall, kernel, KVM, swap, or sysctl state was changed"
fi

FAILED=0
check() {
    if "$@"; then
        echo "PASS $*"
    else
        echo "FAIL $*"
        FAILED=1
    fi
}

check test -c /dev/kvm
check test -r /dev/kvm
check test -w /dev/kvm
check test -f /sys/fs/cgroup/cgroup.controllers
check sh -c '[ "$(awk "NR>1 && NF {count++} END {print count+0}" /proc/swaps)" -eq 0 ]'
check sh -c '[ "$(cat /proc/sys/net/ipv4/ip_forward)" = 1 ]'
check command -v ip
check command -v nft
check command -v setpriv
check test -x /usr/local/lib/sova-worker/firecracker
check test -x /usr/local/lib/sova-worker/jailer
check test -x /usr/local/lib/sova-worker/sova-network-mediator
check test -d /srv/sova-worker/cas
check test -d /srv/sova-worker/jailer
check test -d /run/sova-worker/network
check test -d /run/sova-worker/leases

if [ "$FAILED" -ne 0 ]; then
    echo "host scaffold is incomplete; do not run hostile jobs" >&2
    exit 1
fi

echo "scaffold checks passed; run scripts/check_worker_host.py with a configured policy next"
echo "this result is not a live matrix, independent review, or production-isolation receipt"
