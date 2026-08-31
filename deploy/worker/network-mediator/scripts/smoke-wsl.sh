#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if [[ $# -ne 2 ]]; then
  printf 'usage: %s REPOSITORY_ROOT OUTPUT_DIRECTORY\n' "$0" >&2
  exit 2
fi

repository_root=$1
output_directory=$2
binary="$repository_root/deploy/worker/network-mediator/target/x86_64-unknown-linux-musl/release/sova-network-mediator"
fixture="$repository_root/tests/fixtures/worker/network-mediator-policy-python.json"

if [[ ! -x "$binary" || ! -f "$fixture" || ! -d "$output_directory" ]]; then
  printf 'binary, policy fixture, or output directory is unavailable\n' >&2
  exit 2
fi

work_directory=$(mktemp -d /tmp/sova-mediator-smoke.XXXXXX)
mediator_pid=

cleanup() {
  if [[ -n "$mediator_pid" ]]; then
    kill "$mediator_pid" 2>/dev/null || true
    wait "$mediator_pid" 2>/dev/null || true
  fi
  if [[ "$work_directory" == /tmp/sova-mediator-smoke.* ]]; then
    rm -f "$work_directory/receipts/000001.json" "$work_directory/policy.json"
    rmdir "$work_directory/receipts" 2>/dev/null || true
    rmdir "$work_directory" 2>/dev/null || true
  fi
}
trap cleanup EXIT

cp "$fixture" "$work_directory/policy.json"
last_byte=$(tail -c 1 "$work_directory/policy.json" | od -An -tuC | tr -d '[:space:]')
if [[ "$last_byte" != 10 ]]; then
  printf 'policy fixture must end in exactly one newline\n' >&2
  exit 2
fi
truncate -s -1 "$work_directory/policy.json"
mkdir "$work_directory/receipts"

"$binary" \
  --policy-file "$work_directory/policy.json" \
  --listen 127.0.0.1:8888 \
  --receipt-directory "$work_directory/receipts" &
mediator_pid=$!

for _attempt in {1..50}; do
  curl \
    --silent \
    --show-error \
    --max-time 1 \
    --proxy http://127.0.0.1:8888 \
    http://example.com/ >/dev/null 2>&1 || true
  if [[ -f "$work_directory/receipts/000001.json" ]]; then
    break
  fi
  sleep 0.1
done

if [[ ! -f "$work_directory/receipts/000001.json" ]]; then
  printf 'mediator did not emit the expected denied-flow receipt\n' >&2
  exit 1
fi

kill "$mediator_pid"
wait "$mediator_pid" 2>/dev/null || true
mediator_pid=

cp "$work_directory/receipts/000001.json" "$output_directory/receipt.json"
printf 'binary=' && file "$binary"
printf 'receipt-bytes=' && wc -c < "$work_directory/receipts/000001.json"
printf 'receipt-sha256=' && sha256sum "$work_directory/receipts/000001.json" | cut -d' ' -f1
