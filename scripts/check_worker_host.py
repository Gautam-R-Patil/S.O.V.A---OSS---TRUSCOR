# SPDX-License-Identifier: Apache-2.0
"""Measure a configured dedicated worker without changing the host."""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from sova.formats import canonical_json_bytes, validate_document
from sova.formats.errors import FormatError
from sova.worker.attestation import collect_worker_attestation
from sova.worker.deployment import read_worker_deployment_policy
from sova.worker.host_preflight import collect_worker_host_preflight

if TYPE_CHECKING:
    from sova.worker.contracts import WorkerAttestation
    from sova.worker.deployment import WorkerDeploymentPolicy


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Check an exact Linux/KVM worker policy; this command never provisions the host."
        )
    )
    parser.add_argument("policy", type=Path)
    parser.add_argument("--release-commit", required=True)
    return parser


def _verify_pins(attestation: WorkerAttestation, policy: WorkerDeploymentPolicy) -> None:
    expected = policy.pins
    if (
        attestation.host_kernel_digest != expected.host_kernel_digest
        or attestation.microcode_digest != expected.microcode_digest
        or attestation.guest_kernel_digest != expected.guest_kernel_digest
        or attestation.root_filesystem_digest != expected.root_filesystem_digest
        or attestation.advisory_snapshot_digest != expected.advisory_snapshot_digest
        or attestation.policy_digest != policy.source_digest
    ):
        raise FormatError(
            "SOVA-WORKER-DEPLOY-PIN", "measured image, policy, or advisory digest drifted"
        )


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        raw = args.policy.read_bytes()
        policy = read_worker_deployment_policy(raw)
        advisory = policy.advisory_snapshot.read_bytes()
        measured_at = datetime.now(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
        attestation = collect_worker_attestation(
            worker_id=policy.worker_id,
            measured_at=measured_at,
            policy=policy.firecracker,
            host_kernel_image=policy.host_kernel_image,
            microcode_image=policy.microcode_image,
            guest_kernel_image=policy.guest_kernel_image,
            root_filesystem_image=policy.root_filesystem_image,
            worker_policy_bytes=raw,
            advisory_snapshot_bytes=advisory,
            dedicated_linux_host=True,
            default_seccomp_enforced=True,
            unique_uid_gid_enforced=True,
        )
        _verify_pins(attestation, policy)
        preflight = collect_worker_host_preflight(
            release_commit=args.release_commit,
            measured_at=measured_at,
            attestation=attestation,
            firecracker_policy=policy.firecracker,
            network_policy=policy.network,
            identity_lease_directory=policy.identity_lease_directory,
        )
        attestation_mapping = attestation.to_mapping()
        preflight_mapping = preflight.to_mapping()
        validate_document(attestation_mapping)
        validate_document(preflight_mapping)
        output = {
            "artifactType": "sova.worker-host-check-bundle",
            "schemaVersion": "0.1.0",
            "attestation": attestation_mapping,
            "preflight": preflight_mapping,
            "status": preflight_mapping["status"],
            "claims": {
                "hostChanged": False,
                "liveFirecrackerExecuted": False,
                "productionIsolationClaimAllowed": False,
            },
        }
    except (FormatError, OSError) as error:
        sys.stderr.write(f"worker host check failed: {error}\n")
        return 2
    sys.stdout.buffer.write(canonical_json_bytes(output) + b"\n")
    return 0 if preflight.ready_for_live_matrix else 1


if __name__ == "__main__":
    raise SystemExit(main())
