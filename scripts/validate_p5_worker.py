# SPDX-License-Identifier: Apache-2.0
"""Emit a deterministic P5 controller/worker implementation receipt."""

from __future__ import annotations

import sys
import tempfile
import zipfile
from dataclasses import replace
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sova.formats import canonical_json_bytes, sha256_digest, validate_document
from sova.trace.integrity import Ed25519Keypair, sign_dsse_payload
from sova.worker.alternative_backends import (
    KataAdmissionEvidence,
    assess_gvisor_backend,
    assess_kata_backend,
)
from sova.worker.brokers import NetworkBroker, NetworkFlowReceipt, SecretBroker
from sova.worker.cas import ContentAddressedStore
from sova.worker.contracts import (
    FIRECRACKER_VERSION,
    ContentReference,
    NetworkRule,
    ResourceLimits,
    SecretGrant,
    WorkerAttestation,
    WorkerBackend,
    WorkerJobManifest,
    assess_worker_attestation,
)
from sova.worker.evidence import GUEST_OUTPUT_MEDIA_TYPE, validate_and_sign_guest_evidence
from sova.worker.firecracker import (
    FirecrackerHostPolicy,
    FirecrackerLaunchPlan,
    WorkerCleanupReceipt,
)
from sova.worker.lifecycle import FirecrackerLifecycleRunner
from sova.worker.malicious import malicious_guest_matrix
from sova.worker.protocol import (
    ProtocolMessage,
    ProtocolMessageType,
    ProtocolRole,
    certificate_digest,
    sign_protocol_message,
)
from sova.worker.service import WorkerAdmissionService


class _AcceptanceLifecycleBackend:
    """Deterministic non-live backend for exercising the lifecycle state machine."""

    live_execution = False

    def prepare(self, _plan: FirecrackerLaunchPlan) -> None:
        return None

    def launch(self, _plan: FirecrackerLaunchPlan) -> int:
        return 0

    def wait_for_api_socket(self, _plan: FirecrackerLaunchPlan, _timeout: float) -> bool:
        return True

    def read_process_id(self, _plan: FirecrackerLaunchPlan) -> int:
        return 4242

    def wait_for_process_id(self, _plan: FirecrackerLaunchPlan, _timeout: float) -> int:
        return 4242

    def put_api(
        self,
        _plan: FirecrackerLaunchPlan,
        _path: str,
        _payload: dict[str, Any],
    ) -> int:
        return 204

    def wait_for_process(self, _process_id: int, _timeout: float) -> int:
        return 0

    def terminate_process(self, _process_id: int) -> bool:
        return True

    def cleanup(
        self,
        plan: FirecrackerLaunchPlan,
        *,
        completed_at: str,
        secret_broker_revoked: bool,
    ) -> WorkerCleanupReceipt:
        return WorkerCleanupReceipt(
            job_id=plan.job_id,
            vm_id=plan.vm_id,
            completed_at=completed_at,
            process_terminated=True,
            api_socket_removed=True,
            cgroup_removed=True,
            network_namespace_removed=True,
            chroot_removed=True,
            writable_layer_removed=True,
            secret_broker_revoked=secret_broker_revoked,
        )


def _digest(value: str) -> str:
    return sha256_digest(value.encode("utf-8"))


def _keypair(label: str) -> Ed25519Keypair:
    private_bytes = bytes.fromhex(_digest(label)[7:])
    private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return Ed25519Keypair(private_bytes, public_bytes, sha256_digest(public_bytes))


def _base_manifest(guest_key_digest: str) -> WorkerJobManifest:
    return WorkerJobManifest(
        job_id="job:p5-acceptance",
        issued_at="2026-08-27T10:00:00Z",
        expires_at="2026-08-27T10:15:00Z",
        target_profile_digest=_digest("target"),
        authorization_decision_digest=_digest("authority"),
        methodology_plan_digest=_digest("methodology"),
        guest_output_key_digest=guest_key_digest,
        guest_kernel=ContentReference(
            "guest-kernel", _digest("kernel"), 6, "application/octet-stream"
        ),
        root_filesystem=ContentReference(
            "root-filesystem", _digest("rootfs"), 6, "application/octet-stream"
        ),
        writable_layer_seed=ContentReference(
            "writable-seed", _digest("writable"), 8, "application/octet-stream"
        ),
        inputs=(ContentReference("target-input", _digest("input"), 5, "application/zip"),),
        network_rules=(NetworkRule("example.com", 443, "tcp", ("1.1.1.1",)),),
        secret_grants=(SecretGrant("target-api", "https://example.com", "2026-08-27T10:10:00Z"),),
        output_schema_ids=("sova.worker-network-receipt",),
        limits=ResourceLimits(
            timeout_seconds=600,
            output_bytes=1024 * 1024,
            network_connection_limit=2,
            network_bytes=4096,
        ),
    )


def _attestation() -> WorkerAttestation:
    return WorkerAttestation(
        worker_id="worker:p5-acceptance",
        measured_at="2026-08-27T09:55:00Z",
        backend=WorkerBackend.FIRECRACKER,
        dedicated_linux_host=False,
        wsl_environment=True,
        kvm_available=True,
        cgroup_v2=True,
        swap_disabled=True,
        default_seccomp=True,
        unique_uid_gid_per_job=True,
        host_paths_root_owned=True,
        firecracker_version=FIRECRACKER_VERSION,
        firecracker_digest=_digest("firecracker"),
        jailer_digest=_digest("jailer"),
        host_kernel_digest=_digest("host-kernel"),
        microcode_digest=_digest("microcode"),
        guest_kernel_digest=_digest("kernel"),
        root_filesystem_digest=_digest("rootfs"),
        policy_digest=_digest("policy"),
        advisory_snapshot_digest=_digest("advisories"),
    )


def _guest_bundle(guest_key: Ed25519Keypair, receipt: NetworkFlowReceipt) -> bytes:
    raw = canonical_json_bytes(receipt.to_mapping())
    manifest = {
        "artifactType": "sova.worker-guest-output-manifest",
        "schemaVersion": "0.1.0",
        "jobId": "job:p5-acceptance",
        "artifacts": [
            {
                "name": "artifacts/network.json",
                "digest": sha256_digest(raw),
                "size": len(raw),
                "mediaType": "application/json",
                "schemaId": "sova.worker-network-receipt",
            }
        ],
    }
    manifest["contentDigest"] = sha256_digest(canonical_json_bytes(manifest))
    envelope = sign_dsse_payload(
        GUEST_OUTPUT_MEDIA_TYPE,
        canonical_json_bytes(manifest),
        guest_key,
    )
    stream = BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in (
            ("manifest.json", canonical_json_bytes(manifest)),
            ("manifest.dsse.json", canonical_json_bytes(envelope)),
            ("artifacts/network.json", raw),
        ):
            member = zipfile.ZipInfo(name, date_time=(2026, 8, 27, 10, 1, 0))
            member.compress_type = zipfile.ZIP_DEFLATED
            member.create_system = 3
            member.external_attr = 0o100644 << 16
            archive.writestr(member, payload)
    return stream.getvalue()


def main() -> int:
    guest = _keypair("p5-acceptance-guest-key")
    controller = _keypair("p5-acceptance-controller-key")
    now = datetime(2026, 8, 27, 10, 1, tzinfo=UTC)
    with tempfile.TemporaryDirectory(prefix="sova-p5-") as temporary:
        root = Path(temporary).resolve()
        store = ContentAddressedStore(root / "cas")
        manifest = replace(
            _base_manifest(sha256_digest(guest.public_key)),
            guest_kernel=store.put(
                name="guest-kernel", media_type="application/octet-stream", data=b"kernel"
            ),
            root_filesystem=store.put(
                name="root-filesystem", media_type="application/octet-stream", data=b"rootfs"
            ),
            writable_layer_seed=store.put(
                name="writable-seed", media_type="application/octet-stream", data=b"writable"
            ),
            inputs=(store.put(name="target-input", media_type="application/zip", data=b"input"),),
        )
        raw_manifest = canonical_json_bytes(manifest.to_mapping())
        validate_document(manifest.to_mapping())
        peer_certificate = b"p5-controller-certificate-der"
        message = ProtocolMessage(
            message_type=ProtocolMessageType.SUBMIT_JOB,
            message_id="message:p5-acceptance",
            job_id=manifest.job_id,
            sender_role=ProtocolRole.CONTROLLER,
            sender_id="controller:p5-acceptance",
            recipient_id="worker:p5-acceptance",
            issued_at="2026-08-27T10:00:00Z",
            expires_at="2026-08-27T10:02:00Z",
            nonce="ABCDEFGHIJKLMNOPQRSTUV",
            sender_certificate_digest=certificate_digest(peer_certificate),
            payload_digest=sha256_digest(raw_manifest),
        )
        admission = assess_worker_attestation(
            _attestation(),
            expected_policy_digest=_digest("policy"),
            expected_guest_kernel_digest=_digest("kernel"),
            expected_root_filesystem_digest=_digest("rootfs"),
        )
        service = WorkerAdmissionService(
            worker_id="worker:p5-acceptance",
            controller_id="controller:p5-acceptance",
            controller_public_key=controller.public_key,
            content_store=store,
            host_policy=FirecrackerHostPolicy(
                firecracker_binary=root / "bin" / "firecracker",
                jailer_binary=root / "bin" / "jailer",
                chroot_base=root / "jailer",
                network_namespace_base=root / "netns",
                content_store=store.root,
                cgroup_base=root / "cgroup",
                approved_firecracker_digest=_digest("firecracker"),
                approved_jailer_digest=_digest("jailer"),
            ),
            worker_admission=admission,
            allow_nonproduction=True,
        )
        accepted = service.admit_signed_job(
            envelope=sign_protocol_message(message, controller),
            peer_certificate_der=peer_certificate,
            raw_manifest=raw_manifest,
            now=now,
            identity_slot=7,
        )
        validate_document(accepted.launch_plan.to_mapping())
        network = NetworkBroker(manifest)
        allowed_flow = network.authorize(
            hostname="example.com",
            port=443,
            protocol="tcp",
            resolved_addresses=("1.1.1.1",),
            selected_address="1.1.1.1",
            requested_bytes=100,
            now=now,
        )
        denied_rebind = network.authorize(
            hostname="example.com",
            port=443,
            protocol="tcp",
            resolved_addresses=("1.1.1.1", "169.254.169.254"),
            selected_address="169.254.169.254",
            requested_bytes=1,
            now=now,
        )
        secret = SecretBroker(manifest)
        token = secret.provision("target-api", b"acceptance-secret", now=now)
        denied_secret, denied_secret_receipt = secret.redeem(token, audience="wrong", now=now)
        allowed_secret, allowed_secret_receipt = secret.redeem(
            token, audience="https://example.com", now=now
        )
        evidence = validate_and_sign_guest_evidence(
            _guest_bundle(guest, allowed_flow),
            manifest,
            guest.public_key,
            controller,
            redaction_values=(b"acceptance-secret",),
        )
        validate_document(evidence.report)

        def revoke_secrets() -> bool:
            secret.revoke_all()
            return True

        lifecycle = FirecrackerLifecycleRunner(
            _AcceptanceLifecycleBackend(),
            clock=lambda: datetime(2026, 8, 27, 10, 12, tzinfo=UTC),
        ).run(accepted.launch_plan, revoke_secrets=revoke_secrets)
        cleanup = lifecycle.cleanup
        validate_document(lifecycle.execution.to_mapping())
        validate_document(cleanup.to_mapping())
    kata = assess_kata_backend(
        KataAdmissionEvidence(
            installed_version=None,
            approved_version="unselected",
            runtime_digest_pinned=False,
            advisory_snapshot_current=True,
            unresolved_escape_advisories=("current-advisory-review-required",),
            untrusted_annotations_disabled=False,
            host_mounts_disabled=False,
            configuration_paths_root_owned=False,
        )
    )
    gvisor = assess_gvisor_backend(installed=False, conformance_passed=False)
    local_pass = all(
        (
            admission.readiness.value == "developer-only",
            allowed_flow.decision == "allowed",
            denied_rebind.decision == "denied",
            denied_secret is None,
            denied_secret_receipt.decision == "denied",
            allowed_secret == b"acceptance-secret",
            allowed_secret_receipt.decision == "allowed",
            cleanup.complete,
            lifecycle.execution.execution_status == "process-exited",
            lifecycle.execution.execution_mode == "simulated",
            kata.status == "disabled",
            gvisor.status == "disabled",
        )
    )
    receipt = {
        "artifactType": "sova.p5-acceptance-receipt",
        "schemaVersion": "0.1.0",
        "localImplementationAcceptancePassed": local_pass,
        "p5ExitGatePassed": False,
        "controls": {
            "P5-01": "dedicated-linux-worker-required",
            "P5-02": "locally-passed",
            "P5-03": "launch-contract-passed-live-worker-required",
            "P5-04": "locally-passed",
            "P5-05": "locally-passed",
            "P5-06": "locally-passed",
            "P5-07": "disabled-by-default-policy-passed",
            "P5-08": "lower-assurance-policy-passed",
            "P5-09": "local-adverse-matrix-passed-exact-host-cases-required",
            "P5-10": "independent-review-and-exact-host-tests-required",
        },
        "workerReadiness": admission.readiness.value,
        "firecrackerVersionPin": FIRECRACKER_VERSION,
        "launchPlanValidated": True,
        "launchPlanFirecrackerVersion": accepted.launch_plan.firecracker_version,
        "evidenceReportDigest": evidence.report["contentDigest"],
        "cleanupReceiptDigest": cleanup.to_mapping()["contentDigest"],
        "lifecycleStateMachinePassed": lifecycle.execution.execution_status == "process-exited",
        "maliciousGuestMatrix": [item.to_mapping() for item in malicious_guest_matrix()],
        "claims": {
            "productionIsolationClaimAllowed": False,
            "liveFirecrackerExecuted": False,
            "exactHostContainmentTested": False,
            "independentlyReviewed": False,
            "escapeImpossible": False,
        },
    }
    receipt["contentDigest"] = sha256_digest(canonical_json_bytes(receipt))
    sys.stdout.buffer.write(canonical_json_bytes(receipt) + b"\n")
    return 0 if local_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
