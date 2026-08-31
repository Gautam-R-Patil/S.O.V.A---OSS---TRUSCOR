# SPDX-License-Identifier: Apache-2.0
"""Worker-side admission from authenticated controller message to immutable launch plan."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from sova.formats import sha256_digest
from sova.formats.errors import FormatError
from sova.worker.contracts import WorkerReadiness
from sova.worker.firecracker import (
    build_firecracker_launch_plan,
)
from sova.worker.identity import IdentitySlotLease
from sova.worker.io import read_worker_job_manifest
from sova.worker.lifecycle import FirecrackerLifecycleRunner
from sova.worker.network_plane import build_firecracker_network_plan
from sova.worker.protocol import (
    ProtocolMessage,
    ProtocolMessageType,
    ProtocolRole,
    ReplayCache,
    verify_protocol_message,
)

if TYPE_CHECKING:
    from datetime import datetime

    from sova.worker.brokers import SecretBroker
    from sova.worker.cas import ContentAddressedStore
    from sova.worker.contracts import WorkerAdmission, WorkerJobManifest
    from sova.worker.firecracker import FirecrackerHostPolicy, FirecrackerLaunchPlan
    from sova.worker.identity import IdentitySlotLeaseTable
    from sova.worker.lifecycle import FirecrackerLifecycleBackend, FirecrackerLifecycleResult
    from sova.worker.network_plane import FirecrackerNetworkPlan, NetworkPlaneHostPolicy


@dataclass(frozen=True, slots=True)
class AdmittedWorkerJob:
    message: ProtocolMessage
    manifest: WorkerJobManifest
    launch_plan: FirecrackerLaunchPlan
    network_plan: FirecrackerNetworkPlan | None = None

    def to_mapping(self) -> dict[str, Any]:
        return {
            "messageDigest": self.message.to_mapping()["contentDigest"],
            "manifestDigest": self.manifest.digest,
            "launchPlanDigest": self.launch_plan.to_mapping()["contentDigest"],
            "networkPlanDigest": (
                None
                if self.network_plan is None
                else self.network_plan.to_mapping()["contentDigest"]
            ),
            "status": "admitted",
            "productionIsolationClaimAllowed": False,
        }


@dataclass(slots=True)
class WorkerAdmissionService:
    """Fail closed before any jailer process receives untrusted job material."""

    worker_id: str
    controller_id: str
    controller_public_key: bytes
    content_store: ContentAddressedStore
    host_policy: FirecrackerHostPolicy
    worker_admission: WorkerAdmission
    network_policy: NetworkPlaneHostPolicy | None = None
    identity_leases: IdentitySlotLeaseTable | None = None
    allow_nonproduction: bool = False
    replay_cache: ReplayCache = field(default_factory=ReplayCache)

    def __post_init__(self) -> None:
        if self.host_policy.content_store.resolve() != self.content_store.root:
            raise FormatError(
                "SOVA-WORKER-SERVICE-CAS",
                "admission service and host policy must bind the same content store",
            )

    def admit_signed_job(
        self,
        *,
        envelope: dict[str, Any],
        peer_certificate_der: bytes,
        raw_manifest: bytes,
        now: datetime,
        identity_slot: int,
    ) -> AdmittedWorkerJob:
        message = verify_protocol_message(
            envelope,
            self.controller_public_key,
            expected_sender_role=ProtocolRole.CONTROLLER,
            expected_sender_id=self.controller_id,
            expected_recipient_id=self.worker_id,
            peer_certificate_der=peer_certificate_der,
            now=now,
            replay_cache=self.replay_cache,
        )
        if message.message_type != ProtocolMessageType.SUBMIT_JOB:
            raise FormatError("SOVA-WORKER-SERVICE-MESSAGE", "message is not a job submission")
        if message.payload_digest != sha256_digest(raw_manifest):
            raise FormatError(
                "SOVA-WORKER-SERVICE-PAYLOAD", "transport payload digest does not match manifest"
            )
        manifest = read_worker_job_manifest(raw_manifest)
        if manifest.job_id != message.job_id:
            raise FormatError("SOVA-WORKER-SERVICE-JOB", "protocol message and manifest job differ")
        if (
            self.worker_admission.readiness != WorkerReadiness.PRODUCTION_READY
            and not self.allow_nonproduction
        ):
            raise FormatError(
                "SOVA-WORKER-SERVICE-READINESS",
                "worker lacks production admission; explicit development mode is required",
            )
        references = (
            manifest.guest_kernel,
            manifest.root_filesystem,
            manifest.writable_layer_seed,
            *manifest.inputs,
        )
        for reference in references:
            self.content_store.verify(reference)
        plan = build_firecracker_launch_plan(
            manifest,
            self.worker_admission,
            self.host_policy,
            identity_slot=identity_slot,
        )
        network_plan = (
            None
            if self.network_policy is None
            else build_firecracker_network_plan(manifest, plan, self.network_policy)
        )
        return AdmittedWorkerJob(message, manifest, plan, network_plan)

    def execute_admitted_job(  # noqa: PLR0912 - admission remains one fail-closed state machine
        self,
        admitted: AdmittedWorkerJob,
        *,
        backend: FirecrackerLifecycleBackend,
        secret_broker: SecretBroker,
    ) -> FirecrackerLifecycleResult:
        """Run only the exact plan this service can independently reconstruct."""
        lease_table = self.identity_leases
        if secret_broker.manifest.digest != admitted.manifest.digest:
            raise FormatError(
                "SOVA-WORKER-SERVICE-SECRET",
                "secret broker is not bound to the admitted manifest",
            )
        expected = build_firecracker_launch_plan(
            admitted.manifest,
            self.worker_admission,
            self.host_policy,
            identity_slot=admitted.launch_plan.identity_slot,
        )
        if (
            expected.to_mapping()["contentDigest"]
            != admitted.launch_plan.to_mapping()["contentDigest"]
        ):
            raise FormatError(
                "SOVA-WORKER-SERVICE-PLAN",
                "admitted launch plan no longer matches worker policy",
            )
        expected_network = (
            None
            if self.network_policy is None
            else build_firecracker_network_plan(
                admitted.manifest,
                admitted.launch_plan,
                self.network_policy,
            )
        )
        if (expected_network is None) != (admitted.network_plan is None) or (
            expected_network is not None
            and admitted.network_plan is not None
            and expected_network.digest != admitted.network_plan.digest
        ):
            raise FormatError(
                "SOVA-WORKER-SERVICE-NETWORK",
                "admitted network plan no longer matches worker policy",
            )
        if backend.live_execution:
            if admitted.network_plan is None:
                raise FormatError(
                    "SOVA-WORKER-SERVICE-NETWORK",
                    "live execution requires the compiled network-plane boundary",
                )
            network_evidence = getattr(backend, "network_evidence", None)
            if not callable(network_evidence):
                raise FormatError(
                    "SOVA-WORKER-SERVICE-NETWORK",
                    "live backend cannot prove its network-plan binding",
                )
            observed_plan_digest, _receipt_digest = network_evidence(admitted.launch_plan)
            if observed_plan_digest != admitted.network_plan.digest:
                raise FormatError(
                    "SOVA-WORKER-SERVICE-NETWORK",
                    "live backend is bound to another network plan",
                )
            if lease_table is None:
                raise FormatError(
                    "SOVA-WORKER-SERVICE-LEASE",
                    "live execution requires a persistent identity-slot lease table",
                )

        def revoke() -> bool:
            secret_broker.revoke_all()
            return True

        lease = IdentitySlotLease(
            admitted.launch_plan.identity_slot,
            admitted.manifest.job_id,
            admitted.manifest.digest,
        )
        if backend.live_execution:
            if lease_table is None:  # defensive narrowing for mutable service configuration
                raise FormatError("SOVA-WORKER-SERVICE-LEASE", "identity lease table vanished")
            lease_table.acquire(lease)
        result = FirecrackerLifecycleRunner(backend).run(
            admitted.launch_plan,
            revoke_secrets=revoke,
        )
        if backend.live_execution and (
            admitted.network_plan is None
            or result.execution.network_plan_digest != admitted.network_plan.digest
            or result.execution.network_receipt_digest is None
            or result.network is None
            or not result.network.complete
        ):
            raise FormatError(
                "SOVA-WORKER-SERVICE-NETWORK",
                "live execution did not emit its admitted network-plane receipt",
            )
        if backend.live_execution:
            if lease_table is None:  # defensive narrowing for mutable service configuration
                raise FormatError("SOVA-WORKER-SERVICE-LEASE", "identity lease table vanished")
            if not lease_table.release(lease, cleanup_complete=result.cleanup.complete):
                raise FormatError(
                    "SOVA-WORKER-SERVICE-LEASE",
                    "identity slot remains leased because cleanup is incomplete",
                )
        return result


__all__ = ["AdmittedWorkerJob", "WorkerAdmissionService"]
