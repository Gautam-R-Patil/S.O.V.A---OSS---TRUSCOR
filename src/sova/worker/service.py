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
from sova.worker.io import read_worker_job_manifest
from sova.worker.lifecycle import FirecrackerLifecycleRunner
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
    from sova.worker.lifecycle import FirecrackerLifecycleBackend, FirecrackerLifecycleResult


@dataclass(frozen=True, slots=True)
class AdmittedWorkerJob:
    message: ProtocolMessage
    manifest: WorkerJobManifest
    launch_plan: FirecrackerLaunchPlan

    def to_mapping(self) -> dict[str, Any]:
        return {
            "messageDigest": self.message.to_mapping()["contentDigest"],
            "manifestDigest": self.manifest.digest,
            "launchPlanDigest": self.launch_plan.to_mapping()["contentDigest"],
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
        return AdmittedWorkerJob(message, manifest, plan)

    def execute_admitted_job(
        self,
        admitted: AdmittedWorkerJob,
        *,
        backend: FirecrackerLifecycleBackend,
        secret_broker: SecretBroker,
    ) -> FirecrackerLifecycleResult:
        """Run only the exact plan this service can independently reconstruct."""
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

        def revoke() -> bool:
            secret_broker.revoke_all()
            return True

        return FirecrackerLifecycleRunner(backend).run(
            admitted.launch_plan,
            revoke_secrets=revoke,
        )


__all__ = ["AdmittedWorkerJob", "WorkerAdmissionService"]
