# SPDX-License-Identifier: Apache-2.0
"""Controller/worker isolation contracts and policy-enforcing helpers."""

from sova.worker.alternative_backends import (
    AlternativeBackendAdmission,
    KataAdmissionEvidence,
    assess_gvisor_backend,
    assess_kata_backend,
)
from sova.worker.brokers import NetworkBroker, NetworkFlowReceipt, SecretBroker, SecretUseReceipt
from sova.worker.cas import ContentAddressedStore
from sova.worker.contracts import (
    FIRECRACKER_VERSION,
    PROTOCOL_VERSION,
    ContentReference,
    NetworkRule,
    ResourceLimits,
    SecretGrant,
    SecretKind,
    WorkerAdmission,
    WorkerAttestation,
    WorkerBackend,
    WorkerJobManifest,
    WorkerJobState,
    WorkerReadiness,
    assess_worker_attestation,
)
from sova.worker.evidence import ControllerEvidencePackage, validate_and_sign_guest_evidence
from sova.worker.firecracker import (
    FirecrackerHostPolicy,
    FirecrackerLaunchPlan,
    WorkerCleanupReceipt,
    build_firecracker_launch_plan,
    validate_cleanup_receipt,
)
from sova.worker.io import job_manifest_from_mapping, read_worker_job_manifest
from sova.worker.lifecycle import (
    FirecrackerApiReceipt,
    FirecrackerExecutionReceipt,
    FirecrackerLifecycleBackend,
    FirecrackerLifecycleResult,
    FirecrackerLifecycleRunner,
    FirecrackerUnixApiClient,
    PosixFirecrackerBackend,
)
from sova.worker.malicious import MaliciousGuestCase, malicious_guest_matrix
from sova.worker.protocol import (
    ProtocolMessage,
    ProtocolMessageType,
    ProtocolRole,
    ReplayCache,
    sign_protocol_message,
    verify_protocol_message,
)
from sova.worker.service import AdmittedWorkerJob, WorkerAdmissionService

__all__ = [
    "FIRECRACKER_VERSION",
    "PROTOCOL_VERSION",
    "AdmittedWorkerJob",
    "AlternativeBackendAdmission",
    "ContentAddressedStore",
    "ContentReference",
    "ControllerEvidencePackage",
    "FirecrackerApiReceipt",
    "FirecrackerExecutionReceipt",
    "FirecrackerHostPolicy",
    "FirecrackerLaunchPlan",
    "FirecrackerLifecycleBackend",
    "FirecrackerLifecycleResult",
    "FirecrackerLifecycleRunner",
    "FirecrackerUnixApiClient",
    "KataAdmissionEvidence",
    "MaliciousGuestCase",
    "NetworkBroker",
    "NetworkFlowReceipt",
    "NetworkRule",
    "PosixFirecrackerBackend",
    "ProtocolMessage",
    "ProtocolMessageType",
    "ProtocolRole",
    "ReplayCache",
    "ResourceLimits",
    "SecretBroker",
    "SecretGrant",
    "SecretKind",
    "SecretUseReceipt",
    "WorkerAdmission",
    "WorkerAdmissionService",
    "WorkerAttestation",
    "WorkerBackend",
    "WorkerCleanupReceipt",
    "WorkerJobManifest",
    "WorkerJobState",
    "WorkerReadiness",
    "assess_gvisor_backend",
    "assess_kata_backend",
    "assess_worker_attestation",
    "build_firecracker_launch_plan",
    "job_manifest_from_mapping",
    "malicious_guest_matrix",
    "read_worker_job_manifest",
    "sign_protocol_message",
    "validate_and_sign_guest_evidence",
    "validate_cleanup_receipt",
    "verify_protocol_message",
]
