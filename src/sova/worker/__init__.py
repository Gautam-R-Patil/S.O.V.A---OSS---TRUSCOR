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
from sova.worker.deployment import (
    DeploymentPins,
    WorkerDeploymentPolicy,
    read_worker_deployment_policy,
)
from sova.worker.evidence import ControllerEvidencePackage, validate_and_sign_guest_evidence
from sova.worker.firecracker import (
    FirecrackerHostPolicy,
    FirecrackerLaunchPlan,
    WorkerCleanupReceipt,
    build_firecracker_launch_plan,
    validate_cleanup_receipt,
    worker_network_addresses,
)
from sova.worker.host_acceptance import (
    POSITIVE_CONTROL,
    ExactHostAcceptanceReceipt,
    ExactHostCaseResult,
    HostCaseStatus,
)
from sova.worker.host_preflight import (
    HostPreflightCheck,
    WorkerHostPreflightReceipt,
    collect_worker_host_preflight,
)
from sova.worker.identity import IdentitySlotLease, IdentitySlotLeaseTable
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
from sova.worker.network_plane import (
    FirecrackerNetworkPlan,
    FirecrackerNetworkPlaneBackend,
    NetworkCommand,
    NetworkPlaneHostPolicy,
    NetworkPlaneReceipt,
    PosixNetworkCommandBackend,
    build_firecracker_network_plan,
)
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
    "POSITIVE_CONTROL",
    "PROTOCOL_VERSION",
    "AdmittedWorkerJob",
    "AlternativeBackendAdmission",
    "ContentAddressedStore",
    "ContentReference",
    "ControllerEvidencePackage",
    "DeploymentPins",
    "ExactHostAcceptanceReceipt",
    "ExactHostCaseResult",
    "FirecrackerApiReceipt",
    "FirecrackerExecutionReceipt",
    "FirecrackerHostPolicy",
    "FirecrackerLaunchPlan",
    "FirecrackerLifecycleBackend",
    "FirecrackerLifecycleResult",
    "FirecrackerLifecycleRunner",
    "FirecrackerNetworkPlan",
    "FirecrackerNetworkPlaneBackend",
    "FirecrackerUnixApiClient",
    "HostCaseStatus",
    "HostPreflightCheck",
    "IdentitySlotLease",
    "IdentitySlotLeaseTable",
    "KataAdmissionEvidence",
    "MaliciousGuestCase",
    "NetworkBroker",
    "NetworkCommand",
    "NetworkFlowReceipt",
    "NetworkPlaneHostPolicy",
    "NetworkPlaneReceipt",
    "NetworkRule",
    "PosixFirecrackerBackend",
    "PosixNetworkCommandBackend",
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
    "WorkerDeploymentPolicy",
    "WorkerHostPreflightReceipt",
    "WorkerJobManifest",
    "WorkerJobState",
    "WorkerReadiness",
    "assess_gvisor_backend",
    "assess_kata_backend",
    "assess_worker_attestation",
    "build_firecracker_launch_plan",
    "build_firecracker_network_plan",
    "collect_worker_host_preflight",
    "job_manifest_from_mapping",
    "malicious_guest_matrix",
    "read_worker_deployment_policy",
    "read_worker_job_manifest",
    "sign_protocol_message",
    "validate_and_sign_guest_evidence",
    "validate_cleanup_receipt",
    "verify_protocol_message",
    "worker_network_addresses",
]
