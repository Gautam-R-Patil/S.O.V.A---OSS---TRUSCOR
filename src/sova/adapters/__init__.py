# SPDX-License-Identifier: Apache-2.0
"""Optional capture adapters that never become SOVA's trust root."""

from sova.adapters.codex_exec import CodexExecAdapter, CodexRunResult
from sova.adapters.security_catalog import (
    get_security_adapter,
    promoted_security_adapters,
    security_adapter_catalog,
)
from sova.adapters.security_contracts import (
    AdapterAdmission,
    AdapterDescriptor,
    AdapterInvocation,
    AdapterRunReport,
    ExternalTransferDecision,
    ExternalTransferGate,
    ExternalTransferRequest,
    NormalizedObservation,
    ObservationState,
)
from sova.adapters.security_runner import (
    AdapterExecutionProposal,
    build_security_adapter_proposal,
    run_security_adapter,
)

__all__ = [
    "AdapterAdmission",
    "AdapterDescriptor",
    "AdapterExecutionProposal",
    "AdapterInvocation",
    "AdapterRunReport",
    "CodexExecAdapter",
    "CodexRunResult",
    "ExternalTransferDecision",
    "ExternalTransferGate",
    "ExternalTransferRequest",
    "NormalizedObservation",
    "ObservationState",
    "build_security_adapter_proposal",
    "get_security_adapter",
    "promoted_security_adapters",
    "run_security_adapter",
    "security_adapter_catalog",
]
