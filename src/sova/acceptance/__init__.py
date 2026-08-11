# SPDX-License-Identifier: Apache-2.0
"""Executable acceptance and stable-release evidence gates."""

from sova.acceptance.io import load_receipts, receipt_from_mapping
from sova.acceptance.lab import (
    AcceptanceLabArtifacts,
    acceptance_receipt_template,
    run_offline_acceptance_lab,
)
from sova.acceptance.model import (
    AcceptanceGate,
    AcceptanceReceipt,
    GateClass,
    GateResult,
    ReleaseReadinessReport,
    default_release_gates,
    evaluate_gate,
    evaluate_release_readiness,
)

__all__ = [
    "AcceptanceGate",
    "AcceptanceLabArtifacts",
    "AcceptanceReceipt",
    "GateClass",
    "GateResult",
    "ReleaseReadinessReport",
    "acceptance_receipt_template",
    "default_release_gates",
    "evaluate_gate",
    "evaluate_release_readiness",
    "load_receipts",
    "receipt_from_mapping",
    "run_offline_acceptance_lab",
]
