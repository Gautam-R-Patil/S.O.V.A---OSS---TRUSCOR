# SPDX-License-Identifier: Apache-2.0
"""Calibrated oracle, fresh-reproduction, and coverage accounting contracts."""

from sova.oracle_lab.calibration import calibrate_oracle, score_blinded_study
from sova.oracle_lab.comparison import evaluate_comparison
from sova.oracle_lab.contracts import (
    CalibrationCase,
    CalibrationPolicy,
    ComparisonAxis,
    ComparisonKind,
    ComparisonObservation,
    ComparisonRelation,
    ComparisonResult,
    CoverageDimension,
    CoverageEntry,
    CoverageState,
    DecisiveEvidenceBinding,
    EvidenceRole,
    FreshReproduction,
    OracleCalibration,
    OracleDisposition,
    OracleProposal,
    OracleSource,
    OracleVerdict,
    ReproductionState,
)
from sova.oracle_lab.coverage import build_coverage_report
from sova.oracle_lab.evidence import bind_decisive_evidence
from sova.oracle_lab.io import (
    calibration_from_mapping,
    proposal_from_mapping,
    read_oracle_lab_artifact,
    validate_oracle_lab_artifact,
)
from sova.oracle_lab.proposal import ProposalSeed, derive_oracle_proposals
from sova.oracle_lab.reproduction import assess_fresh_reproduction
from sova.oracle_lab.study import (
    bind_answer_key_to_predictions,
    build_seeded_blinded_study,
    predict_blinded_study,
)

__all__ = [
    "CalibrationCase",
    "CalibrationPolicy",
    "ComparisonAxis",
    "ComparisonKind",
    "ComparisonObservation",
    "ComparisonRelation",
    "ComparisonResult",
    "CoverageDimension",
    "CoverageEntry",
    "CoverageState",
    "DecisiveEvidenceBinding",
    "EvidenceRole",
    "FreshReproduction",
    "OracleCalibration",
    "OracleDisposition",
    "OracleProposal",
    "OracleSource",
    "OracleVerdict",
    "ProposalSeed",
    "ReproductionState",
    "assess_fresh_reproduction",
    "bind_answer_key_to_predictions",
    "bind_decisive_evidence",
    "build_coverage_report",
    "build_seeded_blinded_study",
    "calibrate_oracle",
    "calibration_from_mapping",
    "derive_oracle_proposals",
    "evaluate_comparison",
    "predict_blinded_study",
    "proposal_from_mapping",
    "read_oracle_lab_artifact",
    "score_blinded_study",
    "validate_oracle_lab_artifact",
]
