# SPDX-License-Identifier: Apache-2.0
"""Composite, content-addressed universal target intake."""

from sova.intake.contracts import (
    PROFILE_SCHEMA_VERSION,
    CredentialReference,
    EntryPoint,
    EntryPointKind,
    EnvironmentConstraint,
    InputDescriptor,
    InputKind,
    ProfileTargetKind,
    SourceClass,
    TargetProfile,
    target_profile_from_mapping,
    target_profile_template,
    validate_target_profile,
)
from sova.intake.materials import describe_material, fingerprint_material_path
from sova.intake.pipeline import (
    IntakeArtifacts,
    read_intake_report,
    read_target_profile,
    run_universal_intake,
    validate_intake_report,
)

__all__ = [
    "PROFILE_SCHEMA_VERSION",
    "CredentialReference",
    "EntryPoint",
    "EntryPointKind",
    "EnvironmentConstraint",
    "InputDescriptor",
    "InputKind",
    "IntakeArtifacts",
    "ProfileTargetKind",
    "SourceClass",
    "TargetProfile",
    "describe_material",
    "fingerprint_material_path",
    "read_intake_report",
    "read_target_profile",
    "run_universal_intake",
    "target_profile_from_mapping",
    "target_profile_template",
    "validate_intake_report",
    "validate_target_profile",
]
