# SPDX-License-Identifier: Apache-2.0
"""Portable `.sova` AI-behavior capsules."""

from sova.capsule.lifecycle import CapsuleLifecycle, can_transition
from sova.capsule.migrate import analyze_migration, migrate_capsule, migrate_manifest
from sova.capsule.model import (
    CaptureProfile,
    DomainProfile,
    build_capsule,
    capsule_manifest_template,
    lint_capsule,
    lint_scenario,
    render_capsule,
    scenario_template,
)
from sova.capsule.primitives import (
    Actor,
    Artifact,
    Environment,
    Evaluation,
    Event,
    Procedure,
    Provenance,
)

__all__ = [
    "Actor",
    "Artifact",
    "CapsuleLifecycle",
    "CaptureProfile",
    "DomainProfile",
    "Environment",
    "Evaluation",
    "Event",
    "Procedure",
    "Provenance",
    "analyze_migration",
    "build_capsule",
    "can_transition",
    "capsule_manifest_template",
    "lint_capsule",
    "lint_scenario",
    "migrate_capsule",
    "migrate_manifest",
    "render_capsule",
    "scenario_template",
]
