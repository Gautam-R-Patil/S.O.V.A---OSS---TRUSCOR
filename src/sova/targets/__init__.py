# SPDX-License-Identifier: Apache-2.0
"""Target connector declarations and conformance checks."""

from sova.targets.contract import (
    TargetKind,
    TargetManifest,
    target_manifest_from_mapping,
    validate_target_manifest,
)

__all__ = [
    "TargetKind",
    "TargetManifest",
    "target_manifest_from_mapping",
    "validate_target_manifest",
]
