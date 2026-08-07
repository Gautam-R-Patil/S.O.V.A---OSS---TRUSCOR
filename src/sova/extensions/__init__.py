# SPDX-License-Identifier: Apache-2.0
"""Fail-closed extension contracts and subprocess conformance helpers."""

from sova.extensions.model import (
    EXTENSION_API_VERSION,
    ExtensionKind,
    ExtensionManifest,
    ExtensionMetadata,
    discover_extension_metadata,
)
from sova.extensions.runner import ExtensionRunResult, SubprocessExtensionRunner
from sova.extensions.workflow import (
    ExtensionApproval,
    ExtensionApprovalPrompt,
    ExtensionLaunch,
    ExtensionWorkflowArtifacts,
    PinnedArgumentFile,
    extension_launch_from_mapping,
    prepare_extension_launch,
    run_extension_workflow,
)

__all__ = [
    "EXTENSION_API_VERSION",
    "ExtensionApproval",
    "ExtensionApprovalPrompt",
    "ExtensionKind",
    "ExtensionLaunch",
    "ExtensionManifest",
    "ExtensionMetadata",
    "ExtensionRunResult",
    "ExtensionWorkflowArtifacts",
    "PinnedArgumentFile",
    "SubprocessExtensionRunner",
    "discover_extension_metadata",
    "extension_launch_from_mapping",
    "prepare_extension_launch",
    "run_extension_workflow",
]
