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

__all__ = [
    "EXTENSION_API_VERSION",
    "ExtensionKind",
    "ExtensionManifest",
    "ExtensionMetadata",
    "ExtensionRunResult",
    "SubprocessExtensionRunner",
    "discover_extension_metadata",
]
