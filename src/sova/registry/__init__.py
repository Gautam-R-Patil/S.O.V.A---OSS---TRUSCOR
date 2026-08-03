# SPDX-License-Identifier: Apache-2.0
"""Offline-first registry, synchronization, contribution, and adapters."""

from sova.registry.adapters import (
    import_benchmark_scenario,
    import_passive_trace,
    import_sarif_findings,
    map_external_taxonomy,
)
from sova.registry.contribution import prepare_contribution, preview_contribution
from sova.registry.index import build_registry, verify_registry
from sova.registry.model import RegistryEntry, RegistryIndex, VerificationTier
from sova.registry.sync import sync_registry

__all__ = [
    "RegistryEntry",
    "RegistryIndex",
    "VerificationTier",
    "build_registry",
    "import_benchmark_scenario",
    "import_passive_trace",
    "import_sarif_findings",
    "map_external_taxonomy",
    "prepare_contribution",
    "preview_contribution",
    "sync_registry",
    "verify_registry",
]
