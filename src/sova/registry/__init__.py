# SPDX-License-Identifier: Apache-2.0
"""Offline-first registry, synchronization, contribution, and adapters."""

from sova.registry.adapters import (
    import_benchmark_scenario,
    import_passive_trace,
    import_sarif_findings,
    map_external_taxonomy,
)
from sova.registry.auto_contribute import auto_contribute_after_run
from sova.registry.backup import (
    RegistryBackupLimits,
    create_registry_backup,
    restore_registry_backup,
    verify_registry_backup,
)
from sova.registry.client import RegistryClient, RegistryEndpoint
from sova.registry.contribution import prepare_contribution, preview_contribution
from sova.registry.index import build_registry, resolve_registry_capsule, verify_registry
from sova.registry.model import RegistryEntry, RegistryIndex, VerificationTier
from sova.registry.pr_contribution import prepare_pr_contribution
from sova.registry.service import (
    CommunityHTTPService,
    CommunityRegistryStore,
    CommunityServiceConfig,
    CommunityServiceLimits,
    check_community_service_health,
    create_community_service_token,
    prepare_community_submission,
    serialize_community_submission,
    verify_community_service_index,
)
from sova.registry.sync import sync_registry

__all__ = [
    "CommunityHTTPService",
    "CommunityRegistryStore",
    "CommunityServiceConfig",
    "CommunityServiceLimits",
    "RegistryBackupLimits",
    "RegistryClient",
    "RegistryEndpoint",
    "RegistryEntry",
    "RegistryIndex",
    "VerificationTier",
    "auto_contribute_after_run",
    "build_registry",
    "check_community_service_health",
    "create_community_service_token",
    "create_registry_backup",
    "import_benchmark_scenario",
    "import_passive_trace",
    "import_sarif_findings",
    "map_external_taxonomy",
    "prepare_community_submission",
    "prepare_contribution",
    "prepare_pr_contribution",
    "preview_contribution",
    "resolve_registry_capsule",
    "restore_registry_backup",
    "serialize_community_submission",
    "sync_registry",
    "verify_community_service_index",
    "verify_registry",
    "verify_registry_backup",
]
