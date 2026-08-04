# SPDX-License-Identifier: Apache-2.0
"""Safe local initialization, diagnostics, and managed-data removal."""

from __future__ import annotations

import importlib.metadata
import os
import platform
import secrets
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sova import __version__
from sova.formats import canonical_json_bytes, sha256_digest, strict_json_loads
from sova.formats.errors import FormatError
from sova.local_mcp import create_control_key, load_control_key, manifest_self_check

INSTANCE_MARKER = ".sova-managed.json"
CONFIG_FILE = "config.json"
CONTROL_KEY = "control/control.key"
MANAGED_DIRECTORIES = ("artifacts", "control", "evidence", "registry-cache", "tmp")
_PROVIDERS: dict[str, str | None] = {
    "none": None,
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "google": "GOOGLE_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "ollama": None,
    "custom": "SOVA_PROVIDER_API_KEY",
}
_MAX_MANAGED_FILES = 100_000
_MAX_MANAGED_BYTES = 2 * 1024 * 1024 * 1024


def _timestamp() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _safe_root(root: Path) -> Path:
    expanded = root.expanduser()
    if expanded.exists() and expanded.is_symlink():
        raise FormatError("SOVA-INSTANCE-SYMLINK", "managed root cannot be a symlink")
    resolved = expanded.resolve()
    anchor = Path(resolved.anchor).resolve()
    home = Path.home().resolve()
    if resolved in {anchor, home}:
        raise FormatError(
            "SOVA-INSTANCE-BROAD-ROOT",
            "refusing to manage a filesystem root or the user home directory",
        )
    return resolved


def _load_object(path: Path, *, code: str) -> dict[str, Any]:
    if path.is_symlink():
        raise FormatError(code, f"required local file cannot be a symlink: {path.name}")
    try:
        value = strict_json_loads(path.read_bytes(), max_bytes=64 * 1024)
    except OSError as error:
        raise FormatError(code, f"required local file is unavailable: {path.name}") from error
    if not isinstance(value, dict):
        raise FormatError(code, f"local file must contain a JSON object: {path.name}")
    return value


def _write_new(path: Path, value: dict[str, Any]) -> None:
    data = canonical_json_bytes(value) + b"\n"
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
        0o600,
    )
    try:
        os.write(descriptor, data)
    finally:
        os.close(descriptor)


def initialize_instance(
    root: Path,
    *,
    provider: str = "none",
    registry: Path | None = None,
) -> dict[str, Any]:
    """Create an account-free local SOVA instance without storing provider secrets."""
    if provider not in _PROVIDERS:
        raise FormatError("SOVA-INIT-PROVIDER", "unsupported provider selection")
    resolved = _safe_root(root)
    marker_path = resolved / INSTANCE_MARKER
    if marker_path.exists():
        marker = _load_object(marker_path, code="SOVA-INIT-MARKER")
        return {
            "artifactType": "sova.initialization-result",
            "schemaVersion": "0.1.0",
            "instanceId": marker.get("instanceId"),
            "root": str(resolved),
            "created": False,
            "reused": True,
            "networkUsed": False,
            "secretsPrinted": False,
            "next": ["sova doctor " + str(resolved), "sova demo <output-directory>"],
        }
    if resolved.exists() and any(resolved.iterdir()):
        raise FormatError(
            "SOVA-INIT-NONEMPTY",
            "refusing to adopt a non-empty directory without a SOVA marker",
        )
    registry_path = registry.expanduser().resolve() if registry is not None else None
    if registry_path is not None and not registry_path.is_dir():
        raise FormatError("SOVA-INIT-REGISTRY", "registry selection must be an existing directory")

    resolved.mkdir(parents=True, exist_ok=True)
    for name in MANAGED_DIRECTORIES:
        (resolved / name).mkdir()
    instance_id = "sova-instance-" + secrets.token_hex(16)
    credential_environment = _PROVIDERS[provider]
    config = {
        "artifactType": "sova.local-config",
        "schemaVersion": "0.1.0",
        "instanceId": instance_id,
        "provider": {
            "name": provider,
            "credentialEnvironment": credential_environment,
            "credentialStorage": "environment-reference-only",
        },
        "registry": {
            "mode": "local-mirror" if registry_path is not None else "offline-empty",
            "source": str(registry_path) if registry_path is not None else None,
            "cache": "registry-cache",
        },
        "networkDefault": "disabled",
        "telemetryEnabled": False,
        "accountRequired": False,
        "executionDefault": "inert-until-explicit-command-and-authorization",
    }
    marker = {
        "artifactType": "sova.managed-instance",
        "schemaVersion": "0.1.0",
        "instanceId": instance_id,
        "sovaVersion": __version__,
        "createdAt": _timestamp(),
        "rootDigest": sha256_digest(str(resolved).encode("utf-8")),
        "managedDirectories": list(MANAGED_DIRECTORIES),
        "managedFiles": [CONFIG_FILE, CONTROL_KEY, INSTANCE_MARKER],
    }
    # The marker is written last, so an interrupted initialization is never
    # mistaken for a complete managed instance.
    create_control_key(resolved / CONTROL_KEY)
    _write_new(resolved / CONFIG_FILE, config)
    _write_new(marker_path, marker)
    return {
        "artifactType": "sova.initialization-result",
        "schemaVersion": "0.1.0",
        "instanceId": instance_id,
        "root": str(resolved),
        "created": True,
        "reused": False,
        "provider": provider,
        "providerCredentialStored": False,
        "registryMode": "local-mirror" if registry_path is not None else "offline-empty",
        "networkUsed": False,
        "telemetryEnabled": False,
        "secretsPrinted": False,
        "next": ["sova doctor " + str(resolved), "sova demo <output-directory>"],
    }


def _dependency_version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def diagnose_instance(root: Path) -> dict[str, Any]:
    """Run deterministic local checks without reading or emitting secret values."""
    resolved = _safe_root(root)
    marker = _load_object(resolved / INSTANCE_MARKER, code="SOVA-DOCTOR-MARKER")
    config = _load_object(resolved / CONFIG_FILE, code="SOVA-DOCTOR-CONFIG")
    instance_matches = marker.get("instanceId") == config.get("instanceId")
    key_path = resolved / CONTROL_KEY
    key_valid = False
    try:
        load_control_key(key_path)
        key_valid = True
    except (FormatError, OSError):
        key_valid = False
    mode = stat.S_IMODE(key_path.stat().st_mode) if key_path.exists() else None
    if os.name == "nt":
        permission_state = "platform-acl-not-assessed"
    else:
        permission_state = (
            "owner-only"
            if mode is not None and mode & (stat.S_IRWXG | stat.S_IRWXO) == 0
            else "weak"
        )
    provider = config.get("provider")
    provider_name = provider.get("name") if isinstance(provider, dict) else None
    credential_name = provider.get("credentialEnvironment") if isinstance(provider, dict) else None
    credential_available = (
        bool(os.environ.get(credential_name)) if isinstance(credential_name, str) else None
    )
    registry = config.get("registry")
    registry_mode = registry.get("mode") if isinstance(registry, dict) else None
    registry_source = registry.get("source") if isinstance(registry, dict) else None
    registry_available = (
        Path(registry_source).is_dir()
        if isinstance(registry_source, str)
        else registry_mode == "offline-empty"
    )
    mcp = manifest_self_check()
    checks = {
        "instanceMarker": marker.get("artifactType") == "sova.managed-instance",
        "configuration": config.get("artifactType") == "sova.local-config",
        "instanceIdentity": instance_matches,
        "controlKey": key_valid,
        "mcpManifest": bool(mcp.get("accepted")),
        "runtimeDependencies": all(
            _dependency_version(name) is not None for name in ("jsonschema", "jsonschema-rs")
        ),
        "registrySelection": registry_available,
    }
    warnings: list[str] = []
    if permission_state == "platform-acl-not-assessed":
        warnings.append("Windows ACL strength is not established by this portable doctor check.")
    if credential_available is False:
        warnings.append(
            f"{provider_name} credential environment is absent; offline core features still work."
        )
    return {
        "artifactType": "sova.doctor-report",
        "schemaVersion": "0.1.0",
        "status": "pass" if all(checks.values()) else "fail",
        "root": str(resolved),
        "instanceId": marker.get("instanceId"),
        "sovaVersion": __version__,
        "python": platform.python_version(),
        "platform": platform.system().lower(),
        "checks": checks,
        "provider": {
            "name": provider_name,
            "credentialEnvironment": credential_name,
            "credentialAvailable": credential_available,
            "credentialValueRead": False,
        },
        "registry": {"mode": registry_mode, "available": registry_available},
        "controlKey": {
            "valid": key_valid,
            "permissionState": permission_state,
            "valueExposed": False,
        },
        "mcp": mcp,
        "warnings": warnings,
        "networkUsed": False,
        "telemetrySent": False,
    }


def _inventory_managed_root(root: Path) -> tuple[list[Path], list[str], int]:
    allowed_top = {INSTANCE_MARKER, CONFIG_FILE, *MANAGED_DIRECTORIES}
    unknown = sorted(item.name for item in root.iterdir() if item.name not in allowed_top)
    files: list[Path] = []
    total = 0
    for directory_name in MANAGED_DIRECTORIES:
        directory = root / directory_name
        if not directory.exists():
            continue
        if directory.is_symlink() or not directory.is_dir():
            raise FormatError("SOVA-DATA-SYMLINK", "managed directories cannot be symlinks")
        for item in directory.rglob("*"):
            if item.is_symlink():
                raise FormatError("SOVA-DATA-SYMLINK", "managed data cannot contain symlinks")
            if item.is_file():
                files.append(item)
                total += item.stat().st_size
                if len(files) > _MAX_MANAGED_FILES or total > _MAX_MANAGED_BYTES:
                    raise FormatError(
                        "SOVA-DATA-LIMIT", "managed data exceeds deletion review limits"
                    )
    config = root / CONFIG_FILE
    marker = root / INSTANCE_MARKER
    if config.is_symlink() or marker.is_symlink():
        raise FormatError("SOVA-DATA-SYMLINK", "managed files cannot be symlinks")
    files.extend(path for path in (config, marker) if path.is_file())
    return files, unknown, total


def delete_instance_data(
    root: Path,
    *,
    instance_id: str,
    confirmed: bool,
) -> dict[str, Any]:
    """Preview or delete one exactly identified managed instance without following links."""
    resolved = _safe_root(root)
    marker = _load_object(resolved / INSTANCE_MARKER, code="SOVA-DATA-MARKER")
    if marker.get("instanceId") != instance_id:
        raise FormatError("SOVA-DATA-INSTANCE", "instance identifier did not match the marker")
    files, unknown, total = _inventory_managed_root(resolved)
    if unknown:
        raise FormatError(
            "SOVA-DATA-UNKNOWN",
            "unknown top-level entries must be moved before managed deletion",
            details={"entries": unknown},
        )
    report: dict[str, Any] = {
        "artifactType": "sova.data-deletion-result",
        "schemaVersion": "0.1.0",
        "instanceId": instance_id,
        "root": str(resolved),
        "fileCount": len(files),
        "managedPayloadBytes": total,
        "confirmed": confirmed,
        "deleted": False,
        "recoverable": False,
        "networkUsed": False,
    }
    if not confirmed:
        return {**report, "status": "preview", "next": "repeat with --yes after review"}
    for path in sorted(files, key=lambda item: len(item.parts), reverse=True):
        if path.exists():
            path.unlink()
    for directory_name in MANAGED_DIRECTORIES:
        directory = resolved / directory_name
        if directory.exists():
            directories = sorted(
                (item for item in directory.rglob("*") if item.is_dir()),
                key=lambda item: len(item.parts),
                reverse=True,
            )
            for child in directories:
                child.rmdir()
            directory.rmdir()
    resolved.rmdir()
    return {**report, "status": "deleted", "deleted": True}


__all__ = [
    "CONFIG_FILE",
    "CONTROL_KEY",
    "INSTANCE_MARKER",
    "MANAGED_DIRECTORIES",
    "delete_instance_data",
    "diagnose_instance",
    "initialize_instance",
]
