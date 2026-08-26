# SPDX-License-Identifier: Apache-2.0
"""Strict portable configuration for built-in Executor Engine surfaces."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, NoReturn

from sova.community.executor_surfaces import (
    ExactProcessSurfaceSpec,
    process_surface_generation,
    workspace_codec_factory,
    workspace_surface_generation,
)
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.trace import Redactor

if TYPE_CHECKING:
    from collections.abc import Mapping

    from sova.community.executor_chamber import ChamberActionCodec, ChamberObservation
    from sova.community.executor_engine import CodecFactory, EngineSurfaceGeneration
    from sova.executors import ActionRequest
    from sova.runtime.action_codecs import ProcessActionCodec

_ARTIFACT_TYPE = "sova.executor-engine-runtime"
_SCHEMA_VERSION = "0.1.0"
_WORKSPACE_CODEC_ID = "sova.action-codec.workspace/0.1.0"
_PROCESS_CODEC_PREFIX = "sova.action-codec.process."
_PROCESS_CODEC_SUFFIX = "/0.1.0"
_PROCESS_ID = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_SHELL_NAMES = frozenset(
    {
        "bash",
        "bash.exe",
        "cmd",
        "cmd.exe",
        "command.com",
        "csh",
        "dash",
        "fish",
        "ksh",
        "powershell",
        "powershell.exe",
        "pwsh",
        "pwsh.exe",
        "sh",
        "sh.exe",
        "tcsh",
        "wsl",
        "wsl.exe",
        "zsh",
    }
)
_SHELL_SUFFIXES = frozenset({".bat", ".cmd", ".command", ".ps1", ".sh"})
_MAX_WORKSPACE_BYTES = 1024 * 1024
_MAX_ARGS = 64
_MAX_ARG_BYTES = 64 * 1024
_MAX_SINGLE_ARG_BYTES = 4096
_MIN_OUTPUT_BYTES = 1024
_MAX_OUTPUT_BYTES = 64 * 1024 * 1024
_MAX_EXECUTABLE_CHARS = 32_768
_MAX_HOST_PROCESSES = 64


def _raise_config(
    message: str,
    *,
    details: dict[str, Any] | None = None,
    cause: Exception | None = None,
) -> NoReturn:
    error = FormatError(
        "SOVA-EXECUTOR-ENGINE-RUNTIME-CONFIG",
        message,
        details=details,
    )
    if cause is not None:
        raise error from cause
    raise error


def _object(value: object, path: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        _raise_config(f"{path} must be an object")
    return value


def _array(value: object, path: str) -> list[Any]:
    if not isinstance(value, list):
        _raise_config(f"{path} must be an array")
    return value


def _fields(value: dict[str, Any], path: str, required: tuple[str, ...]) -> None:
    missing = sorted(set(required) - set(value))
    unknown = sorted(set(value) - set(required))
    if missing or unknown:
        _raise_config(
            f"{path} fields are invalid",
            details={"missing": missing, "unknown": unknown},
        )


def _boolean(value: object, path: str) -> bool:
    if not isinstance(value, bool):
        _raise_config(f"{path} must be a boolean")
    return value


def _bounded_integer(value: object, path: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        _raise_config(f"{path} is outside the admitted range")
    return value


def _reject_secrets(document: dict[str, Any]) -> None:
    _redacted, disclosures = Redactor(context_id="sova-executor-engine-runtime-document").redact(
        document
    )
    if disclosures:
        raise FormatError(
            "SOVA-EXECUTOR-ENGINE-RUNTIME-SENSITIVE",
            "executor runtime surface document must not contain credential-shaped material",
        )


def _process_codec_id(identifier: str) -> str:
    return f"{_PROCESS_CODEC_PREFIX}{identifier}{_PROCESS_CODEC_SUFFIX}"


@dataclass(frozen=True, slots=True)
class WorkspaceRuntimeSurfaceConfig:
    """Immutable limits for one disposable workspace surface."""

    enabled: bool
    max_read_bytes: int
    max_write_bytes: int


@dataclass(frozen=True, slots=True)
class ParsedExecutorEngineRuntimeConfig:
    """Fully admitted surface configuration with exact process specifications."""

    document_digest: str
    workspace: WorkspaceRuntimeSurfaceConfig
    host_processes: tuple[ExactProcessSurfaceSpec, ...]

    @property
    def codec_ids(self) -> tuple[str, ...]:
        values = [
            *([_WORKSPACE_CODEC_ID] if self.workspace.enabled else []),
            *(_process_codec_id(spec.identifier) for spec in self.host_processes),
        ]
        return tuple(sorted(values))


@dataclass(frozen=True, slots=True)
class _ProcessDeclaration:
    identifier: str
    executable: Path
    argv_prefix: tuple[str, ...]
    max_args: int
    max_arg_bytes: int
    max_output_bytes: int


@dataclass(frozen=True, slots=True)
class _TemplateProcessCodec:
    codec_id: str
    delegate: ProcessActionCodec

    def decode(
        self,
        value: object,
        *,
        request_id: str,
        timeout_seconds: float,
    ) -> ActionRequest:
        return self.delegate.decode(
            value,
            request_id=request_id,
            timeout_seconds=timeout_seconds,
        )


def _template_codec_factory(spec: ExactProcessSurfaceSpec) -> CodecFactory:
    codec_id = _process_codec_id(spec.identifier)

    def factory(_observation: ChamberObservation) -> ChamberActionCodec:
        return _TemplateProcessCodec(codec_id, spec.codec())

    return factory


class ExecutorEngineRuntimeSurfaceBuilder:
    """Create fresh built-in surface generations for each engine phase."""

    __slots__ = ("__codec_factories", "__config")

    def __init__(self, config: ParsedExecutorEngineRuntimeConfig) -> None:
        if type(config) is not ParsedExecutorEngineRuntimeConfig:
            _raise_config("surface builder requires one exact parsed runtime config")
        factories: dict[str, CodecFactory] = {}
        if config.workspace.enabled:
            factories[_WORKSPACE_CODEC_ID] = workspace_codec_factory(
                max_content_bytes=config.workspace.max_write_bytes
            )
        for spec in config.host_processes:
            factories[_process_codec_id(spec.identifier)] = _template_codec_factory(spec)
        if tuple(sorted(factories)) != config.codec_ids:
            _raise_config("runtime codec registry does not match the admitted surfaces")
        self.__config = config
        self.__codec_factories: Mapping[str, CodecFactory] = MappingProxyType(
            dict(sorted(factories.items()))
        )

    @property
    def config(self) -> ParsedExecutorEngineRuntimeConfig:
        return self.__config

    @property
    def codec_factories(self) -> Mapping[str, CodecFactory]:
        return self.__codec_factories

    def __call__(self, phase: str) -> tuple[EngineSurfaceGeneration, ...]:
        if phase not in {"primary", "reproduction"}:
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-PHASE",
                "engine runtime surface phase is unsupported",
            )
        surfaces: list[EngineSurfaceGeneration] = []
        try:
            if self.__config.workspace.enabled:
                surfaces.append(
                    workspace_surface_generation(
                        max_read_bytes=self.__config.workspace.max_read_bytes,
                        max_write_bytes=self.__config.workspace.max_write_bytes,
                    )
                )
            surfaces.extend(
                process_surface_generation(spec) for spec in self.__config.host_processes
            )
        except Exception as error:
            cleanup_failed = False
            for surface in reversed(surfaces):
                try:
                    surface.close()
                except Exception:  # noqa: BLE001 - backend cleanup details stay private
                    cleanup_failed = True
            if cleanup_failed:
                raise FormatError(
                    "SOVA-EXECUTOR-ENGINE-RUNTIME-CLEANUP",
                    "runtime surface construction failed and cleanup could not be verified",
                ) from error
            raise
        return tuple(surfaces)


def _workspace(value: object) -> WorkspaceRuntimeSurfaceConfig:
    path = "$.workspace"
    item = _object(value, path)
    _fields(item, path, ("enabled", "maxReadBytes", "maxWriteBytes"))
    return WorkspaceRuntimeSurfaceConfig(
        _boolean(item["enabled"], f"{path}.enabled"),
        _bounded_integer(item["maxReadBytes"], f"{path}.maxReadBytes", 1, _MAX_WORKSPACE_BYTES),
        _bounded_integer(
            item["maxWriteBytes"],
            f"{path}.maxWriteBytes",
            1,
            _MAX_WORKSPACE_BYTES,
        ),
    )


def _path_syntax(value: object, path: str) -> Path:
    if (
        not isinstance(value, str)
        or not value
        or "\x00" in value
        or len(value) > _MAX_EXECUTABLE_CHARS
    ):
        _raise_config(f"{path} must be a bounded absolute executable path")
    executable = Path(value)
    if (
        not executable.is_absolute()
        or any(part in {".", ".."} for part in executable.parts)
        or executable.name.casefold() in _SHELL_NAMES
        or executable.suffix.casefold() in _SHELL_SUFFIXES
    ):
        _raise_config(f"{path} must be an exact absolute non-shell executable path")
    return executable


def _argv_prefix(value: object, path: str, *, max_args: int) -> tuple[str, ...]:
    raw = _array(value, path)
    if len(raw) > max_args:
        _raise_config(f"{path} exceeds maxArgs")
    values: list[str] = []
    for index, item in enumerate(raw):
        item_path = f"{path}[{index}]"
        if not isinstance(item, str) or not item or "\x00" in item:
            _raise_config(f"{item_path} must be a non-empty argv string")
        try:
            encoded = item.encode("utf-8", errors="strict")
        except UnicodeEncodeError as error:
            _raise_config(f"{item_path} must be valid UTF-8", cause=error)
        if len(encoded) > _MAX_SINGLE_ARG_BYTES:
            _raise_config(f"{item_path} exceeds 4096 encoded bytes")
        values.append(item)
    return tuple(values)


def _process_declarations(value: object) -> tuple[_ProcessDeclaration, ...]:
    rows = _array(value, "$.hostProcesses")
    if len(rows) > _MAX_HOST_PROCESSES:
        _raise_config("$.hostProcesses exceeds 64 exact process surfaces")
    declarations: list[_ProcessDeclaration] = []
    identifiers: set[str] = set()
    required = (
        "id",
        "executable",
        "argvPrefix",
        "maxArgs",
        "maxArgBytes",
        "maxOutputBytes",
        "trustedHostProcessAcknowledged",
    )
    for index, raw in enumerate(rows):
        path = f"$.hostProcesses[{index}]"
        item = _object(raw, path)
        _fields(item, path, required)
        identifier = item["id"]
        if not isinstance(identifier, str) or _PROCESS_ID.fullmatch(identifier) is None:
            _raise_config(f"{path}.id is not a portable exact process id")
        if identifier in identifiers:
            _raise_config("host process id is duplicated")
        if item["trustedHostProcessAcknowledged"] is not True:
            _raise_config(f"{path}.trustedHostProcessAcknowledged must be exactly true")
        max_args = _bounded_integer(item["maxArgs"], f"{path}.maxArgs", 1, _MAX_ARGS)
        max_arg_bytes = _bounded_integer(
            item["maxArgBytes"],
            f"{path}.maxArgBytes",
            1,
            _MAX_ARG_BYTES,
        )
        executable = _path_syntax(item["executable"], f"{path}.executable")
        prefix = _argv_prefix(item["argvPrefix"], f"{path}.argvPrefix", max_args=max_args)
        encoded_prefix = (str(executable), *prefix)
        if sum(len(item.encode("utf-8")) for item in encoded_prefix) > max_arg_bytes:
            _raise_config(f"{path} exact argv prefix exceeds maxArgBytes")
        declarations.append(
            _ProcessDeclaration(
                identifier,
                executable,
                prefix,
                max_args,
                max_arg_bytes,
                _bounded_integer(
                    item["maxOutputBytes"],
                    f"{path}.maxOutputBytes",
                    _MIN_OUTPUT_BYTES,
                    _MAX_OUTPUT_BYTES,
                ),
            )
        )
        identifiers.add(identifier)
    return tuple(declarations)


def _path_is_link(path: Path) -> bool:
    is_junction = getattr(path, "is_junction", lambda: False)
    return path.is_symlink() or bool(is_junction())


def _materialize_processes(
    declarations: tuple[_ProcessDeclaration, ...],
) -> tuple[ExactProcessSurfaceSpec, ...]:
    specs: list[ExactProcessSurfaceSpec] = []
    for declaration in declarations:
        if any(
            _path_is_link(path)
            for path in (declaration.executable, *declaration.executable.parents)
        ):
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-RUNTIME-LINK",
                "host process executable cannot traverse a symbolic link or junction",
            )
        specs.append(
            ExactProcessSurfaceSpec(
                declaration.identifier,
                declaration.executable,
                declaration.argv_prefix,
                declaration.max_args,
                declaration.max_arg_bytes,
                declaration.max_output_bytes,
                trusted_host_process_acknowledged=True,
            )
        )
    return tuple(specs)


def parse_executor_engine_runtime_document(
    document: dict[str, Any],
) -> ParsedExecutorEngineRuntimeConfig:
    """Validate the complete document before touching any executable path."""
    root = _object(document, "$")
    _fields(root, "$", ("artifactType", "schemaVersion", "workspace", "hostProcesses"))
    if root["artifactType"] != _ARTIFACT_TYPE or root["schemaVersion"] != _SCHEMA_VERSION:
        raise FormatError(
            "SOVA-EXECUTOR-ENGINE-RUNTIME-VERSION",
            "executor engine runtime surface document is unsupported",
        )
    _reject_secrets(root)
    workspace = _workspace(root["workspace"])
    declarations = _process_declarations(root["hostProcesses"])
    if not workspace.enabled and not declarations:
        _raise_config("executor engine runtime requires at least one enabled surface")

    # Only after every schema, value, secret, budget, and cross-reference
    # check succeeds may executable paths be inspected or specs constructed.
    specs = _materialize_processes(declarations)
    return ParsedExecutorEngineRuntimeConfig(
        sha256_digest(canonical_json_bytes(root)),
        workspace,
        specs,
    )


def build_executor_engine_runtime_surfaces(
    config: ParsedExecutorEngineRuntimeConfig,
) -> ExecutorEngineRuntimeSurfaceBuilder:
    """Return a fresh phase factory and its immutable exact codec registry."""
    return ExecutorEngineRuntimeSurfaceBuilder(config)


__all__ = [
    "ExecutorEngineRuntimeSurfaceBuilder",
    "ParsedExecutorEngineRuntimeConfig",
    "WorkspaceRuntimeSurfaceConfig",
    "build_executor_engine_runtime_surfaces",
    "parse_executor_engine_runtime_document",
]
