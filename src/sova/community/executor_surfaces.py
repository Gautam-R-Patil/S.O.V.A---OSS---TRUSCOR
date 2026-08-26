# SPDX-License-Identifier: Apache-2.0
"""Built-in disposable workspace and exact-process SOVA Engine surfaces."""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from sova.community.executor_engine import CodecFactory, EngineSurfaceGeneration
from sova.executors.gvisor import GVisorOciExecutor
from sova.executors.workspace import ExactProcessExecutor, WorkspaceExecutor
from sova.formats import canonical_json_bytes, sha256_digest, strict_json_loads
from sova.formats.errors import FormatError
from sova.live.semantic_workflow import SemanticBrowserMission
from sova.runtime.action_codecs import (
    BrowserActionCodec,
    ComputerActionCodec,
    ComputerIdentityBinding,
    OciProcessActionCodec,
    ProcessActionCodec,
    ReviewedComputerTarget,
    WorkspaceActionCodec,
)
from sova.runtime.browser_surface import ManagedPlaywrightBrowserSurface
from sova.runtime.computer_surface import ManagedComputerSurface
from sova.runtime.environment_builder import BackendAdmission
from sova.runtime.managed_surfaces import EvidenceSatisfactionPolicy
from sova.runtime.melra_computer import MelraComputerSnapshotSource, melra_computer_lazy_executor

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from sova.executors import (
        ActionOutcome,
        ActionRequest,
        CancellationToken,
        Capability,
        ExecutionContext,
    )
    from sova.runtime.target_environment import SessionEnvelope, TargetInstance

_MAX_OBSERVED_FILES = 256
_MAX_OBSERVED_BYTES = 8 * 1024 * 1024
_MAX_INCLUDED_TEXT_BYTES = 128 * 1024
_MAX_REVIEWED_COMPUTER_TARGETS = 2_000
_RESERVED_RUNTIME_ROOTS = frozenset({".cache", ".sova"})


class _WorkspaceObservation:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._workspace: Path | None = None
        self._workspace_identity: tuple[int, int] | None = None
        self._session_digest: str | None = None

    @staticmethod
    def _is_link_or_junction(path: Path) -> bool:
        return path.is_symlink() or getattr(path, "is_junction", lambda: False)()

    def bind(self, session: SessionEnvelope, target: TargetInstance, workspace: Path) -> None:
        with self._lock:
            if self._workspace is not None:
                raise FormatError(
                    "SOVA-EXECUTOR-SURFACE-AFFINITY",
                    "workspace surface cannot be rebound",
                )
            session.assert_target(target)
            if self._is_link_or_junction(workspace):
                raise FormatError(
                    "SOVA-EXECUTOR-SURFACE-WORKSPACE",
                    "workspace surface requires one real disposable workspace",
                )
            try:
                resolved = workspace.resolve(strict=True)
                workspace_stat = resolved.stat()
            except (OSError, RuntimeError) as error:
                raise FormatError(
                    "SOVA-EXECUTOR-SURFACE-WORKSPACE",
                    "workspace surface requires one real disposable workspace",
                ) from error
            if not resolved.is_dir():
                raise FormatError(
                    "SOVA-EXECUTOR-SURFACE-WORKSPACE",
                    "workspace surface requires one real disposable workspace",
                )
            self._workspace = resolved
            self._workspace_identity = (workspace_stat.st_dev, workspace_stat.st_ino)
            self._session_digest = session.digest

    def _bound_workspace(self) -> tuple[Path, str]:
        with self._lock:
            root = self._workspace
            identity = self._workspace_identity
            session_digest = self._session_digest
        if root is None or identity is None or session_digest is None:
            raise FormatError(
                "SOVA-EXECUTOR-SURFACE-AFFINITY",
                "workspace surface is not session-bound",
            )
        if self._is_link_or_junction(root):
            raise FormatError(
                "SOVA-EXECUTOR-SURFACE-WORKSPACE",
                "bound workspace identity is no longer valid",
            )
        try:
            resolved = root.resolve(strict=True)
            current_stat = root.stat()
        except (OSError, RuntimeError) as error:
            raise FormatError(
                "SOVA-EXECUTOR-SURFACE-WORKSPACE",
                "bound workspace identity is no longer valid",
            ) from error
        if (
            resolved != root
            or not root.is_dir()
            or (current_stat.st_dev, current_stat.st_ino) != identity
        ):
            raise FormatError(
                "SOVA-EXECUTOR-SURFACE-WORKSPACE",
                "bound workspace identity is no longer valid",
            )
        return root, session_digest

    def __call__(self) -> Mapping[str, Any]:
        root, session_digest = self._bound_workspace()
        documents: dict[str, dict[str, Any]] = {}
        total_bytes = 0
        included_text_bytes = 0

        def reject_walk_error(error: OSError) -> None:
            raise FormatError(
                "SOVA-EXECUTOR-SURFACE-WORKSPACE",
                "observable workspace could not be traversed",
            ) from error

        for current, directory_names, file_names in os.walk(
            root,
            followlinks=False,
            onerror=reject_walk_error,
        ):
            current_path = Path(current)
            relative_current = current_path.relative_to(root)
            if relative_current.parts and relative_current.parts[0].casefold() in (
                _RESERVED_RUNTIME_ROOTS
            ):
                directory_names[:] = []
                continue
            kept_directories: list[str] = []
            for name in sorted(directory_names):
                candidate = current_path / name
                top = (*relative_current.parts, name)[0].casefold()
                if top in _RESERVED_RUNTIME_ROOTS:
                    continue
                if self._is_link_or_junction(candidate):
                    raise FormatError(
                        "SOVA-EXECUTOR-SURFACE-WORKSPACE",
                        "observable workspace cannot contain links or junctions",
                    )
                kept_directories.append(name)
            directory_names[:] = kept_directories
            for name in sorted(file_names):
                path = current_path / name
                relative = path.relative_to(root).as_posix()
                if path.is_symlink() or not path.is_file():
                    raise FormatError(
                        "SOVA-EXECUTOR-SURFACE-WORKSPACE",
                        "observable workspace contains a non-regular file",
                    )
                before = path.stat()
                data = path.read_bytes()
                after = path.stat()
                if before.st_size != len(data) or (before.st_size, before.st_mtime_ns) != (
                    after.st_size,
                    after.st_mtime_ns,
                ):
                    raise FormatError(
                        "SOVA-EXECUTOR-SURFACE-WORKSPACE",
                        "workspace file changed during observation",
                    )
                total_bytes += len(data)
                if len(documents) >= _MAX_OBSERVED_FILES or total_bytes > _MAX_OBSERVED_BYTES:
                    raise FormatError(
                        "SOVA-EXECUTOR-SURFACE-LIMIT",
                        "observable workspace exceeds 256 files or 8 MiB",
                    )
                item: dict[str, Any] = {
                    "digest": sha256_digest(data),
                    "size": len(data),
                    "textIncluded": False,
                }
                try:
                    text = data.decode("utf-8", errors="strict")
                except UnicodeDecodeError:
                    text = None
                if text is not None and included_text_bytes + len(data) <= _MAX_INCLUDED_TEXT_BYTES:
                    item.update({"textIncluded": True, "text": text})
                    included_text_bytes += len(data)
                documents[relative] = item
        generation_digest = sha256_digest(canonical_json_bytes(documents))
        return {
            "sessionDigest": session_digest,
            "generationDigest": generation_digest,
            "documents": documents,
            "fileCount": len(documents),
            "totalBytes": total_bytes,
            "includedTextBytes": included_text_bytes,
        }


class _ObservedProcessExecutor:
    """Record only normalized process outcomes for the next trusted observation."""

    def __init__(self, delegate: ExactProcessExecutor, template_id: str) -> None:
        self._delegate = delegate
        self._template_id = template_id
        self._lock = threading.RLock()
        self._last: dict[str, Any] = {
            "templateId": template_id,
            "executed": False,
        }

    @property
    def name(self) -> str:
        return f"{self._delegate.name}:{self._template_id}"

    def capabilities(self) -> tuple[Capability, ...]:
        return self._delegate.capabilities()

    def execute(
        self,
        request: ActionRequest,
        context: ExecutionContext,
        cancellation: CancellationToken,
    ) -> ActionOutcome:
        outcome = self._delegate.execute(request, context, cancellation)
        document = {
            "templateId": self._template_id,
            "executed": True,
            "requestId": outcome.request_id,
            "status": outcome.status.value,
            "output": outcome.output,
            "evidenceDigests": sorted(item.digest for item in outcome.evidence),
            "verification": outcome.verification,
        }
        detached = strict_json_loads(canonical_json_bytes(document))
        if not isinstance(detached, dict):  # pragma: no cover - source is an object
            raise TypeError
        with self._lock:
            self._last = detached
        return outcome

    def observe(self) -> dict[str, Any]:
        with self._lock:
            detached = strict_json_loads(canonical_json_bytes(self._last))
        if not isinstance(detached, dict):  # pragma: no cover - stored value is an object
            raise TypeError
        return detached

    def close(self) -> None:
        self._delegate.close()


class _ObservedGVisorProcessExecutor:
    """Bind one attested runsc generation and expose only normalized outcomes."""

    def __init__(self, delegate: GVisorOciExecutor, template_id: str) -> None:
        if type(delegate) is not GVisorOciExecutor or not delegate.attestation.ready:
            raise FormatError(
                "SOVA-EXECUTOR-SURFACE-GVISOR",
                "gVisor process surface requires one exact already-ready executor generation",
            )
        attestation = delegate.attestation
        self._delegate = delegate
        self._template_id = template_id
        self._lock = threading.RLock()
        self._closed = False
        self._session_digest: str | None = None
        self._target_digest: str | None = None
        self._static: dict[str, Any] = {
            "templateId": template_id,
            "attestationDigest": attestation.digest,
            "image": attestation.image,
            "runtime": attestation.runtime,
            "engineServerVersion": attestation.engine_server_version,
            "networkMode": "none",
            "hostWorkspaceMounted": False,
            "rootFilesystemReadOnly": True,
        }
        self._last: dict[str, Any] = {**self._static, "executed": False}

    @property
    def name(self) -> str:
        return f"{self._delegate.name}:{self._template_id}:{self._delegate.attestation.digest}"

    def capabilities(self) -> tuple[Capability, ...]:
        return self._delegate.capabilities()

    def bind(self, session: SessionEnvelope, target: TargetInstance, workspace: Path) -> None:
        del workspace
        session.assert_target(target)
        with self._lock:
            if self._closed or self._session_digest is not None:
                raise FormatError(
                    "SOVA-EXECUTOR-SURFACE-GVISOR-AFFINITY",
                    "gVisor process surface is closed or already bound",
                )
            self._session_digest = session.digest
            self._target_digest = target.digest
            self._last = {
                **self._last,
                "sessionDigest": session.digest,
                "targetInstanceDigest": target.digest,
            }

    def execute(
        self,
        request: ActionRequest,
        context: ExecutionContext,
        cancellation: CancellationToken,
    ) -> ActionOutcome:
        with self._lock:
            if self._closed or self._session_digest is None or self._target_digest is None:
                raise FormatError(
                    "SOVA-EXECUTOR-SURFACE-GVISOR-AFFINITY",
                    "gVisor process surface must be session-bound before execution",
                )
        outcome = self._delegate.execute(request, context, cancellation)
        expected_output = {
            "runtime": self._static["runtime"],
            "attestationDigest": self._static["attestationDigest"],
            "networkMode": "none",
            "hostWorkspaceMounted": False,
        }
        if any(
            key in outcome.output and outcome.output.get(key) != expected
            for key, expected in expected_output.items()
        ) or (
            outcome.status.value == "succeeded"
            and any(key not in outcome.output for key in expected_output)
        ):
            raise FormatError(
                "SOVA-EXECUTOR-SURFACE-GVISOR-SUBSTITUTION",
                "gVisor process outcome does not match its attested isolation generation",
            )
        document = {
            **self._static,
            "executed": True,
            "sessionDigest": self._session_digest,
            "targetInstanceDigest": self._target_digest,
            "requestId": outcome.request_id,
            "status": outcome.status.value,
            "output": outcome.output,
            "evidenceDigests": sorted(item.digest for item in outcome.evidence),
            "verification": outcome.verification,
        }
        detached = strict_json_loads(canonical_json_bytes(document))
        if not isinstance(detached, dict):  # pragma: no cover - source is an object
            raise TypeError
        with self._lock:
            if self._closed:
                raise FormatError(
                    "SOVA-EXECUTOR-SURFACE-GVISOR-AFFINITY",
                    "gVisor process surface closed during execution",
                )
            self._last = detached
        return outcome

    def observe(self) -> dict[str, Any]:
        with self._lock:
            if self._closed or self._session_digest is None:
                raise FormatError(
                    "SOVA-EXECUTOR-SURFACE-GVISOR-AFFINITY",
                    "gVisor process surface is not an open session-bound generation",
                )
            detached = strict_json_loads(canonical_json_bytes(self._last))
        if not isinstance(detached, dict):  # pragma: no cover - stored value is an object
            raise TypeError
        return detached

    def close(self) -> None:
        with self._lock:
            self._closed = True


@dataclass(frozen=True, slots=True)
class ExactProcessSurfaceSpec:
    """One explicitly reviewed shell-free trusted process template."""

    identifier: str
    executable: Path
    argv_prefix: tuple[str, ...] = ()
    max_args: int = 64
    max_arg_bytes: int = 64 * 1024
    max_output_bytes: int = 1024 * 1024
    trusted_host_process_acknowledged: bool = False

    def __post_init__(self) -> None:
        if (
            not self.identifier
            or not self.identifier.replace("-", "_").isidentifier()
            or self.trusted_host_process_acknowledged is not True
        ):
            raise FormatError(
                "SOVA-EXECUTOR-SURFACE-PROCESS",
                "exact process template requires an id and explicit trusted-host acknowledgement",
            )
        # Constructing the codec performs the exact path/prefix/argument validation now.
        self.codec()

    def codec(self) -> ProcessActionCodec:
        return ProcessActionCodec(
            self.executable,
            self.argv_prefix,
            max_args=self.max_args,
            max_arg_bytes=self.max_arg_bytes,
        )


@dataclass(frozen=True, slots=True)
class ExactOciProcessSurfaceSpec:
    """One finite shell-free command template inside a gVisor OCI image."""

    identifier: str
    executable: str
    argv_prefix: tuple[str, ...] = ()
    max_args: int = 256
    max_arg_bytes: int = 64 * 1024
    max_stdin_bytes: int = 64 * 1024

    def __post_init__(self) -> None:
        if not self.identifier or not self.identifier.replace("-", "_").isidentifier():
            raise FormatError(
                "SOVA-EXECUTOR-SURFACE-GVISOR",
                "exact OCI process template requires one valid identifier",
            )
        self.codec()

    def codec(self) -> OciProcessActionCodec:
        return OciProcessActionCodec(
            self.executable,
            self.argv_prefix,
            max_args=self.max_args,
            max_arg_bytes=self.max_arg_bytes,
            max_stdin_bytes=self.max_stdin_bytes,
        )


def workspace_surface_generation(
    *,
    max_read_bytes: int = 1024 * 1024,
    max_write_bytes: int = 1024 * 1024,
) -> EngineSurfaceGeneration:
    executor = WorkspaceExecutor(
        max_read_bytes=max_read_bytes,
        max_write_bytes=max_write_bytes,
    )
    observation = _WorkspaceObservation()
    policies = (
        EvidenceSatisfactionPolicy(
            "filesystem.read/0.1",
            ("content-digest", "path", "size"),
            required_projection_paths=(("workspace", "documents"),),
            required_output_keys=("path", "digest", "size"),
        ),
        EvidenceSatisfactionPolicy(
            "filesystem.write/0.1",
            ("content-digest", "path", "size"),
            required_projection_paths=(("workspace", "generationDigest"),),
            required_output_keys=("path", "digest", "size"),
            require_observation_change=True,
        ),
        EvidenceSatisfactionPolicy(
            "filesystem.delete/0.1",
            ("deleted-content-digest", "path", "size"),
            required_projection_paths=(("workspace", "generationDigest"),),
            required_output_keys=("path", "deletedDigest", "size"),
            require_observation_change=True,
        ),
        EvidenceSatisfactionPolicy(
            "filesystem.move/0.1",
            (
                "destination-path",
                "post-move-content-digest",
                "pre-move-content-digest",
                "source-absence",
                "source-path",
            ),
            required_projection_paths=(("workspace", "generationDigest"),),
            required_output_keys=(
                "source",
                "destination",
                "preMoveDigest",
                "postMoveDigest",
                "sourceAbsent",
            ),
            require_observation_change=True,
        ),
    )
    return EngineSurfaceGeneration(
        "workspace",
        BackendAdmission(
            "workspace",
            executor,
            "sova.workspace-byte-and-state-verifier/0.1",
            ("workspace:disposable",),
            {
                "filesystem.write": ("workspace:files",),
                "filesystem.delete": ("workspace:files",),
                "filesystem.move": ("workspace:files",),
            },
        ),
        observation,
        policies,
        bind=observation.bind,
    )


def browser_surface_generation(
    surface: ManagedPlaywrightBrowserSurface,
) -> EngineSurfaceGeneration:
    """Adapt one managed Playwright surface into an exact engine generation."""
    if type(surface) is not ManagedPlaywrightBrowserSurface:
        raise FormatError(
            "SOVA-EXECUTOR-SURFACE-BROWSER",
            "browser engine surface requires one exact managed Playwright generation",
        )
    capabilities = surface.capabilities()
    policies = tuple(
        EvidenceSatisfactionPolicy(
            capability.identifier,
            tuple(sorted(capability.evidence)),
            required_projection_paths=(("browser", "url"), ("browser", "snapshot")),
            required_output_keys=(
                ("text",) if capability.name == "browser.snapshot" else ("postObservationDigest",)
            ),
            require_observation_change=capability.side_effect.value != "read",
        )
        for capability in capabilities
    )

    def bind(session: SessionEnvelope, _target: TargetInstance, workspace: Path) -> None:
        surface.bind(workspace=workspace, session_digest=session.digest)

    return EngineSurfaceGeneration(
        "browser",
        BackendAdmission(
            "browser",
            surface.executor,
            "sova.playwright-post-action-observation-verifier/0.1",
            (f"browser-origin:{surface.allowed_origin}", "browser:session"),
            {
                capability.name: ("browser:session",)
                for capability in capabilities
                if capability.side_effect.value != "read"
            },
        ),
        surface.observe,
        policies,
        bind=bind,
        close=surface.close,
    )


def browser_codec_factory(
    mission: SemanticBrowserMission,
    *,
    sensor_name: str = "browser",
) -> CodecFactory:
    """Resolve one browser codec from the current redacted surface observation."""
    if type(mission) is not SemanticBrowserMission or not sensor_name:
        raise FormatError(
            "SOVA-EXECUTOR-SURFACE-BROWSER",
            "browser codec factory requires one exact mission and sensor name",
        )

    def factory(observation: Any) -> BrowserActionCodec:
        projection = getattr(observation, "projection", None)
        surface_projection = projection.get(sensor_name) if isinstance(projection, dict) else None
        if not isinstance(surface_projection, dict):
            raise FormatError(
                "SOVA-EXECUTOR-SURFACE-BROWSER-OBSERVATION",
                "current browser surface observation is absent",
            )
        refs = surface_projection.get("locatorRefs")
        if (
            surface_projection.get("missionDigest") != mission.digest
            or not isinstance(refs, list)
            or not all(isinstance(item, str) for item in refs)
            or len(refs) != len(set(refs))
        ):
            raise FormatError(
                "SOVA-EXECUTOR-SURFACE-BROWSER-OBSERVATION",
                "browser mission or current locator reference set is malformed",
            )
        version = getattr(observation, "version", None)
        digest = getattr(version, "content_digest", None)
        if not isinstance(digest, str):
            raise FormatError(
                "SOVA-EXECUTOR-SURFACE-BROWSER-OBSERVATION",
                "browser observation version digest is malformed",
            )
        return BrowserActionCodec(
            mission,
            frozenset(refs),
            digest,
            reviewed_targets=frozenset(refs),
        )

    return factory


def computer_surface_generation(surface: ManagedComputerSurface) -> EngineSurfaceGeneration:
    """Adapt one exact managed application/window surface into an engine generation."""
    if type(surface) is not ManagedComputerSurface:
        raise FormatError(
            "SOVA-EXECUTOR-SURFACE-COMPUTER",
            "computer engine surface requires one exact managed computer generation",
        )
    capabilities = surface.capabilities()
    identity_resource = f"computer-identity:{surface.identity_digest}"
    policies = tuple(
        EvidenceSatisfactionPolicy(
            capability.identifier,
            tuple(sorted(capability.evidence)),
            required_projection_paths=(
                ("computer", "binding"),
                ("computer", "reviewedTargets"),
                ("computer", "ui"),
            ),
            require_observation_change=capability.side_effect.value != "read",
        )
        for capability in capabilities
    )
    return EngineSurfaceGeneration(
        "computer",
        BackendAdmission(
            "computer",
            surface.executor,
            "sova.computer-reviewed-target-observation-verifier/0.1",
            (identity_resource, "computer:session"),
            {
                capability.name: (identity_resource,)
                for capability in capabilities
                if capability.side_effect.value != "read"
            },
        ),
        surface.observe,
        policies,
        bind=surface.bind,
        close=surface.close,
    )


def computer_codec_factory(*, sensor_name: str = "computer") -> CodecFactory:
    """Build a codec solely from the current bound, redacted computer observation."""
    if not sensor_name or not sensor_name.replace("-", "_").isidentifier():
        raise FormatError(
            "SOVA-EXECUTOR-SURFACE-COMPUTER",
            "computer codec factory requires one valid sensor name",
        )

    def factory(observation: Any) -> ComputerActionCodec:
        projection = getattr(observation, "projection", None)
        version = getattr(observation, "version", None)
        surface_projection = projection.get(sensor_name) if isinstance(projection, dict) else None
        observation_digest = getattr(version, "content_digest", None)
        observation_session = getattr(version, "session_digest", None)
        if (
            not isinstance(projection, dict)
            or not isinstance(surface_projection, dict)
            or not isinstance(observation_digest, str)
            or not isinstance(observation_session, str)
            or observation_digest != sha256_digest(canonical_json_bytes(projection))
        ):
            raise FormatError(
                "SOVA-EXECUTOR-SURFACE-COMPUTER-OBSERVATION",
                "current computer observation or version binding is malformed",
            )
        raw_binding = surface_projection.get("binding")
        raw_targets = surface_projection.get("reviewedTargets")
        if not isinstance(raw_binding, dict) or not isinstance(raw_targets, list):
            raise FormatError(
                "SOVA-EXECUTOR-SURFACE-COMPUTER-OBSERVATION",
                "computer binding or reviewed target list is absent",
            )
        kind = raw_binding.get("kind")
        binding_kind: Literal["application", "window"]
        if kind == "application":
            binding_kind = "application"
        elif kind == "window":
            binding_kind = "window"
        else:
            raise FormatError(
                "SOVA-EXECUTOR-SURFACE-COMPUTER-BINDING",
                "computer observation identity binding is malformed",
            )
        expected_binding_fields = (
            {"kind", "sessionDigest", "identityDigest"}
            if binding_kind == "application"
            else {"kind", "sessionDigest", "identityDigest", "pid", "windowId"}
        )
        binding_session = raw_binding.get("sessionDigest")
        identity_digest = raw_binding.get("identityDigest")
        if (
            set(raw_binding) != expected_binding_fields
            or not isinstance(binding_session, str)
            or not isinstance(identity_digest, str)
        ):
            raise FormatError(
                "SOVA-EXECUTOR-SURFACE-COMPUTER-BINDING",
                "computer observation identity binding is malformed",
            )
        binding = ComputerIdentityBinding(
            binding_kind,
            binding_session,
            identity_digest,
            raw_binding.get("pid"),
            raw_binding.get("windowId"),
        )
        if binding.session_digest != observation_session:
            raise FormatError(
                "SOVA-EXECUTOR-SURFACE-COMPUTER-BINDING",
                "computer observation substituted its session generation",
            )
        if len(raw_targets) > _MAX_REVIEWED_COMPUTER_TARGETS:
            raise FormatError(
                "SOVA-EXECUTOR-SURFACE-COMPUTER-TARGET",
                "computer observation contains too many reviewed targets",
            )
        targets: list[ReviewedComputerTarget] = []
        for item in raw_targets:
            reference = item.get("reference") if isinstance(item, dict) else None
            actions = item.get("actions") if isinstance(item, dict) else None
            locator = item.get("locator") if isinstance(item, dict) else None
            if (
                not isinstance(item, dict)
                or set(item) != {"reference", "actions", "locator"}
                or not isinstance(reference, str)
                or not isinstance(actions, list)
                or not all(isinstance(action, str) for action in actions)
                or not isinstance(locator, dict)
            ):
                raise FormatError(
                    "SOVA-EXECUTOR-SURFACE-COMPUTER-TARGET",
                    "computer observation reviewed target is malformed",
                )
            targets.append(
                ReviewedComputerTarget(
                    reference,
                    tuple(actions),
                    locator,
                )
            )
        return ComputerActionCodec(binding, observation_digest, tuple(targets))

    return factory


def melra_computer_surface_generation(  # noqa: PLR0913 - each identity input is independent
    *,
    node_executable: Path,
    cli_entrypoint: Path,
    policy_factory: Callable[[Path], Path],
    identity_digest: str,
    pid: int,
    window_id: int,
    mutations: tuple[str, ...] = ("computer.click", "computer.type"),
) -> EngineSurfaceGeneration:
    """Adapt a lazily-launched MELRA desktop computer-use backend into an engine
    generation.

    The underlying `ManagedComputerSurface` requires its snapshot callback to
    be workspace-bound before use; this wrapper's `bind` closure binds both the
    surface and the MELRA snapshot source from the same fresh session/target/
    workspace triple the engine supplies. `mutations` is the reviewed mutation
    ceiling (default click + type); it is threaded identically to the lazy
    executor (advertised capabilities), the snapshot source (per-element action
    assignment), and the managed surface (admitted actions) so all three agree.
    """
    lazy_executor = melra_computer_lazy_executor(
        node_executable=node_executable,
        cli_entrypoint=cli_entrypoint,
        policy_factory=policy_factory,
        mutations=mutations,
    )
    snapshot_source = MelraComputerSnapshotSource(lazy_executor, mutations=mutations)
    surface = ManagedComputerSurface(
        executor=lazy_executor,
        kind="window",
        identity_digest=identity_digest,
        snapshot=snapshot_source,
        pid=pid,
        window_id=window_id,
        cleanup=lazy_executor.close,
        mutations=mutations,
    )
    base = computer_surface_generation(surface)

    def bind(session: SessionEnvelope, target: TargetInstance, workspace: Path) -> None:
        surface.bind(session, target, workspace)
        snapshot_source.bind_workspace(workspace)

    return replace(base, bind=bind)


def workspace_codec_factory(*, max_content_bytes: int = 1024 * 1024) -> CodecFactory:
    def factory(_observation: Any) -> WorkspaceActionCodec:
        return WorkspaceActionCodec(max_content_bytes)

    return factory


def process_surface_generation(spec: ExactProcessSurfaceSpec) -> EngineSurfaceGeneration:
    delegate = ExactProcessExecutor(
        spec.executable,
        spec.argv_prefix,
        max_args=spec.max_args,
        max_arg_bytes=spec.max_arg_bytes,
        max_output_bytes=spec.max_output_bytes,
    )
    executor = _ObservedProcessExecutor(delegate, spec.identifier)
    capability = executor.capabilities()[0]
    return EngineSurfaceGeneration(
        f"process_{spec.identifier}",
        BackendAdmission(
            f"process-{spec.identifier}",
            executor,
            "sova.exact-process-output-verifier/0.1",
            (f"process-template:{spec.identifier}", "workspace:disposable"),
            {"process.exec": (f"process-template:{spec.identifier}",)},
        ),
        executor.observe,
        (
            EvidenceSatisfactionPolicy(
                capability.identifier,
                tuple(sorted(capability.evidence)),
                required_projection_paths=(
                    (f"process_{spec.identifier}", "executed"),
                    (f"process_{spec.identifier}", "output"),
                ),
                required_output_keys=("returncode", "stdout", "stderr"),
                require_observation_change=True,
            ),
        ),
        close=executor.close,
    )


def process_codec_factory(spec: ExactProcessSurfaceSpec) -> CodecFactory:
    def factory(_observation: Any) -> ProcessActionCodec:
        return spec.codec()

    return factory


def gvisor_process_surface_generation(
    spec: ExactOciProcessSurfaceSpec,
    executor: GVisorOciExecutor,
) -> EngineSurfaceGeneration:
    """Adapt one already-attested, mount-free runsc executor generation."""
    if type(spec) is not ExactOciProcessSurfaceSpec:
        raise FormatError(
            "SOVA-EXECUTOR-SURFACE-GVISOR",
            "gVisor process surface requires one exact OCI template contract",
        )
    observed = _ObservedGVisorProcessExecutor(executor, spec.identifier)
    attestation = executor.attestation
    capability = observed.capabilities()[0]
    sensor_name = f"oci_process_{spec.identifier}"
    attestation_resource = f"oci-attestation:{attestation.digest}"
    image_resource = f"oci-image-binding:{sha256_digest(attestation.image.encode('utf-8'))}"
    runtime_resource = f"oci-runtime:{attestation.runtime}"
    effect_resource = f"oci-target-process:{spec.identifier}:{attestation.digest}"
    return EngineSurfaceGeneration(
        sensor_name,
        BackendAdmission(
            f"gvisor-process-{spec.identifier}",
            observed,
            "sova.gvisor-target-process-attestation-output-verifier/0.1",
            tuple(
                sorted(
                    {
                        attestation_resource,
                        image_resource,
                        runtime_resource,
                        "oci-host-mounts:none",
                        "oci-network:none",
                        "oci-rootfs:read-only",
                        f"process-template:{spec.identifier}",
                    }
                )
            ),
            {"process.exec": (effect_resource,)},
        ),
        observed.observe,
        (
            EvidenceSatisfactionPolicy(
                capability.identifier,
                tuple(sorted(capability.evidence)),
                required_projection_paths=(
                    (sensor_name, "attestationDigest"),
                    (sensor_name, "executed"),
                    (sensor_name, "hostWorkspaceMounted"),
                    (sensor_name, "image"),
                    (sensor_name, "networkMode"),
                    (sensor_name, "output"),
                    (sensor_name, "runtime"),
                    (sensor_name, "sessionDigest"),
                    (sensor_name, "targetInstanceDigest"),
                ),
                required_output_keys=(
                    "attestationDigest",
                    "cleanupVerified",
                    "hostWorkspaceMounted",
                    "networkMode",
                    "returncode",
                    "runtime",
                    "stderr",
                    "stdout",
                ),
                require_observation_change=True,
            ),
        ),
        bind=observed.bind,
        close=observed.close,
    )


def oci_process_codec_factory(
    spec: ExactOciProcessSurfaceSpec,
    executor: GVisorOciExecutor,
    *,
    sensor_name: str | None = None,
) -> CodecFactory:
    """Resolve the OCI codec only from its exact current attested observation."""
    if type(spec) is not ExactOciProcessSurfaceSpec or type(executor) is not GVisorOciExecutor:
        raise FormatError(
            "SOVA-EXECUTOR-SURFACE-GVISOR",
            "OCI codec factory requires exact template and gVisor executor generations",
        )
    attestation = executor.attestation
    if not attestation.ready:
        raise FormatError(
            "SOVA-EXECUTOR-SURFACE-GVISOR",
            "OCI codec factory requires an already-ready gVisor attestation",
        )
    expected_sensor = sensor_name or f"oci_process_{spec.identifier}"
    expected = {
        "attestationDigest": attestation.digest,
        "hostWorkspaceMounted": False,
        "image": attestation.image,
        "networkMode": "none",
        "rootFilesystemReadOnly": True,
        "runtime": attestation.runtime,
        "templateId": spec.identifier,
    }

    def factory(observation: Any) -> OciProcessActionCodec:
        projection = getattr(observation, "projection", None)
        version = getattr(observation, "version", None)
        surface_projection = (
            projection.get(expected_sensor) if isinstance(projection, dict) else None
        )
        observation_digest = getattr(version, "content_digest", None)
        observation_session = getattr(version, "session_digest", None)
        if (
            not isinstance(projection, dict)
            or not isinstance(surface_projection, dict)
            or not isinstance(observation_digest, str)
            or observation_digest != sha256_digest(canonical_json_bytes(projection))
            or not isinstance(observation_session, str)
            or surface_projection.get("sessionDigest") != observation_session
            or any(surface_projection.get(key) != value for key, value in expected.items())
        ):
            raise FormatError(
                "SOVA-EXECUTOR-SURFACE-GVISOR-OBSERVATION",
                "current OCI observation does not match its attested image/runtime generation",
            )
        return spec.codec()

    return factory


__all__ = [
    "ExactOciProcessSurfaceSpec",
    "ExactProcessSurfaceSpec",
    "browser_codec_factory",
    "browser_surface_generation",
    "computer_codec_factory",
    "computer_surface_generation",
    "gvisor_process_surface_generation",
    "melra_computer_surface_generation",
    "oci_process_codec_factory",
    "process_codec_factory",
    "process_surface_generation",
    "workspace_codec_factory",
    "workspace_surface_generation",
]
