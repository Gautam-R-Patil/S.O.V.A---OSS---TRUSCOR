# SPDX-License-Identifier: Apache-2.0
"""Human-authorized, digest-pinned operator workflow for subprocess extensions."""

from __future__ import annotations

import hmac
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypeAlias

from sova.extensions.runner import ExtensionRunResult, SubprocessExtensionRunner
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.trace import Redactor, TraceReader, TraceWriter, generate_ed25519_keypair

if TYPE_CHECKING:
    from sova.extensions.model import ExtensionManifest

_OPERATIONS = frozenset({"describe", "self-test", "invoke", "conform"})
_DIGEST_PREFIX = "sha256:"
_MAX_ARGUMENT_FILES = 63
_MAX_PAYLOAD_BYTES = 1024 * 1024
_MAX_TIMEOUT_SECONDS = 60
_DIGEST_HEX_LENGTH = 64
_INTERPRETER_INLINE_FLAGS = {
    "cmd": frozenset({"/c", "/k"}),
    "cmd.exe": frozenset({"/c", "/k"}),
    "node": frozenset({"-e", "--eval"}),
    "node.exe": frozenset({"-e", "--eval"}),
    "powershell": frozenset({"-c", "-command", "-encodedcommand"}),
    "powershell.exe": frozenset({"-c", "-command", "-encodedcommand"}),
    "pwsh": frozenset({"-c", "-command", "-encodedcommand"}),
    "pwsh.exe": frozenset({"-c", "-command", "-encodedcommand"}),
    "python": frozenset({"-c", "-m"}),
    "python.exe": frozenset({"-c", "-m"}),
    "python3": frozenset({"-c", "-m"}),
    "sh": frozenset({"-c"}),
}


@dataclass(frozen=True, slots=True)
class PinnedArgumentFile:
    """One command argument that is an exact regular-file input."""

    index: int
    digest: str

    def __post_init__(self) -> None:
        if isinstance(self.index, bool) or not 1 <= self.index <= _MAX_ARGUMENT_FILES:
            raise FormatError("SOVA-EXTENSION-ARGUMENT-PIN", "argument-file index is invalid")
        if not _is_digest(self.digest):
            raise FormatError("SOVA-EXTENSION-ARGUMENT-PIN", "argument-file digest is invalid")

    def to_mapping(self) -> dict[str, Any]:
        return {"index": self.index, "digest": self.digest}


@dataclass(frozen=True, slots=True)
class ExtensionLaunch:
    """A local, non-portable launch record bound to one extension manifest."""

    manifest_digest: str
    operation: str
    command: tuple[str, ...]
    executable_digest: str
    argument_files: tuple[PinnedArgumentFile, ...]
    working_directory: Path
    timeout_seconds: int
    payload: dict[str, Any]

    def __post_init__(self) -> None:
        if not _is_digest(self.manifest_digest) or not _is_digest(self.executable_digest):
            raise FormatError("SOVA-EXTENSION-LAUNCH", "launch digests are invalid")
        if self.operation not in _OPERATIONS:
            raise FormatError("SOVA-EXTENSION-LAUNCH", "launch operation is unsupported")
        if not self.command or any(not isinstance(item, str) for item in self.command):
            raise FormatError("SOVA-EXTENSION-LAUNCH", "launch command is invalid")
        if not Path(self.command[0]).is_absolute():
            raise FormatError(
                "SOVA-EXTENSION-EXECUTABLE",
                "extension executable path must be absolute",
            )
        if not self.working_directory.is_absolute():
            raise FormatError(
                "SOVA-EXTENSION-CWD",
                "extension working directory must be absolute",
            )
        if (
            isinstance(self.timeout_seconds, bool)
            or not 1 <= self.timeout_seconds <= _MAX_TIMEOUT_SECONDS
        ):
            raise FormatError("SOVA-EXTENSION-LAUNCH", "launch timeout is invalid")
        if self.operation == "conform" and self.payload:
            raise FormatError("SOVA-EXTENSION-LAUNCH", "conformance payload must be empty")
        indices = [item.index for item in self.argument_files]
        if len(indices) != len(set(indices)) or any(
            index >= len(self.command) for index in indices
        ):
            raise FormatError("SOVA-EXTENSION-ARGUMENT-PIN", "argument-file pins are invalid")
        encoded = canonical_json_bytes(self.payload)
        if len(encoded) > _MAX_PAYLOAD_BYTES:
            raise FormatError("SOVA-EXTENSION-PAYLOAD", "extension payload exceeds 1 MiB")
        _redacted, disclosures = Redactor(context_id="sova-extension-payload").redact(self.payload)
        if disclosures:
            raise FormatError(
                "SOVA-EXTENSION-PAYLOAD",
                "extension payload contains credential-shaped material",
            )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "artifactType": "sova.extension-launch",
            "schemaVersion": "0.1.0",
            "manifestDigest": self.manifest_digest,
            "operation": self.operation,
            "command": list(self.command),
            "executableDigest": self.executable_digest,
            "argumentFiles": [item.to_mapping() for item in self.argument_files],
            "workingDirectory": str(self.working_directory),
            "timeoutSeconds": self.timeout_seconds,
            "payload": self.payload,
        }

    @property
    def digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.to_mapping()))


@dataclass(frozen=True, slots=True)
class ExtensionApproval:
    """Exact phrase challenge for one complete local extension launch."""

    scope_digest: str
    exact_phrase: str
    summary: dict[str, Any]


ExtensionApprovalPrompt: TypeAlias = Callable[[ExtensionApproval], str]


@dataclass(frozen=True, slots=True)
class ExtensionWorkflowArtifacts:
    """Signed evidence and local report for one extension process workflow."""

    trace: Path
    report: Path
    status: str

    def to_mapping(self) -> dict[str, Any]:
        return {"status": self.status, "trace": str(self.trace), "report": str(self.report)}


def _is_digest(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith(_DIGEST_PREFIX):
        return False
    suffix = value[len(_DIGEST_PREFIX) :]
    return len(suffix) == _DIGEST_HEX_LENGTH and all(
        character in "0123456789abcdef" for character in suffix
    )


def extension_launch_from_mapping(value: Mapping[str, Any]) -> ExtensionLaunch:
    """Parse an exact-field local launch document."""
    if set(value) != {
        "artifactType",
        "schemaVersion",
        "manifestDigest",
        "operation",
        "command",
        "executableDigest",
        "argumentFiles",
        "workingDirectory",
        "timeoutSeconds",
        "payload",
    }:
        raise FormatError("SOVA-EXTENSION-LAUNCH", "launch fields are invalid")
    if (
        value.get("artifactType") != "sova.extension-launch"
        or value.get("schemaVersion") != "0.1.0"
    ):
        raise FormatError("SOVA-EXTENSION-LAUNCH", "launch version is unsupported")
    command = value.get("command")
    pins = value.get("argumentFiles")
    payload = value.get("payload")
    if not isinstance(command, list) or any(not isinstance(item, str) for item in command):
        raise FormatError("SOVA-EXTENSION-LAUNCH", "command must be a string array")
    if not isinstance(pins, list) or not isinstance(payload, dict):
        raise FormatError("SOVA-EXTENSION-LAUNCH", "argumentFiles and payload are required")
    parsed_pins: list[PinnedArgumentFile] = []
    for row in pins:
        if not isinstance(row, Mapping) or set(row) != {"index", "digest"}:
            raise FormatError("SOVA-EXTENSION-ARGUMENT-PIN", "argument-file pin is invalid")
        index = row.get("index")
        digest = row.get("digest")
        if isinstance(index, bool) or not isinstance(index, int) or not isinstance(digest, str):
            raise FormatError("SOVA-EXTENSION-ARGUMENT-PIN", "argument-file pin is invalid")
        parsed_pins.append(PinnedArgumentFile(index, digest))
    timeout = value.get("timeoutSeconds")
    fields = (
        value.get("manifestDigest"),
        value.get("operation"),
        value.get("executableDigest"),
        value.get("workingDirectory"),
    )
    if any(not isinstance(item, str) for item in fields):
        raise FormatError("SOVA-EXTENSION-LAUNCH", "launch string fields are invalid")
    if isinstance(timeout, bool) or not isinstance(timeout, int):
        raise FormatError("SOVA-EXTENSION-LAUNCH", "timeoutSeconds must be an integer")
    return ExtensionLaunch(
        str(fields[0]),
        str(fields[1]),
        tuple(command),
        str(fields[2]),
        tuple(parsed_pins),
        Path(str(fields[3])),
        timeout,
        payload,
    )


def _resolved_argument_path(argument: str, working_directory: Path) -> Path:
    path = Path(argument)
    return path.resolve() if path.is_absolute() else (working_directory / path).resolve()


def _verify_launch_files(launch: ExtensionLaunch) -> dict[int, dict[str, Any]]:
    working_directory = launch.working_directory.resolve()
    if not working_directory.is_dir() or working_directory.is_symlink():
        raise FormatError("SOVA-EXTENSION-CWD", "working directory is missing or symbolic")
    executable = Path(launch.command[0]).resolve()
    if not executable.is_file() or executable.is_symlink():
        raise FormatError("SOVA-EXTENSION-EXECUTABLE", "extension executable is unsafe")
    if sha256_digest(executable.read_bytes()) != launch.executable_digest:
        raise FormatError("SOVA-EXTENSION-EXECUTABLE", "extension executable digest changed")
    inline_flags = _INTERPRETER_INLINE_FLAGS.get(executable.name.casefold(), frozenset())
    if any(argument.casefold() in inline_flags for argument in launch.command[1:]):
        raise FormatError(
            "SOVA-EXTENSION-INLINE-CODE",
            "inline interpreter code is forbidden; pin a regular script file instead",
        )
    pins = {item.index: item.digest for item in launch.argument_files}
    verified: dict[int, dict[str, Any]] = {}
    for index, argument in enumerate(launch.command[1:], start=1):
        candidate = _resolved_argument_path(argument, working_directory)
        path_shaped = Path(argument).is_absolute() or any(
            separator in argument for separator in ("/", "\\")
        )
        if not candidate.exists() and path_shaped:
            raise FormatError("SOVA-EXTENSION-ARGUMENT-FILE", "path argument does not exist")
        if not candidate.exists():
            continue
        if index not in pins:
            raise FormatError(
                "SOVA-EXTENSION-ARGUMENT-PIN",
                "every existing file argument requires an exact digest pin",
            )
        if not candidate.is_file() or candidate.is_symlink():
            raise FormatError("SOVA-EXTENSION-ARGUMENT-FILE", "argument file is unsafe")
        digest = sha256_digest(candidate.read_bytes())
        if digest != pins[index]:
            raise FormatError("SOVA-EXTENSION-ARGUMENT-PIN", "argument file digest changed")
        verified[index] = {"path": str(candidate), "digest": digest}
    if set(pins) != set(verified):
        raise FormatError(
            "SOVA-EXTENSION-ARGUMENT-PIN",
            "argument-file pin does not identify an existing command file",
        )
    return verified


def _approval(
    manifest: ExtensionManifest,
    launch: ExtensionLaunch,
    verified_files: dict[int, dict[str, Any]],
) -> ExtensionApproval:
    summary = {
        "manifest": manifest.to_mapping(),
        "launch": launch.to_mapping(),
        "verifiedArgumentFiles": [
            {"index": index, **verified_files[index]} for index in sorted(verified_files)
        ],
        "warning": (
            "This starts an operator-selected host process. A sanitized environment, exact "
            "digest pins, protocol limits, and evidence do not make it a security sandbox."
        ),
        "extensionAuthorityInherited": False,
    }
    scope_digest = sha256_digest(canonical_json_bytes(summary))
    return ExtensionApproval(
        scope_digest,
        f"AUTHORIZE SOVA EXTENSION {scope_digest[7:23]}",
        summary,
    )


def _require_approval(prompt: ExtensionApprovalPrompt, challenge: ExtensionApproval) -> None:
    response = prompt(challenge)
    if not isinstance(response, str) or not hmac.compare_digest(response, challenge.exact_phrase):
        raise FormatError(
            "SOVA-EXTENSION-APPROVAL",
            "exact extension launch approval was not granted",
        )


def _sanitized_result(result: ExtensionRunResult) -> dict[str, Any]:
    sanitized, disclosures = Redactor(context_id="sova-extension-response").redact(result.response)
    if not isinstance(sanitized, dict):
        raise FormatError("SOVA-EXTENSION-PROTOCOL", "sanitized response is invalid")
    return {
        "manifestDigest": result.manifest_digest,
        "operation": result.operation,
        "response": sanitized,
        "responseDigest": sha256_digest(canonical_json_bytes(sanitized)),
        "captureTimeRedactions": len(disclosures),
        "stderrTruncated": result.stderr_truncated,
    }


def prepare_extension_launch(  # noqa: PLR0913
    manifest: ExtensionManifest,
    *,
    operation: str,
    executable: Path,
    arguments: tuple[str, ...],
    working_directory: Path,
    timeout_seconds: int = 30,
    payload: dict[str, Any] | None = None,
) -> ExtensionLaunch:
    """Pin one inspectable local command without executing extension code."""
    if manifest.isolation != "subprocess":
        raise FormatError("SOVA-EXTENSION-ISOLATION", "launch preparation requires subprocess")
    executable = executable.resolve()
    working_directory = working_directory.resolve()
    if not executable.is_file() or executable.is_symlink():
        raise FormatError("SOVA-EXTENSION-EXECUTABLE", "extension executable is unsafe")
    pins: list[PinnedArgumentFile] = []
    for index, argument in enumerate(arguments, start=1):
        candidate = _resolved_argument_path(argument, working_directory)
        if not candidate.exists():
            continue
        if not candidate.is_file() or candidate.is_symlink():
            raise FormatError("SOVA-EXTENSION-ARGUMENT-FILE", "argument file is unsafe")
        pins.append(PinnedArgumentFile(index, sha256_digest(candidate.read_bytes())))
    launch = ExtensionLaunch(
        manifest.digest,
        operation,
        (str(executable), *arguments),
        sha256_digest(executable.read_bytes()),
        tuple(pins),
        working_directory,
        timeout_seconds,
        {} if payload is None else payload,
    )
    _verify_launch_files(launch)
    return launch


def run_extension_workflow(
    manifest: ExtensionManifest,
    launch: ExtensionLaunch,
    destination: Path,
    *,
    approval_prompt: ExtensionApprovalPrompt,
) -> ExtensionWorkflowArtifacts:
    """Run one exact local extension process after a digest-bound human approval."""
    if manifest.digest != launch.manifest_digest:
        raise FormatError("SOVA-EXTENSION-SUBSTITUTION", "launch manifest digest does not match")
    if manifest.isolation != "subprocess":
        raise FormatError("SOVA-EXTENSION-ISOLATION", "operator workflow requires subprocess")
    if destination.exists() and (destination.is_symlink() or not destination.is_dir()):
        raise FormatError("SOVA-EXTENSION-DESTINATION", "destination is not a safe directory")
    destination = destination.resolve()
    if destination.exists() and any(destination.iterdir()):
        raise FormatError("SOVA-EXTENSION-DESTINATION", "destination is not empty")
    verified_files = _verify_launch_files(launch)
    challenge = _approval(manifest, launch, verified_files)
    _require_approval(approval_prompt, challenge)
    if _approval(manifest, launch, verified_files).scope_digest != challenge.scope_digest:
        raise FormatError("SOVA-EXTENSION-DRIFT", "launch scope changed after approval")
    # Recheck every digest after approval and immediately before process creation.
    if _verify_launch_files(launch) != verified_files:
        raise FormatError("SOVA-EXTENSION-DRIFT", "launch files changed after approval")
    destination.mkdir(parents=True, exist_ok=True)
    trace_path = destination / "extension.sova-trace"
    report_path = destination / "report.json"
    signing_key = generate_ed25519_keypair()
    writer = TraceWriter(
        trace_path,
        capture_profile="standard",
        content_capture="metadata-only",
        signing_key=signing_key,
        authorization={
            "decision": "allowed",
            "scopeDigest": challenge.scope_digest,
            "decidedBy": "exact-human-extension-launch-approval",
        },
        executor={
            "id": f"sova:extension:{manifest.identifier}",
            "name": "allowlisted-subprocess-extension",
            "version": manifest.version,
            "capabilityDigest": sha256_digest(
                canonical_json_bytes(
                    {
                        "capabilities": list(manifest.capabilities),
                        "sideEffects": list(manifest.side_effects),
                    }
                )
            ),
        },
    )
    parent = writer.append(
        "run.started",
        {
            "manifestDigest": manifest.digest,
            "launchDigest": launch.digest,
            "operation": launch.operation,
            "securitySandbox": False,
        },
    )
    runner = SubprocessExtensionRunner(
        manifest,
        launch.command,
        executable_allowlist=(Path(launch.command[0]),),
        working_directory=launch.working_directory,
        timeout_seconds=float(launch.timeout_seconds),
    )
    operations = ("describe", "self-test") if launch.operation == "conform" else (launch.operation,)
    results: list[dict[str, Any]] = []
    try:
        for operation in operations:
            requested = writer.append(
                "process.requested",
                {
                    "operation": operation,
                    "commandDigest": sha256_digest(canonical_json_bytes(list(launch.command))),
                    "payloadDigest": sha256_digest(canonical_json_bytes(launch.payload)),
                    "extensionAuthorityInherited": False,
                },
                parents=[parent] if parent else [],
            )
            result = runner.run(operation, launch.payload if operation == launch.operation else {})
            sanitized = _sanitized_result(result)
            results.append(sanitized)
            parent = writer.append(
                "process.completed",
                {
                    "operation": operation,
                    "responseDigest": sanitized["responseDigest"],
                    "accepted": sanitized["response"].get("accepted"),
                    "captureTimeRedactions": sanitized["captureTimeRedactions"],
                    "stderrTruncated": sanitized["stderrTruncated"],
                },
                parents=[requested] if requested else [],
            )
        status = (
            "pass"
            if results and all(row["response"].get("accepted") is True for row in results)
            else "fail"
        )
        writer.append(
            "run.completed",
            {"completion": "completed", "status": status, "operationCount": len(results)},
            parents=[parent] if parent else [],
        )
        writer.finalize()
    except Exception:
        with suppress(Exception):
            writer.append("run.failed", {"completion": "failed"})
            writer.finalize(completion="failed")
        raise
    TraceReader(trace_path).verify(require_signature=True)
    report: dict[str, Any] = {
        "artifactType": "sova.extension-workflow-report",
        "schemaVersion": "0.1.0",
        "status": status,
        "manifest": manifest.to_mapping(),
        "manifestDigest": manifest.digest,
        "launch": launch.to_mapping(),
        "launchDigest": launch.digest,
        "authorizationScopeDigest": challenge.scope_digest,
        "results": results,
        "trace": {
            "path": trace_path.name,
            "digest": sha256_digest(trace_path.read_bytes()),
            "signed": True,
        },
        "claims": {
            "exactExecutableDigestVerified": True,
            "allExistingFileArgumentsPinned": True,
            "sanitizedEnvironment": True,
            "shellUsed": False,
            "humanApproval": True,
            "extensionAuthorityInherited": False,
            "securitySandbox": False,
        },
        "limitations": [
            "The extension is an operator-selected host process, not contained untrusted code.",
            "Manifest capability and side-effect declarations are assertions, not observed truth.",
            "Signature integrity does not establish publisher identity or extension correctness.",
        ],
    }
    report["reportDigest"] = sha256_digest(canonical_json_bytes(report))
    report_path.write_bytes(canonical_json_bytes(report) + b"\n")
    return ExtensionWorkflowArtifacts(trace_path, report_path, status)


__all__ = [
    "ExtensionApproval",
    "ExtensionApprovalPrompt",
    "ExtensionLaunch",
    "ExtensionWorkflowArtifacts",
    "PinnedArgumentFile",
    "extension_launch_from_mapping",
    "prepare_extension_launch",
    "run_extension_workflow",
]
