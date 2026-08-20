# SPDX-License-Identifier: Apache-2.0
"""Digest-pinned external agent protocol executed only through gVisor OCI isolation."""

from __future__ import annotations

import hmac
import re
from collections.abc import Callable
from contextlib import suppress
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any

from sova.executors import (
    ActionRequest,
    CancellationToken,
    ExecutionContext,
    GVisorOciExecutor,
    OutcomeStatus,
)
from sova.formats import canonical_json_bytes, sha256_digest, strict_json_loads
from sova.formats.errors import FormatError
from sova.trace import Redactor, TraceReader, TraceWriter, generate_ed25519_keypair

if TYPE_CHECKING:
    from pathlib import Path

_PROTOCOL = "sova.oci-agent/0.1"
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{0,126}$")
_DIGEST_IMAGE = re.compile(r"^[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}$")
_MAX_PROMPT_BYTES = 48 * 1024
_MAX_RESPONSE_BYTES = 1024 * 1024
_MAX_TIMEOUT_SECONDS = 300
_MAX_ENTRYPOINT_CHARS = 1024
_MAX_TOKEN_COUNT = 10_000_000
_MIN_IO_BYTES = 1024


def _integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


@dataclass(frozen=True, slots=True)
class OciAgentRuntime:
    """Portable identity and resource contract for one sandboxed external agent image."""

    identifier: str
    image: str
    entrypoint: str
    runtime: str = "runsc"
    timeout_seconds: int = 60
    max_prompt_bytes: int = _MAX_PROMPT_BYTES
    max_response_bytes: int = _MAX_RESPONSE_BYTES

    def __post_init__(self) -> None:
        if _IDENTIFIER.fullmatch(self.identifier) is None:
            raise FormatError("SOVA-OCI-AGENT-ID", "OCI agent identifier is invalid")
        if _DIGEST_IMAGE.fullmatch(self.image) is None:
            raise FormatError(
                "SOVA-OCI-AGENT-IMAGE",
                "OCI agent image must be an exact repository@sha256 digest",
            )
        if (
            not self.entrypoint.startswith("/")
            or "\\" in self.entrypoint
            or "\x00" in self.entrypoint
            or len(self.entrypoint) > _MAX_ENTRYPOINT_CHARS
        ):
            raise FormatError(
                "SOVA-OCI-AGENT-ENTRYPOINT",
                "OCI agent entrypoint must be a bounded absolute POSIX path",
            )
        if self.runtime != "runsc":
            raise FormatError(
                "SOVA-OCI-AGENT-RUNTIME",
                "OCI agent isolation requires the Docker runtime name to be exactly runsc",
            )
        if (
            not _integer(self.timeout_seconds)
            or not 1 <= self.timeout_seconds <= _MAX_TIMEOUT_SECONDS
        ):
            raise FormatError("SOVA-OCI-AGENT-BUDGET", "OCI agent timeout is invalid")
        if (
            not _integer(self.max_prompt_bytes)
            or not _MIN_IO_BYTES <= self.max_prompt_bytes <= _MAX_PROMPT_BYTES
        ):
            raise FormatError("SOVA-OCI-AGENT-BUDGET", "OCI agent prompt budget is invalid")
        if (
            not _integer(self.max_response_bytes)
            or not _MIN_IO_BYTES <= self.max_response_bytes <= _MAX_RESPONSE_BYTES
        ):
            raise FormatError("SOVA-OCI-AGENT-BUDGET", "OCI agent response budget is invalid")

    @property
    def digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.to_mapping()))

    def to_mapping(self) -> dict[str, Any]:
        return {
            "artifactType": "sova.oci-agent-runtime",
            "schemaVersion": "0.1.0",
            "id": self.identifier,
            "image": self.image,
            "entrypoint": self.entrypoint,
            "runtime": self.runtime,
            "budgets": {
                "timeoutSeconds": self.timeout_seconds,
                "maxPromptBytes": self.max_prompt_bytes,
                "maxResponseBytes": self.max_response_bytes,
            },
            "security": {
                "network": "none",
                "credentials": "none",
                "hostMounts": "none",
                "rootFilesystem": "read-only",
                "requiredIsolation": "gvisor-runsc",
            },
        }


def oci_agent_runtime_from_mapping(value: dict[str, Any]) -> OciAgentRuntime:
    """Parse one exact-field external-agent runtime document."""
    if set(value) != {
        "artifactType",
        "schemaVersion",
        "id",
        "image",
        "entrypoint",
        "runtime",
        "budgets",
        "security",
    }:
        raise FormatError("SOVA-OCI-AGENT-FIELDS", "OCI agent runtime fields are invalid")
    if (
        value.get("artifactType") != "sova.oci-agent-runtime"
        or value.get("schemaVersion") != "0.1.0"
    ):
        raise FormatError("SOVA-OCI-AGENT-VERSION", "OCI agent runtime version is unsupported")
    budgets = value.get("budgets")
    security = value.get("security")
    if not isinstance(budgets, dict) or set(budgets) != {
        "timeoutSeconds",
        "maxPromptBytes",
        "maxResponseBytes",
    }:
        raise FormatError("SOVA-OCI-AGENT-BUDGET", "OCI agent budgets are invalid")
    expected_security = {
        "network": "none",
        "credentials": "none",
        "hostMounts": "none",
        "rootFilesystem": "read-only",
        "requiredIsolation": "gvisor-runsc",
    }
    if security != expected_security:
        raise FormatError(
            "SOVA-OCI-AGENT-SECURITY",
            "OCI agent runtime must require the fail-closed gVisor profile",
        )
    strings = (
        value.get("id"),
        value.get("image"),
        value.get("entrypoint"),
        value.get("runtime"),
    )
    if any(not isinstance(item, str) for item in strings) or any(
        not _integer(budgets.get(name)) for name in budgets
    ):
        raise FormatError("SOVA-OCI-AGENT-FIELDS", "OCI agent runtime values are invalid")
    return OciAgentRuntime(
        str(strings[0]),
        str(strings[1]),
        str(strings[2]),
        str(strings[3]),
        int(budgets["timeoutSeconds"]),
        int(budgets["maxPromptBytes"]),
        int(budgets["maxResponseBytes"]),
    )


@dataclass(frozen=True, slots=True)
class OciAgentResponse:
    """Observable response satisfying SOVA's tool-free role-model protocol."""

    response_text: str
    structured: dict[str, Any]
    token_count: int | None
    tool_calls: tuple[dict[str, Any], ...] = ()
    monetary_cost: str | None = None
    resolved_model_id: str | None = None


@dataclass(frozen=True, slots=True)
class OciAgentInvocation:
    """One protocol-bound result from the isolated image."""

    operation: str
    accepted: bool
    response: dict[str, Any]
    attestation_digest: str
    execution_verification: str

    def to_mapping(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class OciAgentApproval:
    """Digest-bound approval challenge for executing one external agent image."""

    scope_digest: str
    exact_phrase: str
    summary: dict[str, Any]


OciAgentApprovalPrompt = Callable[[OciAgentApproval], str]


@dataclass(frozen=True, slots=True)
class OciAgentConformanceArtifacts:
    """Signed conformance evidence for one isolated external-agent image."""

    runtime: Path
    report: Path
    trace: Path
    status: str


class GVisorOciAgentAdapter:
    """Invoke one arbitrary agent image without granting it host or target authority."""

    def __init__(
        self,
        runtime: OciAgentRuntime,
        executor: GVisorOciExecutor,
        workspace: Path,
    ) -> None:
        if runtime.runtime != "runsc" or executor.attestation.runtime != "runsc":
            raise FormatError(
                "SOVA-OCI-AGENT-RUNTIME",
                "external agents require an attested Docker runtime named exactly runsc",
            )
        if not executor.attestation.ready:
            raise FormatError(
                "SOVA-OCI-AGENT-NOT-ATTESTED",
                "external agent requires a ready gVisor runtime and cached image digest",
            )
        if executor.attestation.image != runtime.image:
            raise FormatError(
                "SOVA-OCI-AGENT-SUBSTITUTION",
                "gVisor executor image does not match the agent runtime",
            )
        if executor.attestation.runtime != runtime.runtime:
            raise FormatError(
                "SOVA-OCI-AGENT-SUBSTITUTION",
                "gVisor executor runtime does not match the agent runtime",
            )
        self.runtime = runtime
        self.executor = executor
        self.workspace = workspace.resolve()

    @property
    def model_id(self) -> str:
        image_digest = self.runtime.image.rsplit("@", 1)[1]
        attestation = self.executor.attestation.digest.removeprefix("sha256:")
        return (
            f"oci-agent:{self.runtime.identifier}:{image_digest}:"
            f"{self.runtime.runtime}:{attestation}"
        )

    def invoke(self, operation: str, payload: dict[str, Any]) -> OciAgentInvocation:
        if operation not in {"describe", "self-test", "respond"}:
            raise FormatError("SOVA-OCI-AGENT-OPERATION", "OCI agent operation is unsupported")
        request = {
            "protocol": _PROTOCOL,
            "runtimeDigest": self.runtime.digest,
            "operation": operation,
            "payload": payload,
        }
        request_bytes = canonical_json_bytes(request)
        if len(request_bytes) > self.runtime.max_prompt_bytes:
            raise FormatError("SOVA-OCI-AGENT-PROMPT-LIMIT", "OCI agent request exceeds budget")
        _redacted, disclosures = Redactor(context_id="sova-oci-agent-input").redact(request)
        if disclosures:
            raise FormatError(
                "SOVA-OCI-AGENT-SENSITIVE-INPUT",
                "credential-shaped material cannot enter an external agent image",
            )
        if not self.workspace.is_dir():
            raise FormatError("SOVA-OCI-AGENT-WORKSPACE", "agent evidence workspace is missing")
        outcome = self.executor.execute(
            ActionRequest(
                f"oci-agent-{operation}",
                "process.exec",
                {
                    "argv": [
                        self.runtime.entrypoint,
                        "--sova-request-stdin",
                    ],
                    "stdin": request_bytes.decode("utf-8"),
                },
                float(self.runtime.timeout_seconds),
            ),
            ExecutionContext(
                self.workspace,
                {
                    "decision": "allowed",
                    "scopeDigest": self.runtime.digest,
                    "targetAuthorityInherited": False,
                    "credentialsImported": False,
                },
            ),
            CancellationToken(),
        )
        if outcome.status != OutcomeStatus.SUCCEEDED:
            raise FormatError(
                "SOVA-OCI-AGENT-EXECUTION",
                "isolated OCI agent execution failed",
                details={"status": outcome.status.value, "errorCode": outcome.error_code},
            )
        raw = outcome.output.get("stdout")
        if not isinstance(raw, str) or len(raw.encode("utf-8")) > self.runtime.max_response_bytes:
            raise FormatError("SOVA-OCI-AGENT-OUTPUT-LIMIT", "OCI agent output is invalid")
        rows = raw.splitlines()
        if len(rows) != 1:
            raise FormatError(
                "SOVA-OCI-AGENT-PROTOCOL",
                "OCI agent must return exactly one JSON row",
            )
        response = strict_json_loads(
            rows[0].encode("utf-8"),
            max_bytes=self.runtime.max_response_bytes,
        )
        if not isinstance(response, dict) or set(response) != {
            "protocol",
            "runtimeDigest",
            "operation",
            "accepted",
            "response",
        }:
            raise FormatError("SOVA-OCI-AGENT-PROTOCOL", "OCI agent response fields are invalid")
        if (
            response.get("protocol") != _PROTOCOL
            or response.get("runtimeDigest") != self.runtime.digest
            or response.get("operation") != operation
            or not isinstance(response.get("accepted"), bool)
            or not isinstance(response.get("response"), dict)
        ):
            raise FormatError(
                "SOVA-OCI-AGENT-SUBSTITUTION",
                "OCI agent response binding failed",
            )
        return OciAgentInvocation(
            operation,
            bool(response["accepted"]),
            dict(response["response"]),
            str(outcome.output["attestationDigest"]),
            outcome.verification,
        )

    def conform(self) -> dict[str, Any]:
        described = self.invoke("describe", {})
        tested = self.invoke("self-test", {})
        description = described.response
        self_test = tested.response
        if set(description) != {"agentId", "operations", "capabilities"}:
            raise FormatError(
                "SOVA-OCI-AGENT-DESCRIBE",
                "OCI agent describe response fields are invalid",
            )
        operations = description.get("operations")
        capabilities = description.get("capabilities")
        if (
            description.get("agentId") != self.runtime.identifier
            or not isinstance(operations, list)
            or set(operations) != {"describe", "self-test", "respond"}
            or not isinstance(capabilities, list)
            or not capabilities
            or not all(isinstance(item, str) and item for item in capabilities)
            or self_test != {"status": "pass"}
            or not described.accepted
            or not tested.accepted
        ):
            raise FormatError("SOVA-OCI-AGENT-CONFORMANCE", "OCI agent conformance failed")
        return {
            "artifactType": "sova.oci-agent-conformance",
            "schemaVersion": "0.1.0",
            "status": "pass",
            "runtimeDigest": self.runtime.digest,
            "agentId": self.runtime.identifier,
            "capabilities": capabilities,
            "attestationDigest": described.attestation_digest,
            "isolation": "gvisor-runsc-user-kernel",
            "network": "none",
            "credentialsImported": False,
            "hostMounts": False,
            "targetAuthorityInherited": False,
        }

    def respond(self, prompt: str) -> OciAgentResponse:
        invocation = self.invoke("respond", {"prompt": prompt})
        if not invocation.accepted or set(invocation.response) != {
            "responseText",
            "structured",
            "tokenCount",
        }:
            raise FormatError("SOVA-OCI-AGENT-RESPONSE", "OCI agent response is invalid")
        text = invocation.response.get("responseText")
        structured = invocation.response.get("structured")
        tokens = invocation.response.get("tokenCount")
        if (
            not isinstance(text, str)
            or not isinstance(structured, dict)
            or (
                tokens is not None and (not _integer(tokens) or not 0 <= tokens <= _MAX_TOKEN_COUNT)
            )
        ):
            raise FormatError("SOVA-OCI-AGENT-RESPONSE", "OCI agent response values are invalid")
        return OciAgentResponse(
            text,
            structured,
            None if tokens is None else int(tokens),
            resolved_model_id=self.model_id,
        )


def _approval(
    runtime: OciAgentRuntime,
    executor: GVisorOciExecutor,
    *,
    use_scope: dict[str, Any],
) -> OciAgentApproval:
    summary = {
        "runtime": runtime.to_mapping(),
        "runtimeDigest": runtime.digest,
        "attestation": executor.attestation.to_mapping(),
        "useScope": use_scope,
        "authority": {
            "network": "none",
            "credentialsImported": False,
            "hostMounts": False,
            "targetAuthorityInherited": False,
        },
        "warning": (
            "This executes operator-selected native code inside an attested gVisor user-kernel "
            "container. gVisor reduces host-kernel exposure but is not a microVM or a proof that "
            "container escape is impossible."
        ),
    }
    scope_digest = sha256_digest(canonical_json_bytes(summary))
    return OciAgentApproval(
        scope_digest,
        f"AUTHORIZE SOVA OCI AGENT {scope_digest[7:23]}",
        summary,
    )


def authorize_oci_agent_adapter(
    runtime: OciAgentRuntime,
    executor: GVisorOciExecutor,
    workspace: Path,
    *,
    use_scope: dict[str, Any],
    approval_prompt: OciAgentApprovalPrompt,
) -> GVisorOciAgentAdapter:
    """Bind one ready adapter to an explicit, digest-stable operator-approved use scope."""
    if not use_scope:
        raise FormatError("SOVA-OCI-AGENT-SCOPE", "external-agent use scope is required")
    _redacted, disclosures = Redactor(context_id="sova-oci-agent-use-scope").redact(use_scope)
    if disclosures:
        raise FormatError(
            "SOVA-OCI-AGENT-SCOPE",
            "external-agent use scope contains credential-shaped material",
        )
    challenge = _approval(runtime, executor, use_scope=use_scope)
    response = approval_prompt(challenge)
    if not isinstance(response, str) or not hmac.compare_digest(response, challenge.exact_phrase):
        raise FormatError(
            "SOVA-OCI-AGENT-APPROVAL",
            "exact external-agent execution approval was not granted",
        )
    # Re-attest immediately after the human decision. Runtime registration and
    # cached-image state are external mutable inputs, so the pre-approval
    # executor must never be carried into execution unchanged.
    refreshed = executor.reattest()
    if _approval(runtime, refreshed, use_scope=use_scope).scope_digest != challenge.scope_digest:
        raise FormatError(
            "SOVA-OCI-AGENT-DRIFT",
            "external-agent isolation scope changed after approval",
        )
    return GVisorOciAgentAdapter(runtime, refreshed, workspace)


def run_oci_agent_conformance(
    runtime: OciAgentRuntime,
    docker_executable: Path,
    destination: Path,
    *,
    approval_prompt: OciAgentApprovalPrompt,
) -> OciAgentConformanceArtifacts:
    """Execute describe/self-test only after attestation and exact human approval."""
    destination = destination.resolve()
    if destination.exists() and (
        destination.is_symlink() or not destination.is_dir() or any(destination.iterdir())
    ):
        raise FormatError(
            "SOVA-OCI-AGENT-DESTINATION",
            "OCI agent conformance destination must be an empty real directory",
        )
    first = GVisorOciExecutor(
        docker_executable,
        runtime.image,
        runtime=runtime.runtime,
    )
    if not first.attestation.ready:
        raise FormatError(
            "SOVA-OCI-AGENT-NOT-ATTESTED",
            "external agent requires a ready gVisor runtime and cached image digest",
        )
    use_scope = {"purpose": "agent-protocol-conformance"}
    challenge = _approval(runtime, first, use_scope=use_scope)
    response = approval_prompt(challenge)
    if not isinstance(response, str) or not hmac.compare_digest(response, challenge.exact_phrase):
        raise FormatError(
            "SOVA-OCI-AGENT-APPROVAL",
            "exact external-agent execution approval was not granted",
        )
    # Re-attest immediately after approval to reject runtime/image drift.
    executor = GVisorOciExecutor(
        docker_executable,
        runtime.image,
        runtime=runtime.runtime,
    )
    if _approval(runtime, executor, use_scope=use_scope).scope_digest != challenge.scope_digest:
        raise FormatError(
            "SOVA-OCI-AGENT-DRIFT",
            "external-agent isolation scope changed after approval",
        )
    destination.mkdir(parents=True, exist_ok=True)
    runtime_path = destination / "runtime.json"
    report_path = destination / "report.json"
    trace_path = destination / "conformance.sova-trace"
    runtime_path.write_bytes(canonical_json_bytes(runtime.to_mapping()) + b"\n")
    writer = TraceWriter(
        trace_path,
        capture_profile="standard",
        content_capture="metadata-only",
        signing_key=generate_ed25519_keypair(),
        authorization={
            "decision": "allowed",
            "scopeDigest": challenge.scope_digest,
            "decidedBy": "exact-human-oci-agent-approval",
        },
        executor={
            "id": "sova:executor:gvisor-oci-agent",
            "name": "gvisor-runsc-external-agent",
            "version": "0.1.0",
            "capabilityDigest": executor.attestation.digest,
        },
    )
    parent = writer.append(
        "run.started",
        {
            "runtimeDigest": runtime.digest,
            "attestationDigest": executor.attestation.digest,
            "network": "none",
            "credentialsImported": False,
            "hostMounts": False,
            "targetAuthorityInherited": False,
        },
    )
    adapter = GVisorOciAgentAdapter(runtime, executor, destination)
    try:
        result = adapter.conform()
        writer.append(
            "x.sova.oci-agent.conformance",
            {
                "status": result["status"],
                "runtimeDigest": runtime.digest,
                "attestationDigest": executor.attestation.digest,
                "capabilities": result["capabilities"],
                "responseContentCaptured": False,
            },
            parents=[parent] if parent else [],
        )
        writer.append(
            "run.completed",
            {"completion": "completed", "status": "pass"},
        )
        writer.finalize()
    except Exception:
        with suppress(Exception):
            writer.append("run.failed", {"completion": "failed"})
            writer.finalize(completion="failed")
        raise
    TraceReader(trace_path).verify(require_signature=True)
    report = {
        **result,
        "runtime": runtime.to_mapping(),
        "authorizationScopeDigest": challenge.scope_digest,
        "trace": {
            "path": trace_path.name,
            "digest": sha256_digest(trace_path.read_bytes()),
            "signed": True,
        },
        "claims": {
            "digestPinnedImage": True,
            "gvisorAttestedBeforeAndAfterApproval": True,
            "networkDisabled": True,
            "credentialsImported": False,
            "hostMounts": False,
            "targetAuthorityInherited": False,
            "arbitraryBrowserToolsGranted": False,
        },
        "limitations": list(executor.attestation.limitations),
    }
    report["reportDigest"] = sha256_digest(canonical_json_bytes(report))
    report_path.write_bytes(canonical_json_bytes(report) + b"\n")
    return OciAgentConformanceArtifacts(runtime_path, report_path, trace_path, "pass")


__all__ = [
    "GVisorOciAgentAdapter",
    "OciAgentApproval",
    "OciAgentApprovalPrompt",
    "OciAgentConformanceArtifacts",
    "OciAgentInvocation",
    "OciAgentResponse",
    "OciAgentRuntime",
    "authorize_oci_agent_adapter",
    "oci_agent_runtime_from_mapping",
    "run_oci_agent_conformance",
]
