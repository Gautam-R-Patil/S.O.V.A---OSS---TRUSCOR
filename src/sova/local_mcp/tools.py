# SPDX-License-Identifier: Apache-2.0
"""Local-only SOVA MCP tool schemas and fail-closed dispatch."""

from __future__ import annotations

import platform
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

from jsonschema import Draft202012Validator

from sova.community import verify_probe_response
from sova.forensics import reconstruct_trace
from sova.formats import canonical_json_bytes, sha256_digest, strict_json_loads
from sova.formats.errors import FormatError
from sova.local_mcp.model import InvocationDescriptor, LocalToolDefinition, manifest_document
from sova.mapping import build_capability_map
from sova.registry import verify_registry
from sova.rehearsal import run_rehearsal, specification_from_mapping
from sova.replay import verify_artifact
from sova.runtime import standard_profile
from sova.trace import TraceWriter, generate_ed25519_keypair
from sova.workflows import run_check, run_complete_demo

if TYPE_CHECKING:
    from sova.local_mcp.approval import LocalApprovalStore

_OBJECT_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "additionalProperties": True,
}
_RESULT_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "required": ["artifactType"],
    "properties": {"artifactType": {"type": "string"}},
    "additionalProperties": True,
}
_MAX_SEARCH_RESULTS = 100
# This release pin must be reviewed and updated intentionally when any public tool contract changes.
PINNED_TOOL_MANIFEST_DIGEST = (
    "sha256:966d1622ac8a089b77c53eb565014c46bf5290a765cdec3e32a55370ea0adfe7"
)


def _schema(properties: dict[str, Any], required: tuple[str, ...] = ()) -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": properties,
        "required": list(required),
        "additionalProperties": False,
    }


LOCAL_TOOL_DEFINITIONS = (
    LocalToolDefinition(
        "sova.map",
        "Map declared capability reach inside the server-pinned local workspace; "
        "never execute target code.",
        _schema({"root": {"type": "string", "default": "."}}),
        _RESULT_SCHEMA,
        read_only=True,
        destructive=False,
        open_world=False,
        gated=False,
        side_effects=("reads-pinned-workspace", "emits-local-trace"),
    ),
    LocalToolDefinition(
        "sova.check",
        "Run a bounded self-owned check and return an explicit non-clean assurance state.",
        _schema(
            {
                "target": {"type": "string"},
                "output": {"type": "string"},
            },
            ("target", "output"),
        ),
        _RESULT_SCHEMA,
        read_only=False,
        destructive=False,
        open_world=False,
        gated=False,
        side_effects=("writes-evidence-only", "does-not-mutate-target"),
    ),
    LocalToolDefinition(
        "sova.verify",
        "Verify one local SOVA capsule or trace offline.",
        _schema({"path": {"type": "string"}}, ("path",)),
        _RESULT_SCHEMA,
        read_only=True,
        destructive=False,
        open_world=False,
        gated=False,
        side_effects=("reads-one-local-artifact", "emits-local-trace"),
    ),
    LocalToolDefinition(
        "sova.forensics",
        "Reconstruct an uncertainty-preserving timeline from one verified local trace.",
        _schema({"trace": {"type": "string"}}, ("trace",)),
        _RESULT_SCHEMA,
        read_only=True,
        destructive=False,
        open_world=False,
        gated=False,
        side_effects=("reads-one-local-trace", "emits-local-trace"),
    ),
    LocalToolDefinition(
        "sova.registry.search",
        "Search a verified local registry index without network access or execution.",
        _schema(
            {
                "registry": {"type": "string"},
                "query": {"type": "string", "default": ""},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20},
            },
            ("registry",),
        ),
        _RESULT_SCHEMA,
        read_only=True,
        destructive=False,
        open_world=False,
        gated=False,
        side_effects=("reads-verified-local-registry", "no-network"),
    ),
    LocalToolDefinition(
        "sova.detonate",
        "Execute only an explicitly approved self-owned detonation; the reference backend "
        "accepts the bundled sleeper fixture only.",
        _schema(
            {
                "target": {"type": "string"},
                "output": {"type": "string"},
                "approvalChallengeId": {"type": "string"},
            },
            ("target", "output"),
        ),
        _RESULT_SCHEMA,
        read_only=False,
        destructive=True,
        open_world=False,
        gated=True,
        side_effects=("offensive-execution", "writes-evidence", "self-owned-fixture-only"),
    ),
    LocalToolDefinition(
        "sova.rehearse",
        "Execute an exact reviewed rehearsal only inside a prepared substitute workspace.",
        _schema(
            {
                "specification": _OBJECT_SCHEMA,
                "workspace": {"type": "string"},
                "trace": {"type": "string"},
                "approvalChallengeId": {"type": "string"},
            },
            ("specification", "workspace", "trace"),
        ),
        _RESULT_SCHEMA,
        read_only=False,
        destructive=True,
        open_world=False,
        gated=True,
        side_effects=("substitute-workspace-mutation", "writes-evidence"),
    ),
    LocalToolDefinition(
        "sova.probe",
        "Verify a supplied probe response or run limited conformance only after exact approval.",
        _schema(
            {
                "response": {"type": "string"},
                "mode": {"type": "string", "enum": ["verify", "conformance"]},
                "expectedNonce": {"type": "string", "minLength": 1},
                "expectedScope": {
                    "type": "array",
                    "minItems": 1,
                    "uniqueItems": True,
                    "items": {"type": "string", "minLength": 1},
                },
                "requiredKeyId": {
                    "type": "string",
                    "pattern": "^sha256:[0-9a-f]{64}$",
                },
                "approvalChallengeId": {"type": "string"},
            },
            ("response", "mode", "expectedNonce", "expectedScope"),
        ),
        _RESULT_SCHEMA,
        read_only=False,
        destructive=True,
        open_world=True,
        gated=True,
        side_effects=("may-touch-third-party", "writes-evidence"),
    ),
)


@dataclass(frozen=True, slots=True)
class LocalToolContext:
    workspace: Path
    evidence: Path
    approval_store: LocalApprovalStore
    sensitive_mapping_allowed: bool = False

    def __post_init__(self) -> None:
        if not self.workspace.resolve().is_dir():
            raise FormatError("SOVA-LOCAL-MCP-WORKSPACE", "workspace must exist")
        self.evidence.resolve().mkdir(parents=True, exist_ok=True)


def _relative_path(root: Path, value: Any, *, must_exist: bool = False) -> Path:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise FormatError("SOVA-LOCAL-MCP-PATH", "path must be a relative POSIX string")
    candidate = PurePosixPath(value)
    if value != "." and (
        candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        raise FormatError("SOVA-LOCAL-MCP-PATH", "path escapes the pinned workspace")
    resolved = (root / Path(*candidate.parts)).resolve() if value != "." else root.resolve()
    if resolved != root.resolve() and root.resolve() not in resolved.parents:
        raise FormatError("SOVA-LOCAL-MCP-PATH", "path escapes the pinned workspace")
    if must_exist and not resolved.exists():
        raise FormatError("SOVA-LOCAL-MCP-PATH", "referenced path does not exist")
    return resolved


def _trace(
    context: LocalToolContext,
    tool: str,
    status: str,
    payload: dict[str, Any],
) -> str:
    destination = context.evidence / f"mcp-{secrets.token_hex(12)}.sova-trace"
    writer = TraceWriter(
        destination,
        signing_key=generate_ed25519_keypair(),
        authorization={
            "decision": status,
            "scopeDigest": sha256_digest(canonical_json_bytes({"tool": tool, **payload})),
            "decidedBy": "sova.local-mcp-control/0.1",
        },
        environment={
            "platform": platform.platform(),
            "python": platform.python_version(),
            "codeDigest": None,
            "model": None,
            "dependencies": [],
        },
        executor={
            "id": "sova:executor:local-mcp",
            "name": "sova-local-mcp",
            "version": "0.1.0",
            "capabilityDigest": None,
        },
    )
    started = writer.append("run.started", {"tool": tool, "transport": "stdio"})
    writer.append(
        "authorization.decision",
        {"tool": tool, "decision": status, **payload},
        parents=[started] if started else [],
    )
    writer.append(
        "run.completed" if status == "allowed" else "run.failed",
        {"tool": tool, "completion": status},
    )
    writer.finalize(completion="completed" if status == "allowed" else "failed")
    return str(destination)


def _string(arguments: dict[str, Any], name: str) -> str:
    value = arguments.get(name)
    if not isinstance(value, str) or not value:
        raise FormatError("SOVA-LOCAL-MCP-ARGUMENT", f"{name} must be a non-empty string")
    return value


def _invocation(tool: str, arguments: dict[str, Any]) -> InvocationDescriptor:
    public_arguments = {
        key: value for key, value in arguments.items() if key != "approvalChallengeId"
    }
    target = str(
        public_arguments.get("target")
        or public_arguments.get("workspace")
        or public_arguments.get("response")
        or "unknown"
    )
    return InvocationDescriptor(
        tool,
        public_arguments,
        target,
        ("exact-tool", "exact-arguments", "self-owned-target"),
        (tool,),
        {"maxInvocations": 1, "maxDurationSeconds": 300, "scopeWidening": False},
        300,
        (
            "prompt injection may attempt to widen scope",
            "tool execution may produce local side effects",
            "authorization does not establish target safety",
        ),
    )


def _registry_search(context: LocalToolContext, arguments: dict[str, Any]) -> dict[str, Any]:
    root = _relative_path(context.workspace, _string(arguments, "registry"), must_exist=True)
    verification = verify_registry(root)
    index = strict_json_loads((root / "index.json").read_bytes())
    if not isinstance(index, dict) or not isinstance(index.get("index"), dict):
        raise FormatError("SOVA-LOCAL-MCP-REGISTRY", "registry index is malformed")
    entries = index["index"].get("entries")
    if not isinstance(entries, list):
        raise FormatError("SOVA-LOCAL-MCP-REGISTRY", "registry entries are malformed")
    query = str(arguments.get("query", "")).casefold()
    limit = arguments.get("limit", 20)
    if (
        not isinstance(limit, int)
        or isinstance(limit, bool)
        or not 1 <= limit <= _MAX_SEARCH_RESULTS
    ):
        raise FormatError("SOVA-LOCAL-MCP-LIMIT", "registry search limit is invalid")
    matches = [
        entry for entry in entries if query in canonical_json_bytes(entry).decode().casefold()
    ]
    return {
        "artifactType": "sova.registry-search-result",
        "schemaVersion": "0.1.0",
        "verification": verification,
        "query": query,
        "matches": matches[:limit],
        "truncated": len(matches) > limit,
        "networkUsed": False,
    }


def _safe_dispatch(
    context: LocalToolContext, tool: str, arguments: dict[str, Any]
) -> dict[str, Any]:
    if tool == "sova.map":
        if not context.sensitive_mapping_allowed:
            raise FormatError(
                "SOVA-LOCAL-MCP-MAP-CONSENT",
                "server was not launched with sensitive workspace mapping consent",
            )
        root = _relative_path(context.workspace, str(arguments.get("root", ".")), must_exist=True)
        result = build_capability_map(root).to_mapping()
    elif tool == "sova.check":
        target = _string(arguments, "target")
        output = _relative_path(context.workspace, _string(arguments, "output"))
        result = run_check(target, output, profile=standard_profile()).to_mapping()
    elif tool == "sova.verify":
        path = _relative_path(context.workspace, _string(arguments, "path"), must_exist=True)
        result = verify_artifact(path).to_mapping()
    elif tool == "sova.forensics":
        path = _relative_path(context.workspace, _string(arguments, "trace"), must_exist=True)
        result = reconstruct_trace(path).to_mapping()
    elif tool == "sova.registry.search":
        result = _registry_search(context, arguments)
    else:
        raise FormatError("SOVA-LOCAL-MCP-TOOL", "unknown safe MCP tool")
    trace_path = _trace(context, tool, "allowed", {"gated": False})
    return {"artifactType": "sova.mcp-tool-result", "result": result, "trace": trace_path}


def _gated_dispatch(
    context: LocalToolContext, tool: str, arguments: dict[str, Any]
) -> dict[str, Any]:
    invocation = _invocation(tool, arguments)
    challenge_id = arguments.get("approvalChallengeId")
    if challenge_id is None:
        challenge = context.approval_store.challenge(invocation)
        trace_path = _trace(
            context,
            tool,
            "denied",
            {
                "reason": "challenge-required",
                "invocationDigest": invocation.digest,
                "challengeId": challenge["challengeId"],
            },
        )
        return {
            "artifactType": "sova.mcp-authorization-required",
            "executed": False,
            "challenge": challenge,
            "trace": trace_path,
        }
    if not isinstance(challenge_id, str):
        raise FormatError("SOVA-LOCAL-MCP-CHALLENGE", "approvalChallengeId must be a string")
    decision = context.approval_store.consume(challenge_id, invocation)
    if tool == "sova.detonate":
        if _string(arguments, "target") not in {"sleeper", "synthetic-sleeper"}:
            raise FormatError(
                "SOVA-LOCAL-MCP-DETONATE-TARGET",
                "reference MCP detonation accepts only the bundled self-owned sleeper",
            )
        output = _relative_path(context.workspace, _string(arguments, "output"))
        artifacts = run_complete_demo(output, profile=standard_profile())
        result = {
            "artifactType": "sova.mcp-detonation-result",
            "capsule": str(artifacts.capsule),
            "trace": str(artifacts.trace),
            "reproduced": artifacts.reproduced,
            "safeOrCleanClaim": False,
        }
    elif tool == "sova.rehearse":
        specification = arguments.get("specification")
        if not isinstance(specification, dict):
            raise FormatError("SOVA-LOCAL-MCP-REHEARSE", "specification must be an object")
        workspace = _relative_path(
            context.workspace, _string(arguments, "workspace"), must_exist=True
        )
        trace = _relative_path(context.workspace, _string(arguments, "trace"))
        result = run_rehearsal(
            specification_from_mapping(specification), workspace, trace
        ).to_mapping()
    else:
        response_path = _relative_path(
            context.workspace, _string(arguments, "response"), must_exist=True
        )
        document = strict_json_loads(response_path.read_bytes())
        if not isinstance(document, dict):
            raise FormatError("SOVA-LOCAL-MCP-PROBE", "probe response must be an object")
        expected_scope = arguments.get("expectedScope")
        if not isinstance(expected_scope, list) or not all(
            isinstance(item, str) for item in expected_scope
        ):
            raise FormatError("SOVA-LOCAL-MCP-PROBE", "expectedScope must be strings")
        result = verify_probe_response(
            document,
            expected_nonce=_string(arguments, "expectedNonce"),
            expected_scope=expected_scope,
            required_key_id=(
                str(arguments["requiredKeyId"])
                if arguments.get("requiredKeyId") is not None
                else None
            ),
            now=datetime.now(UTC),
        )
        result["mode"] = arguments["mode"]
        result["networkUsed"] = False
        if arguments["mode"] == "conformance":
            result["conformanceBoundary"] = "signed-response-contract-only"
    trace_path = _trace(
        context,
        tool,
        "allowed",
        {"gated": True, "authorization": decision, "invocationDigest": invocation.digest},
    )
    return {
        "artifactType": "sova.mcp-tool-result",
        "executed": True,
        "authorization": decision,
        "result": result,
        "trace": trace_path,
    }


def dispatch_local_tool(
    context: LocalToolContext, tool: str, arguments: dict[str, Any]
) -> dict[str, Any]:
    definition = next((item for item in LOCAL_TOOL_DEFINITIONS if item.name == tool), None)
    if definition is None:
        raise FormatError("SOVA-LOCAL-MCP-TOOL", "unknown local MCP tool")
    errors = sorted(
        Draft202012Validator(definition.input_schema).iter_errors(arguments),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        raise FormatError(
            "SOVA-LOCAL-MCP-ARGUMENT-SCHEMA",
            "tool arguments do not match the pinned manifest schema",
            details={"errorCount": len(errors)},
        )
    return (
        _gated_dispatch(context, tool, arguments)
        if definition.gated
        else _safe_dispatch(context, tool, arguments)
    )


def tool_manifest() -> dict[str, Any]:
    return manifest_document(LOCAL_TOOL_DEFINITIONS)


def manifest_self_check() -> dict[str, Any]:
    manifest = tool_manifest()
    gated = {"sova.detonate", "sova.rehearse", "sova.probe"}
    names = {str(tool["name"]) for tool in manifest["tools"]}
    gates_correct = all(
        bool(tool["_meta"]["sova/gated"]) for tool in manifest["tools"] if tool["name"] in gated
    )
    pin_matches = manifest["manifestDigest"] == PINNED_TOOL_MANIFEST_DIGEST
    return {
        "artifactType": "sova.mcp-self-check",
        "schemaVersion": "0.1.0",
        "accepted": pin_matches and gates_correct and "sova.approve" not in names,
        "manifestDigest": manifest["manifestDigest"],
        "pinnedManifestDigest": PINNED_TOOL_MANIFEST_DIGEST,
        "manifestPinMatches": pin_matches,
        "gatedTools": sorted(gated),
        "approvalToolExposed": "sova.approve" in names,
        "hostedDependency": False,
    }


__all__ = [
    "LOCAL_TOOL_DEFINITIONS",
    "PINNED_TOOL_MANIFEST_DIGEST",
    "LocalToolContext",
    "dispatch_local_tool",
    "manifest_self_check",
    "tool_manifest",
]
