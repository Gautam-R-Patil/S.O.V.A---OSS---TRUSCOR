# SPDX-License-Identifier: Apache-2.0
"""Fail-closed codecs from untrusted model JSON to bounded action requests."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from sova.executors.contract import ActionRequest
from sova.formats import canonical_json_bytes, strict_json_loads
from sova.formats.errors import FormatError
from sova.live.semantic_workflow import (
    SemanticBrowserMission,
    semantic_browser_action_from_mapping,
)
from sova.trace import Redactor

_MAX_MODEL_OUTPUT_BYTES = 1024 * 1024
_MAX_PATH_BYTES = 512
_MAX_FILE_CONTENT_BYTES = 1024 * 1024
_MAX_ARGS = 64
_MAX_ARG_BYTES = 64 * 1024
_MAX_SINGLE_ARG_BYTES = 4096
_MAX_COMPUTER_TEXT_BYTES = 16 * 1024
_MAX_COMPUTER_LOCATOR_BYTES = 512
_MAX_COMPUTER_COORDINATE = 1_000_000
_CONTROL_CHARACTER_LIMIT = 32
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_COMPUTER_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_COMPUTER_ELEMENT_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,511}$")
_BROWSER_ACTION_CODEC_ID = "sova.action-codec.browser/0.1.0"
_COMPUTER_ACTION_CODEC_ID = "sova.action-codec.computer/0.1.0"
_OCI_PROCESS_ACTION_CODEC_ID = "sova.action-codec.oci-process/0.1.0"
_PROCESS_ACTION_CODEC_ID = "sova.action-codec.process/0.1.0"
_WORKSPACE_ACTION_CODEC_ID = "sova.action-codec.workspace/0.1.0"
_COMPUTER_MUTATIONS = frozenset(
    {"computer.click", "computer.type", "computer.scroll", "computer.drag", "computer.key"}
)
_COMPUTER_SCROLL_DIRECTIONS = frozenset({"up", "down", "left", "right"})
_MAX_COMPUTER_SCROLL_AMOUNT = 10_000
#: Conservative allowlist of non-text navigation/control keys. Extend deliberately;
#: text entry belongs in ``computer.type``, not here.
_COMPUTER_KEYS = frozenset(
    {
        "Enter",
        "Tab",
        "Escape",
        "Backspace",
        "Delete",
        "Space",
        "Home",
        "End",
        "PageUp",
        "PageDown",
        "ArrowUp",
        "ArrowDown",
        "ArrowLeft",
        "ArrowRight",
    }
)
_COMPUTER_MUTATION_FIELDS: dict[str, set[str]] = {
    "computer.click": {"targetRef"},
    "computer.type": {"targetRef", "text"},
    "computer.scroll": {"targetRef", "direction", "amount"},
    "computer.key": {"targetRef", "key"},
    "computer.drag": {"targetRef", "endTargetRef"},
}
_MAX_OCI_ARGS = 256
_MAX_OCI_ARG_BYTES = 64 * 1024
_MAX_OCI_STDIN_BYTES = 64 * 1024
_APPIUM_LOCATOR_STRATEGIES = frozenset({"accessibility id", "name", "class name", "id"})
_WORKSPACE_ACTION_FIELDS = {
    "filesystem.read": frozenset({"path"}),
    "filesystem.write": frozenset({"path", "content", "overwrite"}),
    "filesystem.delete": frozenset({"path"}),
    "filesystem.move": frozenset({"source", "destination", "overwrite"}),
}
_SENSITIVE_PATH = re.compile(
    r"(?i)(?:^|[/\\])(?:\.aws|\.azure|\.config|\.sova|\.ssh|cookies?|credentials?|"
    r"browser[-_]?profiles?|profiles?|secrets?|tokens?|user[-_]?data[-_]?dir)(?:[/\\]|$)|"
    r"sova-secret:"
)
_SHELL_EXECUTABLES = frozenset(
    {
        "bash",
        "bash.exe",
        "cmd",
        "cmd.exe",
        "command.com",
        "dash",
        "fish",
        "ksh",
        "powershell",
        "powershell.exe",
        "pwsh",
        "pwsh.exe",
        "sh",
        "sh.exe",
        "zsh",
    }
)
_WINDOWS_RESERVED = frozenset(
    {
        "aux",
        "clock$",
        "con",
        "nul",
        "prn",
        *(f"com{index}" for index in range(1, 10)),
        *(f"lpt{index}" for index in range(1, 10)),
    }
)


def _is_json_native(value: object) -> bool:
    if value is None or isinstance(value, (str, bool)):
        return True
    if isinstance(value, int) and not isinstance(value, bool):
        return True
    if isinstance(value, list):
        return all(_is_json_native(item) for item in value)
    if isinstance(value, dict):
        return all(isinstance(key, str) and _is_json_native(item) for key, item in value.items())
    return False


def _canonical_object(value: object, *, code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not _is_json_native(value):
        raise FormatError(code, "model action output must be one JSON-native object")
    encoded = canonical_json_bytes(value)
    if len(encoded) > _MAX_MODEL_OUTPUT_BYTES:
        raise FormatError(code, "model action output exceeds the 1 MiB encoded limit")
    parsed = strict_json_loads(encoded, max_bytes=_MAX_MODEL_OUTPUT_BYTES)
    if not isinstance(parsed, dict):  # pragma: no cover - narrowed above and by round trip
        raise FormatError(code, "model action output did not remain an object")
    return parsed


def _reject_sensitive_material(value: object, *, code: str) -> None:
    _redacted, disclosures = Redactor(context_id="sova-action-codec").redact(value)

    def strings(item: object) -> tuple[str, ...]:
        if isinstance(item, str):
            return (item,)
        if isinstance(item, list):
            return tuple(text for child in item for text in strings(child))
        if isinstance(item, dict):
            return tuple(text for child in item.values() for text in strings(child))
        return ()

    path_shaped = (
        text
        for text in strings(value)
        if any(mark in text for mark in ("/", "\\"))
        or text.startswith(".")
        or "sova-secret:" in text.casefold()
    )
    if disclosures or any(_SENSITIVE_PATH.search(text) for text in path_shaped):
        raise FormatError(code, "model action contains secret-shaped data or a secret/profile path")


def normalize_workspace_relative_path(value: object, *, allow_root: bool = False) -> str:
    """Return one exact portable relative path or fail before filesystem access."""
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        raise FormatError(
            "SOVA-WORKSPACE-PATH",
            "workspace path must be a non-empty portable relative string",
        )
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise FormatError("SOVA-WORKSPACE-PATH", "workspace path is not valid UTF-8") from error
    if len(encoded) > _MAX_PATH_BYTES:
        raise FormatError("SOVA-WORKSPACE-PATH", "workspace path exceeds 512 encoded bytes")
    path = PurePosixPath(value)
    normalized = path.as_posix()
    if (
        path.is_absolute()
        or value != normalized
        or (normalized == "." and not allow_root)
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise FormatError(
            "SOVA-WORKSPACE-PATH",
            "workspace path must already be normalized and cannot escape its root",
        )
    for part in path.parts:
        stem = part.split(".", 1)[0].casefold()
        if (
            ":" in part
            or part[-1:] in {".", " "}
            or any(ord(character) < _CONTROL_CHARACTER_LIMIT for character in part)
            or stem in _WINDOWS_RESERVED
        ):
            raise FormatError("SOVA-WORKSPACE-PATH", "workspace path is not portable")
    if _SENSITIVE_PATH.search(normalized):
        raise FormatError("SOVA-WORKSPACE-SENSITIVE", "secret and profile paths are not admitted")
    return normalized


def _locator_values(arguments: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    values: list[tuple[str, str]] = []
    for name in ("ref", "target", "startTarget", "endTarget"):
        value = arguments.get(name)
        if isinstance(value, str):
            values.append((name, value))
    return tuple(values)


def _bounded_computer_string(value: object, *, role: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise FormatError(
            "SOVA-ACTION-CODEC-COMPUTER-TARGET",
            f"reviewed computer {role} must be a non-empty string",
        )
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise FormatError(
            "SOVA-ACTION-CODEC-COMPUTER-TARGET",
            f"reviewed computer {role} is not valid UTF-8",
        ) from error
    if len(encoded) > _MAX_COMPUTER_LOCATOR_BYTES:
        raise FormatError(
            "SOVA-ACTION-CODEC-COMPUTER-TARGET",
            f"reviewed computer {role} exceeds 512 encoded bytes",
        )
    return value


def _computer_locator_kind(locator: dict[str, Any]) -> str:
    keys = set(locator)
    if keys == {"strategy", "value"}:
        strategy = locator.get("strategy")
        if strategy not in _APPIUM_LOCATOR_STRATEGIES:
            raise FormatError(
                "SOVA-ACTION-CODEC-COMPUTER-TARGET",
                "reviewed Appium target uses an unsupported accessibility strategy",
            )
        _bounded_computer_string(locator.get("value"), role="Appium locator")
        return "appium-accessibility"
    if keys == {"role", "name"}:
        _bounded_computer_string(locator.get("role"), role="AT-SPI role")
        _bounded_computer_string(locator.get("name"), role="AT-SPI name")
        return "atspi-accessibility"
    if keys == {"elementToken"}:
        element_token = locator.get("elementToken")
        if (
            not isinstance(element_token, str)
            or _COMPUTER_ELEMENT_TOKEN.fullmatch(element_token) is None
        ):
            raise FormatError(
                "SOVA-ACTION-CODEC-COMPUTER-TARGET",
                "reviewed CUA element token is invalid",
            )
        return "cua-element"
    if keys == {"x", "y"}:
        coordinates = (locator.get("x"), locator.get("y"))
        if any(
            isinstance(item, bool)
            or not isinstance(item, int)
            or not 0 <= item <= _MAX_COMPUTER_COORDINATE
            for item in coordinates
        ):
            raise FormatError(
                "SOVA-ACTION-CODEC-COMPUTER-TARGET",
                "reviewed CUA coordinates must be bounded non-negative integers",
            )
        return "cua-coordinate"
    raise FormatError(
        "SOVA-ACTION-CODEC-COMPUTER-TARGET",
        "reviewed computer target is not an admitted accessibility or CUA locator",
    )


@dataclass(frozen=True, slots=True)
class ComputerIdentityBinding:
    """Opaque session/target identity plus the exact CUA window when applicable."""

    kind: Literal["application", "window"]
    session_digest: str
    identity_digest: str
    pid: int | None = None
    window_id: int | None = None

    def __post_init__(self) -> None:
        if self.kind not in {"application", "window"}:
            raise FormatError(
                "SOVA-ACTION-CODEC-COMPUTER-BINDING",
                "computer identity kind must be application or window",
            )
        if (
            _SHA256.fullmatch(self.session_digest) is None
            or _SHA256.fullmatch(self.identity_digest) is None
        ):
            raise FormatError(
                "SOVA-ACTION-CODEC-COMPUTER-BINDING",
                "computer session and target identity require canonical digests",
            )
        if self.kind == "application":
            if self.pid is not None or self.window_id is not None:
                raise FormatError(
                    "SOVA-ACTION-CODEC-COMPUTER-BINDING",
                    "application identity cannot carry ambient window coordinates",
                )
            return
        if any(
            isinstance(item, bool) or not isinstance(item, int) or item <= 0
            for item in (self.pid, self.window_id)
        ):
            raise FormatError(
                "SOVA-ACTION-CODEC-COMPUTER-BINDING",
                "window identity requires one exact positive pid and windowId",
            )

    def to_mapping(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "kind": self.kind,
            "sessionDigest": self.session_digest,
            "identityDigest": self.identity_digest,
        }
        if self.kind == "window":
            result.update({"pid": self.pid, "windowId": self.window_id})
        return result


@dataclass(frozen=True, slots=True)
class ReviewedComputerTarget:
    """One target copied from the current trusted accessibility observation."""

    reference: str
    actions: tuple[str, ...]
    locator: dict[str, Any]
    _locator_kind: str = field(init=False, repr=False)
    _canonical_locator: bytes = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.reference, str)
            or _COMPUTER_REFERENCE.fullmatch(self.reference) is None
        ):
            raise FormatError(
                "SOVA-ACTION-CODEC-COMPUTER-TARGET",
                "reviewed computer target reference is invalid",
            )
        if (
            not isinstance(self.actions, tuple)
            or not self.actions
            or any(action not in _COMPUTER_MUTATIONS for action in self.actions)
            or len(set(self.actions)) != len(self.actions)
        ):
            raise FormatError(
                "SOVA-ACTION-CODEC-COMPUTER-TARGET",
                "reviewed computer target actions must be unique click/type capabilities",
            )
        locator = _canonical_object(
            self.locator,
            code="SOVA-ACTION-CODEC-COMPUTER-TARGET",
        )
        _reject_sensitive_material(
            locator,
            code="SOVA-ACTION-CODEC-COMPUTER-SENSITIVE",
        )
        locator_kind = _computer_locator_kind(locator)
        object.__setattr__(self, "actions", tuple(sorted(self.actions)))
        object.__setattr__(self, "locator", locator)
        object.__setattr__(self, "_locator_kind", locator_kind)
        object.__setattr__(self, "_canonical_locator", canonical_json_bytes(locator))

    @property
    def locator_kind(self) -> str:
        return self._locator_kind

    def canonical_locator(self) -> dict[str, Any]:
        value = strict_json_loads(self._canonical_locator, max_bytes=_MAX_MODEL_OUTPUT_BYTES)
        if not isinstance(value, dict):  # pragma: no cover - constructor proves this
            raise TypeError
        return value


@dataclass(frozen=True, slots=True)
class ComputerActionCodec:
    """Select only reviewed accessibility/CUA targets from one bound observation."""

    binding: ComputerIdentityBinding
    observation_digest: str
    reviewed_targets: tuple[ReviewedComputerTarget, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.binding, ComputerIdentityBinding):
            raise FormatError(
                "SOVA-ACTION-CODEC-COMPUTER-BINDING",
                "computer codec requires one explicit identity binding",
            )
        if _SHA256.fullmatch(self.observation_digest) is None:
            raise FormatError(
                "SOVA-ACTION-CODEC-COMPUTER-OBSERVATION",
                "computer codec requires one canonical observation digest",
            )
        if not isinstance(self.reviewed_targets, tuple) or not all(
            isinstance(target, ReviewedComputerTarget) for target in self.reviewed_targets
        ):
            raise FormatError(
                "SOVA-ACTION-CODEC-COMPUTER-TARGET",
                "reviewed computer targets must use the declared immutable contract",
            )
        ordered = tuple(sorted(self.reviewed_targets, key=lambda target: target.reference))
        if len({target.reference for target in ordered}) != len(ordered):
            raise FormatError(
                "SOVA-ACTION-CODEC-COMPUTER-TARGET",
                "reviewed computer target reference is duplicated",
            )
        locator_families = {target.locator_kind.split("-", 1)[0] for target in ordered}
        if len(locator_families) > 1:
            raise FormatError(
                "SOVA-ACTION-CODEC-COMPUTER-TARGET",
                "one computer codec cannot mix incompatible adapter locator families",
            )
        admitted_families = {"appium", "atspi"} if self.binding.kind == "application" else {"cua"}
        if not locator_families <= admitted_families:
            raise FormatError(
                "SOVA-ACTION-CODEC-COMPUTER-BINDING",
                "reviewed targets do not match the bound application/window identity",
            )
        object.__setattr__(self, "reviewed_targets", ordered)

    @property
    def codec_id(self) -> str:
        return _COMPUTER_ACTION_CODEC_ID

    def rebind_for_reproduction(self, value: object) -> dict[str, Any]:
        """Rebind only freshness/identity fields for a new controlled run.

        Effect-bearing arguments and reviewed target references are preserved
        byte-for-byte; ``decode`` still rejects a target that is absent from
        the fresh independently observed UI.
        """
        document = _canonical_object(value, code="SOVA-ACTION-CODEC-COMPUTER")
        if set(document) != {"action", "arguments", "binding", "observationDigest"}:
            raise FormatError(
                "SOVA-ACTION-CODEC-COMPUTER",
                "computer reproduction fields are invalid",
            )
        rebound = dict(document)
        rebound["binding"] = self.binding.to_mapping()
        rebound["observationDigest"] = self.observation_digest
        return _canonical_object(rebound, code="SOVA-ACTION-CODEC-COMPUTER")

    @staticmethod
    def reproduction_equivalence_inputs(value: object) -> dict[str, Any]:
        """Remove only fresh OS generation coordinates from equivalence.

        The reviewed target locator, action text/key/direction, and every other
        effect-bearing value remain byte-for-byte comparable. A fresh process
        and HWND are required for reproduction, so their identifiers must not
        make a semantically identical action look different.
        """
        inputs = _canonical_object(
            value,
            code="SOVA-ACTION-CODEC-COMPUTER-REPRODUCTION",
        )
        return {key: child for key, child in inputs.items() if key not in {"pid", "windowId"}}

    def _target(self, reference: object, action: str) -> ReviewedComputerTarget:
        if not isinstance(reference, str):
            raise FormatError(
                "SOVA-ACTION-CODEC-COMPUTER-TARGET",
                "computer mutation requires one reviewed target reference",
            )
        target = next(
            (item for item in self.reviewed_targets if item.reference == reference),
            None,
        )
        if target is None or action not in target.actions:
            raise FormatError(
                "SOVA-ACTION-CODEC-COMPUTER-STALE",
                "computer target is absent from the current reviewed observation",
            )
        return target

    def _observation_request(
        self,
        action: str,
        arguments: dict[str, Any],
        request_id: str,
        timeout_seconds: float,
    ) -> ActionRequest | None:
        if action not in {"computer.snapshot", "computer.inspect"}:
            return None
        expected = "computer.snapshot" if self.binding.kind == "application" else "computer.inspect"
        if action != expected or arguments:
            raise FormatError(
                "SOVA-ACTION-CODEC-COMPUTER-ACTION",
                "computer observation action does not match its application/window binding",
            )
        inputs: dict[str, Any] = (
            {}
            if self.binding.kind == "application"
            else {"pid": self.binding.pid, "windowId": self.binding.window_id}
        )
        return ActionRequest(
            request_id,
            action,
            _canonical_object(inputs, code="SOVA-ACTION-CODEC-COMPUTER-ARGUMENTS"),
            timeout_seconds,
        )

    def _bound_inputs(self, target: ReviewedComputerTarget) -> dict[str, Any]:
        inputs: dict[str, Any] = target.canonical_locator()
        if self.binding.kind == "window":
            inputs.update({"pid": self.binding.pid, "windowId": self.binding.window_id})
        return inputs

    def _mutation_inputs(self, action: str, arguments: dict[str, Any]) -> dict[str, Any]:
        expected_fields = _COMPUTER_MUTATION_FIELDS.get(action)
        if expected_fields is None:
            raise FormatError(
                "SOVA-ACTION-CODEC-COMPUTER-ACTION",
                "computer model proposed an action outside the finite reviewed algebra",
            )
        if set(arguments) != expected_fields:
            raise FormatError(
                "SOVA-ACTION-CODEC-COMPUTER-TARGET",
                "computer mutation must select one reviewed target without raw coordinates",
            )
        _reject_sensitive_material(
            arguments,
            code="SOVA-ACTION-CODEC-COMPUTER-SENSITIVE",
        )
        target = self._target(arguments.get("targetRef"), action)
        inputs = self._bound_inputs(target)
        if action == "computer.click":
            return inputs
        if action == "computer.type":
            inputs["text"] = self._type_text(arguments.get("text"))
            return inputs
        if action == "computer.scroll":
            inputs["direction"], inputs["amount"] = self._scroll_arguments(arguments)
            return inputs
        if action == "computer.key":
            inputs["key"] = self._key_argument(arguments.get("key"))
            return inputs
        # computer.drag: the destination must be a second reviewed drag target.
        end_target = self._target(arguments.get("endTargetRef"), action)
        inputs["endLocator"] = end_target.canonical_locator()
        return inputs

    @staticmethod
    def _type_text(text: object) -> str:
        if not isinstance(text, str) or "\x00" in text:
            raise FormatError(
                "SOVA-ACTION-CODEC-COMPUTER-TEXT",
                "computer type text must be valid bounded text",
            )
        try:
            encoded = text.encode("utf-8", errors="strict")
        except UnicodeEncodeError as error:
            raise FormatError(
                "SOVA-ACTION-CODEC-COMPUTER-TEXT",
                "computer type text is not valid UTF-8",
            ) from error
        if len(encoded) > _MAX_COMPUTER_TEXT_BYTES:
            raise FormatError(
                "SOVA-ACTION-CODEC-COMPUTER-TEXT",
                "computer type text exceeds the common 16 KiB adapter limit",
            )
        return text

    @staticmethod
    def _scroll_arguments(arguments: dict[str, Any]) -> tuple[str, int]:
        direction = arguments.get("direction")
        amount = arguments.get("amount")
        if direction not in _COMPUTER_SCROLL_DIRECTIONS:
            raise FormatError(
                "SOVA-ACTION-CODEC-COMPUTER-SCROLL",
                "computer scroll direction must be up, down, left, or right",
            )
        if (
            isinstance(amount, bool)
            or not isinstance(amount, int)
            or not 1 <= amount <= _MAX_COMPUTER_SCROLL_AMOUNT
        ):
            raise FormatError(
                "SOVA-ACTION-CODEC-COMPUTER-SCROLL",
                "computer scroll amount must be a bounded positive integer",
            )
        return direction, amount

    @staticmethod
    def _key_argument(key: object) -> str:
        if not isinstance(key, str) or key not in _COMPUTER_KEYS:
            raise FormatError(
                "SOVA-ACTION-CODEC-COMPUTER-KEY",
                "computer key press must be one exact allowlisted navigation key",
            )
        return key

    def decode(
        self,
        value: object,
        *,
        request_id: str,
        timeout_seconds: float,
    ) -> ActionRequest:
        document = _canonical_object(value, code="SOVA-ACTION-CODEC-COMPUTER")
        if set(document) != {"action", "arguments", "binding", "observationDigest"}:
            raise FormatError(
                "SOVA-ACTION-CODEC-COMPUTER",
                "computer model output fields are invalid",
            )
        if document.get("observationDigest") != self.observation_digest:
            raise FormatError(
                "SOVA-ACTION-CODEC-COMPUTER-STALE",
                "computer action was proposed against a stale observation",
            )
        if document.get("binding") != self.binding.to_mapping():
            raise FormatError(
                "SOVA-ACTION-CODEC-COMPUTER-BINDING",
                "computer action substituted its session or target identity",
            )
        action = document.get("action")
        arguments = document.get("arguments")
        if not isinstance(action, str) or not isinstance(arguments, dict):
            raise FormatError(
                "SOVA-ACTION-CODEC-COMPUTER",
                "computer action and arguments are invalid",
            )
        observation_request = self._observation_request(
            action,
            arguments,
            request_id,
            timeout_seconds,
        )
        if observation_request is not None:
            return observation_request
        inputs = self._mutation_inputs(action, arguments)
        canonical_inputs = _canonical_object(
            inputs,
            code="SOVA-ACTION-CODEC-COMPUTER-ARGUMENTS",
        )
        return ActionRequest(request_id, action, canonical_inputs, timeout_seconds)


@dataclass(frozen=True, slots=True)
class BrowserActionCodec:
    """Bind the existing semantic browser algebra to one fresh observation."""

    mission: SemanticBrowserMission
    current_locator_refs: frozenset[str]
    observation_digest: str
    reviewed_targets: frozenset[str] = frozenset()

    @property
    def codec_id(self) -> str:
        return _BROWSER_ACTION_CODEC_ID

    def __post_init__(self) -> None:
        if _SHA256.fullmatch(self.observation_digest) is None:
            raise FormatError(
                "SOVA-ACTION-CODEC-BROWSER-OBSERVATION",
                "browser codec requires one canonical observation digest",
            )
        for collection in (self.current_locator_refs, self.reviewed_targets):
            if not all(
                isinstance(item, str) and item and len(item) <= _MAX_PATH_BYTES
                for item in collection
            ):
                raise FormatError(
                    "SOVA-ACTION-CODEC-BROWSER-LOCATOR",
                    "browser locator admission sets are invalid",
                )

    def rebind_for_reproduction(self, value: object) -> dict[str, Any]:
        """Attach a recorded semantic action to the fresh observation only."""
        document = _canonical_object(value, code="SOVA-ACTION-CODEC-BROWSER")
        if set(document) != {"action", "arguments", "observationDigest"}:
            raise FormatError(
                "SOVA-ACTION-CODEC-BROWSER",
                "browser reproduction fields are invalid",
            )
        rebound = dict(document)
        rebound["observationDigest"] = self.observation_digest
        return _canonical_object(rebound, code="SOVA-ACTION-CODEC-BROWSER")

    def decode(
        self,
        value: object,
        *,
        request_id: str,
        timeout_seconds: float,
    ) -> ActionRequest:
        """Validate exact model JSON and return an executor-ready browser request."""
        document = _canonical_object(value, code="SOVA-ACTION-CODEC-BROWSER")
        if set(document) != {"action", "arguments", "observationDigest"}:
            raise FormatError(
                "SOVA-ACTION-CODEC-BROWSER",
                "browser model output fields are invalid",
            )
        if document["observationDigest"] != self.observation_digest:
            raise FormatError(
                "SOVA-ACTION-CODEC-BROWSER-STALE",
                "browser action was proposed against a stale observation",
            )
        action = semantic_browser_action_from_mapping(
            {"action": document["action"], "arguments": document["arguments"]},
            self.mission,
        )
        _reject_sensitive_material(action.arguments, code="SOVA-ACTION-CODEC-BROWSER-SENSITIVE")
        for name, locator in _locator_values(action.arguments):
            admitted = (
                locator in self.current_locator_refs
                if name == "ref"
                else locator in self.current_locator_refs or locator in self.reviewed_targets
            )
            if not admitted:
                raise FormatError(
                    "SOVA-ACTION-CODEC-BROWSER-STALE",
                    "browser action contains a stale or unreviewed locator reference",
                )
        inputs = _canonical_object(
            action.arguments,
            code="SOVA-ACTION-CODEC-BROWSER-ARGUMENTS",
        )
        return ActionRequest(request_id, action.action, inputs, timeout_seconds)


def _workspace_move_inputs(arguments: dict[str, Any]) -> dict[str, Any]:
    source = normalize_workspace_relative_path(arguments.get("source"))
    destination = normalize_workspace_relative_path(arguments.get("destination"))
    overwrite = arguments.get("overwrite")
    if source == destination or not isinstance(overwrite, bool):
        raise FormatError(
            "SOVA-ACTION-CODEC-WORKSPACE-MOVE",
            "workspace move requires distinct paths and an overwrite boolean",
        )
    return {
        "source": source,
        "destination": destination,
        "overwrite": overwrite,
    }


def _workspace_write_inputs(
    arguments: dict[str, Any],
    max_content_bytes: int,
) -> dict[str, Any]:
    path = normalize_workspace_relative_path(arguments.get("path"))
    content = arguments.get("content")
    overwrite = arguments.get("overwrite")
    if not isinstance(content, str) or "\x00" in content or not isinstance(overwrite, bool):
        raise FormatError(
            "SOVA-ACTION-CODEC-WORKSPACE-CONTENT",
            "workspace write requires UTF-8 text and an overwrite boolean",
        )
    try:
        content_bytes = content.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise FormatError(
            "SOVA-ACTION-CODEC-WORKSPACE-CONTENT",
            "workspace write content is not valid UTF-8",
        ) from error
    if len(content_bytes) > max_content_bytes:
        raise FormatError(
            "SOVA-ACTION-CODEC-WORKSPACE-LIMIT",
            "workspace write content exceeds its encoded byte limit",
        )
    return {"path": path, "content": content, "overwrite": overwrite}


@dataclass(frozen=True, slots=True)
class WorkspaceActionCodec:
    """Decode text-only operations for an operator-supplied disposable workspace."""

    max_content_bytes: int = _MAX_FILE_CONTENT_BYTES

    @property
    def codec_id(self) -> str:
        return _WORKSPACE_ACTION_CODEC_ID

    def __post_init__(self) -> None:
        if (
            isinstance(self.max_content_bytes, bool)
            or not 1 <= self.max_content_bytes <= _MAX_FILE_CONTENT_BYTES
        ):
            raise FormatError(
                "SOVA-ACTION-CODEC-WORKSPACE-LIMIT",
                "workspace content limit must be between 1 byte and 1 MiB",
            )

    def decode(
        self,
        value: object,
        *,
        request_id: str,
        timeout_seconds: float,
    ) -> ActionRequest:
        document = _canonical_object(value, code="SOVA-ACTION-CODEC-WORKSPACE")
        if set(document) != {"action", "arguments"}:
            raise FormatError(
                "SOVA-ACTION-CODEC-WORKSPACE",
                "workspace model output fields are invalid",
            )
        action = document.get("action")
        arguments = document.get("arguments")
        expected = _WORKSPACE_ACTION_FIELDS.get(action) if isinstance(action, str) else None
        if expected is None:
            raise FormatError(
                "SOVA-ACTION-CODEC-WORKSPACE-ACTION",
                "workspace model proposed an unknown action",
            )
        if not isinstance(arguments, dict):
            raise FormatError(
                "SOVA-ACTION-CODEC-WORKSPACE-ARGUMENTS",
                "workspace action arguments must be an object",
            )
        if set(arguments) != expected:
            raise FormatError(
                "SOVA-ACTION-CODEC-WORKSPACE-ARGUMENTS",
                "workspace action arguments are invalid",
            )
        if action == "filesystem.move":
            inputs = _workspace_move_inputs(arguments)
        elif action == "filesystem.write":
            inputs = _workspace_write_inputs(arguments, self.max_content_bytes)
        else:
            path = normalize_workspace_relative_path(arguments.get("path"))
            inputs = {"path": path}
        _reject_sensitive_material(inputs, code="SOVA-ACTION-CODEC-WORKSPACE-SENSITIVE")
        canonical_inputs = _canonical_object(
            inputs,
            code="SOVA-ACTION-CODEC-WORKSPACE-ARGUMENTS",
        )
        return ActionRequest(request_id, str(action), canonical_inputs, timeout_seconds)


@dataclass(frozen=True, slots=True)
class ProcessActionCodec:
    """Build one shell-free argv request beneath an exact operator-reviewed prefix."""

    executable: Path
    argv_prefix: tuple[str, ...] = ()
    max_args: int = _MAX_ARGS
    max_arg_bytes: int = _MAX_ARG_BYTES

    @property
    def codec_id(self) -> str:
        return _PROCESS_ACTION_CODEC_ID

    def __post_init__(self) -> None:
        executable = self.executable
        if (
            not executable.is_absolute()
            or executable.is_symlink()
            or not executable.is_file()
            or executable.name.casefold() in _SHELL_EXECUTABLES
        ):
            raise FormatError(
                "SOVA-ACTION-CODEC-PROCESS-EXECUTABLE",
                "process codec requires one existing non-shell absolute executable",
            )
        object.__setattr__(self, "executable", executable.resolve())
        if (
            isinstance(self.max_args, bool)
            or not 1 <= self.max_args <= _MAX_ARGS
            or isinstance(self.max_arg_bytes, bool)
            or not 1 <= self.max_arg_bytes <= _MAX_ARG_BYTES
        ):
            raise FormatError(
                "SOVA-ACTION-CODEC-PROCESS-LIMIT",
                "process argument limits are invalid",
            )
        self._validate_arguments(self.argv_prefix, model_supplied=False)

    def _validate_arguments(
        self,
        arguments: tuple[str, ...] | list[Any],
        *,
        model_supplied: bool,
    ) -> tuple[str, ...]:
        if not isinstance(arguments, (tuple, list)) or not all(
            isinstance(item, str) and item and "\x00" not in item for item in arguments
        ):
            raise FormatError(
                "SOVA-ACTION-CODEC-PROCESS-ARGV",
                "process arguments must be a non-empty-string argv array",
            )
        values = tuple(arguments)
        total_count = len(values) + (len(self.argv_prefix) if model_supplied else 0)
        if total_count > self.max_args:
            raise FormatError(
                "SOVA-ACTION-CODEC-PROCESS-LIMIT",
                "process argv exceeds its argument-count limit",
            )
        try:
            encoded_lengths = tuple(len(item.encode("utf-8", errors="strict")) for item in values)
        except UnicodeEncodeError as error:
            raise FormatError(
                "SOVA-ACTION-CODEC-PROCESS-ARGV",
                "process argument is not valid UTF-8",
            ) from error
        if any(length > _MAX_SINGLE_ARG_BYTES for length in encoded_lengths):
            raise FormatError(
                "SOVA-ACTION-CODEC-PROCESS-LIMIT",
                "one process argument exceeds 4096 encoded bytes",
            )
        for argument in values:
            _reject_sensitive_material(
                {"argument": argument},
                code="SOVA-ACTION-CODEC-PROCESS-SENSITIVE",
            )
        if model_supplied:
            for argument in values:
                if (
                    argument.startswith("-")
                    and "=" not in argument
                    and any(mark in argument for mark in ("/", "\\"))
                ):
                    raise FormatError(
                        "SOVA-ACTION-CODEC-PROCESS-ARGV",
                        "path-valued options must use a separate argv item or --name=relative/path",
                    )
                path_value = (
                    argument.split("=", 1)[1]
                    if argument.startswith("-") and "=" in argument
                    else argument
                )
                if any(mark in path_value for mark in ("/", "\\")) or path_value.startswith("."):
                    normalize_workspace_relative_path(path_value)
        return values

    def decode(
        self,
        value: object,
        *,
        request_id: str,
        timeout_seconds: float,
    ) -> ActionRequest:
        document = _canonical_object(value, code="SOVA-ACTION-CODEC-PROCESS")
        if set(document) != {"action", "arguments"} or document.get("action") != "process.exec":
            raise FormatError(
                "SOVA-ACTION-CODEC-PROCESS",
                "process model output must request exactly process.exec",
            )
        arguments = document.get("arguments")
        if not isinstance(arguments, dict) or set(arguments) != {"args", "cwd"}:
            raise FormatError(
                "SOVA-ACTION-CODEC-PROCESS-ARGV",
                "process action requires only an argv data array and relative cwd",
            )
        raw_args = arguments.get("args")
        if not isinstance(raw_args, list):
            raise FormatError(
                "SOVA-ACTION-CODEC-PROCESS-ARGV",
                "shell command strings are forbidden; args must be an array",
            )
        model_args = self._validate_arguments(raw_args, model_supplied=True)
        cwd = normalize_workspace_relative_path(arguments.get("cwd"), allow_root=True)
        argv = (str(self.executable), *self.argv_prefix, *model_args)
        if sum(len(item.encode("utf-8")) for item in argv) > self.max_arg_bytes:
            raise FormatError(
                "SOVA-ACTION-CODEC-PROCESS-LIMIT",
                "process argv exceeds its total encoded byte limit",
            )
        inputs = _canonical_object(
            {"argv": list(argv), "cwd": cwd},
            code="SOVA-ACTION-CODEC-PROCESS-ARGV",
        )
        return ActionRequest(request_id, "process.exec", inputs, timeout_seconds)


def _absolute_container_path(value: object, *, role: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        raise FormatError(
            "SOVA-ACTION-CODEC-OCI-PATH",
            f"OCI {role} must be one non-empty absolute POSIX path",
        )
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise FormatError(
            "SOVA-ACTION-CODEC-OCI-PATH",
            f"OCI {role} is not valid UTF-8",
        ) from error
    path = PurePosixPath(value)
    if (
        len(encoded) > _MAX_SINGLE_ARG_BYTES
        or value == "/"
        or value.startswith("//")
        or not path.is_absolute()
        or value != path.as_posix()
        or any(part in {".", ".."} for part in path.parts)
        or any(
            ord(character) < _CONTROL_CHARACTER_LIMIT for part in path.parts for character in part
        )
    ):
        raise FormatError(
            "SOVA-ACTION-CODEC-OCI-PATH",
            f"OCI {role} must be a normalized absolute POSIX path",
        )
    _reject_sensitive_material(
        {role: value},
        code="SOVA-ACTION-CODEC-OCI-SENSITIVE",
    )
    return value


def _oci_argument(value: object, *, role: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise FormatError(
            "SOVA-ACTION-CODEC-OCI-ARGV",
            f"OCI {role} must be one non-empty UTF-8 argv item",
        )
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise FormatError(
            "SOVA-ACTION-CODEC-OCI-ARGV",
            f"OCI {role} is not valid UTF-8",
        ) from error
    if len(encoded) > _MAX_SINGLE_ARG_BYTES:
        raise FormatError(
            "SOVA-ACTION-CODEC-OCI-LIMIT",
            "one OCI process argument exceeds 4096 encoded bytes",
        )
    _reject_sensitive_material(
        {role: value},
        code="SOVA-ACTION-CODEC-OCI-SENSITIVE",
    )
    path_candidate = value
    if value.startswith("-"):
        option, separator, option_value = value.partition("=")
        if "/" in option or "\\" in option:
            raise FormatError(
                "SOVA-ACTION-CODEC-OCI-ARGV",
                "OCI option names cannot contain path separators",
            )
        if not separator:
            return value
        if not option_value:
            raise FormatError(
                "SOVA-ACTION-CODEC-OCI-ARGV",
                "OCI option values cannot be empty",
            )
        path_candidate = option_value
    if "/" in path_candidate or "\\" in path_candidate or path_candidate.startswith("."):
        _absolute_container_path(path_candidate, role=role)
    return value


@dataclass(frozen=True, slots=True)
class OciProcessActionCodec:
    """Build one shell-free request for an exact container-local argv template."""

    executable: str
    argv_prefix: tuple[str, ...] = ()
    max_args: int = _MAX_OCI_ARGS
    max_arg_bytes: int = _MAX_OCI_ARG_BYTES
    max_stdin_bytes: int = _MAX_OCI_STDIN_BYTES

    @property
    def codec_id(self) -> str:
        return _OCI_PROCESS_ACTION_CODEC_ID

    def __post_init__(self) -> None:
        executable = _absolute_container_path(self.executable, role="executable")
        if PurePosixPath(executable).name.casefold() in _SHELL_EXECUTABLES:
            raise FormatError(
                "SOVA-ACTION-CODEC-OCI-EXECUTABLE",
                "OCI process executable cannot be a command shell",
            )
        if (
            not isinstance(self.argv_prefix, tuple)
            or isinstance(self.max_args, bool)
            or not 1 <= self.max_args <= _MAX_OCI_ARGS
            or isinstance(self.max_arg_bytes, bool)
            or not 1 <= self.max_arg_bytes <= _MAX_OCI_ARG_BYTES
            or isinstance(self.max_stdin_bytes, bool)
            or not 1 <= self.max_stdin_bytes <= _MAX_OCI_STDIN_BYTES
        ):
            raise FormatError(
                "SOVA-ACTION-CODEC-OCI-LIMIT",
                "OCI process argument and stdin limits are invalid",
            )
        prefix = tuple(
            _oci_argument(value, role="reviewed argv prefix") for value in self.argv_prefix
        )
        if 1 + len(prefix) > self.max_args:
            raise FormatError(
                "SOVA-ACTION-CODEC-OCI-LIMIT",
                "reviewed OCI argv prefix exceeds its argument-count limit",
            )
        if sum(len(item.encode("utf-8")) for item in (executable, *prefix)) > self.max_arg_bytes:
            raise FormatError(
                "SOVA-ACTION-CODEC-OCI-LIMIT",
                "reviewed OCI argv prefix exceeds its encoded byte limit",
            )
        object.__setattr__(self, "executable", executable)
        object.__setattr__(self, "argv_prefix", prefix)

    def decode(
        self,
        value: object,
        *,
        request_id: str,
        timeout_seconds: float,
    ) -> ActionRequest:
        document = _canonical_object(value, code="SOVA-ACTION-CODEC-OCI")
        if set(document) != {"action", "arguments"} or document.get("action") != "process.exec":
            raise FormatError(
                "SOVA-ACTION-CODEC-OCI",
                "OCI model output must request exactly process.exec",
            )
        arguments = document.get("arguments")
        if not isinstance(arguments, dict) or set(arguments) not in ({"args"}, {"args", "stdin"}):
            raise FormatError(
                "SOVA-ACTION-CODEC-OCI-ARGV",
                "OCI process action accepts only an argv data array and optional stdin",
            )
        raw_args = arguments.get("args")
        if not isinstance(raw_args, list):
            raise FormatError(
                "SOVA-ACTION-CODEC-OCI-ARGV",
                "shell command strings are forbidden; OCI args must be an array",
            )
        model_args = tuple(_oci_argument(item, role="model argv item") for item in raw_args)
        argv = (self.executable, *self.argv_prefix, *model_args)
        if (
            len(argv) > self.max_args
            or sum(len(item.encode("utf-8")) for item in argv) > self.max_arg_bytes
        ):
            raise FormatError(
                "SOVA-ACTION-CODEC-OCI-LIMIT",
                "OCI process argv exceeds its count or encoded byte limit",
            )
        inputs: dict[str, Any] = {"argv": list(argv)}
        if "stdin" in arguments:
            stdin = arguments.get("stdin")
            if not isinstance(stdin, str) or "\x00" in stdin:
                raise FormatError(
                    "SOVA-ACTION-CODEC-OCI-STDIN",
                    "OCI stdin must be one bounded UTF-8 string",
                )
            try:
                stdin_bytes = stdin.encode("utf-8", errors="strict")
            except UnicodeEncodeError as error:
                raise FormatError(
                    "SOVA-ACTION-CODEC-OCI-STDIN",
                    "OCI stdin is not valid UTF-8",
                ) from error
            if len(stdin_bytes) > self.max_stdin_bytes:
                raise FormatError(
                    "SOVA-ACTION-CODEC-OCI-LIMIT",
                    "OCI stdin exceeds its encoded byte limit",
                )
            _reject_sensitive_material(
                {"stdin": stdin},
                code="SOVA-ACTION-CODEC-OCI-SENSITIVE",
            )
            inputs["stdin"] = stdin
        return ActionRequest(
            request_id,
            "process.exec",
            _canonical_object(inputs, code="SOVA-ACTION-CODEC-OCI-ARGV"),
            timeout_seconds,
        )


__all__ = [
    "BrowserActionCodec",
    "ComputerActionCodec",
    "ComputerIdentityBinding",
    "OciProcessActionCodec",
    "ProcessActionCodec",
    "ReviewedComputerTarget",
    "WorkspaceActionCodec",
    "normalize_workspace_relative_path",
]
