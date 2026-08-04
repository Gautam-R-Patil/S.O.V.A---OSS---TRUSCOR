# SPDX-License-Identifier: Apache-2.0
"""Failure, trust, and hostile-input coverage for Topic 22."""

from __future__ import annotations

import io
import sys
import urllib.error
import urllib.request
from email.message import Message
from importlib.metadata import EntryPoint
from pathlib import Path
from typing import TYPE_CHECKING, Any, Self

import pytest

import sova.extensions.model as extension_model
import sova.providers.core as provider_core
from sova.extensions import (
    EXTENSION_API_VERSION,
    ExtensionKind,
    ExtensionManifest,
    SubprocessExtensionRunner,
    discover_extension_metadata,
)
from sova.formats.errors import FormatError
from sova.interoperability import export_inspect_samples, import_inspect_samples
from sova.providers import (
    AnthropicAdapter,
    FakeTransport,
    HttpRequest,
    HttpResponse,
    KeyringSecretResolver,
    ModelRequest,
    ModelResult,
    OllamaAdapter,
    OpenAIAdapter,
    OpenRouterAdapter,
    ProviderAdapter,
    ProviderError,
    ProviderRoleRouter,
    UrllibTransport,
    compare_model_results,
    run_model_swap,
)
from sova.targets import TargetKind, TargetManifest, validate_target_manifest

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import ModuleType

    from pytest import MonkeyPatch


def _request() -> ModelRequest:
    return ModelRequest("model", ({"role": "user", "content": "fixture"},))


@pytest.mark.parametrize(
    ("arguments", "code"),
    [
        (("Bad ID", "1", EXTENSION_API_VERSION), "SOVA-EXTENSION-ID"),
        (("ok", "", EXTENSION_API_VERSION), "SOVA-EXTENSION-VERSION"),
        (("ok", "1", "9"), "SOVA-EXTENSION-API"),
    ],
)
def test_extension_manifest_rejects_invalid_identity_and_version(
    arguments: tuple[str, str, str], code: str
) -> None:
    with pytest.raises(FormatError) as caught:
        ExtensionManifest(*arguments, ExtensionKind.ORACLE, (), ())
    assert caught.value.issue.code == code


def test_extension_manifest_rejects_invalid_policy_and_round_trips() -> None:
    invalid: list[dict[str, Any]] = [
        {"isolation": "thread"},
        {"trust": "mystery"},
        {"isolation": "in-process", "trust": "verified-publisher"},
        {"capabilities": ("BAD VALUE",)},
        {"capabilities": ("same", "same")},
        {"distribution_digest": "sha256:no"},
    ]
    for override in invalid:
        values: dict[str, Any] = {
            "identifier": "example.ok",
            "version": "1",
            "api_version": EXTENSION_API_VERSION,
            "kind": ExtensionKind.ORACLE,
            "capabilities": ("oracle.fixture",),
            "side_effects": (),
        }
        values.update(override)
        with pytest.raises(FormatError):
            ExtensionManifest(**values)

    manifest = ExtensionManifest(
        "example.ok",
        "1",
        EXTENSION_API_VERSION,
        ExtensionKind.REPORT,
        ("report.fixture",),
        ("reads.input",),
        trust="first-party",
        distribution_digest="sha256:" + "a" * 64,
    )
    assert ExtensionManifest.from_mapping(manifest.to_mapping()) == manifest
    with pytest.raises(FormatError, match="malformed"):
        ExtensionManifest.from_mapping({})


def test_extension_metadata_discovery_does_not_load_entry_point(monkeypatch: MonkeyPatch) -> None:
    entry = EntryPoint("z-fixture", "never.imported:plugin", "sova.extensions")
    monkeypatch.setattr(extension_model, "entry_points", lambda **_kwargs: (entry,))
    metadata = discover_extension_metadata()
    assert metadata[0].value == "never.imported:plugin"
    assert metadata[0].distribution is None


def test_extension_runner_rejects_contract_edges(tmp_path: Path) -> None:
    manifest = ExtensionManifest(
        "example.ok", "1", EXTENSION_API_VERSION, ExtensionKind.ORACLE, (), ()
    )
    with pytest.raises(FormatError, match="subprocess isolation"):
        SubprocessExtensionRunner(
            ExtensionManifest(
                "example.first",
                "1",
                EXTENSION_API_VERSION,
                ExtensionKind.ORACLE,
                (),
                (),
                isolation="in-process",
                trust="first-party",
            ),
            (sys.executable,),
            executable_allowlist=(Path(sys.executable),),
            working_directory=tmp_path,
        )
    for command in ((), ("",), (sys.executable,) * 65):
        with pytest.raises(FormatError):
            SubprocessExtensionRunner(
                manifest,
                command,
                executable_allowlist=(Path(sys.executable),),
                working_directory=tmp_path,
            )
    with pytest.raises(FormatError, match="working directory"):
        SubprocessExtensionRunner(
            manifest,
            (sys.executable,),
            executable_allowlist=(Path(sys.executable),),
            working_directory=tmp_path / "absent",
        )
    with pytest.raises(FormatError, match="within 60"):
        SubprocessExtensionRunner(
            manifest,
            (sys.executable,),
            executable_allowlist=(Path(sys.executable),),
            working_directory=tmp_path,
            timeout_seconds=61,
        )


@pytest.mark.parametrize(
    "case_data",
    [
        {"model": "", "messages": ({"role": "user", "content": "x"},)},
        {"model": "m", "messages": ()},
        {
            "model": "m",
            "messages": ({"role": "user", "content": "x"},),
            "temperature": 3,
        },
        {
            "model": "m",
            "messages": ({"role": "user", "content": "x"},),
            "max_output_tokens": 0,
        },
        {"model": "m", "messages": ({"role": "tool", "content": "x"},)},
    ],
)
def test_model_request_rejects_invalid_envelopes(case_data: dict[str, Any]) -> None:
    with pytest.raises(ProviderError):
        ModelRequest(**case_data)


def test_transport_and_fake_failure_normalization(monkeypatch: MonkeyPatch) -> None:
    for origin in ("not-an-origin", "https://example.com/path"):
        with pytest.raises(FormatError, match="origin is invalid"):
            UrllibTransport((origin,))
    transport = UrllibTransport(("https://example.com",))
    for timeout in (0, 61):
        with pytest.raises(ProviderError, match="timeout"):
            transport.send(HttpRequest("GET", "https://example.com", {}, None), timeout=timeout)
    with pytest.raises(ProviderError, match="not pinned"):
        transport.send(
            HttpRequest("GET", "https://user:pass@example.com/path", {}, None), timeout=1
        )
    fake = FakeTransport(())
    with pytest.raises(AssertionError):
        fake.send(HttpRequest("GET", "https://example.com", {}, None), timeout=1)

    def fail_import(_name: str) -> ModuleType:
        raise ImportError

    monkeypatch.setattr(provider_core, "import_module", fail_import)
    with pytest.raises(ProviderError, match="keyring"):
        KeyringSecretResolver().store("OPENAI_API_KEY", "secret")


def test_pinned_transport_success_limit_http_and_network_paths(monkeypatch: MonkeyPatch) -> None:
    class Response:
        def __init__(self, body: bytes) -> None:
            self.body = body
            self.status = 200
            self.headers = {"content-type": "application/json"}

        def __enter__(self) -> Self:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _limit: int) -> bytes:
            return self.body

    class Opener:
        def __init__(self, outcome: object) -> None:
            self.outcome = outcome

        def open(self, *_args: object, **_kwargs: object) -> Response:
            if isinstance(self.outcome, BaseException):
                raise self.outcome
            assert isinstance(self.outcome, Response)
            return self.outcome

    transport = UrllibTransport(("https://example.com",))
    monkeypatch.setattr(
        urllib.request,
        "build_opener",
        lambda *_args: Opener(Response(b'{"ok":true}')),
    )
    result = transport.send(HttpRequest("GET", "https://example.com/v1", {}, None), timeout=1)
    assert result.status == 200

    monkeypatch.setattr(
        urllib.request,
        "build_opener",
        lambda *_args: Opener(Response(b"x" * (8 * 1024 * 1024 + 1))),
    )
    with pytest.raises(ProviderError, match="exceeded"):
        transport.send(HttpRequest("GET", "https://example.com/v1", {}, None), timeout=1)

    headers = Message()
    headers["retry-after"] = "1"
    http_error = urllib.error.HTTPError(
        "https://example.com/v1", 429, "limited", headers, io.BytesIO(b"{}")
    )
    monkeypatch.setattr(
        urllib.request,
        "build_opener",
        lambda *_args: Opener(http_error),
    )
    assert (
        transport.send(HttpRequest("GET", "https://example.com/v1", {}, None), timeout=1).status
        == 429
    )

    monkeypatch.setattr(
        urllib.request,
        "build_opener",
        lambda *_args: Opener(urllib.error.URLError("offline")),
    )
    with pytest.raises(ProviderError, match="request failed"):
        transport.send(HttpRequest("GET", "https://example.com/v1", {}, None), timeout=1)


def test_keyring_policy_with_injected_backend(monkeypatch: MonkeyPatch) -> None:
    class Keyring:
        value: str | None = None

        @classmethod
        def get_password(cls, _service: str, _name: str) -> str | None:
            return cls.value

        @classmethod
        def set_password(cls, _service: str, _name: str, value: str) -> None:
            cls.value = value

        @classmethod
        def delete_password(cls, _service: str, _name: str) -> None:
            cls.value = None

    monkeypatch.setattr(provider_core, "import_module", lambda _name: Keyring)
    resolver = KeyringSecretResolver()
    assert resolver("OPENAI_API_KEY") is None
    resolver.store("OPENAI_API_KEY", "secret")
    assert resolver("OPENAI_API_KEY") == "secret"
    resolver.delete("OPENAI_API_KEY")
    actions: tuple[Callable[[], object], ...] = (
        lambda: resolver("OTHER"),
        lambda: resolver.store("OTHER", "secret"),
        lambda: resolver.store("OPENAI_API_KEY", ""),
        lambda: resolver.delete("OTHER"),
    )
    for action in actions:
        with pytest.raises(ProviderError):
            action()


def test_provider_base_and_response_error_paths() -> None:
    base = ProviderAdapter(FakeTransport(()))
    base.credential_name = None
    assert base._credential() is None
    with pytest.raises(NotImplementedError):
        base._request(_request())
    with pytest.raises(NotImplementedError):
        base._parse(_request(), {})
    with pytest.raises(NotImplementedError):
        base.list_models()

    missing = OpenAIAdapter(FakeTransport(()), secret_resolver=lambda _name: None)
    with pytest.raises(ProviderError, match="unavailable"):
        missing._credential()
    for response in (
        HttpResponse(500, {}, b"{}"),
        HttpResponse(200, {}, b"[]"),
    ):
        adapter = OpenAIAdapter(FakeTransport((response,)), secret_resolver=lambda _name: "secret")
        with pytest.raises(ProviderError):
            adapter.complete(_request())


def test_provider_discovery_and_parse_fallbacks() -> None:
    for response in (
        HttpResponse(500, {}, b"{}"),
        HttpResponse(200, {}, b"[]"),
        HttpResponse(200, {}, b'{"data":"bad"}'),
    ):
        adapter = OpenAIAdapter(FakeTransport((response,)), secret_resolver=lambda _name: "secret")
        with pytest.raises(ProviderError):
            adapter.list_models()

    openai = OpenAIAdapter(
        FakeTransport(
            (
                HttpResponse(
                    200,
                    {},
                    b'{"output":[{"content":[{"type":"output_text","text":"ok"}]}],"usage":null}',
                ),
                HttpResponse(200, {}, b'{"data":[{"name":"named"},null]}'),
            )
        ),
        secret_resolver=lambda _name: "secret",
    )
    assert openai.complete(_request()).text == "ok"
    assert openai.list_models() == ("named",)

    anthropic = AnthropicAdapter(
        FakeTransport(
            (
                HttpResponse(200, {}, b'{"content":[],"usage":null}'),
                HttpResponse(200, {}, b'{"data":[]}'),
            )
        ),
        secret_resolver=lambda _name: "secret",
    )
    assert anthropic.complete(_request()).text == ""
    assert anthropic.list_models() == ()

    router = OpenRouterAdapter(
        FakeTransport(
            (
                HttpResponse(200, {}, b'{"choices":{},"usage":null}'),
                HttpResponse(200, {}, b'{"data":[]}'),
            )
        ),
        secret_resolver=lambda _name: "secret",
    )
    assert router.complete(_request()).text == ""
    assert router.list_models() == ()

    ollama = OllamaAdapter(
        FakeTransport(
            (
                HttpResponse(200, {}, b'{"message":"bad","done":false}'),
                HttpResponse(200, {}, b'{"models":[]}'),
            )
        )
    )
    assert ollama.complete(_request()).finish_reason is None
    assert ollama.list_models() == ()


def test_provider_comparison_and_routing_refusals() -> None:
    with pytest.raises(ProviderError, match="at least one"):
        compare_model_results(())
    result = ModelResult("p", "m", "x", None, {}, None)
    assert compare_model_results((result,))["semanticJudgment"] == "not-performed"
    for routes in ({}, {"invalid": (OllamaAdapter(FakeTransport(())), "m")}):
        with pytest.raises(ProviderError, match="role map"):
            ProviderRoleRouter(routes)
    router = ProviderRoleRouter({"judge": (OllamaAdapter(FakeTransport(())), "m")})
    with pytest.raises(ProviderError, match="not configured"):
        router.complete("attacker", _request())
    with pytest.raises(ProviderError, match="at least two"):
        run_model_swap(((OllamaAdapter(FakeTransport(())), "m"),), _request())


def test_target_contract_rejection_and_trace_only_policy() -> None:
    for values in (
        ("BAD ID", "1", ("protocol.mcp",), "self", {}),
        ("ok", "", ("protocol.mcp",), "self", {}),
        ("ok", "1", ("BAD VALUE",), "self", {}),
        ("ok", "1", ("protocol.mcp",), "self", {"secret": "value"}),
    ):
        with pytest.raises(FormatError):
            TargetManifest(
                values[0], TargetKind.MCP_SERVER, values[1], values[2], values[3], values[4]
            )
    missing = TargetManifest("ok", TargetKind.MCP_SERVER, "1", (), "self", {})
    assert validate_target_manifest(missing)["accepted"] is False
    trace_only = TargetManifest(
        "trace", TargetKind.TRACE_ONLY, "1", ("trace.import", "process.invoke"), "self", {}
    )
    assert validate_target_manifest(trace_only)["traceOnlyExecutionDisabled"] is False


def test_inspect_import_export_hostile_documents(tmp_path: Path) -> None:
    missing_input = tmp_path / "missing.json"
    missing_input.write_text("{}", encoding="utf-8")
    with pytest.raises(FormatError, match="input is required"):
        import_inspect_samples(missing_input, license_expression="A", source_url="u")
    bad_metadata = tmp_path / "metadata.json"
    bad_metadata.write_text('{"input":"x","metadata":[]}', encoding="utf-8")
    with pytest.raises(FormatError, match="metadata"):
        import_inspect_samples(bad_metadata, license_expression="A", source_url="u")
    with pytest.raises(FormatError, match="required"):
        import_inspect_samples(missing_input, license_expression="", source_url="u")

    destination = tmp_path / "out.jsonl"
    with pytest.raises(FormatError, match="not an external"):
        export_inspect_samples({}, destination)
    with pytest.raises(FormatError, match="array"):
        export_inspect_samples({"artifactType": "sova.external-scenario-set"}, destination)
    with pytest.raises(FormatError, match="sample must"):
        export_inspect_samples(
            {"artifactType": "sova.external-scenario-set", "samples": [None]}, destination
        )
