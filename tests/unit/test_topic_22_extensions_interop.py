# SPDX-License-Identifier: Apache-2.0
"""Topic 22 extension, provider, target, and interoperability acceptance tests."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from sova.extensions import (
    EXTENSION_API_VERSION,
    ExtensionKind,
    ExtensionManifest,
    SubprocessExtensionRunner,
)
from sova.formats import strict_json_loads
from sova.formats.errors import FormatError
from sova.interoperability import export_inspect_samples, import_inspect_samples
from sova.providers import (
    AnthropicAdapter,
    FakeTransport,
    HttpResponse,
    ModelRequest,
    OllamaAdapter,
    OpenAIAdapter,
    OpenRouterAdapter,
    ProviderError,
    ProviderRoleRouter,
    UrllibTransport,
    compare_model_results,
    run_model_swap,
)
from sova.targets import TargetKind, TargetManifest, validate_target_manifest


def _manifest() -> ExtensionManifest:
    return ExtensionManifest(
        "example.external-oracle",
        "1.2.3",
        EXTENSION_API_VERSION,
        ExtensionKind.ORACLE,
        ("oracle.fixture",),
        ("reads-request",),
    )


def _request(model: str = "model-a") -> ModelRequest:
    return ModelRequest(model, ({"role": "user", "content": "safe fixture"},))


def test_external_subprocess_extension_conforms_without_importing_it(tmp_path: Path) -> None:
    script = Path(__file__).parents[1] / "fixtures" / "external_extension.py"
    runner = SubprocessExtensionRunner(
        _manifest(),
        (sys.executable, str(script)),
        executable_allowlist=(Path(sys.executable),),
        working_directory=tmp_path,
    )
    report = runner.conform()
    assert report["describePassed"] is True
    assert report["selfTestPassed"] is True
    assert report["isolation"] == "subprocess-not-security-sandbox"

    with pytest.raises(FormatError, match="exactly allowlisted"):
        SubprocessExtensionRunner(
            _manifest(),
            ("untrusted-executable",),
            executable_allowlist=(Path(sys.executable),),
            working_directory=tmp_path,
        )
    with pytest.raises(FormatError, match="first-party"):
        ExtensionManifest(
            "example.bad",
            "1",
            EXTENSION_API_VERSION,
            ExtensionKind.JUDGE,
            (),
            (),
            isolation="in-process",
            trust="untrusted",
        )


def test_external_subprocess_extension_bounds_hostile_output_and_time(tmp_path: Path) -> None:
    noisy = tmp_path / "noisy.py"
    noisy.write_text(
        "import sys\nsys.stdin.buffer.readline()\nsys.stdout.buffer.write(b'x' * 2097153)\n",
        encoding="utf-8",
    )
    noisy_runner = SubprocessExtensionRunner(
        _manifest(),
        (sys.executable, str(noisy)),
        executable_allowlist=(Path(sys.executable),),
        working_directory=tmp_path,
    )
    with pytest.raises(FormatError, match="output exceeded limit"):
        noisy_runner.run("describe", {})

    slow = tmp_path / "slow.py"
    slow.write_text(
        "import sys, time\nsys.stdin.buffer.readline()\ntime.sleep(2)\n",
        encoding="utf-8",
    )
    slow_runner = SubprocessExtensionRunner(
        _manifest(),
        (sys.executable, str(slow)),
        executable_allowlist=(Path(sys.executable),),
        working_directory=tmp_path,
        timeout_seconds=0.05,
    )
    with pytest.raises(FormatError, match="time budget"):
        slow_runner.run("describe", {})


@pytest.mark.parametrize(
    ("adapter_type", "body", "expected"),
    [
        (OpenAIAdapter, b'{"id":"r1","output_text":"ok","usage":{}}', "ok"),
        (
            AnthropicAdapter,
            b'{"id":"r2","content":[{"type":"text","text":"ok"}],"usage":{}}',
            "ok",
        ),
        (
            OpenRouterAdapter,
            b'{"id":"r3","choices":[{"message":{"content":"ok"}}],"usage":{}}',
            "ok",
        ),
        (OllamaAdapter, b'{"message":{"content":"ok"},"done":true}', "ok"),
    ],
)
def test_all_provider_adapters_work_with_injected_no_network_transport(
    adapter_type: type[OpenAIAdapter], body: bytes, expected: str
) -> None:
    transport = FakeTransport([HttpResponse(200, {}, body)])
    adapter = adapter_type(transport, secret_resolver=lambda _name: "test-secret")
    result = adapter.complete(_request())
    assert result.text == expected
    assert result.estimated_cost is None
    outbound = transport.requests[0]
    assert outbound.url.startswith(adapter.origin)
    assert b"test-secret" not in (outbound.body or b"")


def test_provider_role_routing_model_swap_discovery_and_rate_limit() -> None:
    first = OpenAIAdapter(
        FakeTransport(
            [
                HttpResponse(200, {}, b'{"output_text":"a"}'),
                HttpResponse(200, {}, b'{"data":[{"id":"m2"},{"id":"m1"}]}'),
            ]
        ),
        secret_resolver=lambda _name: "one",
    )
    router = ProviderRoleRouter({"judge": (first, "judge-model")})
    routed = router.complete("judge", _request())
    assert routed.model == "judge-model"
    assert first.list_models() == ("m1", "m2")

    # Fresh deterministic adapters make the controlled model-swap call.
    a = OpenAIAdapter(
        FakeTransport([HttpResponse(200, {}, b'{"output_text":"same"}')]),
        secret_resolver=lambda _name: "one",
    )
    b = OllamaAdapter(
        FakeTransport([HttpResponse(200, {}, b'{"message":{"content":"same"},"done":true}')])
    )
    swapped = run_model_swap(((a, "remote"), (b, "local")), _request())
    assert compare_model_results(swapped)["exactTextAgreement"] is True

    limited = OpenRouterAdapter(
        FakeTransport([HttpResponse(429, {"retry-after": "4"}, b"{}")]),
        secret_resolver=lambda _name: "key",
    )
    with pytest.raises(ProviderError) as caught:
        limited.complete(_request())
    assert caught.value.issue.code == "SOVA-PROVIDER-RATE-LIMIT"
    assert caught.value.issue.details == {"retryAfter": "4"}


def test_live_transport_rejects_unpinned_or_insecure_origins_without_network() -> None:
    with pytest.raises(FormatError, match="require HTTPS"):
        UrllibTransport(("http://example.com",))
    transport = UrllibTransport(("https://api.openai.com",))
    with pytest.raises(ProviderError, match="not pinned"):
        transport.send(
            # Construction itself has no network effect; origin rejection precedes I/O.
            __import__("sova.providers", fromlist=["HttpRequest"]).HttpRequest(
                "GET", "https://attacker.invalid/v1/models", {}, None
            ),
            timeout=1,
        )


@pytest.mark.parametrize("kind", list(TargetKind))
def test_target_adapter_contracts_cover_all_declared_surfaces(kind: TargetKind) -> None:
    capability = {
        TargetKind.MCP_SERVER: "protocol.mcp",
        TargetKind.LOCAL_PROCESS: "process.invoke",
        TargetKind.REST_API: "protocol.http",
        TargetKind.BROWSER_AGENT: "browser.observe",
        TargetKind.COMPUTER_AGENT: "computer.observe",
        TargetKind.FRAMEWORK: "manifest.inspect",
        TargetKind.MULTI_AGENT: "inter-agent.observe",
        TargetKind.TRACE_ONLY: "trace.import",
    }[kind]
    manifest = TargetManifest("example:target", kind, "1", (capability,), "self-owned", {})
    assert validate_target_manifest(manifest)["accepted"] is True


def test_inspect_jsonl_round_trip_preserves_identity_license_and_reports_loss(
    tmp_path: Path,
) -> None:
    source = tmp_path / "inspect.jsonl"
    source.write_text(
        '{"id":"sample-1","input":"hello","target":"world","metadata":{"split":"test"},'
        '"setup":"echo never-run","custom":{"preserved":true}}\n',
        encoding="utf-8",
    )
    imported = import_inspect_samples(
        source,
        license_expression="Apache-2.0",
        source_url="https://example.invalid/dataset",
    )
    assert imported["source"]["license"] == "Apache-2.0"
    assert imported["samples"][0]["originalId"] == "sample-1"
    assert imported["conversion"]["lossless"] is False
    assert "not-executed" in " ".join(imported["conversion"]["semanticLoss"])

    exported = tmp_path / "roundtrip.jsonl"
    report = export_inspect_samples(imported, exported)
    row = strict_json_loads(exported.read_bytes())
    assert row["id"] == "sample-1"
    assert row["setup"] == "echo never-run"
    assert row["custom"] == {"preserved": True}
    assert report["semanticLoss"]
