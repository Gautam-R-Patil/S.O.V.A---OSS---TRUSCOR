# SPDX-License-Identifier: Apache-2.0
"""Provider/runtime bridge tests with no network or external credentials."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sova.cli import main
from sova.formats import strict_json_loads
from sova.providers import (
    FakeTransport,
    HttpResponse,
    OpenAIAdapter,
    ProviderError,
    ProviderRoleModel,
    ProviderRoute,
    ProviderRuntimeConfig,
    provider_model_from_route,
    provider_model_router,
    provider_runtime_from_mapping,
)
from sova.runtime import RoleKind


def _response(text: str) -> HttpResponse:
    return HttpResponse(
        200,
        {},
        json.dumps(
            {
                "id": "response-fixture",
                "status": "completed",
                "output_text": text,
                "usage": {"input_tokens": 7, "output_tokens": 3},
            }
        ).encode(),
    )


def _config() -> ProviderRuntimeConfig:
    return ProviderRuntimeConfig(
        {
            role: ProviderRoute("openai", "fixture-model", max_output_tokens=512)
            for role in (
                RoleKind.RECON,
                RoleKind.EXPLORER,
                RoleKind.STRATEGIST,
                RoleKind.ATTACKER,
                RoleKind.JUDGE,
            )
        },
        max_model_turns=8,
        max_total_tokens=4_096,
    )


def test_provider_role_model_parses_one_strict_object_and_reports_usage() -> None:
    transport = FakeTransport((_response('{"candidates":[["hello"]]}'),))
    adapter = OpenAIAdapter(transport, secret_resolver=lambda _name: "fixture-secret")
    response = ProviderRoleModel(
        adapter,
        "fixture-model",
        RoleKind.ATTACKER,
    ).respond('{"contract":"fixture"}')

    assert response.structured == {"candidates": [["hello"]]}
    assert response.token_count == 10
    assert response.tool_calls == ()
    request = transport.requests[0]
    assert request.url == "https://api.openai.com/v1/responses"
    assert b"fixture-secret" not in (request.body or b"")
    assert request.headers["authorization"] == "Bearer fixture-secret"


@pytest.mark.parametrize("text", ('```json\n{"x":1}\n```', "[]", "not-json"))
def test_provider_role_model_rejects_non_object_or_wrapped_output(text: str) -> None:
    adapter = OpenAIAdapter(
        FakeTransport((_response(text),)),
        secret_resolver=lambda _name: "fixture-secret",
    )
    with pytest.raises(ProviderError):
        ProviderRoleModel(adapter, "fixture-model", RoleKind.RECON).respond("fixture")


def test_provider_runtime_config_round_trip_is_secret_free_and_lazy() -> None:
    source = _config()
    parsed = provider_runtime_from_mapping(source.to_mapping())
    resolutions: list[str] = []

    def resolve(name: str) -> str:
        resolutions.append(name)
        return "never-returned-yet"

    router = provider_model_router(
        parsed,
        secret_resolver=resolve,
    )

    assert parsed == source
    assert router.has_role(RoleKind.ATTACKER)
    assert resolutions == []
    rendered = json.dumps(parsed.to_mapping())
    assert "API_KEY" not in rendered
    assert "secret" not in rendered.casefold()


def test_provider_runtime_config_fails_closed_on_missing_roles_and_bad_numbers() -> None:
    value = _config().to_mapping()
    del value["routes"]["judge"]
    with pytest.raises(ProviderError, match="missing required roles"):
        provider_runtime_from_mapping(value)

    value = _config().to_mapping()
    value["routes"]["attacker"]["timeoutSeconds"] = "0"
    with pytest.raises(ProviderError, match="timeout"):
        provider_runtime_from_mapping(value)


def test_agent_browser_cli_requires_explicit_provider_permission_before_io(
    capfd: pytest.CaptureFixture[str],
) -> None:
    missing = "missing.json"
    assert main(["hunt", "agent-browser", missing, missing, missing, "out"]) == 2
    assert "SOVA-PROVIDER-CALLS-NOT-ALLOWED" in capfd.readouterr().err

    assert (
        main(
            [
                "hunt",
                "agent-browser",
                missing,
                missing,
                missing,
                "out",
                "--allow-provider-calls",
            ]
        )
        == 2
    )
    assert "SOVA-LIVE-INTERACTIVE-APPROVAL" in capfd.readouterr().err


def test_public_provider_runtime_example_is_valid_and_secret_free() -> None:
    value = strict_json_loads(Path("examples/live/provider-runtime.json").read_bytes())
    assert isinstance(value, dict)
    parsed = provider_runtime_from_mapping(value)
    assert parsed.max_model_turns == 5
    rendered = json.dumps(parsed.to_mapping()).casefold()
    assert "api_key" not in rendered
    assert "secret" not in rendered


def test_named_provider_participant_is_credential_late() -> None:
    resolutions: list[str] = []

    def resolve(name: str) -> str:
        resolutions.append(name)
        return "fixture-secret"

    model = provider_model_from_route(
        ProviderRoute("openai", "fixture-model"),
        role="arena-defender",
        secret_resolver=resolve,
    )
    assert model.model_id == "openai:fixture-model:arena-defender"
    assert resolutions == []


def test_provider_role_model_rejects_invalid_roles_and_bounded_output() -> None:
    adapter = OpenAIAdapter(
        FakeTransport((_response('{"ok":true}'),)),
        secret_resolver=lambda _name: "fixture-secret",
    )
    for role in ("", "x" * 129):
        with pytest.raises(ProviderError, match="role"):
            ProviderRoleModel(adapter, "fixture-model", role)

    oversized = '{"value":"' + ("x" * (1024 * 1024)) + '"}'
    model = ProviderRoleModel(
        OpenAIAdapter(
            FakeTransport((_response(oversized),)),
            secret_resolver=lambda _name: "fixture-secret",
        ),
        "fixture-model",
        "bounded-role",
    )
    with pytest.raises(ProviderError, match="byte limit"):
        model.respond("fixture")


def test_provider_role_model_reports_unknown_usage_as_none() -> None:
    body = json.dumps(
        {
            "id": "response-fixture",
            "status": "completed",
            "output_text": '{"ok":true}',
            "usage": {"input_tokens": "unknown", "cached": False},
        }
    ).encode()
    model = ProviderRoleModel(
        OpenAIAdapter(
            FakeTransport((HttpResponse(200, {}, body),)),
            secret_resolver=lambda _name: "fixture-secret",
        ),
        "fixture-model",
        RoleKind.RECON,
    )
    assert model.respond("fixture").token_count is None


@pytest.mark.parametrize(
    ("provider", "model"),
    [("unknown", "model"), ("openai", "")],
)
def test_provider_route_rejects_unsupported_provider_or_empty_model(
    provider: str,
    model: str,
) -> None:
    with pytest.raises(ProviderError):
        ProviderRoute(provider, model)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda value: value.update(extra=True), "fields"),
        (lambda value: value.update(schemaVersion="9"), "version"),
        (lambda value: value.update(routes=[]), "routes and budgets"),
        (lambda value: value["budgets"].update(extra=1), "budget fields"),
        (
            lambda value: value["routes"].update(
                {"unsupported-role": value["routes"].pop("recon")}
            ),
            "role is unsupported",
        ),
        (lambda value: value["routes"].update(recon=[]), "route fields"),
        (
            lambda value: value["routes"]["recon"].update(temperature="not-a-number"),
            "route numbers",
        ),
        (
            lambda value: value["routes"]["recon"].update(maxOutputTokens=True),
            "token limit",
        ),
        (lambda value: value["budgets"].update(maxModelTurns=True), "model-turn budget"),
        (lambda value: value["budgets"].update(maxTotalTokens="many"), "token budget"),
    ],
)
def test_provider_runtime_parser_rejects_each_hostile_shape(
    mutate: object,
    message: str,
) -> None:
    value = _config().to_mapping()
    assert callable(mutate)
    mutate(value)
    with pytest.raises(ProviderError, match=message):
        provider_runtime_from_mapping(value)


def test_provider_runtime_budget_bounds_and_all_adapter_routes_are_lazy() -> None:
    routes = dict(_config().routes)
    providers = ("openai", "anthropic", "openrouter", "ollama", "openai")
    for role, provider in zip(routes, providers, strict=True):
        routes[role] = ProviderRoute(provider, f"{provider}-fixture")
    resolutions: list[str] = []

    def resolve(name: str) -> str:
        resolutions.append(name)
        return "fixture-secret"

    router = provider_model_router(
        ProviderRuntimeConfig(routes, max_total_tokens=None),
        secret_resolver=resolve,
    )
    assert all(router.has_role(role) for role in routes)
    assert resolutions == []

    for turns, tokens in ((4, None), (101, None), (8, 0), (8, 10_000_001)):
        with pytest.raises(ProviderError, match="budget"):
            ProviderRuntimeConfig(routes, max_model_turns=turns, max_total_tokens=tokens)
