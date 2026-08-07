# SPDX-License-Identifier: Apache-2.0
"""Credential-late, transport-injected adapters for supported model providers."""

from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from importlib import import_module
from typing import Any, Protocol
from urllib.parse import urlsplit

from sova.formats import strict_json_loads
from sova.formats.errors import FormatError

_MAX_PROVIDER_RESPONSE = 8 * 1024 * 1024
_MAX_TIMEOUT_SECONDS = 60
_MAX_MODEL_NAME = 256
_MAX_TEMPERATURE = 2
_MAX_OUTPUT_TOKENS = 32768
_RATE_LIMIT_STATUS = 429
_HTTP_SUCCESS_MIN = 200
_HTTP_SUCCESS_MAX = 300
_MIN_SWAP_CONFIGURATIONS = 2


class ProviderError(FormatError):
    """Normalized provider failure that never includes credential values."""


@dataclass(frozen=True, slots=True)
class HttpRequest:
    method: str
    url: str
    headers: Mapping[str, str]
    body: bytes | None


@dataclass(frozen=True, slots=True)
class HttpResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


class HttpTransport(Protocol):
    def send(self, request: HttpRequest, *, timeout: float) -> HttpResponse: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        _req: Any,
        _fp: Any,
        _code: int,
        _msg: str,
        _headers: Any,
        _newurl: str,
    ) -> None:
        return None


class UrllibTransport:
    """Small HTTPS transport with exact origins, no redirects, and bounded responses."""

    def __init__(self, allowed_origins: tuple[str, ...]) -> None:
        normalized: set[str] = set()
        for origin in allowed_origins:
            parsed = urlsplit(origin)
            if parsed.scheme not in {"https", "http"} or not parsed.netloc or parsed.path:
                raise FormatError("SOVA-PROVIDER-ORIGIN", "provider origin is invalid")
            if parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
                raise FormatError("SOVA-PROVIDER-TLS", "non-loopback providers require HTTPS")
            normalized.add(f"{parsed.scheme}://{parsed.netloc}")
        self.allowed_origins = frozenset(normalized)

    def send(self, request: HttpRequest, *, timeout: float) -> HttpResponse:
        parsed = urlsplit(request.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin not in self.allowed_origins or parsed.username or parsed.password:
            raise ProviderError("SOVA-PROVIDER-ORIGIN", "request origin is not pinned")
        if not 0 < timeout <= _MAX_TIMEOUT_SECONDS:
            raise ProviderError(
                "SOVA-PROVIDER-TIMEOUT", "provider timeout must be within 60 seconds"
            )
        opener = urllib.request.build_opener(
            _NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context())
        )
        outbound = urllib.request.Request(  # noqa: S310 - scheme and origin pinned above
            request.url,
            method=request.method,
            headers=dict(request.headers),
            data=request.body,
        )
        try:
            with opener.open(outbound, timeout=timeout) as response:
                body = response.read(_MAX_PROVIDER_RESPONSE + 1)
                if len(body) > _MAX_PROVIDER_RESPONSE:
                    raise ProviderError(
                        "SOVA-PROVIDER-OUTPUT-LIMIT", "provider response exceeded limit"
                    )
                return HttpResponse(response.status, dict(response.headers.items()), body)
        except urllib.error.HTTPError as error:
            body = error.read(_MAX_PROVIDER_RESPONSE + 1)
            return HttpResponse(error.code, dict(error.headers.items()), body)
        except urllib.error.URLError as error:
            raise ProviderError("SOVA-PROVIDER-NETWORK", "provider request failed") from error


class FakeTransport:
    """Deterministic no-network transport used by mandatory tests."""

    def __init__(self, responses: Sequence[HttpResponse]) -> None:
        self.responses = list(responses)
        self.requests: list[HttpRequest] = []

    def send(self, request: HttpRequest, *, timeout: float) -> HttpResponse:
        del timeout
        self.requests.append(request)
        if not self.responses:
            raise AssertionError
        return self.responses.pop(0)


@dataclass(frozen=True, slots=True)
class ModelRequest:
    model: str
    messages: tuple[dict[str, str], ...]
    temperature: float = 0.0
    max_output_tokens: int = 512
    timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        if not self.model or len(self.model) > _MAX_MODEL_NAME:
            raise ProviderError("SOVA-PROVIDER-MODEL", "model identifier is invalid")
        if not self.messages:
            raise ProviderError("SOVA-PROVIDER-MESSAGES", "at least one message is required")
        if not 0 <= self.temperature <= _MAX_TEMPERATURE:
            raise ProviderError("SOVA-PROVIDER-TEMPERATURE", "temperature is outside 0..2")
        if not 1 <= self.max_output_tokens <= _MAX_OUTPUT_TOKENS:
            raise ProviderError("SOVA-PROVIDER-TOKENS", "output token budget is invalid")
        if not 0 < self.timeout_seconds <= _MAX_TIMEOUT_SECONDS:
            raise ProviderError(
                "SOVA-PROVIDER-TIMEOUT",
                "provider timeout must be within 60 seconds",
            )
        for message in self.messages:
            if set(message) != {"role", "content"} or message["role"] not in {
                "system",
                "user",
                "assistant",
            }:
                raise ProviderError("SOVA-PROVIDER-MESSAGES", "message shape is invalid")


@dataclass(frozen=True, slots=True)
class ModelResult:
    provider: str
    model: str
    text: str
    finish_reason: str | None
    usage: Mapping[str, int | None]
    response_id: str | None
    cost_status: str = "provider-pricing-not-pinned"
    estimated_cost: float | None = None


SecretResolver = Callable[[str], str | None]


def _environment_secret(name: str) -> str | None:
    return os.environ.get(name)


class KeyringSecretResolver:
    """Optional OS-keyring bridge; key material is never serialized by SOVA."""

    service = "sova-oss"
    _allowed = frozenset({"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OPENROUTER_API_KEY"})

    def _keyring(self) -> Any:
        try:
            return import_module("keyring")
        except ImportError as error:
            raise ProviderError(
                "SOVA-PROVIDER-KEYRING",
                "install an OS keyring backend to use local credential storage",
            ) from error

    def __call__(self, name: str) -> str | None:
        if name not in self._allowed:
            raise ProviderError("SOVA-PROVIDER-CREDENTIAL-NAME", "credential name is not allowed")
        value = self._keyring().get_password(self.service, name)
        return value if isinstance(value, str) and value else None

    def store(self, name: str, value: str) -> None:
        if name not in self._allowed or not value:
            raise ProviderError("SOVA-PROVIDER-CREDENTIAL-NAME", "credential is invalid")
        self._keyring().set_password(self.service, name, value)

    def delete(self, name: str) -> None:
        if name not in self._allowed:
            raise ProviderError("SOVA-PROVIDER-CREDENTIAL-NAME", "credential name is not allowed")
        self._keyring().delete_password(self.service, name)


class ProviderAdapter:
    """Base adapter: credentials are resolved only immediately before the call."""

    provider: str
    origin: str
    credential_name: str | None

    def __init__(
        self,
        transport: HttpTransport,
        *,
        secret_resolver: SecretResolver = _environment_secret,
    ) -> None:
        self.transport = transport
        self.secret_resolver = secret_resolver

    def _credential(self) -> str | None:
        if self.credential_name is None:
            return None
        value = self.secret_resolver(self.credential_name)
        if value is None or not value:
            raise ProviderError(
                "SOVA-PROVIDER-CREDENTIAL",
                f"required credential {self.credential_name} is unavailable",
            )
        return value

    def _request(self, request: ModelRequest) -> HttpRequest:
        raise NotImplementedError

    def _parse(self, request: ModelRequest, response: dict[str, Any]) -> ModelResult:
        raise NotImplementedError

    def complete(self, request: ModelRequest) -> ModelResult:
        response = self.transport.send(self._request(request), timeout=request.timeout_seconds)
        if response.status == _RATE_LIMIT_STATUS:
            raise ProviderError(
                "SOVA-PROVIDER-RATE-LIMIT",
                "provider rate limit reached",
                details={"retryAfter": response.headers.get("retry-after")},
            )
        if not _HTTP_SUCCESS_MIN <= response.status < _HTTP_SUCCESS_MAX:
            raise ProviderError(
                "SOVA-PROVIDER-HTTP",
                "provider returned an error",
                details={"status": response.status},
            )
        decoded = strict_json_loads(response.body, max_bytes=_MAX_PROVIDER_RESPONSE)
        if not isinstance(decoded, dict):
            raise ProviderError("SOVA-PROVIDER-RESPONSE", "provider response must be an object")
        return self._parse(request, decoded)

    def list_models(self, *, timeout_seconds: float = 10.0) -> tuple[str, ...]:
        raise NotImplementedError

    def _model_request(self, url: str, headers: Mapping[str, str]) -> tuple[str, ...]:
        response = self.transport.send(HttpRequest("GET", url, headers, None), timeout=10.0)
        if not _HTTP_SUCCESS_MIN <= response.status < _HTTP_SUCCESS_MAX:
            raise ProviderError(
                "SOVA-PROVIDER-DISCOVERY",
                "model discovery failed",
                details={"status": response.status},
            )
        decoded = strict_json_loads(response.body, max_bytes=_MAX_PROVIDER_RESPONSE)
        if not isinstance(decoded, dict):
            raise ProviderError("SOVA-PROVIDER-DISCOVERY", "model discovery response is invalid")
        rows = decoded.get("data", decoded.get("models", []))
        if not isinstance(rows, list):
            raise ProviderError("SOVA-PROVIDER-DISCOVERY", "model list is invalid")
        names = {
            str(item.get("id", item.get("name")))
            for item in rows
            if isinstance(item, dict) and item.get("id", item.get("name"))
        }
        return tuple(sorted(names))


def _json_headers(**extra: str) -> dict[str, str]:
    return {"content-type": "application/json", "accept": "application/json", **extra}


def _provider_json_bytes(value: dict[str, Any]) -> bytes:
    """Serialize provider JSON with finite floats; SOVA artifacts still use canonical JSON."""
    return json.dumps(value, allow_nan=False, ensure_ascii=False, separators=(",", ":")).encode()


class OpenAIAdapter(ProviderAdapter):
    provider = "openai"
    origin = "https://api.openai.com"
    credential_name = "OPENAI_API_KEY"

    def _headers(self) -> dict[str, str]:
        return _json_headers(authorization=f"Bearer {self._credential()}")

    def _request(self, request: ModelRequest) -> HttpRequest:
        body = {
            "model": request.model,
            "input": list(request.messages),
            "temperature": request.temperature,
            "max_output_tokens": request.max_output_tokens,
            "store": False,
        }
        return HttpRequest(
            "POST", f"{self.origin}/v1/responses", self._headers(), _provider_json_bytes(body)
        )

    def _parse(self, request: ModelRequest, response: dict[str, Any]) -> ModelResult:
        text = response.get("output_text")
        if not isinstance(text, str):
            text = "".join(
                str(content.get("text", ""))
                for item in response.get("output", [])
                if isinstance(item, dict)
                for content in item.get("content", [])
                if isinstance(content, dict) and content.get("type") in {"output_text", "text"}
            )
        usage = response.get("usage", {})
        return ModelResult(
            self.provider,
            request.model,
            text,
            response.get("status") if isinstance(response.get("status"), str) else None,
            {
                "inputTokens": usage.get("input_tokens") if isinstance(usage, dict) else None,
                "outputTokens": usage.get("output_tokens") if isinstance(usage, dict) else None,
            },
            response.get("id") if isinstance(response.get("id"), str) else None,
        )

    def list_models(self, *, timeout_seconds: float = 10.0) -> tuple[str, ...]:
        del timeout_seconds
        return self._model_request(f"{self.origin}/v1/models", self._headers())


class AnthropicAdapter(ProviderAdapter):
    provider = "anthropic"
    origin = "https://api.anthropic.com"
    credential_name = "ANTHROPIC_API_KEY"

    def _headers(self) -> dict[str, str]:
        return _json_headers(
            **{"x-api-key": str(self._credential()), "anthropic-version": "2023-06-01"}
        )

    def _request(self, request: ModelRequest) -> HttpRequest:
        body = {
            "model": request.model,
            "messages": [item for item in request.messages if item["role"] != "system"],
            "system": "\n".join(
                item["content"] for item in request.messages if item["role"] == "system"
            ),
            "temperature": request.temperature,
            "max_tokens": request.max_output_tokens,
        }
        return HttpRequest(
            "POST", f"{self.origin}/v1/messages", self._headers(), _provider_json_bytes(body)
        )

    def _parse(self, request: ModelRequest, response: dict[str, Any]) -> ModelResult:
        text = "".join(
            str(item.get("text", ""))
            for item in response.get("content", [])
            if isinstance(item, dict) and item.get("type") == "text"
        )
        usage = response.get("usage", {})
        return ModelResult(
            self.provider,
            request.model,
            text,
            response.get("stop_reason") if isinstance(response.get("stop_reason"), str) else None,
            {
                "inputTokens": usage.get("input_tokens") if isinstance(usage, dict) else None,
                "outputTokens": usage.get("output_tokens") if isinstance(usage, dict) else None,
            },
            response.get("id") if isinstance(response.get("id"), str) else None,
        )

    def list_models(self, *, timeout_seconds: float = 10.0) -> tuple[str, ...]:
        del timeout_seconds
        return self._model_request(f"{self.origin}/v1/models", self._headers())


class OpenRouterAdapter(ProviderAdapter):
    provider = "openrouter"
    origin = "https://openrouter.ai"
    credential_name = "OPENROUTER_API_KEY"

    def _headers(self) -> dict[str, str]:
        return _json_headers(authorization=f"Bearer {self._credential()}")

    def _request(self, request: ModelRequest) -> HttpRequest:
        body = {
            "model": request.model,
            "messages": list(request.messages),
            "temperature": request.temperature,
            "max_tokens": request.max_output_tokens,
        }
        return HttpRequest(
            "POST",
            f"{self.origin}/api/v1/chat/completions",
            self._headers(),
            _provider_json_bytes(body),
        )

    def _parse(self, request: ModelRequest, response: dict[str, Any]) -> ModelResult:
        choices = response.get("choices", [])
        choice = choices[0] if isinstance(choices, list) and choices else {}
        message = choice.get("message", {}) if isinstance(choice, dict) else {}
        usage = response.get("usage", {})
        return ModelResult(
            self.provider,
            request.model,
            str(message.get("content", "")) if isinstance(message, dict) else "",
            choice.get("finish_reason") if isinstance(choice, dict) else None,
            {
                "inputTokens": usage.get("prompt_tokens") if isinstance(usage, dict) else None,
                "outputTokens": usage.get("completion_tokens") if isinstance(usage, dict) else None,
            },
            response.get("id") if isinstance(response.get("id"), str) else None,
        )

    def list_models(self, *, timeout_seconds: float = 10.0) -> tuple[str, ...]:
        del timeout_seconds
        return self._model_request(f"{self.origin}/api/v1/models", self._headers())


class OllamaAdapter(ProviderAdapter):
    provider = "ollama"
    origin = "http://127.0.0.1:11434"
    credential_name = None

    def _request(self, request: ModelRequest) -> HttpRequest:
        body = {
            "model": request.model,
            "messages": list(request.messages),
            "stream": False,
            "options": {
                "temperature": request.temperature,
                "num_predict": request.max_output_tokens,
            },
        }
        return HttpRequest(
            "POST", f"{self.origin}/api/chat", _json_headers(), _provider_json_bytes(body)
        )

    def _parse(self, request: ModelRequest, response: dict[str, Any]) -> ModelResult:
        message = response.get("message", {})
        return ModelResult(
            self.provider,
            request.model,
            str(message.get("content", "")) if isinstance(message, dict) else "",
            "stop" if response.get("done") is True else None,
            {
                "inputTokens": response.get("prompt_eval_count")
                if isinstance(response.get("prompt_eval_count"), int)
                else None,
                "outputTokens": response.get("eval_count")
                if isinstance(response.get("eval_count"), int)
                else None,
            },
            None,
            cost_status="local-runtime-no-provider-price",
        )

    def list_models(self, *, timeout_seconds: float = 10.0) -> tuple[str, ...]:
        del timeout_seconds
        return self._model_request(f"{self.origin}/api/tags", _json_headers())


def compare_model_results(results: Sequence[ModelResult]) -> dict[str, Any]:
    """Return observable comparison facts without pretending to judge semantic equivalence."""
    if not results:
        raise ProviderError("SOVA-PROVIDER-COMPARE", "at least one result is required")
    return {
        "artifactType": "sova.provider-comparison",
        "resultCount": len(results),
        "models": [f"{item.provider}:{item.model}" for item in results],
        "exactTextAgreement": len({item.text for item in results}) == 1,
        "outputLengths": [len(item.text) for item in results],
        "usage": [dict(item.usage) for item in results],
        "semanticJudgment": "not-performed",
    }


class ProviderRoleRouter:
    """Select an independently configured provider/model for each experimental role."""

    def __init__(self, routes: Mapping[str, tuple[ProviderAdapter, str]]) -> None:
        allowed = {"attacker", "judge", "mutator", "oracle", "target-model"}
        if not routes or any(role not in allowed for role in routes):
            raise ProviderError("SOVA-PROVIDER-ROLE", "provider role map is invalid")
        self.routes = dict(routes)

    def complete(self, role: str, request: ModelRequest) -> ModelResult:
        try:
            adapter, model = self.routes[role]
        except KeyError as error:
            raise ProviderError("SOVA-PROVIDER-ROLE", "provider role is not configured") from error
        return adapter.complete(replace(request, model=model))


def run_model_swap(
    configurations: Sequence[tuple[ProviderAdapter, str]], request: ModelRequest
) -> tuple[ModelResult, ...]:
    """Run the same observable request envelope across explicit provider/model choices."""
    if len(configurations) < _MIN_SWAP_CONFIGURATIONS:
        raise ProviderError("SOVA-PROVIDER-SWAP", "model swap requires at least two configurations")
    return tuple(
        adapter.complete(replace(request, model=model)) for adapter, model in configurations
    )
