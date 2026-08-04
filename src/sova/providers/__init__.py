# SPDX-License-Identifier: Apache-2.0
"""Provider-neutral observable model adapters."""

from sova.providers.core import (
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

__all__ = [
    "AnthropicAdapter",
    "FakeTransport",
    "HttpRequest",
    "HttpResponse",
    "KeyringSecretResolver",
    "ModelRequest",
    "ModelResult",
    "OllamaAdapter",
    "OpenAIAdapter",
    "OpenRouterAdapter",
    "ProviderAdapter",
    "ProviderError",
    "ProviderRoleRouter",
    "UrllibTransport",
    "compare_model_results",
    "run_model_swap",
]
