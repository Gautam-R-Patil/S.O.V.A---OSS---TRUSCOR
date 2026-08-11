# SPDX-License-Identifier: Apache-2.0
"""Authenticated monitoring webhook and service-integration tests."""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import TYPE_CHECKING, Any

import pytest

import sova.monitoring.alerts as alerts_module
from sova.cli import main
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.monitoring import (
    ContinuousMonitorService,
    StrictWebhookTransport,
    WebhookAlertNotifier,
    monitoring_jobs_from_document,
)

if TYPE_CHECKING:
    from pathlib import Path


class _AcknowledgingTransport:
    def __init__(self, secret: bytes, *, fail_first: bool = False) -> None:
        self.secret = secret
        self.fail_first = fail_first
        self.calls: list[tuple[str, bytes, dict[str, str]]] = []

    def post(
        self,
        endpoint: str,
        body: bytes,
        headers: dict[str, str],
        *,
        timeout_seconds: float,
    ) -> tuple[int, bytes]:
        assert timeout_seconds > 0
        self.calls.append((endpoint, body, headers))
        identifier = sha256_digest(body)
        signed = headers["X-SOVA-Timestamp"].encode() + b"\n" + identifier.encode() + b"\n" + body
        expected = hmac.new(self.secret, signed, hashlib.sha256).hexdigest()
        assert headers["X-SOVA-Signature"] == f"hmac-sha256={expected}"
        assert headers["Idempotency-Key"] == identifier
        if self.fail_first and len(self.calls) == 1:
            return 503, b'{"accepted":false}'
        return 202, canonical_json_bytes({"accepted": True, "idempotencyKey": identifier})


class _RejectingTransport:
    def post(
        self,
        endpoint: str,
        body: bytes,
        headers: dict[str, str],
        *,
        timeout_seconds: float,
    ) -> tuple[int, bytes]:
        del endpoint, body, headers, timeout_seconds
        return 200, b'{"accepted":false,"idempotencyKey":"wrong"}'


class _AlertResponse:
    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self.body = body

    def read(self, _limit: int) -> bytes:
        return self.body


class _AlertConnection:
    def __init__(self, response: _AlertResponse | None = None, *, fails: bool = False) -> None:
        self.response = response or _AlertResponse(202, b"{}")
        self.fails = fails
        self.closed = False

    def request(self, *_args: Any, **_kwargs: Any) -> None:
        if self.fails:
            raise OSError("fixture failure")  # noqa: TRY003

    def getresponse(self) -> _AlertResponse:
        return self.response

    def close(self) -> None:
        self.closed = True


def _alert() -> dict[str, Any]:
    return {
        "artifactType": "sova.monitor-alert",
        "schemaVersion": "0.1.0",
        "runId": "fixture-run",
        "jobId": "fixture-job",
        "status": "failed",
        "triggers": ["behavioral-drift-threshold"],
        "traceDigest": "sha256:" + ("a" * 64),
    }


def test_webhook_is_authenticated_idempotent_acknowledged_and_retried() -> None:
    secret = b"s" * 32
    transport = _AcknowledgingTransport(secret, fail_first=True)
    notifier = WebhookAlertNotifier(
        "https://alerts.example.test/sova",
        secret,
        transport=transport,
    )

    result = notifier.notify(_alert())

    assert result["status"] == "acknowledged"
    assert result["attempts"] == 2
    assert result["secretRecorded"] is False
    assert result["endpointOrigin"] == "https://alerts.example.test"
    assert len({call[2]["Idempotency-Key"] for call in transport.calls}) == 1


def test_webhook_rejects_unsafe_endpoints_secrets_and_false_acknowledgements() -> None:
    with pytest.raises(FormatError, match="HTTPS"):
        WebhookAlertNotifier("http://alerts.example.test/hook", b"s" * 32)
    with pytest.raises(FormatError, match="32 bytes"):
        WebhookAlertNotifier("https://alerts.example.test/hook", b"short")

    notifier = WebhookAlertNotifier(
        "http://127.0.0.1:8123/hook",
        b"s" * 32,
        transport=_RejectingTransport(),
        max_attempts=2,
    )
    result = notifier.notify(_alert())
    assert result["status"] == "failed"
    assert result["attempts"] == 2


@pytest.mark.parametrize(
    "endpoint",
    (
        "ftp://alerts.example.test/hook",
        "https://user@alerts.example.test/hook",
        "https://alerts.example.test/hook?secret=no",
        "https://alerts.example.test/hook#fragment",
        "http://192.0.2.1/hook",
    ),
)
def test_webhook_endpoint_validation_rejects_ambiguous_authority(endpoint: str) -> None:
    with pytest.raises(FormatError, match="HTTPS"):
        WebhookAlertNotifier(endpoint, b"s" * 32)


def test_strict_webhook_transport_uses_bounded_connections_and_closes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = StrictWebhookTransport()
    connection = _AlertConnection(_AlertResponse(202, b'{"accepted":true}'))
    monkeypatch.setattr(
        alerts_module,
        "HTTPConnection",
        lambda *_args, **_kwargs: connection,
    )
    status, body = transport.post(
        "http://127.0.0.1:8123",
        b"{}",
        {"Content-Type": "application/json"},
        timeout_seconds=1,
    )
    assert (status, body) == (202, b'{"accepted":true}')
    assert connection.closed

    secure = _AlertConnection(_AlertResponse(200, b"{}"))
    monkeypatch.setattr(
        alerts_module,
        "HTTPSConnection",
        lambda *_args, **_kwargs: secure,
    )
    monkeypatch.setattr("sova.monitoring.alerts.ssl.create_default_context", object)
    assert (
        transport.post(
            "https://alerts.example.test/path",
            b"{}",
            {},
            timeout_seconds=1,
        )[0]
        == 200
    )

    oversized = _AlertConnection(_AlertResponse(200, b"x" * (64 * 1024 + 1)))
    monkeypatch.setattr(
        alerts_module,
        "HTTPConnection",
        lambda *_args, **_kwargs: oversized,
    )
    with pytest.raises(FormatError, match="64 KiB"):
        transport.post("http://localhost/hook", b"{}", {}, timeout_seconds=1)

    broken = _AlertConnection(fails=True)
    monkeypatch.setattr(
        alerts_module,
        "HTTPConnection",
        lambda *_args, **_kwargs: broken,
    )
    with pytest.raises(FormatError, match="delivery failed"):
        transport.post("http://localhost/hook", b"{}", {}, timeout_seconds=1)
    assert broken.closed


class _MalformedTransport:
    def post(
        self,
        endpoint: str,
        body: bytes,
        headers: dict[str, str],
        *,
        timeout_seconds: float,
    ) -> tuple[int, bytes]:
        del endpoint, body, headers, timeout_seconds
        return 200, b"not-json"


def test_webhook_configuration_bounds_and_malformed_acknowledgement() -> None:
    with pytest.raises(FormatError, match="bounds"):
        WebhookAlertNotifier("https://alerts.example.test", b"s" * 32, timeout_seconds=0)
    with pytest.raises(FormatError, match="bounds"):
        WebhookAlertNotifier("https://alerts.example.test", b"s" * 32, max_attempts=4)
    report = WebhookAlertNotifier(
        "https://alerts.example.test:443/path",
        b"s" * 32,
        transport=_MalformedTransport(),
        max_attempts=1,
    ).notify(_alert())
    assert report["failureClasses"] == ["attempt-1:transport-or-acknowledgement-error"]
    assert report["endpointOrigin"] == "https://alerts.example.test:443"


class _RecordingNotifier:
    def __init__(self) -> None:
        self.alerts: list[dict[str, Any]] = []

    def notify(self, alert: dict[str, Any]) -> dict[str, Any]:
        self.alerts.append(alert)
        return {"mode": "fixture", "status": "acknowledged"}


def _snapshot(identity: str, marker: str) -> dict[str, Any]:
    return {
        "id": identity,
        "target": {"kind": "fixture"},
        "environment": {"platform": "test"},
        "methodology": {"profile": "standard"},
        "observedEffects": [{"marker": marker}],
        "reproductionRates": {"marker": "1/1"},
        "findings": [],
        "approvalSurface": {"mode": "explicit"},
        "registrySnapshot": {"digest": "sha256:" + ("0" * 64)},
    }


def test_monitor_service_delivers_only_failed_alerts_without_paths_or_secrets(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "baseline.json").write_bytes(canonical_json_bytes(_snapshot("base", "safe")))
    (workspace / "current.json").write_bytes(canonical_json_bytes(_snapshot("current", "changed")))
    jobs = monitoring_jobs_from_document(
        {
            "artifactType": "sova.monitor-service-spec",
            "schemaVersion": "0.1.0",
            "jobs": [
                {
                    "id": "fixture-drift",
                    "baseline": "baseline.json",
                    "current": "current.json",
                    "policy": None,
                    "intervalSeconds": 1,
                    "retentionRuns": 2,
                }
            ],
        },
        workspace=workspace,
    )
    notifier = _RecordingNotifier()
    result = ContinuousMonitorService(
        jobs,
        tmp_path / "state",
        notifier=notifier,
    ).run_job("fixture-drift")

    assert result["alertDelivery"]["status"] == "acknowledged"
    assert len(notifier.alerts) == 1
    encoded = json.dumps(notifier.alerts[0])
    assert str(tmp_path) not in encoded
    assert "secret" not in encoded.casefold()


def test_monitor_cli_resolves_webhook_secret_late_without_printing_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "baseline.json").write_bytes(canonical_json_bytes(_snapshot("base", "safe")))
    (workspace / "current.json").write_bytes(canonical_json_bytes(_snapshot("current", "changed")))
    specification = tmp_path / "monitor.json"
    specification.write_bytes(
        canonical_json_bytes(
            {
                "artifactType": "sova.monitor-service-spec",
                "schemaVersion": "0.1.0",
                "jobs": [
                    {
                        "id": "fixture-drift",
                        "baseline": "baseline.json",
                        "current": "current.json",
                        "policy": None,
                        "intervalSeconds": 1,
                        "retentionRuns": 2,
                    }
                ],
            }
        )
    )
    notifier = _RecordingNotifier()
    monkeypatch.setenv("SOVA_TEST_ALERT_SECRET", "not-recorded-" + ("s" * 32))
    monkeypatch.setattr(
        "sova.cli.WebhookAlertNotifier",
        lambda _endpoint, _secret: notifier,
    )

    assert (
        main(
            [
                "monitor",
                "serve",
                str(specification),
                str(tmp_path / "state"),
                "--workspace",
                str(workspace),
                "--once",
                "--alert-webhook",
                "https://alerts.example.test/sova",
                "--alert-secret-env",
                "SOVA_TEST_ALERT_SECRET",
            ]
        )
        == 1
    )
    output = capsys.readouterr().out
    assert "not-recorded" not in output
    assert len(notifier.alerts) == 1
