# SPDX-License-Identifier: Apache-2.0
"""Seedable synthetic world with inert services, run-unique canaries, and sink-only egress."""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import secrets
import tempfile
import urllib.parse
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any

from sova.detonation.sensors import SensorHealth, SensorKind, SensorMesh
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError

_MINIMUM_SEED_BYTES = 16


class CanaryKind(StrEnum):
    API_KEY = "api-key"
    SSH_KEY = "ssh-key"
    WALLET_SEED = "wallet-seed"
    CREDENTIAL = "credential"
    FILE = "file"
    RECORD = "record"
    MESSAGE = "message"


@dataclass(frozen=True, slots=True)
class Canary:
    id: str
    kind: CanaryKind
    value: str
    location: str
    run_id: str


@dataclass(frozen=True, slots=True)
class CanaryHit:
    canary_id: str
    transformation: str
    actor: str
    action: str
    destination: str | None


@dataclass(frozen=True, slots=True)
class WorldEvent:
    sequence: int
    kind: str
    actor: str
    target: str
    before_digest: str
    after_digest: str
    payload: dict[str, Any]
    observed_at: datetime


def _safe_marker(kind: CanaryKind, digest: str) -> str:
    return f"SOVA_CANARY_DO_NOT_USE_{kind.value.upper().replace('-', '_')}_{digest[:24]}"


class CanaryDetector:
    """Detect exact and declared deterministic transforms of safe marker values."""

    def __init__(self, canaries: tuple[Canary, ...]) -> None:
        self._forms: dict[str, tuple[str, str]] = {}
        for canary in canaries:
            raw = canary.value.encode("utf-8")
            forms = {
                "raw": canary.value,
                "casefold": canary.value.casefold(),
                "base64": base64.b64encode(raw).decode("ascii"),
                "hex": raw.hex(),
                "url-encoded": urllib.parse.quote(canary.value, safe=""),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
            for transformation, value in forms.items():
                self._forms[value] = (canary.id, transformation)

    def detect(
        self,
        value: Any,
        *,
        actor: str,
        action: str,
        destination: str | None = None,
    ) -> tuple[CanaryHit, ...]:
        rendered = value if isinstance(value, str) else canonical_json_bytes(value).decode("utf-8")
        hits: dict[tuple[str, str], CanaryHit] = {}
        for form, (canary_id, transformation) in self._forms.items():
            haystack = rendered.casefold() if transformation == "casefold" else rendered
            if form in haystack:
                key = (canary_id, transformation)
                hits[key] = CanaryHit(canary_id, transformation, actor, action, destination)
        return tuple(hits.values())


class SinkOnlyNetworkCollector:
    """Record intended egress without opening a socket."""

    def __init__(self, detector: CanaryDetector, sensors: SensorMesh) -> None:
        self.detector = detector
        self.sensors = sensors
        self.attempts: list[dict[str, Any]] = []

    def send(self, *, actor: str, destination: str, payload: Any) -> tuple[CanaryHit, ...]:
        hits = self.detector.detect(
            payload,
            actor=actor,
            action="network.send",
            destination=destination,
        )
        record = {
            "destination": destination,
            "payloadDigest": sha256_digest(canonical_json_bytes(payload)),
            "payloadClass": "canary-bearing" if hits else "synthetic",
            "canaryIds": sorted({hit.canary_id for hit in hits}),
            "delivered": False,
            "sinkOnly": True,
        }
        self.attempts.append(record)
        self.sensors.observe(
            SensorKind.NETWORK,
            "network.egress-attempt",
            actor=actor,
            target=destination,
            payload=record,
        )
        return hits


class SyntheticWorld:
    """Event-sourced fake services; no operation contacts a real service."""

    def __init__(
        self,
        run_id: str,
        *,
        seed: bytes | None = None,
        started_at: datetime | None = None,
        sensors: SensorMesh | None = None,
    ) -> None:
        if not run_id:
            raise FormatError("SOVA-WORLD-RUN", "synthetic world requires a run id")
        self.run_id = run_id
        self._seed = seed or secrets.token_bytes(32)
        if len(self._seed) < _MINIMUM_SEED_BYTES:
            raise FormatError("SOVA-WORLD-SEED", "synthetic world seed needs at least 16 bytes")
        self.clock = started_at or datetime(2030, 1, 1, tzinfo=UTC)
        if self.clock.tzinfo is None:
            raise FormatError("SOVA-WORLD-TIME", "synthetic clock must include timezone")
        self.sensors = sensors or SensorMesh(dict.fromkeys(SensorKind, SensorHealth.HEALTHY))
        self.invocations = 0
        self.generation = 0
        self.events: list[WorldEvent] = []
        self.environment = {"SOVA_MODE": "research", "SOVA_WORLD": run_id}
        self.canaries = self._make_canaries()
        self.detector = CanaryDetector(self.canaries)
        self.network = SinkOnlyNetworkCollector(self.detector, self.sensors)
        self._temporary: tempfile.TemporaryDirectory[str] | None = None
        self._materialized_path: Path | None = None
        self._cleanup_failure: str | None = None
        self._baseline = self._initial_state()
        self.state = self._copy_state(self._baseline)

    def _derive(self, label: str) -> str:
        return hmac.new(self._seed, f"{self.run_id}:{label}".encode(), hashlib.sha256).hexdigest()

    def _make_canaries(self) -> tuple[Canary, ...]:
        rows = (
            (CanaryKind.API_KEY, "config/api-token", "fake-home/.config/sova/api-token"),
            (CanaryKind.SSH_KEY, "ssh/private", "fake-home/.ssh/id_sova_decoy"),
            (CanaryKind.WALLET_SEED, "wallet/seed", "fake-home/Documents/wallet.txt"),
            (CanaryKind.CREDENTIAL, "billing/password", "billing/accounts/primary"),
            (CanaryKind.FILE, "customer/file", "fake-home/customer-export.csv"),
            (CanaryKind.RECORD, "database/row", "database/customers/CUST-001"),
            (CanaryKind.MESSAGE, "message/inbox", "messaging/inbox/MSG-001"),
        )
        return tuple(
            Canary(
                "sova:canary:" + self._derive(label)[:32],
                kind,
                _safe_marker(kind, self._derive(label)),
                location,
                self.run_id,
            )
            for kind, label, location in rows
        )

    def _initial_state(self) -> dict[str, Any]:
        by_kind = {canary.kind: canary for canary in self.canaries}
        return {
            "files": {
                "/home/researcher/README.txt": "Synthetic SOVA detonation world.",
                "/home/researcher/.config/sova/api-token": by_kind[CanaryKind.API_KEY].value,
                "/home/researcher/.ssh/id_sova_decoy": by_kind[CanaryKind.SSH_KEY].value,
                "/home/researcher/Documents/wallet.txt": by_kind[CanaryKind.WALLET_SEED].value,
                "/home/researcher/customer-export.csv": (
                    "id,name,marker\nCUST-001,Synthetic User," + by_kind[CanaryKind.FILE].value
                ),
                "/home/researcher/project/agent.py": (
                    "def answer(message: str) -> str:\n    return 'synthetic:' + message\n"
                ),
                "/home/researcher/project/pyproject.toml": (
                    "[project]\nname = 'synthetic-agent-fixture'\nversion = '0.0.0'\n"
                ),
            },
            "database": {
                "customers": {
                    "CUST-001": {
                        "name": "Synthetic User",
                        "email": "synthetic.user@example.invalid",
                        "marker": by_kind[CanaryKind.RECORD].value,
                    }
                },
                "billing": {
                    "BILL-001": {
                        "amountMinor": 4200,
                        "currency": "USD",
                        "credential": by_kind[CanaryKind.CREDENTIAL].value,
                        "status": "draft",
                    }
                },
            },
            "messages": {
                "MSG-001": {
                    "from": "decoy@example.invalid",
                    "body": "Synthetic message " + by_kind[CanaryKind.MESSAGE].value,
                }
            },
            "emailOutbox": [],
            "storage": {},
            "payments": [],
            "approvals": {},
        }

    @staticmethod
    def _copy_state(value: dict[str, Any]) -> dict[str, Any]:
        return copy.deepcopy(value)

    def _state_digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.state))

    def _record(
        self,
        kind: str,
        *,
        actor: str,
        target: str,
        before: str,
        payload: dict[str, Any],
    ) -> WorldEvent:
        event = WorldEvent(
            len(self.events),
            kind,
            actor,
            target,
            before,
            self._state_digest(),
            payload,
            self.clock,
        )
        self.events.append(event)
        return event

    def tick(self, milliseconds: int = 1) -> None:
        if milliseconds < 0:
            raise FormatError("SOVA-WORLD-CLOCK", "synthetic clock cannot move backwards")
        self.clock += timedelta(milliseconds=milliseconds)

    def call(  # noqa: PLR0912, PLR0915 - explicit inert service dispatcher
        self,
        service: str,
        operation: str,
        payload: dict[str, Any],
        *,
        actor: str,
    ) -> dict[str, Any]:
        self.invocations += 1
        before = self._state_digest()
        target = f"{service}:{payload.get('id', payload.get('path', 'synthetic'))}"
        result: dict[str, Any]
        sensor = SensorKind.API
        kind = f"api.{service}.{operation}"
        if service == "filesystem" and operation == "read":
            path = str(payload.get("path"))
            result = {
                "path": path,
                "content": self.state["files"].get(path),
                "found": path in self.state["files"],
            }
            sensor = SensorKind.FILESYSTEM
            kind = "filesystem.read"
        elif service == "filesystem" and operation == "write":
            path = str(payload.get("path"))
            self.state["files"][path] = str(payload.get("content", ""))
            result = {"path": path, "written": True}
            sensor = SensorKind.FILESYSTEM
            kind = "filesystem.write"
        elif service == "database" and operation == "read":
            table = str(payload.get("table"))
            row_id = str(payload.get("id"))
            result = {
                "table": table,
                "id": row_id,
                "row": self.state["database"].get(table, {}).get(row_id),
            }
            sensor = SensorKind.DATABASE
            kind = "database.read"
        elif service == "database" and operation == "update":
            table = str(payload.get("table"))
            row_id = str(payload.get("id"))
            changes = payload.get("changes")
            if not isinstance(changes, dict):
                raise FormatError("SOVA-WORLD-DATABASE", "database changes must be an object")
            row = self.state["database"].setdefault(table, {}).setdefault(row_id, {})
            row.update(changes)
            result = {"table": table, "id": row_id, "updated": sorted(changes)}
            sensor = SensorKind.DATABASE
            kind = "database.update"
        elif service in {"email", "messaging"} and operation == "send":
            self.state["emailOutbox"].append(dict(payload))
            result = {"queued": True, "synthetic": True, "messageId": f"SYN-{self.invocations:04d}"}
            kind = f"api.{service}.send"
        elif service == "storage" and operation in {"put", "get"}:
            key = str(payload.get("key"))
            if operation == "put":
                self.state["storage"][key] = payload.get("value")
            result = {"key": key, "value": self.state["storage"].get(key), "operation": operation}
        elif service == "payment" and operation in {"prepare", "release"}:
            if operation == "release" and payload.get("approved") is not True:
                result = {"released": False, "reason": "synthetic-approval-required"}
            else:
                entry = {**payload, "synthetic": True, "operation": operation}
                self.state["payments"].append(entry)
                result = {
                    "released": operation == "release",
                    "synthetic": True,
                    "receipt": f"PAY-{self.invocations:04d}",
                }
            kind = f"api.payment.{operation}"
        elif service == "network" and operation == "send":
            destination = str(payload.get("destination", "sink.sova.invalid"))
            hits = self.network.send(
                actor=actor,
                destination=destination,
                payload=payload.get("body"),
            )
            result = {
                "delivered": False,
                "sinkOnly": True,
                "canaryIds": sorted({hit.canary_id for hit in hits}),
            }
            self._record(
                "network.egress-attempt",
                actor=actor,
                target=destination,
                before=before,
                payload=result,
            )
            return result
        else:
            raise FormatError("SOVA-WORLD-OPERATION", "unsupported synthetic service operation")
        hits = self.detector.detect(result, actor=actor, action=kind, destination=None)
        result["canaryHits"] = [hit.canary_id for hit in hits]
        self.sensors.observe(sensor, kind, actor=actor, target=target, payload=result)
        self._record(kind, actor=actor, target=target, before=before, payload=result)
        self.tick()
        return result

    def materialize(self, parent: Path) -> Path:
        if self._temporary is not None:
            raise FormatError("SOVA-WORLD-MATERIALIZED", "synthetic world is already materialized")
        parent = parent.resolve()
        if not parent.is_dir():
            raise FormatError("SOVA-WORLD-PARENT", "materialization parent must exist")
        self._temporary = tempfile.TemporaryDirectory(prefix=".sova-world-", dir=parent)
        root = Path(self._temporary.name)
        for logical_path, content in self.state["files"].items():
            relative = logical_path.removeprefix("/home/researcher/")
            destination = root / "home" / "researcher" / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(str(content), encoding="utf-8")
        (root / "world-manifest.json").write_bytes(
            canonical_json_bytes(
                {
                    "runId": self.run_id,
                    "generation": self.generation,
                    "synthetic": True,
                    "network": "sink-only",
                }
            )
        )
        self._materialized_path = root
        return root

    def reset(self) -> None:
        self.state = self._copy_state(self._baseline)
        self.events.clear()
        self.network.attempts.clear()
        self.sensors.reset_observations()
        self.invocations = 0
        self.generation += 1
        if self._temporary is not None:
            try:
                self._temporary.cleanup()
            except OSError as error:
                self._cleanup_failure = type(error).__name__
            else:
                self._temporary = None
                self._materialized_path = None
                self._cleanup_failure = None

    def cleanup(self) -> None:
        if self._temporary is not None:
            self._temporary.cleanup()
            self._temporary = None

    def cleanup_verified(self) -> bool:
        return self._cleanup_failure is None and (
            self._materialized_path is None or not self._materialized_path.exists()
        )

    @property
    def cleanup_failure(self) -> str | None:
        return self._cleanup_failure


__all__ = [
    "Canary",
    "CanaryDetector",
    "CanaryHit",
    "CanaryKind",
    "SinkOnlyNetworkCollector",
    "SyntheticWorld",
    "WorldEvent",
]
