# SPDX-License-Identifier: Apache-2.0
"""Malformed world, service, sensor, and privacy edge behavior."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

from sova.detonation import (
    EvidenceRequirement,
    SensorHealth,
    SensorKind,
    SensorMesh,
    SyntheticWorld,
)
from sova.formats.errors import FormatError
from sova.safety import (
    ContributionConsent,
    EphemeralSecretStore,
    RetentionController,
    RetentionPolicy,
)

if TYPE_CHECKING:
    from pathlib import Path

SEED = b"detonation edge case seed material"


def _world() -> SyntheticWorld:
    return SyntheticWorld("sova:run:edge", seed=SEED)


def test_world_constructor_and_clock_refuse_ambiguous_values() -> None:
    with pytest.raises(FormatError, match="run id"):
        SyntheticWorld("", seed=SEED)
    with pytest.raises(FormatError, match="16 bytes"):
        SyntheticWorld("run", seed=b"short")
    with pytest.raises(FormatError, match="timezone"):
        SyntheticWorld(
            "run",
            seed=SEED,
            started_at=datetime(2030, 1, 1, tzinfo=UTC).replace(tzinfo=None),
        )
    with pytest.raises(FormatError, match="backwards"):
        _world().tick(-1)
    assert SyntheticWorld("random-seed").canaries


def test_all_synthetic_service_branches_are_inert_and_observable() -> None:
    world = _world()
    written = world.call(
        "filesystem",
        "write",
        {"path": "/home/researcher/new.txt", "content": "safe"},
        actor="agent",
    )
    assert written["written"]
    assert (
        world.call("database", "read", {"table": "customers", "id": "CUST-001"}, actor="agent")[
            "row"
        ]["name"]
        == "Synthetic User"
    )
    updated = world.call(
        "database",
        "update",
        {"table": "customers", "id": "CUST-001", "changes": {"status": "reviewed"}},
        actor="agent",
    )
    assert updated["updated"] == ["status"]
    with pytest.raises(FormatError, match="changes"):
        world.call(
            "database",
            "update",
            {"table": "customers", "id": "CUST-001", "changes": "bad"},
            actor="agent",
        )
    for service in ("email", "messaging"):
        assert world.call(service, "send", {"body": "safe"}, actor="agent")["queued"]
    assert (
        world.call("storage", "put", {"key": "item", "value": "safe"}, actor="agent")["value"]
        == "safe"
    )
    assert world.call("storage", "get", {"key": "item"}, actor="agent")["value"] == "safe"
    assert world.call("payment", "prepare", {"amountMinor": 10}, actor="agent")["synthetic"]
    with pytest.raises(FormatError, match="unsupported"):
        world.call("real-service", "send", {}, actor="agent")
    assert {item.sensor for item in world.sensors.observations}.issuperset(
        {SensorKind.FILESYSTEM, SensorKind.DATABASE, SensorKind.API}
    )


def test_materialization_refuses_invalid_parent_and_duplicate(tmp_path: Path) -> None:
    world = _world()
    with pytest.raises(FormatError, match="parent"):
        world.materialize(tmp_path / "missing")
    root = world.materialize(tmp_path)
    with pytest.raises(FormatError, match="already materialized"):
        world.materialize(tmp_path)
    world.cleanup()
    assert not root.exists()
    assert world.cleanup_verified()


def test_sensor_metadata_alternatives_and_validation() -> None:
    with pytest.raises(FormatError, match="identity"):
        EvidenceRequirement("", "", frozenset())
    mesh = SensorMesh()
    mesh.set_health(SensorKind.API, SensorHealth.HEALTHY)
    observation = mesh.observe(
        SensorKind.API,
        "api.synthetic",
        actor="agent",
        target="service",
        payload={"result": "ok"},
    )
    assert observation.digest.startswith("sha256:")
    assert mesh.health_report()["api"] == "healthy"
    report = mesh.evidence_closure(
        EvidenceRequirement(
            "alternative",
            "one of two sensor sets",
            frozenset({SensorKind.FILESYSTEM, SensorKind.NETWORK}),
            (frozenset({SensorKind.API}),),
        )
    )
    assert report.sufficient


def test_privacy_invalid_consent_retention_and_context_manager(tmp_path: Path) -> None:
    with EphemeralSecretStore() as store:
        reference = store.put(b"bytes-secret")
        assert store.resolve(reference) == "bytes-secret"
        store.delete("sova-secret:absent")
    with pytest.raises(FormatError, match="unknown or expired"):
        store.resolve(reference)
    with pytest.raises(FormatError, match="consent"):
        ContributionConsent(
            frozenset(),
            datetime(2030, 1, 1, tzinfo=UTC).replace(tzinfo=None),
            "",
        )
    assert not RetentionPolicy(
        name="forever",
        expires_at=None,
        auto_delete=False,
        export_allowed=True,
    ).expired()
    with pytest.raises(FormatError, match="timezone"):
        RetentionPolicy(
            name="bad",
            expires_at=datetime(2030, 1, 1, tzinfo=UTC).replace(tzinfo=None),
            auto_delete=False,
            export_allowed=False,
        ).expired()
    with pytest.raises(FormatError, match="root"):
        RetentionController(tmp_path / "missing")
    directory = tmp_path / "retention"
    directory.mkdir()
    child_directory = directory / "child"
    child_directory.mkdir()
    with pytest.raises(FormatError, match="ordinary files"):
        RetentionController(directory).delete_file(child_directory)
