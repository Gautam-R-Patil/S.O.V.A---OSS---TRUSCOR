# SPDX-License-Identifier: Apache-2.0
"""Bounded authorized robustness ("stress") profile: bounds, tactics, delegation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from sova.community.swarm import stress as stress_module
from sova.community.swarm.stress import (
    _MAX_AGENTS,
    _MAX_REPETITIONS,
    _MAX_TOTAL_INTERACTIONS,
    StressReport,
    run_stress_profile,
)
from sova.formats.errors import FormatError
from sova.live.adversarial_missions import adversarial_tactic, adversarial_tactic_ids
from sova.trace import Redactor

_ENTRY = "http://127.0.0.1:8080/chat"


def _run_kwargs(**overrides: Any) -> dict[str, Any]:
    defaults: dict[str, Any] = {
        "target": "target",
        "base_chamber_document": {
            "oracle": {
                "kind": "projection-field-contains",
                "fieldPath": ["browser", "snapshot"],
                "contains": "template-value-that-must-not-survive",
            }
        },
        "destination": Path("dest"),
        "entry_url": _ENTRY,
        "package_runner": Path("pr"),
        "browser_executable": Path("be"),
        "approval_prompt": lambda _c, _i: "x",
        "secret_resolver": lambda _n: None,
        "provider_calls_authorized": True,
        "target_observation_disclosure_authorized": True,
        "agent_count": 2,
    }
    defaults.update(overrides)
    return defaults


def test_bounds_reject_too_many_agents() -> None:
    with pytest.raises(FormatError, match="agent count is outside"):
        run_stress_profile(**_run_kwargs(agent_count=_MAX_AGENTS + 1))


def test_bounds_reject_too_many_repetitions() -> None:
    with pytest.raises(FormatError, match="repetitions is outside"):
        run_stress_profile(**_run_kwargs(repetitions=_MAX_REPETITIONS + 1))


def test_bounds_reject_too_many_total_interactions() -> None:
    # Individually valid agent_count/repetitions whose product exceeds the ceiling.
    agent_count = _MAX_AGENTS
    repetitions = _MAX_TOTAL_INTERACTIONS // agent_count + 1
    assert repetitions <= _MAX_REPETITIONS
    assert agent_count * repetitions > _MAX_TOTAL_INTERACTIONS
    with pytest.raises(FormatError, match="exceeds the total interaction ceiling"):
        run_stress_profile(**_run_kwargs(agent_count=agent_count, repetitions=repetitions))


def test_unknown_tactic_rejected() -> None:
    with pytest.raises(FormatError, match="unknown adversarial tactic"):
        run_stress_profile(**_run_kwargs(tactic_ids=("no-such-tactic",)))


def test_default_uses_full_tactic_library(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def fake_run_web_swarm(_target: Any, mission: Any, *_args: Any, **kwargs: Any) -> Any:
        captured["mission"] = mission
        captured["kwargs"] = kwargs

        class _Artifacts:
            destination = Path("dest")

        return _Artifacts()

    monkeypatch.setattr(stress_module, "run_web_swarm", fake_run_web_swarm)
    report = run_stress_profile(**_run_kwargs())
    assert report.tactic_ids == adversarial_tactic_ids()
    assert isinstance(report, StressReport)


def test_mission_is_offensive_and_folds_all_payloads(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def fake_run_web_swarm(_target: Any, mission: Any, *_args: Any, **kwargs: Any) -> Any:
        captured["mission"] = mission
        captured["kwargs"] = kwargs

        class _Artifacts:
            destination = Path("dest")

        return _Artifacts()

    monkeypatch.setattr(stress_module, "run_web_swarm", fake_run_web_swarm)
    tactics = ("direct-instruction-override", "hidden-context-disclosure")
    run_stress_profile(**_run_kwargs(tactic_ids=tactics))
    mission = captured["mission"]
    assert mission.offensive is True
    assert captured["kwargs"]["offensive"] is True
    for tactic_id in tactics:
        tactic = adversarial_tactic(tactic_id)
        assert any(payload in mission.seed_inputs for payload in tactic.payloads)


def test_duplicate_payloads_deduped(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def fake_run_web_swarm(_target: Any, mission: Any, *_args: Any, **_kwargs: Any) -> Any:
        captured["mission"] = mission

        class _Artifacts:
            destination = Path("dest")

        return _Artifacts()

    monkeypatch.setattr(stress_module, "run_web_swarm", fake_run_web_swarm)
    tactic = adversarial_tactic("direct-instruction-override")
    # An extra payload that duplicates one already in the primary tactic's own
    # payload set must not raise (it is folded away, not passed to the builder).
    run_stress_profile(
        **_run_kwargs(
            tactic_ids=("direct-instruction-override",),
            extra_payloads=(tactic.payloads[0],),
        )
    )
    mission = captured["mission"]
    assert mission.seed_inputs.count(tactic.payloads[0]) == 1


def test_delegates_to_swarm_with_expected_agent_count(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def fake_run_web_swarm(
        target: Any, mission: Any, document: Any, dest: Any, **kwargs: Any
    ) -> Any:
        captured["target"] = target
        captured["mission"] = mission
        captured["document"] = document
        captured["dest"] = dest
        captured["kwargs"] = kwargs

        class _Artifacts:
            destination = dest

        return _Artifacts()

    monkeypatch.setattr(stress_module, "run_web_swarm", fake_run_web_swarm)
    report = run_stress_profile(**_run_kwargs(agent_count=5, repetitions=3))
    assert captured["kwargs"]["agent_count"] == 5
    assert captured["document"] is not _run_kwargs()["base_chamber_document"]
    assert captured["document"]["oracle"] == {
        "kind": "projection-field-contains",
        "fieldPath": ["browser", "snapshot"],
        "contains": captured["mission"].oracle_contains,
    }
    assert report.agent_count == 5
    assert report.repetitions == 3
    assert isinstance(report.swarm, object)


def test_repetitions_scale_the_mission_budget_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def fake_run_web_swarm(_target: Any, mission: Any, *_args: Any, **_kwargs: Any) -> Any:
        captured["mission"] = mission

        class _Artifacts:
            destination = Path("dest")

        return _Artifacts()

    monkeypatch.setattr(stress_module, "run_web_swarm", fake_run_web_swarm)
    run_stress_profile(**_run_kwargs(repetitions=1))
    low = captured["mission"]
    run_stress_profile(**_run_kwargs(repetitions=10))
    high = captured["mission"]
    assert high.max_planner_turns > low.max_planner_turns
    assert high.max_actions > low.max_actions
    assert high.max_mutations > low.max_mutations
    assert high.max_planner_turns <= 64
    assert high.max_actions <= 512
    assert high.max_mutations <= 512


def test_payloads_stay_non_credential_shaped(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def fake_run_web_swarm(_target: Any, mission: Any, *_args: Any, **_kwargs: Any) -> Any:
        captured["mission"] = mission

        class _Artifacts:
            destination = Path("dest")

        return _Artifacts()

    monkeypatch.setattr(stress_module, "run_web_swarm", fake_run_web_swarm)
    run_stress_profile(**_run_kwargs(repetitions=5))
    redactor = Redactor(context_id="test-stress-payload-scan")
    for payload in captured["mission"].seed_inputs:
        _redacted, disclosures = redactor.redact(payload)
        assert not disclosures, f"payload looked credential-shaped: {payload!r}"
