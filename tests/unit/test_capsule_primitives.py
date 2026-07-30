# SPDX-License-Identifier: Apache-2.0
"""Universal capsule primitive serialization."""

from __future__ import annotations

from sova.capsule import Actor, Artifact, Environment, Evaluation, Procedure, Provenance
from sova.contracts.versions import ContentDigest


def test_all_universal_primitives_have_plain_mapping_views() -> None:
    actor = Actor("actor", "agent", "Fixture", "1", "prov")
    artifact = Artifact(
        "artifact",
        "text/plain",
        ContentDigest("sha256:" + "1" * 64),
        4,
        "fixture",
    )
    environment = Environment("env", "synthetic", "python", ({"name": "dep"},))
    procedure = Procedure("procedure", ({"action": "observe"},))
    evaluation = Evaluation(
        "evaluation",
        "exact",
        "1",
        ("subject",),
        "pass",
        "high",
        (),
        ("evidence",),
    )
    provenance = Provenance("provenance", ("author",), ("source",), ("created",))

    assert actor.to_mapping()["name"] == "Fixture"
    assert artifact.to_mapping()["digest"] == "sha256:" + "1" * 64
    assert environment.to_mapping()["platform"] == "synthetic"
    assert procedure.to_mapping()["steps"][0]["action"] == "observe"
    assert evaluation.to_mapping()["outcome"] == "pass"
    assert provenance.to_mapping()["creators"] == ("author",)
