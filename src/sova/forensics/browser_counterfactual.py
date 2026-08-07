# SPDX-License-Identifier: Apache-2.0
"""Evidence-producing paired browser interventions on controlled targets."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sova.capsule import DomainProfile, build_capsule, capsule_manifest_template, scenario_template
from sova.forensics.attribution import assess_counterfactuals
from sova.forensics.model import CausalLayer, CounterfactualTrial
from sova.formats import PackageReader, canonical_json_bytes, sha256_digest, strict_json_loads
from sova.formats.errors import FormatError
from sova.live.campaign import (
    BrowserCampaign,
    BrowserCampaignArtifacts,
    browser_campaign_from_mapping,
    run_browser_campaign,
)
from sova.trace import TraceReader

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from pathlib import Path

    from sova.live.browser import ApprovalPrompt
    from sova.runtime import RunProfile
    from sova.safety import ControlProof
    from sova.targets import TargetManifest

_MIN_REPETITIONS = 4
_MAX_REPETITIONS = 10
_MAX_STUDY_ID_CHARS = 128
_MIN_BASELINE_MESSAGES = 2
_PAIR_ATTEMPTS = 2


@dataclass(frozen=True, slots=True)
class BrowserCounterfactualStudy:
    """One predeclared removal intervention over an exact browser sequence."""

    identifier: str
    title: str
    baseline: BrowserCampaign
    layer: CausalLayer
    message_index: int
    repetitions: int = 4

    def __post_init__(self) -> None:
        if not self.identifier or len(self.identifier) > _MAX_STUDY_ID_CHARS or not self.title:
            raise FormatError("SOVA-BROWSER-CF-STUDY", "counterfactual study identity is invalid")
        if self.baseline.offensive:
            raise FormatError(
                "SOVA-BROWSER-CF-OFFENSIVE",
                "browser counterfactual studies accept only non-offensive campaigns",
            )
        if len(self.baseline.candidates) != 1 or self.baseline.max_attempts != 1:
            raise FormatError(
                "SOVA-BROWSER-CF-BASELINE",
                "baseline must declare exactly one candidate and one attempt",
            )
        sequence = self.baseline.candidates[0]
        if len(sequence) < _MIN_BASELINE_MESSAGES:
            raise FormatError(
                "SOVA-BROWSER-CF-BASELINE",
                "baseline sequence needs at least two messages",
            )
        if isinstance(self.message_index, bool) or not 0 <= self.message_index < len(sequence):
            raise FormatError("SOVA-BROWSER-CF-INDEX", "message removal index is invalid")
        if self.layer != CausalLayer.ORCHESTRATION:
            raise FormatError(
                "SOVA-BROWSER-CF-LAYER",
                "message removal changes only the declared orchestration layer",
            )
        if (
            isinstance(self.repetitions, bool)
            or not _MIN_REPETITIONS <= self.repetitions <= _MAX_REPETITIONS
        ):
            raise FormatError(
                "SOVA-BROWSER-CF-REPETITIONS",
                "counterfactual repetitions must be between four and ten",
            )

    @property
    def intervention_sequence(self) -> tuple[str, ...]:
        baseline = self.baseline.candidates[0]
        return baseline[: self.message_index] + baseline[self.message_index + 1 :]

    @property
    def paired_campaign(self) -> BrowserCampaign:
        baseline = self.baseline
        return BrowserCampaign(
            f"{baseline.identifier}:counterfactual-pair",
            f"{baseline.title} — counterfactual pair",
            baseline.entry_url,
            baseline.input_target,
            baseline.submit_target,
            (self.intervention_sequence, baseline.candidates[0]),
            baseline.oracle_contains,
            _PAIR_ATTEMPTS,
            baseline.max_duration_seconds,
            offensive=False,
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "artifactType": "sova.browser-counterfactual-study",
            "schemaVersion": "0.1.0",
            "id": self.identifier,
            "title": self.title,
            "baselineCampaign": self.baseline.to_mapping(),
            "intervention": {
                "kind": "remove-message",
                "messageIndex": self.message_index,
                "layer": self.layer.value,
            },
            "repetitions": self.repetitions,
        }


@dataclass(frozen=True, slots=True)
class BrowserCounterfactualArtifacts:
    report: Path
    capsule: Path
    traces: tuple[Path, ...]
    status: str


def browser_counterfactual_from_mapping(value: Mapping[str, Any]) -> BrowserCounterfactualStudy:
    """Parse a strict untrusted study document without accepting implied interventions."""
    required = {
        "artifactType",
        "schemaVersion",
        "id",
        "title",
        "baselineCampaign",
        "intervention",
        "repetitions",
    }
    if set(value) != required:
        raise FormatError("SOVA-BROWSER-CF-FIELDS", "counterfactual study fields are invalid")
    if (
        value.get("artifactType") != "sova.browser-counterfactual-study"
        or value.get("schemaVersion") != "0.1.0"
    ):
        raise FormatError("SOVA-BROWSER-CF-VERSION", "counterfactual study version is invalid")
    baseline = value.get("baselineCampaign")
    intervention = value.get("intervention")
    if not isinstance(baseline, dict):
        raise FormatError("SOVA-BROWSER-CF-BASELINE", "baseline campaign must be an object")
    if not isinstance(intervention, dict) or set(intervention) != {
        "kind",
        "messageIndex",
        "layer",
    }:
        raise FormatError("SOVA-BROWSER-CF-INTERVENTION", "intervention shape is invalid")
    if intervention.get("kind") != "remove-message":
        raise FormatError(
            "SOVA-BROWSER-CF-INTERVENTION",
            "only the explicit remove-message intervention is supported",
        )
    try:
        layer = CausalLayer(str(intervention.get("layer")))
    except ValueError as error:
        raise FormatError("SOVA-BROWSER-CF-LAYER", "causal layer is unsupported") from error
    message_index = intervention.get("messageIndex")
    repetitions = value.get("repetitions")
    if not isinstance(message_index, int) or isinstance(message_index, bool):
        raise FormatError("SOVA-BROWSER-CF-INDEX", "messageIndex must be an integer")
    if not isinstance(repetitions, int) or isinstance(repetitions, bool):
        raise FormatError("SOVA-BROWSER-CF-REPETITIONS", "repetitions must be an integer")
    identifier = value.get("id")
    title = value.get("title")
    if not isinstance(identifier, str) or not isinstance(title, str):
        raise FormatError("SOVA-BROWSER-CF-STUDY", "study identity must be text")
    return BrowserCounterfactualStudy(
        identifier,
        title,
        browser_campaign_from_mapping(baseline),
        layer,
        message_index,
        repetitions,
    )


def _read_report(path: Path) -> dict[str, Any]:
    value = strict_json_loads(path.read_bytes())
    if not isinstance(value, dict) or value.get("artifactType") != (
        "sova.live-browser-campaign-report"
    ):
        raise FormatError("SOVA-BROWSER-CF-REPORT", "paired campaign report is invalid")
    return value


def _verified_trace(path: Path) -> bool:
    report = TraceReader(path).verify(require_signature=True)
    return report.signature_valid and report.completion == "completed"


def _fingerprints(path: Path) -> dict[str, Any]:
    value = TraceReader(path).manifest().get("fingerprints")
    if not isinstance(value, dict):
        raise FormatError("SOVA-BROWSER-CF-FINGERPRINT", "trace fingerprints are missing")
    return value


def _trial(
    index: int,
    study: BrowserCounterfactualStudy,
    artifacts: BrowserCampaignArtifacts,
) -> CounterfactualTrial:
    report = _read_report(artifacts.report)
    attempts = report.get("attempts")
    if not isinstance(attempts, list):
        raise FormatError("SOVA-BROWSER-CF-REPORT", "paired attempts are missing")
    intervention_outcome = (
        attempts[0].get("triggered") if attempts and isinstance(attempts[0], dict) else None
    )
    baseline_outcome = (
        attempts[1].get("triggered")
        if len(attempts) > 1 and isinstance(attempts[1], dict)
        else None
    )
    if intervention_outcome is not None and not isinstance(intervention_outcome, bool):
        intervention_outcome = None
    if baseline_outcome is not None and not isinstance(baseline_outcome, bool):
        baseline_outcome = None
    intervention_trace = artifacts.traces[0] if artifacts.traces else None
    baseline_trace = artifacts.traces[1] if len(artifacts.traces) > 1 else None
    evidence_complete = bool(
        intervention_trace is not None
        and baseline_trace is not None
        and artifacts.reproduction_trace is not None
        and all(
            _verified_trace(path)
            for path in (intervention_trace, baseline_trace, artifacts.reproduction_trace)
        )
    )
    context_equivalent = bool(
        intervention_trace is not None
        and baseline_trace is not None
        and _fingerprints(intervention_trace) == _fingerprints(baseline_trace)
    )
    return CounterfactualTrial(
        trial_id=f"{study.identifier}:pair-{index:03d}",
        layer=study.layer,
        changed_layers=(study.layer,),
        baseline_outcome=baseline_outcome,
        intervention_outcome=intervention_outcome,
        context_equivalent=context_equivalent,
        evidence_complete=evidence_complete,
        original_trace=None if baseline_trace is None else str(baseline_trace),
        counterfactual_trace=(None if intervention_trace is None else str(intervention_trace)),
        execution_status=("completed" if len(attempts) == _PAIR_ATTEMPTS else "incomplete"),
        limitation=(
            None
            if len(attempts) == _PAIR_ATTEMPTS
            else "paired campaign did not reach the declared baseline candidate"
        ),
    )


def _trial_mapping(trial: CounterfactualTrial) -> dict[str, Any]:
    return {
        "trialId": trial.trial_id,
        "layer": trial.layer.value,
        "changedLayers": [layer.value for layer in trial.changed_layers],
        "baselineOutcome": trial.baseline_outcome,
        "interventionOutcome": trial.intervention_outcome,
        "contextEquivalent": trial.context_equivalent,
        "evidenceComplete": trial.evidence_complete,
        "originalTrace": trial.original_trace,
        "counterfactualTrace": trial.counterfactual_trace,
        "executionStatus": trial.execution_status,
        "limitation": trial.limitation,
    }


def run_browser_counterfactual_study(  # noqa: PLR0913
    target: TargetManifest,
    study: BrowserCounterfactualStudy,
    destination: Path,
    *,
    profile: RunProfile,
    package_runner: Path,
    browser_executable: Path,
    approval_prompt: ApprovalPrompt,
    control_proof: ControlProof | None = None,
    runner: Callable[..., BrowserCampaignArtifacts] = run_browser_campaign,
) -> BrowserCounterfactualArtifacts:
    """Run repeated authorized pairs and assess only recorded observable outcomes."""
    destination = destination.resolve()
    if destination.exists() and any(destination.iterdir()):
        raise FormatError(
            "SOVA-BROWSER-CF-EXISTS",
            "counterfactual destination is not empty",
        )
    destination.mkdir(parents=True, exist_ok=True)
    package_cache = destination / ".cache" / "npm-playwright"
    packaged_traces = destination / "evidence-traces"
    packaged_traces.mkdir()
    trials: list[CounterfactualTrial] = []
    trace_paths: list[Path] = []
    for index in range(1, study.repetitions + 1):
        pair = runner(
            target,
            study.paired_campaign,
            destination / f"pair-{index:03d}",
            package_runner=package_runner,
            browser_executable=browser_executable,
            approval_prompt=approval_prompt,
            control_proof=control_proof,
            package_cache=package_cache,
        )
        trial = _trial(index, study, pair)
        trials.append(trial)
        sources: list[tuple[str, Path]] = []
        if pair.traces:
            sources.append(("intervention", pair.traces[0]))
        if len(pair.traces) > 1:
            sources.append(("baseline", pair.traces[1]))
        if pair.reproduction_trace is not None:
            sources.append(("reproduction", pair.reproduction_trace))
        for role, source in sources:
            packaged = packaged_traces / f"pair-{index:03d}-{role}.sova-trace"
            packaged.write_bytes(source.read_bytes())
            trace_paths.append(packaged)
    original = next(
        (trial.original_trace for trial in trials if trial.original_trace is not None),
        "unavailable",
    )
    attribution = assess_counterfactuals(original, tuple(trials), layers=(study.layer,))
    assessment = attribution.assessments[0]
    report_path = destination / "counterfactual-report.json"
    report = {
        "artifactType": "sova.browser-counterfactual-report",
        "schemaVersion": "0.1.0",
        "study": study.to_mapping(),
        "profile": profile.to_mapping(),
        "targetDigest": target.digest,
        "trials": [_trial_mapping(trial) for trial in trials],
        "evidenceTraces": [path.relative_to(destination).as_posix() for path in trace_paths],
        "attribution": attribution.to_mapping(),
        "status": assessment.state.value,
        "claims": {
            "realBrowserPairsExecuted": True,
            "baselineAndInterventionObserved": True,
            "singleDeclaredLayerChanged": True,
            "causalCertainty": False,
            "hiddenReasoningObserved": False,
        },
        "limitations": [
            (
                "The intervention removes one declared message; unmeasured runtime variation "
                "may remain."
            ),
            "A supported result is bounded to this target, sequence, oracle, and run cohort.",
            "Not-observed intervention outcomes do not prove universal absence.",
            "The browser session is restricted but is not a VM security sandbox.",
        ],
    }
    report_path.write_bytes(canonical_json_bytes(report) + b"\n")
    capsule_path = destination / "counterfactual-study.sova"
    manifest = capsule_manifest_template(
        title=study.title,
        summary="Repeated controlled browser interventions with signed observable evidence.",
        author="SOVA operator",
        domain_profile=DomainProfile.INCIDENT_FORENSICS,
    )
    manifest["license"] = "Apache-2.0"
    manifest["methodology"] = {
        "id": "sova.browser-counterfactual.remove-message",
        "version": "0.1.0",
        "digest": sha256_digest(canonical_json_bytes(study.to_mapping())),
    }
    manifest["taxonomy"] = {
        "id": "sova.causal-layer",
        "version": "0.1.0",
        "digest": sha256_digest(canonical_json_bytes([layer.value for layer in CausalLayer])),
    }
    manifest["limitations"] = report["limitations"]
    scenario = scenario_template(
        title=study.title,
        purpose="Repeat one declared browser sequence with and without one message.",
    )
    scenario["parameters"] = {
        "studyDigest": sha256_digest(canonical_json_bytes(study.to_mapping())),
        "targetDigest": target.digest,
        "repetitions": study.repetitions,
    }
    scenario["procedure"]["steps"] = [
        {
            "id": "paired-browser-intervention",
            "action": "sova.forensics.browser-counterfactual",
            "inputs": {"intervention": "remove-message", "index": study.message_index},
            "onFailure": "inconclusive",
            "requires": ["browser.counterfactual/0.1"],
        }
    ]
    scenario["limitations"] = report["limitations"]
    build_capsule(
        capsule_path,
        manifest,
        scenario=scenario,
        attachments={
            "study.json": canonical_json_bytes(study.to_mapping()),
            "counterfactual-report.json": canonical_json_bytes(report),
        },
        traces=trace_paths,
    )
    PackageReader(capsule_path).verify("sova.capsule")
    return BrowserCounterfactualArtifacts(
        report_path,
        capsule_path,
        tuple(trace_paths),
        assessment.state.value,
    )


__all__ = [
    "BrowserCounterfactualArtifacts",
    "BrowserCounterfactualStudy",
    "browser_counterfactual_from_mapping",
    "run_browser_counterfactual_study",
]
