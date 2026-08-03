# SPDX-License-Identifier: Apache-2.0
"""Local, inert-by-default command line for SOVA artifacts."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sova import __version__
from sova.capsule import (
    analyze_migration,
    build_capsule,
    capsule_manifest_template,
    lint_capsule,
    migrate_capsule,
    render_capsule,
    scenario_template,
)
from sova.composition import (
    CompositionBudget,
    CompositionObservation,
    CompositionSearchEngine,
    CompositionStrategy,
    graph_from_mapping,
)
from sova.evidence import (
    ExecutionObservation,
    ObservationState,
    ScannerFinding,
    adjudicate_findings,
    build_evidence_bundle,
    construct_safe_test_plan,
    default_disclosure_clock,
    discover_maintainer_contacts,
    evidence_to_sarif,
    prepare_disclosure_package,
    render_evidence_report,
)
from sova.forensics import (
    CausalLayer,
    CounterfactualTrial,
    assess_counterfactuals,
    reconstruct_events,
    reconstruct_trace,
    run_attribution_ground_truth_fixture,
)
from sova.formats import (
    PackageReader,
    canonical_json_bytes,
    sha256_digest,
    strict_json_loads,
    validate_document,
)
from sova.formats.errors import FormatError
from sova.mapping import build_capability_map, write_capability_map, write_tool_snapshot
from sova.mcp import MELRA_AUDIT_RECEIPT, PLAYWRIGHT_MCP_RECEIPT, WINDOWS_MCP_RECEIPT
from sova.monitoring import (
    build_behavior_snapshot,
    build_integrity_manifest,
    compare_behavior_snapshots,
    evaluate_ci,
    record_local_process,
    run_sentinel,
    verify_integrity_manifest,
)
from sova.registry import prepare_contribution, sync_registry, verify_registry
from sova.rehearsal import (
    export_approved_changes,
    prepare_rehearsal_environment,
    run_rehearsal,
    specification_from_mapping,
)
from sova.replay import (
    ReplayMode,
    VerificationState,
    render_timeline_html,
    semantic_reproduction_study,
    verify_artifact,
)
from sova.reproduction import compare_observable_outcomes
from sova.runtime import ProfileKind, RunProfile, standard_profile
from sova.safety import (
    DisclosureRequest,
    VulnerabilityState,
    known_backend_descriptors,
)
from sova.search import run_trigger_search_demo
from sova.trace import TraceReader, recover_trace
from sova.trace.otel import export_event
from sova.workflows import run_check, run_complete_demo

if TYPE_CHECKING:
    from collections.abc import Sequence


def _path(value: str) -> Path:
    return Path(value)


def build_parser() -> argparse.ArgumentParser:  # noqa: PLR0915
    """Build the public command-line parser without performing side effects."""
    parser = argparse.ArgumentParser(
        prog="sova",
        description=(
            "SOVA OSS pre-alpha: inspect, validate, migrate, and verify portable "
            "AI-behavior capsules and traces locally."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command")

    inspect_parser = commands.add_parser("inspect", help="render an inert capsule summary")
    inspect_parser.add_argument("path", type=_path)
    inspect_parser.set_defaults(handler=_inspect)

    validate_parser = commands.add_parser(
        "validate",
        help="validate a capsule, trace, or JSON object",
    )
    validate_parser.add_argument("path", type=_path)
    validate_parser.set_defaults(handler=_validate)

    lint_parser = commands.add_parser("lint", help="report capsule semantic warnings")
    lint_parser.add_argument("path", type=_path)
    lint_parser.set_defaults(handler=_lint)

    verify_parser = commands.add_parser("verify", help="verify a capsule or trace offline")
    verify_parser.add_argument("path", type=_path)
    verify_parser.add_argument("--require-signature", action="store_true")
    verify_parser.add_argument("--key-id")
    verify_parser.set_defaults(handler=_verify)

    migrate_parser = commands.add_parser(
        "migrate",
        help="migrate a capsule without overwriting it",
    )
    migrate_parser.add_argument("source", type=_path)
    migrate_parser.add_argument("destination", type=_path)
    migrate_parser.add_argument("--to", default="0.1.0")
    migrate_parser.set_defaults(handler=_migrate)

    compat_parser = commands.add_parser(
        "compat",
        help="explain capsule migration compatibility without writing",
    )
    compat_parser.add_argument("source", type=_path)
    compat_parser.add_argument("--to", default="0.1.0")
    compat_parser.set_defaults(handler=_compat)

    format_parser = commands.add_parser("format", help="emit canonical JSON")
    format_parser.add_argument("path", type=_path)
    format_parser.set_defaults(handler=_format)

    hash_parser = commands.add_parser("hash", help="hash exact artifact bytes")
    hash_parser.add_argument("path", type=_path)
    hash_parser.add_argument(
        "--content",
        action="store_true",
        help="hash the canonical manifest/root instead of ZIP transport bytes",
    )
    hash_parser.set_defaults(handler=_hash)

    template_parser = commands.add_parser("template", help="write a safe authoring template")
    template_parser.add_argument("kind", choices=("capsule", "scenario"))
    template_parser.add_argument("destination", type=_path)
    template_parser.add_argument("--title", default="Untitled SOVA behavior")
    template_parser.add_argument(
        "--summary",
        default="Describe the observed or hypothesized behavior.",
    )
    template_parser.add_argument("--author", default="Unknown author")
    template_parser.set_defaults(handler=_template)

    pack_parser = commands.add_parser(
        "pack",
        help="build a capsule from manifest and scenario JSON",
    )
    pack_parser.add_argument("manifest", type=_path)
    pack_parser.add_argument("scenario", type=_path)
    pack_parser.add_argument("destination", type=_path)
    pack_parser.set_defaults(handler=_pack)

    playback_parser = commands.add_parser(
        "playback",
        help="print an inert trace timeline",
    )
    playback_parser.add_argument("path", type=_path)
    playback_parser.set_defaults(handler=_playback)

    replay_parser = commands.add_parser(
        "replay",
        help="use one explicitly named playback or semantic-reproduction mode",
    )
    replay_commands = replay_parser.add_subparsers(dest="replay_command")
    replay_modes = replay_commands.add_parser(
        "modes", help="describe the three non-interchangeable replay operations"
    )
    replay_modes.set_defaults(handler=_replay_modes)
    replay_timeline = replay_commands.add_parser(
        "timeline", help="render a self-contained inert visual timeline"
    )
    replay_timeline.add_argument("source", type=_path)
    replay_timeline.add_argument("destination", type=_path)
    replay_timeline.add_argument("--comparison", type=_path)
    replay_timeline.add_argument("--counterfactual")
    replay_timeline.set_defaults(handler=_replay_timeline)
    replay_study = replay_commands.add_parser(
        "study", help="measure observable-outcome reproduction across fresh traces"
    )
    replay_study.add_argument("reference", type=_path)
    replay_study.add_argument("trials", nargs="+", type=_path)
    replay_study.add_argument(
        "--condition",
        action="append",
        help="one condition label per trial; defaults to declared-baseline",
    )
    replay_study.set_defaults(handler=_replay_study)

    query_parser = commands.add_parser("query", help="query trace events offline")
    query_parser.add_argument("path", type=_path)
    query_parser.add_argument("--kind-prefix")
    query_parser.add_argument("--actor-id")
    query_parser.add_argument("--start", type=int, default=0)
    query_parser.add_argument("--stop", type=int)
    query_parser.set_defaults(handler=_query)

    compare_parser = commands.add_parser(
        "compare",
        help="compare declared observable outcomes from two traces without re-execution",
    )
    compare_parser.add_argument("left", type=_path)
    compare_parser.add_argument("right", type=_path)
    compare_parser.add_argument(
        "--kind",
        action="append",
        help="event kind to compare; repeat to select multiple kinds",
    )
    compare_parser.set_defaults(handler=_compare)

    export_parser = commands.add_parser(
        "export",
        help="write a local machine-readable trace projection to stdout",
    )
    export_parser.add_argument("path", type=_path)
    export_parser.add_argument(
        "--format",
        choices=("native-jsonl", "otel-jsonl", "disclosure-json"),
        default="native-jsonl",
    )
    export_parser.add_argument("--sequence", action="append", type=int)
    export_parser.add_argument("--include-payload", action="store_true")
    export_parser.set_defaults(handler=_export)

    recover_parser = commands.add_parser(
        "recover-trace",
        help="recover a force-interrupted trace as an explicit observable prefix",
    )
    recover_parser.add_argument("destination", type=_path)
    recover_parser.set_defaults(handler=_recover_trace)

    safety_parser = commands.add_parser(
        "safety",
        help="inspect local containment capability without starting a backend",
    )
    safety_commands = safety_parser.add_subparsers(dest="safety_command")
    backends_parser = safety_commands.add_parser(
        "backends",
        help="report known containment backends and explicit limitations",
    )
    backends_parser.set_defaults(handler=_safety_backends)

    demo_parser = commands.add_parser(
        "demo",
        help="run a safe no-native-code synthetic demonstration",
    )
    demo_parser.add_argument("kind", choices=("sleeper",))
    demo_parser.add_argument("destination", type=_path)
    demo_parser.set_defaults(handler=_demo)

    check_parser = commands.add_parser(
        "check",
        help="run a bounded local check and return an explicit assurance state",
    )
    check_parser.add_argument("target")
    check_parser.add_argument("destination", type=_path)
    check_parser.add_argument(
        "--custom-profile",
        type=_path,
        help="canonical JSON customization; marks the run non-standard",
    )
    check_parser.set_defaults(handler=_check)

    map_parser = commands.add_parser(
        "map",
        help="map local declared capability reach without executing target code",
    )
    map_parser.add_argument("root", nargs="?", type=_path, default=Path())
    map_parser.add_argument("--output", "-o", type=_path)
    map_parser.add_argument("--inventory", action="append", type=_path, default=[])
    map_parser.add_argument("--observed-inventory", action="append", type=_path, default=[])
    map_parser.add_argument(
        "--authorize-runtime-inventory",
        action="store_true",
        help="confirm imported observed inventory was collected under authorization",
    )
    map_parser.add_argument("--baseline", type=_path)
    map_parser.add_argument("--write-tool-snapshot", type=_path)
    map_parser.set_defaults(handler=_map)

    executors_parser = commands.add_parser(
        "executors", help="inspect external executor receipts and limitations"
    )
    executors_commands = executors_parser.add_subparsers(dest="executors_command")
    executor_receipts = executors_commands.add_parser(
        "receipts", help="print pinned MELRA and open-source fallback receipts"
    )
    executor_receipts.set_defaults(handler=_executor_receipts)

    hunt_demo_parser = commands.add_parser(
        "hunt-demo",
        help="run an owned inert trigger-search comparison without native code",
    )
    hunt_demo_parser.set_defaults(handler=_hunt_demo)

    forensics_parser = commands.add_parser(
        "forensics", help="reconstruct evidence or assess declared counterfactual trials"
    )
    forensics_commands = forensics_parser.add_subparsers(dest="forensics_command")
    reconstruct_parser = forensics_commands.add_parser(
        "reconstruct", help="build an uncertainty-preserving evidence timeline"
    )
    reconstruct_parser.add_argument("source", type=_path)
    reconstruct_parser.set_defaults(handler=_forensics_reconstruct)
    attribute_parser = forensics_commands.add_parser(
        "attribute", help="assess paired intervention records without claiming causal proof"
    )
    attribute_parser.add_argument("study", type=_path)
    attribute_parser.set_defaults(handler=_forensics_attribute)
    benchmark_parser = forensics_commands.add_parser(
        "benchmark", help="run the safe deterministic attribution acceptance fixture"
    )
    benchmark_parser.set_defaults(handler=_forensics_benchmark)

    evidence_parser = commands.add_parser(
        "evidence", help="build a bounded, watermarked self-assessment evidence bundle"
    )
    evidence_parser.add_argument("specification", type=_path)
    evidence_parser.add_argument(
        "--format",
        choices=("json", "sarif", "technical", "executive", "reproduction", "methodology"),
        default="json",
    )
    evidence_parser.set_defaults(handler=_evidence)

    adjudicate_parser = commands.add_parser(
        "adjudicate", help="bound scanner disagreement using reviewed execution observations"
    )
    adjudicate_commands = adjudicate_parser.add_subparsers(dest="adjudicate_command")
    adjudicate_plan = adjudicate_commands.add_parser(
        "plan", help="construct an inert authorized test plan"
    )
    adjudicate_plan.add_argument("study", type=_path)
    adjudicate_plan.set_defaults(handler=_adjudicate_plan)
    adjudicate_evaluate = adjudicate_commands.add_parser(
        "evaluate", help="adjudicate already-recorded observations"
    )
    adjudicate_evaluate.add_argument("study", type=_path)
    adjudicate_evaluate.set_defaults(handler=_adjudicate_evaluate)

    disclose_parser = commands.add_parser(
        "disclose", help="prepare a local disclosure package without sending or publishing"
    )
    disclose_parser.add_argument("specification", type=_path)
    disclose_parser.set_defaults(handler=_disclose)

    compose_parser = commands.add_parser(
        "compose", help="plan or evaluate bounded multi-component interaction searches"
    )
    compose_commands = compose_parser.add_subparsers(dest="compose_command")
    compose_plan = compose_commands.add_parser(
        "plan", help="list deterministic candidates without executing them"
    )
    compose_plan.add_argument("graph", type=_path)
    compose_plan.add_argument("--strategy", choices=tuple(CompositionStrategy), default="pairwise")
    compose_plan.add_argument("--limit", type=int, default=100)
    compose_plan.add_argument("--t", type=int, default=3)
    compose_plan.set_defaults(handler=_compose_plan)
    compose_evaluate = compose_commands.add_parser(
        "evaluate", help="evaluate declared observations; never execute target actions"
    )
    compose_evaluate.add_argument("study", type=_path)
    compose_evaluate.add_argument(
        "--strategy", choices=tuple(CompositionStrategy), default="trigger-aware-sequence"
    )
    compose_evaluate.set_defaults(handler=_compose_evaluate)

    rehearse_parser = commands.add_parser(
        "rehearse", help="run a user-agent task only in a prepared substitute workspace"
    )
    rehearse_commands = rehearse_parser.add_subparsers(dest="rehearse_command")
    rehearse_prepare = rehearse_commands.add_parser(
        "prepare", help="create a credential-stripped disposable workspace"
    )
    rehearse_prepare.add_argument("source", type=_path)
    rehearse_prepare.add_argument("workspace", type=_path)
    rehearse_prepare.add_argument("--substitute", action="append")
    rehearse_prepare.set_defaults(handler=_rehearse_prepare)
    rehearse_run = rehearse_commands.add_parser(
        "run", help="execute a reviewed user-agent plan against substitutes"
    )
    rehearse_run.add_argument("specification", type=_path)
    rehearse_run.add_argument("workspace", type=_path)
    rehearse_run.add_argument("trace", type=_path)
    rehearse_run.add_argument("report", type=_path)
    rehearse_run.set_defaults(handler=_rehearse_run)
    rehearse_export = rehearse_commands.add_parser(
        "export", help="stage only explicitly approved file changes"
    )
    rehearse_export.add_argument("report", type=_path)
    rehearse_export.add_argument("workspace", type=_path)
    rehearse_export.add_argument("destination", type=_path)
    rehearse_export.add_argument("--approve", action="append", required=True)
    rehearse_export.set_defaults(handler=_rehearse_export)

    trace_parser = commands.add_parser(
        "trace", help="record an allowlisted local agent process or freeze a behavior snapshot"
    )
    trace_commands = trace_parser.add_subparsers(dest="trace_command")
    trace_run = trace_commands.add_parser(
        "run", help="record one shell-free allowlisted process into a signed trace"
    )
    trace_run.add_argument("specification", type=_path)
    trace_run.add_argument("destination", type=_path)
    trace_run.set_defaults(handler=_trace_run)
    trace_snapshot = trace_commands.add_parser(
        "snapshot", help="canonicalize declared behavior, environment, and methodology axes"
    )
    trace_snapshot.add_argument("specification", type=_path)
    trace_snapshot.add_argument("--output", type=_path)
    trace_snapshot.set_defaults(handler=_trace_snapshot)

    diff_parser = commands.add_parser(
        "diff", help="separate behavior drift from environment and methodology drift"
    )
    diff_parser.add_argument("left", type=_path)
    diff_parser.add_argument("right", type=_path)
    diff_parser.set_defaults(handler=_behavior_diff)

    sentinel_parser = commands.add_parser(
        "sentinel", help="run one local regression check and append local history"
    )
    sentinel_parser.add_argument("baseline", type=_path)
    sentinel_parser.add_argument("current", type=_path)
    sentinel_parser.add_argument("history", type=_path)
    sentinel_parser.add_argument("--policy", type=_path)
    sentinel_parser.set_defaults(handler=_sentinel)

    ci_parser = commands.add_parser("ci", help="apply a deterministic behavioral regression gate")
    ci_parser.add_argument("baseline", type=_path)
    ci_parser.add_argument("current", type=_path)
    ci_parser.add_argument("--policy", type=_path)
    ci_parser.add_argument("--sarif", type=_path)
    ci_parser.set_defaults(handler=_ci)

    registry_parser = commands.add_parser(
        "registry", help="verify a repository-of-files registry entirely offline"
    )
    registry_commands = registry_parser.add_subparsers(dest="registry_command")
    registry_verify = registry_commands.add_parser("verify", help="verify index and objects")
    registry_verify.add_argument("root", type=_path)
    registry_verify.add_argument("--trusted-key-id", action="append")
    registry_verify.set_defaults(handler=_registry_verify)

    sync_parser = commands.add_parser(
        "sync", help="pull and atomically cache a verified local registry mirror"
    )
    sync_parser.add_argument("sources", nargs="+", type=_path)
    sync_parser.add_argument("--cache", required=True, type=_path)
    sync_parser.set_defaults(handler=_sync)

    contribute_parser = commands.add_parser(
        "contribute", help="preview and locally stage an explicit public contribution"
    )
    contribute_parser.add_argument("specification", type=_path)
    contribute_parser.add_argument("destination", type=_path)
    contribute_parser.add_argument("--confirm", action="store_true")
    contribute_parser.set_defaults(handler=_contribute)

    self_check_parser = commands.add_parser(
        "self-check", help="create or verify a local versionable file-integrity baseline"
    )
    self_check_commands = self_check_parser.add_subparsers(dest="self_check_command")
    self_check_create = self_check_commands.add_parser(
        "create", help="create a hash baseline for explicitly listed files"
    )
    self_check_create.add_argument("root", type=_path)
    self_check_create.add_argument("manifest", type=_path)
    self_check_create.add_argument("--include", action="append", required=True)
    self_check_create.set_defaults(handler=_self_check_create)
    self_check_verify = self_check_commands.add_parser(
        "verify", help="verify files against a protected baseline"
    )
    self_check_verify.add_argument("root", type=_path)
    self_check_verify.add_argument("manifest", type=_path)
    self_check_verify.set_defaults(handler=_self_check_verify)
    return parser


def _load_object(path: Path) -> dict[str, Any]:
    value = strict_json_loads(path.read_bytes())
    if not isinstance(value, dict):
        raise FormatError("SOVA-CLI-ROOT-TYPE", "JSON root must be an object")
    return value


def _inspect(args: argparse.Namespace) -> int:
    sys.stdout.write(render_capsule(args.path))
    return 0


def _validate(args: argparse.Namespace) -> int:
    path: Path = args.path
    if path.suffix == ".sova":
        PackageReader(path).verify("sova.capsule")
    elif path.name.endswith(".sova-trace"):
        TraceReader(path).events()
    else:
        validate_document(_load_object(path))
    sys.stdout.write("VALID\n")
    return 0


def _lint(args: argparse.Namespace) -> int:
    issues = lint_capsule(args.path)
    if not issues:
        sys.stdout.write("CLEAN\n")
        return 0
    for issue in issues:
        sys.stdout.write(f"{issue.code} {issue.path}: {issue.message}\n")
    return 1


def _verify(args: argparse.Namespace) -> int:
    path: Path = args.path
    report = verify_artifact(
        path,
        require_signature=args.require_signature,
        required_key_id=args.key_id,
    )
    value = report.to_mapping()
    if report.accepted and path.name.endswith(".sova-trace"):
        trace = TraceReader(path).verify()
        value.update(
            {
                "traceId": trace.trace_id,
                "eventCount": trace.event_count,
                "completion": trace.completion,
                "signaturePresent": trace.signature_present,
                "signatureValid": trace.signature_valid,
                "trustPolicy": trace.trust_policy,
            }
        )
    elif report.accepted and path.suffix == ".sova":
        value["objectCount"] = len(PackageReader(path).verify("sova.capsule"))
    sys.stdout.buffer.write(canonical_json_bytes(value) + b"\n")
    if report.state == VerificationState.INVALID:
        return 2
    if report.state == VerificationState.UNSUPPORTED:
        return 4
    return 0


def _migrate(args: argparse.Namespace) -> int:
    digest = migrate_capsule(args.source, args.destination, destination_version=args.to)
    sys.stdout.write(f"{digest}  {args.destination}\n")
    return 0


def _compat(args: argparse.Namespace) -> int:
    source = PackageReader(args.source).raw_manifest()
    report = analyze_migration(source, destination_version=args.to)
    sys.stdout.write(json.dumps(report.to_mapping(), sort_keys=True) + "\n")
    return 0 if not report.blockers else 1


def _format(args: argparse.Namespace) -> int:
    sys.stdout.buffer.write(canonical_json_bytes(_load_object(args.path)) + b"\n")
    return 0


def _hash(args: argparse.Namespace) -> int:
    digest = (
        PackageReader(args.path).content_digest()
        if args.content
        else sha256_digest(args.path.read_bytes())
    )
    label = "content" if args.content else "package"
    sys.stdout.write(f"{digest}  {label}:{args.path}\n")
    return 0


def _template(args: argparse.Namespace) -> int:
    if args.kind == "capsule":
        document = capsule_manifest_template(
            title=args.title,
            summary=args.summary,
            author=args.author,
        )
    else:
        document = scenario_template(title=args.title, purpose=args.summary)
    args.destination.write_bytes(canonical_json_bytes(document) + b"\n")
    return 0


def _pack(args: argparse.Namespace) -> int:
    digest = build_capsule(
        args.destination,
        _load_object(args.manifest),
        scenario=_load_object(args.scenario),
    )
    sys.stdout.write(f"{digest}  {args.destination}\n")
    return 0


def _playback(args: argparse.Namespace) -> int:
    sys.stdout.write("\n".join(TraceReader(args.path).playback()) + "\n")
    return 0


def _replay_modes(_args: argparse.Namespace) -> int:
    value = {
        "tracePlayback": {
            "mode": ReplayMode.PLAYBACK.value,
            "executesActions": False,
            "claim": "deterministic inspection of recorded evidence",
        },
        "controlledReexecution": {
            "mode": ReplayMode.CONTROLLED_REEXECUTION.value,
            "executesActions": True,
            "claim": "fresh authorized run with condition drift",
        },
        "semanticReproduction": {
            "mode": ReplayMode.SEMANTIC_REPRODUCTION.value,
            "executesActions": "outside-study",
            "claim": "repeated observable-outcome measurement with uncertainty",
        },
        "bitForBitHostedInferenceClaim": False,
    }
    sys.stdout.buffer.write(canonical_json_bytes(value) + b"\n")
    return 0


def _replay_timeline(args: argparse.Namespace) -> int:
    render_timeline_html(
        args.source,
        args.destination,
        comparison=args.comparison,
        counterfactual=args.counterfactual,
    )
    sys.stdout.write(f"{args.destination}\n")
    return 0


def _replay_study(args: argparse.Namespace) -> int:
    conditions = tuple(args.condition) if args.condition else None
    report = semantic_reproduction_study(
        args.reference,
        tuple(args.trials),
        conditions=conditions,
    )
    sys.stdout.buffer.write(canonical_json_bytes(report.to_mapping()) + b"\n")
    return 0 if report.eligible else 3


def _query(args: argparse.Namespace) -> int:
    reader = TraceReader(args.path)
    for event in reader.query(
        kind_prefix=args.kind_prefix,
        actor_id=args.actor_id,
        start_sequence=args.start,
        stop_sequence=args.stop,
    ):
        sys.stdout.buffer.write(canonical_json_bytes(event) + b"\n")
    return 0


def _compare(args: argparse.Namespace) -> int:
    kinds = tuple(args.kind) if args.kind else ("model.response", "oracle.completed")
    result = compare_observable_outcomes(args.left, args.right, kinds=kinds)
    sys.stdout.buffer.write(canonical_json_bytes(asdict(result)) + b"\n")
    return 0 if result.equivalent else 1


def _export(args: argparse.Namespace) -> int:
    reader = TraceReader(args.path)
    if args.format == "native-jsonl":
        for event in reader.events():
            sys.stdout.buffer.write(canonical_json_bytes(event) + b"\n")
        return 0
    if args.format == "otel-jsonl":
        for event in reader.events():
            span, fidelity = export_event(event)
            sys.stdout.buffer.write(
                canonical_json_bytes({"span": span, "fidelity": asdict(fidelity)}) + b"\n"
            )
        return 0
    selected = set(args.sequence) if args.sequence is not None else None
    view = reader.disclosure_view(
        sequences=selected,
        include_payload=args.include_payload,
    )
    sys.stdout.buffer.write(canonical_json_bytes(view) + b"\n")
    return 0


def _recover_trace(args: argparse.Namespace) -> int:
    digest = recover_trace(args.destination)
    sys.stdout.write(f"{digest}  {args.destination}\n")
    return 0


def _safety_backends(_args: argparse.Namespace) -> int:
    value = [backend.to_mapping() for backend in known_backend_descriptors()]
    sys.stdout.buffer.write(canonical_json_bytes(value) + b"\n")
    return 0


def _demo(args: argparse.Namespace) -> int:
    if args.kind != "sleeper":  # pragma: no cover - argparse constrains this
        raise FormatError("SOVA-DEMO-KIND", "unsupported demo kind")
    artifacts = run_complete_demo(args.destination, profile=standard_profile())
    rendered = {
        "capsule": str(artifacts.capsule),
        "trace": str(artifacts.trace),
        "reproductionTrace": str(artifacts.reproduction_trace),
        "orchestrationTrace": str(artifacts.orchestration_trace),
        "mapReport": str(artifacts.map_report),
        "report": str(artifacts.report),
        "summary": str(artifacts.summary),
        "oracleStatus": artifacts.oracle_status,
        "evidenceClosure": artifacts.evidence_closure,
        "cleanupVerified": artifacts.cleanup_verified,
        "reproduced": artifacts.reproduced,
    }
    sys.stdout.buffer.write(canonical_json_bytes(rendered) + b"\n")
    return 0


def _run_profile(custom_profile: Path | None) -> RunProfile:
    if custom_profile is None:
        return standard_profile()
    configuration = _load_object(custom_profile)
    return RunProfile(
        ProfileKind.CUSTOM,
        "0.1.0",
        customization_digest=sha256_digest(canonical_json_bytes(configuration)),
    )


def _check(args: argparse.Namespace) -> int:
    result = run_check(
        args.target,
        args.destination,
        profile=_run_profile(args.custom_profile),
    )
    sys.stdout.buffer.write(canonical_json_bytes(result.to_mapping()) + b"\n")
    return result.exit_code


def _map(args: argparse.Namespace) -> int:
    report = build_capability_map(
        args.root,
        inventories=tuple(args.inventory),
        observed_inventories=tuple(args.observed_inventory),
        runtime_authorized=bool(args.authorize_runtime_inventory),
        baseline=args.baseline,
    )
    if args.write_tool_snapshot is not None:
        write_tool_snapshot(args.write_tool_snapshot, report.graph)
    if args.output is None:
        sys.stdout.buffer.write(canonical_json_bytes(report.to_mapping()) + b"\n")
    else:
        digest = write_capability_map(args.output, report)
        sys.stdout.write(f"{digest}  {args.output}\n")
    return 0


def _executor_receipts(_args: argparse.Namespace) -> int:
    value = {
        "artifactType": "sova.external-executor-receipts",
        "schemaVersion": "0.1.0",
        "receipts": [
            MELRA_AUDIT_RECEIPT.to_mapping(),
            PLAYWRIGHT_MCP_RECEIPT.to_mapping(),
            WINDOWS_MCP_RECEIPT.to_mapping(),
        ],
        "sovaRemainsAuthority": True,
        "noMelraOperationPreserved": True,
    }
    sys.stdout.buffer.write(canonical_json_bytes(value) + b"\n")
    return 0


def _hunt_demo(_args: argparse.Namespace) -> int:
    sys.stdout.buffer.write(canonical_json_bytes(run_trigger_search_demo()) + b"\n")
    return 0


def _object_member(value: dict[str, Any], name: str) -> dict[str, Any]:
    member = value.get(name)
    if not isinstance(member, dict):
        raise FormatError("SOVA-CLI-FIELD", f"{name} must be an object", path=f"$.{name}")
    return member


def _array_member(value: dict[str, Any], name: str) -> list[Any]:
    member = value.get(name)
    if not isinstance(member, list):
        raise FormatError("SOVA-CLI-FIELD", f"{name} must be an array", path=f"$.{name}")
    return member


def _string_member(value: dict[str, Any], name: str) -> str:
    member = value.get(name)
    if not isinstance(member, str) or not member:
        raise FormatError("SOVA-CLI-FIELD", f"{name} must be a string", path=f"$.{name}")
    return member


def _boolean_member(value: dict[str, Any], name: str) -> bool:
    member = value.get(name)
    if not isinstance(member, bool):
        raise FormatError("SOVA-CLI-FIELD", f"{name} must be a boolean", path=f"$.{name}")
    return member


def _optional_boolean_member(value: dict[str, Any], name: str) -> bool | None:
    member = value.get(name)
    if member is not None and not isinstance(member, bool):
        raise FormatError("SOVA-CLI-FIELD", f"{name} must be a boolean or null", path=f"$.{name}")
    return member


def _integer_value(value: Any, name: str, *, default: int) -> int:
    selected = default if value is None else value
    if not isinstance(selected, int) or isinstance(selected, bool):
        raise FormatError("SOVA-CLI-FIELD", f"{name} must be an integer", path=f"$.{name}")
    return selected


def _scanner_finding(value: Any) -> ScannerFinding:
    if not isinstance(value, dict):
        raise FormatError("SOVA-CLI-SCANNER-FINDING", "scanner finding must be an object")
    return ScannerFinding(
        scanner=_string_member(value, "scanner"),
        scanner_version=_string_member(value, "scannerVersion"),
        rule_id=_string_member(value, "ruleId"),
        target_id=_string_member(value, "targetId"),
        location=_string_member(value, "location"),
        message=_string_member(value, "message"),
        evidence_reference=_string_member(value, "evidenceReference"),
        mechanism=_string_member(value, "mechanism"),
    )


def _forensics_reconstruct(args: argparse.Namespace) -> int:
    path: Path = args.source
    if path.name.endswith(".sova-trace"):
        report = reconstruct_trace(path)
    else:
        specification = _load_object(path)
        raw_events = _array_member(specification, "events")
        if any(not isinstance(event, dict) for event in raw_events):
            raise FormatError("SOVA-FORENSICS-EVENT", "events must contain objects")
        report = reconstruct_events(
            raw_events,
            source_type=str(specification.get("sourceType", "external.normalized-events")),
            source_id=str(specification.get("sourceId", path.name)),
            source_digest=(
                str(specification["sourceDigest"])
                if specification.get("sourceDigest") is not None
                else None
            ),
            integrity_state=str(specification.get("integrityState", "not-independently-verified")),
            dropped_event_count=_integer_value(
                specification.get("droppedEventCount"), "droppedEventCount", default=0
            ),
        )
    document = report.to_mapping()
    validate_document(document, "sova.forensic-reconstruction")
    sys.stdout.buffer.write(canonical_json_bytes(document) + b"\n")
    return 0


def _counterfactual_trial(value: Any) -> CounterfactualTrial:
    if not isinstance(value, dict):
        raise FormatError("SOVA-FORENSICS-TRIAL", "counterfactual trial must be an object")
    try:
        layer = CausalLayer(_string_member(value, "layer"))
        changed = tuple(CausalLayer(str(item)) for item in _array_member(value, "changedLayers"))
    except ValueError as error:
        raise FormatError("SOVA-FORENSICS-LAYER", "unsupported causal layer") from error
    return CounterfactualTrial(
        trial_id=_string_member(value, "trialId"),
        layer=layer,
        changed_layers=changed,
        baseline_outcome=_optional_boolean_member(value, "baselineOutcome"),
        intervention_outcome=_optional_boolean_member(value, "interventionOutcome"),
        context_equivalent=_boolean_member(value, "contextEquivalent"),
        evidence_complete=_boolean_member(value, "evidenceComplete"),
        original_trace=(
            str(value["originalTrace"]) if value.get("originalTrace") is not None else None
        ),
        counterfactual_trace=(
            str(value["counterfactualTrace"])
            if value.get("counterfactualTrace") is not None
            else None
        ),
        execution_status=str(value.get("executionStatus", "completed")),
        limitation=str(value["limitation"]) if value.get("limitation") is not None else None,
    )


def _forensics_attribute(args: argparse.Namespace) -> int:
    study = _load_object(args.study)
    trials = tuple(_counterfactual_trial(item) for item in _array_member(study, "trials"))
    report = assess_counterfactuals(_string_member(study, "originalTrace"), trials)
    sys.stdout.buffer.write(canonical_json_bytes(report.to_mapping()) + b"\n")
    return 0


def _forensics_benchmark(_args: argparse.Namespace) -> int:
    result = run_attribution_ground_truth_fixture()
    sys.stdout.buffer.write(canonical_json_bytes(result.to_mapping()) + b"\n")
    return 0


def _evidence(args: argparse.Namespace) -> int:
    bundle = build_evidence_bundle(_load_object(args.specification))
    if args.format == "json":
        document = bundle.to_mapping()
        validate_document(document, "sova.evidence")
        sys.stdout.buffer.write(canonical_json_bytes(document) + b"\n")
    elif args.format == "sarif":
        sys.stdout.buffer.write(canonical_json_bytes(evidence_to_sarif(bundle)) + b"\n")
    else:
        sys.stdout.write(render_evidence_report(bundle, audience=args.format))
    return 0


def _execution_observation(value: Any) -> ExecutionObservation:
    if not isinstance(value, dict):
        raise FormatError("SOVA-CLI-OBSERVATION", "execution observation must be an object")
    try:
        state = ObservationState(_string_member(value, "state"))
    except ValueError as error:
        raise FormatError("SOVA-CLI-OBSERVATION-STATE", "unsupported observation state") from error
    raw_limitations = value.get("limitations", [])
    if not isinstance(raw_limitations, list) or any(
        not isinstance(item, str) for item in raw_limitations
    ):
        raise FormatError("SOVA-CLI-LIMITATIONS", "limitations must be a string array")
    return ExecutionObservation(
        claim_key=_string_member(value, "claimKey"),
        state=state,
        trace_reference=(
            str(value["traceReference"]) if value.get("traceReference") is not None else None
        ),
        oracle_method=_string_member(value, "oracleMethod"),
        evidence_complete=_boolean_member(value, "evidenceComplete"),
        safe_and_authorized=_boolean_member(value, "safeAndAuthorized"),
        limitations=tuple(raw_limitations),
    )


def _adjudicate_plan(args: argparse.Namespace) -> int:
    study = _load_object(args.study)
    findings = tuple(_scanner_finding(item) for item in _array_member(study, "findings"))
    raw_actions = _array_member(study, "allowedActionFamilies")
    if any(not isinstance(item, str) for item in raw_actions):
        raise FormatError("SOVA-CLI-ACTIONS", "allowedActionFamilies must contain strings")
    plan = construct_safe_test_plan(
        findings,
        target_owned_or_authorized=study.get("targetOwnedOrAuthorized") is True,
        allowed_action_families=tuple(raw_actions),
    )
    sys.stdout.buffer.write(canonical_json_bytes(plan) + b"\n")
    return 0


def _adjudicate_evaluate(args: argparse.Namespace) -> int:
    study = _load_object(args.study)
    findings = tuple(_scanner_finding(item) for item in _array_member(study, "findings"))
    observations = tuple(
        _execution_observation(item) for item in _array_member(study, "observations")
    )
    report = adjudicate_findings(findings, observations)
    sys.stdout.buffer.write(canonical_json_bytes(report.to_mapping()) + b"\n")
    return 0


def _disclose(args: argparse.Namespace) -> int:
    specification = _load_object(args.specification)
    bundle = build_evidence_bundle(_object_member(specification, "evidence"))
    raw_request = _object_member(specification, "request")
    try:
        vulnerability_state = VulnerabilityState(_string_member(raw_request, "vulnerabilityState"))
    except ValueError as error:
        raise FormatError("SOVA-DISCLOSE-STATE", "unsupported vulnerability state") from error
    request = DisclosureRequest(
        target_kind=_string_member(raw_request, "targetKind"),
        vulnerability_state=vulnerability_state,
        contains_working_payload=_boolean_member(raw_request, "containsWorkingPayload"),
        authorization_redacted=_boolean_member(raw_request, "authorizationRedacted"),
        secrets_scan_clean=_boolean_member(raw_request, "secretsScanClean"),
        human_reviewed=_boolean_member(raw_request, "humanReviewed"),
        limitations_present=_boolean_member(raw_request, "limitationsPresent"),
        coordinated_disclosure_reference=(
            str(raw_request["coordinatedDisclosureReference"])
            if raw_request.get("coordinatedDisclosureReference") is not None
            else None
        ),
    )
    contacts = specification.get("contacts", [])
    if not isinstance(contacts, list):
        raise FormatError("SOVA-DISCLOSE-CONTACTS", "contacts must be an array")
    if any(not isinstance(item, dict) for item in contacts):
        raise FormatError("SOVA-DISCLOSE-CONTACTS", "contacts must contain objects")
    contact_root = specification.get("contactRoot")
    if contact_root is not None:
        if not isinstance(contact_root, str) or not contact_root:
            raise FormatError("SOVA-DISCLOSE-CONTACTS", "contactRoot must be a path string")
        discovered = discover_maintainer_contacts(Path(contact_root))
        contacts = [*contacts, *discovered]
    if not contacts:
        raise FormatError(
            "SOVA-DISCLOSE-CONTACTS",
            "at least one reviewed or locally discovered contact is required",
        )
    vendor_responses = specification.get("vendorResponses", [])
    if not isinstance(vendor_responses, list) or any(
        not isinstance(item, dict) for item in vendor_responses
    ):
        raise FormatError("SOVA-DISCLOSE-RESPONSES", "vendorResponses must contain objects")
    if "clock" in specification:
        clock = _object_member(specification, "clock")
    else:
        clock = default_disclosure_clock(_string_member(specification, "reportedAt"))
    package = prepare_disclosure_package(
        bundle,
        request,
        contacts=contacts,
        clock=clock,
        vendor_responses=vendor_responses,
        remediation=(
            _object_member(specification, "remediation") if "remediation" in specification else None
        ),
    )
    sys.stdout.buffer.write(canonical_json_bytes(package.to_mapping()) + b"\n")
    return 0 if package.release_allowed else 3


def _composition_budget(
    value: dict[str, Any], *, default_candidates: int = 100
) -> CompositionBudget:
    return CompositionBudget(
        max_attempts=_integer_value(value.get("maxAttempts"), "maxAttempts", default=100),
        max_duration_ms=_integer_value(value.get("maxDurationMs"), "maxDurationMs", default=30_000),
        max_t=_integer_value(value.get("maxT"), "maxT", default=3),
        max_path_nodes=_integer_value(value.get("maxPathNodes"), "maxPathNodes", default=5),
        max_candidates=_integer_value(
            value.get("maxCandidates"), "maxCandidates", default=default_candidates
        ),
    )


def _compose_plan(args: argparse.Namespace) -> int:
    graph = graph_from_mapping(_load_object(args.graph))
    budget = CompositionBudget(max_attempts=args.limit, max_t=args.t, max_candidates=args.limit)
    engine = CompositionSearchEngine(graph, budget)
    candidates = engine.candidates(CompositionStrategy(args.strategy))
    sys.stdout.buffer.write(
        canonical_json_bytes(
            {
                "artifactType": "sova.composition-plan",
                "schemaVersion": "0.1.0",
                "strategy": args.strategy,
                "candidateCount": len(candidates),
                "candidates": [candidate.to_mapping() for candidate in candidates],
                "executesActions": False,
            }
        )
        + b"\n"
    )
    return 0


def _composition_observation(value: Any) -> CompositionObservation:
    if not isinstance(value, dict):
        raise FormatError("SOVA-COMPOSE-OBSERVATION", "observation must be an object")
    traces = value.get("traceReferences", [])
    outcomes = value.get("individualOutcomes", {})
    limitations = value.get("limitations", [])
    if not isinstance(traces, list) or any(not isinstance(item, str) for item in traces):
        raise FormatError("SOVA-COMPOSE-TRACES", "traceReferences must contain strings")
    if not isinstance(outcomes, dict) or any(
        not isinstance(key, str) or not (isinstance(result, bool) or result is None)
        for key, result in outcomes.items()
    ):
        raise FormatError("SOVA-COMPOSE-OUTCOMES", "individualOutcomes is invalid")
    if not isinstance(limitations, list) or any(not isinstance(item, str) for item in limitations):
        raise FormatError("SOVA-COMPOSE-LIMITATIONS", "limitations must contain strings")
    triggered = value.get("triggered")
    if not (isinstance(triggered, bool) or triggered is None):
        raise FormatError("SOVA-COMPOSE-TRIGGERED", "triggered must be boolean or null")
    return CompositionObservation(
        triggered=triggered,
        evidence_complete=_boolean_member(value, "evidenceComplete"),
        oracle_state=_string_member(value, "oracleState"),
        trace_references=tuple(traces),
        individual_outcomes=tuple(sorted(outcomes.items())),
        limitations=tuple(limitations),
    )


def _compose_evaluate(args: argparse.Namespace) -> int:
    study = _load_object(args.study)
    graph = graph_from_mapping(_object_member(study, "graph"))
    observation_rows = _array_member(study, "observations")
    observations: dict[str, CompositionObservation] = {}
    for row in observation_rows:
        if not isinstance(row, dict):
            raise FormatError("SOVA-COMPOSE-OBSERVATION", "observation row must be an object")
        digest = _string_member(row, "candidateDigest")
        if digest in observations:
            raise FormatError("SOVA-COMPOSE-DUPLICATE", "candidate observation is duplicated")
        observations[digest] = _composition_observation(row)

    def evaluator(candidate: Any) -> CompositionObservation:
        return observations.get(
            candidate.digest,
            CompositionObservation(
                triggered=None,
                evidence_complete=False,
                oracle_state="not-observed",
                trace_references=(),
                individual_outcomes=(),
                limitations=("No reviewed observation was supplied for this candidate digest.",),
            ),
        )

    report = CompositionSearchEngine(
        graph, _composition_budget(_object_member(study, "budget"))
    ).search(CompositionStrategy(args.strategy), evaluator)
    document = report.to_mapping()
    validate_document(document, "sova.composition-report")
    sys.stdout.buffer.write(canonical_json_bytes(document) + b"\n")
    return 0 if report.successful is not None else 3


def _rehearse_prepare(args: argparse.Namespace) -> int:
    substitutes = (
        tuple(args.substitute)
        if args.substitute
        else ("process", "database", "api", "network", "browser", "computer")
    )
    report = prepare_rehearsal_environment(
        args.source,
        args.workspace,
        substitutes=substitutes,
    )
    sys.stdout.buffer.write(canonical_json_bytes(report.to_mapping()) + b"\n")
    return 0


def _rehearse_run(args: argparse.Namespace) -> int:
    specification = specification_from_mapping(_load_object(args.specification))
    report = run_rehearsal(specification, args.workspace, args.trace)
    document = report.to_mapping()
    args.report.write_bytes(canonical_json_bytes(document) + b"\n")
    sys.stdout.buffer.write(canonical_json_bytes(document) + b"\n")
    return 0


def _rehearse_export(args: argparse.Namespace) -> int:
    result = export_approved_changes(
        _load_object(args.report),
        args.workspace,
        args.destination,
        frozenset(args.approve),
    )
    sys.stdout.buffer.write(canonical_json_bytes(result) + b"\n")
    return 0


def _trace_run(args: argparse.Namespace) -> int:
    result = record_local_process(_load_object(args.specification), args.destination)
    sys.stdout.buffer.write(canonical_json_bytes(result) + b"\n")
    return 0 if result["processStatus"] == "succeeded" else 3


def _trace_snapshot(args: argparse.Namespace) -> int:
    document = build_behavior_snapshot(_load_object(args.specification)).to_mapping()
    if args.output is None:
        sys.stdout.buffer.write(canonical_json_bytes(document) + b"\n")
    else:
        args.output.write_bytes(canonical_json_bytes(document) + b"\n")
        sys.stdout.write(f"{document['snapshotDigest']}  {args.output}\n")
    return 0


def _snapshot_from_file(path: Path) -> Any:
    value = _load_object(path)
    if value.get("artifactType") == "sova.behavior-snapshot":
        axes = _object_member(value, "axes")
        axes["id"] = _string_member(value, "id")
        trace_reference = value.get("traceReference")
        if trace_reference is not None:
            if not isinstance(trace_reference, str):
                raise FormatError("SOVA-DIFF-TRACE", "traceReference must be a string or null")
            axes["traceReference"] = trace_reference
        return build_behavior_snapshot(axes)
    return build_behavior_snapshot(value)


def _behavior_diff(args: argparse.Namespace) -> int:
    report = compare_behavior_snapshots(
        _snapshot_from_file(args.left),
        _snapshot_from_file(args.right),
    )
    sys.stdout.buffer.write(canonical_json_bytes(report.to_mapping()) + b"\n")
    return 1 if report.behavioral_drift else 0


def _monitor_policy(path: Path | None) -> dict[str, Any]:
    return (
        _load_object(path)
        if path is not None
        else {
            "maxEnvironmentChanges": 0,
            "maxBehaviorChanges": 0,
            "maxMethodologyChanges": 0,
            "allowedFlakyReproductions": 0,
            "observedFlakyReproductions": 0,
            "profile": "standard",
            "retention": "operator-controlled",
        }
    )


def _sentinel(args: argparse.Namespace) -> int:
    report = run_sentinel(
        _snapshot_from_file(args.baseline),
        _snapshot_from_file(args.current),
        policy=_monitor_policy(args.policy),
        history_path=args.history,
    )
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
    return 1 if report["status"] == "failed" else 0


def _ci(args: argparse.Namespace) -> int:
    diff = compare_behavior_snapshots(
        _snapshot_from_file(args.baseline),
        _snapshot_from_file(args.current),
    )
    report = evaluate_ci(diff, _monitor_policy(args.policy))
    if args.sarif is not None:
        args.sarif.write_bytes(canonical_json_bytes(report["sarif"]) + b"\n")
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
    return int(report["exitCode"])


def _registry_verify(args: argparse.Namespace) -> int:
    trusted = frozenset(args.trusted_key_id or [])
    report = verify_registry(args.root, trusted_key_ids=trusted)
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
    return 0


def _sync(args: argparse.Namespace) -> int:
    report = sync_registry(tuple(args.sources), args.cache)
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
    return 0


def _contribute(args: argparse.Namespace) -> int:
    report = prepare_contribution(
        _load_object(args.specification),
        args.destination,
        confirmed=bool(args.confirm),
    )
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
    return 0


def _self_check_create(args: argparse.Namespace) -> int:
    document = build_integrity_manifest(args.root, tuple(args.include))
    args.manifest.write_bytes(canonical_json_bytes(document) + b"\n")
    sys.stdout.write(f"{document['manifestDigest']}  {args.manifest}\n")
    return 0


def _self_check_verify(args: argparse.Namespace) -> int:
    report = verify_integrity_manifest(args.root, _load_object(args.manifest))
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
    return 1 if report["status"] == "failed" else 0


def main(argv: Sequence[str] | None = None) -> int:
    """Parse command-line arguments and return a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = getattr(args, "handler", None)
    if handler is None:
        parser.print_help()
        return 0
    try:
        return int(handler(args))
    except (FormatError, OSError) as error:
        if isinstance(error, FormatError):
            issue = error.issue
            sys.stderr.write(f"{issue.code} {issue.path}: {issue.message}\n")
        else:
            sys.stderr.write(f"SOVA-IO-ERROR: {error}\n")
        return 2
