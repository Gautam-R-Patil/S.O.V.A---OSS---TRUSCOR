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
from sova.replay import (
    ReplayMode,
    VerificationState,
    render_timeline_html,
    semantic_reproduction_study,
    verify_artifact,
)
from sova.reproduction import compare_observable_outcomes
from sova.runtime import ProfileKind, RunProfile, standard_profile
from sova.safety import known_backend_descriptors
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
