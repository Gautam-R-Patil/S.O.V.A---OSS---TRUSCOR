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
from sova.trace import TraceReader, recover_trace
from sova.trace.otel import export_event

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

    query_parser = commands.add_parser("query", help="query trace events offline")
    query_parser.add_argument("path", type=_path)
    query_parser.add_argument("--kind-prefix")
    query_parser.add_argument("--actor-id")
    query_parser.add_argument("--start", type=int, default=0)
    query_parser.add_argument("--stop", type=int)
    query_parser.set_defaults(handler=_query)

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
    if path.name.endswith(".sova-trace"):
        report = TraceReader(path).verify(
            require_signature=args.require_signature,
            required_key_id=args.key_id,
        )
        value = {
            "traceId": report.trace_id,
            "eventCount": report.event_count,
            "completion": report.completion,
            "packageIntegrity": report.package_integrity,
            "eventChainIntegrity": report.event_chain_integrity,
            "manifestIntegrity": report.manifest_integrity,
            "redactionIntegrity": report.redaction_integrity,
            "signaturePresent": report.signature_present,
            "signatureValid": report.signature_valid,
            "verificationMaterialPresent": report.verification_material_present,
            "verificationMaterialVerified": report.verification_material_verified,
            "trustPolicy": report.trust_policy,
            "limitations": list(report.limitations),
        }
        sys.stdout.write(json.dumps(value, sort_keys=True) + "\n")
    else:
        descriptors = PackageReader(path).verify("sova.capsule")
        sys.stdout.write(f"VERIFIED capsule objects={len(descriptors)}\n")
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
