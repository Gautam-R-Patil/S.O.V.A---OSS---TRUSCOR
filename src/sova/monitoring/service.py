# SPDX-License-Identifier: Apache-2.0
"""Durable foreground behavioral-monitoring scheduler with signed run evidence."""

from __future__ import annotations

import os
import re
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from importlib import import_module
from typing import TYPE_CHECKING, Any, Self

from sova.formats import canonical_json_bytes, sha256_digest, strict_json_loads
from sova.formats.errors import FormatError
from sova.monitoring.diff import build_behavior_snapshot
from sova.monitoring.sentinel import run_sentinel
from sova.trace import TraceWriter, generate_ed25519_keypair

if TYPE_CHECKING:
    from pathlib import Path

    from sova.monitoring.model import BehaviorSnapshot

_SAFE_ID = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,95})$")
_MIN_INTERVAL_SECONDS = 1
_MAX_INTERVAL_SECONDS = 31 * 24 * 60 * 60
_MAX_RETENTION_RUNS = 10_000
_MAX_JOBS = 256
_MIN_POLL_SECONDS = 0.01
_MAX_POLL_SECONDS = 60


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: Any, *, name: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise FormatError("SOVA-MONITOR-STATE", f"{name} must be a UTC timestamp")
    try:
        return datetime.fromisoformat(value)
    except ValueError as error:
        raise FormatError("SOVA-MONITOR-STATE", f"{name} is malformed") from error


def _atomic_document(path: Path, document: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    temporary.write_bytes(canonical_json_bytes(dict(document)) + b"\n")
    temporary.replace(path)


def _relative_file(workspace: Path, value: Any, *, name: str) -> Path:
    if (
        not isinstance(value, str)
        or not value
        or value.startswith("/")
        or "\\" in value
        or "\x00" in value
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise FormatError("SOVA-MONITOR-PATH", f"{name} must be normalized relative POSIX")
    path = workspace.joinpath(*value.split("/")).resolve()
    if workspace not in path.parents or not path.is_file() or path.is_symlink():
        raise FormatError("SOVA-MONITOR-PATH", f"{name} must be a regular workspace file")
    return path


def _integer(value: Mapping[str, Any], name: str, *, minimum: int, maximum: int) -> int:
    item = value.get(name)
    if not isinstance(item, int) or isinstance(item, bool) or not minimum <= item <= maximum:
        raise FormatError(
            "SOVA-MONITOR-SPEC",
            f"{name} must be an integer from {minimum} through {maximum}",
        )
    return item


def _snapshot_from_document(value: Mapping[str, Any]) -> BehaviorSnapshot:
    if value.get("artifactType") == "sova.behavior-snapshot":
        axes = value.get("axes")
        identity = value.get("id")
        trace_reference = value.get("traceReference")
        if (
            not isinstance(axes, dict)
            or not isinstance(identity, str)
            or not identity
            or (trace_reference is not None and not isinstance(trace_reference, str))
        ):
            raise FormatError("SOVA-MONITOR-SNAPSHOT", "behavior snapshot is malformed")
        material = dict(axes)
        material["id"] = identity
        if trace_reference is not None:
            material["traceReference"] = trace_reference
        return build_behavior_snapshot(material)
    return build_behavior_snapshot(value)


def _load_snapshot(path: Path) -> BehaviorSnapshot:
    value = strict_json_loads(path.read_bytes())
    if not isinstance(value, Mapping):
        raise FormatError("SOVA-MONITOR-SNAPSHOT", "snapshot document must be an object")
    return _snapshot_from_document(value)


def _load_policy(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {
            "maxEnvironmentChanges": 0,
            "maxBehaviorChanges": 0,
            "maxMethodologyChanges": 0,
            "allowedFlakyReproductions": 0,
            "observedFlakyReproductions": 0,
            "profile": "standard",
            "retention": "bounded-monitor-service",
        }
    value = strict_json_loads(path.read_bytes())
    if not isinstance(value, dict):
        raise FormatError("SOVA-MONITOR-POLICY", "monitor policy must be an object")
    return value


@dataclass(frozen=True, slots=True)
class MonitoringJob:
    identifier: str
    baseline: Path
    current: Path
    policy: Path | None
    interval_seconds: int
    retention_runs: int

    def __post_init__(self) -> None:
        if _SAFE_ID.fullmatch(self.identifier) is None:
            raise FormatError("SOVA-MONITOR-ID", "monitor job id is unsafe")
        if not _MIN_INTERVAL_SECONDS <= self.interval_seconds <= _MAX_INTERVAL_SECONDS:
            raise FormatError("SOVA-MONITOR-INTERVAL", "monitor interval is outside bounds")
        if not 1 <= self.retention_runs <= _MAX_RETENTION_RUNS:
            raise FormatError("SOVA-MONITOR-RETENTION", "monitor retention is outside bounds")


def monitoring_jobs_from_document(
    document: Mapping[str, Any],
    *,
    workspace: Path,
) -> tuple[MonitoringJob, ...]:
    """Parse an exact, non-executable continuous-monitor specification."""
    if set(document) != {"artifactType", "schemaVersion", "jobs"}:
        raise FormatError("SOVA-MONITOR-SPEC", "monitor specification fields are not exact")
    if (
        document.get("artifactType") != "sova.monitor-service-spec"
        or document.get("schemaVersion") != "0.1.0"
    ):
        raise FormatError("SOVA-MONITOR-SPEC", "monitor specification type is unsupported")
    raw_jobs = document.get("jobs")
    if not isinstance(raw_jobs, list) or not 1 <= len(raw_jobs) <= _MAX_JOBS:
        raise FormatError("SOVA-MONITOR-SPEC", "monitor jobs must be a bounded non-empty array")
    workspace = workspace.resolve()
    if not workspace.is_dir():
        raise FormatError("SOVA-MONITOR-WORKSPACE", "monitor workspace must exist")
    jobs: list[MonitoringJob] = []
    for raw in raw_jobs:
        if not isinstance(raw, Mapping) or set(raw) != {
            "id",
            "baseline",
            "current",
            "policy",
            "intervalSeconds",
            "retentionRuns",
        }:
            raise FormatError("SOVA-MONITOR-SPEC", "monitor job fields are not exact")
        identifier = raw.get("id")
        if not isinstance(identifier, str):
            raise FormatError("SOVA-MONITOR-ID", "monitor job id must be a string")
        policy_value = raw.get("policy")
        policy = (
            None if policy_value is None else _relative_file(workspace, policy_value, name="policy")
        )
        jobs.append(
            MonitoringJob(
                identifier,
                _relative_file(workspace, raw.get("baseline"), name="baseline"),
                _relative_file(workspace, raw.get("current"), name="current"),
                policy,
                _integer(
                    raw,
                    "intervalSeconds",
                    minimum=_MIN_INTERVAL_SECONDS,
                    maximum=_MAX_INTERVAL_SECONDS,
                ),
                _integer(
                    raw,
                    "retentionRuns",
                    minimum=1,
                    maximum=_MAX_RETENTION_RUNS,
                ),
            )
        )
    identities = [job.identifier for job in jobs]
    if len(identities) != len(set(identities)):
        raise FormatError("SOVA-MONITOR-ID", "monitor job ids must be unique")
    return tuple(jobs)


class ContinuousMonitorService:
    """Runs deterministic snapshot comparisons on schedule in one foreground process."""

    def __init__(self, jobs: Sequence[MonitoringJob], state_root: Path) -> None:
        if not jobs:
            raise FormatError("SOVA-MONITOR-JOBS", "at least one monitor job is required")
        self.jobs = {job.identifier: job for job in jobs}
        if len(self.jobs) != len(jobs):
            raise FormatError("SOVA-MONITOR-ID", "monitor job ids must be unique")
        self.state_root = state_root.resolve()
        self.state_root.mkdir(parents=True, exist_ok=True)
        self._state_path = self.state_root / "state.json"
        self._lock_path = self.state_root / "service.lock"
        self._mutex = threading.RLock()
        self._state = self._load_state()
        self._recover_interrupted()
        self._lock_descriptor: int | None = None

    def _blank_state(self) -> dict[str, Any]:
        return {
            "artifactType": "sova.monitor-service-state",
            "schemaVersion": "0.1.0",
            "jobs": {
                identity: {
                    "status": "idle",
                    "nextRunAt": None,
                    "runCount": 0,
                    "lastRunId": None,
                    "lastStatus": None,
                    "recoveredRuns": 0,
                }
                for identity in sorted(self.jobs)
            },
            "serviceRuns": 0,
        }

    def _load_state(self) -> dict[str, Any]:
        if not self._state_path.exists():
            state = self._blank_state()
            _atomic_document(self._state_path, state)
            return state
        value = strict_json_loads(self._state_path.read_bytes())
        if (
            not isinstance(value, dict)
            or value.get("artifactType") != "sova.monitor-service-state"
            or value.get("schemaVersion") != "0.1.0"
            or not isinstance(value.get("jobs"), dict)
            or not isinstance(value.get("serviceRuns"), int)
        ):
            raise FormatError("SOVA-MONITOR-STATE", "monitor service state is malformed")
        if set(value["jobs"]) != set(self.jobs):
            raise FormatError(
                "SOVA-MONITOR-STATE",
                "monitor state job set differs from the supplied specification",
            )
        for row in value["jobs"].values():
            if not isinstance(row, dict) or row.get("status") not in {"idle", "running"}:
                raise FormatError("SOVA-MONITOR-STATE", "monitor job state is malformed")
            next_run = row.get("nextRunAt")
            if next_run is not None:
                _parse_timestamp(next_run, name="nextRunAt")
        return value

    def _persist(self) -> None:
        _atomic_document(self._state_path, self._state)

    def _recover_interrupted(self) -> None:
        changed = False
        for row in self._state["jobs"].values():
            if row["status"] == "running":
                row["status"] = "idle"
                row["nextRunAt"] = None
                row["recoveredRuns"] = int(row.get("recoveredRuns", 0)) + 1
                changed = True
        if changed:
            self._persist()

    def acquire(self) -> None:
        if self._lock_descriptor is not None:
            raise FormatError("SOVA-MONITOR-LOCK", "monitor service lock is already held")
        descriptor = os.open(
            self._lock_path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0),
            0o600,
        )
        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
            if os.fstat(descriptor).st_size == 0:
                os.write(descriptor, b" ")
            os.lseek(descriptor, 0, os.SEEK_SET)
            if os.name == "nt":
                msvcrt = import_module("msvcrt")
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            else:  # pragma: no cover - exercised by Linux/macOS CI
                fcntl = import_module("fcntl")
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, PermissionError) as error:
            os.close(descriptor)
            raise FormatError(
                "SOVA-MONITOR-OVERLAP", "another monitor service owns this state directory"
            ) from error
        os.ftruncate(descriptor, 0)
        os.write(descriptor, str(os.getpid()).encode())
        os.fsync(descriptor)
        self._lock_descriptor = descriptor

    def release(self) -> None:
        if self._lock_descriptor is None:
            return
        descriptor = self._lock_descriptor
        if os.name == "nt":
            msvcrt = import_module("msvcrt")
            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        else:  # pragma: no cover - exercised by Linux/macOS CI
            fcntl = import_module("fcntl")
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)
        self._lock_descriptor = None

    def __enter__(self) -> Self:
        self.acquire()
        return self

    def __exit__(self, *_args: object) -> None:
        self.release()

    def _due(self, identity: str, now: datetime) -> bool:
        row = self._state["jobs"][identity]
        if row["status"] == "running":
            return False
        next_run = row.get("nextRunAt")
        return next_run is None or _parse_timestamp(next_run, name="nextRunAt") <= now

    def _write_signed_evidence(
        self,
        job: MonitoringJob,
        run_id: str,
        report: Mapping[str, Any],
        destination: Path,
        *,
        snapshot_digests: tuple[str, str],
    ) -> str:
        writer = TraceWriter(
            destination,
            capture_profile="standard",
            signing_key=generate_ed25519_keypair(),
            authorization={
                "decision": "allowed",
                "scopeDigest": sha256_digest(
                    canonical_json_bytes(
                        {
                            "job": job.identifier,
                            "baseline": snapshot_digests[0],
                            "current": snapshot_digests[1],
                        }
                    )
                ),
                "decidedBy": "operator-declared-monitor-specification",
            },
            executor={
                "id": "sova:monitor:foreground-scheduler",
                "name": "sova-continuous-monitor",
                "version": "0.1.0",
                "capabilityDigest": None,
            },
        )
        start = writer.append("run.started", {"runId": run_id, "jobId": job.identifier})
        oracle = writer.append(
            "oracle.result",
            {
                "status": report["status"],
                "triggers": report["triggers"],
                "policyDigest": sha256_digest(canonical_json_bytes(_load_policy(job.policy))),
                "selfMonitoringOnly": True,
            },
            parents=[start] if start else [],
        )
        writer.append(
            "run.completed",
            {"status": report["status"]},
            parents=[oracle] if oracle else [],
        )
        return writer.finalize(completion="completed")

    def _prune(self, job: MonitoringJob) -> None:
        root = self.state_root / "runs" / job.identifier
        if not root.exists():
            return
        runs = sorted(
            (path for path in root.iterdir() if path.is_dir() and not path.is_symlink()),
            key=lambda item: item.name,
        )
        for expired in runs[: max(0, len(runs) - job.retention_runs)]:
            resolved = expired.resolve()
            if root.resolve() not in resolved.parents:
                raise FormatError("SOVA-MONITOR-RETENTION", "run path escaped retention root")
            for child in sorted(resolved.rglob("*"), reverse=True):
                if child.is_symlink():
                    raise FormatError("SOVA-MONITOR-RETENTION", "run artifacts cannot be symlinks")
                if child.is_file():
                    child.unlink()
                elif child.is_dir():
                    child.rmdir()
            resolved.rmdir()
        history = self.state_root / "history" / f"{job.identifier}.jsonl"
        if history.exists():
            rows = history.read_bytes().splitlines()
            if len(rows) > job.retention_runs:
                temporary = history.with_name(f".{history.name}.{os.getpid()}.tmp")
                temporary.write_bytes(b"\n".join(rows[-job.retention_runs :]) + b"\n")
                temporary.replace(history)

    def run_job(self, identity: str, *, now: datetime | None = None) -> dict[str, Any]:
        selected_now = _utc_now() if now is None else now.astimezone(UTC)
        job = self.jobs.get(identity)
        if job is None:
            raise FormatError("SOVA-MONITOR-ID", "monitor job does not exist")
        with self._mutex:
            row = self._state["jobs"][identity]
            if row["status"] == "running":
                raise FormatError("SOVA-MONITOR-OVERLAP", "monitor job is already running")
            row["status"] = "running"
            self._persist()
        run_number = int(row["runCount"]) + 1
        run_id = f"{selected_now.strftime('%Y%m%dT%H%M%S.%fZ')}-{run_number:08d}"
        run_root = self.state_root / "runs" / identity / run_id
        run_root.mkdir(parents=True)
        history = self.state_root / "history" / f"{identity}.jsonl"
        try:
            baseline = _load_snapshot(job.baseline)
            current = _load_snapshot(job.current)
            report = run_sentinel(
                baseline,
                current,
                policy=_load_policy(job.policy),
                history_path=history,
            )
            report_path = run_root / "report.json"
            report_path.write_bytes(canonical_json_bytes(report) + b"\n")
            trace_path = run_root / "alert.sova-trace"
            trace_digest = self._write_signed_evidence(
                job,
                run_id,
                report,
                trace_path,
                snapshot_digests=(
                    baseline.to_mapping()["snapshotDigest"],
                    current.to_mapping()["snapshotDigest"],
                ),
            )
            result = {
                "artifactType": "sova.monitor-service-run",
                "schemaVersion": "0.1.0",
                "runId": run_id,
                "jobId": identity,
                "status": report["status"],
                "triggers": report["triggers"],
                "report": str(report_path),
                "trace": str(trace_path),
                "traceDigest": trace_digest,
                "signed": True,
                "trustPolicy": "included-key-integrity-only",
                "notification": "local-artifact-and-foreground-output",
            }
            (run_root / "run.json").write_bytes(canonical_json_bytes(result) + b"\n")
        except Exception:
            with self._mutex:
                row["status"] = "idle"
                row["nextRunAt"] = _timestamp(
                    selected_now + timedelta(seconds=job.interval_seconds)
                )
                self._persist()
            raise
        with self._mutex:
            row["status"] = "idle"
            row["nextRunAt"] = _timestamp(selected_now + timedelta(seconds=job.interval_seconds))
            row["runCount"] = run_number
            row["lastRunId"] = run_id
            row["lastStatus"] = result["status"]
            self._state["serviceRuns"] = int(self._state["serviceRuns"]) + 1
            self._persist()
        self._prune(job)
        return result

    def run_due(self, *, now: datetime | None = None) -> tuple[dict[str, Any], ...]:
        selected_now = _utc_now() if now is None else now.astimezone(UTC)
        return tuple(
            self.run_job(identity, now=selected_now)
            for identity in sorted(self.jobs)
            if self._due(identity, selected_now)
        )

    def status(self) -> dict[str, Any]:
        with self._mutex:
            return {
                "artifactType": "sova.monitor-service-status",
                "schemaVersion": "0.1.0",
                "jobs": {key: dict(value) for key, value in self._state["jobs"].items()},
                "serviceRuns": self._state["serviceRuns"],
                "foreground": True,
                "automaticUpload": False,
                "automaticRemediation": False,
                "limitations": [
                    "This scheduler compares operator-supplied observable snapshots.",
                    "It does not independently observe hidden model state or guarantee uptime.",
                ],
            }

    def serve(
        self,
        stop: threading.Event,
        *,
        max_cycles: int | None = None,
        poll_seconds: float = 0.25,
    ) -> tuple[dict[str, Any], ...]:
        if max_cycles is not None and max_cycles < 1:
            raise FormatError("SOVA-MONITOR-CYCLES", "max cycles must be positive")
        if not _MIN_POLL_SECONDS <= poll_seconds <= _MAX_POLL_SECONDS:
            raise FormatError("SOVA-MONITOR-POLL", "poll interval is outside bounds")
        outputs: list[dict[str, Any]] = []
        cycles = 0
        with self:
            while not stop.is_set():
                outputs.extend(self.run_due())
                cycles += 1
                if max_cycles is not None and cycles >= max_cycles:
                    break
                stop.wait(poll_seconds)
        return tuple(outputs)


__all__ = [
    "ContinuousMonitorService",
    "MonitoringJob",
    "monitoring_jobs_from_document",
]
