# SPDX-License-Identifier: Apache-2.0
"""Fail-closed Firecracker jailer lifecycle and exact execution receipts."""

from __future__ import annotations

import hashlib
import os
import platform
import select
import shutil
import signal
import socket
import stat
import subprocess
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any, Protocol, cast

from sova.formats import canonical_json_bytes, sha256_digest, validate_document
from sova.formats.errors import FormatError
from sova.worker.firecracker import (
    FirecrackerHostPolicy,
    FirecrackerLaunchPlan,
    WorkerCleanupReceipt,
)

if TYPE_CHECKING:
    from collections.abc import Callable

_MAX_API_RESPONSE_BYTES = 64 * 1024
_MAX_PID_BYTES = 32
_JAILER_START_TIMEOUT_SECONDS = 30
_PID_FILE_TIMEOUT_SECONDS = 10.0
_API_SOCKET_TIMEOUT_SECONDS = 10.0
_SHUTDOWN_GRACE_SECONDS = 5.0
_MIN_HTTP_PARTS = 2
_MIN_HTTP_STATUS = 100
_MAX_HTTP_STATUS = 599
_HTTP_NO_CONTENT = 204
_AF_UNIX = getattr(socket, "AF_UNIX", 1)
_SIGKILL = getattr(signal, "SIGKILL", signal.SIGTERM)
_IP_BINARY = "/usr/sbin/ip"
_EXPECTED_RESOURCE_LIMITS = 2
_MIN_OPEN_FILES = 32
_MAX_OPEN_FILES = 4096


class _SocketLike(Protocol):
    def settimeout(self, timeout: float) -> None: ...

    def connect(self, path: str) -> None: ...

    def sendall(self, data: bytes) -> None: ...

    def recv(self, size: int) -> bytes: ...

    def close(self) -> None: ...


@dataclass(frozen=True, slots=True)
class FirecrackerApiReceipt:
    """One request sent over the host-visible Firecracker Unix socket."""

    path: str
    request_digest: str
    status_code: int

    def to_mapping(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "requestDigest": self.request_digest,
            "statusCode": self.status_code,
        }


@dataclass(frozen=True, slots=True)
class FirecrackerExecutionReceipt:
    """Controller-observed lifecycle facts; never an isolation review by itself."""

    job_id: str
    vm_id: str
    manifest_digest: str
    launch_plan_digest: str
    execution_mode: str
    started_at: str
    completed_at: str
    jailer_exit_code: int | None
    process_id: int | None
    api_calls: tuple[FirecrackerApiReceipt, ...]
    instance_started: bool
    watchdog_triggered: bool
    execution_status: str
    cleanup_receipt_digest: str
    cleanup_complete: bool
    failure_code: str | None = None

    def to_mapping(self) -> dict[str, Any]:
        status = "cleanup-failed" if not self.cleanup_complete else self.execution_status
        body: dict[str, Any] = {
            "artifactType": "sova.firecracker-execution-receipt",
            "schemaVersion": "0.1.0",
            "jobId": self.job_id,
            "vmId": self.vm_id,
            "manifestDigest": self.manifest_digest,
            "launchPlanDigest": self.launch_plan_digest,
            "executionMode": self.execution_mode,
            "startedAt": self.started_at,
            "completedAt": self.completed_at,
            "jailerExitCode": self.jailer_exit_code,
            "processId": self.process_id,
            "apiCalls": [item.to_mapping() for item in self.api_calls],
            "instanceStarted": self.instance_started,
            "watchdogTriggered": self.watchdog_triggered,
            "executionStatus": self.execution_status,
            "cleanupReceiptDigest": self.cleanup_receipt_digest,
            "cleanupComplete": self.cleanup_complete,
            "failureCode": self.failure_code,
            "status": status,
            "claims": {
                "liveFirecrackerExecuted": (
                    self.execution_mode == "live" and self.instance_started
                ),
                "productionIsolationClaimAllowed": False,
                "exactHostMatrixPassed": False,
                "independentlyReviewed": False,
                "escapeImpossible": False,
            },
        }
        body["contentDigest"] = sha256_digest(canonical_json_bytes(body))
        return body


@dataclass(frozen=True, slots=True)
class FirecrackerLifecycleResult:
    execution: FirecrackerExecutionReceipt
    cleanup: WorkerCleanupReceipt


class FirecrackerLifecycleBackend(Protocol):
    """Small privileged boundary used by the deterministic lifecycle state machine."""

    live_execution: bool

    def prepare(self, plan: FirecrackerLaunchPlan) -> None: ...

    def launch(self, plan: FirecrackerLaunchPlan) -> int: ...

    def wait_for_api_socket(self, plan: FirecrackerLaunchPlan, timeout: float) -> bool: ...

    def wait_for_process_id(self, plan: FirecrackerLaunchPlan, timeout: float) -> int: ...

    def read_process_id(self, plan: FirecrackerLaunchPlan) -> int: ...

    def put_api(self, plan: FirecrackerLaunchPlan, path: str, payload: dict[str, Any]) -> int: ...

    def wait_for_process(self, process_id: int, timeout: float) -> int | None: ...

    def terminate_process(self, process_id: int) -> bool: ...

    def cleanup(
        self,
        plan: FirecrackerLaunchPlan,
        *,
        completed_at: str,
        secret_broker_revoked: bool,
    ) -> WorkerCleanupReceipt: ...


class FirecrackerUnixApiClient:
    """Bounded HTTP/1.1 PUT client for Firecracker's Unix-domain API socket."""

    def __init__(
        self,
        *,
        socket_factory: Callable[[int, int], _SocketLike] = socket.socket,
    ) -> None:
        self._socket_factory = socket_factory

    def put(
        self,
        socket_path: Path,
        path: str,
        payload: dict[str, Any],
        *,
        timeout: float = 2.0,
    ) -> int:
        if not path.startswith("/") or "\r" in path or "\n" in path or " " in path:
            raise FormatError("SOVA-WORKER-API-PATH", "Firecracker API path is invalid")
        body = canonical_json_bytes(payload)
        request = (
            f"PUT {path} HTTP/1.1\r\nHost: localhost\r\n"
            f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii") + body
        client = self._socket_factory(_AF_UNIX, socket.SOCK_STREAM)
        try:
            client.settimeout(timeout)
            client.connect(str(socket_path))
            client.sendall(request)
            response = bytearray()
            while b"\r\n\r\n" not in response:
                chunk = client.recv(4096)
                if not chunk:
                    break
                response.extend(chunk)
                if len(response) > _MAX_API_RESPONSE_BYTES:
                    raise FormatError(
                        "SOVA-WORKER-API-RESPONSE", "Firecracker API response is too large"
                    )
        except (OSError, TimeoutError) as error:
            raise FormatError(
                "SOVA-WORKER-API-IO", "Firecracker API request failed closed"
            ) from error
        finally:
            client.close()
        head, separator, _body = bytes(response).partition(b"\r\n\r\n")
        first_line = head.split(b"\r\n", maxsplit=1)[0]
        parts = first_line.split(b" ")
        if (
            not separator
            or len(parts) < _MIN_HTTP_PARTS
            or parts[0] != b"HTTP/1.1"
            or not parts[1].isdigit()
        ):
            raise FormatError("SOVA-WORKER-API-RESPONSE", "Firecracker API response is invalid")
        status_code = int(parts[1])
        if not _MIN_HTTP_STATUS <= status_code <= _MAX_HTTP_STATUS:
            raise FormatError("SOVA-WORKER-API-RESPONSE", "Firecracker API status is invalid")
        return status_code


class PosixFirecrackerBackend:
    """Root-only host operations for an already provisioned dedicated Linux worker."""

    live_execution = True

    def __init__(
        self,
        policy: FirecrackerHostPolicy,
        *,
        api_client: FirecrackerUnixApiClient | None = None,
    ) -> None:
        self.policy = policy
        self.api_client = api_client or FirecrackerUnixApiClient()
        self._pid_handles: dict[int, int] = {}
        self._plan_processes: dict[str, int] = {}

    @staticmethod
    def _require_live_host() -> None:
        get_euid = cast("Callable[[], int] | None", getattr(os, "geteuid", None))
        if platform.system() != "Linux" or get_euid is None:
            raise FormatError("SOVA-WORKER-HOST", "live Firecracker execution requires Linux")
        if get_euid() != 0:
            raise FormatError("SOVA-WORKER-HOST", "live Firecracker execution requires root")

    @staticmethod
    def _digest_file(path: Path) -> str:
        if path.is_symlink() or not path.is_file():
            raise FormatError("SOVA-WORKER-HOST-FILE", "worker input must be a regular file")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return f"sha256:{digest.hexdigest()}"

    @staticmethod
    def _require_root_controlled(path: Path) -> None:
        current = path
        while True:
            if current.is_symlink() or not current.exists():
                raise FormatError("SOVA-WORKER-HOST-PATH", "worker host path is missing or linked")
            metadata = current.stat()
            if metadata.st_uid != 0 or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise FormatError(
                    "SOVA-WORKER-HOST-PATH", "worker host path is not root controlled"
                )
            if current.parent == current:
                break
            current = current.parent

    def _host_path(self, plan: FirecrackerLaunchPlan, guest_path: str) -> Path:
        relative = PurePosixPath(guest_path)
        if not relative.is_absolute() or ".." in relative.parts:
            raise FormatError("SOVA-WORKER-HOST-PATH", "guest path is invalid")
        root = Path(plan.chroot_directory) / "root"
        return root.joinpath(*relative.parts[1:])

    def _validate_jailer_command(self, plan: FirecrackerLaunchPlan) -> None:
        command = list(plan.jailer_command)
        if not command or command[0] != str(self.policy.jailer_binary) or command.count("--") != 1:
            raise FormatError("SOVA-WORKER-JAILER-ARGV", "jailer command boundary drifted")
        separator = command.index("--")
        forwarded = command[separator + 1 :]
        if forwarded != [
            "--api-sock",
            plan.api_socket,
        ]:
            raise FormatError("SOVA-WORKER-JAILER-ARGV", "Firecracker arguments drifted")
        singleton_flags = {
            "--id",
            "--exec-file",
            "--uid",
            "--gid",
            "--chroot-base-dir",
            "--netns",
            "--cgroup-version",
            "--parent-cgroup",
        }
        repeated_flags = {"--cgroup", "--resource-limit"}
        boolean_flags = {"--new-pid-ns", "--daemonize"}
        singletons: dict[str, str] = {}
        repeated: dict[str, list[str]] = {item: [] for item in repeated_flags}
        observed_booleans: set[str] = set()
        index = 1
        while index < separator:
            flag = command[index]
            if flag in boolean_flags:
                if flag in observed_booleans:
                    raise FormatError("SOVA-WORKER-JAILER-ARGV", "jailer flag is duplicated")
                observed_booleans.add(flag)
                index += 1
                continue
            if flag not in singleton_flags | repeated_flags or index + 1 >= separator:
                raise FormatError("SOVA-WORKER-JAILER-ARGV", "jailer argument is not allowed")
            value = command[index + 1]
            if flag in singleton_flags:
                if flag in singletons:
                    raise FormatError("SOVA-WORKER-JAILER-ARGV", "jailer option is duplicated")
                singletons[flag] = value
            else:
                repeated[flag].append(value)
            index += 2
        expected_singletons = {
            "--id": plan.vm_id,
            "--exec-file": str(self.policy.firecracker_binary),
            "--uid": str(plan.uid),
            "--gid": str(plan.gid),
            "--chroot-base-dir": str(self.policy.chroot_base),
            "--netns": plan.network_namespace,
            "--cgroup-version": "2",
            "--parent-cgroup": "sova",
        }
        resources = repeated["--resource-limit"]
        no_file = [item for item in resources if item.startswith("no-file=")]
        if (
            plan.api_socket != "/api.socket"
            or plan.pid_file != f"/{self.policy.firecracker_binary.name}.pid"
            or singletons != expected_singletons
            or observed_booleans != boolean_flags
            or set(repeated["--cgroup"]) != {f"{key}={value}" for key, value in plan.cgroup_values}
            or len(repeated["--cgroup"]) != len(plan.cgroup_values)
            or len(resources) != _EXPECTED_RESOURCE_LIMITS
            or len(no_file) != 1
            or not no_file[0][8:].isdigit()
            or not _MIN_OPEN_FILES <= int(no_file[0][8:]) <= _MAX_OPEN_FILES
            or f"fsize={plan.maximum_log_bytes}" not in resources
        ):
            raise FormatError("SOVA-WORKER-JAILER-ARGV", "jailer policy arguments drifted")

    def _stage_content(self, plan: FirecrackerLaunchPlan, root: Path) -> None:
        chown = cast(
            "Callable[[Path, int, int], None] | None",
            getattr(os, "chown", None),
        )
        if chown is None:
            raise FormatError("SOVA-WORKER-HOST", "POSIX ownership control is required")
        for source_value, destination_value, mode in plan.staged_content:
            source = Path(source_value)
            destination = Path(destination_value)
            if source.parent.parent != self.policy.content_store / "sha256":
                raise FormatError("SOVA-WORKER-CAS", "staged source is outside the pinned CAS")
            self._require_root_controlled(source)
            if self._digest_file(source) != f"sha256:{source.name}":
                raise FormatError("SOVA-WORKER-CAS", "staged source digest drifted")
            if root not in destination.parents or destination.exists():
                raise FormatError("SOVA-WORKER-HOST-PATH", "staged destination is unsafe")
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination, follow_symlinks=False)
            chown(destination, plan.uid, plan.gid)
            destination.chmod(0o600 if mode == "copy-disposable-writable" else 0o400)
            if self._digest_file(destination) != f"sha256:{source.name}":
                raise FormatError("SOVA-WORKER-CAS", "staged copy digest drifted")

    def prepare(self, plan: FirecrackerLaunchPlan) -> None:
        self._require_live_host()
        self._validate_jailer_command(plan)
        for binary, expected in (
            (self.policy.firecracker_binary, self.policy.approved_firecracker_digest),
            (self.policy.jailer_binary, self.policy.approved_jailer_digest),
        ):
            self._require_root_controlled(binary)
            if self._digest_file(binary) != expected:
                raise FormatError("SOVA-WORKER-HOST-DIGEST", "worker binary digest drifted")
        self._require_root_controlled(self.policy.chroot_base)
        self._require_root_controlled(self.policy.content_store)
        self._require_root_controlled(self.policy.cgroup_base)
        namespace = Path(plan.network_namespace)
        if namespace != self.policy.network_namespace_base / plan.vm_id:
            raise FormatError("SOVA-WORKER-HOST-PATH", "network namespace path drifted")
        self._require_root_controlled(namespace)
        jailer_root = self.policy.chroot_base / self.policy.firecracker_binary.name
        if jailer_root.exists():
            self._require_root_controlled(jailer_root)
            if not jailer_root.is_dir():
                raise FormatError("SOVA-WORKER-HOST-PATH", "jailer root is not a directory")
        expected_chroot = jailer_root / plan.vm_id
        if (
            Path(plan.chroot_directory) != expected_chroot
            or expected_chroot.exists()
            or expected_chroot.is_symlink()
        ):
            raise FormatError("SOVA-WORKER-HOST-PATH", "jail root is drifted or already exists")
        root = expected_chroot / "root"
        try:
            root.mkdir(parents=True, mode=0o700)
            self._stage_content(plan, root)
        except Exception:
            if expected_chroot.exists() and not expected_chroot.is_symlink():
                shutil.rmtree(expected_chroot)
            raise

    def launch(self, plan: FirecrackerLaunchPlan) -> int:
        self._require_live_host()
        completed = subprocess.run(  # noqa: S603 - argv is compiler-owned and digest-pinned
            list(plan.jailer_command),
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={"LANG": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
            timeout=_JAILER_START_TIMEOUT_SECONDS,
        )
        return completed.returncode

    def wait_for_api_socket(self, plan: FirecrackerLaunchPlan, timeout: float) -> bool:
        path = self._host_path(plan, plan.api_socket)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                if stat.S_ISSOCK(path.stat().st_mode):
                    return True
            except FileNotFoundError:
                pass
            time.sleep(0.05)
        return False

    def read_process_id(self, plan: FirecrackerLaunchPlan) -> int:
        existing = self._plan_processes.get(plan.vm_id)
        if existing is not None:
            return existing
        path = self._host_path(plan, plan.pid_file)
        raw = path.read_bytes()
        if not 0 < len(raw) <= _MAX_PID_BYTES or not raw.strip().isdigit():
            raise FormatError("SOVA-WORKER-PID", "Firecracker pid file is invalid")
        process_id = int(raw.strip())
        if process_id <= 1:
            raise FormatError("SOVA-WORKER-PID", "Firecracker process id is unsafe")
        pidfd_open = cast("Callable[[int, int], int] | None", getattr(os, "pidfd_open", None))
        if pidfd_open is None:
            raise FormatError("SOVA-WORKER-PIDFD", "Linux pidfd support is required")
        try:
            handle = pidfd_open(process_id, 0)
        except OSError as error:
            raise FormatError("SOVA-WORKER-PID", "Firecracker process is unavailable") from error
        self._pid_handles[process_id] = handle
        self._plan_processes[plan.vm_id] = process_id
        return process_id

    def wait_for_process_id(self, plan: FirecrackerLaunchPlan, timeout: float) -> int:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                return self.read_process_id(plan)
            except FileNotFoundError:
                time.sleep(0.05)
        raise FormatError("SOVA-WORKER-PID-TIMEOUT", "Firecracker pid file was not created")

    def put_api(
        self,
        plan: FirecrackerLaunchPlan,
        path: str,
        payload: dict[str, Any],
    ) -> int:
        return self.api_client.put(self._host_path(plan, plan.api_socket), path, payload)

    def wait_for_process(self, process_id: int, timeout: float) -> int | None:
        handle = self._pid_handles.get(process_id)
        if handle is None:
            raise FormatError("SOVA-WORKER-PIDFD", "Firecracker pidfd is not bound")
        readable, _writable, _exceptional = select.select([handle], [], [], timeout)
        return 0 if readable else None

    def terminate_process(self, process_id: int) -> bool:
        handle = self._pid_handles.get(process_id)
        send_signal = cast(
            "Callable[[int, int, Any, int], None] | None",
            getattr(signal, "pidfd_send_signal", None),
        )
        if handle is None or send_signal is None:
            return False
        for process_signal in (signal.SIGTERM, _SIGKILL):
            try:
                send_signal(handle, process_signal, None, 0)
            except ProcessLookupError:
                return True
            if self.wait_for_process(process_id, 2.0) is not None:
                return True
        return False

    def cleanup(
        self,
        plan: FirecrackerLaunchPlan,
        *,
        completed_at: str,
        secret_broker_revoked: bool,
    ) -> WorkerCleanupReceipt:
        expected_chroot = self.policy.chroot_base / self.policy.firecracker_binary.name / plan.vm_id
        expected_namespace = self.policy.network_namespace_base / plan.vm_id
        expected_cgroup = self.policy.cgroup_base / "sova" / plan.vm_id
        if (
            Path(plan.chroot_directory) != expected_chroot
            or Path(plan.network_namespace) != expected_namespace
            or Path(plan.cgroup_directory) != expected_cgroup
        ):
            raise FormatError("SOVA-WORKER-HOST-PATH", "cleanup resource path drifted")
        process_id = self._plan_processes.get(plan.vm_id)
        process_terminated = (
            process_id is not None or not self._host_path(plan, plan.pid_file).exists()
        )
        if process_id is not None:
            process_terminated = self.terminate_process(process_id)
        api_socket = self._host_path(plan, plan.api_socket)
        api_socket.unlink(missing_ok=True)
        api_socket_removed = not api_socket.exists()
        cgroup = Path(plan.cgroup_directory)
        try:
            cgroup.rmdir()
        except FileNotFoundError:
            pass
        except OSError:
            pass
        cgroup_removed = not cgroup.exists()
        namespace = Path(plan.network_namespace)
        namespace_removed = not namespace.exists()
        if namespace.exists() and namespace.parent == self.policy.network_namespace_base:
            result = subprocess.run(  # noqa: S603 - absolute root-owned host utility
                [_IP_BINARY, "netns", "delete", plan.vm_id],
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
            namespace_removed = result.returncode == 0 and not namespace.exists()
        chroot = Path(plan.chroot_directory)
        if chroot.exists() and chroot.parent == (
            self.policy.chroot_base / self.policy.firecracker_binary.name
        ):
            if chroot.is_symlink():
                raise FormatError("SOVA-WORKER-HOST-PATH", "jail root became a symlink")
            shutil.rmtree(chroot)
        chroot_removed = not chroot.exists()
        tracked_process = self._plan_processes.pop(plan.vm_id, None)
        if tracked_process is not None:
            handle = self._pid_handles.pop(tracked_process, None)
            if handle is not None:
                os.close(handle)
        return WorkerCleanupReceipt(
            job_id=plan.job_id,
            vm_id=plan.vm_id,
            completed_at=completed_at,
            process_terminated=process_terminated,
            api_socket_removed=api_socket_removed,
            cgroup_removed=cgroup_removed,
            network_namespace_removed=namespace_removed,
            chroot_removed=chroot_removed,
            writable_layer_removed=chroot_removed,
            secret_broker_revoked=secret_broker_revoked,
        )


class FirecrackerLifecycleRunner:
    """Execute an admitted plan and always emit controller-observed cleanup state."""

    def __init__(
        self,
        backend: FirecrackerLifecycleBackend,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.backend = backend
        self.clock = clock or (lambda: datetime.now(UTC))

    def _timestamp(self) -> str:
        value = self.clock().astimezone(UTC).replace(microsecond=0)
        return value.strftime("%Y-%m-%dT%H:%M:%SZ")

    @staticmethod
    def _failure_code(error: Exception) -> str:
        if isinstance(error, FormatError):
            return error.issue.code
        if isinstance(error, subprocess.TimeoutExpired):
            return "SOVA-WORKER-JAILER-TIMEOUT"
        return "SOVA-WORKER-HOST-IO"

    def run(  # noqa: PLR0912, PLR0915 - lifecycle remains one auditable state machine
        self,
        plan: FirecrackerLaunchPlan,
        *,
        revoke_secrets: Callable[[], bool],
    ) -> FirecrackerLifecycleResult:
        plan_mapping = plan.to_mapping()
        validate_document(plan_mapping)
        if not plan.firecracker_api_requests or plan.firecracker_api_requests[-1] != (
            "/actions",
            {"action_type": "InstanceStart"},
        ):
            raise FormatError("SOVA-WORKER-API-SEQUENCE", "launch plan has no final start action")
        started_at = self._timestamp()
        jailer_exit_code: int | None = None
        process_id: int | None = None
        api_calls: list[FirecrackerApiReceipt] = []
        instance_started = False
        watchdog_triggered = False
        execution_status = "failed"
        failure_code: str | None = None
        prepared = False
        try:
            self.backend.prepare(plan)
            prepared = True
            jailer_exit_code = self.backend.launch(plan)
            if jailer_exit_code != 0:
                failure_code = "SOVA-WORKER-JAILER-EXIT"
            else:
                process_id = self.backend.wait_for_process_id(plan, _PID_FILE_TIMEOUT_SECONDS)
            if (
                failure_code is None
                and process_id is not None
                and not self.backend.wait_for_api_socket(plan, _API_SOCKET_TIMEOUT_SECONDS)
            ):
                failure_code = "SOVA-WORKER-API-SOCKET-TIMEOUT"
            if failure_code is None and process_id is not None:
                for path, payload in plan.firecracker_api_requests:
                    status_code = self.backend.put_api(plan, path, payload)
                    api_calls.append(
                        FirecrackerApiReceipt(
                            path,
                            sha256_digest(canonical_json_bytes(payload)),
                            status_code,
                        )
                    )
                    if status_code != _HTTP_NO_CONTENT:
                        failure_code = "SOVA-WORKER-API-STATUS"
                        break
                    if path == "/actions" and payload == {"action_type": "InstanceStart"}:
                        instance_started = True
                if failure_code is not None:
                    self.backend.terminate_process(process_id)
                if failure_code is None:
                    process_exit = self.backend.wait_for_process(
                        process_id, float(plan.watchdog_seconds)
                    )
                    if process_exit is None:
                        watchdog_triggered = True
                        shutdown_payload = {"action_type": "SendCtrlAltDel"}
                        shutdown_status = self.backend.put_api(plan, "/actions", shutdown_payload)
                        api_calls.append(
                            FirecrackerApiReceipt(
                                "/actions",
                                sha256_digest(canonical_json_bytes(shutdown_payload)),
                                shutdown_status,
                            )
                        )
                        process_exit = self.backend.wait_for_process(
                            process_id, _SHUTDOWN_GRACE_SECONDS
                        )
                        if process_exit is None:
                            self.backend.terminate_process(process_id)
                        execution_status = "timed-out"
                        failure_code = "SOVA-WORKER-WATCHDOG"
                    elif process_exit == 0:
                        execution_status = "process-exited"
                    else:
                        failure_code = "SOVA-WORKER-PROCESS-EXIT"
        except (FormatError, OSError, subprocess.SubprocessError) as error:
            failure_code = self._failure_code(error)
            if process_id is not None:
                self.backend.terminate_process(process_id)
        completed_at = self._timestamp()
        secret_broker_revoked = False
        try:
            secret_broker_revoked = revoke_secrets()
        except Exception:  # noqa: BLE001 - the cleanup receipt must preserve callback failure
            secret_broker_revoked = False
        if prepared:
            try:
                cleanup = self.backend.cleanup(
                    plan,
                    completed_at=completed_at,
                    secret_broker_revoked=secret_broker_revoked,
                )
            except (FormatError, OSError, subprocess.SubprocessError):
                cleanup = WorkerCleanupReceipt(
                    job_id=plan.job_id,
                    vm_id=plan.vm_id,
                    completed_at=completed_at,
                    process_terminated=False,
                    api_socket_removed=False,
                    cgroup_removed=False,
                    network_namespace_removed=False,
                    chroot_removed=False,
                    writable_layer_removed=False,
                    secret_broker_revoked=secret_broker_revoked,
                )
        else:
            cleanup = WorkerCleanupReceipt(
                job_id=plan.job_id,
                vm_id=plan.vm_id,
                completed_at=completed_at,
                process_terminated=True,
                api_socket_removed=True,
                cgroup_removed=True,
                network_namespace_removed=True,
                chroot_removed=True,
                writable_layer_removed=True,
                secret_broker_revoked=secret_broker_revoked,
            )
        cleanup_mapping = cleanup.to_mapping()
        validate_document(cleanup_mapping)
        execution = FirecrackerExecutionReceipt(
            job_id=plan.job_id,
            vm_id=plan.vm_id,
            manifest_digest=plan.manifest_digest,
            launch_plan_digest=str(plan_mapping["contentDigest"]),
            execution_mode="live" if self.backend.live_execution else "simulated",
            started_at=started_at,
            completed_at=completed_at,
            jailer_exit_code=jailer_exit_code,
            process_id=process_id,
            api_calls=tuple(api_calls),
            instance_started=instance_started,
            watchdog_triggered=watchdog_triggered,
            execution_status=execution_status,
            cleanup_receipt_digest=str(cleanup_mapping["contentDigest"]),
            cleanup_complete=cleanup.complete,
            failure_code=failure_code,
        )
        validate_document(execution.to_mapping())
        return FirecrackerLifecycleResult(execution, cleanup)


__all__ = [
    "FirecrackerApiReceipt",
    "FirecrackerExecutionReceipt",
    "FirecrackerLifecycleBackend",
    "FirecrackerLifecycleResult",
    "FirecrackerLifecycleRunner",
    "FirecrackerUnixApiClient",
    "PosixFirecrackerBackend",
]
