# SPDX-License-Identifier: Apache-2.0
"""Dedicated Linux/KVM host preflight receipt tests."""

from __future__ import annotations

import stat
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from sova.formats import FormatError, validate_document
from sova.worker.firecracker import FirecrackerHostPolicy
from sova.worker.host_preflight import (
    HostPreflightCheck,
    WorkerHostPreflightReceipt,
    _cpu_vulnerability_state,
    _digest_file,
    _identity_ranges_unallocated,
    _kvm_available,
    _permission_bits,
    _read_text,
    _root_controlled,
    _swap_disabled,
    collect_worker_host_preflight,
)
from sova.worker.network_plane import NetworkPlaneHostPolicy
from tests.support.worker import digest, worker_attestation


def _policies(tmp_path: Path) -> tuple[FirecrackerHostPolicy, NetworkPlaneHostPolicy]:
    binary_values = {
        "firecracker": b"firecracker",
        "jailer": b"jailer",
        "ip": b"ip",
        "nft": b"nft",
        "setpriv": b"setpriv",
        "mediator": b"mediator",
    }
    binary_dir = tmp_path / "bin"
    binary_dir.mkdir()
    for name, value in binary_values.items():
        (binary_dir / name).write_bytes(value)
    for name in (
        "jailer-root",
        "netns",
        "cas",
        "cgroup",
        "network-state",
        "identity-leases",
    ):
        (tmp_path / name).mkdir()
    (tmp_path / "cgroup" / "cgroup.controllers").write_text("cpu memory pids", encoding="utf-8")
    firecracker = FirecrackerHostPolicy(
        firecracker_binary=(binary_dir / "firecracker").resolve(),
        jailer_binary=(binary_dir / "jailer").resolve(),
        chroot_base=(tmp_path / "jailer-root").resolve(),
        network_namespace_base=(tmp_path / "netns").resolve(),
        content_store=(tmp_path / "cas").resolve(),
        cgroup_base=(tmp_path / "cgroup").resolve(),
        approved_firecracker_digest=digest("firecracker"),
        approved_jailer_digest=digest("jailer"),
    )
    network = NetworkPlaneHostPolicy(
        ip_binary=(binary_dir / "ip").resolve(),
        nft_binary=(binary_dir / "nft").resolve(),
        setpriv_binary=(binary_dir / "setpriv").resolve(),
        mediator_binary=(binary_dir / "mediator").resolve(),
        state_directory=(tmp_path / "network-state").resolve(),
        approved_ip_digest=digest("ip"),
        approved_nft_digest=digest("nft"),
        approved_setpriv_digest=digest("setpriv"),
        approved_mediator_digest=digest("mediator"),
        egress_interface="eth0",
        mediator_uid_base=700_000,
        mediator_gid_base=700_000,
    )
    return firecracker, network


def _host_mocks(monkeypatch: pytest.MonkeyPatch, *, kvm: bool = True) -> None:
    values = {
        "/proc/version": "Linux dedicated-worker",
        "/proc/swaps": "Filename Type Size Used Priority",
        "/proc/sys/net/ipv4/ip_forward": "1",
        "/sys/devices/system/cpu/smt/active": "0",
        "/proc/sys/kernel/unprivileged_bpf_disabled": "2",
    }
    monkeypatch.setattr("sova.worker.host_preflight.platform.system", lambda: "Linux")
    monkeypatch.setattr("sova.worker.host_preflight.platform.release", lambda: "6.12.0-sova")
    monkeypatch.setattr("sova.worker.host_preflight.os.geteuid", lambda: 0, raising=False)

    def read_text(path: Path) -> str | None:
        normalized = str(path).replace("\\", "/")
        return next((value for key, value in values.items() if normalized.endswith(key)), None)

    monkeypatch.setattr("sova.worker.host_preflight._read_text", read_text)
    monkeypatch.setattr("sova.worker.host_preflight._root_controlled", lambda _path: True)
    monkeypatch.setattr("sova.worker.host_preflight._kvm_available", lambda: kvm)
    monkeypatch.setattr("sova.worker.host_preflight._egress_interface_exists", lambda _name: True)
    monkeypatch.setattr(
        "sova.worker.host_preflight._identity_ranges_unallocated", lambda *_args: True
    )
    monkeypatch.setattr(
        "sova.worker.host_preflight._permission_bits",
        lambda path: 0o711 if path.name == "network-state" else 0o700,
    )
    monkeypatch.setattr(
        "sova.worker.host_preflight._cpu_vulnerability_state", lambda: (True, "unsafe=none")
    )


def test_preflight_allows_live_matrix_but_never_production_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    firecracker, network = _policies(tmp_path)
    _host_mocks(monkeypatch)
    receipt = collect_worker_host_preflight(
        release_commit="a" * 40,
        measured_at="2026-08-28T12:00:00Z",
        attestation=worker_attestation(),
        firecracker_policy=firecracker,
        network_policy=network,
        identity_lease_directory=(tmp_path / "identity-leases").resolve(),
    )
    mapping = receipt.to_mapping()
    validate_document(mapping)
    assert receipt.ready_for_live_matrix is True
    assert mapping["status"] == "ready-for-live-matrix"
    assert mapping["failedRequiredChecks"] == []
    assert mapping["claims"]["productionIsolationClaimAllowed"] is False
    assert mapping["claims"]["exactHostMatrixPassed"] is False


def test_preflight_reports_every_failed_required_control(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    firecracker, network = _policies(tmp_path)
    _host_mocks(monkeypatch, kvm=False)
    receipt = collect_worker_host_preflight(
        release_commit="b" * 40,
        measured_at="2026-08-28T12:00:00Z",
        attestation=replace(worker_attestation(), dedicated_linux_host=False),
        firecracker_policy=firecracker,
        network_policy=network,
        identity_lease_directory=(tmp_path / "identity-leases").resolve(),
    )
    mapping = receipt.to_mapping()
    validate_document(mapping)
    assert receipt.ready_for_live_matrix is False
    assert set(mapping["failedRequiredChecks"]) >= {
        "dedicated-host-operator-assertion",
        "kvm-character-device-access",
        "attestation-host-controls-consistent",
    }


def test_preflight_does_not_treat_matching_false_path_checks_as_consistent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    firecracker, network = _policies(tmp_path)
    _host_mocks(monkeypatch)
    monkeypatch.setattr("sova.worker.host_preflight._root_controlled", lambda _path: False)
    receipt = collect_worker_host_preflight(
        release_commit="c" * 40,
        measured_at="2026-08-28T12:00:00Z",
        attestation=replace(worker_attestation(), host_paths_root_owned=False),
        firecracker_policy=firecracker,
        network_policy=network,
        identity_lease_directory=(tmp_path / "identity-leases").resolve(),
    )
    assert "root-controlled-host-paths" in receipt.to_mapping()["failedRequiredChecks"]
    assert "attestation-host-controls-consistent" in receipt.to_mapping()["failedRequiredChecks"]


def test_preflight_rejects_allocated_job_or_mediator_identity_ranges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    firecracker, network = _policies(tmp_path)
    _host_mocks(monkeypatch)
    calls = iter((False, False))
    monkeypatch.setattr(
        "sova.worker.host_preflight._identity_ranges_unallocated", lambda *_args: next(calls)
    )
    receipt = collect_worker_host_preflight(
        release_commit="d" * 40,
        measured_at="2026-08-28T12:00:00Z",
        attestation=worker_attestation(),
        firecracker_policy=firecracker,
        network_policy=network,
        identity_lease_directory=(tmp_path / "identity-leases").resolve(),
    )
    assert set(receipt.to_mapping()["failedRequiredChecks"]) >= {
        "job-identity-range-unallocated",
        "mediator-identity-range-unallocated",
    }


def test_preflight_file_and_swap_helpers_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    readable = tmp_path / "value"
    readable.write_text(" value \n", encoding="utf-8")
    assert _read_text(readable) == "value"
    assert _read_text(tmp_path / "missing") is None
    assert _permission_bits(readable) is not None
    assert _permission_bits(tmp_path / "missing") is None
    assert _root_controlled(Path("relative")) is False
    assert _root_controlled((tmp_path / "missing").resolve()) is False

    monkeypatch.setattr(
        "sova.worker.host_preflight._read_text",
        lambda _path: "Filename Type Size Used Priority",
    )
    assert _swap_disabled() == (True, "active-devices=0")
    monkeypatch.setattr(
        "sova.worker.host_preflight._read_text",
        lambda _path: "Filename Type Size Used Priority\n/swap file 1 0 -2",
    )
    assert _swap_disabled() == (False, "active-devices=1")
    monkeypatch.setattr("sova.worker.host_preflight._read_text", lambda _path: None)
    assert _swap_disabled() == (False, "unreadable")


def test_preflight_identity_range_parser_detects_user_and_group_collisions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def values(path: Path) -> str:
        if path.name == "passwd":
            return "root:x:0:0::/root:/bin/sh\nreserved:x:700001:700001::/:/bin/false"
        return "root:x:0:\nreserved:x:700001:"

    monkeypatch.setattr("sova.worker.host_preflight._read_text", values)
    assert _identity_ranges_unallocated(100_000, 600_000, 100_000, 600_000) is True
    assert _identity_ranges_unallocated(700_000, 1_200_000, 700_000, 1_200_000) is False
    monkeypatch.setattr("sova.worker.host_preflight._read_text", lambda _path: None)
    assert _identity_ranges_unallocated(1, 2, 1, 2) is False


def test_preflight_kvm_and_cpu_vulnerability_helpers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_kvm = SimpleNamespace(stat=lambda: SimpleNamespace(st_mode=stat.S_IFCHR))
    monkeypatch.setattr("sova.worker.host_preflight.Path", lambda _value: fake_kvm)
    monkeypatch.setattr("sova.worker.host_preflight.os.access", lambda *_args: True)
    assert _kvm_available() is True
    fake_kvm.stat = lambda: (_ for _ in ()).throw(OSError())
    assert _kvm_available() is False

    cpu = tmp_path / "cpu-vulnerabilities"
    cpu.mkdir()
    (cpu / "spectre_v1").write_text("Mitigation: usercopy barriers", encoding="utf-8")
    monkeypatch.setattr("sova.worker.host_preflight._CPU_VULNERABILITY_DIRECTORY", cpu)
    assert _cpu_vulnerability_state() == (True, "unsafe=none")
    (cpu / "meltdown").write_text("Vulnerable", encoding="utf-8")
    safe, evidence = _cpu_vulnerability_state()
    assert safe is False and "meltdown" in evidence
    monkeypatch.setattr(
        "sova.worker.host_preflight._CPU_VULNERABILITY_DIRECTORY", tmp_path / "missing"
    )
    assert _cpu_vulnerability_state() == (False, "unavailable")


def test_preflight_records_binary_measurement_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    firecracker, network = _policies(tmp_path)
    _host_mocks(monkeypatch)
    monkeypatch.setattr(
        "sova.worker.host_preflight._digest_file",
        lambda _path: (_ for _ in ()).throw(FormatError("TEST", "measurement failed")),
    )
    receipt = collect_worker_host_preflight(
        release_commit="e" * 40,
        measured_at="2026-08-28T12:00:00Z",
        attestation=worker_attestation(),
        firecracker_policy=firecracker,
        network_policy=network,
        identity_lease_directory=(tmp_path / "identity-leases").resolve(),
    )
    assert "binary-digests-pinned" in receipt.to_mapping()["failedRequiredChecks"]


def test_preflight_receipt_and_root_path_invariants(tmp_path: Path) -> None:
    value = tmp_path / "value"
    value.write_bytes(b"value")
    assert _digest_file(value) == digest("value")
    with pytest.raises(FormatError, match="regular file"):
        _digest_file(tmp_path / "missing")

    class _Node:
        def __init__(self, *, safe: bool) -> None:
            self.safe = safe
            self.parent = self
            self.parts = ("root",)

        def is_absolute(self) -> bool:
            return True

        def is_symlink(self) -> bool:
            return False

        def lstat(self) -> SimpleNamespace:
            return SimpleNamespace(st_uid=0, st_mode=0o700 if self.safe else 0o702)

    assert _root_controlled(_Node(safe=True)) is True  # type: ignore[arg-type]
    assert _root_controlled(_Node(safe=False)) is False  # type: ignore[arg-type]

    check = HostPreflightCheck(name="one", required=True, passed=True, evidence="evidence")
    receipt = WorkerHostPreflightReceipt(
        release_commit="a" * 40,
        worker_id="worker:test",
        measured_at="2026-08-28T12:00:00Z",
        attestation_digest=digest("attestation"),
        checks=(check,),
    )
    with pytest.raises(FormatError, match="commit"):
        replace(receipt, release_commit="bad")
    with pytest.raises(FormatError, match="time"):
        replace(receipt, measured_at="bad")
    with pytest.raises(FormatError, match="unique"):
        replace(receipt, checks=(check, check))


def test_cpu_vulnerability_helper_rejects_empty_status_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    empty = tmp_path / "empty-vulnerabilities"
    empty.mkdir()
    monkeypatch.setattr("sova.worker.host_preflight._CPU_VULNERABILITY_DIRECTORY", empty)
    assert _cpu_vulnerability_state() == (False, "no-vulnerability-status-files")
