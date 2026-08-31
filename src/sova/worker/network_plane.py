# SPDX-License-Identifier: Apache-2.0
"""Fail-closed Firecracker TAP, namespace, firewall, and mediator lifecycle."""

from __future__ import annotations

import hashlib
import os
import platform
import re
import signal
import stat
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, cast

from sova.formats import canonical_json_bytes, sha256_digest, strict_json_loads, validate_document
from sova.formats.errors import FormatError
from sova.worker.firecracker import FirecrackerLaunchPlan, worker_network_addresses

if TYPE_CHECKING:
    from sova.worker.contracts import WorkerJobManifest

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_INTERFACE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
_SAFE_NAMESPACE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
MINIMUM_MEDIATOR_IDENTITY_BASE = 700_000
MAXIMUM_MEDIATOR_IDENTITY_BASE = 1_500_000
MAXIMUM_NETWORK_IDENTITY_SLOT = 500_000
_DEFAULT_PROXY_PORT = 8_888
_COMMAND_TIMEOUT_SECONDS = 15
_MEDIATOR_START_SECONDS = 1.0
_HOST_RULE_TEARDOWNS = 2
_HOST_TEARDOWN_COMMANDS = 4
_MAX_MEDIATOR_RECEIPT_FILES = 2_048
_MAX_MEDIATOR_RECEIPT_BYTES = 16 * 1024 * 1024
_MAX_MEDIATED_CONNECTIONS = 1_024


def _validate_digest(value: str, role: str) -> None:
    if _DIGEST.fullmatch(value) is None:
        raise FormatError("SOVA-WORKER-NETWORK-DIGEST", f"{role} digest is invalid")


def _digest_file(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise FormatError("SOVA-WORKER-NETWORK-FILE", "network-plane input is not a file")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _validated_flow_receipt(payload: bytes, job_id: str) -> tuple[int, str]:
    value = strict_json_loads(payload, max_bytes=_MAX_MEDIATOR_RECEIPT_BYTES)
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise FormatError("SOVA-WORKER-NETWORK-RECEIPT", "flow receipt must be an object")
    validate_document(value, "sova.worker-network-receipt")
    if canonical_json_bytes(value) != payload:
        raise FormatError("SOVA-WORKER-NETWORK-RECEIPT", "flow receipt is not canonical JSON")
    unsigned = dict(value)
    claimed = unsigned.pop("contentDigest", None)
    if claimed != sha256_digest(canonical_json_bytes(unsigned)):
        raise FormatError("SOVA-WORKER-NETWORK-RECEIPT", "flow receipt digest is invalid")
    sequence = value.get("sequence")
    if value.get("jobId") != job_id or isinstance(sequence, bool) or not isinstance(sequence, int):
        raise FormatError("SOVA-WORKER-NETWORK-RECEIPT", "flow receipt binding is invalid")
    return sequence, str(claimed)


def _require_root_controlled(path: Path) -> None:
    current = path
    while True:
        if current.is_symlink() or not current.exists():
            raise FormatError(
                "SOVA-WORKER-NETWORK-PATH", "network-plane host path is missing or linked"
            )
        metadata = current.stat()
        if metadata.st_uid != 0 or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise FormatError(
                "SOVA-WORKER-NETWORK-PATH", "network-plane host path is not root controlled"
            )
        if current.parent == current:
            break
        current = current.parent


@dataclass(frozen=True, slots=True)
class NetworkPlaneHostPolicy:
    """Exact host utilities and mediator adapter admitted by the worker operator."""

    ip_binary: Path
    nft_binary: Path
    setpriv_binary: Path
    mediator_binary: Path
    state_directory: Path
    approved_ip_digest: str
    approved_nft_digest: str
    approved_setpriv_digest: str
    approved_mediator_digest: str
    egress_interface: str
    mediator_uid_base: int
    mediator_gid_base: int
    proxy_port: int = _DEFAULT_PROXY_PORT

    def __post_init__(self) -> None:
        for role, path in (
            ("ip", self.ip_binary),
            ("nft", self.nft_binary),
            ("setpriv", self.setpriv_binary),
            ("mediator", self.mediator_binary),
            ("state directory", self.state_directory),
        ):
            if not path.is_absolute() or ".." in path.parts:
                raise FormatError(
                    "SOVA-WORKER-NETWORK-PATH", f"{role} path must be absolute and normalized"
                )
        for role, digest in (
            ("ip", self.approved_ip_digest),
            ("nft", self.approved_nft_digest),
            ("setpriv", self.approved_setpriv_digest),
            ("mediator", self.approved_mediator_digest),
        ):
            _validate_digest(digest, role)
        if _INTERFACE.fullmatch(self.egress_interface) is None:
            raise FormatError("SOVA-WORKER-NETWORK-INTERFACE", "egress interface is invalid")
        if not (
            MINIMUM_MEDIATOR_IDENTITY_BASE
            <= self.mediator_uid_base
            <= MAXIMUM_MEDIATOR_IDENTITY_BASE
        ):
            raise FormatError("SOVA-WORKER-NETWORK-IDENTITY", "mediator UID base is invalid")
        if not (
            MINIMUM_MEDIATOR_IDENTITY_BASE
            <= self.mediator_gid_base
            <= MAXIMUM_MEDIATOR_IDENTITY_BASE
        ):
            raise FormatError("SOVA-WORKER-NETWORK-IDENTITY", "mediator GID base is invalid")
        if self.proxy_port != _DEFAULT_PROXY_PORT:
            raise FormatError(
                "SOVA-WORKER-NETWORK-PORT",
                "protocol 0.1 requires the guest-bound mediator port 8888",
            )


@dataclass(frozen=True, slots=True)
class NetworkCommand:
    """One compiler-owned command with optional bounded stdin and no shell."""

    argv: tuple[str, ...]
    stdin: str | None = None

    def to_mapping(self) -> dict[str, Any]:
        return {
            "argv": list(self.argv),
            "stdin": self.stdin,
            "stdinDigest": None if self.stdin is None else sha256_digest(self.stdin.encode()),
        }


@dataclass(frozen=True, slots=True)
class FirecrackerNetworkPlan:
    """Deterministic per-job broker-only network topology."""

    job_id: str
    vm_id: str
    manifest_digest: str
    launch_plan_digest: str
    enabled: bool
    namespace_name: str
    namespace_path: str
    tap_device: str | None
    root_veth: str | None
    namespace_veth: str | None
    guest_address: str | None
    broker_address: str | None
    root_uplink_address: str | None
    mediator_uplink_address: str | None
    proxy_port: int | None
    namespace_filter_table: str
    host_filter_table: str | None
    host_nat_table: str | None
    mediator_policy: dict[str, Any] | None
    mediator_policy_path: str | None
    mediator_receipt_directory: str | None
    mediator_uid: int | None
    mediator_gid: int | None
    setup_commands: tuple[NetworkCommand, ...]
    mediator_command: tuple[str, ...] | None
    teardown_commands: tuple[NetworkCommand, ...]

    def to_mapping(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "artifactType": "sova.firecracker-network-plan",
            "schemaVersion": "0.1.0",
            "jobId": self.job_id,
            "vmId": self.vm_id,
            "manifestDigest": self.manifest_digest,
            "launchPlanDigest": self.launch_plan_digest,
            "enabled": self.enabled,
            "namespace": {"name": self.namespace_name, "path": self.namespace_path},
            "devices": {
                "tap": self.tap_device,
                "rootVeth": self.root_veth,
                "namespaceVeth": self.namespace_veth,
            },
            "addresses": {
                "guest": self.guest_address,
                "broker": self.broker_address,
                "rootUplink": self.root_uplink_address,
                "mediatorUplink": self.mediator_uplink_address,
            },
            "proxyPort": self.proxy_port,
            "firewallTables": {
                "namespaceFilter": self.namespace_filter_table,
                "hostFilter": self.host_filter_table,
                "hostNat": self.host_nat_table,
            },
            "mediatorPolicy": self.mediator_policy,
            "mediatorPolicyPath": self.mediator_policy_path,
            "mediatorReceiptDirectory": self.mediator_receipt_directory,
            "mediatorIdentity": (
                None
                if self.mediator_uid is None or self.mediator_gid is None
                else {
                    "uid": self.mediator_uid,
                    "gid": self.mediator_gid,
                    "uniquePerJob": True,
                }
            ),
            "setupCommands": [item.to_mapping() for item in self.setup_commands],
            "mediatorCommand": (
                None if self.mediator_command is None else list(self.mediator_command)
            ),
            "teardownCommands": [item.to_mapping() for item in self.teardown_commands],
            "invariants": {
                "ambientGuestNatAllowed": False,
                "guestForwardingAllowed": False,
                "guestDnsAllowed": False,
                "mediatorOnlyEgress": True,
                "rawTcpUdpSupported": False,
                "shellCommandsAllowed": False,
            },
        }
        body["contentDigest"] = sha256_digest(canonical_json_bytes(body))
        return body

    @property
    def digest(self) -> str:
        return cast("str", self.to_mapping()["contentDigest"])


@dataclass(frozen=True, slots=True)
class NetworkPlaneReceipt:
    job_id: str
    vm_id: str
    plan_digest: str
    completed_at: str
    enabled: bool
    namespace_created: bool
    firewall_loaded: bool
    mediator_started: bool
    mediator_process_id: int | None
    mediator_receipt_set_digest: str | None
    mediator_terminated: bool
    host_rules_removed: bool
    root_veth_removed: bool
    namespace_removed: bool
    state_removed: bool
    failure_code: str | None

    @property
    def complete(self) -> bool:
        prepared = self.namespace_created and self.firewall_loaded
        mediated = not self.enabled or self.mediator_started
        captured = not self.enabled or self.mediator_receipt_set_digest is not None
        return (
            prepared
            and mediated
            and captured
            and self.cleanup_complete
            and self.failure_code is None
        )

    @property
    def cleanup_complete(self) -> bool:
        return (
            self.mediator_terminated
            and self.host_rules_removed
            and self.root_veth_removed
            and self.namespace_removed
            and self.state_removed
        )

    def to_mapping(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "artifactType": "sova.worker-network-plane-receipt",
            "schemaVersion": "0.1.0",
            "jobId": self.job_id,
            "vmId": self.vm_id,
            "planDigest": self.plan_digest,
            "completedAt": self.completed_at,
            "enabled": self.enabled,
            "preparation": {
                "namespaceCreated": self.namespace_created,
                "firewallLoaded": self.firewall_loaded,
                "mediatorStarted": self.mediator_started,
                "mediatorProcessId": self.mediator_process_id,
                "mediatorReceiptSetDigest": self.mediator_receipt_set_digest,
            },
            "cleanup": {
                "mediatorTerminated": self.mediator_terminated,
                "hostRulesRemoved": self.host_rules_removed,
                "rootVethRemoved": self.root_veth_removed,
                "namespaceRemoved": self.namespace_removed,
                "stateRemoved": self.state_removed,
            },
            "failureCode": self.failure_code,
            "status": "complete" if self.complete else "failed",
            "claims": {
                "liveHostObserved": True,
                "productionIsolationClaimAllowed": False,
                "escapeImpossible": False,
            },
        }
        body["contentDigest"] = sha256_digest(canonical_json_bytes(body))
        return body


def _mediator_policy(
    manifest: WorkerJobManifest,
    launch_plan: FirecrackerLaunchPlan,
    broker_address: str,
    proxy_port: int,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "artifactType": "sova.worker-network-mediator-policy",
        "schemaVersion": "0.1.0",
        "jobId": manifest.job_id,
        "manifestDigest": manifest.digest,
        "launchPlanDigest": launch_plan.to_mapping()["contentDigest"],
        "listen": {"address": broker_address, "port": proxy_port},
        "allowedTransports": ["http", "https-connect", "websocket", "mcp-http"],
        "rules": [item.to_mapping() for item in manifest.network_rules],
        "budgets": {
            "maximumConnections": manifest.limits.network_connection_limit,
            "maximumBytes": manifest.limits.network_bytes,
            "expiresAt": manifest.expires_at,
        },
        "receiptArtifactType": "sova.worker-network-receipt",
        "invariants": {
            "dnsResolvedByMediator": True,
            "dnsPinsRevalidated": True,
            "selectedAddressBoundToConnection": True,
            "privateAddressesDefaultDenied": True,
            "rawTcpUdpSupported": False,
        },
    }
    body["contentDigest"] = sha256_digest(canonical_json_bytes(body))
    validate_document(body, "sova.worker-network-mediator-policy")
    return body


def _network_tap(launch_plan: FirecrackerLaunchPlan) -> str | None:
    matches = [
        payload.get("host_dev_name")
        for path, payload in launch_plan.firecracker_api_requests
        if path == "/network-interfaces/eth0"
    ]
    if not matches:
        return None
    if len(matches) != 1 or not isinstance(matches[0], str):
        raise FormatError("SOVA-WORKER-NETWORK-DEVICE", "launch plan network device is invalid")
    if _INTERFACE.fullmatch(matches[0]) is None:
        raise FormatError("SOVA-WORKER-NETWORK-DEVICE", "TAP name violates Linux IFNAMSIZ")
    return matches[0]


def build_firecracker_network_plan(
    manifest: WorkerJobManifest,
    launch_plan: FirecrackerLaunchPlan,
    policy: NetworkPlaneHostPolicy,
) -> FirecrackerNetworkPlan:
    """Compile manifest authority into a mediator-only per-job topology."""
    if manifest.digest != launch_plan.manifest_digest or manifest.job_id != launch_plan.job_id:
        raise FormatError("SOVA-WORKER-NETWORK-BINDING", "network inputs bind different jobs")
    namespace = Path(launch_plan.network_namespace)
    namespace_name = namespace.name
    if _SAFE_NAMESPACE.fullmatch(namespace_name) is None or namespace.parent == namespace:
        raise FormatError("SOVA-WORKER-NETWORK-NAMESPACE", "namespace name is invalid")
    token = manifest.digest[7:18]
    namespace_table = f"sn_{token[:10]}"
    tap = _network_tap(launch_plan)
    ip = str(policy.ip_binary)
    nft = str(policy.nft_binary)
    setup: list[NetworkCommand] = [NetworkCommand((ip, "netns", "add", namespace_name))]
    teardown: list[NetworkCommand] = []
    if tap is None:
        namespace_rules = (
            f"table inet {namespace_table} {{ chain input {{ type filter hook input priority 0; "
            'policy drop; iifname "lo" accept; }} chain forward { type filter hook forward '
            "priority 0; policy drop; } chain output { type filter hook output priority 0; "
            'policy drop; oifname "lo" accept; } }'
        )
        setup.extend(
            (
                NetworkCommand(
                    (ip, "netns", "exec", namespace_name, ip, "link", "set", "lo", "up")
                ),
                NetworkCommand(
                    (ip, "netns", "exec", namespace_name, nft, "-f", "-"),
                    namespace_rules,
                ),
            )
        )
        teardown.append(NetworkCommand((ip, "netns", "delete", namespace_name)))
        return FirecrackerNetworkPlan(
            job_id=manifest.job_id,
            vm_id=launch_plan.vm_id,
            manifest_digest=manifest.digest,
            launch_plan_digest=launch_plan.to_mapping()["contentDigest"],
            enabled=False,
            namespace_name=namespace_name,
            namespace_path=str(namespace),
            tap_device=None,
            root_veth=None,
            namespace_veth=None,
            guest_address=None,
            broker_address=None,
            root_uplink_address=None,
            mediator_uplink_address=None,
            proxy_port=None,
            namespace_filter_table=namespace_table,
            host_filter_table=None,
            host_nat_table=None,
            mediator_policy=None,
            mediator_policy_path=None,
            mediator_receipt_directory=None,
            mediator_uid=None,
            mediator_gid=None,
            setup_commands=tuple(setup),
            mediator_command=None,
            teardown_commands=tuple(teardown),
        )

    guest_cidr, broker_cidr, root_uplink_cidr, mediator_uplink_cidr = worker_network_addresses(
        launch_plan.identity_slot
    )
    guest = guest_cidr.removesuffix("/30")
    broker = broker_cidr.removesuffix("/30")
    root_uplink = root_uplink_cidr.removesuffix("/30")
    mediator_uplink = mediator_uplink_cidr.removesuffix("/30")
    root_veth = f"svr-{token[:10]}"
    namespace_veth = f"svn-{token[:10]}"
    host_filter = f"sh_{token[:10]}"
    host_nat = f"st_{token[:10]}"
    state = policy.state_directory / launch_plan.vm_id
    policy_path = state / "mediator-policy.json"
    receipt_directory = state / "receipts"
    if not 0 <= launch_plan.identity_slot <= MAXIMUM_NETWORK_IDENTITY_SLOT:
        raise FormatError("SOVA-WORKER-NETWORK-IDENTITY", "mediator identity slot is invalid")
    mediator_uid = policy.mediator_uid_base + launch_plan.identity_slot
    mediator_gid = policy.mediator_gid_base + launch_plan.identity_slot
    if any(rule.protocol != "tcp" for rule in manifest.network_rules):
        raise FormatError(
            "SOVA-WORKER-NETWORK-PROTOCOL",
            "protocol 0.1 mediator supports HTTP-family traffic over TCP only",
        )
    if manifest.limits.network_connection_limit > _MAX_MEDIATED_CONNECTIONS:
        raise FormatError(
            "SOVA-WORKER-NETWORK-BUDGET",
            "network connection budget exceeds protocol 0.1 evidence limits",
        )
    mediator_policy = _mediator_policy(manifest, launch_plan, broker, policy.proxy_port)
    namespace_rules = (
        f"table inet {namespace_table} {{ "
        "chain input { type filter hook input priority 0; policy drop; "
        'iifname "lo" accept; ct state established,related accept; '
        f'iifname "{tap}" ip daddr {broker} tcp dport {policy.proxy_port} accept; }} '
        "chain forward { type filter hook forward priority 0; policy drop; } "
        "chain output { type filter hook output priority 0; policy drop; "
        'oifname "lo" accept; '
        f'meta skuid {mediator_uid} oifname "{namespace_veth}" accept; '
        f'meta skuid {mediator_uid} oifname "{tap}" ip daddr {guest} '
        f"tcp sport {policy.proxy_port} accept; }} }}"
    )
    host_rules = (
        f"table inet {host_filter} {{ "
        "chain input { type filter hook input priority -10; policy accept; "
        f'iifname "{root_veth}" drop; }} '
        "chain forward { type filter hook forward priority -10; policy accept; "
        f'iifname "{root_veth}" oifname "{policy.egress_interface}" accept; '
        f'iifname "{policy.egress_interface}" oifname "{root_veth}" '
        "ct state established,related accept; "
        f'iifname "{root_veth}" drop; oifname "{root_veth}" drop; }} }} '
        f"table ip {host_nat} {{ chain postrouting {{ type nat hook postrouting priority srcnat; "
        f'policy accept; ip saddr {mediator_uplink} oifname "{policy.egress_interface}" '
        "masquerade; } }"
    )
    setup.extend(
        (
            NetworkCommand(
                (ip, "link", "add", root_veth, "type", "veth", "peer", "name", namespace_veth)
            ),
            NetworkCommand((ip, "link", "set", namespace_veth, "netns", namespace_name)),
            NetworkCommand((ip, "address", "add", f"{root_uplink}/30", "dev", root_veth)),
            NetworkCommand((ip, "link", "set", root_veth, "up")),
            NetworkCommand((ip, "netns", "exec", namespace_name, ip, "link", "set", "lo", "up")),
            NetworkCommand(
                (
                    ip,
                    "netns",
                    "exec",
                    namespace_name,
                    ip,
                    "tuntap",
                    "add",
                    "dev",
                    tap,
                    "mode",
                    "tap",
                    "user",
                    str(launch_plan.uid),
                    "group",
                    str(launch_plan.gid),
                )
            ),
            NetworkCommand(
                (
                    ip,
                    "netns",
                    "exec",
                    namespace_name,
                    ip,
                    "address",
                    "add",
                    f"{broker}/30",
                    "dev",
                    tap,
                )
            ),
            NetworkCommand((ip, "netns", "exec", namespace_name, ip, "link", "set", tap, "up")),
            NetworkCommand(
                (
                    ip,
                    "netns",
                    "exec",
                    namespace_name,
                    ip,
                    "address",
                    "add",
                    f"{mediator_uplink}/30",
                    "dev",
                    namespace_veth,
                )
            ),
            NetworkCommand(
                (
                    ip,
                    "netns",
                    "exec",
                    namespace_name,
                    ip,
                    "link",
                    "set",
                    namespace_veth,
                    "up",
                )
            ),
            NetworkCommand(
                (
                    ip,
                    "netns",
                    "exec",
                    namespace_name,
                    ip,
                    "route",
                    "add",
                    "default",
                    "via",
                    root_uplink,
                    "dev",
                    namespace_veth,
                )
            ),
            NetworkCommand((ip, "netns", "exec", namespace_name, nft, "-f", "-"), namespace_rules),
            NetworkCommand((nft, "-f", "-"), host_rules),
        )
    )
    mediator_command = (
        ip,
        "netns",
        "exec",
        namespace_name,
        str(policy.setpriv_binary),
        "--reuid",
        str(mediator_uid),
        "--regid",
        str(mediator_gid),
        "--clear-groups",
        "--no-new-privs",
        str(policy.mediator_binary),
        "--policy-file",
        str(policy_path),
        "--listen",
        f"{broker}:{policy.proxy_port}",
        "--receipt-directory",
        str(receipt_directory),
    )
    teardown.extend(
        (
            NetworkCommand((nft, "delete", "table", "inet", host_filter)),
            NetworkCommand((nft, "delete", "table", "ip", host_nat)),
            NetworkCommand((ip, "link", "delete", root_veth)),
            NetworkCommand((ip, "netns", "delete", namespace_name)),
        )
    )
    return FirecrackerNetworkPlan(
        job_id=manifest.job_id,
        vm_id=launch_plan.vm_id,
        manifest_digest=manifest.digest,
        launch_plan_digest=launch_plan.to_mapping()["contentDigest"],
        enabled=True,
        namespace_name=namespace_name,
        namespace_path=str(namespace),
        tap_device=tap,
        root_veth=root_veth,
        namespace_veth=namespace_veth,
        guest_address=guest_cidr,
        broker_address=broker_cidr,
        root_uplink_address=root_uplink_cidr,
        mediator_uplink_address=mediator_uplink_cidr,
        proxy_port=policy.proxy_port,
        namespace_filter_table=namespace_table,
        host_filter_table=host_filter,
        host_nat_table=host_nat,
        mediator_policy=mediator_policy,
        mediator_policy_path=str(policy_path),
        mediator_receipt_directory=str(receipt_directory),
        mediator_uid=mediator_uid,
        mediator_gid=mediator_gid,
        setup_commands=tuple(setup),
        mediator_command=mediator_command,
        teardown_commands=tuple(teardown),
    )


class NetworkProcess(Protocol):
    pid: int

    def poll(self) -> int | None: ...

    def terminate(self) -> None: ...

    def kill(self) -> None: ...

    def wait(self, timeout: float | None = None) -> int: ...


class NetworkCommandBackend(Protocol):
    def run(self, command: NetworkCommand) -> int: ...

    def spawn(self, argv: tuple[str, ...]) -> NetworkProcess: ...


class PosixNetworkCommandBackend:
    """Exact-argv subprocess boundary used only on the dedicated Linux worker."""

    def run(self, command: NetworkCommand) -> int:
        if command.stdin is None:
            completed = subprocess.run(  # noqa: S603 - compiler-owned absolute argv
                list(command.argv),
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env={"LANG": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
                timeout=_COMMAND_TIMEOUT_SECONDS,
            )
        else:
            completed = subprocess.run(  # noqa: S603 - compiler-owned absolute argv
                list(command.argv),
                input=command.stdin.encode(),
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env={"LANG": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
                timeout=_COMMAND_TIMEOUT_SECONDS,
            )
        return completed.returncode

    def spawn(self, argv: tuple[str, ...]) -> NetworkProcess:
        return cast(
            "NetworkProcess",
            subprocess.Popen(  # noqa: S603 - compiler-owned absolute argv
                list(argv),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                start_new_session=True,
                env={"LANG": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
            ),
        )


@dataclass(slots=True)
class FirecrackerNetworkPlaneBackend:
    """Prepare and tear down one exact network plan, retaining an evidence receipt."""

    policy: NetworkPlaneHostPolicy
    plan: FirecrackerNetworkPlan
    commands: NetworkCommandBackend = field(default_factory=PosixNetworkCommandBackend)
    _mediator: NetworkProcess | None = field(default=None, init=False)
    _state_created: bool = field(default=False, init=False)
    _namespace_created: bool = field(default=False, init=False)
    _root_veth_created: bool = field(default=False, init=False)
    _host_rules_loaded: bool = field(default=False, init=False)
    _firewall_loaded: bool = field(default=False, init=False)
    _receipt: NetworkPlaneReceipt | None = field(default=None, init=False)

    @staticmethod
    def _require_host() -> None:
        geteuid = cast("Any", getattr(os, "geteuid", None))
        if platform.system() != "Linux" or geteuid is None or geteuid() != 0:
            raise FormatError("SOVA-WORKER-NETWORK-HOST", "network plane requires Linux root")

    def _validate_host(self) -> None:
        for binary, expected in (
            (self.policy.ip_binary, self.policy.approved_ip_digest),
            (self.policy.nft_binary, self.policy.approved_nft_digest),
            (self.policy.setpriv_binary, self.policy.approved_setpriv_digest),
            (self.policy.mediator_binary, self.policy.approved_mediator_digest),
        ):
            _require_root_controlled(binary)
            if _digest_file(binary) != expected:
                raise FormatError(
                    "SOVA-WORKER-NETWORK-DIGEST", "network-plane binary digest drifted"
                )
        _require_root_controlled(self.policy.state_directory)

    def _bind(self, launch_plan: FirecrackerLaunchPlan) -> None:
        if (
            self.plan.vm_id != launch_plan.vm_id
            or self.plan.job_id != launch_plan.job_id
            or self.plan.launch_plan_digest != launch_plan.to_mapping()["contentDigest"]
            or self.plan.namespace_path != launch_plan.network_namespace
        ):
            raise FormatError("SOVA-WORKER-NETWORK-BINDING", "network plan drifted from launch")

    def _write_mediator_policy(self, state: Path) -> None:
        if self.plan.mediator_policy is None:
            return
        policy_path = Path(cast("str", self.plan.mediator_policy_path))
        if policy_path.parent != state:
            raise FormatError(
                "SOVA-WORKER-NETWORK-STATE", "mediator policy path is outside job state"
            )
        payload = canonical_json_bytes(self.plan.mediator_policy)
        policy_path.write_bytes(payload)
        # The policy contains endpoint rules and digests, never credentials. The
        # mediator drops privilege before opening it, so it must remain readable
        # while still being root-owned and immutable to the mediator identity.
        policy_path.chmod(0o444)

    def _prepare_receipt_directory(self, state: Path) -> None:
        if self.plan.mediator_receipt_directory is None:
            return
        receipt_directory = Path(self.plan.mediator_receipt_directory)
        if receipt_directory.parent != state:
            raise FormatError(
                "SOVA-WORKER-NETWORK-STATE", "mediator receipt path is outside job state"
            )
        chown = cast("Any", getattr(os, "chown", None))
        if chown is None:
            raise FormatError("SOVA-WORKER-NETWORK-HOST", "POSIX ownership control is required")
        if self.plan.mediator_uid is None or self.plan.mediator_gid is None:
            raise FormatError("SOVA-WORKER-NETWORK-IDENTITY", "mediator identity is missing")
        receipt_directory.mkdir(mode=0o700)
        receipt_directory.chmod(0o700)
        chown(receipt_directory, self.plan.mediator_uid, self.plan.mediator_gid)

    def _run_setup_commands(self) -> None:
        for index, command in enumerate(self.plan.setup_commands):
            if self.commands.run(command) != 0:
                raise FormatError(
                    "SOVA-WORKER-NETWORK-SETUP", f"network setup command {index} failed"
                )
            if index == 0:
                self._namespace_created = True
            if self.plan.enabled and index == 1:
                self._root_veth_created = True
            if self.plan.enabled and index == len(self.plan.setup_commands) - 1:
                self._host_rules_loaded = True
        self._firewall_loaded = True

    def _start_mediator(self) -> None:
        if self.plan.mediator_command is None:
            return
        self._mediator = self.commands.spawn(self.plan.mediator_command)
        deadline = time.monotonic() + _MEDIATOR_START_SECONDS
        while time.monotonic() < deadline:
            if self._mediator.poll() is not None:
                raise FormatError(
                    "SOVA-WORKER-NETWORK-MEDIATOR", "network mediator exited at startup"
                )
            time.sleep(0.02)

    def prepare(self, launch_plan: FirecrackerLaunchPlan) -> None:
        self._require_host()
        self._bind(launch_plan)
        self._validate_host()
        state = self.policy.state_directory / launch_plan.vm_id
        if state.exists() or state.is_symlink():
            raise FormatError("SOVA-WORKER-NETWORK-STATE", "job network state already exists")
        # Root owns this directory; execute/search permission lets the unprivileged
        # mediator open the immutable policy and its private receipt subdirectory.
        state.mkdir(mode=0o755)
        state.chmod(0o755)
        self._state_created = True
        self._write_mediator_policy(state)
        self._prepare_receipt_directory(state)
        self._run_setup_commands()
        self._start_mediator()

    def _stop_mediator(self) -> bool:
        if self._mediator is None:
            return True
        if self._mediator.poll() is not None:
            return True
        killpg = cast("Any", getattr(os, "killpg", None))
        try:
            if callable(killpg):
                killpg(self._mediator.pid, signal.SIGTERM)
            else:
                self._mediator.terminate()
        except OSError:
            return self._mediator.poll() is not None
        try:
            self._mediator.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            try:
                if callable(killpg):
                    killpg(self._mediator.pid, getattr(signal, "SIGKILL", 9))
                else:
                    self._mediator.kill()
            except OSError:
                return self._mediator.poll() is not None
            try:
                self._mediator.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                return False
        return self._mediator.poll() is not None

    def _capture_mediator_receipts(self, state: Path) -> str | None:
        if self.plan.mediator_receipt_directory is None:
            return None
        receipt_directory = Path(self.plan.mediator_receipt_directory)
        if receipt_directory.parent != state or receipt_directory.is_symlink():
            raise FormatError("SOVA-WORKER-NETWORK-RECEIPT", "receipt directory drifted")
        if not receipt_directory.is_dir():
            raise FormatError("SOVA-WORKER-NETWORK-RECEIPT", "receipt directory is missing")
        entries: list[dict[str, Any]] = []
        sequences: list[int] = []
        total_bytes = 0
        ordered = sorted(receipt_directory.iterdir(), key=lambda item: item.name)
        for index, child in enumerate(ordered):
            if index >= _MAX_MEDIATOR_RECEIPT_FILES:
                raise FormatError("SOVA-WORKER-NETWORK-RECEIPT", "too many mediator receipts")
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(child, flags)
            try:
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise FormatError(
                        "SOVA-WORKER-NETWORK-RECEIPT",
                        "mediator receipt is not a single-link file",
                    )
                if metadata.st_uid != self.plan.mediator_uid:
                    raise FormatError(
                        "SOVA-WORKER-NETWORK-RECEIPT", "mediator receipt owner drifted"
                    )
                with os.fdopen(descriptor, "rb", closefd=False) as stream:
                    payload = stream.read(_MAX_MEDIATOR_RECEIPT_BYTES + 1)
            finally:
                os.close(descriptor)
            if len(payload) != metadata.st_size:
                raise FormatError("SOVA-WORKER-NETWORK-RECEIPT", "flow receipt size drifted")
            total_bytes += len(payload)
            if total_bytes > _MAX_MEDIATOR_RECEIPT_BYTES:
                raise FormatError("SOVA-WORKER-NETWORK-RECEIPT", "mediator receipts exceed budget")
            sequence, content_digest = _validated_flow_receipt(payload, self.plan.job_id)
            if child.name != f"{sequence:06d}.json":
                raise FormatError("SOVA-WORKER-NETWORK-RECEIPT", "flow receipt filename drifted")
            sequences.append(sequence)
            entries.append(
                {
                    "name": child.name,
                    "sequence": sequence,
                    "size": len(payload),
                    "contentDigest": content_digest,
                    "fileDigest": sha256_digest(payload),
                }
            )
        if sequences != list(range(1, len(sequences) + 1)):
            raise FormatError("SOVA-WORKER-NETWORK-RECEIPT", "flow receipt sequence is incomplete")
        return sha256_digest(canonical_json_bytes({"files": entries}))

    def _remove_state(self, state: Path) -> bool:
        if not self._state_created or not state.exists() or state.is_symlink():
            return not state.exists()
        receipt_directory = (
            None
            if self.plan.mediator_receipt_directory is None
            else Path(self.plan.mediator_receipt_directory)
        )
        if receipt_directory is not None and receipt_directory.exists():
            if receipt_directory.is_symlink() or receipt_directory.parent != state:
                raise FormatError("SOVA-WORKER-NETWORK-STATE", "receipt directory drifted")
            receipt_entries = list(receipt_directory.iterdir())
            if len(receipt_entries) > _MAX_MEDIATOR_RECEIPT_FILES:
                return False
            for child in receipt_entries:
                if child.is_symlink() or not child.is_file():
                    raise FormatError("SOVA-WORKER-NETWORK-STATE", "receipt entry drifted")
                child.chmod(0o600)
                child.unlink()
            receipt_directory.chmod(0o700)
            receipt_directory.rmdir()
        for child in state.iterdir():
            if child.is_symlink() or not child.is_file():
                raise FormatError("SOVA-WORKER-NETWORK-STATE", "job state entry drifted")
            child.chmod(0o600)
            child.unlink()
        state.rmdir()
        return not state.exists()

    def _run_cleanup_command(self, command: NetworkCommand) -> bool:
        try:
            return self.commands.run(command) == 0
        except Exception:  # noqa: BLE001 - every remaining teardown must still be attempted
            return False

    def _cleanup_resources(
        self, launch_plan: FirecrackerLaunchPlan
    ) -> tuple[bool, bool, bool, bool, bool, str | None]:
        self._bind(launch_plan)
        mediator_terminated = self._stop_mediator()
        state = self.policy.state_directory / launch_plan.vm_id
        try:
            receipt_set_digest = (
                self._capture_mediator_receipts(state) if self.plan.enabled else None
            )
        except (FormatError, OSError):
            # Evidence collection is fail-closed but must never prevent teardown.
            receipt_set_digest = None
        if self.plan.enabled:
            if len(self.plan.teardown_commands) != _HOST_TEARDOWN_COMMANDS:
                raise FormatError("SOVA-WORKER-NETWORK-CLEANUP", "teardown plan is incomplete")
            host_rule_results = (
                [
                    self._run_cleanup_command(command)
                    for command in self.plan.teardown_commands[:_HOST_RULE_TEARDOWNS]
                ]
                if self._host_rules_loaded
                else [True, True]
            )
            host_rules_removed = all(host_rule_results)
            root_veth_removed = (
                self._run_cleanup_command(self.plan.teardown_commands[2])
                if self._root_veth_created
                else True
            )
            namespace_removed = (
                self._run_cleanup_command(self.plan.teardown_commands[3])
                if self._namespace_created
                else True
            )
        else:
            host_rules_removed = True
            root_veth_removed = True
            namespace_removed = (
                self._run_cleanup_command(self.plan.teardown_commands[0])
                if self._namespace_created and self.plan.teardown_commands
                else True
            )
        try:
            state_removed = self._remove_state(state)
        except (FormatError, OSError):
            state_removed = False
        return (
            mediator_terminated,
            host_rules_removed,
            root_veth_removed,
            namespace_removed,
            state_removed,
            receipt_set_digest,
        )

    def cleanup(
        self, launch_plan: FirecrackerLaunchPlan, *, completed_at: str
    ) -> NetworkPlaneReceipt:
        mediator_pid = None if self._mediator is None else self._mediator.pid
        mediator_started = self._mediator is not None and self._mediator.poll() is None
        failure: str | None = None
        try:
            (
                terminated,
                rules_removed,
                veth_removed,
                namespace_removed,
                state_removed,
                receipt_digest,
            ) = self._cleanup_resources(launch_plan)
        except (FormatError, OSError, subprocess.SubprocessError):
            terminated = rules_removed = veth_removed = namespace_removed = state_removed = False
            receipt_digest = None
            failure = "SOVA-WORKER-NETWORK-CLEANUP"
        if not all((terminated, rules_removed, veth_removed, namespace_removed, state_removed)):
            failure = failure or "SOVA-WORKER-NETWORK-CLEANUP-INCOMPLETE"
        elif not self._firewall_loaded:
            failure = "SOVA-WORKER-NETWORK-PREPARATION-INCOMPLETE"
        elif self.plan.enabled and not mediator_started:
            failure = "SOVA-WORKER-NETWORK-MEDIATOR-EXITED"
        elif self.plan.enabled and receipt_digest is None:
            failure = "SOVA-WORKER-NETWORK-RECEIPT-MISSING"
        receipt = NetworkPlaneReceipt(
            job_id=launch_plan.job_id,
            vm_id=launch_plan.vm_id,
            plan_digest=self.plan.digest,
            completed_at=completed_at,
            enabled=self.plan.enabled,
            namespace_created=self._namespace_created,
            firewall_loaded=self._firewall_loaded,
            mediator_started=mediator_started,
            mediator_process_id=mediator_pid,
            mediator_receipt_set_digest=receipt_digest,
            mediator_terminated=terminated,
            host_rules_removed=rules_removed,
            root_veth_removed=veth_removed,
            namespace_removed=namespace_removed,
            state_removed=state_removed,
            failure_code=failure,
        )
        self._receipt = receipt
        return receipt

    def evidence(self, launch_plan: FirecrackerLaunchPlan) -> tuple[str, str | None]:
        self._bind(launch_plan)
        receipt_digest = (
            None
            if self._receipt is None
            else cast("str", self._receipt.to_mapping()["contentDigest"])
        )
        return self.plan.digest, receipt_digest

    def receipt(self, launch_plan: FirecrackerLaunchPlan) -> NetworkPlaneReceipt | None:
        self._bind(launch_plan)
        return self._receipt


__all__ = [
    "MAXIMUM_MEDIATOR_IDENTITY_BASE",
    "MAXIMUM_NETWORK_IDENTITY_SLOT",
    "MINIMUM_MEDIATOR_IDENTITY_BASE",
    "FirecrackerNetworkPlan",
    "FirecrackerNetworkPlaneBackend",
    "NetworkCommand",
    "NetworkCommandBackend",
    "NetworkPlaneHostPolicy",
    "NetworkPlaneReceipt",
    "PosixNetworkCommandBackend",
    "build_firecracker_network_plan",
]
