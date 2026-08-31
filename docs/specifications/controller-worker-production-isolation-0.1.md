<!-- status: implementation-ready-external-validation-required -->

# Controller/worker production-isolation contract 0.1

## Scope

The Windows SOVA product is a controller. It may prepare authorization,
methodology, immutable inputs, and evidence reports, but it is not the hostile-
code isolation boundary. A production claim requires a dedicated patched Linux
host with KVM, cgroup v2, disabled swap, exact measured images/binaries, and an
independently reviewed Firecracker policy.

The checked-in implementation is runnable and testable at the contract layer on
Windows. It does not convert WSL2, Docker Desktop, a local process, or a self-
issued attestation into production-grade isolation.

## Authority and protocol

Each job uses an immutable `sova.worker-job-manifest` binding:

- target profile, authorization decision, methodology plan, and guest output key;
- content-addressed kernel, root filesystem, writable seed, and target inputs;
- exact network endpoints and initial DNS pins;
- scoped secret grants and output schema identifiers; and
- CPU, memory, process, file, disk, output, network, and time limits.

Controller and worker messages require TLS 1.3 with mutual certificate
verification. The application message is independently DSSE/Ed25519 signed,
binds the authenticated sender certificate digest, has a maximum five-minute
authority window, carries a unique nonce/message identifier, and passes a replay
cache. A transport payload digest binds the canonical manifest bytes.

The worker parses the manifest as hostile input, checks its schema and content
digest, verifies every referenced CAS object, evaluates worker readiness, and
only then compiles a launch plan. A manifest alone never authorizes execution.

## Content store

`ContentAddressedStore` addresses objects only as `sha256/<prefix>/<digest>`.
Names cannot become paths. Publishing is atomic, existing objects are verified,
links are rejected, reads are caller-bounded, and size plus digest are checked
before materialization. Production directories must be root-owned and unavailable
to the guest identity.

## Firecracker boundary

Protocol 0.1 pins Firecracker `1.16.1`. One exclusive host-allocated job UID/GID,
one distinct mediator UID/GID, and one microVM are used per hostile job. Both
numeric identities derive from disjoint policy-pinned bases plus the exclusively
leased slot. The compiler and lifecycle runner require:

- launch through `jailer`, cgroup v2, default seccomp level 2, a private network
  namespace, root-controlled chroot/CAS paths, and no host mounts;
- a read-only copied root filesystem and a separately copied disposable writable
  drive;
- MMIO devices only, PCI disabled, serial UART disabled, and no reusable guest
  state;
- explicit CPU, memory, PID, open-file, file-size, output, network, and watchdog
  limits; and
- a cleanup receipt covering the process, API socket, cgroup, namespace, chroot,
  writable layer, and secret broker.

The lifecycle implementation reconstructs the admitted plan before execution and
accepts no manifest-supplied host command. It validates the exact jailer argument
set, uses the official `<chroot-base>/firecracker/<vm-id>/root` layout, passes
cgroup values through repeated jailer `--cgroup` arguments, and forwards only the
jailed `/api.socket` path to Firecracker. The jailer supplies `--id` itself and
writes `/firecracker.pid`; SOVA does not invent or duplicate those arguments.
Kernel and disk copies are digest-verified and owned by the exclusive guest UID,
with read-only mode for the kernel/base disk and write permission only on the
disposable layer.

The root-only POSIX backend communicates through bounded HTTP/1.1 requests on the
exact Unix socket, requires `204` for every configuration call and final
`InstanceStart`, binds process control to a Linux pidfd, and invokes
`SendCtrlAltDel` before pidfd termination when the watchdog expires. Cleanup uses
the policy-pinned cgroup base and exact VM paths. Its versioned execution receipt
records the jailer start result, API request digests/statuses, observed PID,
watchdog state, process exit observation, and cleanup-receipt digest.
`process-exited` means only that the controller observed the VMM process exit; it
is not a guest-workload verdict or finding.

The checked-in lifecycle has not executed Firecracker on an exact dedicated host.
Its contract is therefore implementation-ready, not production-validated. The
exact jailer/VMM invocation, TAP/broker behavior, kernel behavior, containment,
and cleanup sequence must pass the P5-10 host suite before use.

## Network broker

The guest receives no ambient NAT. A broker authorizes one exact hostname, port,
protocol, pinned DNS set, and selected global address at a time. It rejects
loopback, link-local/metadata, reserved, multicast, and unspecified addresses;
an altered DNS set; unlisted endpoints; and exhausted connection, byte, or time
budgets. Private targets are denied by default and require an explicit rule tied
to the authorized target profile; loopback and link-local destinations cannot be
enabled. Allowed and denied attempts emit content-addressed flow receipts.

The executable host plane compiles one namespace per job. An isolated guest-side
TAP `/30` and a separate mediator-uplink `/30` are allocated deterministically
from `100.64.0.0/10` by the exclusive identity slot. The guest receives its exact
address and `http://<broker>:8888` through kernel boot arguments. It receives no
DNS resolver and no default path around that endpoint.

Inside the namespace, nftables drops all forwarding. Only the policy-pinned exact
per-job mediator UID may send through the uplink veth or return proxy traffic to the TAP.
The Firecracker job UID therefore cannot gain egress by creating a raw socket in
the shared namespace. Host nftables masquerades only the mediator `/32`, drops
access from the job veth to host services, and permits established return traffic.
The mediator runs through pinned `ip`, `nft`, and `setpriv` binaries, an exact
unprivileged UID/GID, `no_new_privs`, and a canonical per-job policy. It writes
only to a private per-job mediator-owned receipt directory below a search-only
root-owned state directory. After stopping the mediator, the controller requires canonical,
digest-valid, exact-job flow receipts with contiguous sequence numbers, binds their
set digest into the network-plane receipt, and then removes the state. The network
receipt records whether that state was removed; a false or missing result fails
cleanup. The lifecycle receipt binds the network-plan and network-plane-receipt
digests, and live admission rejects a missing or incomplete network receipt.

Protocol 0.1 supports mediated HTTP, HTTPS CONNECT, WebSocket, and MCP-over-HTTP.
It deliberately does not claim generic raw TCP/UDP support or transparent TLS
content inspection. Adding either requires a new reviewed protocol and mediator,
not a permissive firewall exception.

Identity and address slots are guarded by root-controlled, `O_EXCL` persistent
lease files. The worker reserves a slot before live prepare, releases it only after
complete process, namespace, chroot, writable-layer, secret, and network cleanup,
and deliberately retains a stale lease after crashes or incomplete evidence for
operator recovery. A controller-supplied integer alone never establishes UID/GID
exclusivity. Exact-host preflight also requires every configured job and mediator
UID/GID in the reserved ranges to be absent from the host passwd/group databases.

## Secret broker

Secrets are scalar broker-memory values, never files, sockets, browser profiles,
daemon access, image layers, or controller signing keys. An opaque capability is
bound to one declared grant, job, audience, expiry, class, and use count. Receipts
contain a digest and decision but never the value or capability. Revocation
overwrites mutable broker buffers on a best-effort basis; OS/runtime copies remain
a documented limitation, so short-lived upstream credentials are still required.

## Evidence extraction

The controller does not extract guest ZIPs into the host filesystem. It validates
them in memory and rejects traversal, Windows-path ambiguity, links/devices,
duplicate names, encryption, excess members, excess compressed/expanded size,
and abnormal compression ratios. It verifies the pre-bound guest output key,
canonical signed manifest, exact job, declared membership, artifact sizes and
digests, authorized schemas, and configured redaction values.

The controller creates and signs a new evidence report containing only facts it
verified. A guest verdict is never trusted, and a valid bundle never proves the
absence of vulnerabilities.

## Optional compatibility backends

Kata Containers stays disabled until an exact version and digest are selected,
the advisory snapshot is current with no unresolved applicable escape issue,
untrusted annotations and host mounts are disabled, and configuration paths are
root-owned. Even after admission it is an OCI compatibility lane.

gVisor is a lower-assurance user-space-kernel compatibility lane. It is not
described as a microVM or as equivalent to the primary hostile-code boundary.

## Required production evidence

P5 is not exited until the exact host kernel, microcode, Firecracker, jailer,
guest kernel, root filesystem, worker policy, and advisory snapshot are measured;
the host-preflight receipt is green; the positive control and all ten
malicious-guest cases pass on that host; every case binds live execution, network,
raw evidence, and complete cleanup receipts; and an independent isolation reviewer
approves the same digests. No self-attestation can satisfy the independent-review
field.
