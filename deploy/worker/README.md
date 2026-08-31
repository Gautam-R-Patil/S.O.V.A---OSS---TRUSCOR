# SOVA dedicated worker deployment boundary

This directory is a reviewable deployment input, not an automatic installer. Do not run
hostile jobs from the Windows checkout or assume WSL2 is the production worker.

Production provisioning must create a dedicated patched Linux/KVM host and then
replace every placeholder in `worker-policy.example.json` with an exact measured
digest. The worker operator must verify:

1. KVM read/write access is limited to the service identity and the host is not
   shared with another tenant.
2. cgroup v2 is active; swap is disabled; host kernel and microcode are current.
3. Firecracker and jailer are exactly version 1.16.1 and match approved digests.
4. CAS, chroot, network-namespace, cgroup-v2 mount, binary, kernel, policy, and image paths are
   root-owned and contain no symlink-controlled component.
5. Guest egress reaches only the exact-digest SOVA mediator; namespace forwarding
   is deny-all, host NAT matches only the mediator `/32`, and the guest has no DNS
   or ambient route.
6. UID/GID slots are allocated exclusively per active job and released only after
   complete cleanup and network receipts. Configure the root-owned `0700`
   persistent lease directory; stale leases require explicit operator recovery.
   Reserve the complete job and mediator UID/GID ranges exclusively for SOVA and
   leave them absent from the host passwd/group databases.
7. The exact-host positive and malicious-guest suites pass and their receipts bind
   every digest in the policy.
8. An independent isolation reviewer signs the final receipt.

Build the exact mediator source under `network-mediator/` on a reviewed Linux
builder, run its locked test/Clippy/RustSec gates, and install only the resulting
root-owned digest-pinned artifact. The source implementation does not make a
developer-host build production-approved; its README records the reproducible
musl build and Pipelock architectural provenance.

`provision-host.sh --check` is read-only. `--apply --ack-dedicated-host` creates
only root-controlled directories; it creates no user/group identity and does not
download binaries/images, change swap, patch a kernel, alter a firewall, or assert
dedication. Each leased slot derives a separate numeric job UID/GID and mediator
UID/GID from disjoint policy-pinned bases. Host preflight rejects any configured
range that overlaps an allocated passwd/group identity. The network-state parent
is root-owned `0711`, allowing only the exact per-job mediator identity to traverse
to its known immutable policy without listing or writing the parent; only its
private per-job receipt directory is writable.
Replace every placeholder, change status to
`configured-not-attested`, and run:

```text
python scripts/check_worker_host.py deploy/worker/worker-policy.json --release-commit <full-commit>
```

The command emits an attestation plus `sova.worker-host-preflight-receipt` and
never changes the host. A green result permits only the live matrix. After every
case has actually run, compile its captured observations with
`scripts/compile_p5_exact_host_receipt.py`; compilation does not run or sign a
case and cannot replace independent review.

The worker service may invoke the live backend only through
`WorkerAdmissionService.execute_admitted_job`; callers do not supply a launch
command. Provision the exact policy-pinned cgroup-v2 base (normally
`/sys/fs/cgroup`). `WorkerAdmissionService` compiles the job-owned namespace,
TAP, veth, nftables, and mediator plan during admission and refuses a live backend
that cannot prove the same plan digest or reserve its identity slot. The lifecycle
backend will stage digest-pinned
content, start the jailer without a shell or inherited credentials, configure the
VM over `/api.socket`, observe `/firecracker.pid` through a pidfd, enforce the
watchdog, validate and bind canonical mediator flow receipts, retain the identity
lease on incomplete cleanup/evidence, record successful state removal, and attempt
exact teardown. A `process-exited` receipt is lifecycle evidence only; guest success
and findings require separate verified evidence.

Until steps 1-8 are complete, configure the controller with nonproduction mode
only and do not advertise production-grade untrusted-agent isolation.
