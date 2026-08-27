# SOVA dedicated worker deployment boundary

This directory is a reviewable deployment input, not an installer. Do not run
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
5. Guest egress reaches only the SOVA broker; the host firewall supplies no
   ambient NAT route.
6. UID/GID slots are allocated exclusively per active job and released only after
   the complete cleanup receipt.
7. The exact-host positive and malicious-guest suites pass and their receipts bind
   every digest in the policy.
8. An independent isolation reviewer signs the final receipt.

The worker service may invoke the live backend only through
`WorkerAdmissionService.execute_admitted_job`; callers do not supply a launch
command. Provision the exact policy-pinned cgroup-v2 base (normally
`/sys/fs/cgroup`), one job-owned network namespace and TAP device, and a broker-only
egress path before admission. The lifecycle backend will stage digest-pinned
content, start the jailer without a shell or inherited credentials, configure the
VM over `/api.socket`, observe `/firecracker.pid` through a pidfd, enforce the
watchdog, and attempt exact teardown. A `process-exited` receipt is lifecycle
evidence only; guest success and findings require separate verified evidence.

Until steps 1-8 are complete, configure the controller with nonproduction mode
only and do not advertise production-grade untrusted-agent isolation.
