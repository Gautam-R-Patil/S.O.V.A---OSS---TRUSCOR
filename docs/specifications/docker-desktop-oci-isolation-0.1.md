<!-- status: experimental-implemented-bounded -->

# VM-hosted OCI isolation backend 0.1

## Purpose

This backend executes a bounded container-local `process.exec/0.1` request
without exposing the host workspace, host Docker socket, network, credentials,
or an image-pull path. It is a materially stronger option than SOVA's ordinary
host-process executor for untrusted Linux command-line workloads.

It is not a per-workload microVM. The OCI container shares the Linux kernel of
Docker Desktop's VM. Docker Desktop, its host proxy, hypervisor, daemon, runtime,
and that VM kernel remain in the trusted computing base.

## Admission and attestation

`sova safety attest-docker --image REPOSITORY@sha256:DIGEST` performs read-only
runtime admission. The image must already be cached under the exact digest;
SOVA never substitutes a tag or pulls an image. Admission requires:

- a responsive Docker client and server;
- a Linux engine identified as Docker Desktop, which supplies the outer host
  VM boundary;
- exact local `RepoDigests` membership;
- seccomp plus enforceable memory, CPU, and PID controls; and
- a safe projection of the daemon state whose canonical digest can be bound
  into SOVA authorization and trace evidence.

Static executable discovery reports only `degraded`. It can never promote a
backend to `ready`. A ready live attestation projects to
`sova:backend:docker-desktop-oci`, with `IsolationKind.CONTAINER`; it deliberately
does not pretend that the workload has its own VM.

## Exact execution posture

The adapter constructs Docker argv itself and accepts no caller-supplied Docker
flags. Each invocation uses:

- `--pull never` and an exact `repository@sha256` image;
- `--network none`;
- no bind mount, volume, device, host namespace, host PID, or Docker socket;
- a read-only root filesystem;
- a bounded `tmpfs` at `/tmp` with `noexec`, `nosuid`, and `nodev`;
- UID/GID `65534:65534`;
- `--cap-drop ALL` and `no-new-privileges`;
- private IPC, no Docker log driver, and bounded CPU, memory, PID, output, and
  wall-clock budgets; and
- a generated container name followed by forced cleanup and negative
  post-cleanup inspection.

Only an absolute container-local POSIX argv is accepted. Shell use is not
implicit; `/bin/sh -c` must be visible in the portable procedure and pass the
ordinary SOVA authorization boundary. Environment injection, host paths,
workspace mounts, capsule-object transfer, background containers, network, and
privileged execution are not supported by this profile.

## Threat model

This backend is designed to reduce the effect of:

- untrusted container-local code attempting ordinary host file, process,
  network, capability, namespace, or resource abuse;
- image-tag substitution or an implicit pull;
- command-line injection into Docker flags;
- runaway output, runtime, memory, CPU, or process count; and
- orphaned containers following failure, timeout, or cancellation.

It does not claim protection from:

- a compromised Windows host, Docker Desktop, hypervisor, Docker daemon,
  container runtime, or Linux VM kernel;
- an unknown container or VM escape;
- denial of service against Docker Desktop or unrelated workloads inside the
  shared VM;
- malicious output defeating a downstream consumer that ignores SOVA's
  redaction and rendering rules; or
- GUI, hardware, kernel-module, Windows-native, or arbitrary desktop software
  compatibility.

## Live validation on 2026-08-09

The optional real-runtime lane used Docker client/server `29.4.2`, Docker
Desktop `4.72.0`, cgroup v2, and a previously cached exact image digest. The
container reported:

- UID/GID `65534:65534`;
- effective capabilities `0000000000000000`;
- `NoNewPrivs: 1`;
- loopback only and no default route;
- read-only rootfs and writable bounded no-exec tmpfs;
- no Docker socket; and
- enforced 256 MiB memory, 32 PID, and 0.5 CPU ceilings.

The public optional test also executed through `DockerDesktopOciExecutor`,
checked the same identity/capability fields, and verified that the generated
container no longer existed after completion. The fixture image is not bundled
or pulled by SOVA.

Docker Sandboxes was separately inspected as the preferred per-agent microVM
candidate. On this host its `v0.12.0` server created a VM record but did not
produce an executable shell sandbox within the 120-second bound, and bootstrap
network logs still contained default Docker-registry allowances. The named VM
was removed and cleanup verified. SOVA therefore records this backend as
`degraded`, not ready, until an in-VM health, mount, network, startup, reset, and
cleanup conformance suite passes.

## Primary references

- [Docker Sandboxes security model](https://docs.docker.com/ai/sandboxes/security/)
- [Docker Desktop WSL 2 security model](https://docs.docker.com/desktop/features/wsl/)
- [Docker container run reference](https://docs.docker.com/reference/cli/docker/container/run/)
- [gVisor security model](https://gvisor.dev/docs/architecture_guide/security/)
- [Kata Containers architecture](https://github.com/kata-containers/kata-containers/tree/main/docs/design)
- [OCI Runtime Specification](https://github.com/opencontainers/runtime-spec)

## Exit to a higher isolation class

A per-workload microVM or user-kernel backend may be promoted only after its
real runtime passes separate-kernel, host-mount absence, credential absence,
deny-by-default network, budget, cancellation, forced-crash, deterministic
reset, artifact extraction, and post-cleanup tests. Binary presence, marketing
architecture, or a VM list entry is not sufficient.
