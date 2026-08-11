<!-- status: implemented -->

# gVisor runsc isolation backend 0.1

`GVisorOciExecutor` is a Linux OCI backend for executing a digest-pinned image
through a Docker runtime registered exactly as `runsc`. Admission refuses tags,
pulls, host mounts, the Docker socket, host networking, privileged mode, added
capabilities, and writable root filesystems. Runs use no network, a read-only
root, dropped capabilities, no-new-privileges, non-root UID/GID, bounded PIDs,
memory and CPU, a bounded tmpfs, timeout/cancellation, post-run inspection, and
forced cleanup.

The attestation records daemon identity, registered runtime, cached image
digest, and the exact isolation posture. Deterministic tests cover command
construction, hostile inputs, conformance, and cleanup. A live test is opt-in
and requires a preconfigured `runsc` Docker runtime plus an already-cached
digest-pinned fixture image.

gVisor interposes a user-space application kernel and reduces direct host-
kernel exposure. It is not a separate machine and does not prove escape
impossibility. The host kernel, container daemon, runsc binary, configuration,
and administrators remain trusted. Workloads requiring a per-workload kernel
boundary must use the separately attested VM/microVM class.

Primary references: [gVisor documentation](https://gvisor.dev/docs/) and
[gVisor architecture guide](https://gvisor.dev/docs/architecture_guide/intro/).
