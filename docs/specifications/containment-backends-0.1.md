<!-- status: experimental-partial -->

# Detonation containment backends 0.1

SOVA selects existing isolation technology through capability descriptors. It
does not build a commodity hypervisor or claim that every installed runtime is
hardened.

## Admission properties

A backend descriptor commits to its isolation class, whether it executes native
target code, network mode, disposability, deterministic reset, synthetic
credentials, cleanup verification, readiness, protections, and limitations.
The descriptor digest is bound into authority.

Admission can require:

- minimum isolation: none, process, OCI container, user-kernel, or microVM;
- maximum network mode: none, sink-only, allowlisted, or live;
- disposable state, deterministic reset, synthetic credentials, and verified
  cleanup.

Missing protections cause refusal. An explicit developer mode may be reported
as `developer-only`, never as allowed hardened isolation.

## Reference inventory

| Backend | Reference status | Security statement |
|---|---|---|
| SOVA synthetic world | implemented | no native target code; simulator, not OS sandbox |
| restricted local process | implemented developer tool | ordinary host process, not sandbox |
| OCI/Docker | capability probe only | client presence does not prove hardened daemon |
| SOVA Docker Desktop OCI | implemented, live-attested per image | no network/host mounts/socket, bounded non-root container inside Docker Desktop VM; shared VM kernel |
| Docker Sandboxes | degraded candidate on current host | per-agent microVM architecture; VM record did not become an executable sandbox within the bounded probe |
| gVisor | capability probe only | user-kernel isolation; configuration unverified |
| Firecracker | capability probe only | microVM candidate; needs Linux/KVM orchestration |
| Kata Containers | capability probe only | VM-backed OCI candidate; configuration unverified |

The no-native-code synthetic world may satisfy a research run that asks for a
stronger native-code boundary only because it executes no target-native code.
That exemption is explicit and appears in the decision.

The Docker Desktop OCI backend can execute explicitly authorized, digest-pinned
Linux command-line workloads only after live attestation. It uses Docker
Desktop's VM as the outer host boundary and a hardened OCI container as the
workload boundary. It is not a per-workload microVM and is not admitted when a
scenario requires `IsolationKind.MICROVM`. Other container, user-kernel, and
microVM candidates remain capability descriptors until their setup, teardown,
network, image, kernel, and escape-oriented conformance tests pass.

## Primary references

- [Firecracker, NSDI 2020](https://www.usenix.org/conference/nsdi20/presentation/agache)
- [gVisor security model](https://gvisor.dev/docs/architecture_guide/security/)
- [Kata Containers architecture](https://github.com/kata-containers/kata-containers/tree/main/docs/design)
- [OCI Runtime Specification](https://github.com/opencontainers/runtime-spec)
