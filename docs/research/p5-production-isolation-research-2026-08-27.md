<!-- status: implemented -->

# P5 production-isolation research refresh

- **Date:** 2026-08-27
- **Decision:** Firecracker is the primary hostile-job worker; Kata remains
  disabled by default; gVisor remains a lower-assurance compatibility lane.
- **Adoption mode:** architecture and security controls were adapted behind SOVA
  contracts. No third-party source code was copied into the worker package.

## Firecracker

Firecracker's production-host guidance and jailer design match SOVA's need for a
small per-job VM boundary: KVM, one VMM process per microVM, jailer chroot and
privilege drop, cgroups, namespaces, and seccomp. The guidance also makes clear
that the operator still owns host hardening, patching, swap policy, output
control, network filtering, and per-tenant process isolation.

SOVA therefore adopts the architecture but adds its own immutable job authority,
mTLS plus DSSE protocol, CAS, endpoint/secret brokers, controller-side evidence
validation, and receipt model. Host egress is deny-by-default because Firecracker
does not itself supply the destination policy SOVA needs.

The protocol pins `1.16.1`, the current supported v1.16 patch at research time.
The release policy supports the v1.16 line through at least 2026-12-03. Two recent
advisories materially influenced the design:

- GHSA-36j2-f825-qvgc described a jailer symlink host-file overwrite and was fixed
  in 1.13.2 and 1.14.1. SOVA requires root-controlled, non-symlink host paths and
  exact binary pins.
- GHSA-776c-mpj7-jm3r described a PCI virtio out-of-bounds write and was fixed in
  1.14.4 and 1.15.1. Firecracker's default MMIO transport was not affected; SOVA
  explicitly disables PCI rather than treating a version pin as the only control.

Primary sources:

- [Firecracker production host setup](https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md)
- [Firecracker jailer documentation](https://github.com/firecracker-microvm/firecracker/blob/main/docs/jailer.md)
- [Firecracker release policy](https://github.com/firecracker-microvm/firecracker/blob/main/docs/RELEASE_POLICY.md)
- [Firecracker releases](https://github.com/firecracker-microvm/firecracker/releases)
- [GHSA-36j2-f825-qvgc](https://github.com/firecracker-microvm/firecracker/security/advisories/GHSA-36j2-f825-qvgc)
- [GHSA-776c-mpj7-jm3r](https://github.com/firecracker-microvm/firecracker/security/advisories/GHSA-776c-mpj7-jm3r)

## Kata Containers

Kata's VM-backed OCI ergonomics are attractive for a future compatibility lane,
but its official advisory set contained multiple 2026 critical/high host-impact
issues at research time, including unsafe host bind mounts from annotations,
policy path subversion, configuration-path loading, block-device hotplug,
virtiofs/virtiofsd issues, and a Dragonball virtio-blk escape class. This is why
`assess_kata_backend` fails closed on version, digest, advisory, annotations,
mounts, and root-owned configuration paths. SOVA does not make a generic “Kata is
safe” statement.

Primary source: [Kata Containers security advisories](https://github.com/kata-containers/kata-containers/security/advisories).

## gVisor

gVisor interposes a user-space application kernel and has a useful two-layer
sandbox model, but its own security documentation states the boundary is not a VM
and does not cover hardware side channels or higher-level runtime mistakes. It is
therefore useful for compatibility testing, not the primary arbitrary-hostile-code
claim.

Primary sources:

- [gVisor security model](https://gvisor.dev/docs/architecture_guide/security/)
- [gVisor architecture introduction](https://gvisor.dev/docs/architecture_guide/intro/)

## Rejected shortcuts

- Docker/Desktop presence is not proof of a dedicated hostile-code boundary.
- WSL2 with `/dev/kvm` is a development environment, not a dedicated reviewed
  worker.
- A generated jailer command is not a passed containment test.
- Self-issued attestation is integrity evidence, not independent assurance.
- “No escape observed” does not mean escape is impossible.
