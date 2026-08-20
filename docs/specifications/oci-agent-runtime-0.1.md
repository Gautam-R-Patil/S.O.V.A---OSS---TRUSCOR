<!-- status: implemented -->

# Sandboxed OCI agent runtime 0.1

## Purpose

`sova.oci-agent-runtime` is the external-agent boundary for Arena and semantic
website exploration. It lets an operator package an agent or agent framework
inside one immutable OCI image while SOVA retains authorization, browser tool
execution, origin policy, evidence, judging, recording, and replay.

This is intentionally not an in-process plugin. The selected image must be an
exact `repository@sha256` reference already cached by the container engine,
and the configured OCI runtime must be registered as gVisor `runsc`. SOVA
refuses tag-only images, pulls, bridge networking, credentials, host mounts,
writable root filesystems, root users, ambient capabilities, and execution when
attestation is unavailable or degraded.

## Protocol

SOVA starts a fresh container for every call and passes exactly one fixed
argument to the image entry point:

```text
--sova-request-stdin
```

The request is supplied as one bounded canonical JSON document on standard
input; it is never placed in the host process command line. The request binds
`sova.oci-agent/0.1`, the runtime-document digest, one of
`describe`, `self-test`, or `respond`, and a secret-free payload. The process
must write exactly one JSON row with these fields:

```json
{
  "protocol": "sova.oci-agent/0.1",
  "runtimeDigest": "sha256:...",
  "operation": "respond",
  "accepted": true,
  "response": {}
}
```

`describe` returns `agentId`, the exact three supported operations, and a
non-empty capability list. `self-test` returns `{"status":"pass"}`. `respond`
returns `responseText`, one structured JSON object, and an integer or null
`tokenCount`. Substitution, extra fields, multiple output rows, malformed JSON,
oversized input/output, missing cleanup, or a non-zero process exit fail the
call. External agents never return executable tool calls; semantic browser
actions remain proposals parsed by SOVA's closed action algebra.

## Operator workflows

First attest the host without running the image:

```powershell
sova safety attest-gvisor --docker docker.exe `
  --image registry.example/sova/my-agent@sha256:<64 hex> --runtime runsc
```

Then run signed protocol conformance. SOVA prints the complete runtime,
attestation, authority exclusions, and limitations and requires the exact
digest-derived phrase before executing native code:

```powershell
sova agent conform-oci .\oci-agent-runtime.json .\agent-conformance `
  --docker docker.exe
```

The output contains a signed `.sova-trace` and canonical report. Arena can mix
provider participants and approved OCI participants through `ociParticipants`.
`arena explore-web` also accepts an OCI runtime in the existing planning-runtime
position with `--allow-sandboxed-agent-code --docker ...`; the image sees only
the bounded redacted accessibility snapshot and proposes typed actions. Every
browser batch still requires its own target-bound SOVA approval.

## Security and claim boundary

gVisor interposes a user-space application kernel and materially strengthens
the boundary around untrusted agent code. It is not a separate VM kernel and
does not prove escape impossibility. The host kernel, container engine, runsc
binary, and their configuration remain trusted. A production operator must
install, patch, monitor, and independently test that infrastructure. On a host
without a ready registered `runsc` runtime and cached exact image digest, this
feature is unavailable by design rather than silently downgraded.
