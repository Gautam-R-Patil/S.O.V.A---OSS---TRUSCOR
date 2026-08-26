<!-- status: implemented -->

# Authorized local-software assessment 0.1

`sova detonate software` executes a portable process-only `.sova` scenario
twice against independent, credential-stripped copies of an operator-supplied
workspace. `sova detonate owned-software-fixture` exercises the same path with
an inert bundled program and no network dependency.

Those two `detonate` commands remain bounded process-only workflows and are not
security sandboxes. The newer `engine run-software`, `engine swarm-software`,
`arena run-software`, and `arena swarm-software` commands extend the same
authority and evidence principles to separately launched, measured native
applications; they do not weaken the process-only capsule contract described
below.

## Native software executor engine

The software executor engine accepts an exact regular executable, a
local-process target manifest, a fresh proof bound to that executable and the
workspace seed, a strict chamber document, and optional explicitly reviewed
process or computer adapters. Primary and reproduction phases receive separate
credential-stripped workspaces and separately launched process generations.

On Windows, the built-in native adapter admits only a visible enabled child
control owned by the exact attested top-level HWND. Each observation regenerates
the binding and control inventory. A typed request must match the current
process generation, HWND, binding digest, observation digest, target reference,
and separately declared `computer.click` or `computer.type` grant. Text is
bounded Unicode; coordinate targets remain operator-reviewed or dynamically
discovered inside that HWND. No model receives raw host, credential, approval,
or unrestricted input authority.

The deterministic oracle evaluates only SOVA-observed projections, including
exact-window frames and disposable-workspace effects. A finding requires a
fresh passing reproduction. Optional recording captures only the measured
application window, packages digest-bound primary and reproduction frame
archives, and selects the decisive passing-oracle moment for inert replay.
Software swarms launch a separate target process and workspace for every worker,
apply both per-worker and aggregate effect budgets, retain signed participant
and coordinator evidence, and package each reproduced finding as a nested
capsule.

This establishes a controlled reference path, not universal desktop
automation. Arbitrary accessibility frameworks, elevated/system windows,
cross-process dialogs, OS permission prompts, credential entry, undisclosed
plugins, arbitrary third-party applications, and strong host isolation require
their own adapters and acceptance evidence.

## Admission and authority

The workflow accepts only:

- a conformant `local-process` target manifest whose configuration declares an
  `authorityBasis` of `self` or `explicit` and a non-secret
  `authorityReference`;
- a regular non-symbolic-link capsule containing 1–32 expanded
  `process.exec` steps;
- one exact absolute executable, installed outside the source workspace and
  named identically by every step;
- no secret environment references, offensive flag, irreversible flag,
  background spawn, shell command, browser action, or computer action; and
- a source workspace that is neither a symbolic link, filesystem root, nor the
  user home directory.

The local-possession proof binds a fresh nonce to the target manifest,
executable digest, and clean-workspace fingerprint. It proves only that the
local workflow observed those values plus an operator assertion. It does not
independently establish legal ownership or authorization.

Before either run, a human-operated terminal displays the closed set of exact
actions and an explicit host-process warning. One exact batch phrase produces
distinct signed one-use approval tokens for every action in the primary and
reproduction runs. A model or agent cannot approve its own actions.

## Clean-room execution

SOVA prepares two separate bounded copies of the source workspace. Preparation
omits version-control data, virtual environments, dependency trees,
credential-shaped files, symbolic links, oversized/binary files, and private
directories; it replaces recognizable secret assignments in copied UTF-8
text. Each run receives an independent copy, so the original workspace is not
modified and target state is reset for controlled reproduction.

The admitted executable runs through `RestrictedLocalExecutor` with
`shell=False`, exact executable allowlisting, a confined working directory,
bounded output and duration, and no secret provider. These controls do not
prevent a trusted executable from accessing host resources through its own
code. SOVA therefore records all of these claims as false:

- security sandbox;
- network isolation;
- filesystem isolation outside the working directory; and
- kernel, registry, or descendant-process observability.

Potentially untrusted native software requires a stronger container, VM, or
operating-system isolation backend before execution.

## Observable sensors and evidence

For each admitted process action, the trace contains:

- authorization decision and exact normalized request;
- direct process completion, return code, bounded stdout, and bounded stderr;
- a before/after digest inventory of regular files below the disposable
  workspace, including created, modified, and deleted paths;
- explicit partial evidence if file/byte budgets, symbolic links, races, or
  unreadable files prevent a complete workspace observation; and
- deterministic oracle output over only those observable records.

The workflow signs both traces, runs the same scenario on a fresh copy, links
the reproduction to the source trace, compares `tool.completed` and
`oracle.completed` outcomes, and packages the scenario, target, declared
containment posture, and both traces into a digest-pinned `.sova` capsule.

`pass` means both declared observable outcomes passed and were equivalent under
the recorded conditions. It does not mean the target is safe, clean, fully
observed, legally authorized, or free of vulnerabilities.

## CLI

```bash
# Real, no-network owned fixture
sova detonate owned-software-fixture ./software-proof

# Trusted software owned by or explicitly authorized to the operator
sova detonate software ./target.json ./scenario.sova ./source-workspace \
  ./software-proof --executable /absolute/path/to/trusted-program
```

Both commands require an interactive terminal. The generic command is intended
for trusted local programs with portable argv/file behavior. Native GUI input,
accessibility-tree automation, persistent profiles, and arbitrary untrusted
code remain outside this process-only backend's claims. Use `engine
run-software` or its Arena alias for the separately authorized executor-engine
path; use `engine swarm-software` or its Arena alias only when each isolated
worker launch and the aggregate effect budget are intended.

## Validation

Mandatory no-network tests execute a real Python subprocess, observe its
planted conditional output and created file, verify both signatures, confirm a
fresh equivalent reproduction, verify the evidence capsule, and build a full
offline case workspace. Failure tests cover bad authority, wrong target kind,
missing capabilities, unsafe paths, executable substitution, disallowed
actions, secret references, effect escalation, sensor truncation, false local
proofs, wrong approval phrases, atomic cleanup, and non-interactive CLI use.

On Windows, the actionful engine lane additionally launches fresh owned GUI
processes and verifies exact-HWND click, changing-control discovery, bounded
type-and-save, primary/reproduction equivalence, decisive frame replay,
portable capsule reproduction, two isolated GUI workers, aggregate measured
coverage, and trusted Registry resolution. This is controlled internal
acceptance on one Windows configuration, not external application coverage.
