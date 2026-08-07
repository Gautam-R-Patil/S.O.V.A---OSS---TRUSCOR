<!-- status: implemented -->

# Authorized website and software testing

SOVA tests only a target you own or are explicitly authorized to assess. A URL,
login, or command line is not proof of authorization.

## Prepare the portable target contract

```console
sova target template browser-agent website-target.json
sova target template local-process software-target.json
sova target validate website-target.json
sova target plan website-target.json website-plan.json
```

Edit the template to declare the exact target version, capability surface,
allowed origins or interface, and authorization scope. Do not place passwords,
cookies, tokens, API keys, or login values in the manifest. `target plan` is
inert: it records the required stages and executor choices but neither proves
ownership nor connects to the target.

## Admit an executor

- Browser targets: pinned Microsoft Playwright MCP is the preferred public
  adapter. It uses an isolated profile and SOVA post-action observations.
- Windows UI: the optional Windows-MCP adapter starts read-only and never maps
  PowerShell, registry, filesystem, process, or clipboard tools.
- Local software: `RestrictedLocalExecutor` accepts only an explicitly
  allowlisted absolute executable and confined working directory. It is not a
  security sandbox; use a disposable VM/container/OS sandbox for untrusted code.
- MELRA is optional and never supplies SOVA authorization, evidence, policy,
  judging, signing, or replay semantics.

Before a live run, review the exact action/effect budget, provide fresh
out-of-band authorization, prepare an isolated test account and data set, and
define deterministic post-action oracles. CAPTCHA bypass, unauthorized account
creation, third-party production access, and stealth persistence are outside
the default workflow.

## Run the real owned-browser acceptance target

The first live runner is deliberately narrow and directly testable:

```console
sova detonate owned-web-fixture ./live-browser-proof
sova verify --require-signature ./live-browser-proof/run.sova-trace
sova verify --require-signature ./live-browser-proof/reproduction.sova-trace
sova inspect ./live-browser-proof/evidence.sova
sova playback ./live-browser-proof/run.sova-trace
```

SOVA launches a real HTTP server on loopback, starts pinned Playwright MCP with
an ephemeral headless browser profile, limits admitted navigation to the exact
origin, requests a fresh exact approval phrase for every action, executes a
two-turn planted behavior, judges the final accessibility snapshot, repeats the
scenario with fresh authority, compares the observable oracle result, signs
both traces, and embeds them in an evidence capsule.

This proves the live browser/evidence path on SOVA's own target. It is not a VM
sandbox, a production-site test, a jailbreak-superiority result, or evidence
that arbitrary web applications are supported. Playwright's origin filter is
defense in depth and does not replace SOVA's pre-dispatch origin check or
post-run evidence review.

## What can be validated without a live browser

`sova target fixture website DEST` and `sova target fixture software DEST`
exercise target → plan → scenario → observable execution → signed trace →
capsule → controlled reproduction → offline verification using deterministic
self-owned scripted fixtures. The command above is the real-browser acceptance
lane. Testing an operator-owned external website remains blocked until its
control proof, target-specific scenario, data policy, accounts, and oracles are
reviewed and admitted.
