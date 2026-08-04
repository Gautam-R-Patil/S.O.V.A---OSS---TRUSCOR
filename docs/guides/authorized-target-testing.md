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

## What can be validated without a target

`sova target fixture website DEST` and `sova target fixture software DEST`
exercise target → plan → scenario → observable execution → signed trace →
capsule → controlled reproduction → offline verification using deterministic
self-owned fixtures. A real test remains pending until the exact target and
authorization are supplied.
