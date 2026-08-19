<!-- status: implemented -->

# Contained consequential-action lab 0.1

Status: experimental implementation contract.

The consequential-action lab proves SOVA's action-to-evidence spine beyond a
chat-only prompt-injection result. It is a self-owned loopback target with four
real, resettable effects:

1. a fixed file is created under a disposable known directory;
2. an email is transferred over SMTP to a loopback-only sink;
3. a message is posted to a loopback-only HTTP sink; and
4. an application setting is persisted under the same disposable directory.

The browser procedure activates the target, waits for its deterministic result,
clicks through the file, email, message, settings, and combined-activity views,
opens the full proof page, and captures snapshot, screenshot, console, and
network observations. SOVA executes the same procedure twice under fresh exact
approval, signs both traces, compares the oracle outcome, records optional
browser pixels, and renders the packaged evidence through `sova replay capsule`.

## Ground truth

Browser text is not the sole evidence source. The fixture independently records
the file digest, SMTP message digest and recipient, message-sink digest and
channel, and settings-file digest. The action-lab run passes only when exactly
two complete effect sets exist and the primary and reproduction effects are
byte-equivalent. The ground-truth receipt is embedded in
`action-evidence.sova` alongside the signed traces and visual replay.

## Containment

- HTTP, SMTP, and message delivery bind to literal `127.0.0.1` addresses on
  ephemeral ports.
- The target accepts one exact fixed instruction and no arbitrary path,
  recipient, URL, process, command, or setting value.
- The only written paths are two known files under a temporary disposable root.
- No process-spawn capability or external account is exposed.
- The effect root is deleted after evidence packaging.

These controls provide a safe acceptance fixture, not a VM sandbox and not a
claim about arbitrary third-party agents.

## Registry module

A passing run emits `registry-entry.json` for
`sova:module:contained-consequential-actions` and a content-addressable
`action-evidence.sova`. It then builds and verifies a signed local
`module-registry` snapshot containing that exact object. This is the first
concrete reusable action-module vertical for the SOVA registry. The entry remains at
`schema-and-safety-validated`; it is not promoted to CI- or independently
reproduced status without the corresponding external evidence.

The registry never executes submitted content. Verification, moderation,
disclosure, and explicit execution authorization remain separate gates.

## Command

```text
sova detonate action-lab ./action-lab-proof --headed --record-video \
  --playwright-browser-cache ./.cache/playwright-browsers
```

The command requires a human-operated terminal and two exact approval phrases,
one for the primary run and one for controlled reproduction.
