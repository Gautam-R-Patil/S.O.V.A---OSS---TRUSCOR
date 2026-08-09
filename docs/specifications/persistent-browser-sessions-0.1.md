<!-- status: implemented -->

# Persistent browser sessions 0.1

## Purpose

SOVA can reuse an operator-authorized browser profile across Playwright MCP
processes without placing credentials, cookies, tokens, browser storage, or the
profile path in a `.sova` capsule, `.sova-trace`, model prompt, report, or CLI
result. Persistent state is optional; every browser workflow remains ephemeral
unless the operator explicitly supplies both a local vault and opaque handle.

This facility exists for controlled sites whose useful workflows require a
login, consent screen, or CAPTCHA. SOVA does not create accounts, harvest
credentials, automate one-time codes, or bypass CAPTCHAs. `sova session
browser-handoff` opens a headful target-bound profile; the operator completes
those steps directly in the browser and returns an exact confirmation phrase.

## Profile and lease model

`BrowserProfileVault` stores each profile under the SHA-256 digest of a random
opaque handle. The metadata binds the handle to an operator identity label and
the exact target-manifest digest. A workflow must prove the same digest before
the executor can receive the directory.

`BrowserProfileLease` creates an atomic cross-process lock containing a random
lease ID, owner label, process ID, and bounded deadline. Concurrent use fails
closed. A stale lock is recoverable only when its deadline has passed and its
recorded process is no longer observable. An uninspectable process is treated
as live. Releasing a lease removes only the lock; the durable profile remains.

The trace-safe mapping includes the handle digest, target binding, lease
metadata, and negative material-presence flags. It never includes the handle or
directory. On POSIX, SOVA applies owner-only modes to vault metadata. Windows
and browser-level protection depend on the host configuration and are not
claimed as SOVA encryption.

## Executor boundary

The pinned Playwright MCP launch defaults to `--isolated`. A persistent run
replaces that flag with `--user-data-dir` only after:

1. the profile is inside an explicitly admitted vault root;
2. neither the root nor profile is a symlink;
3. an exclusive lease is live;
4. the target digest matches; and
5. normal proof-of-control and action authorization pass.

The MCP transport closes stdin and permits a bounded graceful process exit so
Chromium can flush durable state. Termination and kill remain bounded fallbacks
for an unresponsive server. A persistent profile is not a security sandbox and
must not be shared concurrently across swarms. Swarms use distinct profiles or
an explicitly shared identity whose access is serialized.

## Operator workflow

```bash
# Obtain the targetDigest from target validation/plan output.
sova session browser-create ./.sova/browser-profiles operator TARGET_DIGEST

# Use the returned opaque handle. The browser opens headfully; the operator
# completes login/CAPTCHA manually and confirms the handoff in the terminal.
sova session browser-handoff ./website-target.json https://owned.example/login \
  ./.sova/browser-profiles PROFILE_HANDLE ./handoff-evidence \
  --control-proof ./website-proof.json

# Reuse the target-bound profile in a finite authorized campaign.
sova hunt browser ./website-target.json ./browser-campaign.json ./website-hunt \
  --control-proof ./website-proof.json \
  --browser-profile-vault ./.sova/browser-profiles \
  --browser-profile-handle PROFILE_HANDLE
```

`browser-inspect` returns only trace-safe metadata. The profile vault must stay
outside Git, evidence exports, backups not designed for credentials, and model
inputs. Revocation or deletion is intentionally not automated in 0.1 because
removing a browser profile is destructive; the operator manages that local
state deliberately.

## Validation

The mandatory lane verifies target binding, malformed and substituted locks,
live-lock refusal, bounded stale recovery, trace-safe serialization, external
vault admission, campaign integration, manual-handoff negative claims, and
signed evidence without network access.

The optional installed-Chrome lane sets a harmless persistent HttpOnly cookie
on SOVA's self-owned loopback fixture, closes one real Playwright MCP process,
starts a distinct process using the same exclusively leased profile, and
observes `SOVA_SESSION_PRESENT`. The signed trace and report are scanned to
exclude the opaque handle, profile path, and cookie material.

This proves one controlled persistence mechanism. It does not prove arbitrary
provider login compatibility, correct authentication, SSO support, browser
policy compatibility, profile confidentiality against a compromised host, or
safe reuse on an untrusted site.

## Primary interoperability source

Microsoft Playwright MCP documents `--user-data-dir`, isolated storage state,
and the one-browser-instance-per-persistent-profile constraint in its official
[repository](https://github.com/microsoft/playwright-mcp). SOVA adds its own
target binding, lease, evidence minimization, and authorization boundaries; it
does not claim those underlying browser-profile mechanics as novel.
