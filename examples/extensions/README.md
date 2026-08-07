# Safe subprocess extension example

This example demonstrates the `sova.extension-jsonl/0.1` protocol without
granting target, tool, browser, network, or credential authority.

First create a machine-local launch record. On PowerShell:

```powershell
$python = (Get-Command python).Source
sova extension prepare manifest.json launch.json `
  --executable $python `
  --working-directory (Get-Location).Path `
  --argument (Resolve-Path safe_oracle.py).Path
```

On a POSIX shell:

```bash
python_path="$(command -v python3)"
sova extension prepare manifest.json launch.json \
  --executable "$python_path" \
  --working-directory "$PWD" \
  --argument "$PWD/safe_oracle.py"
```

Then inspect `manifest.json` and `launch.json` and run:

```bash
sova extension run manifest.json launch.json ./extension-output
```

The second command requires a human-operated terminal and the exact displayed
approval phrase. SOVA rechecks the executable and script hashes after approval,
uses no shell, sends a sanitized environment, captures a signed trace, and
redacts credential-shaped response values. It still starts an ordinary host
process and therefore is **not a security sandbox**. Only run code you are
authorized and willing to execute under your operating-system account.
