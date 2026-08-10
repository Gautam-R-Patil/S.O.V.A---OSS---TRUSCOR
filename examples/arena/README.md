# Real-time Arena example

`chamber.json` is a safe, offline, two-agent acceptance case for `sova arena
chamber`. It exercises a synthetic filesystem canary, a non-routable `.invalid`
network sink, inter-agent observations, deterministic evidence judging, live
canonical JSONL, a signed `.sova-trace`, and a portable `.sova` capsule.

```powershell
sova arena chamber .\examples\arena\chamber.json .\arena-output `
  --authorize-contained-fixture --stream-jsonl
```

See the [Arena guide](../../docs/guides/arena.md) for artifact verification,
authoring, provider use, authorized website testing, and sensor limitations.

`browser-swarm.json` is the strict no-provider two-role configuration used by
the optional self-owned live-browser acceptance lane. It requires a separately
authored target and campaign, a target-bound opaque profile, and interactive
human approval; opening the JSON performs no action.
