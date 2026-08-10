<!-- status: implemented -->

# Continuous monitoring service 0.1

## Purpose

`sova monitor serve` turns the one-shot `sentinel` comparison into a durable,
foreground scheduler. It monitors operator-supplied observable behavior
snapshots; it does not continuously spy on an agent, discover hidden model
state, remediate systems, or upload results.

## Exact job document

The `sova.monitor-service-spec/0.1.0` document contains one through 256 jobs.
Each job declares:

- a safe identifier;
- a relative baseline snapshot path;
- a relative current snapshot path;
- an optional relative policy path;
- a 1-second through 31-day interval; and
- retention of one through 10,000 runs.

All paths must resolve to non-symlink regular files inside the explicit
workspace. The format has no executable, command, URL, provider, extension, or
upload field.

```console
sova monitor serve ./monitor.json ./.sova-monitor --workspace ./observations
sova monitor status ./monitor.json ./.sova-monitor --workspace ./observations
```

`--once` runs one due cycle for cron, CI, and local validation. The default is a
foreground loop stopped by the operator.

## Scheduler semantics

- Jobs are due immediately on first start, then at their declared interval.
- One kernel-backed state-directory lock rejects overlapping service instances
  and is released by the operating system after a crash.
- A persisted `running` job is recovered to `idle`, counted as interrupted, and
  made due after restart.
- Job execution is sequential and non-overlapping in 0.1.
- Cancellation is cooperative between finite local snapshot comparisons.
- A comparison error returns the job to `idle` and schedules a later retry; it
  is not silently converted into a clean result.

Each completed comparison writes:

- the canonical sentinel report;
- bounded local history;
- one signed `.sova-trace` containing the exact observable result and policy
  digest; and
- a machine-readable run descriptor.

The evidence scope binds the exact in-memory baseline and current snapshot
digests used by the comparison. Included-key signatures provide tamper evidence
for the captured result; they do not independently establish recorder identity,
sensor completeness, truth, or non-repudiation.

## Retention and notifications

Old run directories and history rows are pruned to each job's declared
`retentionRuns`. Notification mode is local artifact plus foreground output.
Email, chat, paging, webhook, public upload, and automatic remediation require
separate explicit adapters and are absent from the reference service.

## Failure boundaries

The service does not guarantee operating-system service supervision, high
availability, wake-from-sleep timing, exact wall-clock execution, distributed
leases, remote snapshot collection, or continuous validity. Operators needing
those properties should run the foreground process under a reviewed service
manager and preserve the state directory on durable storage.

