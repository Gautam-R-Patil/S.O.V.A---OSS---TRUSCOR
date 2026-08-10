<!-- status: implemented -->

# Self-hosted community service 0.1

## Scope

`sova registry serve` is a loopback-only reference service for staging and
reviewing public `.sova` evidence. It adds a live transport to the existing
offline registry and standard-profile leaderboard without making upload a
default SOVA behavior.

The reference service is intentionally not an Internet deployment. Python's
`http.server` documentation says that module is not suitable for production;
therefore an operator must put a separately reviewed production HTTP stack,
TLS, identity system, moderation workflow, backups, and availability controls
in front of any public deployment.

## Initialization and trust

```console
sova registry init-service ./.sova-community/service.token
sova registry serve ./.sova-community/data \
  --token-file ./.sova-community/service.token \
  --trusted-key-id sha256:EXPECTED_EVIDENCE_SIGNER \
  --methodology ./arena-methodology.md
```

The token is generated with `secrets.token_urlsafe`, is stored in a new
operator-controlled file, and is never printed. The server binds only to a
literal loopback IP. Submission requests require the bearer token; read-only
indexes, accepted objects, leaderboard data, health, and events are locally
readable.

There are two independent pins:

1. the server pins evidence-signing key IDs before accepting a submission;
2. a client pins the service-index signing key out of band when running
   `sova registry verify-live-index`.

DSSE authenticates the signed bytes and payload type. DSSE itself deliberately
does not provide PKI or key ownership. SOVA therefore never promotes an
included key into an identity claim.

## Submission lifecycle

The accepted request is an exact `sova.community-submission/0.1.0` JSON object.
It contains one `.sova` capsule and one `.sova-trace`, their sizes and SHA-256
digests, and either registry or standard-leaderboard metadata.

```console
sova registry prepare-upload ./metadata.json ./case.sova ./case.sova-trace \
  ./upload.json --kind leaderboard
```

That command performs no network request. An operator can review `upload.json`
and explicitly submit it to `POST /v1/submissions`.

The service then moves the submission through:

```text
queued -> verifying -> accepted
                   `-> rejected
```

Before acceptance it verifies:

- exact document fields, file names, types, counts, sizes, base64, and digests;
- bounded plaintext credential patterns in metadata and supplied bytes;
- the capsule package and content-addressed descriptors;
- one complete signed trace, pinned to an operator-trusted evidence key;
- exact trace inclusion in the capsule;
- for leaderboard entries, the pinned standard Arena profile and an oracle
  score that matches the signed trace;
- duplicate capsule or trace evidence across alternate submission identities.

Submitted content is never imported as code and never executed. Accepted bytes
are atomically promoted to `objects/sha256/`. Unaccepted or orphaned objects are
not served.

## HTTP surface

| Method | Route | Meaning |
| --- | --- | --- |
| `GET` | `/v1/health` | Local readiness and service key ID |
| `POST` | `/v1/submissions` | Token-gated bounded staged upload |
| `GET` | `/v1/submissions/{id}` | Queue and verification status |
| `GET` | `/v1/index` | DSSE-signed accepted-object index |
| `GET` | `/v1/objects/sha256/{digest}` | Accepted content-addressed object |
| `GET` | `/v1/leaderboard` | Verified standard-profile rows |
| `GET` | `/v1/events` | UTF-8 `text/event-stream` event feed |

The event feed uses the WHATWG Server-Sent Events `id`, `event`, and `data`
framing. A client can resume with `?after=N` or `Last-Event-ID`.

## Durability and abuse controls

- Every transition is atomically persisted before the next transition.
- A `verifying` row is recovered as `queued` after restart.
- Submission identity is content-derived, making identical retries idempotent.
- Body, file, count, decoded-byte, path, type, and per-minute request bounds are
  enforced before verification.
- Content promotion uses a verified temporary file and atomic replace.
- The service key is stable across restarts; private bytes are never returned.
- Service indexes carry a monotonic sequence. Clients can pass
  `--minimum-sequence` to reject a known rollback.

## Non-claims and production gaps

The reference service does not provide TLS, Internet-grade authentication,
multi-tenant authorization, distributed queues, moderation staffing, malware
sandboxing, transparency logs, threshold signatures, revocation, TUF metadata,
expiry/freeze protection, disaster recovery, DDoS resistance, or uptime.

The Update Framework defines defenses against rollback, freeze, mix-and-match,
and key-compromise attacks. This 0.1 service implements content addressing,
explicit pins, atomic snapshots, and an optional sequence floor; it is not a
TUF implementation and must not be described as one.

Primary references:

- [DSSE protocol](https://github.com/secure-systems-lab/dsse)
- [WHATWG Server-Sent Events](https://html.spec.whatwg.org/multipage/server-sent-events.html)
- [The Update Framework specification](https://theupdateframework.github.io/specification/)
- [Python `http.server` security warning](https://docs.python.org/3/library/security_warnings.html)

