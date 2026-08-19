<!-- status: implemented -->

# Evidence replay application 0.1

## Purpose

The replay application is an inert evidence viewer for observable
`.sova-trace` events. It makes a run understandable without pretending to
recover hidden model thoughts or re-executing recorded actions. The reference
application supports finalized traces and the integrity-valid prefix of a trace
that a local `TraceWriter` is still producing.

## Interfaces

`sova replay timeline SOURCE OUTPUT [--comparison TRACE] [--media VIDEO]`
writes one self-contained, offline HTML file. `sova replay capsule CAPSULE
OUTPUT` verifies a `.sova` package and selects its primary trace, optional
reproduction trace, and optional typed visual replay without manual extraction.
If the capsule also contains one typed `replay-cues` object, the renderer
verifies that its media digest matches the selected recording and that every
cue names a real passing `oracle.completed` event at the exact recorded
sequence in the selected trace pair.
`sova replay serve SOURCE` starts a bounded
foreground service on literal `127.0.0.1` and prints a random capability URL.
The service exists for local live tailing; it is not production HTTP.

Both interfaces provide:

- play, pause, scrubbing, and 0.5x through 8x evidence-time navigation;
- lanes grouped by canonical event-family prefix;
- actor, target, phase, and kind search;
- links to recorded causal parents and declared correlation links;
- synchronized nearest-event comparison using normalized monotonic time;
- payload, redaction, actor, target, phase, and completion details; and
- an explicit statement that playback performs no recorded action.

When reviewed WebM or MP4 media is supplied, the static page embeds the bytes
as a local data URL with native playback controls. Media without a cue index is
identified as session-level rather than event-time synchronized. A valid cue
index makes the page select the decisive `oracle.completed` event, seek two
seconds before its bounded video offset, and expose a five-second decisive
playback window. The page displays the synchronization method and uncertainty;
it does not call host-clock synchronization a cryptographic frame timestamp.
Media is never accepted by the live-tail service.

Capsule replay uses exact verified object descriptors. If more than one
candidate comparison trace or visual recording exists, it refuses ambiguity
and requires an internal object path shown by `sova inspect`. Package members
are copied into a private temporary directory only long enough to render the
page; archive member names are never used as host extraction paths.

The visual model borrows the useful evidence-navigation pattern of trace
processors such as Perfetto: multiple time lanes, selection, filtering, and a
detail pane. SOVA's implementation is purpose-built for `.sova-trace`; it does
not claim Perfetto protocol or UI compatibility.

## Sealed and live inputs

A finalized trace is accepted only after the ordinary `TraceReader` checks its
canonical package, object digests, manifest, event schema, local sequence,
causal parents, hash chain, redaction records, and applicable signature
material. Its replay state is `sealed`.

A live source is read only from the writer-owned
`.SOURCE.sova-trace.partial/events/*.jsonl` directory. Every complete line is
schema-validated and checked for contiguous sequence, unique identifier,
available parent, hash-chain continuity, event digest, and typed redaction.
The final unterminated line is ignored because it may still be in transit. A
live state is always `live-prefix`: it is neither sealed nor signed. Once the
final package replaces the staging directory, the next snapshot re-verifies
the sealed trace.

Reference bounds are 50,000 events, 8 MiB for one live event, 256 MiB for the
live source, 16 simultaneous clients, and a 30-second maximum SSE hold. These
are denial-of-service controls, not workload recommendations.

## Local transport

The reference service:

- binds only literal IPv4 loopback;
- uses 32 random bytes in an unlogged capability URL;
- requires an exact `Host` header containing the bound loopback address and
  port, reducing DNS-rebinding exposure;
- accepts only `GET` and `HEAD` and has no action-execution endpoint;
- sets `no-store`, `no-referrer`, `nosniff`, and frame-denial headers;
- emits finite Server-Sent Event responses with `id`, `event`, and `data`
  fields and honors `Last-Event-ID`; and
- limits the request queue and concurrent clients.

SSE is used as a small local update protocol, following the event-stream and
reconnection semantics standardized by W3C. The bundled Python standard-library
server is deliberately not described as Internet-production infrastructure.

## Content and browser security

All trace-controlled values enter the DOM through `textContent`, safe element
properties, or JSON that escapes `<`, `>`, `&`, U+2028, and U+2029. The page has
a restrictive Content Security Policy, no remote dependencies, no forms, and
no execution bridge. Trace payloads cannot become HTML, CSS, URLs, or script.
Static media is limited to one reviewed WebM/MP4 regular file of at most 128
MiB. Empty, linked, unsupported, ambiguous, or digest-invalid media is refused.
Replay cues are capped at 64 entries and 256 KiB, require canonical decimal
timings, must be digest-bound to the selected media, and may reference only
events present in the selected verified traces.
Embedded video pixels are sensitive evidence and receive no automatic visual
redaction.

The capability URL can still leak through local browser history, screenshots,
clipboard use, or a malicious local process. A compromised host or browser can
read or alter anything the operator can. The service provides no TLS, user
identity, authorization delegation, cross-host sharing, or protection from a
host administrator. Operators must export a separately reviewed/redacted trace
before sharing.

## Claim boundary

Replay verifies and displays recorded evidence. It does not prove that the
recorder, sensor, clock, actor label, causal link, or payload is truthful. A
hash chain is tamper evidence inside the tested threat model, not
non-repudiation or unforgeability. Nearest-time comparison is navigation aid,
not causal inference. The application never claims complete observability or
private chain-of-thought capture.

## Revalidation

Re-run hostile-content, malformed-live-line, truncation, reordering,
substitution, causal-parent, redaction, capability-route, Host-header, SSE,
sealed-transition, browser-console, and static-offline tests after any trace,
renderer, browser, or service change.

Primary references:

- [Perfetto UI](https://perfetto.dev/docs/visualization/perfetto-ui)
- [Perfetto trace-processor architecture](https://perfetto.dev/docs/design-docs/trace-processor-architecture)
- [W3C EventSource working draft](https://www.w3.org/TR/2011/WD-eventsource-20110310/)
- [OpenTelemetry general trace conventions](https://opentelemetry.io/docs/specs/semconv/general/trace/)
