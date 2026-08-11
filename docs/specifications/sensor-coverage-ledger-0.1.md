<!-- status: implemented -->

# Sensor coverage ledger 0.1

SOVA represents sensor coverage as a claim-conditioned ledger, not a promise
to record everything. Every sensor declares its surface (SOVA, host, browser,
model, or external service), event kind, health, provider/version, direct,
provider-reported, derived, or unavailable capture mode, clock domain, ordering
guarantee, emitted and dropped counts, and known blind spots.

A coverage policy names the exact claim and required `(surface, kind)` pairs.
Evaluation fails for a missing, unhealthy, unavailable, or dropping required
sensor. Reports retain all declarations and blind spots. They explicitly deny
total sensor coverage, private-thought capture, absence-of-evidence inference,
and independence of provider-reported observations.

This is compatible with OpenTelemetry concepts, but SOVA's trace sequence is
not automatically an OpenTelemetry global order. Each exporter must preserve
its clock domain and causal links, and describe loss, sampling, skew, and
partial traces. Applicable GenAI spans map only observable requests, responses,
authorized reasoning summaries, tools, and effects.

Primary references: [OpenTelemetry semantic convention stability](https://opentelemetry.io/docs/specs/semconv/general/),
and [GenAI agent spans](https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/gen-ai-agent-spans.md).
