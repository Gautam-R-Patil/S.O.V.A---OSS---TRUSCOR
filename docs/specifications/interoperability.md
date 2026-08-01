<!-- status: implemented -->

# Interoperability and fidelity

SOVA uses a minimum native semantic core plus versioned adapters.

| Source or target | Mapping | Fidelity rule |
|---|---|---|
| OpenTelemetry core semantic conventions `1.43.0` at `89aae438b3b3b0a8dd33003c9d70592baf7dbd0d` | span/resource/event import and export | Preserve source attributes; report SOVA fields that telemetry cannot supply |
| Experimental OpenTelemetry GenAI repository at `434c91dcc34ed038e3048c07720ddfed2c6bddfc` | exact-commit research mapping only | No release or stable Schema URL is claimed |
| OpenInference semantic conventions `0.1.30` from `789d41974c08a9a13147977f28ef4142a07e2106` | model, agent, tool, retriever, embedding, reranker, guardrail, evaluator, prompt, and chain span kinds | Do not infer authorization, safety, or causal truth |
| W3C Trace Context | correlation identifiers | Correlation is not artifact identity or proof |
| MCP | tool/resource/prompt messages and approvals | SOVA records protocol version and consent boundary |
| A2A | task/message/artifact exchange | Imported artifacts remain external typed objects |
| OCI descriptors | optional registry/distribution mapping | Native packages do not require an OCI runtime |
| RO-Crate and W3C PROV | research and provenance export | Export is derived, not the native evidence root |
| CycloneDX | component/model/dependency export | It is one view of the environment object |
| in-toto/DSSE/Sigstore | typed statements and signatures | Trust remains policy-bound |

Every importer returns a fidelity report with `preserved`, `approximated`,
`omitted`, and `unavailable` fields. A mapping with any approximation,
omission, or unavailable semantic is not called lossless.

The implemented OTel/OpenInference mapping derives valid 32-hex trace IDs and
16-hex span IDs with domain-separated hashes, retains the original SOVA IDs as
attributes, maps only one causal parent as the OTel parent, and maps additional
parents as Span Links. It is a JSON projection, not OTLP protobuf. It
intentionally reports missing
authorization, safety, monotonic ordering, redaction proof, and event-chain
semantics. Native capture remains the highest-fidelity path, but imported
traces remain useful and openly qualified.

The dedicated OpenInference importer is pinned to the names and span-kind
enumeration shipped by `openinference-semantic-conventions==0.1.30`. Its
default `content_policy="omit"` excludes recognized input/output values, flattened model
messages, prompt templates, tool parameters, retrieval content, embeddings,
exception data, SOVA payload projections, and span events. The returned
fidelity report names every omitted attribute. `content_policy="preserve"` is
an explicit opt-in for an authorized caller; content-bearing keys are then
listed as sensitive and still pass through SOVA capture-time redaction when
the draft is appended to a trace. Unknown top-level producer fields are not
silently reinterpreted. Unsupported span kinds degrade to `UNKNOWN` and are
reported as approximations.

This is schema-aware data minimization, not a secret detector: producer-defined
attributes and resource attributes can still contain sensitive information.
Importers must apply an appropriate SOVA redaction policy and review before
export. Span events are omitted by default because their attributes may carry
exception messages or other unclassified content.

OpenInference `0.1.30` has no `MEMORY` span-kind value. Native SOVA memory
events therefore project to `CHAIN`, retain `sova.payload` in the JSON
projection, and remain visibly lossy. The bridge does not call imported
telemetry replay evidence, authorization evidence, or an event hash chain.
It is a bounded JSON mapping rather than an OTLP protobuf implementation.

Independent consumers need only ZIP, UTF-8 JSON, SHA-256, and the published
schemas for inspection. Signing verification additionally needs Ed25519 and
DSSE PAE.
