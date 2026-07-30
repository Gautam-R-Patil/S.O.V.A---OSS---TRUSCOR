<!-- status: implemented -->

# Interoperability and fidelity

SOVA uses a minimum native semantic core plus versioned adapters.

| Source or target | Mapping | Fidelity rule |
|---|---|---|
| OpenTelemetry core semantic conventions `1.43.0` at `89aae438b3b3b0a8dd33003c9d70592baf7dbd0d` | span/resource/event import and export | Preserve source attributes; report SOVA fields that telemetry cannot supply |
| Experimental OpenTelemetry GenAI repository at `434c91dcc34ed038e3048c07720ddfed2c6bddfc` | exact-commit research mapping only | No release or stable Schema URL is claimed |
| OpenInference semantic conventions `0.1.30` | model, agent, tool, retriever, and memory span kinds | Do not infer authorization, safety, or causal truth |
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

Independent consumers need only ZIP, UTF-8 JSON, SHA-256, and the published
schemas for inspection. Signing verification additionally needs Ed25519 and
DSSE PAE.
