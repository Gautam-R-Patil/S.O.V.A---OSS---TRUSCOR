<!-- status: implemented -->

# Evidence, adjudication, disclosure, and reports 0.1

## Evidence bundle

`sova evidence SPEC.json` builds `sova.evidence/0.1.0`. A valid bundle includes
the finding and affected component/version, capsule and trace references,
technical severity and harm category, tested conditions, coverage denominator,
detection floor, reproduction result and uncertainty, taxonomy mappings and
versions, methodology, mitigations, regression evidence, attachments,
limitations, and lifecycle data. Package/component identifiers can carry SBOM
coordinates such as purl or SPDX identifiers without redefining SBOM formats.

Every machine and human view carries:

> SELF-GENERATED SOVA EVIDENCE - NOT INDEPENDENT ATTESTATION

JSON is canonical machine output. `--format sarif` emits a SARIF 2.1.0 finding
projection with SOVA evidence references. Technical, executive, reproduction,
and methodology Markdown views derive from the same bundle. SARIF import retains
scanner/version/rule/location/evidence identity and caps input at 10,000
results. OpenTelemetry remains linked through referenced traces rather than
duplicated as a finding vocabulary.

## Execution-bounded adjudication

`sova adjudicate plan STUDY.json` requires an owned or explicitly authorized
target and emits an inert plan. It never executes scanner-supplied payloads.
`sova adjudicate evaluate STUDY.json` combines normalized scanner claims with
separately reviewed execution observations. Results are:

- `confirmed-positive`;
- `false-positive-under-declared-test`;
- `not-observed-under-declared-test`; or
- `inconclusive`.

Duplicate terminal observations are rejected. Scanner count is not a vote, and
shared mechanisms are identified as non-independent. Negative outcomes never
imply universal safety.

## Disclosure and dispute lifecycle

`sova disclose SPEC.json` prepares a local package. It records contact source,
disclosure clock and embargo state, vendor responses, remediation and regression
evidence, correction/supersession/dispute lifecycle fields, and a redacted
preview. URI values are omitted from that preview. The existing gate blocks
unsafe working payloads, unreviewed exports, secret-scan failures, missing
limitations, or incomplete coordinated-disclosure state. The command never
sends a message or publishes an artifact.

The system supports evidence and dispute workflows; it does not issue a
certificate, compliance conclusion, TRUSCOR attestation, or legal blame.
