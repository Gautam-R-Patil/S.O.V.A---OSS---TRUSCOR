<!-- status: decision -->

# ADR-0020: Bounded self-assessment evidence, adjudication, and disclosure

- **Status:** Accepted
- **Date:** 2026-08-03
- **Owner:** Gautam R. Patil
- **Scope:** Topic 16 evidence and dispute workflows

## Decision

Every SOVA evidence bundle prominently identifies itself as operator-generated
self-assessment, cites both a `.sova` capsule and `.sova-trace`, states tested
conditions, coverage denominator or its absence, detection floor, reproduction
uncertainty, versions, methods, and limitations. Reports are projections, not
new evidence roots. SARIF is an interoperability projection for findings; SOVA
does not force complete traces into SARIF.

Scanner adjudication normalizes claims but does not count correlated scanners as
independent votes. It can construct only an inert test plan. Already-recorded,
safe, authorized execution observations yield one of confirmed positive, false
positive under the declared test, not observed under the declared test, or
inconclusive. Disclosure preparation is local-only, redacts reference locations
from its preview, applies the existing payload and review gate, and never sends
or publishes anything.

## Alternatives rejected

- Treat scanner majority as truth: mechanisms can be correlated.
- Label a negative run universally safe: exceeds tested conditions and sensors.
- Automate maintainer contact or publication: crosses a human authority boundary.
- Present operator evidence as TRUSCOR or independent attestation: false authority.

## Consequences

Useful evidence can be shared without embedding secret material or implying a
certificate. Real-component publication remains subject to coordinated
disclosure. Scanner-disagreement research claims remain open until a
representative dataset and predeclared execution protocol exist.
