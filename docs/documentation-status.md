<!-- status: implemented -->

# Documentation evidence states

Every technical statement must make its evidence state clear.

| Marker | Meaning | Permitted wording |
|---|---|---|
| `implemented` | Exists in the cited source and passes the stated checks | “does”, bounded to the cited version |
| `planned` | Approved direction not yet implemented or verified | “will”, “plans”, “intended” |
| `experiment` | Protocol, fixture, or result with scope and reproducibility metadata | observation plus protocol/version/limits |
| `claim` | Factual, comparative, market, legal, standards, or novelty statement | only with claims-register ID and evidence state |
| `decision` | Accepted project/governance choice | “decision”, not empirical result |

Foundation documents place a marker such as:

```html
<!-- status: implemented -->
```

at the top. A document may contain multiple states; label a section explicitly
when it differs from the document-level state.

## Rules

- Planned commands are never rendered as successful output from a real release.
- A schema example states whether it is normative, illustrative, experimental,
  invalid, or a golden conformance case.
- A test pass is not described as a security proof.
- “Not observed” is not “safe.”
- A signature establishes only the properties in its threat model.
- Self-assessment is never called independent attestation.
- Comparative language points to the exact protocol, revisions, run-bundle
  digest, uncertainty, and claims-register state.
- Legal and standards summaries include jurisdiction/version/date and do not
  replace qualified advice.
- Generated files identify their source and checker.

The repository policy checker enforces the top-level marker on engineering,
methodology, research-artifact, glossary, and documentation-control documents.
