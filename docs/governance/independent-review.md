<!-- status: planned -->

# Independent review register

Internal tests and same-team reviews are not independent review. Before a
promoted release, record named or organizationally independent review of:

- parser/archive/resource-exhaustion security;
- cryptographic protocol and key-management claims;
- redaction, selective disclosure, and privacy;
- authorization, proof-of-control, and dual-use misuse cases;
- accessibility and first-run usability; and
- at least one independently authored executor adapter and artifact reader.

Each review records scope, commit, reviewer independence, findings, remediation,
accepted risks, and permission to publish. Critical unresolved findings block a
promoted launch. No such review is claimed in the current pre-alpha.
