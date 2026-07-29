# Contributing to SOVA OSS

Thank you for helping build SOVA OSS.

## Before contributing

Read:

- [the public repository boundary](docs/governance/public-repository-boundary.md);
- [the dual-use policy](DUAL_USE_POLICY.md);
- [the security and coordinated-disclosure policy](SECURITY.md);
- [the trademark policy](TRADEMARKS.md);
- [the controlling project decisions](docs/decisions/0005-topic-00-project-constitution.md).

Do not submit credentials, private traces, client data, confidential target details, unpatched exploit payloads, restricted proprietary methods, or material you do not have the right to publish.

Security vulnerabilities must be reported privately as described in `SECURITY.md`, not opened as public issues.

## Licence

SOVA OSS is licensed under the [Apache License 2.0](LICENSE).

Unless you state otherwise, a contribution intentionally submitted for inclusion is provided under Apache-2.0 without additional terms, consistent with Section 5 of the licence.

## Developer Certificate of Origin

Contributions use the [Developer Certificate of Origin 1.1](https://developercertificate.org/) instead of a contributor copyright assignment.

Sign off each commit:

```bash
git commit -s -m "describe the change"
```

The sign-off certifies that you created the contribution or have the right to submit it under the project's licence and understand that the contribution and sign-off record are public.

Do not sign off for another person.

## Public provenance

Every fixture, scenario, benchmark, or dataset contribution must declare one of:

- `synthetic`;
- `public-source`, with source and licence;
- `consented-publication`, with disclosure status;
- `generated-from-public-inputs`, with inputs and method.

Anonymized client data is not accepted.

## Safety requirements

Contributions involving offensive behavior must:

- operate against a deliberately vulnerable fixture or a system the contributor is authorized to test;
- use non-destructive proof by default;
- declare blast-radius and cleanup behavior;
- never contain live credentials or named production targets;
- respect coordinated disclosure;
- preserve the explicit human-authorization gate;
- include tests for refusal and failure paths;
- avoid automatic target modification or remediation.

The official registry does not accept an exploit for an unpatched vulnerability.

## Pull requests

Keep pull requests narrow and include:

- the problem and intended outcome;
- tests or reproducible validation;
- safety and privacy impact;
- artifact/schema compatibility impact;
- public provenance;
- paper, patent, licence, and disclosure status when applicable.

Complete the pull-request boundary checklist. Maintainers may ask for a change to be split, withheld pending disclosure, or recreated with synthetic data.

## Research and citation

Research contributions are welcome. Methods and claims must include:

- a reproducible protocol;
- suitable baselines;
- uncertainty and limitations;
- ethics and authorization context;
- versioned `.sova` and `.sova-trace` artifacts where safe;
- paper/patent review before irreversible disclosure.

If you use SOVA OSS in research or publication, cite the release or commit using [`CITATION.cff`](CITATION.cff).

## Attribution and forks

Distributed derivatives must comply with Apache-2.0, including its licence, modified-file, notice-retention, and `NOTICE` requirements.

Modified forks must follow [`TRADEMARKS.md`](TRADEMARKS.md), use a distinct primary name, and may truthfully describe themselves as based on SOVA-OSS.
