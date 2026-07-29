<!-- status: implemented -->

# Repository controls

## Branch and review model

`main` is the only permanent development branch and must remain releasable.
Contributors use short-lived branches and pull requests. Direct founder pushes
are permitted only during the founder-operated bootstrap period or a documented
emergency, and they must pass the same local and remote checks.

The intended GitHub branch protection is:

- block force pushes and branch deletion;
- require linear history;
- require review-conversation resolution;
- require at least one approving review;
- dismiss stale approval after a material change;
- require CODEOWNERS review for high-risk paths;
- require the complete CI, boundary, secret, dependency, and CodeQL check set;
- allow the repository administrator to bypass only for a documented
  bootstrap or emergency change.

GitHub-hosted settings are defense in depth. This checked-in policy remains the
review contract if a hosting feature is temporarily unavailable.

## Required pull-request evidence

A pull request must answer:

- What changed, why is it public, and what user-visible behavior changes?
- Which tests prove the intended and refused behavior?
- Does it change safety, authorization, privacy, schemas, compatibility,
  methodology, claims, licensing, datasets, or publication status?
- Are all fixtures synthetic or supported by redistributable public provenance?
- Did an invention, paper, patent, coordinated-disclosure, or third-party-rights
  gate trigger?
- Which changelog, methodology, glossary, ADR, and documentation updates apply?

Unchecked required boxes block merge; a maintainer may mark a genuinely
inapplicable item with a short explanation.

## Required checks

| Check family | Purpose |
|---|---|
| Repository policy | Headers, links, provenance, pinned actions, required homes |
| Public boundary | Confidential paths, private material, secrets, retired claims |
| Format and lint | Stable style, correctness, security-oriented static rules |
| Strict typing | Prevent unchecked public interfaces and implicit dynamic values |
| Unit/integration/compatibility | Behavior and cross-boundary contracts |
| Failure/performance | Recovery paths and declared resource ceilings |
| Coverage | Branch coverage floor for production package |
| Platform matrix | CPython and OS-family compatibility |
| Dependency review/audit | Known vulnerabilities and unexpected dependency changes |
| Secret scan | Known credential formats in the full Git history/change |
| CodeQL | Data-flow and security analysis |
| Build | Installable wheel and source distribution |
| DCO | Contribution provenance |

## Protected paths

`CODEOWNERS` assigns explicit review for:

- governance, licence, security, trademarks, notices, and citation;
- workflows, dependencies, packaging, release, and repository scripts;
- artifact schemas, migrations, fixtures, and compatibility suites;
- authorization, sandbox, execution, evidence, signing, and redaction code;
- research methods, claims, benchmark protocols, and publication artifacts.

## Commit and history policy

- Every commit has a DCO `Signed-off-by` line.
- Commit subjects use the imperative mood and describe one coherent change.
- Generated or vendored files identify their generator or upstream source.
- No force push to `main`.
- Do not squash away attribution or provenance required by a third-party licence.
- Never amend published schema, methodology, fixture, or release identifiers;
  issue a new version.

## Release gate

Creating a tag does not by itself authorize publication. A promoted release
requires the checklist in
[publication and IP review](./publication-and-ip-review.md), green CI against
the exact commit, a clean changelog/methodology ledger, security review, and
founder approval. PyPI publishing remains disabled until Trusted Publishing is
configured and separately tested.
