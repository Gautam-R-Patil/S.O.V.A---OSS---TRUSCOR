<!-- status: planned -->

# P6 public-claims reconciliation packet

- **Captured:** 2026-08-31
- **Release gate:** P6-10
- **Public surface inspected:** [TRUSCOR homepage](https://truscor.org/)
- **Result:** replacement copy is decision-complete; the live surface was not
  changed, captured as a release artifact, or approved in this work

## Why this is a launch gate

The public site currently presents SOVA as an autonomous enterprise testing and
real-time risk-rating engine. It also associates SOVA-driven testing with
actuarial damage, loss, insurance-pricing, and rating outcomes. The SOVA-OSS
evidence set proves bounded authorized mechanisms and controlled acceptance
lanes; it does not establish those broader field-performance or actuarial claims.
Separate non-repository evidence may exist, but it is not part of this release
record and cannot be silently inherited by SOVA OSS.

## Surface-by-surface decision

| Surface | Current release state | Required final action |
|---|---|---|
| README | Locally reconciled, not captured for the final commit | Hash the exact final bytes and record them in the public-claims snapshot |
| Documentation | Locally reconciled, not captured for the final commit | Hash the exact shipped documentation set and record its aggregate artifact digest |
| Demo | No release-controlled final demo snapshot | Capture the exact demo copy and media; remove or qualify unsupported autonomy, coverage, and safety implications |
| Website | Live wording is broader than the OSS evidence | Replace it with the approved copy below, then capture and hash the served response |
| Paper | No release-controlled public paper source in this checkout | Bind the exact cleared paper or an explicit no-paper release notice; obtain publication/IP review |
| Registry | No public production Registry surface exists | Capture the deployed surface only after P6-07 operational receipts pass |
| Release notes | Draft repository notes exist, but no final release artifact | Hash the exact final release notes after every evidence gate is resolved |

## Approved SOVA-OSS launch copy

The following text is the evidence-bounded replacement for the SOVA product
section. It does not replace independently reviewed TRUSCOR corporate, actuarial,
or insurance disclosures.

> **SOVA OSS — evidence-first security testing for authorized AI and agentic systems**
>
> SOVA OSS is a local-first open-source security assessment framework. It helps
> operators describe an authorized target, map workflows and attack surfaces,
> compile a bounded methodology, coordinate admitted tools and agents, and package
> reproducible evidence and replay artifacts.
>
> Current public evidence covers controlled and owned test environments. Broad
> blinded multi-provider and multi-target performance, production-grade hostile
> agent isolation, actuarial ratings, loss estimates, and insurance pricing are
> not established by the current OSS release.
>
> SOVA outputs are scoped security-assessment evidence, not certification, a
> security guarantee, or proof that every vulnerability was found.

Roadmap language may describe the intended intake-to-replay platform only as an
aim. It must not convert uncompleted P5 or P6 gates into present-tense capability.

## Exact release binding

The release candidate now requires a digest of one canonical
`sova.public-claims-snapshot`. That snapshot must contain exactly one reviewed
record for each of the seven surfaces above. The launch dossier independently
loads the exact bytes, validates the release commit and content digest, recomputes
the derived readiness state, and keeps `publicClaimsReconciled=false` if any
surface is held or unreviewed. The founder and legal review receipts bind the
resulting release-candidate digest.

## Evidence required to close P6-10

1. A named founder approves the exact copy and all seven surface records.
2. The website operator deploys the approved wording and captures the exact served
   response without relying on a search-engine snippet.
3. The paper, demo, Registry, documentation, README, and release-note bytes are
   frozen for the same release commit.
4. The legal/licence/public-disclosure reviewer and security reviewer approve the
   exact candidate containing the snapshot digest.
5. `sova release dossier` validates the canonical snapshot and reports
   `publicClaimsReconciled=true` with no contradictory public surface.

Until all five conditions hold, P6-10 and publication remain on hold.
