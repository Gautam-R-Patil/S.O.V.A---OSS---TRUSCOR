# SOVA OSS publication and IP review

- **Policy version:** 1.0
- **Decision date:** 2026-07-29
- **Owner:** Gautam R. Patil
- **Legal status:** governance decision; not legal advice

This policy controls public disclosure of research methods, inventions,
vulnerabilities, data, and claims. It applies even when the disclosure contains
no source code.

## What counts as disclosure

Treat each of the following as a public disclosure unless access is
contractually and operationally restricted:

- a commit, branch, tag, release, package, container, or generated documentation
  in a public repository;
- a public issue, discussion, pull request, review, patch, diff, snippet, gist,
  paste, or CI log;
- a preprint, paper submission without a confidential-review basis, supplement,
  dataset, benchmark, model, weights file, poster, thesis, or dissertation;
- a conference talk, meetup, workshop, class, webinar, panel, office-hours
  answer, public grant application, or working-group contribution;
- a demo, screen recording, livestream, social-media post, launch video,
  screenshot, architecture animation, or public hosted instance;
- a blog post, newsletter, press interview, podcast, marketing page, README,
  roadmap, changelog, or release note;
- a public `.sova`, `.sova-trace`, trace excerpt, prompt, attack sequence,
  answer key, result bundle, benchmark artifact, or registry entry;
- an unrestricted customer, partner, investor, candidate, contractor, or
  community message;
- disclosure to an AI service under terms that do not preserve the needed
  confidentiality or ownership position.

Private disclosure is not assumed merely because a URL is obscure, a repository
is later deleted, or a meeting is small.

## Information classes

| Class | Examples | Default |
|---|---|---|
| **PUBLIC-CLEARED** | Accepted ADRs, governance, ordinary interfaces, already published high-level vision, cited prior art, claim status, protocol without hidden answer keys. | May publish under repository review. |
| **REVIEW-BEFORE-PUBLIC** | New schema fields, generic algorithms, experiment results, benchmark translations, redaction designs, evaluation metrics, paper drafts. | Hold until the checklist and relevant gate pass. |
| **EMBARGOED-VULNERABILITY** | Unpatched exploit details, affected identities, reproduction steps, target traces, secret material. | Private coordinated disclosure under `SECURITY.md`. |
| **INVENTION-HOLD** | Non-trivial search, replay, attribution, sensor-fusion, evidence, or redaction mechanism not yet reviewed against prior art. | Private until qualified IP advice and founder decision. |
| **TRADE-SECRET** | Private corpus, corpus-derived tuning, fitted priorities/weights, private run data, client findings, matched loss pairs, internal honeypot intelligence. | Never in SOVA OSS. |
| **PROHIBITED** | Real credentials, unauthorized target data, personal/client data, malicious payload for an unpatched issue, confidential Atlas material. | Do not publish. |

Changing a class requires a dated record. Publishing a derived summary does not
declassify the source.

## Publication Gate 01-C - prospective publication decision

The original roadmap wording said “no public repository before the format
defensive-publication decision.” The repository and high-level artifact ADRs
already existed before Topic 01, so that wording cannot be satisfied
retroactively.

The decision is:

1. Treat the already published `.sova`/`.sova-trace` meanings, versioning
   invariants, and high-level workflow as prior public disclosure.
2. Keep `.sova` and `.sova-trace` open, independently implementable public
   specifications. Format adoption requires this.
3. Publish experimental field schemas only after confirming that they contain
   no undisclosed mechanism that should remain under invention hold.
4. Put every public schema revision through an IP, security, privacy,
   compatibility, and threat-model review.
5. Never embed private corpora, fitted priorities, client-derived information,
   or secret commercial authority into the format or reference runtime.
6. Treat future commits as publication. Deleting or rewriting history does not
   restore rights that disclosure may have affected.

**Gate result: PASS FOR OPEN FORMAT GOVERNANCE; PROSPECTIVE HOLD ON
MECHANISM-BEARING FIELDS.**

This is a product/governance decision, not a patentability opinion. Qualified
counsel must determine the legal effect of prior disclosure in relevant
jurisdictions.

## Patent Gate 01-D - trigger search

Current prior art includes sleeper agents, backdoor-trigger reconstruction,
Plan-of-Thought backdoors, memory poisoning, adaptive long-horizon attacks, and
sequential tool-chain attacks. A broad claim to “finding hidden triggers” is not
a defensible novelty position.

Decision:

- Public now: the problem definition, bounded-search interface, safety envelope,
  deterministic-oracle contract, ordinary exhaustive/random/property-based
  baselines, and the predeclared evaluation protocol.
- **INVENTION-HOLD:** any non-trivial adaptive prioritization, state abstraction,
  budget-allocation rule, feedback update, acquisition function, learned policy,
  corpus-derived ordering, fitted parameter, or combination proposed as new.
- **TRADE-SECRET:** private-corpus conditioning, client-derived tuning, private
  run data, fitted priorities, and internal evaluation sets.
- Before non-trivial code, equations, pseudocode, diagrams, talk demos, or paper
  text are public: create an invention disclosure, perform a documented
  patent/non-patent prior-art search, obtain qualified counsel, and choose
  patent filing, defensive publication, trade secret, or abandonment.
- Whatever generic trigger-search functionality the public SOVA OSS feature
  promises must ultimately have a complete open implementation after the gate.
  Trade secret may improve SOVA Engine; it may not make SOVA OSS a hidden-service
  client or crippled edition.

**Gate result: HOLD. Ordinary baseline work may proceed; non-trivial method
disclosure may not.**

## Patent Gate 01-E - semantic reproduction

Repeated trials, success rates, semantic comparison, replay, and
counterfactual re-execution all have substantial adjacent prior art. Terminology
alone is not an invention.

Decision:

- Public now: the distinction between trace playback, controlled re-execution,
  and semantic reproduction; exact trial counts; confidence intervals; drift
  metadata; the predeclared protocol.
- **INVENTION-HOLD:** a new outcome-equivalence representation, cross-runtime
  state alignment, semantic-oracle construction, drift-normalization rule,
  sample-efficiency method, or calibrated reproduction estimator proposed as
  technically new.
- Existing standards and methods must be preferred when they solve the problem.
- Before publishing the proposed novel mechanism or Paper P4: complete an
  invention disclosure, prior-art search, counsel review, and founder decision.
- Any resulting public `.sova` compatibility/reproduction contract must remain
  independently implementable.

**Gate result: HOLD ON A NOVEL MECHANISM; PASS FOR OPEN TERMINOLOGY AND
EVALUATION PROTOCOL.**

## Other Topic 01 IP dispositions

| Area | Prior-art implication | Decision |
|---|---|---|
| Counterfactual attribution | Causal Agent Replay and other intervention/attribution work are direct prior art. | No broad patent/novelty claim. Compare methods. Hold only a specifically new security-layer mechanism. |
| Selective disclosure/redaction | SD-JWT and W3C selective-disclosure cryptosuites occupy the general concept. | Build on standards. Do not patent or claim generic selective disclosure. Review only trace-specific composition. |
| Signing/evidence envelopes | DSSE, Sigstore, in-toto, and supply-chain attestations are established. | Adopt/interoperate. No bespoke-crypto novelty claim. |
| Portable `.sova` format | Adjacent scenario, evaluation, and finding formats exist; open interoperability is the goal. | Defensive/open specification path; no historical “first format” claim. |
| Unified sensor mesh | Observability conventions and instrumentation ecosystems are dense. | Treat as engineering/research integration until a narrow measured invention is identified. |
| Scanner adjudication | Static scanners and dynamic exploit confirmation exist. | Product capability and empirical question, not assumed invention. |
| Phantom Fuzzer | Absolute uniqueness was not established. | Retire “unmatched”; review a concrete method only if implemented. |

## Required invention record

Before invention-hold material is shared outside the authorised private group,
record:

1. title and inventors/contributors;
2. problem and the narrow technical mechanism;
3. conception dates and supporting records;
4. closest patent and non-patent prior art;
5. differences from each reference;
6. experiments, alternatives, failed approaches, and enabling detail;
7. ownership, employment, contractor, grant, and third-party obligations;
8. open-source dependencies and contributor patent grants;
9. all previous disclosures, audiences, terms, and exact dates;
10. expected public SOVA OSS scope and private SOVA Engine scope;
11. safety, misuse, privacy, and coordinated-disclosure implications;
12. counsel’s advice and founder’s dated disposition.

The private invention ledger belongs under an ignored private path. Its
existence or a public decision may be acknowledged; its mechanism, search
notes, claims, and counsel communications must not enter this repository.

## Paper, release, and public-demo checklist

Every paper, preprint, dataset, benchmark release, public demo, promoted
executable release, and mechanism-bearing documentation change must answer:

### Claims and evidence

- [ ] Every factual/comparative/legal/market/novelty claim has an active claim
      register ID.
- [ ] No evidence is older than its recheck date.
- [ ] Comparative language cites a frozen protocol, exact targets, baselines,
      revisions, budgets, metrics, uncertainty, and run-bundle digest.
- [ ] Negative, failed, unsupported, and inconclusive results are preserved.
- [ ] “First,” “only,” “safe,” “clean,” “unforgeable,” “deterministic,” and
      unsupported percentages are absent or precisely qualified.
- [ ] Legal/compliance wording has qualified legal review where relied upon.

### IP and provenance

- [ ] All contributors and inventors are identified; DCO/provenance is complete.
- [ ] Patent and non-patent prior art was searched and recorded.
- [ ] Gates 01-C, 01-D, and 01-E were applied where relevant.
- [ ] Counsel’s written advice is recorded for any patentability conclusion.
- [ ] Third-party code, data, models, prompts, figures, benchmarks, and licences
      are inventoried and compatible with the intended distribution.
- [ ] The public artifact contains no invention-hold, trade-secret, confidential
      Atlas, client, private-corpus, or counsel-privileged material.

### Security, privacy, and disclosure

- [ ] All testing was authorised and within the recorded target scope.
- [ ] Fixtures are synthetic or have documented public provenance and consent.
- [ ] No live credential, endpoint, identity, personal data, or client content
      remains.
- [ ] Unpatched vulnerabilities completed coordinated disclosure under
      `SECURITY.md`.
- [ ] Exploit detail is the minimum needed for defensive reproduction.
- [ ] Redaction was verified and the limits of redacted proof are stated.
- [ ] Dual-use and misuse review is complete.

### Product and trust boundary

- [ ] Planned capabilities are not presented as released.
- [ ] SOVA output is labelled first-party self-assessment.
- [ ] No TRUSCOR attestation, certificate, score, legal conclusion, insurance,
      or regulator acceptance is implied.
- [ ] The public feature has no hidden dependency on SOVA Engine, a TRUSCOR
      service, or private data.
- [ ] Trademark, citation, attribution, and modified-fork rules are followed.

### Approval record

- [ ] Founder approval, scope, artifact digest, date, and release destination are
      recorded.
- [ ] Security/disclosure approval is recorded when a vulnerability is involved.
- [ ] IP/counsel approval is recorded when invention-hold or patent conclusions
      are involved.
- [ ] The repository boundary check and all relevant tests pass.

An unchecked required item blocks publication. “Not applicable” requires a
one-line reason and reviewer.

## Pull-request rule

A pull request must be stopped and moved to a private review channel when it:

- introduces a non-trivial search, replay, attribution, evidence, sensor-fusion,
  or redaction mechanism;
- publishes a real vulnerability or answer key;
- changes comparative or novelty language;
- adds a third-party dataset/model/benchmark without provenance;
- adds a legal or compliance conclusion;
- includes private traces, corpora, tuning, client data, or confidential
  external material.

Public review cannot be used to decide whether something should have been
public.

## Current publication record

As of 2026-07-29:

- the repository, README, high-level `.sova`/`.sova-trace` meanings, versioning
  invariants, project boundaries, and governance are already public;
- no implemented non-trivial trigger-search or semantic-replay mechanism is
  present in the repository;
- no SOVA comparative result exists;
- Gates 01-A and 01-B are **NOT RUN**;
- broad novelty claims are retired in the claims register;
- future mechanism-bearing disclosure is held by this policy.

This record does not determine patent rights. It prevents the project from
making the situation worse while qualified advice is obtained.
