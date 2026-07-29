# SOVA OSS dual-use policy

- **Policy version:** 1.0
- **Effective date:** 2026-07-29
- **Status:** Founder-approved project governance

## Purpose

SOVA OSS is a defensive and research workbench with offensive capabilities. Those capabilities are intended to help authorized operators discover, reproduce, understand, and remediate security failures in AI-agent systems.

The same capabilities can be misused. This policy defines what the official SOVA OSS project will build, accept, publish, and support.

## Relationship to the licence

The source code is licensed under Apache-2.0. This governance policy does not add field-of-use restrictions to that licence and cannot revoke rights already granted under it.

The policy governs:

- contributions accepted by the official project;
- content accepted into the official registry;
- use of official project infrastructure and marks;
- maintainer support and disclosure handling;
- the safety architecture of official SOVA OSS releases.

## Authorized-use rule

Use offensive capabilities only against:

- systems you own;
- systems for which you hold explicit authorization from a person with authority to grant it;
- deliberately vulnerable research fixtures;
- public programmes whose published rules clearly authorize the exact testing.

Authorization must define target, time, technique, data handling, blast radius, third-party dependencies, and stop conditions. Installing SOVA OSS or possessing a `.sova` file is not authorization.

## Mandatory product controls

Official releases must enforce:

- self-owned target scope by default;
- explicit out-of-band human authorization for every `detonate`, `rehearse`, and `probe` invocation;
- no autonomous agent initiation of offensive MCP tools;
- declared blast-radius limits;
- non-destructive proof by default;
- hard stops for irreversible or out-of-scope effects;
- redaction at capture where sensitive observations are possible;
- local-only keys and no automatic telemetry;
- inert parsing, browsing, syncing, rendering, and verification;
- provenance and human review for public registry entries.

An acknowledgement checkbox by itself is not sufficient authorization for high-risk operation.

## Accepted official-project uses

- authorized security testing;
- defensive research and education;
- secure software development and CI;
- reproducibility and benchmark research;
- deliberately vulnerable demonstrations and CTFs;
- incident reconstruction on evidence the user may lawfully process;
- coordinated vulnerability disclosure;
- enterprise self-assessment;
- tool, model, and component comparison within authorized scope.

## Content the official project will reject

- payloads for an unpatched vulnerability;
- payloads targeting a named production organization or individual;
- credential theft, persistence, destructive action, extortion, or unauthorized access;
- mechanisms designed principally to evade attribution, authorization, or safety controls;
- private data, live tokens, private traces, or client findings;
- instructions that materially increase harm without a necessary defensive or reproducibility purpose;
- scenarios whose blast radius or cleanup cannot be bounded;
- registry entries without provenance and human review;
- contributions that weaken human authorization, self-only defaults, redaction, or non-destructive proof;
- automated uploading of targets, traces, findings, credentials, or tested content.

Public findings about third-party components are accepted only after the coordinated-disclosure requirements in `SECURITY.md` are satisfied.

## Registry rules

Every official registry submission must:

- be signed and provenance-recorded;
- identify author, source, version, disclosure state, and safety review;
- use a synthetic, patched, or explicitly authorized target;
- avoid live secrets and organization-specific identifiers;
- default to non-destructive proof;
- include cleanup and limitations;
- be reviewed by a human before merge.

The registry never auto-executes content. Sync is pull-only and transmits no user target or finding data.

## Research publication

Publish the minimum exploit detail needed for verification until affected users have a patch. Prefer:

- structural descriptions before weaponized payloads;
- deterministic safe canaries;
- patched or deliberately vulnerable fixtures;
- redacted evidence;
- reproducible defensive tests;
- staged release of high-risk technical detail.

Research must state authorization, ethics, limitations, and disclosure status.

## Enforcement by the official project

Maintainers may:

- reject or remove a contribution;
- withdraw or revoke an official registry entry;
- remove official-project access;
- decline support;
- add safety warnings or mitigations;
- coordinate privately with an affected vendor;
- report credible imminent harm where legally or ethically required.

These actions govern official project resources and do not revoke the Apache-2.0 licence.

## Legal review

This policy is a technical and community governance decision, not legal advice. Qualified Indian and relevant international counsel should review it before the first promoted release containing executable offensive capabilities or the first public registry submission.
