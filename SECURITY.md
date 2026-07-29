# Security and coordinated disclosure

- **Policy version:** 1.0
- **Effective date:** 2026-07-29
- **Security contact:** [gautam@truscor.org](mailto:gautam@truscor.org)

## Report privately

Email `gautam@truscor.org` with the subject:

```text
[SOVA SECURITY] Short description
```

Include:

- affected SOVA version, commit, component, or artifact;
- impact and realistic attack conditions;
- minimal reproduction steps;
- whether exploitation is known or suspected in the wild;
- suggested mitigation, if known;
- your preferred name or handle for credit;
- any coordination constraints.

Do not send live credentials, unnecessary personal data, client traces, or third-party confidential material by ordinary email. Send a minimal report and request a safer exchange method when sensitive evidence is necessary.

Do not open a public issue for an unpatched vulnerability.

## Scope

This policy receives vulnerabilities in:

- SOVA OSS source and official releases;
- official schemas, parsers, migrators, verifiers, and renderers;
- official GitHub Actions and release processes;
- official SOVA registry artifacts when that registry launches;
- official deliberately vulnerable fixtures when the issue escapes their documented containment.

This policy does not authorize testing:

- `truscor.org`, XAGI Labs, Atlas infrastructure, or any network service;
- GitHub or another hosting provider;
- third-party agents, models, MCP servers, packages, or production systems;
- systems for which you lack explicit authorization.

Test SOVA OSS on systems you own or are explicitly authorized to test.

## Good-faith research

For research on in-scope SOVA OSS software that follows this policy, avoids privacy violations and service degradation, and makes a good-faith effort to minimize harm, the SOVA OSS maintainers will:

- receive and investigate the report;
- not recommend or pursue legal action merely because the researcher tested and reported in accordance with this policy;
- work to clarify accidental uncertainty about scope;
- recognize the reporter when requested and legally possible.

This statement applies only to rights the project maintainers can grant. It does not bind third parties or excuse violations of law or another party's rights.

## Response targets

The project aims to:

- acknowledge receipt within 3 business days;
- complete initial triage within 7 business days;
- provide a coordination update at least every 14 days while active;
- assign a security advisory or CVE through an appropriate CNA when warranted;
- credit reporters who request credit.

These are service targets, not guarantees. Complex multi-party cases may take longer.

## Embargo and disclosure timeline

The default coordinated-disclosure period is **90 calendar days** from delivery of a sufficiently detailed, reproducible report to the responsible vendor or project.

Earlier disclosure may occur when:

- a fix or effective mitigation is broadly available;
- the vendor and reporter agree;
- the vulnerability is already public;
- credible active exploitation makes continued silence more harmful.

If credible active exploitation exists, the project may use an accelerated deadline as short as **7 days**, while limiting released detail to what defenders need.

One extension of up to **14 days** may be granted when a specific fix is scheduled and the extension materially improves user safety. Multi-party supply-chain cases may use a documented alternative schedule consistent with FIRST coordination guidance.

At disclosure, publish:

- affected versions and impact;
- fixed versions or mitigations;
- credit and timeline;
- enough technical detail for defenders to validate exposure;
- a safe regression artifact when appropriate.

Do not publish a weaponized payload merely because a deadline expired. High-risk exploit detail may remain staged when defenders can act without it.

## Vulnerabilities found in third-party products

When SOVA discovers a vulnerability in another project:

1. Validate the result non-destructively.
2. Identify the responsible vendor or upstream maintainer.
3. Report privately through their published security channel.
4. Preserve evidence and the communication timeline.
5. Coordinate affected downstream parties when necessary.
6. Follow the 90-day default, 14-day limited extension, and active-exploitation exception above unless the vendor's reasonable published policy provides a safer compatible process.
7. Publish only after the coordinated-disclosure gate.

The official SOVA registry will not accept a payload for an unpatched vulnerability.

If coordination fails or affects many vendors, reporters should consider an experienced coordinator such as CERT/CC.

## Policy basis

This process is informed by:

- [CISA vulnerability-disclosure guidance](https://www.cisa.gov/news-events/news/cisa-issues-final-vulnerability-disclosure-policy-directive-federal-agencies);
- [CERT/CC vulnerability-disclosure guidance](https://www.kb.cert.org/vuls/guidance/);
- [FIRST multi-party vulnerability-coordination guidance](https://www.first.org/global/sigs/vulnerability-coordination/multiparty/guidelines-v1-1).

The deadlines above are the SOVA OSS project's selected coordination defaults, not statements imposed by those organizations.

## Security fixes

Security fixes should include:

- a regression test;
- affected and fixed version ranges;
- schema or migration implications;
- evidence of boundary and authorization behavior;
- advisory and CVE references where applicable;
- an audit for the same vulnerability class elsewhere.

## No automatic TRUSCOR submission

SOVA OSS never automatically uploads a target, trace, finding, credential, or report to TRUSCOR. Sending a report under this policy is a deliberate user action and does not create an attestation or commercial engagement.
