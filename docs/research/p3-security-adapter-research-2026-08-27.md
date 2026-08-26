<!-- status: implemented -->

# P3 security-adapter research refresh — 2026-08-27

This record rechecked the primary upstream release, licence, output, privacy,
update, and failure seams used by SOVA's P3 catalog. It is an engineering
admission review, not a security audit or endorsement of any upstream project.
SOVA copied no upstream code, templates, rules, payloads, datasets, or prose.

## Result

No reviewed tool supplies SOVA's authorization, target ownership proof,
containment admission, oracle calibration, independent reproduction, or finding
truth. The safe integration seam is therefore:

1. exact operator-supplied executable bytes and captured version evidence;
2. a SOVA descriptor and digest-pinned configuration/rules/template input;
3. a fresh SOVA authority decision and disclosure gate before any effect;
4. shell-free execution through the existing executor contract;
5. bounded raw-output hashing and a versioned SOVA parser;
6. an unverified observation, never an automatically confirmed finding; and
7. cleanup plus a trace that preserves all decisive pins and failure states.

## Promoted catalog

| Adapter | Exact pin | Licence | Admitted output seam | Important limitation |
|---|---:|---|---|---|
| [OWASP ZAP](https://github.com/zaproxy/zaproxy/releases/tag/v2.17.0) | 2.17.0 | Apache-2.0 | JSON quick-scan report | Active scan requires separate offensive approval |
| [Nuclei](https://github.com/projectdiscovery/nuclei/releases/tag/v3.11.1) | 3.11.1 | MIT | JSONL export | Interactsh and updates disabled; templates pinned separately |
| [Nuclei templates](https://github.com/projectdiscovery/nuclei-templates/releases/tag/v10.4.7) | 10.4.7 / `83234ce` | MIT | reviewed local template tree | A template match remains an assertion |
| [Schemathesis](https://github.com/schemathesis/schemathesis/releases/tag/v4.24.3) | 4.24.3 | MIT | JUnit XML | Closed-object `$ref` edge case is declared inconclusive |
| [PyRIT](https://pypi.org/project/pyrit/1.0.1/) | 1.0.1 | MIT | SOVA-controlled JSON export seam | No invented stable PyRIT CLI is assumed |
| [garak](https://pypi.org/project/garak/0.16.0/) | 0.16.0 | Apache-2.0 | SOVA-controlled JSONL export seam | Pre-1.0; upstream acknowledges detector false positives |
| [promptfoo](https://www.npmjs.com/package/promptfoo/v/0.122.0) | 0.122.0 | MIT | JSON result export | Opt-out flags do not replace egress enforcement; Node 22.22+ |
| [Trivy](https://github.com/aquasecurity/trivy/releases/tag/v0.73.0) | 0.73.0 | Apache-2.0 | JSON | Offline DB required; never resolve through `latest` |
| [Syft](https://github.com/anchore/syft/releases/tag/v1.50.0) | 1.50.0 | Apache-2.0 | Syft JSON | Package inventory is informational, not a vulnerability |
| [Grype](https://github.com/anchore/grype/releases/tag/v0.116.1) | 0.116.1 | Apache-2.0 | JSON | Vulnerability DB snapshot must be separately pinned |
| [OSV-Scanner](https://github.com/google/osv-scanner/releases/tag/v2.4.0) | 2.4.0 | Apache-2.0 | JSON | Online lookup is not enabled implicitly |
| [Gitleaks](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1) | 8.30.1 | MIT | JSON | Secret and match values are excluded from normalized metadata |
| [Semgrep CE](https://github.com/semgrep/semgrep/releases/tag/v1.164.0) | 1.164.0 | LGPL-2.1-only | JSON | External CLI only; local reviewed rules only |

Trivy received an additional supply-chain control because its maintainers
documented a March 2026 release compromise involving malicious `v0.69.4`
artifacts. SOVA's descriptor never uses a floating version, disables implicit
database updates, and requires hashing the exact runtime executable. This
reduces one known route; it does not prove an artifact benign.

## Constrained catalog

| Adapter | Pin | Admission condition |
|---|---:|---|
| [ffuf](https://github.com/ffuf/ffuf/releases/tag/v2.1.0) | 2.1.0 | explicit opt-in, exact wordlist digest, request/rate bounds |
| [httpx](https://github.com/projectdiscovery/httpx/releases/tag/v1.9.0) | 1.9.0 | explicit destination and probe policy |
| [testssl.sh](https://github.com/testssl/testssl.sh/releases/tag/v3.2.3) | 3.2.3 | exact TLS endpoint, JSON output, batch mode |
| [sqlmap](https://github.com/sqlmapproject/sqlmap/blob/master/doc/CHANGELOG.md) | 1.10 | explicit offensive approval, owned fixture, licence review |
| [mitmproxy](https://github.com/mitmproxy/mitmproxy/releases/tag/v12.2.3) | 12.2.3 | per-run config/CA isolation; captured traffic is sensitive |
| [zgrab2](https://github.com/zmap/zgrab2/releases/tag/v1.0.0) | 1.0.0 | selected pre-auth handshakes with rate/time bounds |

Generic MCP stdio and HTTP producer descriptors are constrained transports.
Their declared schemas, summaries, and evidence references begin untrusted.

## Legal hold

[Nmap's NPSL](https://nmap.org/npsl/) and
[Npcap distribution terms](https://nmap.org/npcap/oem/) require qualified,
use-specific review before SOVA ships or redistributes a designed wrapper or
binary. The catalog record is therefore `legal-hold`: SOVA does not install,
redistribute, or execute it through the P3 runner.

## Privacy and update findings

- promptfoo runs with telemetry, remote generation, red-team remote generation,
  and sharing disabled. These controls are process configuration, not a network
  sandbox.
- Nuclei runs without Interactsh or automatic template/update resolution.
- Trivy uses offline scanning and no database updates.
- Syft and Grype disable application/update checks; Grype DB auto-update is off.
- Semgrep disables metrics and version checks and accepts only a local
  digest-pinned ruleset.
- all network/provider descriptors require an allowed disclosure decision whose
  target, destination, ID, and digest match the invocation before an
  authorization proposal can be built.

## Rejected shortcuts

- No wholesale adoption of an autonomous pentest framework: its agent plan and
  scanner verdict would create a second authority and evidence model.
- No shell command strings, container images tagged `latest`, implicit template
  downloads, or automatic upstream rule resolution.
- No scanner-success/failure exit code translated directly into a vulnerability.
- No provider score, MCP schema, summary, or evidence URL trusted at face value.
- No claim that parsing a synthetic fixture proves live tool interoperability,
  target coverage, vulnerability absence, or production containment.

## Implemented evidence

The catalog, contracts, parser set, runner, public schemas, CLI, and tests are
defined in `src/sova/adapters`, `src/sova/schemas`, and
`tests/unit/test_security_adapter_*`. The implementation tests every promoted
parser and the common policy-routed runner against corruption, timeout,
partial output, version drift, nondeterminism, false-positive separation, and
cleanup failure. The owned fixtures validate the integration contract; live
upstream binary lanes remain operator/deployment evidence, not a repository
claim.
