<!-- status: implemented -->

# Finding lifecycle

A finding never has one overloaded status. It carries five independent axes.
Every change appends an event containing previous state, next state, actor,
reason, time, method/tool version, and supporting references.

## Evidence axis

```text
candidate
  -> not-observed
  -> observed -> reproduced -> verified
  -> inconclusive

observed / reproduced / verified may become disputed
disputed or inconclusive may be resolved by new evidence
```

- `candidate`: a testable security hypothesis exists.
- `not-observed`: the outcome did not occur within the recorded conditions and
  budget; this never means safe.
- `observed`: qualifying behavior occurred in at least one run.
- `reproduced`: the outcome recurred under the declared reproduction method.
- `verified`: the named verification policy accepted the evidence and
  reproduction record.
- `inconclusive`: available evidence cannot support observed or not-observed.
- `disputed`: a material challenge to evidence, interpretation, or scope is
  unresolved.

## Disclosure axis

```text
confidential -> embargoed -> disclosed -> published
confidential -------------> disclosed
embargoed -----------------------------> published
```

- `confidential`: restricted to explicitly authorized recipients.
- `embargoed`: disclosure is coordinated but public release is time- or
  remediation-gated.
- `disclosed`: the affected party or defined recipients were notified.
- `published`: cleared public release occurred.

Disclosure says nothing about evidence strength.

## Remediation axis

```text
open -> fixed -> regressed -> fixed
```

`fixed` requires a named validation method and target version. A later
recurrence becomes `regressed`; the original observation remains historical.

## Adjudication axis

```text
not-required -> pending -> resolved
             -> scanner-disagreement -> pending/resolved
resolved ---------------------------> scanner-disagreement
```

A scanner result is an input. Agreement is not proof. Disagreement preserves
every source verdict, source version, target fingerprint, and adjudication run.

## Record axis

```text
active -> superseded
```

Supersession is one-way and requires a replacement finding ID plus a reason.
The old record remains addressable and immutable. Corrections, merges, splits,
scope changes, or materially changed conclusions create new findings and
supersession relationships.

## Common examples

| Situation | Evidence | Disclosure | Remediation | Adjudication | Record |
|---|---|---|---|---|---|
| New hypothesis | `candidate` | `confidential` | `open` | `not-required` | `active` |
| Bounded test did not fire | `not-observed` | `confidential` | `open` | `not-required` | `active` |
| Two scanners conflict | unchanged | unchanged | unchanged | `scanner-disagreement` | `active` |
| Independently reproduced and public | `verified` | `published` | `open` | `resolved` or `not-required` | `active` |
| Vendor fix validated | unchanged | unchanged | `fixed` | unchanged | `active` |
| Failure returns | unchanged or new evidence | unchanged | `regressed` | unchanged | `active` |
| Finding split after correction | historical | historical | historical | historical | `superseded` |

The executable transition table is in `sova.contracts.lifecycle`.
