<!-- status: implemented -->

# Methodology version ledger

`versions.toml` is the machine-readable index for every method that affects how
SOVA produces, compares, interprets, or publishes evidence.

A methodology change receives a new SemVer version when it changes inputs,
sampling, budgets, environment, oracle, judge, statistics, classification,
redaction, reproduction, attribution, or interpretation. Old versions remain
addressable so a finding can identify exactly how it was produced.

`frozen-unexecuted` means a protocol exists but no result has passed its gates.
It must never be rendered as a successful experiment.
