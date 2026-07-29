<!-- status: implemented -->

# SOVA domain model

The generated [glossary](../glossary.md) is normative. This document explains
how its concepts fit together.

## System-under-test layer

An **agent** selects actions toward a goal. A **model** produces model outputs;
it is not automatically an agent. A **component** is the general inventory
unit. MCP servers, skills, plugins, sub-agents, and tools are distinct component
kinds because they create different trust and execution boundaries.

A **target** is the exact system under authorized evaluation. A **target
manifest** declares how SOVA identifies and connects to it, but grants no
authority. “Owned,” “public,” and “bundled” describe provenance and control,
not permission to test; every active run still needs authorization.

Capabilities describe possible operations. Permissions grant authority to
attempt operations. Identity says which principal acts. An approval gate is a
human or policy decision required before a consequential action. Effects are
observed or attempted state changes. Egress crosses a declared boundary.
Transitive reach records what becomes reachable through delegation or chaining,
not only what a component touches directly.

## Experiment layer

An attack is an authorized test strategy. Conditions are predicates over input,
history, identity, time, environment, and state. A trigger is a condition or
conjunction whose satisfaction changes security-relevant behavior. Mutations
make controlled changes. Sequences order interactions.

An attempt is one proposed trial. A run is its realized, bounded execution
under one interpretation context. A campaign groups related runs without
merging their evidence or authorization.

## Measurement and conclusion layer

An observation records what a sensor measured. An oracle applies an explicit,
preferably deterministic rule. A judge is a separately versioned evaluator
used where a deterministic oracle is insufficient. Their output is a verdict
about a run; it is not yet a finding.

A finding is the versioned security conclusion that cites immutable scenarios
and traces. Severity estimates seriousness under a named rubric. Harm describes
the adverse effect. Confidence describes evidential support under a named
method. None of the three substitutes for the others.

## Evidence layer

Evidence is material offered to support or challenge a proposition. A trace is
the canonical inert record of one run. An artifact is any bounded persisted
object. Provenance records origin and custody. A signature authenticates bytes
under a trust policy, not their truth. A timestamp records time under a named
clock or timestamp authority. Redaction transforms or removes protected
content. A commitment permits later integrity checks about concealed content.

## Reproduction and forensics layer

Playback inspects recorded evidence without executing the target. Controlled
re-execution starts a fresh run under pinned or explicitly equivalent
conditions. Semantic reproduction asks whether the same material security
outcome recurs. Its rate always states successes, eligible trials, exclusions,
method, and uncertainty.

Reconstruction orders supported events. A decision point is a state where an
alternative could change the outcome. A hypothesis is testable. An intervention
changes one declared factor. A counterfactual compares the intervention with
the baseline. Attribution is a bounded, uncertainty-bearing causal conclusion,
not a narrative guess.

## Comparability layer

A standard profile contains the complete active native taxonomy for one exact
version and methodology. A custom profile is valid but explicitly
non-comparable. Taxonomy versions classify attacks; methodology versions define
how tests and measurements were performed. Observed coverage reports only the
frozen declared surfaces actually exercised.
