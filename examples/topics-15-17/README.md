<!-- status: implemented -->

# Safe Topics 15–17 examples

These are inert synthetic inputs. They contain no credentials, real target data,
or working exploit payloads.

```console
sova forensics reconstruct examples/topics-15-17/external-events.json
sova forensics attribute examples/topics-15-17/counterfactual-study.json
sova forensics benchmark
sova evidence examples/topics-15-17/evidence.json --format technical
sova adjudicate plan examples/topics-15-17/adjudication-study.json
sova adjudicate evaluate examples/topics-15-17/adjudication-study.json
sova disclose examples/topics-15-17/disclosure-study.json
sova compose plan examples/topics-15-17/composition-graph.json --strategy trigger-aware-sequence
```

The evidence example deliberately references placeholder digests and marks them
unverified. `compose plan` never runs the target. Live observations require the
normal authorization, containment, oracle, and evidence gates before they may be
supplied to `compose evaluate`.
