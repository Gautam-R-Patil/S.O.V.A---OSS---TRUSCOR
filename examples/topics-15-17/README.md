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

After generating a target manifest for a self-owned loopback service that
implements the declared selectors and harmless marker, the real intervention
lane is:

```console
sova forensics browser-counterfactual target.json examples/topics-15-17/browser-counterfactual-study.json ./browser-cf-output
```

This command is intentionally not an inert example: it requires a live owned
or control-proven target, a human-operated terminal, four fresh approval
batches, and the pinned browser dependencies. Edit the example origin to match
the controlled service before running it.

The evidence example deliberately references placeholder digests and marks them
unverified. `compose plan` never runs the target. Live observations require the
normal authorization, containment, oracle, and evidence gates before they may be
supplied to `compose evaluate`.
