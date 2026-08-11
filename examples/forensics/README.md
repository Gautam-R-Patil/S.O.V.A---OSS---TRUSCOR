# Blinded causal-validation example

This example generates synthetic CPU-only data. It contacts no provider,
executes no agent, and establishes no real-system causal accuracy.

```console
sova forensics blind-fixture task.json .sova/private/answer-key.json
sova forensics blind-run task.json predictions.json
sova forensics blind-score task.json predictions.json \
  .sova/private/answer-key.json score.json
```

For a reviewer-key-pinned handoff, create and retain the private key outside
the repository:

```console
sova forensics blind-keygen .sova/private/reviewer.key reviewer.pub
sova forensics blind-sign-key .sova/private/answer-key.json \
  .sova/private/reviewer.key reviewer.pub signed-answer-key.json
sova forensics blind-score task.json predictions.json signed-answer-key.json \
  signed-score.json --reviewer-public-key reviewer.pub \
  --required-reviewer-key-id sha256:REVIEWER_PUBLIC_KEY_DIGEST
```

The task must be frozen before predictions; the answer key must not be
available to the prediction process. A key pin verifies only the signing key,
not reviewer identity, independence, or label correctness. Read the
[protocol](../../docs/specifications/blinded-causal-validation-0.1.md) before
constructing an external study.
