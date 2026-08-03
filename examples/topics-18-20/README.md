# Topics 18-20 safe local example

These fixtures exercise only local, inert behavior. Copy `owned-fixture` to a
temporary directory before running the commands; the examples never contain a
credential or contact a service.

```bash
sova rehearse prepare ./examples/topics-18-20/owned-fixture ./tmp-rehearsal
sova rehearse run ./examples/topics-18-20/rehearsal.json ./tmp-rehearsal ./tmp.sova-trace ./tmp-report.json

sova trace snapshot ./examples/topics-18-20/baseline.json --output ./baseline.snapshot.json
sova trace snapshot ./examples/topics-18-20/regression.json --output ./regression.snapshot.json
sova ci ./baseline.snapshot.json ./regression.snapshot.json --sarif ./results.sarif
```

The CI command intentionally exits `1` because the fixture changes the declared
observable effect. That is a regression-policy result, not a newly discovered
security vulnerability.
