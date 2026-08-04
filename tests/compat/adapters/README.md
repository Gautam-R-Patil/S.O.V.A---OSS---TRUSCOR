<!-- status: implemented -->

# Adapter compatibility

Each public executor or importer adapter must provide:

- a capability manifest;
- supported protocol and version ranges;
- deterministic scripted contract cases;
- unsupported-capability and timeout behavior;
- secret, cancellation, and partial-failure cases;
- fixtures with public provenance.

The core compatibility suite must run without Atlas or any hosted SOVA service.
