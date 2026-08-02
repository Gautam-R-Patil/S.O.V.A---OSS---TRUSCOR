<!-- status: implemented -->

# Experimental SOVA format specifications

The current schemas are experimental `0.1.0` formats. They freeze safety,
identity, type-separation, canonicalization, and migration invariants without
claiming that the field set is ready for `1.0`.

- [`.sova` behavior capsule](./sova-capsule-0.1.md)
- [`.sova-trace` event stream](./sova-trace-0.1.md)
- [migration and compatibility](./migration-and-compatibility.md)
- [interoperability and fidelity](./interoperability.md)
- [privacy and selective disclosure](./privacy-and-disclosure.md)
- [format threat model](./threat-model.md)
- [executor capability contract](./executor-contract-0.1.md)
- [observable oracles and declared-outcome comparison](./observable-oracles-0.1.md)
- [authorization and safety contract](./authorization-safety-0.1.md)
- [containment backend admission](./containment-backends-0.1.md)
- [synthetic detonation world](./synthetic-detonation-0.1.md)
- [MELRA executor adapter boundary](./melra-adapter-boundary-0.1.md)

The normative JSON Schema 2020-12 files ship in
[`src/sova/schemas`](../../src/sova/schemas/README.md). Python is the reference
implementation, not the specification. A conforming independent implementation
may use any language and must produce the same canonical bytes and validation
outcomes for the conformance corpus.

The schemas are immutable once included in a tagged release. Breaking
experimental changes receive a new schema version and an explicit migrator.
