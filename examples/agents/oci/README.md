# Contained external agent example

The example implements the complete `sova.oci-agent/0.1` protocol with no
dependencies. It intentionally proposes no browser action. Supply an immutable
digest-pinned Python base through `PYTHON_IMAGE`, build and publish the image,
then replace the placeholder image digest in `runtime.json` with the exact
published digest.

SOVA sends each bounded protocol request through container standard input; the
request is never placed in the host process command line. The image must accept
the fixed `--sova-request-stdin` flag and emit exactly one JSON response row.

Do not use a mutable base tag or a tag-only final image. `sova safety
attest-gvisor` and `sova agent conform-oci` must both pass on the execution host
before using the adapter in Arena.
