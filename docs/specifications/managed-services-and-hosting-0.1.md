<!-- status: implemented -->

# Managed monitoring and community hosting boundary 0.1

The monitor service can deliver a failed run through an HTTPS webhook. The
payload contains only job/run identity, status, trigger labels, and signed
trace digest. SOVA canonicalizes the payload, derives an idempotency key, signs
timestamp, key and body with HMAC-SHA256, retries within a fixed bound, and
marks delivery successful only when the receiver acknowledges the same key.
Secrets are resolved from an environment variable immediately before service
construction and never written to output.

Systemd, launchd, and WinSW supervision templates ship in `deploy/monitoring`.
The community blueprint uses immutable digest-supplied images, a non-root,
read-only, capability-free registry container, and a Caddy TLS edge sharing the
registry network namespace so the reference Python service remains loopback-
bound. The stack is a deployment starting point, not a production attestation.

Production acceptance requires a real operator, deployment identity,
moderation, backups and restore tests, availability measurement, abuse and
DDoS controls, key rotation/revocation, privacy and retention policy, incident
response, alert escalation, and independent security review. Those facts are
recorded through external acceptance receipts rather than source-code claims.
