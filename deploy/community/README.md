# Internet deployment boundary

This directory is a hardened starting blueprint, not evidence of a production
deployment. Both container images must be supplied by immutable digest. The
edge proxy shares the registry container's network namespace so the Python
reference service remains bound to loopback; Caddy alone terminates TLS on
port 443.

Before an Internet deployment, an operator must add independently reviewed
identity and authorization, moderation, abuse handling, backups and restore
tests, monitoring, alert escalation, DDoS controls, key rotation, revocation,
privacy and retention policy, regional compliance, disaster recovery, and a
documented incident-response owner. Run it first with synthetic capsules only.

Never put a bearer token, private key, accepted trace, or client evidence in
this repository. Create `operator/service.token` with `sova registry
init-service`, create `operator/methodology.md`, and keep `operator/` outside
Git. Public hosting is an external acceptance gate until a real operator has
deployed, tested, and attested this stack.
