# Service-managed monitor templates

The systemd, launchd, and WinSW files are reviewable deployment templates.
Replace paths and endpoints, load `SOVA_ALERT_SECRET` through the platform's
secret manager, run under a dedicated low-privilege account, and validate on a
staging host before installation. Do not commit a populated environment file.

Each failed monitor run creates a signed local trace and sends a bounded HMAC
authenticated webhook. Delivery is successful only after the receiver returns
an acknowledgement containing the exact idempotency key. Supervision does not
turn snapshot comparison into total host observation or guarantee service
availability; those remain deployment acceptance gates.
