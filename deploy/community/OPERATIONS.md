# Registry beta operations and receipts

This is an operator checklist, not a deployment receipt. The reference service
continues to bind to loopback behind the edge proxy. A public beta additionally
requires an independently reviewed OIDC/OAuth2 identity-aware proxy or equivalent
authorization layer; the repository's shared service token is not sufficient
Internet-facing identity.

## Required ten-control receipt set

For the exact release commit, artifact manifest, policy digest, authorized receipt
issuer, and production environment, retain one immutable receipt for each control:

1. authentication and authorization, including negative role tests;
2. moderation and abuse handling, including two-person publication control;
3. malware screening with exact engine, version, and signature digest;
4. secret and private-context screening;
5. application and edge rate/DDoS controls;
6. encrypted off-host backup;
7. restore into a clean environment with measured RPO/RTO;
8. rollback to the exact previous image digest;
9. incident-response exercise with a named owner; and
10. monitoring, alert delivery, acknowledgement, and escalation.

`RegistryBetaPolicy`, `OperationalReceipt`, and `evaluate_registry_beta` reject
missing, duplicated, failed, synthetic, non-production, wrong-policy, and
wrong-artifact or unauthorized-issuer receipts. Only all ten exact production receipts permit the beta
readiness result to become true.

Each production receipt is serialized as `sova.registry-operational-receipt`,
signed with `sova release sign-evidence`, and admitted only when the signer key is
assigned the `registry-operator` role in the separately reviewed launch trust
policy. Keep that policy digest outside the assembled bundle and pass it explicitly
to `sova release dossier`; an included key or included policy alone establishes no
operator identity.

Use `sova release assemble-evidence` to combine the separately reviewed policy,
protocol, candidate, signed observation ledger, and repeated operational, review,
and launch-gate receipts. Assembly checks strict structure and emits a deterministic
bundle but deliberately does not claim signature verification; `release dossier`
performs cryptographic verification and recomputes the launch decision.
When the result is `hold`, use `registrySummary`, `reviewSummary`,
`externalGates`, and sorted `holdReasons` from the dossier as the exact remediation
queue. A missing or failed control remains visible; it is never collapsed into a
generic readiness boolean.

## Local backup and restore rehearsal

Create a deterministic snapshot outside the Registry data root:

```console
python scripts/registry_backup.py create ABSOLUTE_DATA_ROOT ABSOLUTE_BACKUP.zip
python scripts/registry_backup.py verify ABSOLUTE_BACKUP.zip
python scripts/registry_backup.py restore ABSOLUTE_BACKUP.zip ABSOLUTE_EMPTY_RESTORE_ROOT
```

The snapshot tool rejects symlinks, traversal, duplicates, undeclared content,
digest drift, size/file-count bombs, non-empty restore destinations, and overwrite.
It does **not** encrypt archives and therefore always emits
`productionBackupReceipt=false`. Encrypt the verified archive with an
operator-approved system before off-host storage, then test decryption and restore.

## Rollback exercise

- Freeze the failing release commit, artifact manifest, images, and first alert.
- Disable uploads while preserving read-only evidence access where safe.
- Start the previous digest-pinned images; never roll back to a tag.
- Restore only when data compatibility and integrity checks pass.
- Verify health, signed index, authentication, moderation queue, and a synthetic
  upload before reopening traffic.
- Record decision owner, duration, evidence digest, data loss, and follow-up issue.

## Incident exercise

- Assign commander, security lead, communications lead, and evidence custodian.
- Revoke service and signing credentials without deleting forensic evidence.
- Preserve logs, indexes, receipts, and affected immutable objects.
- Classify privacy, malware, secret, containment, and integrity impact separately.
- Follow `SECURITY.md` for coordinated disclosure.
- Record detection, acknowledgement, containment, recovery, and notification times.

No public deployment, backup, restore, rollback, or incident exercise has been
performed merely because these contracts and runbooks exist.
