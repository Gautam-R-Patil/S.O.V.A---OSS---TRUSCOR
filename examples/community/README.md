# Self-hosted community and monitoring examples

`monitor-service.json` and `observations/` form a safe, working drift fixture.
The command intentionally returns a failed drift status because the current
snapshot contains a different declared behavior:

```console
sova monitor serve monitor-service.json ./.sova-monitor \
  --workspace ./observations --once
```

`leaderboard-metadata.json` contains deliberate placeholders. Replace them with
the exact standard-profile values and trace signing key from a completed local
Arena run, then prepare (but do not upload) a contribution:

```console
sova registry prepare-upload leaderboard-metadata.json case.sova \
  case.sova-trace upload.json --kind leaderboard
```

Initialize and start the loopback reference service only after pinning the
publisher/evidence key:

```console
sova registry init-service ./.sova-community/service.token
sova registry serve ./.sova-community/data \
  --token-file ./.sova-community/service.token \
  --trusted-key-id sha256:REPLACE_WITH_TRUSTED_EVIDENCE_KEY \
  --methodology ./arena-methodology.md
```

No example silently submits, uploads, exposes a non-loopback listener, or turns
an included signing key into an identity claim.
