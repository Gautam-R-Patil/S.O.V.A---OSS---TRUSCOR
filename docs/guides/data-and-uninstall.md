<!-- status: implemented -->

# Local data and removal

SOVA has no automatic telemetry or hosted account. A directory created by
`sova init` contains configuration, evidence, artifacts, registry cache,
temporary working data, and an out-of-band control key.

Preview deletion using the exact instance ID printed by `init` or `doctor`:

```console
sova data delete PATH --instance-id sova-instance-...
```

After review, perform irreversible deletion:

```console
sova data delete PATH --instance-id sova-instance-... --yes
```

The command refuses filesystem roots, the user home, symlinked managed data,
identity mismatches, excessive trees, and unknown top-level entries. It does
not use a recycle bin; confirmed deletion is not recoverable. Move any unknown
entry out of the directory before retrying.

Removing the Python environment does not remove separately chosen output
directories. Review and delete them under your own retention policy.
