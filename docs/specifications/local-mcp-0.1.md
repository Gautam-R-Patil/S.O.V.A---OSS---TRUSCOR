<!-- status: implemented -->

# Local MCP and human authorization 0.1

## Surface

`sova mcp serve` is an MCP `2025-11-25` stdio server. It requires a pinned
workspace, evidence directory, out-of-workspace control directory, and local
control key. It opens no listener and needs no account.

Safe tools:

- `sova.map` (requires startup consent because workspace structure is sensitive);
- `sova.check`;
- `sova.verify`;
- `sova.forensics`;
- `sova.registry.search`.

Gated tools:

- `sova.detonate`;
- `sova.rehearse`;
- `sova.probe`.

There is no `approve` tool. Unknown fields fail JSON Schema validation. MCP tool
annotations describe side effects but never grant authority.

## Control flow

```text
agent tools/call
  -> canonical exact invocation descriptor
  -> denial trace + five-minute challenge
  -> human reviews effects in separate terminal
  -> exact phrase + explicit YES
  -> HMAC-bound token outside workspace
  -> same invocation consumes token once
  -> execution + signed authorization trace
```

Changing the target, arguments, action, limit, duration, or scope changes the
digest and invalidates approval. Tokens expire and consumed tokens cannot be
replayed. The control key is never printed or returned over MCP.

## Commands

```console
sova mcp init-control C:/secure/sova-mcp/control.key
sova mcp serve --workspace ./fixture --evidence-dir ./fixture/evidence \
  --control-dir C:/secure/sova-mcp/control \
  --key-file C:/secure/sova-mcp/control.key
sova mcp approve CHALLENGE_ID --workspace ./fixture \
  --control-dir C:/secure/sova-mcp/control \
  --key-file C:/secure/sova-mcp/control.key
sova check --self
```

`sova check --self` compares the generated tool contract with the release pin,
confirms all three gated tools remain gated, and confirms that no MCP approval
tool exists. Release candidates add SHA-256 checksums and GitHub/Sigstore build
provenance; that attestation is separate from SOVA runtime authorization.

## Threat boundary

The tested attacker controls prompts, model output, MCP arguments, and data in
legitimate string fields. The attacker does not control the separate terminal,
control key, control directory, or human. The design mitigates autonomous
approval, scope widening, expiry bypass, token replay, undeclared arguments,
path escape, and tool-description drift. It does not protect a compromised
human account, compromised host, stolen control key, malicious approved target,
or side effects omitted by an executor.

Normative upstream: [MCP tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools),
[MCP elicitation](https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation),
and [MCP transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports).
