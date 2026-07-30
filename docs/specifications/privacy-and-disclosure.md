<!-- status: implemented -->

# Privacy, redaction, and selective disclosure

## Default

The recorder never snapshots the raw process environment. It captures only a
small allowlist of non-secret operational fields. Key names such as token,
secret, password, credential, cookie, authorization, session, and API key are
redacted before persistence. Common secret-shaped values are also detected.

The default placeholder is typed structural omission:

```json
{"$redacted":{"class":"credential","encoding":"sova-canonical-json/0.1","method":"omitted","present":true}}
```

The corresponding event records the path, data class, and method.

## Strategies

| Strategy | Use | Risk |
|---|---|---|
| Omission | Default sharing and unknown sensitivity | Cannot later prove exact concealed bytes |
| Keyed commitment | Private equality checks inside one declared context | Key handling, path leakage, and equality correlation |
| Encryption | Recoverable sealed data for authorized recipients | Key distribution, metadata leakage, future compromise |
| Masking | Human review only | Often leaks length, prefix, or structure |
| Selective disclosure | Future signed-claim profiles | Complexity and incomplete ecosystem support |

Unkeyed hashes of secrets are prohibited because low-entropy values are
vulnerable to dictionary recovery. Keyed commitments are opt-in, domain
separated, bound to canonical type/path/value bytes, and use a context-derived
key. The reference implementation rejects keys shorter than 32 bytes; callers
must generate high-entropy key material rather than deriving it from a
password. Key length does not make a low-entropy source value undiscoverable
if the key is compromised. The key is never stored in the trace. Commitments
are private comparison tokens, not public selective-disclosure proofs.

Encrypted placeholders use AES-256-GCM over canonical JSON with policy, class,
encoding, and path as authenticated data. They are explicitly marked as
recoverable sensitive data. Encryption is not described as deletion,
anonymization, or redaction, and public export should omit sealed blocks unless
the recipient/key policy is explicit.

## Export review

Before public export, the operator reviews prompts, responses, tool arguments,
results, URLs, headers, files, model metadata, identities, filenames, and
attachments. The trace states whether review occurred. SOVA does not upload a
trace or capsule automatically.

The reference reader can create an unsigned selective review view containing
chosen event sequences with payloads included or omitted. The view names the
source manifest digest and all omissions. It is not a cryptographic
selective-disclosure proof and must not be represented as independently
verified without the source trace.

The offline redaction verifier checks that every durable placeholder has a
matching record and fails on residual secret-shaped fields or values. This is a
best-effort structural check, not proof that arbitrary secrets cannot enter a
trace.

Retention is operator-controlled and local. Withdrawal metadata cannot recall
copies already shared. Redaction does not make a dataset anonymous, guarantee
regulatory compliance, or establish consent.

The current reference redactor supports AES-256-GCM placeholders through the
optional signing/cryptography extra. The key is never stored in the trace.
Cryptographic selective-disclosure proofs are not yet implemented; that remains
an explicit extension gate rather than an implied capability.
