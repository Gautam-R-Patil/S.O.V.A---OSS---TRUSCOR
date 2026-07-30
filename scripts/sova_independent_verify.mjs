#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * Dependency-free Node.js verifier implemented independently from the Python
 * SOVA package. It never executes capsule content.
 */

import fs from "node:fs";
import crypto from "node:crypto";
import zlib from "node:zlib";

const MAX_ENTRIES = 4096;
const MAX_ENTRY_BYTES = 256 * 1024 * 1024;
const MAX_TOTAL_BYTES = 1024 * 1024 * 1024;
const MAX_RATIO = 200;
const MIN_RATIO_CHECK_BYTES = 1024;
const MAX_JSON_BYTES = 8 * 1024 * 1024;
const SHA256 = /^sha256:[0-9a-f]{64}$/u;
const REDACTION_METHODS = new Set([
  "omitted",
  "keyed-commitment",
  "encrypted",
  "masked",
]);
const PAYLOAD_TYPE = "application/vnd.in-toto+json";
const PREDICATE_TYPE = "https://sova-oss.org/attestation/trace/v0.1";
const STATEMENT_TYPE = "https://in-toto.io/Statement/v1";
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const CRC32_TABLE = Array.from({ length: 256 }, (_, value) => {
  let remainder = value;
  for (let bit = 0; bit < 8; bit += 1) {
    remainder =
      (remainder & 1) === 1 ? 0xedb88320 ^ (remainder >>> 1) : remainder >>> 1;
  }
  return remainder >>> 0;
});

class VerificationError extends Error {}

function digest(data) {
  return `sha256:${crypto.createHash("sha256").update(data).digest("hex")}`;
}

function crc32(data) {
  let value = 0xffffffff;
  for (const byte of data) {
    value = CRC32_TABLE[(value ^ byte) & 0xff] ^ (value >>> 8);
  }
  return (value ^ 0xffffffff) >>> 0;
}

function validUnicode(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new VerificationError("lone high surrogate in canonical JSON");
      }
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new VerificationError("lone low surrogate in canonical JSON");
    }
  }
}

function canonical(value) {
  if (value === null || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new VerificationError("number outside SOVA I-JSON integer subset");
    }
    return String(value);
  }
  if (typeof value === "string") {
    validUnicode(value);
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonical(item)).join(",")}]`;
  }
  if (typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${canonical(key)}:${canonical(value[key])}`)
      .join(",")}}`;
  }
  throw new VerificationError("non-JSON canonical value");
}

function parseCanonical(raw, label) {
  if (raw.length > MAX_JSON_BYTES) {
    throw new VerificationError(`${label} exceeds JSON byte limit`);
  }
  let value;
  try {
    value = JSON.parse(raw.toString("utf8"));
  } catch {
    throw new VerificationError(`${label} is invalid UTF-8 JSON`);
  }
  if (!Buffer.from(canonical(value), "utf8").equals(raw)) {
    throw new VerificationError(`${label} is not canonical SOVA JSON`);
  }
  return value;
}

function safePath(value) {
  if (
    !value ||
    value.startsWith("/") ||
    value.includes("\\") ||
    value.includes("\0") ||
    value.split("/").some((part) => !part || part === "." || part === "..")
  ) {
    throw new VerificationError(`unsafe package path: ${JSON.stringify(value)}`);
  }
}

function findEocd(data) {
  if (data.length < 22) {
    throw new VerificationError("ZIP archive is too short");
  }
  const minimum = Math.max(0, data.length - 65557);
  for (let offset = data.length - 22; offset >= minimum; offset -= 1) {
    if (data.readUInt32LE(offset) === 0x06054b50) return offset;
  }
  throw new VerificationError("ZIP end-of-central-directory record missing");
}

function archive(path) {
  const data = fs.readFileSync(path);
  const eocd = findEocd(data);
  const disk = data.readUInt16LE(eocd + 4);
  const centralDisk = data.readUInt16LE(eocd + 6);
  const diskEntries = data.readUInt16LE(eocd + 8);
  const entries = data.readUInt16LE(eocd + 10);
  const centralSize = data.readUInt32LE(eocd + 12);
  const centralOffset = data.readUInt32LE(eocd + 16);
  const commentLength = data.readUInt16LE(eocd + 20);
  if (
    disk !== 0 ||
    centralDisk !== 0 ||
    diskEntries !== entries ||
    entries < 1 ||
    entries > MAX_ENTRIES
  ) {
    throw new VerificationError("unsupported ZIP disk or entry count");
  }
  if (eocd + 22 + commentLength !== data.length) {
    throw new VerificationError("ZIP end record does not terminate the archive");
  }
  if (centralOffset + centralSize !== eocd) {
    throw new VerificationError("invalid ZIP central-directory bounds");
  }

  const members = new Map();
  let total = 0;
  let cursor = centralOffset;
  for (let index = 0; index < entries; index += 1) {
    if (cursor + 46 > centralOffset + centralSize) {
      throw new VerificationError("truncated ZIP central-directory entry");
    }
    if (data.readUInt32LE(cursor) !== 0x02014b50) {
      throw new VerificationError("malformed ZIP central-directory entry");
    }
    const flags = data.readUInt16LE(cursor + 8);
    const method = data.readUInt16LE(cursor + 10);
    const expectedCrc = data.readUInt32LE(cursor + 16);
    const compressedSize = data.readUInt32LE(cursor + 20);
    const size = data.readUInt32LE(cursor + 24);
    const nameLength = data.readUInt16LE(cursor + 28);
    const extraLength = data.readUInt16LE(cursor + 30);
    const commentLength = data.readUInt16LE(cursor + 32);
    const externalAttributes = data.readUInt32LE(cursor + 38);
    const localOffset = data.readUInt32LE(cursor + 42);
    const centralEnd = cursor + 46 + nameLength + extraLength + commentLength;
    if (centralEnd > centralOffset + centralSize) {
      throw new VerificationError("ZIP central-directory entry exceeds its bounds");
    }
    const name = data.subarray(cursor + 46, cursor + 46 + nameLength).toString("utf8");
    safePath(name);
    if (members.has(name)) throw new VerificationError("duplicate archive member");
    if ((flags & 0x1) !== 0) throw new VerificationError("encrypted ZIP entry");
    if (![0, 8].includes(method)) throw new VerificationError("unsupported ZIP compression");
    if (size > MAX_ENTRY_BYTES) throw new VerificationError("archive member too large");
    if (
      size > MIN_RATIO_CHECK_BYTES &&
      (compressedSize === 0 || size / compressedSize > MAX_RATIO)
    ) {
      throw new VerificationError("unsafe ZIP compression ratio");
    }
    const unixMode = externalAttributes >>> 16;
    if ((unixMode & 0o170000) !== 0 && (unixMode & 0o170000) !== 0o100000) {
      throw new VerificationError("special ZIP member");
    }
    if (
      localOffset >= centralOffset ||
      localOffset + 30 > centralOffset ||
      data.readUInt32LE(localOffset) !== 0x04034b50
    ) {
      throw new VerificationError("malformed ZIP local header");
    }
    const localFlags = data.readUInt16LE(localOffset + 6);
    const localMethod = data.readUInt16LE(localOffset + 8);
    const localCrc = data.readUInt32LE(localOffset + 14);
    const localCompressedSize = data.readUInt32LE(localOffset + 18);
    const localSize = data.readUInt32LE(localOffset + 22);
    if (localFlags !== flags || localMethod !== method) {
      throw new VerificationError("ZIP local and central metadata differ");
    }
    if (
      (flags & 0x8) === 0 &&
      (localCrc !== expectedCrc ||
        localCompressedSize !== compressedSize ||
        localSize !== size)
    ) {
      throw new VerificationError("ZIP local and central sizes or CRC differ");
    }
    const localNameLength = data.readUInt16LE(localOffset + 26);
    const localExtraLength = data.readUInt16LE(localOffset + 28);
    const localNameStart = localOffset + 30;
    const localNameEnd = localNameStart + localNameLength;
    if (
      localNameEnd + localExtraLength > data.length ||
      !data
        .subarray(localNameStart, localNameEnd)
        .equals(data.subarray(cursor + 46, cursor + 46 + nameLength))
    ) {
      throw new VerificationError("ZIP local and central filenames differ");
    }
    const start = localOffset + 30 + localNameLength + localExtraLength;
    const end = start + compressedSize;
    if (end > centralOffset) throw new VerificationError("ZIP member exceeds data region");
    const compressed = data.subarray(start, end);
    let content;
    try {
      content = method === 0 ? Buffer.from(compressed) : zlib.inflateRawSync(compressed);
    } catch {
      throw new VerificationError("ZIP member decompression failed");
    }
    if (content.length !== size) throw new VerificationError("ZIP size mismatch");
    if (crc32(content) !== expectedCrc) throw new VerificationError("ZIP CRC mismatch");
    total += content.length;
    if (total > MAX_TOTAL_BYTES) throw new VerificationError("archive total size exceeded");
    members.set(name, content);
    cursor = centralEnd;
  }
  if (cursor !== centralOffset + centralSize) {
    throw new VerificationError("ZIP central-directory length mismatch");
  }
  if (!members.has("manifest.json")) {
    throw new VerificationError("manifest.json missing");
  }
  return { members, packageBytes: data };
}

function descriptors(manifest, members) {
  if (!Array.isArray(manifest.objects)) {
    throw new VerificationError("manifest object index is not an array");
  }
  const declared = new Set();
  for (const item of manifest.objects) {
    if (
      typeof item !== "object" ||
      item === null ||
      Object.keys(item).sort().join(",") !== "digest,mediaType,path,role,size"
    ) {
      throw new VerificationError("malformed object descriptor");
    }
    safePath(item.path);
    if (declared.has(item.path)) throw new VerificationError("duplicate descriptor path");
    declared.add(item.path);
    const data = members.get(item.path);
    if (
      !Buffer.isBuffer(data) ||
      !Number.isSafeInteger(item.size) ||
      item.size !== data.length ||
      typeof item.digest !== "string" ||
      !SHA256.test(item.digest) ||
      digest(data) !== item.digest
    ) {
      throw new VerificationError("object descriptor integrity mismatch");
    }
  }
  const actual = [...members.keys()].filter((name) => name !== "manifest.json").sort();
  if (actual.join("\0") !== [...declared].sort().join("\0")) {
    throw new VerificationError("manifest/archive object-index mismatch");
  }
  return manifest.objects;
}

function redactions(value, path = "$") {
  const found = [];
  if (value && typeof value === "object" && !Array.isArray(value)) {
    if (Object.hasOwn(value, "$redacted")) {
      const marker = value.$redacted;
      if (
        !marker ||
        marker.present !== true ||
        !["class", "method", "encoding"].every((field) => typeof marker[field] === "string")
      ) {
        throw new VerificationError("malformed redaction placeholder");
      }
      return [[path, marker.class, marker.method]];
    }
    for (const [name, child] of Object.entries(value)) {
      found.push(...redactions(child, `${path}.${name}`));
    }
  } else if (Array.isArray(value)) {
    value.forEach((child, index) => found.push(...redactions(child, `${path}[${index}]`)));
  }
  return found;
}

function redactionRecords(event) {
  if (!Array.isArray(event.redactions)) {
    throw new VerificationError("event redactions are not an array");
  }
  return event.redactions
    .map((item) => {
      if (
        !item ||
        typeof item !== "object" ||
        Object.keys(item).sort().join(",") !== "class,method,path" ||
        typeof item.path !== "string" ||
        item.path.length === 0 ||
        typeof item.class !== "string" ||
        item.class.length === 0 ||
        !REDACTION_METHODS.has(item.method)
      ) {
        throw new VerificationError("malformed redaction record");
      }
      return [item.path, item.class, item.method];
    })
    .sort();
}

function trace(manifest, objectIndex, members) {
  const segments = objectIndex
    .filter((item) => item.role === "event-segment")
    .sort((left, right) => left.path.localeCompare(right.path));
  let sequence = 0;
  let previous = null;
  for (const descriptor of segments) {
    const raw = members.get(descriptor.path);
    const lines = raw.toString("utf8").split("\n");
    if (lines.at(-1) !== "") {
      throw new VerificationError("event segment lacks final newline");
    }
    for (const line of lines.slice(0, -1)) {
      if (!line) continue;
      const encoded = Buffer.from(line, "utf8");
      const event = parseCanonical(encoded, "event");
      if (event.sequence !== sequence || event.previousHash !== previous) {
        throw new VerificationError("event sequence/hash-chain link mismatch");
      }
      const claimed = event.eventHash;
      const unsigned = { ...event };
      delete unsigned.eventHash;
      if (typeof claimed !== "string" || digest(Buffer.from(canonical(unsigned))) !== claimed) {
        throw new VerificationError("event hash mismatch");
      }
      const records = redactionRecords(event);
      if (JSON.stringify(records) !== JSON.stringify(redactions(event.payload).sort())) {
        throw new VerificationError("redaction record/placeholder mismatch");
      }
      previous = claimed;
      sequence += 1;
    }
  }
  if (manifest.eventCount !== sequence || manifest.chainRoot !== previous) {
    throw new VerificationError("trace manifest chain root/count mismatch");
  }
  const expected = manifest.integrity?.manifestDigest;
  const unsignedManifest = structuredClone(manifest);
  unsignedManifest.integrity.manifestDigest = null;
  unsignedManifest.integrity.signature = null;
  if (expected !== digest(Buffer.from(canonical(unsignedManifest)))) {
    throw new VerificationError("trace manifest digest mismatch");
  }
  return sequence;
}

function decodeBase64(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/u.test(value)) {
    throw new VerificationError("invalid signature base64");
  }
  const decoded = Buffer.from(value, "base64");
  if (decoded.toString("base64") !== value) {
    throw new VerificationError("non-canonical signature base64");
  }
  return decoded;
}

function pae(payloadType, payload) {
  const type = Buffer.from(payloadType);
  return Buffer.concat([
    Buffer.from(`DSSEv1 ${type.length} `),
    type,
    Buffer.from(` ${payload.length} `),
    payload,
  ]);
}

function unsignedManifestDigest(manifest) {
  const value = structuredClone(manifest);
  value.integrity.manifestDigest = null;
  value.integrity.signature = null;
  return digest(Buffer.from(canonical(value)));
}

function signature(manifest, requiredKeyId) {
  const material = manifest.integrity?.signature;
  if (!material || typeof material !== "object") {
    throw new VerificationError("trace signature is required but absent");
  }
  const envelope = material.envelope;
  const publicKey = material.publicKey;
  if (
    !envelope ||
    Object.keys(envelope).sort().join(",") !== "payload,payloadType,signatures" ||
    envelope.payloadType !== PAYLOAD_TYPE ||
    !Array.isArray(envelope.signatures) ||
    envelope.signatures.length !== 1 ||
    publicKey?.algorithm !== "ed25519"
  ) {
    throw new VerificationError("unsupported or malformed DSSE envelope");
  }
  const item = envelope.signatures[0];
  if (
    !item ||
    typeof item !== "object" ||
    Object.keys(item).sort().join(",") !== "keyid,sig" ||
    !publicKey ||
    typeof publicKey !== "object" ||
    Array.isArray(publicKey) ||
    Object.keys(publicKey).sort().join(",") !== "algorithm,keyid,raw"
  ) {
    throw new VerificationError("unsupported or malformed DSSE signature");
  }
  const payload = decodeBase64(envelope.payload);
  const signatureBytes = decodeBase64(item.sig);
  const publicRaw = decodeBase64(publicKey.raw);
  const keyId = digest(publicRaw);
  if (keyId !== publicKey.keyid || keyId !== item.keyid) {
    throw new VerificationError("signature key identifier mismatch");
  }
  if (requiredKeyId && requiredKeyId !== keyId) {
    throw new VerificationError("signature does not match the required key");
  }
  const key = crypto.createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, publicRaw]),
    format: "der",
    type: "spki",
  });
  if (!crypto.verify(null, pae(envelope.payloadType, payload), key, signatureBytes)) {
    throw new VerificationError("Ed25519 signature verification failed");
  }
  const statement = parseCanonical(payload, "signed statement");
  const verificationMaterial = material.verificationMaterial;
  const materialDigest =
    verificationMaterial === null || verificationMaterial === undefined
      ? null
      : digest(Buffer.from(canonical(verificationMaterial)));
  const subject = statement.subject;
  const predicate = statement.predicate;
  if (
    statement._type !== STATEMENT_TYPE ||
    statement.predicateType !== PREDICATE_TYPE ||
    !Array.isArray(subject) ||
    subject.length !== 1 ||
    subject[0]?.name !== "sova.trace.manifest" ||
    subject[0]?.digest?.sha256 !== unsignedManifestDigest(manifest).slice(7) ||
    predicate?.traceId !== manifest.id ||
    predicate?.runId !== manifest.runId ||
    predicate?.eventCount !== manifest.eventCount ||
    predicate?.chainRoot !== manifest.chainRoot ||
    predicate?.verificationMaterialDigest !== materialDigest
  ) {
    throw new VerificationError("signed statement does not match trace manifest");
  }
  return {
    signaturePresent: true,
    signatureChecked: true,
    signatureKeyId: keyId,
    trustPolicy: requiredKeyId ? "required-key" : "included-key-integrity-only",
    verificationMaterialPresent: verificationMaterial != null,
    verificationMaterialVerified: false,
  };
}

function verify(path, options = {}) {
  const { members, packageBytes } = archive(path);
  const manifestBytes = members.get("manifest.json");
  const manifest = parseCanonical(manifestBytes, "manifest");
  if (!["sova.capsule", "sova.trace"].includes(manifest.artifactType)) {
    throw new VerificationError("unsupported artifact type");
  }
  if (manifest.schemaVersion !== "0.1.0") {
    throw new VerificationError("unsupported schema version");
  }
  const objectIndex = descriptors(manifest, members);
  const eventCount =
    manifest.artifactType === "sova.trace" ? trace(manifest, objectIndex, members) : 0;
  const result = {
    artifactType: manifest.artifactType,
    contentDigest: digest(Buffer.from(canonical(manifest))),
    eventCount,
    objectCount: objectIndex.length,
    packageDigest: digest(packageBytes),
    signaturePresent: false,
    signatureChecked: false,
    verifier: "sova-independent-node/0.1",
    valid: true,
  };
  if (manifest.artifactType === "sova.trace") {
    result.signaturePresent = manifest.integrity?.signature != null;
    if (options.requireSignature || options.requiredKeyId) {
      Object.assign(result, signature(manifest, options.requiredKeyId));
    }
  } else if (options.requireSignature || options.requiredKeyId) {
    throw new VerificationError("signature policy is supported only for sova.trace");
  }
  return result;
}

function main(argv) {
  let requireSignature = false;
  let requiredKeyId = null;
  let path = null;
  for (let index = 0; index < argv.length; index += 1) {
    const item = argv[index];
    if (item === "--require-signature") {
      requireSignature = true;
    } else if (item === "--required-key-id") {
      requiredKeyId = argv[index + 1];
      index += 1;
      if (!requiredKeyId) throw new VerificationError("--required-key-id needs a value");
    } else if (item.startsWith("-")) {
      throw new VerificationError(`unknown option: ${item}`);
    } else if (path === null) {
      path = item;
    } else {
      throw new VerificationError("multiple artifact paths supplied");
    }
  }
  if (path === null) {
    throw new VerificationError(
      "usage: sova_independent_verify.mjs <artifact> [--require-signature] " +
        "[--required-key-id sha256:...]",
    );
  }
  return verify(path, { requireSignature, requiredKeyId });
}

try {
  process.stdout.write(`${JSON.stringify(main(process.argv.slice(2)))}\n`);
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`INDEPENDENT-NODE-VERIFY-FAILED: ${message}\n`);
  process.exitCode = 2;
}
