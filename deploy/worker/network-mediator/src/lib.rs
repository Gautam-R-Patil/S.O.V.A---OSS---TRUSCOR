// SPDX-License-Identifier: Apache-2.0
//! SOVA protocol 0.1 HTTP/HTTPS/WebSocket/MCP-over-HTTP egress mediator.

#![forbid(unsafe_code)]

use std::collections::{BTreeSet, HashSet};
#[cfg(unix)]
use std::fs::File;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs,
};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use url::Url;

const MAX_POLICY_BYTES: usize = 1024 * 1024;
const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_HEADERS: usize = 128;
const MAX_TLS_HELLO_BYTES: usize = 128 * 1024;
const MAX_RECEIPT_FILES: u64 = 2048;
const MAX_CONNECTIONS: u64 = 1024;
const MAX_NETWORK_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_RULES: usize = 1024;
const MAX_DNS_PINS: usize = 16;
const IO_TIMEOUT: Duration = Duration::from_secs(15);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const ACCEPT_POLL: Duration = Duration::from_millis(50);
const MAX_ACTIVE_CONNECTIONS: usize = 128;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Policy {
    artifact_type: String,
    schema_version: String,
    pub job_id: String,
    manifest_digest: String,
    launch_plan_digest: String,
    listen: Listen,
    allowed_transports: Vec<String>,
    rules: Vec<Rule>,
    budgets: Budgets,
    receipt_artifact_type: String,
    invariants: Invariants,
    content_digest: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Listen {
    address: String,
    port: u16,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Rule {
    hostname: String,
    port: u16,
    protocol: String,
    initial_addresses: Vec<String>,
    allow_private: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Budgets {
    maximum_connections: u64,
    maximum_bytes: u64,
    expires_at: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
struct Invariants {
    dns_resolved_by_mediator: bool,
    dns_pins_revalidated: bool,
    selected_address_bound_to_connection: bool,
    private_addresses_default_denied: bool,
    raw_tcp_udp_supported: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Endpoint {
    hostname: String,
    port: u16,
}

#[derive(Clone, Debug)]
struct Authorization {
    endpoint: Endpoint,
    pins: Vec<IpAddr>,
    resolved: Vec<IpAddr>,
    selected: Option<IpAddr>,
    allow_private: bool,
}

#[derive(Debug)]
enum RequestKind {
    Connect,
    Forward {
        outbound_head: Vec<u8>,
        content_length: u64,
        body_prefix: Vec<u8>,
        websocket: bool,
    },
}

#[derive(Debug)]
struct ParsedRequest {
    endpoint: Endpoint,
    kind: RequestKind,
    received_head_bytes: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReceiptEndpoint<'a> {
    hostname: &'a str,
    port: u16,
    protocol: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReceiptBody<'a> {
    artifact_type: &'static str,
    schema_version: &'static str,
    job_id: &'a str,
    sequence: u64,
    observed_at: String,
    endpoint: ReceiptEndpoint<'a>,
    pinned_addresses: Vec<String>,
    resolved_addresses: Vec<String>,
    selected_address: Option<String>,
    requested_bytes: u64,
    decision: &'a str,
    reason: &'a str,
}

fn digest(raw: &[u8]) -> String {
    let value = Sha256::digest(raw);
    let mut output = String::with_capacity(71);
    output.push_str("sha256:");
    for byte in value {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn canonical_bytes(value: &Value) -> Result<Vec<u8>, String> {
    serde_json::to_vec(value).map_err(|error| format!("cannot canonicalize JSON: {error}"))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_hostname(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 253
        || value.ends_with('.')
        || value.bytes().any(|b| b.is_ascii_uppercase())
    {
        return false;
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

fn parse_expiry(value: &str) -> Result<OffsetDateTime, String> {
    if value.len() != 20 || !value.ends_with('Z') {
        return Err("expiresAt must be second-precision UTC".to_owned());
    }
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| "expiresAt is invalid".to_owned())
}

fn policy_without_digest(value: &Value) -> Result<Value, String> {
    let mut unsigned = value.clone();
    let object = unsigned
        .as_object_mut()
        .ok_or("policy must be a JSON object")?;
    object
        .remove("contentDigest")
        .ok_or("policy contentDigest is missing")?;
    Ok(unsigned)
}

/// Parse, canonicalize, content-verify, and validate one immutable worker policy.
///
/// # Errors
///
/// Returns an error when the input is malformed, noncanonical, content-tampered,
/// outside protocol limits, or requests an unsupported authority shape.
pub fn parse_policy(raw: &[u8]) -> Result<Policy, String> {
    if raw.is_empty() || raw.len() > MAX_POLICY_BYTES {
        return Err("policy size is outside the 1 MiB limit".to_owned());
    }
    let value: Value =
        serde_json::from_slice(raw).map_err(|error| format!("invalid policy JSON: {error}"))?;
    if canonical_bytes(&value)? != raw {
        return Err("policy is not canonical SOVA JSON".to_owned());
    }
    let policy: Policy = serde_json::from_value(value.clone())
        .map_err(|error| format!("policy contract is invalid: {error}"))?;
    let calculated = digest(&canonical_bytes(&policy_without_digest(&value)?)?);
    if policy.content_digest != calculated {
        return Err("policy contentDigest does not match its canonical body".to_owned());
    }
    policy.validate()?;
    Ok(policy)
}

impl Policy {
    fn validate(&self) -> Result<(), String> {
        if self.artifact_type != "sova.worker-network-mediator-policy"
            || self.schema_version != "0.1.0"
            || self.receipt_artifact_type != "sova.worker-network-receipt"
        {
            return Err("policy artifact or schema version is unsupported".to_owned());
        }
        if self.job_id.is_empty()
            || self.job_id.len() > 191
            || !valid_digest(&self.manifest_digest)
            || !valid_digest(&self.launch_plan_digest)
        {
            return Err("policy identity or binding digest is invalid".to_owned());
        }
        let listen_ip = IpAddr::from_str(&self.listen.address)
            .map_err(|_| "policy listener must be an IP address".to_owned())?;
        if !matches!(listen_ip, IpAddr::V4(_)) || self.listen.port != 8888 {
            return Err("protocol 0.1 requires an IPv4 listener on port 8888".to_owned());
        }
        let expected = ["http", "https-connect", "mcp-http", "websocket"];
        let actual: BTreeSet<&str> = self.allowed_transports.iter().map(String::as_str).collect();
        if actual != expected.into_iter().collect()
            || self.allowed_transports.len() != expected.len()
        {
            return Err("allowedTransports does not match protocol 0.1".to_owned());
        }
        if self.budgets.maximum_connections > MAX_CONNECTIONS
            || self.budgets.maximum_bytes > MAX_NETWORK_BYTES
        {
            return Err("mediator budget exceeds protocol 0.1 evidence limits".to_owned());
        }
        parse_expiry(&self.budgets.expires_at)?;
        if self.rules.len() > MAX_RULES {
            return Err("policy contains too many endpoint rules".to_owned());
        }
        if !self.invariants.dns_resolved_by_mediator
            || !self.invariants.dns_pins_revalidated
            || !self.invariants.selected_address_bound_to_connection
            || !self.invariants.private_addresses_default_denied
            || self.invariants.raw_tcp_udp_supported
        {
            return Err("policy invariants do not match protocol 0.1".to_owned());
        }
        let mut endpoints = HashSet::new();
        for rule in &self.rules {
            if !valid_hostname(&rule.hostname) || rule.port == 0 || rule.protocol != "tcp" {
                return Err("policy contains an unsupported network endpoint".to_owned());
            }
            if !endpoints.insert((rule.hostname.as_str(), rule.port, rule.protocol.as_str())) {
                return Err("policy contains a duplicate network endpoint".to_owned());
            }
            if rule.initial_addresses.is_empty() || rule.initial_addresses.len() > MAX_DNS_PINS {
                return Err("network rule DNS pin count is outside protocol limits".to_owned());
            }
            let mut pins = HashSet::new();
            for raw in &rule.initial_addresses {
                let address = IpAddr::from_str(raw)
                    .map_err(|_| "network rule contains an invalid DNS pin")?;
                if !pins.insert(address) || !address_admissible(address, rule.allow_private) {
                    return Err(
                        "network rule contains a duplicate or prohibited DNS pin".to_owned()
                    );
                }
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn listen_authority(&self) -> String {
        format!("{}:{}", self.listen.address, self.listen.port)
    }

    fn rule(&self, endpoint: &Endpoint) -> Option<&Rule> {
        self.rules.iter().find(|rule| {
            rule.hostname == endpoint.hostname
                && rule.port == endpoint.port
                && rule.protocol == "tcp"
        })
    }
}

fn v4_private(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    a == 10 || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168)
}

fn v4_global(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224)
}

const fn v6_private(ip: Ipv6Addr) -> bool {
    ip.segments()[0] & 0xfe00 == 0xfc00
}

const fn v6_global(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    let global_unicast = segments[0] & 0xe000 == 0x2000;
    let ietf_special = segments[0] == 0x2001 && segments[1] <= 0x01ff;
    let six_to_four = segments[0] == 0x2002;
    let documentation = (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || (segments[0] == 0x3fff && segments[1] & 0xf000 == 0);
    global_unicast && !ietf_special && !six_to_four && !documentation
}

fn address_admissible(ip: IpAddr, allow_private: bool) -> bool {
    match ip {
        IpAddr::V4(value) => v4_global(value) || (allow_private && v4_private(value)),
        IpAddr::V6(value) => v6_global(value) || (allow_private && v6_private(value)),
    }
}

fn now_utc() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

fn timestamp(now: OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    )
}

/// Canonical, contiguous, create-new receipt writer owned by the mediator identity.
pub struct ReceiptRecorder {
    directory: PathBuf,
    job_id: String,
    sequence: u64,
}

impl ReceiptRecorder {
    /// Open an empty controller-created directory for contiguous receipt output.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory is missing, linked, non-directory,
    /// non-empty, or cannot be inspected.
    pub fn open(directory: &Path, job_id: String) -> Result<Self, String> {
        let metadata = fs::symlink_metadata(directory)
            .map_err(|error| format!("cannot inspect receipt directory: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("receipt path must be a non-symlink directory".to_owned());
        }
        if fs::read_dir(directory)
            .map_err(|error| format!("cannot inspect receipt directory: {error}"))?
            .next()
            .is_some()
        {
            return Err("receipt directory must be empty at mediator startup".to_owned());
        }
        Ok(Self {
            directory: directory.to_owned(),
            job_id,
            sequence: 0,
        })
    }

    fn record(
        &mut self,
        authorization: &Authorization,
        requested_bytes: u64,
        decision: &str,
        reason: &str,
    ) -> Result<(), String> {
        if self.sequence >= MAX_RECEIPT_FILES {
            return Err("receipt count exceeds the controller evidence limit".to_owned());
        }
        let sequence = self.sequence + 1;
        let body = ReceiptBody {
            artifact_type: "sova.worker-network-receipt",
            schema_version: "0.1.0",
            job_id: &self.job_id,
            sequence,
            observed_at: timestamp(now_utc()),
            endpoint: ReceiptEndpoint {
                hostname: &authorization.endpoint.hostname,
                port: authorization.endpoint.port,
                protocol: "tcp",
            },
            pinned_addresses: authorization.pins.iter().map(ToString::to_string).collect(),
            resolved_addresses: authorization
                .resolved
                .iter()
                .map(ToString::to_string)
                .collect(),
            selected_address: authorization.selected.map(|value| value.to_string()),
            requested_bytes,
            decision,
            reason,
        };
        let mut value = serde_json::to_value(body)
            .map_err(|error| format!("cannot encode receipt: {error}"))?;
        let unsigned = canonical_bytes(&value)?;
        value
            .as_object_mut()
            .ok_or("receipt encoder did not produce an object")?
            .insert("contentDigest".to_owned(), Value::String(digest(&unsigned)));
        let payload = canonical_bytes(&value)?;
        let final_path = self.directory.join(format!("{sequence:06}.json"));
        let temporary = self.directory.join(format!(".{sequence:06}.tmp"));
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut output = options
            .open(&temporary)
            .map_err(|error| format!("cannot create receipt atomically: {error}"))?;
        output
            .write_all(&payload)
            .and_then(|()| output.sync_all())
            .map_err(|error| format!("cannot persist receipt: {error}"))?;
        drop(output);
        fs::hard_link(&temporary, &final_path)
            .map_err(|error| format!("cannot commit receipt without replacement: {error}"))?;
        fs::remove_file(&temporary)
            .map_err(|error| format!("cannot remove committed receipt temporary: {error}"))?;
        #[cfg(unix)]
        File::open(&self.directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("cannot persist receipt directory entry: {error}"))?;
        self.sequence = sequence;
        Ok(())
    }
}

struct State {
    recorder: ReceiptRecorder,
    connections: u64,
    bytes: u64,
}

struct Runtime {
    policy: Policy,
    state: Mutex<State>,
    fatal: AtomicBool,
    active: AtomicUsize,
}

impl Runtime {
    const fn new(policy: Policy, recorder: ReceiptRecorder) -> Self {
        Self {
            policy,
            state: Mutex::new(State {
                recorder,
                connections: 0,
                bytes: 0,
            }),
            fatal: AtomicBool::new(false),
            active: AtomicUsize::new(0),
        }
    }

    fn lock_state(&self) -> Result<std::sync::MutexGuard<'_, State>, String> {
        self.state
            .lock()
            .map_err(|_| "mediator state lock was poisoned".to_owned())
    }

    fn deny(
        &self,
        authorization: &Authorization,
        requested: u64,
        reason: &str,
    ) -> Result<(), String> {
        let mut state = self.lock_state()?;
        state
            .recorder
            .record(authorization, requested, "denied", reason)
    }

    fn admit(&self, authorization: &Authorization, requested: u64) -> Result<(), String> {
        let mut state = self.lock_state()?;
        let expiry = parse_expiry(&self.policy.budgets.expires_at)?;
        let reason = if now_utc() >= expiry {
            Some("job-time-budget-exhausted")
        } else if state.connections >= self.policy.budgets.maximum_connections {
            Some("connection-budget-exhausted")
        } else if requested
            > self
                .policy
                .budgets
                .maximum_bytes
                .saturating_sub(state.bytes)
        {
            Some("byte-budget-exhausted")
        } else {
            None
        };
        if let Some(reason) = reason {
            state
                .recorder
                .record(authorization, requested, "denied", reason)?;
            return Err(reason.to_owned());
        }
        state.recorder.record(
            authorization,
            requested,
            "allowed",
            "policy-and-budgets-satisfied",
        )?;
        state.connections += 1;
        state.bytes += requested;
        drop(state);
        Ok(())
    }

    fn consume(&self, authorization: &Authorization, amount: u64) -> Result<(), String> {
        if amount == 0 {
            return Ok(());
        }
        let mut state = self.lock_state()?;
        if amount
            > self
                .policy
                .budgets
                .maximum_bytes
                .saturating_sub(state.bytes)
        {
            state
                .recorder
                .record(authorization, amount, "denied", "byte-budget-exhausted")?;
            return Err("byte-budget-exhausted".to_owned());
        }
        state.bytes += amount;
        drop(state);
        Ok(())
    }

    fn finish(&self, authorization: &Authorization, actual_bytes: u64) -> Result<(), String> {
        let mut state = self.lock_state()?;
        state
            .recorder
            .record(authorization, actual_bytes, "allowed", "flow-complete")
    }

    fn fail(&self) {
        self.fatal.store(true, Ordering::Release);
    }
}

struct ActiveGuard(Arc<Runtime>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
    }
}

#[allow(clippy::too_many_lines)]
fn read_request(stream: &mut TcpStream) -> Result<ParsedRequest, String> {
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|error| error.to_string())?;
    let mut buffer = Vec::with_capacity(4096);
    let header_end = loop {
        if buffer.len() >= MAX_HEADER_BYTES {
            return Err("request headers exceed 64 KiB".to_owned());
        }
        let mut chunk = [0_u8; 4096];
        let count = stream
            .read(&mut chunk)
            .map_err(|error| format!("cannot read request: {error}"))?;
        if count == 0 {
            return Err("client closed before a complete request".to_owned());
        }
        buffer.extend_from_slice(&chunk[..count]);
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut request = httparse::Request::new(&mut headers);
    match request
        .parse(&buffer[..header_end])
        .map_err(|error| format!("malformed HTTP request: {error}"))?
    {
        httparse::Status::Complete(_) => {}
        httparse::Status::Partial => return Err("incomplete HTTP request".to_owned()),
    }
    let method = request.method.ok_or("HTTP method is missing")?;
    let target = request.path.ok_or("HTTP request target is missing")?;
    let version = request.version.ok_or("HTTP version is missing")?;
    if version != 0 && version != 1 {
        return Err("only HTTP/1.0 and HTTP/1.1 are supported".to_owned());
    }
    let host_values: Vec<&[u8]> = request
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("host"))
        .map(|header| header.value)
        .collect();
    if host_values.len() != 1 {
        return Err("exactly one Host header is required".to_owned());
    }
    let host_header =
        std::str::from_utf8(host_values[0]).map_err(|_| "Host header must be UTF-8")?;
    if request.headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("transfer-encoding")
            || header.name.eq_ignore_ascii_case("proxy-authorization")
    }) {
        return Err("Transfer-Encoding and Proxy-Authorization are unsupported".to_owned());
    }
    let content_lengths: Vec<&[u8]> = request
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("content-length"))
        .map(|header| header.value)
        .collect();
    if content_lengths.len() > 1 {
        return Err("duplicate Content-Length is forbidden".to_owned());
    }
    let content_length = if let Some(raw) = content_lengths.first() {
        std::str::from_utf8(raw)
            .map_err(|_| "Content-Length must be ASCII")?
            .trim()
            .parse::<u64>()
            .map_err(|_| "Content-Length is invalid")?
    } else {
        0
    };
    let received_head_bytes =
        u64::try_from(header_end).map_err(|_| "request header length overflow")?;
    if method.eq_ignore_ascii_case("CONNECT") {
        if content_length != 0 || buffer.len() != header_end {
            return Err("CONNECT request must not carry a body or early tunnel bytes".to_owned());
        }
        let endpoint = parse_authority(target, None)?;
        let host_endpoint = parse_authority(host_header.trim(), Some(endpoint.port))?;
        if endpoint != host_endpoint {
            return Err("CONNECT authority and Host header disagree".to_owned());
        }
        return Ok(ParsedRequest {
            endpoint,
            kind: RequestKind::Connect,
            received_head_bytes,
        });
    }
    let url =
        Url::parse(target).map_err(|_| "forward proxy request target must be an absolute URL")?;
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err("URL credentials and fragments are forbidden".to_owned());
    }
    let scheme = url.scheme();
    if scheme != "http" && scheme != "ws" {
        return Err("forward proxy supports only http and ws; use CONNECT for TLS".to_owned());
    }
    let hostname = url
        .host_str()
        .ok_or("absolute URL hostname is missing")?
        .to_ascii_lowercase();
    if !valid_hostname(&hostname) {
        return Err("absolute URL hostname is invalid".to_owned());
    }
    let port = url
        .port_or_known_default()
        .ok_or("absolute URL port is unknown")?;
    let endpoint = Endpoint { hostname, port };
    if parse_authority(host_header.trim(), Some(port))? != endpoint {
        return Err("absolute URL authority and Host header disagree".to_owned());
    }
    let connection_upgrade = request.headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("connection")
            && std::str::from_utf8(header.value).is_ok_and(|value| {
                value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
            })
    });
    let websocket = scheme == "ws"
        && connection_upgrade
        && request.headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("upgrade")
                && std::str::from_utf8(header.value)
                    .is_ok_and(|value| value.trim().eq_ignore_ascii_case("websocket"))
        });
    if scheme == "ws" && !websocket {
        return Err("ws requests require a WebSocket Upgrade handshake".to_owned());
    }
    let mut outbound = Vec::with_capacity(header_end);
    let origin = url.query().map_or_else(
        || url.path().to_owned(),
        |query| format!("{}?{query}", url.path()),
    );
    write!(&mut outbound, "{method} {origin} HTTP/1.1\r\n").map_err(|error| error.to_string())?;
    for header in request.headers.iter() {
        let name = header.name;
        if name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("proxy-connection")
            || name.eq_ignore_ascii_case("keep-alive")
        {
            continue;
        }
        outbound.extend_from_slice(name.as_bytes());
        outbound.extend_from_slice(b": ");
        outbound.extend_from_slice(header.value);
        outbound.extend_from_slice(b"\r\n");
    }
    let default_port = 80;
    if port == default_port {
        write!(&mut outbound, "Host: {}\r\n", endpoint.hostname)
            .map_err(|error| error.to_string())?;
    } else {
        write!(
            &mut outbound,
            "Host: {}:{}\r\n",
            endpoint.hostname, endpoint.port
        )
        .map_err(|error| error.to_string())?;
    }
    if websocket {
        outbound.extend_from_slice(b"Connection: Upgrade\r\n");
    } else {
        outbound.extend_from_slice(b"Connection: close\r\n");
    }
    outbound.extend_from_slice(b"\r\n");
    let body_prefix = buffer[header_end..].to_vec();
    if u64::try_from(body_prefix.len()).map_err(|_| "request body length overflow")?
        > content_length
    {
        return Err("pipelined bytes after the declared request body are forbidden".to_owned());
    }
    Ok(ParsedRequest {
        endpoint,
        kind: RequestKind::Forward {
            outbound_head: outbound,
            content_length,
            body_prefix,
            websocket,
        },
        received_head_bytes,
    })
}

fn parse_authority(value: &str, default_port: Option<u16>) -> Result<Endpoint, String> {
    if value.contains('@') || value.contains('/') || value.contains('[') || value.contains(']') {
        return Err("authority contains unsupported syntax".to_owned());
    }
    let (host, port) = match value.rsplit_once(':') {
        Some((host, raw_port)) if !host.contains(':') => {
            let port = raw_port
                .parse::<u16>()
                .map_err(|_| "authority port is invalid")?;
            (host, port)
        }
        None => (value, default_port.ok_or("authority port is required")?),
        _ => return Err("authority is invalid".to_owned()),
    };
    let hostname = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if port == 0 || !valid_hostname(&hostname) {
        return Err("authority endpoint is invalid".to_owned());
    }
    Ok(Endpoint { hostname, port })
}

fn resolve_authorization(
    policy: &Policy,
    endpoint: Endpoint,
) -> Result<Authorization, Authorization> {
    resolve_authorization_with(policy, endpoint, |target| {
        (target.hostname.as_str(), target.port)
            .to_socket_addrs()
            .map(|addresses| addresses.map(|address| address.ip()).collect())
            .map_err(|_| ())
    })
}

fn resolve_authorization_with<F>(
    policy: &Policy,
    endpoint: Endpoint,
    lookup: F,
) -> Result<Authorization, Authorization>
where
    F: FnOnce(&Endpoint) -> Result<BTreeSet<IpAddr>, ()>,
{
    let Some(rule) = policy.rule(&endpoint) else {
        return Err(Authorization {
            endpoint,
            pins: Vec::new(),
            resolved: Vec::new(),
            selected: None,
            allow_private: false,
        });
    };
    let pins: Vec<IpAddr> = rule
        .initial_addresses
        .iter()
        .filter_map(|raw| IpAddr::from_str(raw).ok())
        .collect();
    let mut authorization = Authorization {
        endpoint: endpoint.clone(),
        pins,
        resolved: Vec::new(),
        selected: None,
        allow_private: rule.allow_private,
    };
    let Ok(addresses) = lookup(&endpoint) else {
        return Err(authorization);
    };
    authorization.resolved = addresses.iter().copied().collect();
    let pin_set: BTreeSet<IpAddr> = authorization.pins.iter().copied().collect();
    if addresses.is_empty()
        || addresses != pin_set
        || addresses
            .iter()
            .any(|address| !address_admissible(*address, authorization.allow_private))
    {
        return Err(authorization);
    }
    authorization.selected = authorization.pins.first().copied();
    Ok(authorization)
}

fn connect_selected(authorization: &Authorization) -> Result<TcpStream, String> {
    let selected = authorization
        .selected
        .ok_or("authorized destination has no selected address")?;
    let stream = TcpStream::connect_timeout(
        &SocketAddr::new(selected, authorization.endpoint.port),
        CONNECT_TIMEOUT,
    )
    .map_err(|error| format!("selected address connection failed: {error}"))?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|error| error.to_string())?;
    Ok(stream)
}

fn read_exact_counted(stream: &mut TcpStream, length: usize) -> Result<Vec<u8>, String> {
    let mut output = vec![0_u8; length];
    stream
        .read_exact(&mut output)
        .map_err(|error| format!("cannot read bounded payload: {error}"))?;
    Ok(output)
}

fn read_tls_client_hello(
    stream: &mut TcpStream,
    expected_hostname: &str,
) -> Result<Vec<u8>, String> {
    let mut records = Vec::new();
    let mut handshake = Vec::new();
    let expected_length = loop {
        let header = read_exact_counted(stream, 5)?;
        if header[0] != 22 || header[1] != 3 {
            return Err("CONNECT tunnel must begin with a TLS handshake record".to_owned());
        }
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if length == 0 || records.len() + 5 + length > MAX_TLS_HELLO_BYTES {
            return Err("TLS ClientHello exceeds the mediator limit".to_owned());
        }
        let payload = read_exact_counted(stream, length)?;
        records.extend_from_slice(&header);
        records.extend_from_slice(&payload);
        handshake.extend_from_slice(&payload);
        if handshake.len() >= 4 {
            if handshake[0] != 1 {
                return Err("first TLS handshake message is not ClientHello".to_owned());
            }
            let wanted = 4
                + (usize::from(handshake[1]) << 16)
                + (usize::from(handshake[2]) << 8)
                + usize::from(handshake[3]);
            if wanted > MAX_TLS_HELLO_BYTES {
                return Err("TLS ClientHello exceeds the mediator limit".to_owned());
            }
            if handshake.len() >= wanted {
                break wanted;
            }
        }
    };
    let sni = client_hello_sni(&handshake[..expected_length])?;
    if !sni.eq_ignore_ascii_case(expected_hostname) {
        return Err("TLS SNI does not match the authorized CONNECT hostname".to_owned());
    }
    Ok(records)
}

fn take<'a>(input: &mut &'a [u8], count: usize) -> Result<&'a [u8], String> {
    if input.len() < count {
        return Err("TLS ClientHello is truncated".to_owned());
    }
    let (head, tail) = input.split_at(count);
    *input = tail;
    Ok(head)
}

fn take_u16(input: &mut &[u8]) -> Result<usize, String> {
    let raw = take(input, 2)?;
    Ok(usize::from(u16::from_be_bytes([raw[0], raw[1]])))
}

fn client_hello_sni(handshake: &[u8]) -> Result<String, String> {
    let mut input = handshake;
    let header = take(&mut input, 4)?;
    if header[0] != 1 {
        return Err("TLS message is not ClientHello".to_owned());
    }
    take(&mut input, 2 + 32)?;
    let session_length = usize::from(take(&mut input, 1)?[0]);
    take(&mut input, session_length)?;
    let cipher_length = take_u16(&mut input)?;
    take(&mut input, cipher_length)?;
    let compression_length = usize::from(take(&mut input, 1)?[0]);
    take(&mut input, compression_length)?;
    let extensions_length = take_u16(&mut input)?;
    let mut extensions = take(&mut input, extensions_length)?;
    while !extensions.is_empty() {
        let kind = take_u16(&mut extensions)?;
        let length = take_u16(&mut extensions)?;
        let mut extension = take(&mut extensions, length)?;
        if kind != 0 {
            continue;
        }
        let list_length = take_u16(&mut extension)?;
        let mut names = take(&mut extension, list_length)?;
        let mut result = None;
        while !names.is_empty() {
            let name_kind = take(&mut names, 1)?[0];
            let name_length = take_u16(&mut names)?;
            let raw = take(&mut names, name_length)?;
            if name_kind == 0 {
                if result.is_some() {
                    return Err("TLS ClientHello contains multiple host_name values".to_owned());
                }
                let value = std::str::from_utf8(raw).map_err(|_| "TLS SNI is not UTF-8")?;
                let normalized = value.trim_end_matches('.').to_ascii_lowercase();
                if !valid_hostname(&normalized) {
                    return Err("TLS SNI hostname is invalid".to_owned());
                }
                result = Some(normalized);
            }
        }
        return result.ok_or_else(|| "TLS ClientHello omits host_name SNI".to_owned());
    }
    Err("TLS ClientHello omits SNI".to_owned())
}

#[allow(clippy::needless_pass_by_value)]
fn relay_one_way(
    mut input: TcpStream,
    mut output: TcpStream,
    runtime: Arc<Runtime>,
    authorization: Authorization,
    flow_bytes: Arc<Mutex<u64>>,
) -> Result<(), String> {
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let count = match input.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => count,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                break
            }
            Err(error) => return Err(format!("relay read failed: {error}")),
        };
        let count_u64 = u64::try_from(count).map_err(|_| "relay byte count overflow")?;
        runtime.consume(&authorization, count_u64)?;
        output
            .write_all(&buffer[..count])
            .map_err(|error| format!("relay write failed: {error}"))?;
        let mut total = flow_bytes
            .lock()
            .map_err(|_| "flow byte lock was poisoned")?;
        *total = total.saturating_add(count_u64);
    }
    let _ = output.shutdown(Shutdown::Write);
    Ok(())
}

fn bidirectional_relay(
    client: TcpStream,
    upstream: TcpStream,
    runtime: &Arc<Runtime>,
    authorization: &Authorization,
    initial_bytes: u64,
) -> Result<u64, String> {
    let client_read = client.try_clone().map_err(|error| error.to_string())?;
    let upstream_read = upstream.try_clone().map_err(|error| error.to_string())?;
    let flow_bytes = Arc::new(Mutex::new(initial_bytes));
    let left = {
        let runtime = Arc::clone(runtime);
        let authorization = authorization.clone();
        let flow_bytes = Arc::clone(&flow_bytes);
        thread::spawn(move || {
            relay_one_way(client_read, upstream, runtime, authorization, flow_bytes)
        })
    };
    let right = {
        let runtime = Arc::clone(runtime);
        let authorization = authorization.clone();
        let flow_bytes = Arc::clone(&flow_bytes);
        thread::spawn(move || {
            relay_one_way(upstream_read, client, runtime, authorization, flow_bytes)
        })
    };
    let left_result = left.join().map_err(|_| "client relay thread panicked")?;
    let right_result = right.join().map_err(|_| "upstream relay thread panicked")?;
    left_result?;
    right_result?;
    let value = *flow_bytes
        .lock()
        .map_err(|_| "flow byte lock was poisoned")?;
    Ok(value)
}

fn handle_connect(
    mut client: TcpStream,
    mut upstream: TcpStream,
    runtime: &Arc<Runtime>,
    authorization: &Authorization,
    initial_bytes: u64,
) -> Result<u64, String> {
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\nConnection: close\r\n\r\n")
        .map_err(|error| format!("cannot acknowledge CONNECT: {error}"))?;
    let hello = match read_tls_client_hello(&mut client, &authorization.endpoint.hostname) {
        Ok(hello) => hello,
        Err(error) => {
            runtime.deny(authorization, 0, "tls-sni-mismatch-or-invalid")?;
            return Err(error);
        }
    };
    let hello_len = u64::try_from(hello.len()).map_err(|_| "TLS ClientHello length overflow")?;
    runtime.consume(authorization, hello_len)?;
    upstream
        .write_all(&hello)
        .map_err(|error| format!("cannot forward TLS ClientHello: {error}"))?;
    bidirectional_relay(
        client,
        upstream,
        runtime,
        authorization,
        initial_bytes + hello_len,
    )
}

fn copy_fixed_body(
    client: &mut TcpStream,
    upstream: &mut TcpStream,
    prefix: &[u8],
    length: u64,
    runtime: &Runtime,
    authorization: &Authorization,
) -> Result<u64, String> {
    let prefix_len = u64::try_from(prefix.len()).map_err(|_| "body prefix length overflow")?;
    if prefix_len > length {
        return Err("body prefix exceeds Content-Length".to_owned());
    }
    if !prefix.is_empty() {
        runtime.consume(authorization, prefix_len)?;
        upstream
            .write_all(prefix)
            .map_err(|error| format!("cannot forward request body: {error}"))?;
    }
    let mut remaining = length - prefix_len;
    let mut copied = prefix_len;
    let mut buffer = vec![0_u8; 64 * 1024];
    while remaining > 0 {
        let wanted = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| "body size overflow")?;
        client
            .read_exact(&mut buffer[..wanted])
            .map_err(|error| format!("request body is truncated: {error}"))?;
        let amount = u64::try_from(wanted).map_err(|_| "request body size overflow")?;
        runtime.consume(authorization, amount)?;
        upstream
            .write_all(&buffer[..wanted])
            .map_err(|error| format!("cannot forward request body: {error}"))?;
        remaining -= amount;
        copied += amount;
    }
    Ok(copied)
}

#[allow(clippy::too_many_arguments)]
fn handle_forward(
    mut client: TcpStream,
    mut upstream: TcpStream,
    runtime: &Arc<Runtime>,
    authorization: &Authorization,
    outbound_head: &[u8],
    content_length: u64,
    body_prefix: &[u8],
    websocket: bool,
    initial_bytes: u64,
) -> Result<u64, String> {
    let head_len =
        u64::try_from(outbound_head.len()).map_err(|_| "outbound header length overflow")?;
    runtime.consume(authorization, head_len)?;
    upstream
        .write_all(outbound_head)
        .map_err(|error| format!("cannot forward request headers: {error}"))?;
    let body_bytes = copy_fixed_body(
        &mut client,
        &mut upstream,
        body_prefix,
        content_length,
        runtime,
        authorization,
    )?;
    if websocket {
        return bidirectional_relay(
            client,
            upstream,
            runtime,
            authorization,
            initial_bytes + head_len + body_bytes,
        );
    }
    upstream
        .shutdown(Shutdown::Write)
        .map_err(|error| format!("cannot close upstream request: {error}"))?;
    let flow_bytes = Arc::new(Mutex::new(initial_bytes + head_len + body_bytes));
    relay_one_way(
        upstream,
        client,
        Arc::clone(runtime),
        authorization.clone(),
        Arc::clone(&flow_bytes),
    )?;
    let value = *flow_bytes
        .lock()
        .map_err(|_| "flow byte lock was poisoned")?;
    Ok(value)
}

fn handle_client(mut client: TcpStream, runtime: &Arc<Runtime>) -> Result<(), String> {
    client
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|error| error.to_string())?;
    client
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|error| error.to_string())?;
    let request = read_request(&mut client)?;
    let authorization = match resolve_authorization(&runtime.policy, request.endpoint.clone()) {
        Ok(value) => value,
        Err(value) => {
            let reason = if value.pins.is_empty() {
                "endpoint-not-authorized"
            } else if value.resolved.is_empty() {
                "dns-resolution-failed"
            } else {
                "dns-pin-mismatch-or-prohibited-address"
            };
            runtime.deny(&value, request.received_head_bytes, reason)?;
            return Err(reason.to_owned());
        }
    };
    runtime.admit(&authorization, request.received_head_bytes)?;
    let upstream = match connect_selected(&authorization) {
        Ok(stream) => stream,
        Err(error) => {
            runtime.deny(&authorization, 0, "selected-address-connect-failed")?;
            return Err(error);
        }
    };
    let actual = match request.kind {
        RequestKind::Connect => handle_connect(
            client,
            upstream,
            runtime,
            &authorization,
            request.received_head_bytes,
        )?,
        RequestKind::Forward {
            outbound_head,
            content_length,
            body_prefix,
            websocket,
        } => handle_forward(
            client,
            upstream,
            runtime,
            &authorization,
            &outbound_head,
            content_length,
            &body_prefix,
            websocket,
            request.received_head_bytes,
        )?,
    };
    runtime.finish(&authorization, actual)
}

/// Serve until the controller terminates the process or a receipt/invariant failure occurs.
///
/// # Errors
///
/// Returns an error if the listener cannot enter fail-fast mode or if accepting
/// connections or persisting mandatory evidence fails.
pub fn serve(
    policy: Policy,
    listener: &TcpListener,
    recorder: ReceiptRecorder,
) -> Result<(), String> {
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("cannot configure listener: {error}"))?;
    let runtime = Arc::new(Runtime::new(policy, recorder));
    loop {
        if runtime.fatal.load(Ordering::Acquire) {
            return Err("fatal mediator evidence failure".to_owned());
        }
        match listener.accept() {
            Ok((client, _peer)) => {
                let active = runtime.active.fetch_add(1, Ordering::AcqRel) + 1;
                if active > MAX_ACTIVE_CONNECTIONS {
                    runtime.active.fetch_sub(1, Ordering::AcqRel);
                    drop(client);
                    continue;
                }
                let runtime = Arc::clone(&runtime);
                thread::spawn(move || {
                    let _guard = ActiveGuard(Arc::clone(&runtime));
                    if let Err(error) = handle_client(client, &runtime) {
                        if error.contains("receipt") || error.contains("poisoned") {
                            runtime.fail();
                        }
                    }
                });
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::sleep(ACCEPT_POLL),
            Err(error) => return Err(format!("listener failed: {error}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::time::SystemTime;

    fn policy_value() -> Value {
        serde_json::json!({
            "allowedTransports": ["http", "https-connect", "websocket", "mcp-http"],
            "artifactType": "sova.worker-network-mediator-policy",
            "budgets": {"expiresAt": "2099-01-01T00:00:00Z", "maximumBytes": 1_048_576, "maximumConnections": 8},
            "invariants": {"dnsPinsRevalidated": true, "dnsResolvedByMediator": true, "privateAddressesDefaultDenied": true, "rawTcpUdpSupported": false, "selectedAddressBoundToConnection": true},
            "jobId": "job-test",
            "launchPlanDigest": format!("sha256:{}", "2".repeat(64)),
            "listen": {"address": "100.64.0.2", "port": 8888},
            "manifestDigest": format!("sha256:{}", "1".repeat(64)),
            "receiptArtifactType": "sova.worker-network-receipt",
            "rules": [{"allowPrivate": false, "hostname": "example.com", "initialAddresses": ["93.184.216.34"], "port": 443, "protocol": "tcp"}],
            "schemaVersion": "0.1.0"
        })
    }

    fn encoded_policy() -> Vec<u8> {
        let mut value = policy_value();
        let unsigned = canonical_bytes(&value).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("contentDigest".to_owned(), Value::String(digest(&unsigned)));
        canonical_bytes(&value).unwrap()
    }

    #[test]
    fn policy_accepts_exact_canonical_contract() {
        let parsed = parse_policy(&encoded_policy()).unwrap();
        assert_eq!(parsed.listen_authority(), "100.64.0.2:8888");
    }

    #[test]
    fn python_controller_policy_fixture_is_wire_compatible() {
        let raw =
            include_bytes!("../../../../tests/fixtures/worker/network-mediator-policy-python.json");
        let parsed = parse_policy(raw.strip_suffix(b"\n").unwrap_or(raw)).unwrap();
        assert_eq!(parsed.listen_authority(), "127.0.0.1:8888");
        assert_eq!(parsed.job_id, "job:mediator-cross-language-fixture");
    }

    #[test]
    fn authorization_requires_exact_dns_set_and_selects_a_literal_pin() {
        let policy = parse_policy(&encoded_policy()).unwrap();
        let endpoint = Endpoint {
            hostname: "example.com".to_owned(),
            port: 443,
        };
        let matching: BTreeSet<IpAddr> =
            std::iter::once("93.184.216.34".parse().unwrap()).collect();
        let allowed =
            resolve_authorization_with(&policy, endpoint.clone(), |_| Ok(matching)).unwrap();
        assert_eq!(allowed.selected, Some("93.184.216.34".parse().unwrap()));

        let changed: BTreeSet<IpAddr> = std::iter::once("8.8.8.8".parse().unwrap()).collect();
        let denied =
            resolve_authorization_with(&policy, endpoint.clone(), |_| Ok(changed)).unwrap_err();
        assert_eq!(
            denied.pins,
            vec!["93.184.216.34".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(denied.resolved, vec!["8.8.8.8".parse::<IpAddr>().unwrap()]);

        let failed = resolve_authorization_with(&policy, endpoint, |_| Err(())).unwrap_err();
        assert!(failed.resolved.is_empty());
        let unlisted = resolve_authorization_with(
            &policy,
            Endpoint {
                hostname: "other.example".to_owned(),
                port: 443,
            },
            |_| panic!("unlisted endpoints must not reach DNS"),
        )
        .unwrap_err();
        assert!(unlisted.pins.is_empty());
    }

    #[test]
    fn policy_rejects_noncanonical_or_tampered_contract() {
        let mut raw = encoded_policy();
        raw.push(b' ');
        assert!(parse_policy(&raw).unwrap_err().contains("canonical"));
        let mut value: Value = serde_json::from_slice(&encoded_policy()).unwrap();
        value["budgets"]["maximumConnections"] = Value::from(9);
        assert!(parse_policy(&canonical_bytes(&value).unwrap())
            .unwrap_err()
            .contains("contentDigest"));

        let mut value = policy_value();
        value["rules"][0]
            .as_object_mut()
            .unwrap()
            .remove("allowPrivate");
        let unsigned = canonical_bytes(&value).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("contentDigest".to_owned(), Value::String(digest(&unsigned)));
        assert!(parse_policy(&canonical_bytes(&value).unwrap())
            .unwrap_err()
            .contains("contract"));
    }

    #[test]
    fn policy_rejects_udp_and_prohibited_pins() {
        let mut value = policy_value();
        value["rules"][0]["protocol"] = Value::String("udp".to_owned());
        let unsigned = canonical_bytes(&value).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("contentDigest".to_owned(), Value::String(digest(&unsigned)));
        assert!(parse_policy(&canonical_bytes(&value).unwrap())
            .unwrap_err()
            .contains("unsupported"));

        let mut value = policy_value();
        value["rules"][0]["initialAddresses"] = serde_json::json!(["127.0.0.1"]);
        let unsigned = canonical_bytes(&value).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("contentDigest".to_owned(), Value::String(digest(&unsigned)));
        assert!(parse_policy(&canonical_bytes(&value).unwrap())
            .unwrap_err()
            .contains("prohibited"));
    }

    #[test]
    fn address_floor_allows_only_global_or_explicit_private() {
        assert!(address_admissible("8.8.8.8".parse().unwrap(), false));
        assert!(!address_admissible("10.0.0.1".parse().unwrap(), false));
        assert!(address_admissible("10.0.0.1".parse().unwrap(), true));
        assert!(!address_admissible("127.0.0.1".parse().unwrap(), true));
        assert!(!address_admissible(
            "169.254.169.254".parse().unwrap(),
            true
        ));
        assert!(!address_admissible("2001:db8::1".parse().unwrap(), false));
        assert!(!address_admissible("2001::1".parse().unwrap(), false));
        assert!(!address_admissible(
            "2002:c000:0204::1".parse().unwrap(),
            false
        ));
        assert!(!address_admissible("3fff::1".parse().unwrap(), false));
        assert!(address_admissible(
            "2606:4700:4700::1111".parse().unwrap(),
            false
        ));
    }

    fn parse(raw: &[u8]) -> Result<ParsedRequest, String> {
        let mut cursor = Cursor::new(raw.to_vec());
        let mut data = Vec::new();
        cursor.read_to_end(&mut data).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let client = thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            stream.write_all(&data).unwrap();
        });
        let (mut server, _) = listener.accept().unwrap();
        let result = read_request(&mut server);
        client.join().unwrap();
        result
    }

    #[test]
    fn request_parser_binds_connect_and_forward_authority() {
        let connect =
            parse(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n").unwrap();
        assert_eq!(
            connect.endpoint,
            Endpoint {
                hostname: "example.com".to_owned(),
                port: 443
            }
        );
        assert!(matches!(connect.kind, RequestKind::Connect));

        let forward = parse(b"POST http://example.com/api?q=1 HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\nabc").unwrap();
        assert_eq!(forward.endpoint.port, 80);
        assert!(matches!(
            forward.kind,
            RequestKind::Forward {
                content_length: 3,
                ..
            }
        ));
    }

    #[test]
    fn request_parser_rejects_confusion_and_pipelining() {
        assert!(
            parse(b"CONNECT example.com:443 HTTP/1.1\r\nHost: other.example:443\r\n\r\n")
                .unwrap_err()
                .contains("disagree")
        );
        assert!(parse(
            b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nHost: example.com\r\n\r\n"
        )
        .unwrap_err()
        .contains("exactly one"));
        assert!(parse(b"POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1\r\n\r\nab").unwrap_err().contains("pipelined"));
    }

    fn client_hello(hostname: &str) -> Vec<u8> {
        let name = hostname.as_bytes();
        let mut sni = Vec::new();
        sni.extend_from_slice(&(u16::try_from(name.len() + 3).unwrap()).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(u16::try_from(name.len()).unwrap()).to_be_bytes());
        sni.extend_from_slice(name);
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0_u16.to_be_bytes());
        extensions.extend_from_slice(&(u16::try_from(sni.len()).unwrap()).to_be_bytes());
        extensions.extend_from_slice(&sni);
        let mut body = vec![3, 3];
        body.extend_from_slice(&[0_u8; 32]);
        body.push(0);
        body.extend_from_slice(&2_u16.to_be_bytes());
        body.extend_from_slice(&0x1301_u16.to_be_bytes());
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(u16::try_from(extensions.len()).unwrap()).to_be_bytes());
        body.extend_from_slice(&extensions);
        let mut handshake = vec![1, 0, 0, u8::try_from(body.len()).unwrap()];
        handshake.extend_from_slice(&body);
        handshake
    }

    #[test]
    fn tls_parser_requires_exact_sni() {
        let hello = client_hello("example.com");
        assert_eq!(client_hello_sni(&hello).unwrap(), "example.com");
        assert_ne!(client_hello_sni(&hello).unwrap(), "other.example");
        assert!(client_hello_sni(&[1, 0, 0, 0]).is_err());
    }

    #[test]
    fn recorder_emits_controller_compatible_canonical_receipts() {
        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("sova-mediator-test-{nonce}"));
        fs::create_dir(&root).unwrap();
        let mut recorder = ReceiptRecorder::open(&root, "job-test".to_owned()).unwrap();
        let authorization = Authorization {
            endpoint: Endpoint {
                hostname: "example.com".to_owned(),
                port: 443,
            },
            pins: vec!["93.184.216.34".parse().unwrap()],
            resolved: vec!["93.184.216.34".parse().unwrap()],
            selected: Some("93.184.216.34".parse().unwrap()),
            allow_private: false,
        };
        recorder
            .record(&authorization, 12, "allowed", "flow-complete")
            .unwrap();
        let raw = fs::read(root.join("000001.json")).unwrap();
        let value: Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(canonical_bytes(&value).unwrap(), raw);
        let unsigned = policy_without_named_digest(&value, "contentDigest").unwrap();
        assert_eq!(
            value["contentDigest"],
            Value::String(digest(&canonical_bytes(&unsigned).unwrap()))
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recorder_never_replaces_a_raced_final_receipt() {
        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("sova-mediator-race-test-{nonce}"));
        fs::create_dir(&root).unwrap();
        let mut recorder = ReceiptRecorder::open(&root, "job-test".to_owned()).unwrap();
        let final_path = root.join("000001.json");
        fs::write(&final_path, b"existing").unwrap();
        let authorization = Authorization {
            endpoint: Endpoint {
                hostname: "example.com".to_owned(),
                port: 443,
            },
            pins: vec!["93.184.216.34".parse().unwrap()],
            resolved: vec!["93.184.216.34".parse().unwrap()],
            selected: Some("93.184.216.34".parse().unwrap()),
            allow_private: false,
        };
        let error = recorder
            .record(&authorization, 12, "allowed", "flow-complete")
            .unwrap_err();
        assert!(error.contains("without replacement"));
        assert_eq!(fs::read(&final_path).unwrap(), b"existing");
        assert!(root.join(".000001.tmp").is_file());
        fs::remove_dir_all(root).unwrap();
    }

    fn policy_without_named_digest(value: &Value, key: &str) -> Result<Value, String> {
        let mut unsigned = value.clone();
        unsigned
            .as_object_mut()
            .ok_or("not object")?
            .remove(key)
            .ok_or("missing")?;
        Ok(unsigned)
    }
}
