//! Local configuration snapshots and diffing.
//!
//! Snapshots are written to a local directory only; nothing is ever uploaded.
//! To limit the damage if a snapshot file is shared by accident:
//! - environment and header values are stored only as salted SHA-256
//!   fingerprints (truncated), never as text;
//! - arguments, URLs and other settings that look like credentials are replaced
//!   with `<redacted>`;
//! - on Unix the directory is created with mode 0700 and files with mode 0600.
//!
//! A fingerprint of every server's full content is also stored so that changes
//! to redacted values are still detected (but never shown).

use crate::config::{McpConfig, ServerConfig};
use crate::scanner::{classify_secret, is_name_like, parse_url, secret_args};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const FORMAT_VERSION: u32 = 1;
const REDACTED: &str = "<redacted>";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum SnapshotError {
    Io { context: String, source: io::Error },
    NotFound { config: String, dir: String },
    Corrupt { file: String, reason: String },
    NoDataDir,
}

impl SnapshotError {
    fn io(context: String, source: io::Error) -> Self {
        SnapshotError::Io { context, source }
    }
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SnapshotError::Io { context, source } => write!(f, "{context}: {source}"),
            SnapshotError::NotFound { config, dir } => write!(
                f,
                "no snapshot found for '{config}' in '{dir}'; create one first with `mcpwatch snapshot {config}`"
            ),
            SnapshotError::Corrupt { file, reason } => {
                write!(f, "snapshot '{file}' cannot be used: {reason}")
            }
            SnapshotError::NoDataDir => write!(
                f,
                "cannot determine a local data directory; pass --snapshot-dir or set MCPWATCH_HOME"
            ),
        }
    }
}

impl Error for SnapshotError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            SnapshotError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    pub format_version: u32,
    pub tool_version: String,
    pub created_unix: u64,
    pub source_path: String,
    pub salt: String,
    pub servers: Vec<ServerSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerSnapshot {
    pub id: String,
    #[serde(default)]
    pub transport: Option<String>,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    /// Variable name -> salted fingerprint of the value.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub url: Option<String>,
    /// Header name -> salted fingerprint of the value.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// Setting name -> compact JSON with credential-like values redacted.
    #[serde(default)]
    pub settings: BTreeMap<String, String>,
    /// Salted fingerprint of the complete, unredacted server definition.
    pub fingerprint: String,
}

impl Snapshot {
    pub fn build(config: &McpConfig, source_path: String, salt: String, created_unix: u64) -> Self {
        let servers = config
            .servers
            .iter()
            .map(|s| ServerSnapshot::from_server(s, &salt))
            .collect();
        Snapshot {
            format_version: FORMAT_VERSION,
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            created_unix,
            source_path,
            salt,
            servers,
        }
    }
}

impl ServerSnapshot {
    fn from_server(s: &ServerConfig, salt: &str) -> Self {
        let secrets: HashMap<usize, bool> = secret_args(&s.args)
            .into_iter()
            .map(|a| (a.index, a.value_only))
            .collect();
        let args: Vec<String> = s
            .args
            .iter()
            .enumerate()
            .map(|(i, a)| match secrets.get(&i).copied() {
                Some(true) => REDACTED.to_string(),
                Some(false) => redact_arg(a),
                None => a.clone(),
            })
            .collect();
        let command = s.command.as_deref().map(|c| {
            if classify_secret(None, c).is_some() {
                REDACTED.to_string()
            } else {
                c.to_string()
            }
        });
        let env: BTreeMap<String, String> = s
            .env
            .iter()
            .map(|(k, v)| (k.clone(), fingerprint(salt, v)))
            .collect();
        let headers: BTreeMap<String, String> = s
            .headers
            .iter()
            .map(|(k, v)| (k.clone(), fingerprint(salt, v)))
            .collect();
        let settings: BTreeMap<String, String> = s
            .settings
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    serde_json::to_string(&redact_json(Some(k), v)).unwrap_or_default(),
                )
            })
            .collect();
        let raw = json!({
            "id": s.path,
            "transport": s.transport,
            "command": s.command,
            "args": s.args,
            "env": s.env,
            "url": s.url,
            "headers": s.headers,
            "settings": s.settings,
        });
        ServerSnapshot {
            id: s.path.clone(),
            transport: s.transport.clone(),
            command,
            args,
            env,
            url: s.url.as_deref().map(redact_url),
            headers,
            settings,
            fingerprint: fingerprint(salt, &raw.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

fn safe_name(name: &str) -> bool {
    is_name_like(name) && name.len() <= 40 && classify_secret(None, name).is_none()
}

fn redact_arg(arg: &str) -> String {
    if let Some((n, _)) = arg.split_once('=') {
        if safe_name(n) {
            return format!("{n}={REDACTED}");
        }
    }
    if let Some((n, _)) = arg.split_once(':') {
        if safe_name(n) {
            return format!("{n}: {REDACTED}");
        }
    }
    REDACTED.to_string()
}

fn redact_url(url: &str) -> String {
    let Some(p) = parse_url(url) else {
        return if classify_secret(None, url).is_some() {
            REDACTED.to_string()
        } else {
            url.to_string()
        };
    };
    let mut out = format!("{}://", p.scheme);
    if p.userinfo.is_some() {
        out.push_str(REDACTED);
        out.push('@');
    }
    out.push_str(p.hostport);
    out.push_str(p.path);
    if let Some(query) = p.query {
        let cleaned: Vec<String> = query
            .split('&')
            .map(|pair| match pair.split_once('=') {
                Some((k, v)) if classify_secret(Some(k), v).is_some() => {
                    format!("{k}={REDACTED}")
                }
                _ => pair.to_string(),
            })
            .collect();
        out.push('?');
        out.push_str(&cleaned.join("&"));
    }
    out
}

fn redact_json(name: Option<&str>, value: &Value) -> Value {
    match value {
        Value::String(s) => {
            if classify_secret(name, s).is_some() {
                Value::String(REDACTED.to_string())
            } else {
                value.clone()
            }
        }
        Value::Array(items) => Value::Array(items.iter().map(|v| redact_json(name, v)).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), redact_json(Some(k), v)))
                .collect(),
        ),
        _ => value.clone(),
    }
}

// ---------------------------------------------------------------------------
// Hashing (SHA-256, implemented with the standard library only)
// ---------------------------------------------------------------------------

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[4 * i],
                chunk[4 * i + 1],
                chunk[4 * i + 2],
                chunk[4 * i + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    h.iter().map(|x| format!("{x:08x}")).collect()
}

fn fingerprint(salt: &str, data: &str) -> String {
    let digest = sha256_hex(format!("{salt}\0{data}").as_bytes());
    digest[..16].to_string()
}

fn new_salt() -> String {
    let mut seed: Vec<u8> = Vec::new();
    if let Ok(mut f) = File::open("/dev/urandom") {
        let mut buf = [0u8; 16];
        if f.read_exact(&mut buf).is_ok() {
            seed.extend_from_slice(&buf);
        }
    }
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    seed.extend_from_slice(&nanos.to_le_bytes());
    seed.extend_from_slice(&std::process::id().to_le_bytes());
    seed.extend_from_slice(format!("{:?}", std::thread::current().id()).as_bytes());
    sha256_hex(&seed)[..32].to_string()
}

// ---------------------------------------------------------------------------
// Time formatting
// ---------------------------------------------------------------------------

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Formats a Unix timestamp as `YYYY-MM-DD HH:MM:SS UTC`.
pub fn format_utc(unix: u64) -> String {
    let (y, m, d) = civil_from_days((unix / 86_400) as i64);
    let rem = unix % 86_400;
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// Platform default location for snapshots (a per-user data directory).
pub fn default_dir() -> Result<PathBuf, SnapshotError> {
    let base = if cfg!(windows) {
        env_path("LOCALAPPDATA")
            .or_else(|| env_path("USERPROFILE").map(|p| p.join("AppData").join("Local")))
    } else if cfg!(target_os = "macos") {
        env_path("HOME").map(|p| p.join("Library").join("Application Support"))
    } else {
        env_path("XDG_DATA_HOME").or_else(|| env_path("HOME").map(|p| p.join(".local").join("share")))
    };
    base.map(|b| b.join("mcpwatch").join("snapshots"))
        .ok_or(SnapshotError::NoDataDir)
}

#[cfg(unix)]
fn create_private_dir(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().recursive(true).mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_private_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)
}

#[cfg(unix)]
fn private_open_options() -> OpenOptions {
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = OpenOptions::new();
    options.mode(0o600);
    options
}

#[cfg(not(unix))]
fn private_open_options() -> OpenOptions {
    OpenOptions::new()
}

fn write_new_private(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut options = private_open_options();
    options.write(true).create_new(true);
    let mut file = options.open(path)?;
    let result = file.write_all(data).and_then(|_| file.sync_all());
    if result.is_err() {
        drop(file);
        let _ = fs::remove_file(path);
    }
    result
}

/// Returns a file-name stem and a stable identifier for a configuration path.
fn file_key(config_path: &Path) -> (String, String) {
    let canonical = fs::canonicalize(config_path).unwrap_or_else(|_| config_path.to_path_buf());
    let id = sha256_hex(canonical.to_string_lossy().as_bytes())[..16].to_string();
    let stem: String = canonical
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("config")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(32)
        .collect();
    (stem, id)
}

/// Writes a new snapshot of `config` into `dir` and returns its path.
pub fn save(dir: &Path, config_path: &Path, config: &McpConfig) -> Result<PathBuf, SnapshotError> {
    create_private_dir(dir).map_err(|e| {
        SnapshotError::io(
            format!("cannot create snapshot directory '{}'", dir.display()),
            e,
        )
    })?;
    let (stem, id) = file_key(config_path);
    let canonical = fs::canonicalize(config_path).unwrap_or_else(|_| config_path.to_path_buf());
    let snapshot = Snapshot::build(
        config,
        canonical.display().to_string(),
        new_salt(),
        now_millis() / 1000,
    );
    let json = serde_json::to_string_pretty(&snapshot).map_err(|e| {
        SnapshotError::io(
            "cannot serialize snapshot".to_string(),
            io::Error::new(io::ErrorKind::InvalidData, e),
        )
    })?;

    let mut millis = now_millis();
    for _ in 0..16 {
        let file = dir.join(format!("{stem}-{id}.{millis:013}.json"));
        match write_new_private(&file, json.as_bytes()) {
            Ok(()) => return Ok(file),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => millis += 1,
            Err(e) => {
                return Err(SnapshotError::io(
                    format!("cannot write snapshot '{}'", file.display()),
                    e,
                ))
            }
        }
    }
    Err(SnapshotError::io(
        "cannot allocate a unique snapshot file name".to_string(),
        io::Error::from(io::ErrorKind::AlreadyExists),
    ))
}

pub struct LoadedSnapshot {
    pub snapshot: Snapshot,
    pub file: PathBuf,
}

/// Loads the most recent snapshot taken for `config_path`.
pub fn load_latest(dir: &Path, config_path: &Path) -> Result<LoadedSnapshot, SnapshotError> {
    let not_found = || SnapshotError::NotFound {
        config: config_path.display().to_string(),
        dir: dir.display().to_string(),
    };
    let (stem, id) = file_key(config_path);
    let prefix = format!("{stem}-{id}.");
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(not_found()),
        Err(e) => {
            return Err(SnapshotError::io(
                format!("cannot read snapshot directory '{}'", dir.display()),
                e,
            ))
        }
    };

    let mut best: Option<(String, PathBuf)> = None;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(&prefix) && name.ends_with(".json") {
            let newer = best.as_ref().map_or(true, |(b, _)| name > *b);
            if newer {
                best = Some((name, entry.path()));
            }
        }
    }
    let (_, file) = best.ok_or_else(not_found)?;

    let text = fs::read_to_string(&file).map_err(|e| {
        SnapshotError::io(format!("cannot read snapshot '{}'", file.display()), e)
    })?;
    let snapshot: Snapshot = serde_json::from_str(&text).map_err(|e| SnapshotError::Corrupt {
        file: file.display().to_string(),
        reason: e.to_string(),
    })?;
    if snapshot.format_version != FORMAT_VERSION {
        return Err(SnapshotError::Corrupt {
            file: file.display().to_string(),
            reason: format!("unsupported format version {}", snapshot.format_version),
        });
    }
    Ok(LoadedSnapshot { snapshot, file })
}

// ---------------------------------------------------------------------------
// Diff
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    Added,
    Removed,
    Modified,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub id: String,
    pub kind: ChangeKind,
    pub details: Vec<String>,
}

fn opt(value: &Option<String>) -> String {
    match value {
        Some(v) => format!("`{v}`"),
        None => "(none)".to_string(),
    }
}

fn describe(s: &ServerSnapshot) -> Vec<String> {
    let mut details = Vec::new();
    if let Some(c) = &s.command {
        let n = s.args.len();
        details.push(format!(
            "command: `{c}` with {n} argument{}",
            if n == 1 { "" } else { "s" }
        ));
    }
    if let Some(u) = &s.url {
        details.push(format!("url: {u}"));
    }
    if !s.env.is_empty() {
        let names: Vec<&str> = s.env.keys().map(String::as_str).collect();
        details.push(format!("env: {}", names.join(", ")));
    }
    details
}

fn compare_maps(
    label: &str,
    before: &BTreeMap<String, String>,
    after: &BTreeMap<String, String>,
    show_values: bool,
    details: &mut Vec<String>,
) {
    for (k, v) in after {
        match before.get(k) {
            None => details.push(format!("{label} added: {k}")),
            Some(old) if old != v => {
                if show_values {
                    details.push(format!("{label} `{k}` changed: {old} -> {v}"));
                } else {
                    details.push(format!("{label} value changed: {k} (value not shown)"));
                }
            }
            Some(_) => {}
        }
    }
    for k in before.keys() {
        if !after.contains_key(k) {
            details.push(format!("{label} removed: {k}"));
        }
    }
}

fn compare(before: &ServerSnapshot, after: &ServerSnapshot) -> Vec<String> {
    let mut details = Vec::new();
    if before.transport != after.transport {
        details.push(format!(
            "transport: {} -> {}",
            opt(&before.transport),
            opt(&after.transport)
        ));
    }
    if before.command != after.command {
        details.push(format!(
            "command: {} -> {}",
            opt(&before.command),
            opt(&after.command)
        ));
    }
    if before.args != after.args {
        details.push(format!("args: {:?} -> {:?}", before.args, after.args));
    }
    if before.url != after.url {
        details.push(format!("url: {} -> {}", opt(&before.url), opt(&after.url)));
    }
    compare_maps("env", &before.env, &after.env, false, &mut details);
    compare_maps("header", &before.headers, &after.headers, false, &mut details);
    compare_maps("setting", &before.settings, &after.settings, true, &mut details);
    if details.is_empty() && before.fingerprint != after.fingerprint {
        details.push(
            "values that are not stored in the snapshot changed (for example a redacted argument)"
                .to_string(),
        );
    }
    details
}

/// Compares the current configuration with a stored snapshot. Servers are
/// matched by their dotted path (for example `mcpServers.github`).
pub fn diff(old: &Snapshot, config: &McpConfig) -> Vec<Change> {
    let current: BTreeMap<String, ServerSnapshot> = config
        .servers
        .iter()
        .map(|s| (s.path.clone(), ServerSnapshot::from_server(s, &old.salt)))
        .collect();
    let previous: BTreeMap<&str, &ServerSnapshot> =
        old.servers.iter().map(|s| (s.id.as_str(), s)).collect();

    let mut changes = Vec::new();
    for (id, now) in &current {
        match previous.get(id.as_str()) {
            None => changes.push(Change {
                id: id.clone(),
                kind: ChangeKind::Added,
                details: describe(now),
            }),
            Some(before) => {
                let details = compare(before, now);
                if !details.is_empty() {
                    changes.push(Change {
                        id: id.clone(),
                        kind: ChangeKind::Modified,
                        details,
                    });
                }
            }
        }
    }
    for (id, before) in &previous {
        if !current.contains_key(*id) {
            changes.push(Change {
                id: (*id).to_string(),
                kind: ChangeKind::Removed,
                details: describe(before),
            });
        }
    }
    changes.sort_by(|a, b| a.id.cmp(&b.id));
    changes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let dir = std::env::temp_dir().join(format!(
                "mcpwatch-unit-{}-{}-{}",
                std::process::id(),
                now_millis(),
                n
            ));
            fs::create_dir_all(&dir).unwrap();
            TempDir(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn cfg(json: &str) -> McpConfig {
        config::parse(json).expect("valid test configuration")
    }

    #[test]
    fn sha256_matches_known_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let long = "a".repeat(1000);
        assert_eq!(sha256_hex(long.as_bytes()).len(), 64);
    }

    #[test]
    fn formats_utc_timestamps() {
        assert_eq!(format_utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(format_utc(1_000_000_000), "2001-09-09 01:46:40 UTC");
    }

    #[test]
    fn snapshot_never_stores_secret_values() {
        let config = cfg(
            r#"{"mcpServers":{"a":{"command":"node","args":["s.js","--token","tok-123456789","--password=pw-abcdefgh"],"env":{"API_KEY":"supersecretvalue"},"url":"https://u:pw12345@h.example/x?token=abcdefgh"}}}"#,
        );
        let snap = Snapshot::build(&config, "test".into(), "salt".into(), 0);
        let json = serde_json::to_string(&snap).unwrap();
        for secret in [
            "tok-123456789",
            "pw-abcdefgh",
            "supersecretvalue",
            "pw12345",
            "abcdefgh",
        ] {
            assert!(!json.contains(secret), "snapshot leaked {secret}");
        }
        assert!(json.contains("--password=<redacted>"));
        assert!(json.contains("https://<redacted>@h.example/x?token=<redacted>"));
        assert!(json.contains("API_KEY"));
    }

    #[test]
    fn detects_added_removed_and_modified_servers() {
        let old = cfg(
            r#"{"mcpServers":{
                "a":{"command":"node","args":["a.js"]},
                "b":{"command":"node","args":["b.js"]},
                "c":{"command":"node","args":["c.js"],"env":{"K":"1"},"autoApprove":["x"]}}}"#,
        );
        let new = cfg(
            r#"{"mcpServers":{
                "a":{"command":"deno","args":["a2.js"]},
                "c":{"command":"node","args":["c.js"],"env":{"K":"2","NEW":"x"},"autoApprove":["x","y"]},
                "d":{"command":"node","args":["d.js"]}}}"#,
        );
        let snap = Snapshot::build(&old, "t".into(), "salt".into(), 0);
        let changes = diff(&snap, &new);

        let kinds: Vec<(&str, ChangeKind)> =
            changes.iter().map(|c| (c.id.as_str(), c.kind)).collect();
        assert_eq!(
            kinds,
            vec![
                ("mcpServers.a", ChangeKind::Modified),
                ("mcpServers.b", ChangeKind::Removed),
                ("mcpServers.c", ChangeKind::Modified),
                ("mcpServers.d", ChangeKind::Added),
            ]
        );
        let a = &changes[0].details;
        assert!(a.iter().any(|d| d.starts_with("command:")));
        assert!(a.iter().any(|d| d.starts_with("args:")));
        let c = &changes[2].details;
        assert!(c.iter().any(|d| d == "env added: NEW"));
        assert!(c.iter().any(|d| d == "env value changed: K (value not shown)"));
        assert!(c.iter().any(|d| d.starts_with("setting `autoApprove` changed")));
    }

    #[test]
    fn identical_configuration_has_no_changes() {
        let text = r#"{"mcpServers":{"a":{"command":"node","env":{"K":"v"}}}}"#;
        let snap = Snapshot::build(&cfg(text), "t".into(), "salt".into(), 0);
        assert!(diff(&snap, &cfg(text)).is_empty());
    }

    #[test]
    fn changes_to_redacted_values_are_still_detected() {
        let old = cfg(r#"{"mcpServers":{"a":{"command":"node","args":["--token","tok-aaaaaaaa"]}}}"#);
        let new = cfg(r#"{"mcpServers":{"a":{"command":"node","args":["--token","tok-bbbbbbbb"]}}}"#);
        let snap = Snapshot::build(&old, "t".into(), "salt".into(), 0);
        let changes = diff(&snap, &new);
        assert_eq!(changes.len(), 1);
        assert!(changes[0].details[0].contains("not stored"));
        assert!(!changes[0].details.iter().any(|d| d.contains("tok-")));
    }

    #[test]
    fn save_and_load_latest_round_trip() {
        let tmp = TempDir::new();
        let config_path = tmp.0.join("mcp.json");
        fs::write(&config_path, "{}").unwrap();
        let snap_dir = tmp.0.join("snaps");

        let first = cfg(r#"{"mcpServers":{"a":{"command":"node"}}}"#);
        let second = cfg(r#"{"mcpServers":{"a":{"command":"node"},"b":{"command":"deno"}}}"#);
        let f1 = save(&snap_dir, &config_path, &first).unwrap();
        let f2 = save(&snap_dir, &config_path, &second).unwrap();
        assert_ne!(f1, f2);

        let loaded = load_latest(&snap_dir, &config_path).unwrap();
        assert_eq!(loaded.file, f2);
        assert_eq!(loaded.snapshot.servers.len(), 2);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let file_mode = fs::metadata(&f2).unwrap().permissions().mode() & 0o777;
            assert_eq!(file_mode, 0o600);
            let dir_mode = fs::metadata(&snap_dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(dir_mode, 0o700);
        }
    }

    #[test]
    fn missing_or_corrupt_snapshots_are_reported() {
        let tmp = TempDir::new();
        let config_path = tmp.0.join("mcp.json");
        fs::write(&config_path, "{}").unwrap();
        let missing = tmp.0.join("nothing-here");
        assert!(matches!(
            load_latest(&missing, &config_path),
            Err(SnapshotError::NotFound { .. })
        ));

        let dir = tmp.0.join("snaps");
        fs::create_dir_all(&dir).unwrap();
        assert!(matches!(
            load_latest(&dir, &config_path),
            Err(SnapshotError::NotFound { .. })
        ));

        let (stem, id) = file_key(&config_path);
        fs::write(dir.join(format!("{stem}-{id}.0000000000001.json")), "not json").unwrap();
        assert!(matches!(
            load_latest(&dir, &config_path),
            Err(SnapshotError::Corrupt { .. })
        ));
    }
}
