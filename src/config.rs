//! Loading and normalising MCP client configuration files.
//!
//! Supported layouts (plain JSON only):
//! - `mcpServers`      (Claude Desktop, Cursor, Windsurf, project `.mcp.json` files)
//! - `servers`         (VS Code `mcp.json`)
//! - `mcp.servers`     (VS Code `settings.json`)
//! - `context_servers` (Zed), including its nested `command` object
//!
//! Nothing here executes or resolves anything referenced by a configuration.

use serde_json::Value;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::Path;

const MAX_CONFIG_BYTES: u64 = 10 * 1024 * 1024;
const SERVER_CONTAINERS: &[&str] = &["mcpServers", "servers", "context_servers"];
const URL_KEYS: &[&str] = &["url", "serverUrl", "httpUrl"];
const TRANSPORT_KEYS: &[&str] = &["type", "transport"];
const HANDLED_KEYS: &[&str] = &[
    "command",
    "args",
    "env",
    "headers",
    "url",
    "serverUrl",
    "httpUrl",
    "type",
    "transport",
];

/// A structural problem found while reading a server definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigIssue {
    pub field: String,
    pub message: String,
}

impl ConfigIssue {
    fn new(field: &str, message: &str) -> Self {
        ConfigIssue {
            field: field.to_string(),
            message: message.to_string(),
        }
    }
}

/// A normalised MCP server definition.
#[derive(Debug, Clone, Default)]
pub struct ServerConfig {
    /// Key of the server inside its container (for example `github`).
    pub name: String,
    /// Dotted path of the server (for example `mcpServers.github`).
    pub path: String,
    pub transport: Option<String>,
    pub command: Option<String>,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub url: Option<String>,
    pub headers: BTreeMap<String, String>,
    /// Every other field of the definition, kept verbatim.
    pub settings: BTreeMap<String, Value>,
    pub command_path: String,
    pub args_path: String,
    pub env_path: String,
    pub headers_path: String,
    pub url_path: Option<String>,
    pub issues: Vec<ConfigIssue>,
}

/// All servers found in one configuration file.
#[derive(Debug, Clone)]
pub struct McpConfig {
    pub servers: Vec<ServerConfig>,
}

#[derive(Debug)]
pub enum ConfigError {
    Io { path: String, source: std::io::Error },
    NotAFile(String),
    NotUtf8(String),
    TooLarge { path: String, limit: u64 },
    Empty,
    Json(serde_json::Error),
    NotAnObject,
    BadContainer { key: String },
    NoServers,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io { path, source } => write!(f, "cannot read '{path}': {source}"),
            ConfigError::NotAFile(path) => write!(f, "'{path}' is not a regular file"),
            ConfigError::NotUtf8(path) => write!(f, "'{path}' is not valid UTF-8 text"),
            ConfigError::TooLarge { path, limit } => {
                write!(f, "'{path}' is larger than the {limit}-byte limit for configuration files")
            }
            ConfigError::Empty => write!(f, "the configuration file is empty"),
            ConfigError::Json(e) => write!(
                f,
                "invalid JSON: {e} (MCPWatch reads strict JSON; comments and trailing commas are not supported)"
            ),
            ConfigError::NotAnObject => {
                write!(f, "the top-level JSON value must be an object")
            }
            ConfigError::BadContainer { key } => write!(
                f,
                "`{key}` must be an object that maps server names to server definitions"
            ),
            ConfigError::NoServers => write!(
                f,
                "no MCP server definitions found (looked for `mcpServers`, `servers`, `mcp.servers` and `context_servers`)"
            ),
        }
    }
}

impl Error for ConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ConfigError::Io { source, .. } => Some(source),
            ConfigError::Json(e) => Some(e),
            _ => None,
        }
    }
}

/// Reads and parses a configuration file.
pub fn load(path: &Path) -> Result<McpConfig, ConfigError> {
    let shown = path.display().to_string();
    let io_err = |source: std::io::Error| ConfigError::Io {
        path: shown.clone(),
        source,
    };
    let meta = fs::metadata(path).map_err(io_err)?;
    if !meta.is_file() {
        return Err(ConfigError::NotAFile(shown));
    }
    if meta.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::TooLarge {
            path: shown,
            limit: MAX_CONFIG_BYTES,
        });
    }
    let bytes = fs::read(path).map_err(|source| ConfigError::Io {
        path: shown.clone(),
        source,
    })?;
    let text = String::from_utf8(bytes).map_err(|_| ConfigError::NotUtf8(shown))?;
    parse(&text)
}

/// Parses configuration text.
pub fn parse(text: &str) -> Result<McpConfig, ConfigError> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    if text.trim().is_empty() {
        return Err(ConfigError::Empty);
    }
    let value: Value = serde_json::from_str(text).map_err(ConfigError::Json)?;
    let root = value.as_object().ok_or(ConfigError::NotAnObject)?;

    let mut containers: Vec<(String, &Value)> = Vec::new();
    for key in SERVER_CONTAINERS {
        if let Some(v) = root.get(*key) {
            containers.push((key.to_string(), v));
        }
    }
    if let Some(v) = root.get("mcp").and_then(|m| m.get("servers")) {
        containers.push(("mcp.servers".to_string(), v));
    }
    if containers.is_empty() {
        return Err(ConfigError::NoServers);
    }

    let mut servers = Vec::new();
    for (key, container) in containers {
        let map = container
            .as_object()
            .ok_or_else(|| ConfigError::BadContainer { key: key.clone() })?;
        for (name, definition) in map {
            servers.push(parse_server(&key, name, definition));
        }
    }
    Ok(McpConfig { servers })
}

fn parse_server(container: &str, name: &str, def: &Value) -> ServerConfig {
    let path = format!("{container}.{name}");
    let mut server = ServerConfig {
        name: name.to_string(),
        command_path: format!("{path}.command"),
        args_path: format!("{path}.args"),
        env_path: format!("{path}.env"),
        headers_path: format!("{path}.headers"),
        path: path.clone(),
        ..ServerConfig::default()
    };

    let Some(obj) = def.as_object() else {
        server
            .issues
            .push(ConfigIssue::new(&path, "server definition must be a JSON object"));
        return server;
    };

    let mut nested_command = false;
    match obj.get("command") {
        Some(Value::String(c)) => server.command = Some(c.clone()),
        Some(Value::Object(nested)) => {
            nested_command = true;
            server.command_path = format!("{path}.command.path");
            server.args_path = format!("{path}.command.args");
            server.env_path = format!("{path}.command.env");
            match nested.get("path") {
                Some(Value::String(p)) => server.command = Some(p.clone()),
                _ => server
                    .issues
                    .push(ConfigIssue::new(&server.command_path, "`path` must be a string")),
            }
            if let Some(a) = nested.get("args") {
                server.args = parse_string_list(a, &server.args_path, &mut server.issues);
            }
            if let Some(e) = nested.get("env") {
                server.env = parse_string_map(e, &server.env_path, &mut server.issues);
            }
        }
        Some(other) => server.issues.push(ConfigIssue::new(
            &server.command_path,
            &format!("`command` must be a string, found {}", json_type(other)),
        )),
        None => {}
    }

    if !nested_command {
        if let Some(a) = obj.get("args") {
            server.args = parse_string_list(a, &server.args_path, &mut server.issues);
        }
        if let Some(e) = obj.get("env") {
            server.env = parse_string_map(e, &server.env_path, &mut server.issues);
        }
    }
    if let Some(h) = obj.get("headers") {
        server.headers = parse_string_map(h, &server.headers_path, &mut server.issues);
    }

    for key in URL_KEYS {
        if let Some(v) = obj.get(*key) {
            let field = format!("{path}.{key}");
            match v {
                Value::String(u) => {
                    if server.url.is_none() {
                        server.url = Some(u.clone());
                        server.url_path = Some(field);
                    }
                }
                other => server.issues.push(ConfigIssue::new(
                    &field,
                    &format!("`{key}` must be a string, found {}", json_type(other)),
                )),
            }
        }
    }

    for key in TRANSPORT_KEYS {
        if let Some(v) = obj.get(*key) {
            match v {
                Value::String(t) => {
                    if server.transport.is_none() {
                        server.transport = Some(t.clone());
                    }
                }
                other => server.issues.push(ConfigIssue::new(
                    &format!("{path}.{key}"),
                    &format!("`{key}` must be a string, found {}", json_type(other)),
                )),
            }
        }
    }

    for (key, value) in obj {
        if !HANDLED_KEYS.contains(&key.as_str()) {
            server.settings.insert(key.clone(), value.clone());
        }
    }

    let has_url_key = URL_KEYS.iter().any(|k| obj.contains_key(*k));
    if !obj.contains_key("command") && !has_url_key {
        server.issues.push(ConfigIssue::new(
            &path,
            "server defines neither `command` nor a URL, so a client has nothing to start or connect to",
        ));
    }

    server
}

fn parse_string_list(value: &Value, field: &str, issues: &mut Vec<ConfigIssue>) -> Vec<String> {
    let Some(items) = value.as_array() else {
        issues.push(ConfigIssue::new(field, "must be an array of strings"));
        return Vec::new();
    };
    items
        .iter()
        .enumerate()
        .map(|(i, item)| scalar_to_string(item, &format!("{field}[{i}]"), issues))
        .collect()
}

fn parse_string_map(
    value: &Value,
    field: &str,
    issues: &mut Vec<ConfigIssue>,
) -> BTreeMap<String, String> {
    let Some(map) = value.as_object() else {
        issues.push(ConfigIssue::new(field, "must be an object of string values"));
        return BTreeMap::new();
    };
    map.iter()
        .map(|(k, v)| (k.clone(), scalar_to_string(v, &format!("{field}.{k}"), issues)))
        .collect()
}

/// Converts a JSON value to text. Non-string scalars are accepted but reported,
/// because most clients expect strings here.
fn scalar_to_string(value: &Value, field: &str, issues: &mut Vec<ConfigIssue>) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(_) | Value::Bool(_) => {
            issues.push(ConfigIssue::new(
                field,
                &format!("expected a string, found {}", json_type(value)),
            ));
            value.to_string()
        }
        other => {
            issues.push(ConfigIssue::new(
                field,
                &format!("expected a string, found {}", json_type(other)),
            ));
            String::new()
        }
    }
}

fn json_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mcp_servers_layout() {
        let cfg = parse(
            r#"{"mcpServers":{"gh":{"command":"npx","args":["-y","pkg"],"env":{"A":"b"},"extra":true}}}"#,
        )
        .unwrap();
        assert_eq!(cfg.servers.len(), 1);
        let s = &cfg.servers[0];
        assert_eq!(s.name, "gh");
        assert_eq!(s.path, "mcpServers.gh");
        assert_eq!(s.command.as_deref(), Some("npx"));
        assert_eq!(s.args, vec!["-y", "pkg"]);
        assert_eq!(s.env.get("A").map(String::as_str), Some("b"));
        assert!(s.settings.contains_key("extra"));
        assert!(s.issues.is_empty());
    }

    #[test]
    fn parses_vscode_layouts() {
        let a = parse(r#"{"servers":{"x":{"type":"http","url":"https://example.com/mcp"}}}"#).unwrap();
        assert_eq!(a.servers[0].url.as_deref(), Some("https://example.com/mcp"));
        assert_eq!(a.servers[0].transport.as_deref(), Some("http"));
        assert_eq!(a.servers[0].url_path.as_deref(), Some("servers.x.url"));

        let b = parse(r#"{"mcp":{"servers":{"y":{"command":"node"}}}}"#).unwrap();
        assert_eq!(b.servers[0].path, "mcp.servers.y");
    }

    #[test]
    fn parses_zed_nested_command() {
        let cfg = parse(
            r#"{"context_servers":{"z":{"command":{"path":"/bin/tool","args":["--a"],"env":{"K":"v"}}}}}"#,
        )
        .unwrap();
        let s = &cfg.servers[0];
        assert_eq!(s.command.as_deref(), Some("/bin/tool"));
        assert_eq!(s.args, vec!["--a"]);
        assert_eq!(s.args_path, "context_servers.z.command.args");
        assert_eq!(s.env_path, "context_servers.z.command.env");
        assert!(s.issues.is_empty());
    }

    #[test]
    fn rejects_invalid_documents() {
        assert!(matches!(parse(""), Err(ConfigError::Empty)));
        assert!(matches!(parse("   \n"), Err(ConfigError::Empty)));
        assert!(matches!(parse("{ nope"), Err(ConfigError::Json(_))));
        assert!(matches!(parse("[]"), Err(ConfigError::NotAnObject)));
        assert!(matches!(parse(r#"{"other":1}"#), Err(ConfigError::NoServers)));
        assert!(matches!(
            parse(r#"{"mcpServers":[]}"#),
            Err(ConfigError::BadContainer { .. })
        ));
    }

    #[test]
    fn accepts_utf8_bom() {
        let cfg = parse("\u{feff}{\"mcpServers\":{}}").unwrap();
        assert!(cfg.servers.is_empty());
    }

    #[test]
    fn reports_malformed_fields_without_failing() {
        let cfg = parse(
            r#"{"mcpServers":{"a":{"command":42,"args":"-y x","env":{"N":1,"O":{}}},"b":"text","c":{}}}"#,
        )
        .unwrap();
        assert_eq!(cfg.servers.len(), 3);
        let a = &cfg.servers[0];
        assert!(a.issues.iter().any(|i| i.field == "mcpServers.a.command"));
        assert!(a.issues.iter().any(|i| i.field == "mcpServers.a.args"));
        assert!(a.issues.iter().any(|i| i.field == "mcpServers.a.env.N"));
        assert!(a.issues.iter().any(|i| i.field == "mcpServers.a.env.O"));
        let b = &cfg.servers[1];
        assert!(b.issues.iter().any(|i| i.message.contains("JSON object")));
        let c = &cfg.servers[2];
        assert!(c.issues.iter().any(|i| i.message.contains("neither")));
    }

    #[test]
    fn missing_file_is_an_io_error() {
        let err = load(Path::new("definitely/not/here.json")).unwrap_err();
        assert!(matches!(err, ConfigError::Io { .. }));
        assert!(err.to_string().contains("cannot read"));
    }
}
