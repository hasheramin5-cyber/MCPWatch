//! End-to-end tests that run the compiled `mcpwatch` binary.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "mcpwatch-it-{}-{}-{}",
            std::process::id(),
            nanos,
            n
        ));
        fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn write(&self, name: &str, content: &str) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, content).unwrap();
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn mcpwatch(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mcpwatch"))
        .args(args)
        .env("NO_COLOR", "1")
        .env_remove("MCPWATCH_HOME")
        .output()
        .expect("failed to run mcpwatch")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn code(o: &Output) -> i32 {
    o.status.code().expect("process terminated by a signal")
}

fn s(path: &Path) -> &str {
    path.to_str().unwrap()
}

const CLEAN: &str = r#"{"mcpServers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem@2025.1.14","./project"]}}}"#;

const SECRET: &str = "integration-secret-value-42";

fn risky() -> String {
    format!(
        r#"{{"mcpServers":{{
            "fs":{{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem@2025.1.14","/"]}},
            "gh":{{"command":"node","args":["gh.js"],"env":{{"GITHUB_TOKEN":"{SECRET}"}}}}
        }}}}"#
    )
}

#[test]
fn version_and_help() {
    let v = mcpwatch(&["--version"]);
    assert_eq!(code(&v), 0);
    assert!(stdout(&v).contains("mcpwatch"));
    assert!(stdout(&v).contains(env!("CARGO_PKG_VERSION")));

    let h = mcpwatch(&["--help"]);
    assert_eq!(code(&h), 0);
    let text = stdout(&h);
    assert!(text.contains("Know what your AI agents can access"));
    for word in ["scan", "snapshot", "diff", "EXIT CODES"] {
        assert!(text.contains(word), "help should mention {word}");
    }
}

#[test]
fn usage_errors_exit_with_two() {
    assert_eq!(code(&mcpwatch(&["frobnicate"])), 2);
    assert_eq!(code(&mcpwatch(&["scan"])), 2);
    assert_eq!(code(&mcpwatch(&["scan", "x.json", "--fail-on", "bogus"])), 2);
}

#[test]
fn clean_configuration_succeeds() {
    let tmp = TempDir::new();
    let cfg = tmp.write("mcp.json", CLEAN);
    let out = mcpwatch(&["scan", s(&cfg)]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    assert!(stdout(&out).contains("No findings"));
}

#[test]
fn risky_configuration_fails_and_never_prints_secrets() {
    let tmp = TempDir::new();
    let cfg = tmp.write("mcp.json", &risky());
    let out = mcpwatch(&["scan", s(&cfg)]);
    let text = stdout(&out);
    assert_eq!(code(&out), 1);
    assert!(text.contains("[HIGH]"));
    assert!(text.contains("filesystem root"));
    assert!(text.contains("mcpServers.gh.env.GITHUB_TOKEN"));
    assert!(text.contains("Summary:"));
    assert!(!text.contains(SECRET));
    assert!(!stderr(&out).contains(SECRET));
}

#[test]
fn fail_on_threshold_controls_exit_code() {
    let tmp = TempDir::new();
    let medium_only = tmp.write("m.json", r#"{"mcpServers":{"r":{"url":"http://example.com/mcp"}}}"#);
    assert_eq!(code(&mcpwatch(&["scan", s(&medium_only)])), 0);
    assert_eq!(code(&mcpwatch(&["scan", s(&medium_only), "--fail-on", "medium"])), 1);
    assert_eq!(code(&mcpwatch(&["scan", s(&medium_only), "--fail-on", "info"])), 1);

    let risky_cfg = tmp.write("r.json", &risky());
    assert_eq!(code(&mcpwatch(&["scan", s(&risky_cfg), "--fail-on", "never"])), 0);
}

#[test]
fn invalid_inputs_exit_with_three() {
    let tmp = TempDir::new();

    let missing = tmp.path().join("missing.json");
    let out = mcpwatch(&["scan", s(&missing)]);
    assert_eq!(code(&out), 3);
    assert!(stderr(&out).contains("error: cannot read"));

    let bad = tmp.write("bad.json", r#"{ "mcpServers": "#);
    let out = mcpwatch(&["scan", s(&bad)]);
    assert_eq!(code(&out), 3);
    assert!(stderr(&out).contains("invalid JSON"));

    let no_servers = tmp.write("none.json", r#"{"foo":1}"#);
    let out = mcpwatch(&["scan", s(&no_servers)]);
    assert_eq!(code(&out), 3);
    assert!(stderr(&out).contains("no MCP server definitions"));

    let empty = tmp.write("empty.json", "");
    assert_eq!(code(&mcpwatch(&["scan", s(&empty)])), 3);

    let out = mcpwatch(&["scan", s(tmp.path())]);
    assert_eq!(code(&out), 3);
    assert!(stderr(&out).contains("not a regular file"));
}

#[test]
fn configuration_without_servers_is_reported_as_nothing_to_analyze() {
    let tmp = TempDir::new();
    let cfg = tmp.write("mcp.json", r#"{"mcpServers":{}}"#);
    let out = mcpwatch(&["scan", s(&cfg)]);
    assert_eq!(code(&out), 0);
    assert!(stdout(&out).contains("No MCP servers"));
}

#[test]
fn malformed_server_fields_are_reported() {
    let tmp = TempDir::new();
    let cfg = tmp.write("mcp.json", r#"{"mcpServers":{"a":{"command":42}}}"#);
    let out = mcpwatch(&["scan", s(&cfg), "--fail-on", "low"]);
    assert_eq!(code(&out), 1);
    assert!(stdout(&out).contains("MW-CFG-001"));
}

#[test]
fn example_configuration_produces_expected_summary() {
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/mcp.example.json");
    let out = mcpwatch(&["scan", s(&example)]);
    let text = stdout(&out);
    assert_eq!(code(&out), 1);
    assert!(
        text.contains("Summary: 7 findings (3 high, 2 medium, 2 low, 0 info)"),
        "unexpected output:\n{text}"
    );
    assert!(!text.contains("not-a-real-token-1234567890"));
}

#[test]
fn snapshot_creates_a_protected_file_without_secrets() {
    let tmp = TempDir::new();
    let cfg = tmp.write("mcp.json", &risky());
    let snaps = tmp.path().join("snaps");

    let out = mcpwatch(&["snapshot", s(&cfg), "--snapshot-dir", s(&snaps)]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    assert!(stdout(&out).contains("Snapshot saved"));

    let files: Vec<PathBuf> = fs::read_dir(&snaps)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(files.len(), 1);
    let content = fs::read_to_string(&files[0]).unwrap();
    assert!(!content.contains(SECRET));
    assert!(content.contains("GITHUB_TOKEN"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&files[0]).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}

#[test]
fn snapshot_dir_can_come_from_the_environment() {
    let tmp = TempDir::new();
    let cfg = tmp.write("mcp.json", CLEAN);
    let snaps = tmp.path().join("env-snaps");
    let out = Command::new(env!("CARGO_BIN_EXE_mcpwatch"))
        .args(["snapshot", s(&cfg)])
        .env("NO_COLOR", "1")
        .env("MCPWATCH_HOME", &snaps)
        .output()
        .unwrap();
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    assert_eq!(fs::read_dir(&snaps).unwrap().count(), 1);
}

#[test]
fn diff_requires_a_snapshot() {
    let tmp = TempDir::new();
    let cfg = tmp.write("mcp.json", CLEAN);
    let snaps = tmp.path().join("snaps");
    let out = mcpwatch(&["diff", s(&cfg), "--snapshot-dir", s(&snaps)]);
    assert_eq!(code(&out), 3);
    assert!(stderr(&out).contains("no snapshot found"));
}

#[test]
fn diff_reports_no_changes_for_an_unchanged_configuration() {
    let tmp = TempDir::new();
    let cfg = tmp.write("mcp.json", &risky());
    let snaps = tmp.path().join("snaps");
    assert_eq!(code(&mcpwatch(&["snapshot", s(&cfg), "--snapshot-dir", s(&snaps)])), 0);
    let out = mcpwatch(&["diff", s(&cfg), "--snapshot-dir", s(&snaps)]);
    assert_eq!(code(&out), 0, "stdout: {}", stdout(&out));
    assert!(stdout(&out).contains("No changes"));
}

#[test]
fn diff_detects_added_removed_and_modified_servers() {
    let tmp = TempDir::new();
    let snaps = tmp.path().join("snaps");
    let cfg = tmp.write(
        "mcp.json",
        r#"{"mcpServers":{
            "keep":{"command":"node","args":["keep.js"],"env":{"MODE":"a"}},
            "gone":{"command":"node","args":["gone.js"]},
            "edit":{"command":"node","args":["edit.js"]}}}"#,
    );
    assert_eq!(code(&mcpwatch(&["snapshot", s(&cfg), "--snapshot-dir", s(&snaps)])), 0);

    fs::write(
        &cfg,
        r#"{"mcpServers":{
            "keep":{"command":"node","args":["keep.js"],"env":{"MODE":"b-private-value"}},
            "edit":{"command":"deno","args":["edit.js","--allow-all"]},
            "fresh":{"command":"node","args":["fresh.js"]}}}"#,
    )
    .unwrap();

    let out = mcpwatch(&["diff", s(&cfg), "--snapshot-dir", s(&snaps)]);
    let text = stdout(&out);
    assert_eq!(code(&out), 1, "stderr: {}", stderr(&out));
    assert!(text.contains("[+] added"));
    assert!(text.contains("mcpServers.fresh"));
    assert!(text.contains("[-] removed"));
    assert!(text.contains("mcpServers.gone"));
    assert!(text.contains("[~] modified"));
    assert!(text.contains("mcpServers.edit"));
    assert!(text.contains("command:"));
    assert!(text.contains("args:"));
    assert!(text.contains("env value changed: MODE (value not shown)"));
    assert!(!text.contains("b-private-value"));
    assert!(text.contains("Summary: 4 changes (1 added, 1 removed, 2 modified)"));
}

#[test]
fn diff_uses_the_most_recent_snapshot() {
    let tmp = TempDir::new();
    let snaps = tmp.path().join("snaps");
    let cfg = tmp.write("mcp.json", r#"{"mcpServers":{"a":{"command":"node"}}}"#);
    assert_eq!(code(&mcpwatch(&["snapshot", s(&cfg), "--snapshot-dir", s(&snaps)])), 0);

    fs::write(&cfg, r#"{"mcpServers":{"a":{"command":"node"},"b":{"command":"node"}}}"#).unwrap();
    assert_eq!(code(&mcpwatch(&["snapshot", s(&cfg), "--snapshot-dir", s(&snaps)])), 0);

    let out = mcpwatch(&["diff", s(&cfg), "--snapshot-dir", s(&snaps)]);
    assert_eq!(code(&out), 0, "stdout: {}", stdout(&out));
}
