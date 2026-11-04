//! Terminal rendering. Every function returns a `String` so output is easy to
//! test; `main` is responsible for printing it.
//!
//! Findings never contain secret values (the scanner does not copy them), and
//! this module only prints what the findings and changes already contain.

use crate::scanner::{Finding, Severity};
use crate::snapshot::{format_utc, Change, ChangeKind};
use std::io::IsTerminal;
use std::path::Path;

/// Decides whether ANSI colors should be used on stdout.
pub fn color_enabled(no_color_flag: bool) -> bool {
    if no_color_flag || std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty()) {
        return false;
    }
    if std::env::var("TERM").is_ok_and(|t| t == "dumb") {
        return false;
    }
    if !std::io::stdout().is_terminal() {
        return false;
    }
    if cfg!(windows) {
        // Older Windows consoles do not interpret ANSI sequences by default.
        return ["WT_SESSION", "ANSICON", "ConEmuANSI", "TERM"]
            .iter()
            .any(|v| std::env::var_os(v).is_some());
    }
    true
}

#[derive(Debug, Clone, Copy)]
pub struct Style {
    enabled: bool,
}

impl Style {
    pub fn new(enabled: bool) -> Self {
        Style { enabled }
    }

    fn paint(self, code: &str, text: &str) -> String {
        if self.enabled {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    fn bold(self, text: &str) -> String {
        self.paint("1", text)
    }

    fn dim(self, text: &str) -> String {
        self.paint("2", text)
    }

    fn green(self, text: &str) -> String {
        self.paint("32", text)
    }

    fn red(self, text: &str) -> String {
        self.paint("31", text)
    }

    fn yellow(self, text: &str) -> String {
        self.paint("33", text)
    }

    fn severity(self, severity: Severity, text: &str) -> String {
        let code = match severity {
            Severity::High => "1;31",
            Severity::Medium => "33",
            Severity::Low => "36",
            Severity::Info => "2",
        };
        self.paint(code, text)
    }
}

const WIDTH: usize = 80;
const LABEL_WIDTH: usize = 9;

fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if !current.is_empty() && current.chars().count() + 1 + word.chars().count() > width {
            lines.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

fn push_field(out: &mut String, style: Style, label: &str, text: &str) {
    let lines = wrap(text, WIDTH - LABEL_WIDTH - 3);
    if lines.is_empty() {
        return;
    }
    for (i, line) in lines.iter().enumerate() {
        let shown = if i == 0 {
            style.dim(&format!(
                "{:<width$}",
                format!("{label}:"),
                width = LABEL_WIDTH
            ))
        } else {
            " ".repeat(LABEL_WIDTH)
        };
        out.push_str(&format!("  {shown} {line}\n"));
    }
}

fn header(style: Style, title: &str) -> String {
    format!(
        "{} - {title}\n",
        style.bold(&format!("MCPWatch {}", env!("CARGO_PKG_VERSION")))
    )
}

fn plural(n: usize, singular: &str, plural: &str) -> String {
    format!("{n} {}", if n == 1 { singular } else { plural })
}

/// Counts findings as (high, medium, low, info).
pub fn severity_counts(findings: &[Finding]) -> (usize, usize, usize, usize) {
    let count = |s: Severity| findings.iter().filter(|f| f.severity == s).count();
    (
        count(Severity::High),
        count(Severity::Medium),
        count(Severity::Low),
        count(Severity::Info),
    )
}

pub fn render_scan(
    config_path: &str,
    server_count: usize,
    findings: &[Finding],
    style: Style,
) -> String {
    let mut out = header(style, "configuration scan");
    push_field(&mut out, style, "Config", config_path);
    push_field(&mut out, style, "Servers", &server_count.to_string());
    out.push('\n');

    if server_count == 0 {
        out.push_str(&format!(
            "{} No MCP servers are defined in this file, so there is nothing to analyze.\n",
            style.green("[OK]")
        ));
        return out;
    }

    if findings.is_empty() {
        out.push_str(&format!(
            "{} No findings in {}. None of MCPWatch's built-in checks matched; this is not a guarantee that the configuration is safe.\n",
            style.green("[OK]"),
            plural(server_count, "server", "servers")
        ));
        return out;
    }

    for finding in findings {
        out.push_str(&format!(
            "{} {}\n",
            style.severity(
                finding.severity,
                &format!("[{}]", finding.severity.label())
            ),
            style.bold(&finding.title)
        ));
        push_field(&mut out, style, "Server", &finding.server);
        push_field(&mut out, style, "Field", &finding.field);
        push_field(&mut out, style, "Basis", finding.confidence.label());
        push_field(&mut out, style, "Why", &finding.why);
        push_field(&mut out, style, "Fix", &finding.fix);
        push_field(&mut out, style, "Rule", finding.rule);
        out.push('\n');
    }

    let (high, medium, low, info) = severity_counts(findings);
    out.push_str(&style.bold(&format!(
        "Summary: {} ({high} high, {medium} medium, {low} low, {info} info)\n",
        plural(findings.len(), "finding", "findings")
    )));
    out.push_str(&style.dim(
        "These results are static, heuristic indicators, not confirmed vulnerabilities. MCPWatch never starts your servers, so it cannot assess runtime behavior or the code they run.\n",
    ));
    out
}

pub fn render_snapshot_saved(file: &Path, server_count: usize, style: Style) -> String {
    let mut out = header(style, "snapshot");
    out.push_str(&format!("{} Snapshot saved\n", style.green("[OK]")));
    push_field(&mut out, style, "File", &file.display().to_string());
    push_field(&mut out, style, "Servers", &server_count.to_string());
    push_field(
        &mut out,
        style,
        "Privacy",
        "Stored locally only; nothing is uploaded. Environment and header values are kept as salted fingerprints and credential-like values are redacted, but treat the file as sensitive.",
    );
    out
}

pub fn render_diff(
    config_path: &str,
    snapshot_file: &str,
    created_unix: u64,
    server_count: usize,
    changes: &[Change],
    style: Style,
) -> String {
    let mut out = header(style, "snapshot diff");
    push_field(&mut out, style, "Config", config_path);
    push_field(
        &mut out,
        style,
        "Snapshot",
        &format!("{snapshot_file} (taken {})", format_utc(created_unix)),
    );
    out.push('\n');

    if changes.is_empty() {
        out.push_str(&format!(
            "{} No changes since the snapshot ({} compared).\n",
            style.green("[OK]"),
            plural(server_count, "server", "servers")
        ));
        return out;
    }

    for change in changes {
        let (marker, label) = match change.kind {
            ChangeKind::Added => (style.green("[+]"), "added"),
            ChangeKind::Removed => (style.red("[-]"), "removed"),
            ChangeKind::Modified => (style.yellow("[~]"), "modified"),
        };
        out.push_str(&format!("{marker} {label:<8} {}\n", style.bold(&change.id)));
        for detail in &change.details {
            out.push_str(&format!("      {detail}\n"));
        }
    }

    let count = |k: ChangeKind| changes.iter().filter(|c| c.kind == k).count();
    out.push('\n');
    out.push_str(&style.bold(&format!(
        "Summary: {} ({} added, {} removed, {} modified)\n",
        plural(changes.len(), "change", "changes"),
        count(ChangeKind::Added),
        count(ChangeKind::Removed),
        count(ChangeKind::Modified)
    )));
    out.push_str(&style.dim(
        "Run `mcpwatch scan` on the configuration to review the current state. Values that may be credentials are never shown.\n",
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::Confidence;

    fn finding(severity: Severity) -> Finding {
        Finding {
            rule: "MW-TEST-001",
            severity,
            confidence: Confidence::Heuristic,
            server: "srv".to_string(),
            field: "mcpServers.srv.env.API_TOKEN".to_string(),
            title: "Hardcoded credential in environment variable".to_string(),
            why: "Because it matters.".to_string(),
            fix: "Do something else.".to_string(),
        }
    }

    #[test]
    fn renders_findings_and_summary_without_color() {
        let findings = vec![finding(Severity::High), finding(Severity::Low)];
        let text = render_scan("mcp.json", 1, &findings, Style::new(false));
        assert!(text.contains("[HIGH] Hardcoded credential"));
        assert!(text.contains("[LOW]"));
        assert!(text.contains("Field:"));
        assert!(text.contains("mcpServers.srv.env.API_TOKEN"));
        assert!(text.contains("Summary: 2 findings (1 high, 0 medium, 1 low, 0 info)"));
        assert!(!text.contains('\x1b'));
    }

    #[test]
    fn color_output_contains_escape_codes() {
        let text = render_scan("mcp.json", 1, &[finding(Severity::High)], Style::new(true));
        assert!(text.contains("\x1b["));
    }

    #[test]
    fn renders_clean_and_empty_configurations() {
        let clean = render_scan("mcp.json", 2, &[], Style::new(false));
        assert!(clean.contains("[OK] No findings in 2 servers"));
        let empty = render_scan("mcp.json", 0, &[], Style::new(false));
        assert!(empty.contains("No MCP servers are defined"));
    }

    #[test]
    fn renders_diff() {
        let changes = vec![
            Change {
                id: "mcpServers.a".into(),
                kind: ChangeKind::Added,
                details: vec!["command: `node` with 0 arguments".into()],
            },
            Change {
                id: "mcpServers.b".into(),
                kind: ChangeKind::Removed,
                details: vec![],
            },
            Change {
                id: "mcpServers.c".into(),
                kind: ChangeKind::Modified,
                details: vec!["env added: X".into()],
            },
        ];
        let text = render_diff("mcp.json", "snap.json", 0, 2, &changes, Style::new(false));
        assert!(text.contains("[+] added"));
        assert!(text.contains("[-] removed"));
        assert!(text.contains("[~] modified"));
        assert!(text.contains("1970-01-01 00:00:00 UTC"));
        assert!(text.contains("Summary: 3 changes (1 added, 1 removed, 1 modified)"));

        let none = render_diff("mcp.json", "snap.json", 0, 2, &[], Style::new(false));
        assert!(none.contains("No changes since the snapshot"));
    }

    #[test]
    fn wraps_long_text() {
        let lines = wrap("one two three four five six seven", 10);
        assert!(lines.iter().all(|l| l.chars().count() <= 10));
        assert_eq!(lines.join(" "), "one two three four five six seven");
    }
}
