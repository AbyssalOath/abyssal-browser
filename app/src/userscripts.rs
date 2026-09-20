//! Local userscripts — a Tampermonkey/Greasemonkey-style system: real
//! JS files the user drops into a local folder, each declaring which
//! pages it applies to via `// @match <pattern>` lines inside a
//! `// ==UserScript== ... // ==/UserScript==` header (the same real,
//! recognizable format those tools use), automatically injected as
//! real scripts into every page they match — see `ipc::RenderRequest::
//! user_scripts`'s own doc comment for exactly how (and when: after
//! the page's own scripts, the "document-idle" timing real userscript
//! managers default to).
//!
//! Deliberately NOT a full extension system: no manifest.json, no
//! declared permissions, no background pages/service workers, no
//! browser-action toolbar buttons, no extension store/install-from-URL
//! — just real local script files the user manages directly on disk,
//! matching this project's "personal browser," not "mass-market
//! platform," scope. A userscript runs with the SAME trust as any
//! other script on the page (full DOM/JS access via the existing Boa
//! engine) — the user opted into it by putting the file there
//! themselves, unlike a page's own (untrusted) script.
//!
//! Re-read from disk on every navigation, not cached — these are
//! small, local text files a user is expected to edit directly; a
//! stale in-memory copy surviving an edit until the next restart would
//! be a real, avoidable annoyance for something this cheap to just
//! re-read.

use std::path::Path;

/// One userscript file: its raw source (run as-is — the header comment
/// is just an ordinary JS comment, harmless to leave in) plus the real
/// match patterns parsed out of its header.
pub struct UserScript {
    pub source: String,
    pub match_patterns: Vec<String>,
}

/// Loads every `.js` file directly inside `dir` (no subdirectories) as
/// a `UserScript` — a missing directory (no userscripts installed at
/// all, the common case) or one that can't be listed for any other
/// reason yields an empty list rather than an error; a single
/// unreadable file inside it is skipped (logged, not fatal to every
/// other userscript).
pub fn load_all(dir: &Path) -> Vec<UserScript> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut scripts = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("js") {
            continue;
        }
        match std::fs::read_to_string(&path) {
            Ok(source) => {
                let match_patterns = parse_match_patterns(&source);
                scripts.push(UserScript {
                    source,
                    match_patterns,
                });
            }
            Err(e) => {
                eprintln!("Skipping unreadable userscript {}: {e}", path.display());
            }
        }
    }
    scripts
}

/// Extracts every `// @match <pattern>` line found strictly between a
/// `// ==UserScript==` line and the next `// ==/UserScript==` line —
/// the same real header format Tampermonkey/Greasemonkey use. A file
/// with no such header (or no `@match` lines inside it) matches
/// NOTHING — there's no implicit "runs everywhere" default, the same
/// safe-by-default posture real userscript managers take.
fn parse_match_patterns(source: &str) -> Vec<String> {
    let mut patterns = Vec::new();
    let mut in_header = false;
    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed == "// ==UserScript==" {
            in_header = true;
            continue;
        }
        if trimmed == "// ==/UserScript==" {
            break;
        }
        if in_header {
            if let Some(pattern) = trimmed.strip_prefix("// @match ") {
                patterns.push(pattern.trim().to_string());
            }
        }
    }
    patterns
}

/// Every loaded userscript's raw source whose own match patterns match
/// `url` — what `Browser::navigate_without_history` sends over as
/// `ipc::RenderRequest::user_scripts`.
pub fn scripts_for_url<'a>(scripts: &'a [UserScript], url: &str) -> Vec<&'a str> {
    scripts
        .iter()
        .filter(|s| s.match_patterns.iter().any(|p| pattern_matches(p, url)))
        .map(|s| s.source.as_str())
        .collect()
}

/// Real (simplified) browser-extension match-pattern semantics:
/// `<scheme>://<host><path>`, where scheme may be `*` (any scheme),
/// host may be `*` (any host) or `*.example.com` (that host and every
/// subdomain), and path may contain `*` wildcards (matched against the
/// URL's own path plus query string). Simplified relative to the full
/// WebExtensions spec in one way: a bare `*` scheme here matches ANY
/// scheme (the real spec restricts it to http/https specifically) — a
/// minor, documented looseness, not a security boundary (a userscript
/// is a locally-installed, fully-trusted file; this only decides which
/// pages one runs on, not what it's allowed to do once it does).
pub fn pattern_matches(pattern: &str, url: &str) -> bool {
    let Some((scheme_pattern, rest)) = pattern.split_once("://") else {
        return false;
    };
    let (host_pattern, path_pattern) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/*"),
    };
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    if scheme_pattern != "*" && scheme_pattern != parsed.scheme() {
        return false;
    }
    let host = parsed.host_str().unwrap_or("");
    let host_matches = if host_pattern == "*" {
        true
    } else if let Some(suffix) = host_pattern.strip_prefix("*.") {
        host == suffix || host.ends_with(&format!(".{suffix}"))
    } else {
        host == host_pattern
    };
    if !host_matches {
        return false;
    }
    let mut path_and_query = parsed.path().to_string();
    if let Some(query) = parsed.query() {
        path_and_query.push('?');
        path_and_query.push_str(query);
    }
    glob_match(path_pattern, &path_and_query)
}

/// A minimal glob matcher supporting only `*` (matches any sequence,
/// including empty) — all real match patterns ever need; there's no
/// `?`/character-class wildcard in the spec this mirrors.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    glob_match_inner(&p, &t)
}

fn glob_match_inner(p: &[char], t: &[char]) -> bool {
    match p.first() {
        None => t.is_empty(),
        Some('*') => {
            glob_match_inner(&p[1..], t) || (!t.is_empty() && glob_match_inner(p, &t[1..]))
        }
        Some(c) => t.first() == Some(c) && glob_match_inner(&p[1..], &t[1..]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_matches_an_exact_host_and_wildcard_path() {
        assert!(pattern_matches(
            "https://example.com/*",
            "https://example.com/page"
        ));
    }

    #[test]
    fn pattern_rejects_a_different_host() {
        assert!(!pattern_matches(
            "https://example.com/*",
            "https://example.org/page"
        ));
    }

    #[test]
    fn wildcard_host_matches_any_subdomain() {
        assert!(pattern_matches(
            "https://*.example.com/*",
            "https://www.example.com/page"
        ));
        assert!(pattern_matches(
            "https://*.example.com/*",
            "https://example.com/page"
        ));
        assert!(!pattern_matches(
            "https://*.example.com/*",
            "https://example.org/page"
        ));
    }

    #[test]
    fn wildcard_scheme_matches_http_and_https() {
        assert!(pattern_matches("*://example.com/*", "http://example.com/x"));
        assert!(pattern_matches(
            "*://example.com/*",
            "https://example.com/x"
        ));
    }

    #[test]
    fn wildcard_host_matches_everything() {
        assert!(pattern_matches(
            "*://*/*",
            "https://anything.example/whatever"
        ));
    }

    #[test]
    fn path_wildcard_restricts_to_a_real_prefix() {
        assert!(pattern_matches(
            "https://example.com/blog/*",
            "https://example.com/blog/post-1"
        ));
        assert!(!pattern_matches(
            "https://example.com/blog/*",
            "https://example.com/other"
        ));
    }

    #[test]
    fn a_malformed_pattern_never_matches_rather_than_panicking() {
        assert!(!pattern_matches(
            "not-a-real-pattern",
            "https://example.com/"
        ));
    }

    #[test]
    fn parse_match_patterns_only_reads_lines_inside_the_real_header() {
        let source = r#"
// Just a comment, not inside any header: @match https://evil.example/*
// ==UserScript==
// @name My Script
// @match https://example.com/*
// @match https://example.org/*
// ==/UserScript==
console.log("hi");
// @match https://after-the-header.example/* (should not count)
"#;
        let patterns = parse_match_patterns(source);
        assert_eq!(
            patterns,
            vec!["https://example.com/*", "https://example.org/*"]
        );
    }

    #[test]
    fn a_file_with_no_header_matches_nothing() {
        let patterns = parse_match_patterns("console.log('no header at all');");
        assert!(patterns.is_empty());
    }

    #[test]
    fn scripts_for_url_returns_only_matching_sources() {
        let scripts = vec![
            UserScript {
                source: "A".to_string(),
                match_patterns: vec!["https://example.com/*".to_string()],
            },
            UserScript {
                source: "B".to_string(),
                match_patterns: vec!["https://example.org/*".to_string()],
            },
        ];
        let matched = scripts_for_url(&scripts, "https://example.com/page");
        assert_eq!(matched, vec!["A"]);
    }

    #[test]
    fn load_all_returns_empty_for_a_missing_directory() {
        let scripts = load_all(std::path::Path::new("/nonexistent/does/not/exist"));
        assert!(scripts.is_empty());
    }

    #[test]
    fn load_all_reads_real_js_files_and_ignores_others() {
        let dir = std::env::temp_dir().join(format!(
            "abyssal-userscripts-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("real.js"),
            "// ==UserScript==\n// @match https://example.com/*\n// ==/UserScript==\n1;",
        )
        .unwrap();
        std::fs::write(dir.join("not-a-script.txt"), "ignored").unwrap();

        let scripts = load_all(&dir);
        assert_eq!(scripts.len(), 1);
        assert_eq!(scripts[0].match_patterns, vec!["https://example.com/*"]);

        std::fs::remove_dir_all(&dir).ok();
    }
}
