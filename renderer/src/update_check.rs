//! Auto-update: check-and-notify only — no download, no binary
//! replacement. A self-replacing binary is itself a real attack
//! surface (whatever verifies and applies the update becomes something
//! a compromised or spoofed release feed could target), and would need
//! a real signing/release-verification story this project doesn't have
//! yet; "tell me a newer version exists" covers the actual need for a
//! personal, self-built browser far more cheaply and far more safely.
//!
//! Routed through this sandboxed `renderer` process rather than `app`
//! doing the HTTP request itself (see `ipc::ClientMessageKind::
//! CheckForUpdate`) — `app` deliberately never links an HTTP client
//! (see its own `Cargo.toml`), and this is still a real fetch of a
//! remote, adversary-influenceable-in-principle response (a
//! compromised or mirrored GitHub, a MITM without working TLS
//! validation), so it goes through the exact same sandboxed
//! `network::Fetcher` path (DNS-over-HTTPS included) as every other
//! fetch this process makes, rather than carving out a special
//! unsandboxed exception for it.
//!
//! Uses GitHub's `/repos/{repo}/releases` LIST endpoint, not `/releases/
//! latest` — `/latest` deliberately skips prereleases and drafts, and
//! `.github/workflows/release.yml` marks every release `prerelease:
//! true` until a real, audited 1.0 (see that file's own comment on
//! why). `/latest` would therefore 404 for this project's entire
//! pre-1.0 life; the list endpoint's first (most recent) entry doesn't
//! have that blind spot.

use network::{Fetcher, FilteringFetcher};

/// This project's GitHub repo slug ("owner/name"), once it actually has
/// one. `None` until then: rather than guess or hardcode a repository
/// this project isn't hosted at yet (see the README's own note on not
/// pushing this to GitHub until it's further along), update checking
/// honestly reports `CheckFailed` instead of silently claiming
/// "up to date" — fill this in once the real repo exists.
const RELEASES_REPO: Option<&str> = None;

/// Checks whether a newer release than `current_version` exists,
/// through `fetcher` (the same sandboxed, blocklist-and-DoH-routed
/// fetcher every other request in this process uses). `current_version`
/// is expected in `major.minor.patch` form (`env!("CARGO_PKG_VERSION")`
/// on the `app` side) — see `compare_versions` for exactly what does
/// and doesn't parse.
pub fn check_for_update<F: Fetcher>(
    fetcher: &mut FilteringFetcher<F>,
    current_version: &str,
) -> ipc::UpdateCheckOutcome {
    let Some(repo) = RELEASES_REPO else {
        return ipc::UpdateCheckOutcome::CheckFailed(
            "no release repository configured yet".to_string(),
        );
    };

    let url = format!("https://api.github.com/repos/{repo}/releases");
    let response = match fetcher.fetch_in_context(&url, None) {
        Ok(response) => response,
        Err(e) => return ipc::UpdateCheckOutcome::CheckFailed(format!("{e:?}")),
    };
    if response.status != 200 {
        return ipc::UpdateCheckOutcome::CheckFailed(format!(
            "unexpected status {} from GitHub's releases API",
            response.status
        ));
    }

    let Some((tag, html_url)) = parse_latest_release(&response.body) else {
        return ipc::UpdateCheckOutcome::CheckFailed(
            "couldn't parse GitHub's releases response".to_string(),
        );
    };

    match compare_versions(&tag, current_version) {
        Some(std::cmp::Ordering::Greater) => ipc::UpdateCheckOutcome::NewVersionAvailable {
            version: tag,
            html_url,
        },
        Some(_) => ipc::UpdateCheckOutcome::UpToDate,
        None => ipc::UpdateCheckOutcome::CheckFailed(format!(
            "couldn't compare release tag {tag:?} against current version {current_version:?}"
        )),
    }
}

/// Pulls the most recent entry's tag and page URL out of a real
/// `GET /repos/{repo}/releases` response body — pure parsing, no I/O,
/// so it's unit-testable against a fixed, real-shaped JSON fixture
/// rather than a live GitHub response.
fn parse_latest_release(body: &[u8]) -> Option<(String, String)> {
    let json: serde_json::Value = serde_json::from_slice(body).ok()?;
    let latest = json.as_array()?.first()?;
    let tag = latest.get("tag_name")?.as_str()?.to_string();
    let html_url = latest.get("html_url")?.as_str()?.to_string();
    Some((tag, html_url))
}

/// Compares two `major.minor.patch` version strings (an optional
/// leading `v` on either is stripped first, matching this project's own
/// `v*.*.*` release-tag format — see `.github/workflows/release.yml`).
/// `None` if either side isn't in exactly that shape — deliberately not
/// a fuzzy/best-effort comparison: a release tagged something this
/// doesn't understand should fail the check honestly (see
/// `check_for_update`'s doc comment) rather than guess and risk either
/// a false "up to date" or a false "update available."
fn compare_versions(a: &str, b: &str) -> Option<std::cmp::Ordering> {
    Some(parse_version(a)?.cmp(&parse_version(b)?))
}

fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let v = v.strip_prefix('v').unwrap_or(v);
    let mut parts = v.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_tag_and_url_out_of_a_real_shaped_releases_response() {
        let body = br#"[
            {"tag_name": "v0.3.0", "html_url": "https://github.com/example/abyssal/releases/tag/v0.3.0"},
            {"tag_name": "v0.2.0", "html_url": "https://github.com/example/abyssal/releases/tag/v0.2.0"}
        ]"#;
        let (tag, url) = parse_latest_release(body).expect("should parse the first entry");
        assert_eq!(tag, "v0.3.0");
        assert_eq!(
            url,
            "https://github.com/example/abyssal/releases/tag/v0.3.0"
        );
    }

    #[test]
    fn returns_none_for_an_empty_releases_list() {
        assert_eq!(parse_latest_release(b"[]"), None);
    }

    #[test]
    fn returns_none_for_malformed_json() {
        assert_eq!(parse_latest_release(b"not json"), None);
    }

    #[test]
    fn compares_versions_with_or_without_a_leading_v() {
        assert_eq!(
            compare_versions("v0.3.0", "0.2.0"),
            Some(std::cmp::Ordering::Greater)
        );
        assert_eq!(
            compare_versions("0.2.0", "v0.2.0"),
            Some(std::cmp::Ordering::Equal)
        );
        assert_eq!(
            compare_versions("v0.1.0", "0.2.0"),
            Some(std::cmp::Ordering::Less)
        );
    }

    #[test]
    fn numeric_comparison_is_not_lexicographic() {
        // A naive string comparison would put "0.9.0" ahead of "0.10.0"
        // — proves this actually parses each component as a number.
        assert_eq!(
            compare_versions("0.10.0", "0.9.0"),
            Some(std::cmp::Ordering::Greater)
        );
    }

    #[test]
    fn a_tag_that_isnt_plain_major_minor_patch_fails_the_comparison_honestly() {
        assert_eq!(compare_versions("v0.3.0-rc1", "0.2.0"), None);
        assert_eq!(compare_versions("not-a-version", "0.2.0"), None);
    }

    #[test]
    fn check_for_update_fails_honestly_with_no_repo_configured() {
        // `RELEASES_REPO` is `None` until this project actually has a
        // GitHub home (see its own doc comment) — confirms that state
        // reports `CheckFailed`, never a false "up to date."
        let fake = network::FakeFetcher::new();
        let mut fetcher = FilteringFetcher::new(fake, privacy::Blocklist::new());
        let outcome = check_for_update(&mut fetcher, "0.1.0");
        assert!(matches!(outcome, ipc::UpdateCheckOutcome::CheckFailed(_)));
    }
}
