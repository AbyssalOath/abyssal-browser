//! Downloads: fetching the bytes behind an `<a download>` link (see
//! `ipc::ClientMessageKind::Download`) through the SAME sandboxed,
//! blocklist-and-DoH-routed fetcher every other request in this
//! process uses — never a separate, unsandboxed download path in the
//! privileged `app` process.
//!
//! No `Content-Disposition` awareness: `network::Response` doesn't
//! expose arbitrary response headers today (only `Set-Cookie`/
//! `Cache-Control` specifically — see that crate's own docs), so the
//! suggested filename here is always derived from the URL's own path.
//! `app` combines it with the clicked link's own `download="..."`
//! attribute value (which takes priority when non-empty) — see
//! `Browser::download`.

use network::{Fetcher, FilteringFetcher};

/// Practical size cap for one download — see `ipc::DownloadSuccess`'s
/// own doc comment for exactly why: base64-encoding a file this size
/// keeps the resulting IPC message just under `ipc::MAX_MESSAGE_LEN`
/// (64 MiB), with headroom for the rest of the JSON envelope. A file
/// over this fails cleanly (`DownloadOutcome::Failed`) here rather than
/// being read fully into memory only to fail once `app` tries to read
/// the oversized reply off the wire.
const MAX_DOWNLOAD_BYTES: usize = 45 * 1024 * 1024;

/// Fetches `url` and hands back either its bytes (plus a suggested
/// filename) or a human-readable failure reason.
pub fn download<F: Fetcher>(
    fetcher: &mut FilteringFetcher<F>,
    url: &str,
    top_level_host: Option<&str>,
) -> ipc::DownloadOutcome {
    let response = match fetcher.fetch_in_context(url, top_level_host) {
        Ok(response) => response,
        Err(e) => return ipc::DownloadOutcome::Failed(format!("{e:?}")),
    };
    if response.status != 200 {
        return ipc::DownloadOutcome::Failed(format!(
            "server responded with status {}",
            response.status
        ));
    }
    if response.body.len() > MAX_DOWNLOAD_BYTES {
        return ipc::DownloadOutcome::Failed(format!(
            "file is too large to download ({} bytes; this browser's current limit is {} bytes)",
            response.body.len(),
            MAX_DOWNLOAD_BYTES
        ));
    }

    let suggested_filename = filename_from_url(url);
    ipc::DownloadOutcome::Downloaded(ipc::DownloadSuccess::new(
        &response.body,
        suggested_filename,
    ))
}

/// The last path segment of `url`, percent-decoded — falls back to
/// `"download"` if nothing usable is there (no path, a trailing
/// slash, ...). Pure string handling, no dependency on the `url`
/// crate: this browser already has one hand-rolled URL utility set
/// (`network::extract_host`/`extract_path`) rather than pulling in
/// real URL parsing for "just enough to key a hashmap"; this is the
/// same tier of narrow-scope parsing, for the same reason.
fn filename_from_url(url: &str) -> String {
    let without_query = url.split(['?', '#']).next().unwrap_or(url);
    let last_segment = without_query.rsplit('/').next().unwrap_or("");
    let decoded = percent_decode(last_segment);
    if decoded.is_empty() {
        "download".to_string()
    } else {
        decoded
    }
}

/// A minimal percent-decoder (`%XX` becomes the byte it encodes;
/// invalid/incomplete `%` sequences pass through literally) — just
/// enough for a URL path segment to turn into a sane filename, not a
/// full RFC 3986 implementation.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
            if let Ok(byte) = u8::from_str_radix(hex, 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filename_from_url_uses_the_last_path_segment() {
        assert_eq!(
            filename_from_url("https://example.com/files/report.pdf"),
            "report.pdf"
        );
    }

    #[test]
    fn filename_from_url_ignores_a_query_string() {
        assert_eq!(
            filename_from_url("https://example.com/report.pdf?v=2&ref=home"),
            "report.pdf"
        );
    }

    #[test]
    fn filename_from_url_decodes_percent_encoded_characters() {
        assert_eq!(
            filename_from_url("https://example.com/my%20report.pdf"),
            "my report.pdf"
        );
    }

    #[test]
    fn filename_from_url_falls_back_for_a_trailing_slash_with_nothing_after_it() {
        assert_eq!(filename_from_url("https://example.com/"), "download");
    }

    #[test]
    fn filename_from_url_uses_the_host_when_the_url_has_no_path_at_all() {
        // A real, if imperfect, consequence of this crate's deliberately
        // narrow "last '/'-separated segment" scope (see this module's
        // own doc comment on why there's no real URL parser here) — a
        // bare origin with no path segment still has ONE `/`-delimited
        // piece after the scheme, and it's the host.
        assert_eq!(filename_from_url("https://example.com"), "example.com");
    }

    #[test]
    fn percent_decode_passes_through_an_invalid_escape_literally() {
        assert_eq!(percent_decode("100%off"), "100%off");
        assert_eq!(percent_decode("trailing%"), "trailing%");
        assert_eq!(percent_decode("trailing%2"), "trailing%2");
    }

    #[test]
    fn download_reports_a_clean_failure_for_a_response_over_the_size_cap() {
        let mut fake = network::FakeFetcher::new();
        fake.register_bytes(
            "http://example.com/big.bin",
            vec![0u8; MAX_DOWNLOAD_BYTES + 1],
        );
        let mut fetcher = FilteringFetcher::new(fake, privacy::Blocklist::new());

        let outcome = download(&mut fetcher, "http://example.com/big.bin", None);
        assert!(matches!(outcome, ipc::DownloadOutcome::Failed(_)));
    }

    #[test]
    fn download_succeeds_for_a_normal_sized_response_with_a_derived_filename() {
        let mut fake = network::FakeFetcher::new();
        fake.register_bytes(
            "http://example.com/files/report.pdf",
            b"pdf bytes here".to_vec(),
        );
        let mut fetcher = FilteringFetcher::new(fake, privacy::Blocklist::new());

        let outcome = download(&mut fetcher, "http://example.com/files/report.pdf", None);
        match outcome {
            ipc::DownloadOutcome::Downloaded(success) => {
                assert_eq!(success.bytes().unwrap(), b"pdf bytes here");
                assert_eq!(success.suggested_filename, "report.pdf");
            }
            ipc::DownloadOutcome::Failed(e) => panic!("expected success, got: {e}"),
        }
    }

    #[test]
    fn download_reports_a_clean_failure_for_a_blocked_third_party_url() {
        let mut fake = network::FakeFetcher::new();
        fake.register_bytes("http://g.doubleclick.net/file.bin", b"x".to_vec());
        let mut fetcher = FilteringFetcher::new(fake, privacy::Blocklist::with_seed_list());

        let outcome = download(
            &mut fetcher,
            "http://g.doubleclick.net/file.bin",
            Some("news.example.com"),
        );
        assert!(matches!(outcome, ipc::DownloadOutcome::Failed(_)));
    }
}
