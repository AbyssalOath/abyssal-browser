//! An on-disk HTTP response cache, partitioned by `privacy::StoragePartitionKey`
//! exactly like `PartitionedCookieJar` — an UNpartitioned cache would
//! itself be a cross-site tracking side-channel: a tracker embedded on
//! two different sites could measure "was this resource already
//! cached" (e.g. via a timing difference on load) to infer whether the
//! user separately visited the OTHER site that also embeds it.
//! Partitioning by (top-level site, resource host) closes that off the
//! same way cookie partitioning does — see `DiskCache::path_for`.
//!
//! Deliberately conservative about what gets cached at all: only
//! responses that explicitly opt in via `Cache-Control: max-age=N`
//! (see `parse_max_age`) are ever written — no guessed default TTL for
//! a response that never said it wanted to be cached, and `no-store`/
//! `no-cache` are honored.
//!
//! NOT a full RFC 7234 cache: no ETag/If-None-Match revalidation, no
//! `Vary` handling, and no size limit/eviction policy — an entry just
//! sits on disk until its own `max-age` naturally expires, at which
//! point it's treated as a miss (see `get`'s doc comment for why it
//! isn't proactively deleted). Good enough to avoid needlessly
//! re-fetching unchanged resources; not a general-purpose HTTP cache.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use privacy::StoragePartitionKey;
use sha2::{Digest, Sha256};

pub(crate) struct DiskCache {
    cache_dir: PathBuf,
}

impl DiskCache {
    pub(crate) fn open(cache_dir: impl AsRef<Path>) -> std::io::Result<Self> {
        let cache_dir = cache_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&cache_dir)?;
        Ok(DiskCache { cache_dir })
    }

    /// Hashes the partition key AND the url together into the cache
    /// filename, rather than using either alone — this is what makes
    /// the partitioning real: the SAME url embedded on two different
    /// top-level sites hashes to two different files, so there's no
    /// shared cache entry a cross-site timing/existence check could
    /// exploit. Also sidesteps any path-traversal concern from an
    /// arbitrary URL string, same reasoning `sync::FileSyncServer` uses
    /// for hashing `account_id` into a filename.
    fn path_for(&self, partition_key: &StoragePartitionKey, url: &str) -> PathBuf {
        let mut hasher = Sha256::new();
        hasher.update(partition_key.top_level_site.as_bytes());
        hasher.update(b"\0");
        hasher.update(partition_key.resource_host.as_bytes());
        hasher.update(b"\0");
        hasher.update(url.as_bytes());
        let hex: String = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        self.cache_dir.join(format!("{hex}.cache"))
    }

    /// Returns `Some((status, body))` for a fresh (non-expired) entry
    /// at this exact (partition, url) pair; `None` for a miss OR an
    /// expired entry. An expired entry is left on disk rather than
    /// proactively deleted here — `put` overwrites it in place the
    /// next time this same resource is successfully fetched, and until
    /// then it's simply inert (never returned, never actively cleaned
    /// up — there's no "clear browsing data" feature yet to hook a
    /// sweep into).
    pub(crate) fn get(
        &self,
        partition_key: &StoragePartitionKey,
        url: &str,
    ) -> Option<(u16, Vec<u8>)> {
        let bytes = std::fs::read(self.path_for(partition_key, url)).ok()?;
        let entry = CacheEntry::decode(&bytes)?;
        if now_unix() >= entry.stored_at_unix.saturating_add(entry.max_age_secs) {
            return None;
        }
        Some((entry.status, entry.body))
    }

    /// Writes via a temp file + rename — same reasoning as
    /// `sync::FileSyncServer::write_blob`: a crash or power loss
    /// mid-write can never leave a half-written, corrupt cache entry
    /// in the real file's place. Does nothing for `max_age` of zero
    /// (nothing to cache).
    pub(crate) fn put(
        &self,
        partition_key: &StoragePartitionKey,
        url: &str,
        status: u16,
        body: &[u8],
        max_age: Duration,
    ) {
        if max_age.is_zero() {
            return;
        }
        let entry = CacheEntry {
            stored_at_unix: now_unix(),
            max_age_secs: max_age.as_secs(),
            status,
            body: body.to_vec(),
        };
        let path = self.path_for(partition_key, url);
        let tmp_path = self.cache_dir.join(format!(
            "{}.tmp",
            path.file_name().unwrap().to_string_lossy()
        ));
        if std::fs::write(&tmp_path, entry.encode()).is_ok() {
            let _ = std::fs::rename(&tmp_path, &path);
        }
    }
}

struct CacheEntry {
    stored_at_unix: u64,
    max_age_secs: u64,
    status: u16,
    body: Vec<u8>,
}

impl CacheEntry {
    /// On-disk layout, all in one flat file: 8 bytes little-endian
    /// `stored_at_unix`, then 8 bytes `max_age_secs`, then 2 bytes
    /// `status`, then the body's raw bytes to EOF — NOT assumed to be
    /// UTF-8 text (an image response's body lands here as raw bytes
    /// too; a text response's own bytes already happen to BE its raw
    /// UTF-8 encoding, so this needed no format change to support
    /// both). No serde/JSON — the shape never changes and nothing but
    /// this file reads it.
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(18 + self.body.len());
        out.extend_from_slice(&self.stored_at_unix.to_le_bytes());
        out.extend_from_slice(&self.max_age_secs.to_le_bytes());
        out.extend_from_slice(&self.status.to_le_bytes());
        out.extend_from_slice(&self.body);
        out
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 18 {
            return None; // truncated/corrupt — treat like "no entry" rather than panicking
        }
        let stored_at_unix = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
        let max_age_secs = u64::from_le_bytes(bytes[8..16].try_into().ok()?);
        let status = u16::from_le_bytes(bytes[16..18].try_into().ok()?);
        let body = bytes[18..].to_vec();
        Some(CacheEntry {
            stored_at_unix,
            max_age_secs,
            status,
            body,
        })
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Parses `max-age=N` out of a `Cache-Control` header value. Returns
/// `None` (meaning "don't cache this") for `no-store`/`no-cache`, a
/// missing/malformed `max-age`, or no directive at all — a
/// conservative default rather than guessing a TTL for a response that
/// never explicitly opted into caching.
pub(crate) fn parse_max_age(cache_control: &str) -> Option<Duration> {
    let lower = cache_control.to_ascii_lowercase();
    if lower.contains("no-store") || lower.contains("no-cache") {
        return None;
    }
    for directive in lower.split(',') {
        if let Some(value) = directive.trim().strip_prefix("max-age=") {
            if let Ok(secs) = value.trim().parse::<u64>() {
                return Some(Duration::from_secs(secs));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory under the OS temp dir, unique per test (PID + an
    /// incrementing counter), cleaned up when the returned guard drops
    /// — avoids pulling in a `tempfile` dependency just for this (same
    /// pattern `sync`'s own tests use).
    struct TempDir(PathBuf);
    impl TempDir {
        fn new(label: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "abyssal-cache-test-{label}-{}-{n}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).unwrap();
            TempDir(path)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn key(top_level_site: &str, resource_host: &str) -> StoragePartitionKey {
        StoragePartitionKey {
            top_level_site: top_level_site.to_string(),
            resource_host: resource_host.to_string(),
        }
    }

    #[test]
    fn put_then_get_round_trips_within_the_ttl() {
        let dir = TempDir::new("roundtrip");
        let cache = DiskCache::open(&dir.0).unwrap();
        let k = key("news.example.com", "cdn.example.com");
        cache.put(
            &k,
            "https://cdn.example.com/style.css",
            200,
            b"body { color: red }",
            Duration::from_secs(3600),
        );

        let (status, body) = cache.get(&k, "https://cdn.example.com/style.css").unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, b"body { color: red }".to_vec());
    }

    #[test]
    fn a_zero_max_age_is_never_written() {
        let dir = TempDir::new("zero-ttl");
        let cache = DiskCache::open(&dir.0).unwrap();
        let k = key("news.example.com", "news.example.com");
        cache.put(
            &k,
            "https://news.example.com/",
            200,
            b"<html></html>",
            Duration::ZERO,
        );
        assert!(cache.get(&k, "https://news.example.com/").is_none());
    }

    #[test]
    fn an_expired_entry_is_treated_as_a_miss() {
        let dir = TempDir::new("expired");
        let cache = DiskCache::open(&dir.0).unwrap();
        let k = key("news.example.com", "news.example.com");

        // Write an entry that's already expired (stored an hour ago
        // with a 1-second max-age) by constructing it directly, rather
        // than waiting a second for a real `put` entry to expire.
        let entry = CacheEntry {
            stored_at_unix: now_unix() - 3600,
            max_age_secs: 1,
            status: 200,
            body: b"stale".to_vec(),
        };
        let path = cache.path_for(&k, "https://news.example.com/");
        std::fs::write(&path, entry.encode()).unwrap();

        assert!(cache.get(&k, "https://news.example.com/").is_none());
    }

    #[test]
    fn the_same_url_in_different_partitions_never_collides() {
        let dir = TempDir::new("partitioned");
        let cache = DiskCache::open(&dir.0).unwrap();
        let key_a = key("siteA.com", "cdn.example.com");
        let key_b = key("siteB.com", "cdn.example.com");

        cache.put(
            &key_a,
            "https://cdn.example.com/lib.js",
            200,
            b"from site A's embedding",
            Duration::from_secs(3600),
        );

        // Same resource URL, different top-level embedding site — must
        // be a clean miss, not the other partition's entry. This IS
        // the actual privacy property this module exists to provide.
        assert!(cache
            .get(&key_b, "https://cdn.example.com/lib.js")
            .is_none());
    }

    #[test]
    fn parse_max_age_reads_the_directive() {
        assert_eq!(
            parse_max_age("max-age=3600"),
            Some(Duration::from_secs(3600))
        );
        assert_eq!(
            parse_max_age("public, max-age=60"),
            Some(Duration::from_secs(60))
        );
    }

    #[test]
    fn parse_max_age_refuses_no_store_and_no_cache() {
        assert_eq!(parse_max_age("no-store"), None);
        assert_eq!(parse_max_age("no-cache, max-age=3600"), None);
    }

    #[test]
    fn parse_max_age_is_none_with_no_directive_at_all() {
        assert_eq!(parse_max_age("public"), None);
        assert_eq!(parse_max_age(""), None);
    }
}
