//! `localStorage` — a real, per-origin, disk-persisted key/value store
//! exposed to page JS (see `script::setup_globals`) implementing the
//! standard Web Storage API's method surface (`getItem`/`setItem`/
//! `removeItem`/`clear`/`key`/`.length`). Deliberately NOT partitioned
//! by top-level site the way `network::PartitionedCookieJar` is (see
//! that type's own doc comment for why cookies need it) — this browser
//! has no `<iframe>` support at all, so there is no way for a
//! third-party embedded context to ever read another site's
//! localStorage in the first place; the cross-site-tracking concern
//! partitioning exists to defend against simply doesn't apply here.
//!
//! Persisted to disk now too, but not by this process: this crate
//! reports its own real, plaintext `to_bytes()` back to `app` over the
//! existing IPC channel (`ipc::ServerMessage::updated_local_storage`),
//! and `app` (the only process that ever holds the account's
//! encryption key) actually encrypts and writes `local_storage.enc`,
//! and decrypts and seeds a freshly-spawned renderer from it
//! (`ipc::RenderRequest::initial_local_storage`) — see those two
//! fields' own doc comments. `merge_into` is what
//! `RendererState::seed_storage_from_request` uses to fold seed bytes
//! into this process's live store; a version counter lets a caller
//! cheaply tell whether anything actually changed since it last
//! reported this store.
//!
//! Scope, deliberately narrow:
//!   - No IndexedDB (a separate module, `indexed_db`, covers a real
//!     but intentionally-reduced subset of that — see its own docs for
//!     exactly where it stops short of the full spec).
//!   - A generous but real quota (`MAX_BYTES_PER_ORIGIN`), enforced
//!     with a plain summed-bytes check, not anything more precise —
//!     same motivation as real browsers' own per-origin caps: a
//!     misbehaving or adversarial page can't grow this file (and the
//!     process's own memory) without bound.
//!
//! `set`/`remove`/`clear` all report the PREVIOUS value(s) they
//! overwrote — not needed by this module itself, but exactly what
//! `script::build_local_storage_object`'s closures need to build a
//! real, spec-shaped `StorageChange` (`key`/`oldValue`/`newValue`) for
//! the cross-tab `storage` event (see `script::StorageChange`'s own
//! doc comment) without a second, redundant `get` call at every
//! mutation site.

use std::collections::HashMap;

/// Real browsers cap `localStorage` per origin (Chrome/Firefox: ~5-10
/// MiB) — 5 MiB matches the low end of what real browsers actually
/// enforce.
const MAX_BYTES_PER_ORIGIN: usize = 5 * 1024 * 1024;

#[derive(Debug, Default, Clone)]
pub struct LocalStorageStore {
    origins: HashMap<String, OriginStorage>,
    /// Bumped by every real mutation (`set`/`remove`/`clear`) — see
    /// `network::PartitionedCookieJar::version`'s own doc comment for
    /// why this exists (the same "only persist if something actually
    /// changed" check `renderer::RendererState` uses for both).
    version: u64,
}

/// One origin's stored entries. `order` (insertion order, a checked-
/// out-and-appended-to `Vec` rather than relying on `HashMap`'s
/// unspecified iteration order) is what makes the real `key(index)`
/// method well-defined and stable across a save/load round trip —
/// removing a key removes it from both `entries` and `order` together.
#[derive(Debug, Default, Clone)]
struct OriginStorage {
    entries: HashMap<String, String>,
    order: Vec<String>,
}

impl OriginStorage {
    fn total_bytes(&self) -> usize {
        self.entries.iter().map(|(k, v)| k.len() + v.len()).sum()
    }
}

/// Real `localStorage.setItem` throws a `QuotaExceededError` `DOMException`
/// when a write would exceed the origin's quota — `script::setup_globals`
/// is what turns this into that real, catchable JS exception.
#[derive(Debug)]
pub struct QuotaExceeded;

impl LocalStorageStore {
    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn get(&self, origin: &str, key: &str) -> Option<String> {
        self.origins.get(origin)?.entries.get(key).cloned()
    }

    /// Returns the key's PREVIOUS value (`None` if this is a brand new
    /// key) — see this module's own doc comment for why.
    pub fn set(
        &mut self,
        origin: &str,
        key: String,
        value: String,
    ) -> Result<Option<String>, QuotaExceeded> {
        let storage = self.origins.entry(origin.to_string()).or_default();
        let previous_bytes = storage
            .entries
            .get(&key)
            .map(|v| key.len() + v.len())
            .unwrap_or(0);
        let new_bytes = key.len() + value.len();
        if storage.total_bytes() - previous_bytes + new_bytes > MAX_BYTES_PER_ORIGIN {
            return Err(QuotaExceeded);
        }
        if !storage.entries.contains_key(&key) {
            storage.order.push(key.clone());
        }
        let previous = storage.entries.insert(key, value);
        self.version += 1;
        Ok(previous)
    }

    /// Returns the removed key's previous value (`None` if it didn't
    /// exist — a real no-op, matching `removeItem`'s own real
    /// behavior).
    pub fn remove(&mut self, origin: &str, key: &str) -> Option<String> {
        let storage = self.origins.get_mut(origin)?;
        let previous = storage.entries.remove(key)?;
        storage.order.retain(|k| k != key);
        self.version += 1;
        Some(previous)
    }

    /// Returns whether this origin actually had anything to clear — a
    /// real `clear()` on an already-empty origin is a no-op, and real
    /// browsers don't fire a `storage` event for it.
    pub fn clear(&mut self, origin: &str) -> bool {
        let had_entries = self
            .origins
            .get(origin)
            .is_some_and(|storage| !storage.entries.is_empty());
        if self.origins.remove(origin).is_some() {
            self.version += 1;
        }
        had_entries
    }

    pub fn len(&self, origin: &str) -> usize {
        self.origins.get(origin).map_or(0, |s| s.order.len())
    }

    pub fn key_at(&self, origin: &str, index: usize) -> Option<String> {
        self.origins.get(origin)?.order.get(index).cloned()
    }

    /// Real JSON serialization via `serde_json::Value` — see
    /// `network::PartitionedCookieJar::to_bytes`'s own doc comment for
    /// why this crate hand-builds `Value`s rather than deriving
    /// `Serialize` (no plain `serde` dependency, just `serde_json`).
    /// An array of `{"origin", "order", "entries"}` objects, one per
    /// origin — `order` is its own array (not just `entries.keys()`)
    /// specifically so real insertion order survives the round trip.
    pub fn to_bytes(&self) -> Vec<u8> {
        let entries: Vec<serde_json::Value> = self
            .origins
            .iter()
            .map(|(origin, storage)| {
                serde_json::json!({
                    "origin": origin,
                    "order": storage.order,
                    "entries": storage.entries,
                })
            })
            .collect();
        serde_json::to_vec(&entries).unwrap_or_default()
    }

    /// The `to_bytes` inverse. A malformed entry (missing a field, a
    /// non-string value) is skipped rather than failing the whole
    /// load — one bad origin shouldn't cost every other site's stored
    /// data too. Malformed `bytes` overall (not valid JSON at all) is
    /// the one case that gives up entirely.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let parsed: Vec<serde_json::Value> = serde_json::from_slice(bytes).ok()?;
        let mut origins = HashMap::new();
        for entry in &parsed {
            let (Some(origin), Some(order_value), Some(entries_obj)) = (
                entry.get("origin").and_then(|v| v.as_str()),
                entry.get("order").and_then(|v| v.as_array()),
                entry.get("entries").and_then(|v| v.as_object()),
            ) else {
                continue;
            };
            let order: Vec<String> = order_value
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect();
            let entries: HashMap<String, String> = entries_obj
                .iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect();
            origins.insert(origin.to_string(), OriginStorage { entries, order });
        }
        Some(LocalStorageStore {
            origins,
            version: 0,
        })
    }

    /// Overwrites, into `on_disk`, every origin THIS store has an
    /// entry for — leaving any origin this store has no opinion on
    /// untouched. See `network::PartitionedCookieJar::merge_into`'s
    /// own doc comment: the same mechanism, for the same reason
    /// (several concurrent, independent renderer processes — one per
    /// site — each reporting their own origins toward the ONE shared,
    /// `app`-owned `local_storage.enc`, over `ipc::ServerMessage::
    /// updated_local_storage` — see that field's own doc comment for
    /// why persistence moved to `app` at all). Used directly by
    /// `renderer::RendererState::seed_storage_from_request` to merge
    /// `app`-decrypted seed bytes into this process's live store;
    /// `app` itself can't call this method directly (it must never
    /// depend on this crate — see `ARCHITECTURE.md`), so
    /// `app::merge_persisted_json` reimplements the same semantics
    /// generically, over raw JSON, using this method's own real
    /// behavior as the reference.
    pub fn merge_into(&self, on_disk: &mut Self) {
        for (origin, storage) in &self.origins {
            on_disk.origins.insert(origin.clone(), storage.clone());
        }
        on_disk.version += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_then_get_round_trips_within_one_origin() {
        let mut store = LocalStorageStore::default();
        store
            .set(
                "https://example.com",
                "theme".to_string(),
                "dark".to_string(),
            )
            .unwrap();
        assert_eq!(
            store.get("https://example.com", "theme").as_deref(),
            Some("dark")
        );
    }

    #[test]
    fn different_origins_never_see_each_others_data() {
        let mut store = LocalStorageStore::default();
        store
            .set("https://a.example", "k".to_string(), "a-value".to_string())
            .unwrap();
        store
            .set("https://b.example", "k".to_string(), "b-value".to_string())
            .unwrap();
        assert_eq!(
            store.get("https://a.example", "k").as_deref(),
            Some("a-value")
        );
        assert_eq!(
            store.get("https://b.example", "k").as_deref(),
            Some("b-value")
        );
    }

    #[test]
    fn remove_deletes_a_key_and_is_a_no_op_if_already_absent() {
        let mut store = LocalStorageStore::default();
        store
            .set("https://example.com", "k".to_string(), "v".to_string())
            .unwrap();
        store.remove("https://example.com", "k");
        assert_eq!(store.get("https://example.com", "k"), None);
        store.remove("https://example.com", "k");
        assert_eq!(store.get("https://example.com", "k"), None);
    }

    #[test]
    fn clear_removes_every_key_for_that_origin_only() {
        let mut store = LocalStorageStore::default();
        store
            .set("https://a.example", "k".to_string(), "v".to_string())
            .unwrap();
        store
            .set("https://b.example", "k".to_string(), "v".to_string())
            .unwrap();
        store.clear("https://a.example");
        assert_eq!(store.get("https://a.example", "k"), None);
        assert_eq!(store.get("https://b.example", "k").as_deref(), Some("v"));
    }

    #[test]
    fn key_at_reflects_real_insertion_order() {
        let mut store = LocalStorageStore::default();
        store
            .set("https://example.com", "first".to_string(), "1".to_string())
            .unwrap();
        store
            .set("https://example.com", "second".to_string(), "2".to_string())
            .unwrap();
        assert_eq!(store.len("https://example.com"), 2);
        assert_eq!(
            store.key_at("https://example.com", 0).as_deref(),
            Some("first")
        );
        assert_eq!(
            store.key_at("https://example.com", 1).as_deref(),
            Some("second")
        );
        assert_eq!(store.key_at("https://example.com", 2), None);
    }

    #[test]
    fn overwriting_an_existing_key_does_not_duplicate_it_in_key_order() {
        let mut store = LocalStorageStore::default();
        store
            .set("https://example.com", "k".to_string(), "1".to_string())
            .unwrap();
        store
            .set("https://example.com", "k".to_string(), "2".to_string())
            .unwrap();
        assert_eq!(store.len("https://example.com"), 1);
        assert_eq!(store.get("https://example.com", "k").as_deref(), Some("2"));
    }

    #[test]
    fn writing_past_the_quota_is_rejected_and_does_not_change_anything() {
        let mut store = LocalStorageStore::default();
        let big_value = "x".repeat(MAX_BYTES_PER_ORIGIN + 1);
        let result = store.set("https://example.com", "k".to_string(), big_value);
        assert!(result.is_err());
        assert_eq!(store.get("https://example.com", "k"), None);
    }

    #[test]
    fn a_real_mutation_bumps_the_version_but_a_lookup_does_not() {
        let mut store = LocalStorageStore::default();
        assert_eq!(store.version(), 0);
        store
            .set("https://example.com", "k".to_string(), "v".to_string())
            .unwrap();
        assert_eq!(store.version(), 1);
        let _ = store.get("https://example.com", "k");
        assert_eq!(store.version(), 1, "a read-only lookup shouldn't bump it");
    }

    #[test]
    fn store_round_trips_through_bytes_including_key_order() {
        let mut store = LocalStorageStore::default();
        store
            .set("https://example.com", "a".to_string(), "1".to_string())
            .unwrap();
        store
            .set("https://example.com", "b".to_string(), "2".to_string())
            .unwrap();

        let restored = LocalStorageStore::from_bytes(&store.to_bytes()).unwrap();
        assert_eq!(
            restored.key_at("https://example.com", 0).as_deref(),
            Some("a")
        );
        assert_eq!(
            restored.key_at("https://example.com", 1).as_deref(),
            Some("b")
        );
        assert_eq!(
            restored.get("https://example.com", "b").as_deref(),
            Some("2")
        );
    }

    #[test]
    fn from_bytes_is_none_for_garbage() {
        assert!(LocalStorageStore::from_bytes(b"not json at all").is_none());
    }

    #[test]
    fn merge_into_overwrites_only_the_origins_it_has_an_opinion_on() {
        // Mirrors what `app::merge_persisted_json` now does generically
        // over raw JSON (see that function's own doc comment for why
        // `app` can't call this real, typed method directly) — this
        // test covers the real thing directly: renderer process A
        // (siteA.com) and renderer process B (siteB.com) each only
        // ever touch their own origin, so merging B's store into A's
        // must not clobber A's data.
        let mut on_disk = LocalStorageStore::default();
        on_disk
            .set("https://siteA.com", "k".to_string(), "a-value".to_string())
            .unwrap();

        let mut store_b = LocalStorageStore::default();
        store_b
            .set("https://siteB.com", "k".to_string(), "b-value".to_string())
            .unwrap();
        store_b.merge_into(&mut on_disk);

        assert_eq!(
            on_disk.get("https://siteA.com", "k").as_deref(),
            Some("a-value")
        );
        assert_eq!(
            on_disk.get("https://siteB.com", "k").as_deref(),
            Some("b-value")
        );
    }
}
