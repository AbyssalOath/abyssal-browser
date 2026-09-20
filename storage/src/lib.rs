//! `storage` — the local data model for bookmarks and settings.
//!
//! This is deliberately the one crate in the sync path that knows
//! nothing about encryption or networking: it just models "what data
//! syncs" and can turn itself into bytes (`to_bytes`) and back
//! (`from_bytes`). Those bytes are what `account::encrypt` seals
//! before `sync` uploads them — this crate has no idea that's
//! happening, which is the point (easy to unit test in isolation).
//!
//! Scope of this stub:
//!   - `Bookmark`: title + URL + creation timestamp only. No folders,
//!     no tags, no favicons.
//!   - `Settings`: a flat string->string map (e.g. "fingerprint
//!     resistance level" -> "strict"), each entry carrying its own
//!     `updated_at_unix` internally — see `Settings::merge`.
//!   - `SyncPayload::merge`: combines two payloads that diverged
//!     offline (e.g. a bookmark added on one device while another was
//!     offline, then both synced) into one result that keeps data from
//!     BOTH sides wherever possible, instead of one whole side being
//!     silently discarded. This is what `app` calls when `sync`
//!     reports a version conflict — see its own module docs for why
//!     the merge has to live here (in the crate that can see
//!     plaintext) rather than in `sync` (which never can).
//!
//! Next steps, roughly in order of payoff:
//!   1. Bookmark folders/ordering, and a real `Settings` schema
//!      instead of stringly-typed keys.
//!   2. `SyncPayload::merge`'s bookmark side has no stable identity to
//!      key off of beyond URL — a rename-in-place edit feature (not
//!      implemented yet; today bookmarks are only ever added, never
//!      edited) would need a real `id` field to merge correctly rather
//!      than treating "same URL" as "same bookmark."
//!   3. A CRDT (e.g. an OR-Set for bookmarks, proper LWW-registers with
//!      per-replica ids for settings) is the fully-correct answer if
//!      this ever needs to resolve concurrent edits to the SAME field
//!      without an arbitrary tie-break — see `Settings::merge`'s doc
//!      comment for exactly where the current merge still has to pick
//!      a side arbitrarily.

use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Bookmark {
    pub title: String,
    pub url: String,
    pub created_at_unix: u64,
}

/// One visited page — unlike `Bookmark`, NOT deduplicated by URL:
/// visiting the same page twice is two separate entries, matching how
/// a real browser's history works (a bookmark means "keep this
/// forever"; a history entry means "I was here at this moment").
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct HistoryEntry {
    pub url: String,
    /// `None` for a page with no `<title>` — real browsers fall back to
    /// showing the bare URL in that case, which `app`'s history page
    /// does too rather than storing a fake placeholder string here.
    pub title: Option<String>,
    pub visited_at_unix: u64,
}

/// How many history entries `SyncPayload::record_visit` keeps before
/// pruning the oldest — bounds how large the synced blob can grow from
/// history alone. Every sync round-trips the ENTIRE payload (see this
/// module's own docs), so an unbounded, ever-growing history log would
/// make every single sync progressively slower and heavier forever;
/// capping it is what keeps that cost bounded for a browser that stays
/// installed (and browsing) indefinitely. Arbitrary but generous for
/// personal use — real browsers typically cap by AGE (e.g. 90 days)
/// rather than count, which would be a more principled choice than a
/// flat count if this ever needs revisiting.
const MAX_HISTORY_ENTRIES: usize = 500;

/// One setting's value plus WHEN it was last set. The timestamp is
/// what makes `Settings::merge` a real last-write-wins-PER-KEY
/// resolution rather than the old whole-blob "whichever push landed
/// last wins for literally every key" behavior.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct SettingEntry {
    key: String,
    value: String,
    updated_at_unix: u64,
}

#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Settings {
    entries: Vec<SettingEntry>,
}

impl Settings {
    pub fn set(&mut self, key: &str, value: &str) {
        self.set_at(key, value, now_unix());
    }

    /// Same as `set`, but with an explicit timestamp instead of
    /// "right now" — used by `merge` to preserve each side's original
    /// modification time when folding one `Settings` into another, and
    /// by this module's own tests, which need deterministic timestamps
    /// rather than whatever `now_unix()` happens to return.
    fn set_at(&mut self, key: &str, value: &str, updated_at_unix: u64) {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.key == key) {
            entry.value = value.to_string();
            entry.updated_at_unix = updated_at_unix;
        } else {
            self.entries.push(SettingEntry {
                key: key.to_string(),
                value: value.to_string(),
                updated_at_unix,
            });
        }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|e| e.key == key)
            .map(|e| e.value.as_str())
    }

    /// Last-write-wins-per-key merge: a key present on only one side is
    /// kept as-is; a key present on BOTH sides keeps whichever entry
    /// has the later `updated_at_unix`. That only still loses data in
    /// the narrower case of both sides changing the SAME key offline —
    /// there's no third value to reconcile a genuine conflict on one
    /// field down to, so one write has to be picked (ties, e.g. two
    /// changes in the same second, are broken toward `self`'s value).
    /// A real CRDT LWW-register (with a per-replica id breaking ties
    /// deterministically instead of by argument order) is the fully
    /// principled version of this; not worth the complexity yet for a
    /// handful of string settings.
    fn merge(&self, other: &Settings) -> Settings {
        let mut merged = self.clone();
        for entry in &other.entries {
            match merged.entries.iter().position(|e| e.key == entry.key) {
                Some(idx) => {
                    if entry.updated_at_unix > merged.entries[idx].updated_at_unix {
                        merged.entries[idx] = entry.clone();
                    }
                }
                None => merged.entries.push(entry.clone()),
            }
        }
        merged
    }
}

/// The full syncable payload: everything that gets encrypted as one
/// blob and pushed/pulled as a unit.
///
/// TODO: syncing everything as one blob is the simplest possible
/// design and the easiest to get right first, but it means every
/// sync round-trips your entire bookmark set. Fine at hobby scale;
/// revisit (per-record blobs, or a CRDT) if that becomes a problem.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SyncPayload {
    pub bookmarks: Vec<Bookmark>,
    pub settings: Settings,
    /// Newest-last. `#[serde(default)]` so a payload persisted before
    /// this field existed still deserializes (as an empty history)
    /// rather than failing to load at all.
    #[serde(default)]
    pub history: Vec<HistoryEntry>,
}

impl SyncPayload {
    pub fn new() -> Self {
        Self::default()
    }

    /// A no-op if `url` is already bookmarked — keeps this idempotent
    /// the way a toggle button needs it to be (press it twice on the
    /// same page and there's still exactly one bookmark), and matches
    /// `merge`'s own by-URL dedup semantics above instead of fighting
    /// them: without this, pressing the star, syncing, then pressing
    /// it again on another device would leave two separate `Bookmark`
    /// rows for the same URL until the next merge quietly collapsed
    /// them.
    pub fn add_bookmark(&mut self, title: &str, url: &str) {
        if self.is_bookmarked(url) {
            return;
        }
        self.bookmarks.push(Bookmark {
            title: title.to_string(),
            url: url.to_string(),
            created_at_unix: now_unix(),
        });
    }

    /// Whether `url` (exact match) is already in `bookmarks` — the
    /// bookmark toggle button's read side; see `add_bookmark`'s doc
    /// comment for why "bookmarked" has no separate stable id and URL
    /// is the identity used everywhere else in this type too.
    pub fn is_bookmarked(&self, url: &str) -> bool {
        self.bookmarks.iter().any(|b| b.url == url)
    }

    /// Removes every bookmark whose URL is exactly `url` — the
    /// bookmark toggle button's un-bookmark side. A no-op if `url`
    /// isn't bookmarked, so callers don't need to check first.
    pub fn remove_bookmark(&mut self, url: &str) {
        self.bookmarks.retain(|b| b.url != url);
    }

    /// Records a visit to `url` (with whatever title, if any, the page
    /// had), pruning down to `MAX_HISTORY_ENTRIES` (oldest first) so
    /// this never grows the synced blob without bound — see that
    /// constant's own doc comment.
    pub fn record_visit(&mut self, url: &str, title: Option<&str>) {
        self.history.push(HistoryEntry {
            url: url.to_string(),
            title: title.map(str::to_string),
            visited_at_unix: now_unix(),
        });
        if self.history.len() > MAX_HISTORY_ENTRIES {
            let excess = self.history.len() - MAX_HISTORY_ENTRIES;
            self.history.drain(0..excess);
        }
    }

    /// Erases all history entries — the one thing a "clear history"
    /// action needs to do; bookmarks/settings are untouched.
    pub fn clear_history(&mut self) {
        self.history.clear();
    }

    /// Real JSON serialization via `serde_json` — handles quotes, tabs,
    /// newlines, and any other bookmark-title content correctly, unlike
    /// the hand-rolled tab-delimited format this replaces (which
    /// corrupted or dropped other bookmarks in the same file if a title
    /// contained a literal tab or newline).
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self)
            .expect("SyncPayload contains only plain data and always serializes")
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice(bytes).ok()
    }

    /// Combines `self` with `other` — typically "my local, possibly
    /// offline-modified bookmarks" and "whatever the sync server
    /// actually has" — into one payload that keeps data from BOTH
    /// sides wherever the two didn't genuinely conflict, instead of
    /// the old behavior of one whole side winning and the other being
    /// silently discarded:
    ///   - bookmarks: unioned by URL — the natural identity for a
    ///     bookmark here, since there's no separate stable id (see
    ///     this module's "next steps"). A URL saved on both sides
    ///     keeps whichever copy has the later `created_at_unix`.
    ///   - settings: merged key-by-key via `Settings::merge`.
    ///   - history: unioned by (url, visited_at_unix) pair — unlike
    ///     bookmarks, the SAME url legitimately appears many times (one
    ///     per visit), so url alone can't be the identity; an exact
    ///     duplicate entry (both fields equal, e.g. the same visit
    ///     synced from two devices) is kept once, not twice. Re-sorted
    ///     by time and re-capped to `MAX_HISTORY_ENTRIES` afterward, the
    ///     same as a single `record_visit` would.
    ///
    /// Not perfectly order-independent: an exact tie (identical
    /// timestamp on both sides for the same URL/key) breaks toward
    /// `self`, so `a.merge(&b)` and `b.merge(&a)` could differ in that
    /// edge case. That only matters for which of two otherwise-equal
    /// writes "wins" cosmetically — no bookmark or setting is ever
    /// dropped by it.
    pub fn merge(&self, other: &SyncPayload) -> SyncPayload {
        let mut bookmarks = self.bookmarks.clone();
        for candidate in &other.bookmarks {
            match bookmarks.iter().position(|b| b.url == candidate.url) {
                Some(idx) => {
                    if candidate.created_at_unix > bookmarks[idx].created_at_unix {
                        bookmarks[idx] = candidate.clone();
                    }
                }
                None => bookmarks.push(candidate.clone()),
            }
        }

        let mut history = self.history.clone();
        for candidate in &other.history {
            let is_duplicate = history
                .iter()
                .any(|h| h.url == candidate.url && h.visited_at_unix == candidate.visited_at_unix);
            if !is_duplicate {
                history.push(candidate.clone());
            }
        }
        history.sort_by_key(|h| h.visited_at_unix);
        if history.len() > MAX_HISTORY_ENTRIES {
            let excess = history.len() - MAX_HISTORY_ENTRIES;
            history.drain(0..excess);
        }

        SyncPayload {
            bookmarks,
            settings: self.settings.merge(&other.settings),
            history,
        }
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_bookmarks_and_settings_through_bytes() {
        let mut payload = SyncPayload::new();
        payload.add_bookmark("Example", "https://example.com");
        payload.settings.set("fingerprint_resistance", "strict");

        let bytes = payload.to_bytes();
        let restored = SyncPayload::from_bytes(&bytes).unwrap();

        assert_eq!(restored.bookmarks.len(), 1);
        assert_eq!(restored.bookmarks[0].url, "https://example.com");
        assert_eq!(
            restored.settings.get("fingerprint_resistance"),
            Some("strict")
        );
    }

    #[test]
    fn is_bookmarked_is_true_only_for_an_exact_url_match() {
        let mut payload = SyncPayload::new();
        payload.add_bookmark("Example", "https://example.com");

        assert!(payload.is_bookmarked("https://example.com"));
        assert!(!payload.is_bookmarked("https://example.com/"));
        assert!(!payload.is_bookmarked("https://example.org"));
    }

    #[test]
    fn adding_the_same_url_twice_does_not_create_a_duplicate_bookmark() {
        let mut payload = SyncPayload::new();
        payload.add_bookmark("Example", "https://example.com");
        payload.add_bookmark("Example Again", "https://example.com");

        assert_eq!(payload.bookmarks.len(), 1);
        assert_eq!(payload.bookmarks[0].title, "Example");
    }

    #[test]
    fn remove_bookmark_deletes_it_and_is_a_no_op_if_already_absent() {
        let mut payload = SyncPayload::new();
        payload.add_bookmark("Example", "https://example.com");

        payload.remove_bookmark("https://example.com");
        assert!(!payload.is_bookmarked("https://example.com"));
        assert!(payload.bookmarks.is_empty());

        payload.remove_bookmark("https://example.com");
        assert!(payload.bookmarks.is_empty());
    }

    #[test]
    fn special_characters_in_a_bookmark_title_survive_the_round_trip() {
        let mut payload = SyncPayload::new();
        payload.add_bookmark("My \"Cool\"\tSite\nWith Weird Stuff", "https://example.com");
        payload.add_bookmark("Second Bookmark", "https://example.org");

        let bytes = payload.to_bytes();
        let restored = SyncPayload::from_bytes(&bytes).unwrap();

        assert_eq!(
            restored.bookmarks.len(),
            2,
            "a tab/newline/quote in one title should never corrupt or drop other bookmarks"
        );
        assert_eq!(
            restored.bookmarks[0].title,
            "My \"Cool\"\tSite\nWith Weird Stuff"
        );
        assert_eq!(restored.bookmarks[1].url, "https://example.org");
    }

    #[test]
    fn merge_keeps_bookmarks_added_independently_on_both_sides() {
        let mut local = SyncPayload::new();
        local.add_bookmark("Local Only", "https://local.example");

        let mut remote = SyncPayload::new();
        remote.add_bookmark("Remote Only", "https://remote.example");

        let merged = local.merge(&remote);

        assert_eq!(
            merged.bookmarks.len(),
            2,
            "neither side's independent addition should be dropped"
        );
        assert!(merged
            .bookmarks
            .iter()
            .any(|b| b.url == "https://local.example"));
        assert!(merged
            .bookmarks
            .iter()
            .any(|b| b.url == "https://remote.example"));
    }

    #[test]
    fn merge_of_the_same_url_keeps_the_more_recent_copy() {
        let local = SyncPayload {
            bookmarks: vec![Bookmark {
                title: "Old Title".into(),
                url: "https://example.com".into(),
                created_at_unix: 100,
            }],
            settings: Settings::default(),
            history: Vec::new(),
        };
        let remote = SyncPayload {
            bookmarks: vec![Bookmark {
                title: "New Title".into(),
                url: "https://example.com".into(),
                created_at_unix: 200,
            }],
            settings: Settings::default(),
            history: Vec::new(),
        };

        let merged = local.merge(&remote);

        assert_eq!(
            merged.bookmarks.len(),
            1,
            "same URL on both sides is one bookmark, not two"
        );
        assert_eq!(merged.bookmarks[0].title, "New Title");
    }

    #[test]
    fn merge_is_a_no_op_when_both_sides_are_identical() {
        let mut payload = SyncPayload::new();
        payload.add_bookmark("Example", "https://example.com");
        payload.settings.set("theme", "dark");

        let merged = payload.merge(&payload.clone());
        assert_eq!(merged, payload);
    }

    #[test]
    fn settings_merge_keeps_independent_keys_from_both_sides() {
        let mut local = Settings::default();
        local.set_at("theme", "dark", 100);

        let mut remote = Settings::default();
        remote.set_at("fingerprint_resistance", "strict", 100);

        let merged = local.merge(&remote);

        assert_eq!(
            merged.get("theme"),
            Some("dark"),
            "local-only setting should survive the merge"
        );
        assert_eq!(
            merged.get("fingerprint_resistance"),
            Some("strict"),
            "remote-only setting should survive the merge"
        );
    }

    #[test]
    fn settings_merge_of_the_same_key_keeps_the_more_recent_value() {
        let mut local = Settings::default();
        local.set_at("theme", "dark", 100);

        let mut remote = Settings::default();
        remote.set_at("theme", "light", 200);

        let merged = local.merge(&remote);
        assert_eq!(
            merged.get("theme"),
            Some("light"),
            "the later write should win, not whichever side pushed last"
        );

        // And the reverse: an older remote value should never clobber
        // a newer local one, which whole-blob last-write-wins couldn't
        // guarantee (it only knows about the blob's own push order).
        let mut newer_local = Settings::default();
        newer_local.set_at("theme", "dark", 300);
        let merged_reverse = newer_local.merge(&remote);
        assert_eq!(merged_reverse.get("theme"), Some("dark"));
    }

    #[test]
    fn record_visit_appends_a_history_entry_with_the_given_title() {
        let mut payload = SyncPayload::new();
        payload.record_visit("https://example.com", Some("Example Domain"));

        assert_eq!(payload.history.len(), 1);
        assert_eq!(payload.history[0].url, "https://example.com");
        assert_eq!(payload.history[0].title, Some("Example Domain".to_string()));
    }

    #[test]
    fn record_visit_allows_a_missing_title() {
        let mut payload = SyncPayload::new();
        payload.record_visit("https://example.com", None);
        assert_eq!(payload.history[0].title, None);
    }

    #[test]
    fn the_same_url_visited_twice_is_two_separate_history_entries() {
        let mut payload = SyncPayload::new();
        payload.record_visit("https://example.com", Some("First"));
        payload.record_visit("https://example.com", Some("First"));
        assert_eq!(
            payload.history.len(),
            2,
            "unlike a bookmark, each visit is its own entry, not deduplicated by URL"
        );
    }

    #[test]
    fn history_is_pruned_to_the_configured_maximum_oldest_first() {
        let mut payload = SyncPayload::new();
        for i in 0..(MAX_HISTORY_ENTRIES + 10) {
            payload.record_visit(&format!("https://example.com/{i}"), None);
        }
        assert_eq!(payload.history.len(), MAX_HISTORY_ENTRIES);
        assert_eq!(
            payload.history[0].url,
            format!("https://example.com/{}", 10),
            "the oldest 10 entries should have been pruned, not the newest"
        );
    }

    #[test]
    fn clear_history_empties_it_without_touching_bookmarks_or_settings() {
        let mut payload = SyncPayload::new();
        payload.record_visit("https://example.com", None);
        payload.add_bookmark("Example", "https://example.com");
        payload.settings.set("theme", "dark");

        payload.clear_history();

        assert!(payload.history.is_empty());
        assert_eq!(payload.bookmarks.len(), 1);
        assert_eq!(payload.settings.get("theme"), Some("dark"));
    }

    #[test]
    fn merge_unions_history_from_both_sides_without_duplicating_an_identical_entry() {
        let mut local = SyncPayload::new();
        local.record_visit("https://local.example", None);

        let mut remote = SyncPayload::new();
        remote.record_visit("https://remote.example", None);

        // Simulate the same visit having already synced to both sides.
        let shared = storage_history_entry("https://shared.example", 500);
        local.history.push(shared.clone());
        remote.history.push(shared);

        let merged = local.merge(&remote);

        assert_eq!(
            merged.history.len(),
            3,
            "two distinct visits plus one shared, deduplicated visit"
        );
        assert_eq!(
            merged
                .history
                .iter()
                .filter(|h| h.url == "https://shared.example")
                .count(),
            1,
            "an entry present on both sides (identical url + timestamp) should not be duplicated"
        );
    }

    #[test]
    fn merged_history_is_sorted_oldest_first_regardless_of_which_side_it_came_from() {
        let mut local = SyncPayload::new();
        local
            .history
            .push(storage_history_entry("https://b.example", 200));

        let mut remote = SyncPayload::new();
        remote
            .history
            .push(storage_history_entry("https://a.example", 100));

        let merged = local.merge(&remote);
        assert_eq!(merged.history[0].url, "https://a.example");
        assert_eq!(merged.history[1].url, "https://b.example");
    }

    fn storage_history_entry(url: &str, visited_at_unix: u64) -> HistoryEntry {
        HistoryEntry {
            url: url.to_string(),
            title: None,
            visited_at_unix,
        }
    }
}
