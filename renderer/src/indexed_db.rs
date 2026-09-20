//! IndexedDB — a real, per-origin, disk-persisted object store exposed
//! to page JS (see `script`'s `indexedDB` global) as a genuine subset
//! of the standard API, not an approximation bolted onto `localStorage`.
//! Persisted to disk the same way `local_storage::LocalStorageStore` is
//! now (see that module's own doc comment for the full reasoning,
//! which applies unchanged here): this crate reports its own real,
//! plaintext `to_bytes()` back to `app` over the existing IPC channel,
//! and `app` (the only process that ever holds the account's
//! encryption key) actually encrypts, merges, and writes
//! `indexed_db.enc`. A version counter lets a caller cheaply tell
//! whether anything actually changed since it last reported this
//! store.
//!
//! Scope, deliberately real but narrower than the full spec — this is
//! the "much bigger effort" the `local_storage` module's docs used to
//! flag as entirely out of scope; this module covers the part of it
//! that's actually load-bearing for real sites (a genuine, working
//! object store with keys, `keyPath`, `autoIncrement`, and real
//! version-gated `onupgradeneeded`), not the whole spec:
//!   - **Keys are strings or numbers only** — no `Date`, no binary
//!     keys, no array (compound) keys. Covers the overwhelming
//!     majority of real-world IndexedDB usage (an id, a UUID string, a
//!     timestamp).
//!   - **Values must be JSON-representable** — the same real
//!     constraint `network`'s `fetch().json()` already has elsewhere
//!     in this codebase, not a new one invented here. Real IndexedDB
//!     structured-clones values (so it can store `Date`/`Map`/`Set`/
//!     `ArrayBuffer`/circular references); this store round-trips
//!     through `serde_json::Value` instead, which cannot represent any
//!     of those.
//!   - **No indexes** (`createIndex`/`IDBIndex`) and **no cursors**
//!     (`openCursor`) or **key ranges** (`IDBKeyRange`) — `get`/`put`/
//!     `add`/`delete`/`clear`/`getAll`/`getAllKeys`/`count` cover
//!     direct key access and full-store scans, which is what a very
//!     large fraction of real sites that reach for IndexedDB (rather
//!     than a real backend database) actually use it for.
//!   - **No cross-connection `versionchange` event** — real browsers
//!     notify every OTHER open connection to the same database when
//!     one tab starts a version-upgrading `open()`, so it can close
//!     itself out of the way; this implementation has no notion of an
//!     open connection surviving past one script's synchronous access,
//!     so there is nothing to notify.
//!   - **Transactions don't really isolate or roll back** — every
//!     `__idb*` operation this module backs is already synchronous and
//!     immediately committed; `IDBTransaction` (built in `script`'s JS
//!     prelude) is a real, spec-shaped object with a real deferred
//!     `oncomplete`, but a request that fails partway through a
//!     multi-request transaction does NOT undo the requests that
//!     already succeeded, unlike a real browser's ACID transactions.
//!   - A generous but real quota (`MAX_BYTES_PER_ORIGIN`), enforced
//!     the same summed-bytes way `local_storage` enforces its own,
//!     smaller one — real browsers give IndexedDB a much larger quota
//!     than `localStorage`, which this mirrors.

use std::collections::HashMap;

use serde_json::Value;

/// Real browsers give IndexedDB a much larger quota than `localStorage`
/// (`local_storage::MAX_BYTES_PER_ORIGIN`, 5 MiB) — 25 MiB matches that
/// real-world gap without being unbounded.
const MAX_BYTES_PER_ORIGIN: usize = 25 * 1024 * 1024;

/// Mirrors the real `DOMException` names IndexedDB actually throws —
/// `script::idb_error_to_js` is what turns one of these into a real,
/// catchable JS exception carrying that same name in its message, the
/// same way `local_storage::QuotaExceeded` becomes a real
/// `QuotaExceededError`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdbError {
    /// No such database, object store, or (implicitly) key — real
    /// IndexedDB's `NotFoundError`.
    NotFound,
    /// A key constraint wasn't satisfied: `add()` on an already-used
    /// key, a keyed store given an explicit key anyway, a key-less
    /// store given neither an explicit key nor an extractable/
    /// generatable one, or a key of an unsupported type — real
    /// IndexedDB's `ConstraintError` (the last case would really be a
    /// `DataError`, collapsed into this one broader category here to
    /// keep the error surface small and real rather than exhaustively
    /// spec-accurate).
    ConstraintError,
    /// This origin's total stored bytes would exceed
    /// `MAX_BYTES_PER_ORIGIN` — real IndexedDB's `QuotaExceededError`.
    QuotaExceeded,
}

#[derive(Debug, Default, Clone)]
pub struct IndexedDbStore {
    origins: HashMap<String, HashMap<String, Database>>,
    /// Bumped by every real mutation — see
    /// `local_storage::LocalStorageStore::version`'s own doc comment
    /// for why this exists.
    version: u64,
}

#[derive(Debug, Default, Clone)]
struct Database {
    version: u64,
    object_stores: HashMap<String, ObjectStore>,
    /// Real creation order — `objectStoreNames` (a `DOMStringList` in
    /// a real browser) reports stores in a stable, deterministic
    /// order, not whatever `HashMap` iteration happens to give.
    store_order: Vec<String>,
}

#[derive(Debug, Default, Clone)]
struct ObjectStore {
    key_path: Option<String>,
    auto_increment: bool,
    next_auto_key: u64,
    /// Keyed by `canonical_key_string` — see that function's own doc
    /// comment. Each value is `(the real key, the stored record)`, so
    /// `getAllKeys`/`put`'s own return value can hand back the ORIGINAL
    /// typed key (a real number stays a `Value::Number`), not just the
    /// string used internally to index this map.
    entries: HashMap<String, (Value, Value)>,
    /// Real insertion order — same reasoning as `Database::store_order`
    /// and `local_storage::OriginStorage::order`.
    order: Vec<String>,
}

impl ObjectStore {
    fn total_bytes(&self) -> usize {
        self.entries
            .values()
            .map(|(k, v)| approx_json_bytes(k) + approx_json_bytes(v))
            .sum()
    }
}

fn approx_json_bytes(value: &Value) -> usize {
    serde_json::to_vec(value).map(|b| b.len()).unwrap_or(0)
}

/// Only a string or a number is a supported IndexedDB key here (see
/// this module's own scope doc comment) — `serde_json::to_string`
/// gives each a distinct, stable textual form (`"\"foo\""` vs `"3"`),
/// safe to use as a `HashMap` key without implementing `Eq`/`Hash` for
/// `Value` (which `f64` can't support directly) ourselves.
fn canonical_key_string(key: &Value) -> Option<String> {
    match key {
        Value::String(_) | Value::Number(_) => serde_json::to_string(key).ok(),
        _ => None,
    }
}

/// Extracts the value at a (possibly dotted, e.g. `"user.id"`) key path
/// out of a record — real IndexedDB `keyPath` support, including its
/// real nested-path form. `None` if any segment is missing or the
/// value isn't a plain object at that point — the caller then falls
/// back to auto-increment or reports a real `ConstraintError`.
fn extract_key_path<'a>(value: &'a Value, key_path: &str) -> Option<&'a Value> {
    let mut current = value;
    for segment in key_path.split('.') {
        current = current.as_object()?.get(segment)?;
    }
    Some(current)
}

/// The `extract_key_path` inverse: writes `key` into `value` at
/// (possibly dotted) `key_path`, creating intermediate objects as
/// needed — real IndexedDB's `autoIncrement` + `keyPath` behavior
/// (e.g. `{ keyPath: "id", autoIncrement: true }`) writes the
/// generated key back into the stored record so a caller reading it
/// back later sees its own real id, not just gets it as `put`'s return
/// value.
fn set_key_path(value: &mut Value, key_path: &str, key: Value) {
    let segments: Vec<&str> = key_path.split('.').collect();
    let mut current = value;
    for (i, segment) in segments.iter().enumerate() {
        if !current.is_object() {
            *current = Value::Object(serde_json::Map::new());
        }
        let obj = current
            .as_object_mut()
            .expect("just ensured this is an object");
        if i + 1 == segments.len() {
            obj.insert((*segment).to_string(), key);
            return;
        }
        current = obj
            .entry((*segment).to_string())
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
    }
}

/// What `IndexedDbStore::open` reports — `script`'s `indexedDB.open`
/// JS binding uses this directly to decide whether to fire a real
/// `onupgradeneeded` before `onsuccess` (`needs_upgrade`), and to give
/// that event its own real `oldVersion`/`newVersion` fields.
#[derive(Debug, Clone, Copy)]
pub struct OpenOutcome {
    pub old_version: u64,
    pub new_version: u64,
    pub needs_upgrade: bool,
}

impl IndexedDbStore {
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Opens (creating if this is the first time) `db_name` for
    /// `origin`. `requested_version` mirrors real
    /// `indexedDB.open(name, version)`: `None` means "whatever version
    /// already exists, or 1 for a brand new database" (real
    /// `indexedDB.open(name)` with no version argument); `Some(v)`
    /// requests exactly `v`, needing an upgrade if `v` is newer than
    /// what's stored.
    ///
    /// A version bump happens immediately here, not gated behind the
    /// upgrade transaction actually completing — see this module's own
    /// doc comment on why there's no real transactional rollback.
    pub fn open(
        &mut self,
        origin: &str,
        db_name: &str,
        requested_version: Option<u64>,
    ) -> OpenOutcome {
        let dbs = self.origins.entry(origin.to_string()).or_default();
        let is_new = !dbs.contains_key(db_name);
        let db = dbs.entry(db_name.to_string()).or_default();
        let old_version = db.version;
        let new_version = requested_version.unwrap_or(old_version.max(1));
        let needs_upgrade = is_new || new_version > old_version;
        if needs_upgrade {
            db.version = new_version;
            self.version += 1;
        }
        OpenOutcome {
            old_version,
            new_version,
            needs_upgrade,
        }
    }

    pub fn database_version(&self, origin: &str, db_name: &str) -> u64 {
        self.origins
            .get(origin)
            .and_then(|dbs| dbs.get(db_name))
            .map_or(0, |db| db.version)
    }

    pub fn create_object_store(
        &mut self,
        origin: &str,
        db_name: &str,
        store_name: &str,
        key_path: Option<String>,
        auto_increment: bool,
    ) -> Result<(), IdbError> {
        let db = self
            .origins
            .get_mut(origin)
            .and_then(|dbs| dbs.get_mut(db_name))
            .ok_or(IdbError::NotFound)?;
        if db.object_stores.contains_key(store_name) {
            return Err(IdbError::ConstraintError);
        }
        db.object_stores.insert(
            store_name.to_string(),
            ObjectStore {
                key_path,
                auto_increment,
                next_auto_key: 1,
                entries: HashMap::new(),
                order: Vec::new(),
            },
        );
        db.store_order.push(store_name.to_string());
        self.version += 1;
        Ok(())
    }

    pub fn delete_object_store(
        &mut self,
        origin: &str,
        db_name: &str,
        store_name: &str,
    ) -> Result<(), IdbError> {
        let db = self
            .origins
            .get_mut(origin)
            .and_then(|dbs| dbs.get_mut(db_name))
            .ok_or(IdbError::NotFound)?;
        if db.object_stores.remove(store_name).is_none() {
            return Err(IdbError::NotFound);
        }
        db.store_order.retain(|s| s != store_name);
        self.version += 1;
        Ok(())
    }

    pub fn object_store_names(&self, origin: &str, db_name: &str) -> Vec<String> {
        self.origins
            .get(origin)
            .and_then(|dbs| dbs.get(db_name))
            .map(|db| db.store_order.clone())
            .unwrap_or_default()
    }

    /// Real `put`/`add` key resolution, in the real spec's own order:
    /// a keyed (`key_path` set) store derives the key from the record
    /// itself (auto-incrementing and writing it back if missing and
    /// `auto_increment` is set) and REJECTS an explicit key argument
    /// outright; a key-less store requires an explicit key unless
    /// `auto_increment` supplies one. `is_add` additionally rejects
    /// overwriting an existing key (real `add()` vs `put()`).
    pub fn put(
        &mut self,
        origin: &str,
        db_name: &str,
        store_name: &str,
        mut value: Value,
        explicit_key: Option<Value>,
        is_add: bool,
    ) -> Result<Value, IdbError> {
        let db = self
            .origins
            .get_mut(origin)
            .and_then(|dbs| dbs.get_mut(db_name))
            .ok_or(IdbError::NotFound)?;
        let store = db
            .object_stores
            .get_mut(store_name)
            .ok_or(IdbError::NotFound)?;

        let key: Value = if let Some(path) = store.key_path.clone() {
            if explicit_key.is_some() {
                return Err(IdbError::ConstraintError);
            }
            match extract_key_path(&value, &path).cloned() {
                Some(k) => k,
                None if store.auto_increment => {
                    let k = Value::from(store.next_auto_key);
                    store.next_auto_key += 1;
                    set_key_path(&mut value, &path, k.clone());
                    k
                }
                None => return Err(IdbError::ConstraintError),
            }
        } else if let Some(k) = explicit_key {
            k
        } else if store.auto_increment {
            let k = Value::from(store.next_auto_key);
            store.next_auto_key += 1;
            k
        } else {
            return Err(IdbError::ConstraintError);
        };

        let canonical = canonical_key_string(&key).ok_or(IdbError::ConstraintError)?;
        if is_add && store.entries.contains_key(&canonical) {
            return Err(IdbError::ConstraintError);
        }
        let previous_bytes = store
            .entries
            .get(&canonical)
            .map(|(k, v)| approx_json_bytes(k) + approx_json_bytes(v))
            .unwrap_or(0);
        let new_bytes = approx_json_bytes(&key) + approx_json_bytes(&value);
        if store.total_bytes() - previous_bytes + new_bytes > MAX_BYTES_PER_ORIGIN {
            return Err(IdbError::QuotaExceeded);
        }
        if !store.entries.contains_key(&canonical) {
            store.order.push(canonical.clone());
        }
        store.entries.insert(canonical, (key.clone(), value));
        self.version += 1;
        Ok(key)
    }

    pub fn get(
        &self,
        origin: &str,
        db_name: &str,
        store_name: &str,
        key: &Value,
    ) -> Result<Option<Value>, IdbError> {
        let store = self.find_store(origin, db_name, store_name)?;
        let canonical = canonical_key_string(key).ok_or(IdbError::ConstraintError)?;
        Ok(store.entries.get(&canonical).map(|(_, v)| v.clone()))
    }

    pub fn get_all(
        &self,
        origin: &str,
        db_name: &str,
        store_name: &str,
    ) -> Result<Vec<Value>, IdbError> {
        let store = self.find_store(origin, db_name, store_name)?;
        Ok(store
            .order
            .iter()
            .filter_map(|k| store.entries.get(k))
            .map(|(_, v)| v.clone())
            .collect())
    }

    pub fn get_all_keys(
        &self,
        origin: &str,
        db_name: &str,
        store_name: &str,
    ) -> Result<Vec<Value>, IdbError> {
        let store = self.find_store(origin, db_name, store_name)?;
        Ok(store
            .order
            .iter()
            .filter_map(|k| store.entries.get(k))
            .map(|(k, _)| k.clone())
            .collect())
    }

    pub fn delete(
        &mut self,
        origin: &str,
        db_name: &str,
        store_name: &str,
        key: &Value,
    ) -> Result<(), IdbError> {
        let store = self.find_store_mut(origin, db_name, store_name)?;
        let canonical = canonical_key_string(key).ok_or(IdbError::ConstraintError)?;
        if store.entries.remove(&canonical).is_some() {
            store.order.retain(|k| k != &canonical);
            self.version += 1;
        }
        Ok(())
    }

    pub fn clear(&mut self, origin: &str, db_name: &str, store_name: &str) -> Result<(), IdbError> {
        let store = self.find_store_mut(origin, db_name, store_name)?;
        if !store.entries.is_empty() {
            store.entries.clear();
            store.order.clear();
            self.version += 1;
        }
        Ok(())
    }

    pub fn count(&self, origin: &str, db_name: &str, store_name: &str) -> Result<usize, IdbError> {
        Ok(self.find_store(origin, db_name, store_name)?.entries.len())
    }

    /// Real `indexedDB.deleteDatabase(name)` — a no-op (not an error)
    /// if it didn't exist, matching real behavior.
    pub fn delete_database(&mut self, origin: &str, db_name: &str) {
        if let Some(dbs) = self.origins.get_mut(origin) {
            if dbs.remove(db_name).is_some() {
                self.version += 1;
            }
        }
    }

    fn find_store(
        &self,
        origin: &str,
        db_name: &str,
        store_name: &str,
    ) -> Result<&ObjectStore, IdbError> {
        self.origins
            .get(origin)
            .and_then(|dbs| dbs.get(db_name))
            .and_then(|db| db.object_stores.get(store_name))
            .ok_or(IdbError::NotFound)
    }

    fn find_store_mut(
        &mut self,
        origin: &str,
        db_name: &str,
        store_name: &str,
    ) -> Result<&mut ObjectStore, IdbError> {
        self.origins
            .get_mut(origin)
            .and_then(|dbs| dbs.get_mut(db_name))
            .and_then(|db| db.object_stores.get_mut(store_name))
            .ok_or(IdbError::NotFound)
    }

    /// Real JSON serialization, hand-built the same way
    /// `local_storage::LocalStorageStore::to_bytes` is (see its own
    /// doc comment for why: no plain `serde` dependency, just
    /// `serde_json`) — one object per origin, each holding one object
    /// per database, each holding one object per object store.
    pub fn to_bytes(&self) -> Vec<u8> {
        let origins: Vec<Value> = self
            .origins
            .iter()
            .map(|(origin, dbs)| {
                let databases: Vec<Value> = dbs
                    .iter()
                    .map(|(db_name, db)| {
                        let stores: Vec<Value> = db
                            .store_order
                            .iter()
                            .filter_map(|name| db.object_stores.get(name).map(|s| (name, s)))
                            .map(|(name, store)| {
                                let entries: Vec<Value> = store
                                    .order
                                    .iter()
                                    .filter_map(|k| store.entries.get(k))
                                    .map(|(k, v)| serde_json::json!({"key": k, "value": v}))
                                    .collect();
                                serde_json::json!({
                                    "name": name,
                                    "keyPath": store.key_path,
                                    "autoIncrement": store.auto_increment,
                                    "nextAutoKey": store.next_auto_key,
                                    "entries": entries,
                                })
                            })
                            .collect();
                        serde_json::json!({
                            "name": db_name,
                            "version": db.version,
                            "stores": stores,
                        })
                    })
                    .collect();
                serde_json::json!({
                    "origin": origin,
                    "databases": databases,
                })
            })
            .collect();
        serde_json::to_vec(&origins).unwrap_or_default()
    }

    /// The `to_bytes` inverse — a malformed entry anywhere is skipped
    /// rather than failing the whole load, same philosophy as
    /// `local_storage::LocalStorageStore::from_bytes`.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let parsed: Vec<Value> = serde_json::from_slice(bytes).ok()?;
        let mut origins = HashMap::new();
        for origin_entry in &parsed {
            let (Some(origin), Some(databases)) = (
                origin_entry.get("origin").and_then(|v| v.as_str()),
                origin_entry.get("databases").and_then(|v| v.as_array()),
            ) else {
                continue;
            };
            let mut dbs = HashMap::new();
            for db_entry in databases {
                let (Some(name), Some(version), Some(stores)) = (
                    db_entry.get("name").and_then(|v| v.as_str()),
                    db_entry.get("version").and_then(|v| v.as_u64()),
                    db_entry.get("stores").and_then(|v| v.as_array()),
                ) else {
                    continue;
                };
                let mut object_stores = HashMap::new();
                let mut store_order = Vec::new();
                for store_entry in stores {
                    let Some(store_name) = store_entry.get("name").and_then(|v| v.as_str()) else {
                        continue;
                    };
                    let key_path = store_entry
                        .get("keyPath")
                        .and_then(|v| v.as_str())
                        .map(str::to_string);
                    let auto_increment = store_entry
                        .get("autoIncrement")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let next_auto_key = store_entry
                        .get("nextAutoKey")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(1);
                    let mut entries = HashMap::new();
                    let mut order = Vec::new();
                    if let Some(entry_list) = store_entry.get("entries").and_then(|v| v.as_array())
                    {
                        for entry in entry_list {
                            let (Some(key), Some(value)) = (entry.get("key"), entry.get("value"))
                            else {
                                continue;
                            };
                            let Some(canonical) = canonical_key_string(key) else {
                                continue;
                            };
                            entries.insert(canonical.clone(), (key.clone(), value.clone()));
                            order.push(canonical);
                        }
                    }
                    object_stores.insert(
                        store_name.to_string(),
                        ObjectStore {
                            key_path,
                            auto_increment,
                            next_auto_key,
                            entries,
                            order,
                        },
                    );
                    store_order.push(store_name.to_string());
                }
                dbs.insert(
                    name.to_string(),
                    Database {
                        version,
                        object_stores,
                        store_order,
                    },
                );
            }
            origins.insert(origin.to_string(), dbs);
        }
        Some(IndexedDbStore {
            origins,
            version: 0,
        })
    }

    /// Overwrites, into `on_disk`, every origin THIS store has an
    /// entry for — see `local_storage::LocalStorageStore::merge_into`'s
    /// own doc comment: the same mechanism, for the same reason,
    /// including why `app` can't call this real, typed method directly
    /// and reimplements the same semantics generically over raw JSON
    /// instead (`app::merge_persisted_json`).
    pub fn merge_into(&self, on_disk: &mut Self) {
        for (origin, dbs) in &self.origins {
            on_disk.origins.insert(origin.clone(), dbs.clone());
        }
        on_disk.version += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_a_brand_new_database_needs_an_upgrade_to_version_one() {
        let mut store = IndexedDbStore::default();
        let outcome = store.open("https://example.com", "mydb", None);
        assert!(outcome.needs_upgrade);
        assert_eq!(outcome.old_version, 0);
        assert_eq!(outcome.new_version, 1);
    }

    #[test]
    fn reopening_the_same_version_does_not_need_an_upgrade() {
        let mut store = IndexedDbStore::default();
        store.open("https://example.com", "mydb", Some(3));
        let outcome = store.open("https://example.com", "mydb", Some(3));
        assert!(!outcome.needs_upgrade);
        assert_eq!(outcome.old_version, 3);
        assert_eq!(outcome.new_version, 3);
    }

    #[test]
    fn requesting_a_newer_version_needs_an_upgrade_and_bumps_it() {
        let mut store = IndexedDbStore::default();
        store.open("https://example.com", "mydb", Some(1));
        let outcome = store.open("https://example.com", "mydb", Some(2));
        assert!(outcome.needs_upgrade);
        assert_eq!(outcome.old_version, 1);
        assert_eq!(outcome.new_version, 2);
        assert_eq!(store.database_version("https://example.com", "mydb"), 2);
    }

    #[test]
    fn creating_an_object_store_twice_is_a_constraint_error() {
        let mut store = IndexedDbStore::default();
        store.open("https://example.com", "mydb", None);
        store
            .create_object_store("https://example.com", "mydb", "things", None, false)
            .unwrap();
        let result =
            store.create_object_store("https://example.com", "mydb", "things", None, false);
        assert_eq!(result, Err(IdbError::ConstraintError));
    }

    #[test]
    fn put_and_get_round_trip_with_an_explicit_key() {
        let mut store = IndexedDbStore::default();
        store.open("https://example.com", "mydb", None);
        store
            .create_object_store("https://example.com", "mydb", "things", None, false)
            .unwrap();
        let key = store
            .put(
                "https://example.com",
                "mydb",
                "things",
                serde_json::json!({"a": 1}),
                Some(Value::from("k1")),
                false,
            )
            .unwrap();
        assert_eq!(key, Value::from("k1"));
        assert_eq!(
            store
                .get("https://example.com", "mydb", "things", &Value::from("k1"))
                .unwrap(),
            Some(serde_json::json!({"a": 1}))
        );
    }

    #[test]
    fn put_with_no_key_and_no_auto_increment_and_no_key_path_is_a_constraint_error() {
        let mut store = IndexedDbStore::default();
        store.open("https://example.com", "mydb", None);
        store
            .create_object_store("https://example.com", "mydb", "things", None, false)
            .unwrap();
        let result = store.put(
            "https://example.com",
            "mydb",
            "things",
            serde_json::json!({"a": 1}),
            None,
            false,
        );
        assert_eq!(result, Err(IdbError::ConstraintError));
    }

    #[test]
    fn auto_increment_assigns_sequential_keys_with_no_key_path() {
        let mut store = IndexedDbStore::default();
        store.open("https://example.com", "mydb", None);
        store
            .create_object_store("https://example.com", "mydb", "things", None, true)
            .unwrap();
        let k1 = store
            .put(
                "https://example.com",
                "mydb",
                "things",
                serde_json::json!("first"),
                None,
                false,
            )
            .unwrap();
        let k2 = store
            .put(
                "https://example.com",
                "mydb",
                "things",
                serde_json::json!("second"),
                None,
                false,
            )
            .unwrap();
        assert_eq!(k1, Value::from(1));
        assert_eq!(k2, Value::from(2));
    }

    #[test]
    fn auto_increment_with_a_key_path_writes_the_generated_key_back_into_the_record() {
        let mut store = IndexedDbStore::default();
        store.open("https://example.com", "mydb", None);
        store
            .create_object_store(
                "https://example.com",
                "mydb",
                "things",
                Some("id".to_string()),
                true,
            )
            .unwrap();
        let key = store
            .put(
                "https://example.com",
                "mydb",
                "things",
                serde_json::json!({"name": "widget"}),
                None,
                false,
            )
            .unwrap();
        assert_eq!(key, Value::from(1));
        let stored = store
            .get("https://example.com", "mydb", "things", &Value::from(1))
            .unwrap()
            .unwrap();
        assert_eq!(stored, serde_json::json!({"name": "widget", "id": 1}));
    }

    #[test]
    fn a_key_path_store_rejects_an_explicit_key() {
        let mut store = IndexedDbStore::default();
        store.open("https://example.com", "mydb", None);
        store
            .create_object_store(
                "https://example.com",
                "mydb",
                "things",
                Some("id".to_string()),
                false,
            )
            .unwrap();
        let result = store.put(
            "https://example.com",
            "mydb",
            "things",
            serde_json::json!({"id": 5}),
            Some(Value::from(5)),
            false,
        );
        assert_eq!(result, Err(IdbError::ConstraintError));
    }

    #[test]
    fn add_on_an_existing_key_is_a_constraint_error_but_put_overwrites() {
        let mut store = IndexedDbStore::default();
        store.open("https://example.com", "mydb", None);
        store
            .create_object_store("https://example.com", "mydb", "things", None, false)
            .unwrap();
        store
            .put(
                "https://example.com",
                "mydb",
                "things",
                serde_json::json!("v1"),
                Some(Value::from("k")),
                false,
            )
            .unwrap();
        let add_result = store.put(
            "https://example.com",
            "mydb",
            "things",
            serde_json::json!("v2"),
            Some(Value::from("k")),
            true,
        );
        assert_eq!(add_result, Err(IdbError::ConstraintError));
        store
            .put(
                "https://example.com",
                "mydb",
                "things",
                serde_json::json!("v3"),
                Some(Value::from("k")),
                false,
            )
            .unwrap();
        assert_eq!(
            store
                .get("https://example.com", "mydb", "things", &Value::from("k"))
                .unwrap(),
            Some(serde_json::json!("v3"))
        );
    }

    #[test]
    fn delete_removes_a_key_and_clear_empties_the_store() {
        let mut store = IndexedDbStore::default();
        store.open("https://example.com", "mydb", None);
        store
            .create_object_store("https://example.com", "mydb", "things", None, false)
            .unwrap();
        store
            .put(
                "https://example.com",
                "mydb",
                "things",
                serde_json::json!("v1"),
                Some(Value::from("a")),
                false,
            )
            .unwrap();
        store
            .put(
                "https://example.com",
                "mydb",
                "things",
                serde_json::json!("v2"),
                Some(Value::from("b")),
                false,
            )
            .unwrap();
        store
            .delete("https://example.com", "mydb", "things", &Value::from("a"))
            .unwrap();
        assert_eq!(
            store
                .get("https://example.com", "mydb", "things", &Value::from("a"))
                .unwrap(),
            None
        );
        assert_eq!(
            store
                .count("https://example.com", "mydb", "things")
                .unwrap(),
            1
        );
        store
            .clear("https://example.com", "mydb", "things")
            .unwrap();
        assert_eq!(
            store
                .count("https://example.com", "mydb", "things")
                .unwrap(),
            0
        );
    }

    #[test]
    fn get_all_and_get_all_keys_reflect_real_insertion_order() {
        let mut store = IndexedDbStore::default();
        store.open("https://example.com", "mydb", None);
        store
            .create_object_store("https://example.com", "mydb", "things", None, false)
            .unwrap();
        store
            .put(
                "https://example.com",
                "mydb",
                "things",
                serde_json::json!("first"),
                Some(Value::from("a")),
                false,
            )
            .unwrap();
        store
            .put(
                "https://example.com",
                "mydb",
                "things",
                serde_json::json!("second"),
                Some(Value::from("b")),
                false,
            )
            .unwrap();
        assert_eq!(
            store
                .get_all("https://example.com", "mydb", "things")
                .unwrap(),
            vec![serde_json::json!("first"), serde_json::json!("second")]
        );
        assert_eq!(
            store
                .get_all_keys("https://example.com", "mydb", "things")
                .unwrap(),
            vec![Value::from("a"), Value::from("b")]
        );
    }

    #[test]
    fn different_origins_never_see_each_others_databases() {
        let mut store = IndexedDbStore::default();
        store.open("https://a.example", "db", None);
        store
            .create_object_store("https://a.example", "db", "s", None, true)
            .unwrap();
        store
            .put(
                "https://a.example",
                "db",
                "s",
                serde_json::json!("v"),
                None,
                false,
            )
            .unwrap();
        let result = store.get("https://b.example", "db", "s", &Value::from(1));
        assert_eq!(result, Err(IdbError::NotFound));
    }

    #[test]
    fn writing_past_the_quota_is_rejected_and_does_not_change_anything() {
        let mut store = IndexedDbStore::default();
        store.open("https://example.com", "mydb", None);
        store
            .create_object_store("https://example.com", "mydb", "things", None, false)
            .unwrap();
        let big_value = Value::from("x".repeat(MAX_BYTES_PER_ORIGIN + 1));
        let result = store.put(
            "https://example.com",
            "mydb",
            "things",
            big_value,
            Some(Value::from("k")),
            false,
        );
        assert_eq!(result, Err(IdbError::QuotaExceeded));
        assert_eq!(
            store
                .get("https://example.com", "mydb", "things", &Value::from("k"))
                .unwrap(),
            None
        );
    }

    #[test]
    fn delete_database_removes_it_and_is_a_no_op_if_missing() {
        let mut store = IndexedDbStore::default();
        store.open("https://example.com", "mydb", None);
        store.delete_database("https://example.com", "mydb");
        assert_eq!(store.database_version("https://example.com", "mydb"), 0);
        // No panic on a second, no-op delete of an already-missing db.
        store.delete_database("https://example.com", "mydb");
    }

    #[test]
    fn store_round_trips_through_bytes_including_key_order_and_key_path() {
        let mut store = IndexedDbStore::default();
        store.open("https://example.com", "mydb", Some(2));
        store
            .create_object_store(
                "https://example.com",
                "mydb",
                "things",
                Some("id".to_string()),
                true,
            )
            .unwrap();
        store
            .put(
                "https://example.com",
                "mydb",
                "things",
                serde_json::json!({"name": "a"}),
                None,
                false,
            )
            .unwrap();
        store
            .put(
                "https://example.com",
                "mydb",
                "things",
                serde_json::json!({"name": "b"}),
                None,
                false,
            )
            .unwrap();

        let restored = IndexedDbStore::from_bytes(&store.to_bytes()).unwrap();
        assert_eq!(restored.database_version("https://example.com", "mydb"), 2);
        assert_eq!(
            restored.object_store_names("https://example.com", "mydb"),
            vec!["things".to_string()]
        );
        assert_eq!(
            restored
                .get_all("https://example.com", "mydb", "things")
                .unwrap(),
            vec![
                serde_json::json!({"name": "a", "id": 1}),
                serde_json::json!({"name": "b", "id": 2}),
            ]
        );
        // A subsequent `put` continues the auto-increment counter
        // rather than resetting it — proves `next_auto_key` itself
        // round-tripped, not just the stored records.
        let mut restored = restored;
        let key = restored
            .put(
                "https://example.com",
                "mydb",
                "things",
                serde_json::json!({"name": "c"}),
                None,
                false,
            )
            .unwrap();
        assert_eq!(key, Value::from(3));
    }

    #[test]
    fn from_bytes_is_none_for_garbage() {
        assert!(IndexedDbStore::from_bytes(b"not json at all").is_none());
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
        let mut on_disk = IndexedDbStore::default();
        on_disk.open("https://siteA.com", "db", None);
        on_disk
            .create_object_store("https://siteA.com", "db", "s", None, true)
            .unwrap();
        on_disk
            .put(
                "https://siteA.com",
                "db",
                "s",
                serde_json::json!("a-value"),
                None,
                false,
            )
            .unwrap();

        let mut store_b = IndexedDbStore::default();
        store_b.open("https://siteB.com", "db", None);
        store_b
            .create_object_store("https://siteB.com", "db", "s", None, true)
            .unwrap();
        store_b
            .put(
                "https://siteB.com",
                "db",
                "s",
                serde_json::json!("b-value"),
                None,
                false,
            )
            .unwrap();
        store_b.merge_into(&mut on_disk);

        assert_eq!(
            on_disk.get_all("https://siteA.com", "db", "s").unwrap(),
            vec![serde_json::json!("a-value")]
        );
        assert_eq!(
            on_disk.get_all("https://siteB.com", "db", "s").unwrap(),
            vec![serde_json::json!("b-value")]
        );
    }
}
