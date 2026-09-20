//! `sync` — pushes/pulls the encrypted blob produced by `account`.
//!
//! Deliberate design constraint: this crate's types only ever hold
//! `Vec<u8>` ciphertext plus an `account_id` string — never a
//! `storage::SyncPayload`, never an `account::Account` secret. That's
//! not an accident of what's implemented yet; it's the boundary that
//! makes zero-knowledge sync true. `app` is the layer that knows how
//! to go `SyncPayload -> bytes -> encrypt -> push`, and this crate
//! never needs to change to keep that property.
//!
//! Scope of this stub:
//!   - `FakeSyncServer`: in-memory, single-process stand-in for a
//!     real sync server. Good enough to unit-test push/pull and
//!     conflict handling without any actual networking. Data is lost
//!     on restart — see `FileSyncServer` for the persistent version
//!     `sync-server` actually runs.
//!   - `FileSyncServer`: same push/pull/conflict semantics as
//!     `FakeSyncServer`, but each account's blob is written to its own
//!     file on disk (one `fs::write` + atomic rename per push) instead
//!     of living only in a `HashMap` — a process restart no longer
//!     loses every account's data, which was the actual ship-blocker
//!     `FakeSyncServer` alone represented. It also keeps rotating
//!     local backups of the versions it overwrites (see its own doc
//!     comment) — real replication is unnecessary at personal-use,
//!     single-instance scale, but "a bad push clobbers your only
//!     copy" was a real, easy-to-hit gap.
//!   - Conflict detection: an opaque version counter, checked here.
//!     This crate can never do the actual MERGING itself — it only
//!     ever holds ciphertext, so it has no way to combine two devices'
//!     changes. What it can and does do is refuse a stale push
//!     (`SyncError::Conflict`) instead of silently letting it clobber
//!     newer data, which is what gives the caller a chance to merge
//!     before retrying. `app` is that caller: on `Conflict`, it pulls
//!     the current blob, decrypts both sides, calls
//!     `storage::SyncPayload::merge` (see that crate's own docs), and
//!     retries the push with the merged result — see `app`'s
//!     `sync_push` for the actual retry loop.
//!
//! Next steps, roughly in order of payoff:
//!   1. Multi-device conflict UI: surface "this device's local changes
//!      were merged with a newer sync" (or, before the merge existed,
//!      "...were overwritten by one") so it's visible rather than
//!      silent either way.
//!   2. `FileSyncServer` re-hashes nothing incrementally and holds no
//!      in-memory cache — every push/pull does a fresh disk read. Fine
//!      at demo scale; worth an in-memory index (account_id -> version)
//!      once request volume matters.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum SyncError {
    AccountNotFound(String),
    Unauthorized(String),
    Conflict { server_version: u64 },
    Transport(String),
}

#[derive(Debug, Clone)]
pub struct Blob {
    pub ciphertext: Vec<u8>,
    pub version: u64,
}

pub trait SyncTransport {
    fn push(
        &mut self,
        account_id: &str,
        auth_secret: &[u8; 32],
        ciphertext: Vec<u8>,
        expected_version: u64,
    ) -> Result<u64, SyncError>;
    fn pull(&self, account_id: &str, auth_secret: &[u8; 32]) -> Result<Blob, SyncError>;
}

struct StoredBlob {
    ciphertext: Vec<u8>,
    version: u64,
    auth_secret_hash: [u8; 32],
}

fn hash_auth_secret(secret: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(secret);
    hasher.finalize().into()
}

#[derive(Default)]
pub struct FakeSyncServer {
    blobs: HashMap<String, StoredBlob>,
}

impl FakeSyncServer {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SyncTransport for FakeSyncServer {
    fn push(
        &mut self,
        account_id: &str,
        auth_secret: &[u8; 32],
        ciphertext: Vec<u8>,
        expected_version: u64,
    ) -> Result<u64, SyncError> {
        let incoming_hash = hash_auth_secret(auth_secret);
        if let Some(existing) = self.blobs.get(account_id) {
            if existing.auth_secret_hash != incoming_hash {
                return Err(SyncError::Unauthorized(account_id.to_string()));
            }
        }
        let current_version = self.blobs.get(account_id).map(|b| b.version).unwrap_or(0);
        if expected_version != current_version {
            return Err(SyncError::Conflict {
                server_version: current_version,
            });
        }
        let new_version = current_version + 1;
        self.blobs.insert(
            account_id.to_string(),
            StoredBlob {
                ciphertext,
                version: new_version,
                auth_secret_hash: incoming_hash,
            },
        );
        Ok(new_version)
    }

    fn pull(&self, account_id: &str, auth_secret: &[u8; 32]) -> Result<Blob, SyncError> {
        let stored = self
            .blobs
            .get(account_id)
            .ok_or_else(|| SyncError::AccountNotFound(account_id.to_string()))?;
        if stored.auth_secret_hash != hash_auth_secret(auth_secret) {
            return Err(SyncError::Unauthorized(account_id.to_string()));
        }
        Ok(Blob {
            ciphertext: stored.ciphertext.clone(),
            version: stored.version,
        })
    }
}

/// Persistent, file-backed `SyncTransport`: one file per account under
/// `data_dir`, each holding that account's version, auth-secret hash,
/// and ciphertext. This is what makes a restart survivable — the
/// actual gap `FakeSyncServer` alone left open (see module docs).
///
/// Not a database: every `push`/`pull` does a fresh read/write of that
/// one account's file, with no in-memory cache and no write-ahead log.
/// That's fine at the request volumes a real deployment of this
/// project would see for a while, and it means there's no in-memory
/// state to lose or get out of sync with disk in the first place.
///
/// Every `push` also snapshots the version it's about to overwrite
/// into `data_dir/backups/<account hash>/<version>.blob` before
/// writing the new one, keeping the most recent `backup_retention`
/// versions (oldest pruned first). This is what actually answers "no
/// backup/replication story for `data_dir`" for a single-instance,
/// personal-use deployment: real multi-node replication is overkill
/// when there's one operator and one server, but a bad push (a bug,
/// a corrupted client-side merge) silently overwriting the only copy
/// of your data is a real risk that rotating point-in-time snapshots
/// on the SAME disk directly address. It does not protect against
/// losing the whole disk — that still needs an off-box copy of
/// `data_dir`, which is an operational step outside this crate.
/// `restore_backup` brings a specific version back to being live;
/// `sync-server --restore <account_id> <version>` is the operator-
/// facing entry point (see that binary's own docs).
pub struct FileSyncServer {
    data_dir: PathBuf,
    backup_retention: usize,
}

/// How many prior versions `FileSyncServer::open` keeps per account by
/// default. Arbitrary but generous for a personal-use deployment: each
/// backup is one full copy of that account's (already-small) encrypted
/// blob, so 10 versions costs little disk and covers "I noticed the
/// corruption a few syncs too late."
const DEFAULT_BACKUP_RETENTION: usize = 10;

impl FileSyncServer {
    /// Opens (creating if necessary) a file-backed store rooted at
    /// `data_dir`, keeping `DEFAULT_BACKUP_RETENTION` backups per
    /// account. Fails only if the directory can't be created (e.g.
    /// permissions) — there's no other setup step.
    pub fn open(data_dir: impl AsRef<Path>) -> std::io::Result<Self> {
        Self::open_with_retention(data_dir, DEFAULT_BACKUP_RETENTION)
    }

    /// Same as `open`, but with an explicit backup-retention count
    /// instead of `DEFAULT_BACKUP_RETENTION` — what `sync-server`'s
    /// `ABYSSAL_SYNC_BACKUP_RETENTION` env var maps to, and what tests
    /// use to exercise pruning without pushing ten-plus times.
    pub fn open_with_retention(
        data_dir: impl AsRef<Path>,
        backup_retention: usize,
    ) -> std::io::Result<Self> {
        let data_dir = data_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&data_dir)?;
        Ok(FileSyncServer {
            data_dir,
            backup_retention,
        })
    }

    /// Hashes an account_id for use in a filename/directory name.
    /// Shared by `path_for` and `backups_dir_for` so a live blob and
    /// its backups land under the same identifier. Hashing first
    /// (rather than using account_id directly) means account_id can
    /// never be used for a path-traversal attack (a hostile
    /// account_id like `../../etc/passwd` just hashes to some hex
    /// string, same as any other input), and the on-disk layout never
    /// needs to worry about characters that are valid in an
    /// account_id but not in a filename.
    fn account_hash(account_id: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(account_id.as_bytes());
        hex_encode(&hasher.finalize())
    }

    fn path_for(&self, account_id: &str) -> PathBuf {
        self.data_dir
            .join(format!("{}.blob", Self::account_hash(account_id)))
    }

    fn backups_dir_for(&self, account_id: &str) -> PathBuf {
        self.data_dir
            .join("backups")
            .join(Self::account_hash(account_id))
    }

    /// Snapshots whatever is currently live at `path` (if anything) into
    /// this account's backup directory, tagged by the version it held,
    /// then prunes down to `backup_retention` — called from
    /// `write_blob` right before it overwrites `path` with the new
    /// version, so the version being superseded is never lost.
    /// A missing or unreadably-short file (first push ever for this
    /// account, or a previously-corrupt blob) is a no-op, not an error.
    fn backup_current_blob(&self, account_id: &str, path: &Path) -> std::io::Result<()> {
        if !path.exists() {
            return Ok(());
        }
        let existing = std::fs::read(path)?;
        if existing.len() < 8 {
            return Ok(());
        }
        let version = u64::from_le_bytes(
            existing[0..8]
                .try_into()
                .expect("checked existing.len() >= 8 above"),
        );
        let backups_dir = self.backups_dir_for(account_id);
        std::fs::create_dir_all(&backups_dir)?;
        std::fs::write(backups_dir.join(format!("{version}.blob")), &existing)?;
        self.prune_backups(&backups_dir)
    }

    /// Keeps only the `backup_retention` highest-numbered backup files
    /// in `backups_dir`, deleting the rest (oldest versions first).
    fn prune_backups(&self, backups_dir: &Path) -> std::io::Result<()> {
        let mut versions: Vec<u64> = std::fs::read_dir(backups_dir)?
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| {
                entry
                    .path()
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .and_then(|s| s.parse::<u64>().ok())
            })
            .collect();
        versions.sort_unstable();
        if versions.len() > self.backup_retention {
            for old_version in &versions[..versions.len() - self.backup_retention] {
                let _ = std::fs::remove_file(backups_dir.join(format!("{old_version}.blob")));
            }
        }
        Ok(())
    }

    /// Lists the versions of `account_id` currently retained as
    /// backups, oldest first. An empty result means either no backups
    /// have been made yet (only ever one push) or the account doesn't
    /// exist.
    pub fn list_backup_versions(&self, account_id: &str) -> std::io::Result<Vec<u64>> {
        let backups_dir = self.backups_dir_for(account_id);
        if !backups_dir.exists() {
            return Ok(Vec::new());
        }
        let mut versions: Vec<u64> = std::fs::read_dir(&backups_dir)?
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| {
                entry
                    .path()
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .and_then(|s| s.parse::<u64>().ok())
            })
            .collect();
        versions.sort_unstable();
        Ok(versions)
    }

    /// Restores `account_id`'s live blob to a previously-backed-up
    /// `version`, overwriting whatever is currently live. This is a
    /// deliberate out-of-band recovery operation — there's no HTTP
    /// route for it in `sync-server`, only the `--restore` CLI flag an
    /// operator runs by hand against the data directory. A client
    /// pulling afterward just sees that version's contents, as if the
    /// pushes since then never happened.
    pub fn restore_backup(&self, account_id: &str, version: u64) -> std::io::Result<()> {
        let backup_path = self
            .backups_dir_for(account_id)
            .join(format!("{version}.blob"));
        let contents = std::fs::read(&backup_path)?;
        let live_path = self.path_for(account_id);
        let tmp_path = self.data_dir.join(format!(
            "{}.tmp",
            live_path.file_name().unwrap().to_string_lossy()
        ));
        std::fs::write(&tmp_path, &contents)?;
        std::fs::rename(&tmp_path, &live_path)
    }

    /// On-disk layout, all in one flat file: 8 bytes little-endian
    /// version, then 32 bytes of `auth_secret_hash`, then the raw
    /// ciphertext to EOF. No serde/JSON — the shape never changes and
    /// never needs to be read by anything other than this same code.
    fn read_blob(&self, account_id: &str) -> Option<StoredBlob> {
        let bytes = std::fs::read(self.path_for(account_id)).ok()?;
        if bytes.len() < 40 {
            return None; // truncated/corrupt — treat like "no account" rather than panicking
        }
        let version = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
        let mut auth_secret_hash = [0u8; 32];
        auth_secret_hash.copy_from_slice(&bytes[8..40]);
        let ciphertext = bytes[40..].to_vec();
        Some(StoredBlob {
            ciphertext,
            version,
            auth_secret_hash,
        })
    }

    /// Writes via a temp file + rename rather than a direct
    /// `fs::write`, so a crash or power loss mid-write can never leave
    /// behind a half-written, corrupt blob in the real file's place —
    /// `rename` within the same directory is atomic on the filesystems
    /// this targets (ext4, btrfs, APFS, NTFS).
    fn write_blob(&self, account_id: &str, blob: &StoredBlob) -> std::io::Result<()> {
        let path = self.path_for(account_id);
        self.backup_current_blob(account_id, &path)?;
        let tmp_path = self.data_dir.join(format!(
            "{}.tmp",
            path.file_name().unwrap().to_string_lossy()
        ));
        let mut contents = Vec::with_capacity(40 + blob.ciphertext.len());
        contents.extend_from_slice(&blob.version.to_le_bytes());
        contents.extend_from_slice(&blob.auth_secret_hash);
        contents.extend_from_slice(&blob.ciphertext);
        std::fs::write(&tmp_path, &contents)?;
        std::fs::rename(&tmp_path, &path)
    }
}

impl SyncTransport for FileSyncServer {
    fn push(
        &mut self,
        account_id: &str,
        auth_secret: &[u8; 32],
        ciphertext: Vec<u8>,
        expected_version: u64,
    ) -> Result<u64, SyncError> {
        let incoming_hash = hash_auth_secret(auth_secret);
        let existing = self.read_blob(account_id);
        if let Some(existing) = &existing {
            if existing.auth_secret_hash != incoming_hash {
                return Err(SyncError::Unauthorized(account_id.to_string()));
            }
        }
        let current_version = existing.map(|b| b.version).unwrap_or(0);
        if expected_version != current_version {
            return Err(SyncError::Conflict {
                server_version: current_version,
            });
        }
        let new_version = current_version + 1;
        let stored = StoredBlob {
            ciphertext,
            version: new_version,
            auth_secret_hash: incoming_hash,
        };
        self.write_blob(account_id, &stored)
            .map_err(|e| SyncError::Transport(format!("failed to persist blob: {e}")))?;
        Ok(new_version)
    }

    fn pull(&self, account_id: &str, auth_secret: &[u8; 32]) -> Result<Blob, SyncError> {
        let stored = self
            .read_blob(account_id)
            .ok_or_else(|| SyncError::AccountNotFound(account_id.to_string()))?;
        if stored.auth_secret_hash != hash_auth_secret(auth_secret) {
            return Err(SyncError::Unauthorized(account_id.to_string()));
        }
        Ok(Blob {
            ciphertext: stored.ciphertext,
            version: stored.version,
        })
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Talks to a real `sync-server` instance over HTTPS. `base_url`
/// should be `https://your-host` in production — the auth secret and
/// ciphertext both travel in this request, so it must be TLS, not
/// plain HTTP (localhost dev against `sync-server` is the one
/// exception in practice).
pub struct HttpSyncClient {
    base_url: String,
    client: reqwest::blocking::Client,
}

impl HttpSyncClient {
    pub fn new(base_url: &str) -> Self {
        HttpSyncClient {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: reqwest::blocking::Client::new(),
        }
    }
}

impl SyncTransport for HttpSyncClient {
    fn push(
        &mut self,
        account_id: &str,
        auth_secret: &[u8; 32],
        ciphertext: Vec<u8>,
        expected_version: u64,
    ) -> Result<u64, SyncError> {
        let url = format!("{}/accounts/{}", self.base_url, account_id);
        let response = self
            .client
            .put(&url)
            .header(
                "Authorization",
                format!("Bearer {}", hex_encode(auth_secret)),
            )
            .header("X-Expected-Version", expected_version.to_string())
            .body(ciphertext)
            .send()
            .map_err(|e| SyncError::Transport(e.to_string()))?;

        match response.status().as_u16() {
            200 => {
                let body = response
                    .text()
                    .map_err(|e| SyncError::Transport(e.to_string()))?;
                body.trim().parse::<u64>().map_err(|_| {
                    SyncError::Transport(format!("non-numeric version in response body: {body:?}"))
                })
            }
            401 => Err(SyncError::Unauthorized(account_id.to_string())),
            409 => {
                let body = response
                    .text()
                    .map_err(|e| SyncError::Transport(e.to_string()))?;
                let server_version = body.trim().parse::<u64>().map_err(|_| {
                    SyncError::Transport(format!(
                        "non-numeric server_version in response body: {body:?}"
                    ))
                })?;
                Err(SyncError::Conflict { server_version })
            }
            status => Err(SyncError::Transport(format!(
                "unexpected status {status} from sync server"
            ))),
        }
    }

    fn pull(&self, account_id: &str, auth_secret: &[u8; 32]) -> Result<Blob, SyncError> {
        let url = format!("{}/accounts/{}", self.base_url, account_id);
        let response = self
            .client
            .get(&url)
            .header(
                "Authorization",
                format!("Bearer {}", hex_encode(auth_secret)),
            )
            .send()
            .map_err(|e| SyncError::Transport(e.to_string()))?;

        match response.status().as_u16() {
            200 => {
                let version = response
                    .headers()
                    .get("X-Version")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u64>().ok())
                    .ok_or_else(|| {
                        SyncError::Transport("missing or malformed X-Version header".to_string())
                    })?;
                let ciphertext = response
                    .bytes()
                    .map_err(|e| SyncError::Transport(e.to_string()))?
                    .to_vec();
                Ok(Blob {
                    ciphertext,
                    version,
                })
            }
            404 => Err(SyncError::AccountNotFound(account_id.to_string())),
            401 => Err(SyncError::Unauthorized(account_id.to_string())),
            status => Err(SyncError::Transport(format!(
                "unexpected status {status} from sync server"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_then_pull_round_trips_opaque_bytes() {
        let mut server = FakeSyncServer::new();
        let auth = [7u8; 32];
        let ciphertext = vec![1, 2, 3, 4];
        server.push("acct_1", &auth, ciphertext.clone(), 0).unwrap();

        let blob = server.pull("acct_1", &auth).unwrap();
        assert_eq!(blob.ciphertext, ciphertext);
        assert_eq!(blob.version, 1);
    }

    #[test]
    fn stale_push_reports_conflict_instead_of_overwriting() {
        let mut server = FakeSyncServer::new();
        let auth = [7u8; 32];
        server.push("acct_1", &auth, vec![1], 0).unwrap();

        let result = server.push("acct_1", &auth, vec![2], 0);
        assert!(matches!(
            result,
            Err(SyncError::Conflict { server_version: 1 })
        ));
    }

    /// A directory under the OS temp dir, unique per test run (PID +
    /// an incrementing counter), cleaned up when the returned guard
    /// drops — avoids pulling in a `tempfile` dependency just for this.
    struct TempDir(PathBuf);
    impl TempDir {
        fn new(label: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "abyssal-sync-test-{label}-{}-{n}",
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

    #[test]
    fn file_sync_server_round_trips_like_the_fake_one() {
        let dir = TempDir::new("roundtrip");
        let mut server = FileSyncServer::open(&dir.0).unwrap();
        let auth = [7u8; 32];
        let ciphertext = vec![1, 2, 3, 4];
        let version = server.push("acct_1", &auth, ciphertext.clone(), 0).unwrap();
        assert_eq!(version, 1);

        let blob = server.pull("acct_1", &auth).unwrap();
        assert_eq!(blob.ciphertext, ciphertext);
        assert_eq!(blob.version, 1);
    }

    #[test]
    fn file_sync_server_rejects_wrong_auth_secret() {
        let dir = TempDir::new("auth");
        let mut server = FileSyncServer::open(&dir.0).unwrap();
        server.push("acct_1", &[1u8; 32], vec![9], 0).unwrap();

        assert!(matches!(
            server.pull("acct_1", &[2u8; 32]),
            Err(SyncError::Unauthorized(_))
        ));
        assert!(matches!(
            server.push("acct_1", &[2u8; 32], vec![9], 1),
            Err(SyncError::Unauthorized(_))
        ));
    }

    #[test]
    fn file_sync_server_stale_push_reports_conflict() {
        let dir = TempDir::new("conflict");
        let mut server = FileSyncServer::open(&dir.0).unwrap();
        let auth = [7u8; 32];
        server.push("acct_1", &auth, vec![1], 0).unwrap();

        let result = server.push("acct_1", &auth, vec![2], 0);
        assert!(matches!(
            result,
            Err(SyncError::Conflict { server_version: 1 })
        ));
    }

    #[test]
    fn file_sync_server_survives_a_simulated_restart() {
        let dir = TempDir::new("restart");
        let auth = [7u8; 32];
        {
            let mut server = FileSyncServer::open(&dir.0).unwrap();
            server.push("acct_1", &auth, vec![42, 43], 0).unwrap();
        } // `server` dropped — nothing but the files on disk survives this point

        let server = FileSyncServer::open(&dir.0).unwrap();
        let blob = server.pull("acct_1", &auth).unwrap();
        assert_eq!(blob.ciphertext, vec![42, 43]);
        assert_eq!(blob.version, 1);
    }

    #[test]
    fn file_sync_server_pull_of_unknown_account_is_not_found() {
        let dir = TempDir::new("unknown");
        let server = FileSyncServer::open(&dir.0).unwrap();
        assert!(matches!(
            server.pull("no_such_account", &[0u8; 32]),
            Err(SyncError::AccountNotFound(_))
        ));
    }

    #[test]
    fn a_push_backs_up_the_version_it_overwrites() {
        let dir = TempDir::new("backup-basic");
        let mut server = FileSyncServer::open(&dir.0).unwrap();
        let auth = [7u8; 32];

        // No backups yet — nothing existed before this first push.
        server.push("acct_1", &auth, vec![1], 0).unwrap();
        assert_eq!(
            server.list_backup_versions("acct_1").unwrap(),
            Vec::<u64>::new()
        );

        // The second push backs up version 1 (what it's about to replace).
        server.push("acct_1", &auth, vec![2], 1).unwrap();
        assert_eq!(server.list_backup_versions("acct_1").unwrap(), vec![1]);

        server.push("acct_1", &auth, vec![3], 2).unwrap();
        assert_eq!(server.list_backup_versions("acct_1").unwrap(), vec![1, 2]);
    }

    #[test]
    fn backups_are_pruned_beyond_the_configured_retention() {
        let dir = TempDir::new("backup-prune");
        let mut server = FileSyncServer::open_with_retention(&dir.0, 2).unwrap();
        let auth = [7u8; 32];

        for version in 0..5u64 {
            server
                .push("acct_1", &auth, vec![version as u8], version)
                .unwrap();
        }
        // 5 pushes -> versions 1..=5 live in turn, backing up 1,2,3,4
        // along the way; only the newest 2 (3,4) should survive pruning.
        assert_eq!(server.list_backup_versions("acct_1").unwrap(), vec![3, 4]);
    }

    #[test]
    fn restore_backup_brings_an_older_version_back_to_being_live() {
        let dir = TempDir::new("restore");
        let mut server = FileSyncServer::open(&dir.0).unwrap();
        let auth = [7u8; 32];

        server.push("acct_1", &auth, vec![10, 20], 0).unwrap();
        server.push("acct_1", &auth, vec![30, 40], 1).unwrap();
        assert_eq!(
            server.pull("acct_1", &auth).unwrap().ciphertext,
            vec![30, 40]
        );

        server.restore_backup("acct_1", 1).unwrap();

        let restored = server.pull("acct_1", &auth).unwrap();
        assert_eq!(restored.ciphertext, vec![10, 20]);
        assert_eq!(restored.version, 1);
    }

    #[test]
    fn restore_backup_of_a_version_that_was_never_backed_up_fails_rather_than_corrupting_the_live_blob(
    ) {
        let dir = TempDir::new("restore-missing");
        let mut server = FileSyncServer::open(&dir.0).unwrap();
        let auth = [7u8; 32];
        server.push("acct_1", &auth, vec![1], 0).unwrap();

        assert!(server.restore_backup("acct_1", 999).is_err());
        // The live blob must be untouched by the failed restore attempt.
        assert_eq!(server.pull("acct_1", &auth).unwrap().ciphertext, vec![1]);
    }
}
