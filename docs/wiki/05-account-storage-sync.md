# Account, storage, and sync

This file covers four crates that together implement Abyssal's no-email
account model and cross-device sync: `account`, `storage`, `sync`, and the
`sync-server` binary. Read this if you're touching anything about how
bookmarks/history/settings get encrypted, merged across devices, or served.

The one-sentence version of the whole pipeline:

```
storage::SyncPayload --to_bytes()--> plaintext bytes
                                          |
                              account::encrypt(key)   (ChaCha20-Poly1305)
                                          |
                                      ciphertext
                                          |
                          sync::HttpSyncClient::push(account_id, auth_secret, ciphertext, expected_version)
                                          |
                                sync-server (FileSyncServer, one file per account)
```

Every arrow in that chain except the last two hops is code that lives in
`app`, not in any of these four crates. That's deliberate, and it's the
single most important structural fact in this whole file -- see
"The `account`/`sync` boundary, and why `app` is the glue" near the end.

## `account`: the no-email credential and the real crypto

Source: `account/src/lib.rs`, `account/src/bip39.rs`.

### The model

There's no email, no username, no password by default. `account::create_account()`
(no arguments) mints three things, all via the OS CSPRNG (`rand::rngs::OsRng`,
never a userspace PRNG):

- `account_id`: a random token like `acct_<32 hex chars>` -- just an opaque
  handle the sync server uses to address a blob. Doesn't need to be secret,
  only unique.
- `recovery_code`: a 15-word BIP-39 mnemonic phrase. This **is** the actual
  credential -- the only secret that unlocks anything.
- `kdf_salt`: a random 16-byte salt, generated once and then reused forever
  for this account. Not secret either -- it's fine for this to be visible in
  `account.txt` right next to everything else, because a salt's job is to
  make precomputed rainbow-table attacks useless, not to be secret itself.

Why a 15-word phrase instead of, say, a 40-character hex string carrying the
same 160 bits of entropy? Because a hex blob is brutal to transcribe by hand
and gives you zero feedback if you get it wrong -- you'd just have a
different, silently-wrong secret. A BIP-39 mnemonic has a built-in checksum
(see the `bip39` module below) that catches a misspelled or reordered word,
so a bad transcription fails loudly instead of quietly generating garbage.

### Key derivation: two independent secrets from one phrase

`derive_key(secret, salt)` and `derive_auth_secret(secret, salt)` both run
the recovery code (or an optional password layered on top, if that ever
ships) through Argon2id, but they are **domain-separated** -- `derive_auth_secret`
prepends a fixed string (`"abyssal-sync-auth-v1|"`) to the secret before
hashing, so the two outputs are cryptographically unrelated even though they
come from the same input. `derive_key`'s output encrypts your data locally.
`derive_auth_secret`'s output goes to the sync server so it can authenticate
your pushes/pulls.

This split is the whole reason the server can authenticate you without being
able to read your data: if there were only one derived secret, the server
would necessarily see (or be able to compute) the same value that decrypts
your bookmarks. Domain separation means knowing the auth secret gives you
**zero** information toward the encryption key.

Both functions share one `kdf()` builder function, on purpose -- there's
exactly one place in the whole codebase that decides what "the KDF" means,
so the two call sites can never silently drift onto different parameters.

**The actual Argon2id parameters** (`KDF_MEMORY_COST_KIB = 128 * 1024` i.e.
128 MiB, `KDF_TIME_COST = 3`, `KDF_PARALLELISM = 1`) are deliberately chosen,
not left at the crate's generic default (19 MiB / t=2). Two things worth
understanding if you ever touch these:

1. **Parallelism is pinned at 1 on purpose**, not as an oversight. The
   `argon2` crate (RustCrypto's implementation) has no multi-threaded lane
   execution -- every lane runs serially regardless of `p_cost` -- so raising
   parallelism here would only add wall-clock time with zero benefit. All
   the "make this expensive to crack" budget goes into memory cost instead,
   which is the parameter that actually resists GPU/ASIC parallelization
   (more memory per guess is expensive to replicate across many cracking
   units in hardware).
2. **This only ever runs locally**, to protect a stolen ciphertext blob
   against offline brute-forcing. It never runs server-side against
   concurrent users, so there's no capacity cost to being generous. 128 MiB
   / t=3 completes in well under a second on ordinary desktop hardware in a
   **release** build -- a debug build (this workspace's default) is
   meaningfully slower, which is an expected dev-loop cost, not a signal
   the numbers are wrong.

### Encryption

`encrypt(key, plaintext) -> Vec<u8>` uses ChaCha20-Poly1305, a real AEAD
(authenticated encryption). A fresh random 12-byte nonce is generated per
call and prepended to the ciphertext it returns -- the nonce isn't secret, it
just has to be unique per encryption under a given key, and storing it next
to the ciphertext is the standard way to make it available to `decrypt`
later. Because it's authenticated, `decrypt` doesn't silently produce
garbage on a wrong key or tampered data -- it returns a real `Err(DecryptError)`,
and deliberately does **not** distinguish "wrong key" from "tampered
ciphertext," because an AEAD's whole security property is that those two
cases are indistinguishable from the outside.

### Zeroization, and its real limits

`derive_key`/`derive_auth_secret`/`decrypt` all return `Zeroizing<...>`
wrappers (from the `zeroize` crate), which wipe their contents when dropped.
This guarantees the key/plaintext is overwritten *after* use -- it does
**not** guarantee the memory was never swappable to disk or never captured
in a core dump while it was live. `mlock`/`MADV_DONTDUMP` would close that
gap; the module's own doc comment lists it as a real, not-yet-done next
step. Worth knowing if you're ever debugging something that touches derived
keys: they zeroize on drop, not on creation, so a key that's still in scope
is still live plaintext in ordinary process memory.

### `bip39`: the mnemonic codec

`account/src/bip39.rs` implements BIP-39's encoding scheme (entropy ->
checksummed word indices -> words, and back) using the standard 2048-word
English list (`account/assets/bip39-english.txt`, verified against its
known-good SHA-256 checksum, not retyped by hand). It deliberately does
**not** implement BIP-39's separate seed-derivation step (PBKDF2-HMAC-SHA512
over the mnemonic) -- this app doesn't need it, since the mnemonic here is
just fed straight into this crate's own Argon2id `derive_key`, the same way
a password would be. Interop with other BIP-39 wallets' seed derivation is
explicitly not a goal.

`entropy_to_mnemonic` is what `create_account` calls (with 20 bytes / 160
bits of entropy, producing 15 words). `mnemonic_to_entropy` is the inverse --
**it exists but nothing calls it yet**. There's no "restore this account on
a new device by typing the recovery phrase" UI flow in `app`; today the only
way `app` ever gets a recovery code back is by reading `account.txt` on the
*same* device it was created on. If you build that restore flow, this
function is the piece that's already done.

## `storage`: the data model that knows nothing about crypto

Source: `storage/src/lib.rs`.

This is deliberately the one crate in the whole chain with no idea
encryption or networking exist. It just models "what data syncs" (`Bookmark`,
`HistoryEntry`, `Settings`, all bundled into one `SyncPayload`) and can turn
itself into bytes and back. That separation is what makes it trivially unit
testable -- no fake crypto, no fake network, just plain data round-tripping
through `serde_json`.

Note, if you've read `network`'s or `renderer`'s own on-disk formats: unlike
`PartitionedCookieJar`/`LocalStorageStore`/`IndexedDbStore` (which hand-build
`serde_json::Value` JSON to avoid a `serde` dependency in those crates),
`storage` types use ordinary `#[derive(serde::Serialize, serde::Deserialize)]`
-- this crate already pulls in `serde` directly, so there's no reason not to.

### The three record types

- `Bookmark { title, url, created_at_unix }`. Identity is the URL -- there's
  no separate stable ID yet, which is a real, documented limitation: if a
  future "rename/reorder bookmarks" feature ever needs to distinguish two
  edits of "the same" bookmark from "a bookmark was deleted and a new one
  added," it'll need a real ID field first.
- `HistoryEntry { url, title: Option<String>, visited_at_unix }`. **Not**
  deduplicated by URL -- visiting the same page twice is two separate
  entries, matching how history (as opposed to bookmarks) actually works.
  Capped at `MAX_HISTORY_ENTRIES = 500`, oldest pruned first, because every
  sync round-trips the *entire* payload (see below) -- an unbounded history
  log would make every sync progressively heavier forever.
- `Settings`: a flat `Vec<SettingEntry { key, value, updated_at_unix }>`
  (not a `HashMap`, so serialization order and the merge logic below can be
  deterministic-ish). Each entry independently timestamped.

### `SyncPayload::merge` -- where the real conflict resolution lives

`sync` (the crate) can *detect* that two devices diverged, but it can never
*resolve* it, because it only ever holds ciphertext. `storage::SyncPayload::merge`
is where the actual resolution happens, once `app` has decrypted both sides:

- **Bookmarks**: unioned by URL. Same URL on both sides keeps whichever copy
  has the later `created_at_unix`.
- **Settings**: delegated to `Settings::merge`, which is last-write-wins
  *per key* (not per whole blob) -- a key present on only one side survives
  untouched; a key present on both keeps whichever `updated_at_unix` is
  later. This is a meaningful improvement over "the whole blob from whichever
  side pushed last wins," which would silently drop an unrelated setting
  change made on the other device.
- **History**: unioned by the `(url, visited_at_unix)` pair (not just URL,
  since the same URL legitimately appears many times), re-sorted, then
  re-capped to `MAX_HISTORY_ENTRIES`.

One documented sharp edge: an exact tie (identical timestamp on both sides
for the same key/URL) breaks toward `self`, so `a.merge(&b)` and `b.merge(&a)`
can technically differ on that edge case. It only affects which of two
*otherwise-equal* writes wins cosmetically -- nothing is ever dropped by it.

If you're looking for where a real CRDT (an OR-Set for bookmarks, proper
LWW-registers with per-replica tie-breaking for settings) would slot in --
this merge function is it. The module's own doc comment calls this out as
the fully-correct answer if concurrent-edit-to-the-same-field conflicts ever
become a real problem; not worth the complexity for a handful of string
settings today.

## `sync`: opaque ciphertext in, opaque ciphertext out

Source: `sync/src/lib.rs`.

This crate's types (`Blob`, the `SyncTransport` trait) only ever hold
`Vec<u8>` ciphertext plus an `account_id` string. Never a `SyncPayload`,
never anything from `account`. That's the actual mechanism that makes
"zero-knowledge sync" true rather than a marketing claim -- this crate
*structurally cannot* decrypt anything, because it never has the key, and it
never even sees plaintext long enough to try.

### Three implementations of `SyncTransport`

- **`FakeSyncServer`**: in-memory `HashMap`, no persistence. Good for fast
  unit tests of push/pull/conflict logic; data is gone on restart.
- **`FileSyncServer`**: what `sync-server` actually runs. One file per
  account under `data_dir`, named by a SHA-256 hash of the account ID (not
  the raw ID -- this is what makes a hostile account ID like
  `../../etc/passwd` harmless; it just hashes to some hex string like any
  other input). Each push does a full read-modify-write of that one file,
  atomically (temp file + `rename`), with **no** in-memory cache -- every
  request touches disk. Fine at hobby-project request volumes; an
  `account_id -> version` in-memory index is the documented next step if
  that ever changes.
- **`HttpSyncClient`**: the real HTTP client `app` uses, talking to a real
  `sync-server`. `PUT /accounts/{id}` with `Authorization: Bearer <64 hex
  chars>` and `X-Expected-Version: <n>` to push; `GET /accounts/{id}` (same
  auth header) to pull, reading the version back from an `X-Version`
  response header.

### Conflict detection, not resolution

Every push carries the version the client *thinks* it's overwriting.
`FileSyncServer`/`FakeSyncServer` compare that against the actual current
version; a mismatch returns `SyncError::Conflict { server_version }` instead
of silently overwriting newer data. This crate's job stops there -- it has
no way to combine two devices' changes, so all it can do is refuse and let
the caller (`app`) figure out what to do. See `app::Browser::sync_push`
below for the actual retry-and-merge loop this conflict signal drives.

### File-backed backups (real, not just theoretical)

Every `FileSyncServer::push` snapshots the version it's about to overwrite
into `data_dir/backups/<account hash>/<version>.blob` **before** writing the
new one, keeping the most recent `backup_retention` versions (default 10,
oldest pruned first). This is deliberately *not* full multi-node replication
-- overkill for a single-operator deployment -- but it does mean a bad push
(a client-side merge bug, a corrupted upload) doesn't silently destroy the
only copy of your data. `restore_backup(account_id, version)` brings a
specific version back to being live; there's no HTTP route for it, only the
operator-facing `sync-server --restore` CLI flag (see below) -- a client has
no legitimate reason to roll back a version out from under a possibly-concurrent
other device.

This does **not** protect against losing the whole disk. An off-box copy of
`data_dir` is still an operational step outside this crate entirely.

## `sync-server`: the actual binary

Source: `sync-server/src/main.rs`, `sync-server/src/rate_limit.rs`.

A small `tiny_http`-based HTTP server. `main()` handles two CLI flags
(`--restore <account_id> <version>`, `--list-backups <account_id>`) before
falling through to the actual server loop if neither was given.

### The request loop

For every incoming request: check the per-IP rate limit first (before doing
*any* other work, including parsing the account ID) -> parse `/accounts/{id}`
out of the URL -> extract and validate the `Authorization: Bearer <64 hex>`
header -> check the per-account lockout -> dispatch to `store.push`/`store.pull`
based on HTTP method. `PUT` reads the whole body into memory as the
ciphertext (no streaming, no size cap -- a documented, real gap). `GET`
returns the ciphertext as the response body with `X-Version` as a header.

**Registration is trust-on-first-use**: the first push for a given
`account_id` establishes that account's `auth_secret_hash` (a SHA-256 hash
of the auth secret, stored alongside the blob -- see `sync::StoredBlob`).
Every later request against that same `account_id` must present a secret
that hashes to the same value, or it's `401 Unauthorized`. There's no
separate signup step; pushing *is* signing up.

### `rate_limit::RateLimiter`

Two independent, both-in-memory mechanisms:

- **Per-IP**: `MAX_REQUESTS_PER_IP_WINDOW = 30` per `IP_WINDOW = 60s`, a
  plain fixed-window counter (not a sliding log or token bucket). Stops raw
  hammering regardless of whether requests are authorized.
- **Per-account lockout**: `MAX_AUTH_FAILURES = 10` failed-auth attempts
  against one `account_id` locks it out for `LOCKOUT_DURATION = 15 minutes`,
  **even from a different IP** -- this is what stops someone working around
  the per-IP limit by distributing guesses across many source addresses.
  Deliberately generous (not 3-strikes) because a legitimate second device
  that hasn't synced yet, or one mistyped recovery code, shouldn't lock
  anyone out.

Both maps are **never evicted** except by their own window/lockout expiring
in place -- a sustained flood of distinct `account_id`s grows the map
unboundedly over a long enough time, bounded in practice only by the
attacker's own per-IP request budget. A real deployment wanting stronger
guarantees would want an LRU cap or periodic sweep on top; not implemented.

### What's explicitly NOT here

Plain HTTP, not TLS -- the module doc comment is blunt about this: run it
behind a real reverse proxy that terminates TLS, because the auth secret and
ciphertext both travel over whatever connection this binary itself speaks.
Also: the per-IP limiter keys on the raw socket peer address and knows
nothing about `X-Forwarded-For` or similar, so behind a naive reverse proxy
every client would appear to share one IP's rate budget -- a trusted-proxy
story is still a real gap if you ever put this behind one.

## The `account`/`sync` boundary, and why `app` is the glue

This is the load-bearing structural fact of this whole file: `sync` has **no
Cargo dependency on `account`**, and never will by design. It's enforced at
the `Cargo.toml` level, not just by convention. The consequence: `sync`'s
own code has no way to accidentally gain the ability to decrypt anything,
even by mistake, even in a future refactor -- the type it would need
(`account::Account`, or a derived key) simply isn't reachable from that
crate's dependency graph.

That means something has to actually do the gluing -- `SyncPayload::to_bytes()`
-> `account::encrypt` -> `sync::push`, and the reverse for pull. That "something"
is `app` (specifically `Browser::sync_push`/`Browser::sync_pull` in
`app/src/main.rs`), and it's the *only* place in the entire codebase that
imports both `account` and `sync` together.

Concretely, `sync_push`:

1. Derives `key` (`account::derive_key`) and `auth_secret`
   (`account::derive_auth_secret`) fresh, from `self.account.recovery_code`
   + `self.account.kdf_salt` -- **not cached**, re-derived (full 128 MiB
   Argon2id cost) on every single push. This is fine here because a sync
   push is a comparatively rare, explicit event (adding a bookmark, editing
   a setting), unlike something like a cookie write which can happen on
   nearly every navigation -- see `docs/wiki/01-process-model-and-ipc.md`
   for the contrasting case where `app` *does* cache a derived key for
   exactly that performance reason, and why.
2. Encrypts the current `self.bookmarks.to_bytes()` and pushes it with
   `self.sync_version` as the expected version.
3. On `SyncError::Conflict`, pulls the server's current blob, decrypts it,
   merges it into `self.bookmarks` via `SyncPayload::merge`, saves the
   merged result locally, and loops to push again -- up to
   `MAX_PUSH_ATTEMPTS = 5` times, so a pathological case (another device
   pushing on every single one of *our* retries) can't loop forever.
4. Any transport error (server unreachable) just logs and gives up -- sync
   is explicitly best-effort; nothing about browsing itself depends on it
   succeeding.

`sync_pull` is the mirror image for startup: pull whatever the server has,
decrypt, **merge** into the local payload (never blindly overwrite it -- a
device that made offline changes before its first successful pull needs
those to survive), and push the merged result right back if the merge
actually changed anything, so this device's own local-only additions don't
have to wait for some unrelated future sync to reach the server.

## Where to look next

- `app/src/main.rs`'s own `save_bookmarks`/`load_or_init_bookmarks`/
  `load_or_create_account`/`write_secret_file` functions for how the
  encrypted `.enc` files actually get read/written on disk (owner-only
  permissions, same pattern as the cookie/localStorage/IndexedDB `.enc`
  files described in the network/process-model wiki pages).
- `THREAT_MODEL.md`'s "Account and crypto" and "Sync server" sections for
  the security-review framing of everything in this file (known gaps,
  what an external audit should check first).
- `TESTING.md`'s "Testing the sync server" section for a real, runnable
  `curl`-based walkthrough of the HTTP API.
