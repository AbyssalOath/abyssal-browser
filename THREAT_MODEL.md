# Threat model and security self-review

This is a self-review written by the maintainer with AI assistance (Claude
Code). It is **not** a professional security audit. It exists to make the next
real step, an actual third-party audit before this project is handed to anyone
who is not the person building it, cheaper and more focused. An auditor's time is
better spent checking claims than rediscovering the architecture.

Treat every statement below as "this is what the code appears to do as of this
writing", not as an independently verified guarantee. Nothing here should be
read as "audited" or "secure". See the "Security status" section of
[`README.md`](README.md), and see [`SECURITY.md`](SECURITY.md) for how to report
a vulnerability. For the structure being described here, see
[`ARCHITECTURE.md`](ARCHITECTURE.md).

## Contents

- [What this project tries to protect against](#what-this-project-tries-to-protect-against)
- [What it does not protect against](#what-it-does-not-protect-against)
- [Trust boundaries](#trust-boundaries)
- [Renderer sandbox](#renderer-sandbox)
- [The IPC boundary](#the-ipc-boundary)
- [Account and crypto](#account-and-crypto)
- [Network layer](#network-layer)
- [Attack surface added by later features](#attack-surface-added-by-later-features)
- [Sync server](#sync-server)
- [Dependencies and supply chain](#dependencies-and-supply-chain)
- [Update checking](#update-checking)
- [Priority list for an external audit](#priority-list-for-an-external-audit)

## What this project tries to protect against

Roughly in order of how central they are to the design:

1. **Cross-site tracking on the open web.** Trackers correlating a user across
   sites through cookies, cache, or storage, and fingerprinting through window
   size, timezone, locale, and header values.
2. **A malicious or compromised web page compromising the browser itself.** A
   memory-safety bug or logic flaw in HTML, CSS, JS, image, audio, or PDF
   processing being used to read local files, pivot to other tabs, or reach the
   network in ways the user did not intend.
3. **The sync server operator (or anyone who compromises the server) reading a
   user's bookmarks, history, or settings.** The server should only ever see
   ciphertext.
4. **Passive network observers** (ISP, Wi-Fi operator, compromised router)
   learning which sites are visited through plaintext DNS.

## What it does not protect against

These are explicitly **not** goals right now:

- **A targeted attacker with physical or local access to the machine.**
  `account.txt` is now owner-only (`0o600`), but it still holds the recovery
  code in plaintext, so any process or person running as the same OS user can
  read it. Full-disk encryption and physical security are up to the user.
- **A malicious sync server operator who can also tamper with the client
  binary** the user runs.
- **High-assurance anonymity against a strong adversary.** This is not Tor, and
  it does not hide your IP address from the sites you visit.
- **Network-level metadata.** Even with DoH and TLS, an on-path observer still
  sees the destination IP addresses and the TLS SNI hostname. This project does
  not implement Encrypted Client Hello.
- **Cloudflare seeing your DNS queries.** Hostnames are resolved through
  Cloudflare's DoH resolver (bootstrapped via a hardcoded IP). That hides them
  from the local network but makes Cloudflare a party that sees them.
- **Users who did not build the binary themselves** and cannot audit what is
  running. There are no reproducible builds or signed release artifacts.
- **Anything a malicious userscript does.** Userscripts are fully trusted.

## Trust boundaries

```
+------------------------------+   stdin/stdout, length-prefixed JSON   +-----------------------------------+
| app  (privileged)            | -------------------------------------> | renderer  (sandboxed, per-site)   |
|                              | <------------------------------------- |                                   |
|  - account recovery code     |     ipc::ClientMessage / ServerMessage |  - DNS-over-HTTPS + TLS + HTTP    |
|  - derived encryption keys   |                                        |  - HTML / CSS parse + layout      |
|  - decrypted bookmarks       |                                        |  - JavaScript execution (Boa)     |
|  - NO network access         |                                        |  - image / audio / PDF decoding   |
|    (no HTTP client linked)   |                                        |  - Landlock + seccomp-bpf (Linux) |
+------------------------------+                                        +-----------------------------------+
```

`app` never links an HTTP client (see the comment in `app/Cargo.toml`). This is
enforced by the dependency graph, not just convention: adding one would be a
visible, deliberate act rather than an accidental transitive pull. Every real
fetch, including the update checker, is done by a `renderer` process instead.
`renderer` never receives the account's recovery code, derived keys, or
decrypted bookmarks and settings. No field in `ipc::RenderRequest` or any other
client message carries them.

This is the single most load-bearing security property in the codebase. A bug
in HTML, CSS, or JS processing, code that by construction runs on
attacker-controlled bytes, cannot leak those secrets, because the process that
has that bug never had them.

**Site isolation.** `app`'s `RendererPool` spawns one renderer process per
distinct eTLD+1 (`privacy::registrable_domain`) that any open tab is showing. A
memory-safety bug in one site's process cannot read another open tab's DOM or
script state. All renderers currently share one disk-cache directory. See
[Known gaps](#network-layer).

## Renderer sandbox

Linux only (`renderer::sandbox`), applied in this order:

1. **Landlock** (ABI V4, kernel 6.7+ for the network rules; on older kernels it
   degrades with a printed warning rather than failing silently):
   - Filesystem: read-only access to the OS TLS trust store paths (`/etc/ssl`,
     `/etc/pki`, `$SSL_CERT_FILE`, `$SSL_CERT_DIR`) and read/write access to
     only its own disk-cache directory. Nothing else on disk is reachable. The
     account file and encrypted bookmarks are outside the allowlist entirely.
   - Network: outbound `ConnectTcp` only to ports 80 and 443, and no `BindTcp`
     rule at all, so the process cannot listen anywhere.
2. **seccomp-bpf** via `seccompiler`: an allowlist of roughly 55 syscalls, with
   everything else killing the process. The allowlist was derived empirically
   (a disposable ptrace-based tracer against a real workload: DoH lookup, HTTPS
   fetch, cache read/write, a second host, `Tick`, `Click`), not guessed. See that
   module's doc comment for the methodology and for which later features were
   verified by code reading rather than a fresh trace.

What this does **not** cover:

- **Non-Linux platforms, unverified.** macOS (Seatbelt/`sandbox_init`) and
  Windows (a Job Object plus several `SetProcessMitigationPolicy` hardening
  policies) both have real sandbox code now, but neither has ever run on a
  real Mac or real Windows machine -- there isn't one in this project's own
  development loop. Both were written and cross-type-checked against the real
  platform APIs (`cargo check --target x86_64-apple-darwin` /
  `--target x86_64-pc-windows-gnu`, and Microsoft's own `windows-sys` bindings
  on the Windows side), which catches real API mistakes but proves nothing
  about runtime behavior. Neither is anywhere near Linux's Landlock+seccomp in
  scope: macOS's profile restricts filesystem/network only (not the exact
  Mach/XPC services real TLS verification needs -- see `renderer::sandbox`'s
  own module docs for why), and Windows has no AppContainer-grade filesystem/
  network restriction at all yet, just process-level hardening. Treat both as
  a real reduction in attack surface, not as tested-and-proven the way Linux's
  is, until someone actually runs this on the real OS.
  **Update**: real GitHub-hosted macOS and Windows CI runners now build this
  project and run its test suite on every push, which is a real step past
  "cross-type-checked only" -- the Windows sandbox itself was confirmed to
  actually apply (`abyssal-renderer`'s own log lines confirm the Job Object
  and mitigation policies are accepted at runtime, not just compiling), and
  macOS built and passed cleanly. This is still not the same as someone
  actually using the browser day to day on either OS, and that same Windows
  CI run also turned up a separate, real, now-diagnosed issue: `app`'s own
  test suite hit a native `STATUS_ACCESS_VIOLATION` crash, three separate
  times across three separate real call sites, every time it exercised the
  real `media_playback::start_playback` (which opens a real `cpal`/WASAPI
  audio stream) on this headless runner, which has no real audio hardware.
  Unlike a clean `cpal::Error` (which every one of those call sites already
  handled gracefully), a raw FFI crash inside `cpal`'s own WASAPI backend
  bypasses Rust's `Result`/panic-unwinding machinery entirely, so no amount
  of error handling on this side of the FFI boundary could have caught it --
  serializing the test run (`--test-threads=1`) was used only as a
  DIAGNOSTIC, to make the harness print each crashing test's name before it
  died (a crashed test's own buffered output never flushes under the
  default parallel, captured execution the workflow now runs), not as the
  actual fix. All three real call sites are now excluded from the default
  `cargo test` run: `media_playback::tests::start_playback_opens_a_real_
  stream_and_reaches_the_end_of_a_tiny_buffer` and `..._resumes_from_a_
  given_offset` are `#[ignore]`d (runnable manually via `cargo test --
  --ignored` on a machine with real audio hardware), and `app`'s own
  `tests::play_then_pause_media_is_internally_consistent_regardless_of_
  audio_hardware` is `#[ignore]`d the same way, while its sibling
  `tests::navigating_away_stops_and_clears_all_media_playback_state` was
  rewritten to stop calling the real hardware path at all (it never needed
  to, for what it actually verifies -- see its own doc comment). The actual
  playback LOGIC these would otherwise cover is already fully verified
  without any real hardware by the pure `fill_output_buffer`/`CachedPcm`
  tests in `app/src/media_playback.rs`.
- **Resource limits.** `sandbox::resource_limits` (Linux/macOS, via real
  `setrlimit(RLIMIT_AS)`/`setrlimit(RLIMIT_CPU)` calls, empirically verified
  on real Linux hardware to actually be enforced - `/proc/<pid>/limits` on a
  running renderer shows the real caps, not just a successful return code)
  and the Windows Job Object's `JOB_OBJECT_LIMIT_PROCESS_MEMORY`/
  `JOB_OBJECT_LIMIT_PROCESS_TIME` fields (real code, unverified on real
  Windows like the rest of that platform's sandbox) now cap virtual memory
  (1.5 GiB) and cumulative CPU time (30 minutes) per renderer process. A
  memory-exhaustion bug, or a page that tries to exhaust memory on purpose,
  gets the process killed rather than left to grow without bound. The CPU
  cap has a real, disclosed limitation: it's CUMULATIVE since the process
  started, not a per-page or per-operation budget, since one renderer
  process can live across many navigations on the same site (see
  `app::RendererPool`) - a very long, genuinely heavy session could in
  principle hit it, though ordinary browsing spends the large majority of
  its time idle between real script/layout work, so 30 minutes of ACTUAL
  busy CPU time is a generous backstop against a pathological runaway, not
  a tight budget. `renderer::script::RuntimeLimits` (loop iteration and
  recursion counts) still separately constrains the JS side specifically,
  and nothing bounds wall-clock time for a single synchronous operation
  (a real per-operation watchdog would need a different design - see
  `sandbox::resource_limits`'s own doc comment).
- **The allowlist's portability.** It was derived on one machine and workload.
  A different libc or a new code path can need a syscall that is not listed,
  which surfaces as the renderer being killed on that operation.
- **The JS engine's own bug surface.** Boa is pure Rust, which removes the
  memory-corruption exploit class. It does not make untrusted script safe in a
  broader sense. A logic bug in Boa, or in how this codebase drives it, is still
  real attack surface, just a narrower class of it. That is why script runs
  inside the same sandboxed, site-isolated process as everything else.

## The IPC boundary

- Length-prefixed JSON over stdin/stdout, one process per renderer.
  `MAX_MESSAGE_LEN` (64 MiB) bounds the allocation `app` makes from a length
  prefix it reads from the **less trusted** side, so a compromised renderer
  cannot force an unbounded buffer through a hostile length field.
- The protocol is strict lockstep: one reply per message and no
  renderer-initiated push. That narrows what a compromised renderer can do to
  `app` even if it fully controls its replies. It can send malformed or
  adversarial JSON payloads, which is still worth an auditor's attention, but it
  cannot make `app` process an unsolicited message at an unexpected time.
- A fully laid-out `LayoutBox` tree (pixel rects, wrapped text) crosses the
  boundary rather than raw DOM or CSS, so `app` never runs layout over
  untrusted content itself.
- A click is mapped to a `dom::NodeId` by `app` from the snapshot it already
  holds. The renderer never learns pixel coordinates.

**What an auditor should check first:** the `serde` deserialization path for every
`ClientMessageKind` and `ServerMessageKind` variant against hand-crafted and
fuzzed payloads. This is a structurally untrusted-input boundary in both
directions (a compromised renderer sending `app` adversarial replies, and in
principle the reverse, though `app` is the higher-trust side). It has only been
tested against well-formed traffic, not fuzzed.

## Account and crypto

- **Argon2id** (128 MiB, t=3, p=1, deliberately tuned rather than left at crate
  defaults) derives keys from a 15-word BIP-39 recovery code (160 bits of OS
  CSPRNG entropy).
- **ChaCha20-Poly1305** (an AEAD) encrypts the bookmarks, history, and settings
  blob. Tampering is detected and `decrypt` fails loudly.
- A second, **domain-separated** secret (`derive_auth_secret`) authenticates to
  the sync server. It is structurally unable to derive the encryption key, so a
  server that captures it still cannot decrypt the data it stores.
- Derived keys and plaintext are `zeroize`d after use.

**Known gaps, stated plainly:**

- **`account.txt`'s plaintext recovery code is still readable by the same OS
  user.** `write_secret_file` in `app/src/main.rs` now writes it (and
  `bookmarks.enc`/`downloads.enc`) owner-only (`0o600` on Unix, via an
  explicit `OpenOptions::mode`/`set_permissions` call, not just the process's
  default umask), which closes the "another local user on a shared machine
  can just read it" gap this used to describe. It does not, and cannot,
  protect against anything running as that same user (malware, another
  process you run, a second person who knows your login password) reading the
  file, because the recovery code has to be plaintext on disk somewhere for
  the browser to read it back at startup.
- **The recovery code is printed to stdout** once at account creation, so it can
  end up in terminal scrollback or a service log.
- **No `mlock` or `MADV_DONTDUMP`** on buffers holding derived keys or decrypted
  plaintext while they are live. `zeroize` guarantees a wipe after use, not that
  the memory was never swappable or captured in a core dump while in use.
- **No recovery or rotation story** if the recovery code is compromised but not
  lost. By the zero-knowledge design there is also no server-side reset.
- **No "restore on a new device" UI.** The BIP-39 decode exists in
  `account::bip39`, but `app` only reads the code back from its own local file.

## Network layer

- **DNS-over-HTTPS** to Cloudflare, bootstrapped through a hardcoded IP to avoid
  the chicken-and-egg problem. It **fails closed**: a DoH failure fails the whole
  fetch rather than falling back to plaintext DNS.
- `FilteringFetcher` enforces the EasyList/EasyPrivacy blocklist (via the
  `adblock` crate) and strips tracking query parameters before every fetch.
  `HttpFetcher` applies the same blocklist check to **every redirect hop**, so a
  tracker behind a 3xx chain does not get a free pass.
- The opt-in disk cache is partitioned by `privacy::StoragePartitionKey`
  (top-level site plus resource host, using a PSL-based eTLD+1), not just by
  host. Only responses that opt in through `Cache-Control: max-age` are stored.
- `PartitionedCookieJar` is real and wired through `FilteringFetcher::
  fetch_in_context`: it supplies the outgoing `Cookie` header and stores every
  `Set-Cookie` in the response, partitioned by the same
  `StoragePartitionKey` (top-level site plus resource host) as the disk
  cache, so the same tracker embedded on two different sites cannot
  correlate a user across them via cookies. `localStorage` (`renderer::
  local_storage`) and IndexedDB (`renderer::indexed_db`) are real too, and
  deliberately NOT partitioned by top-level site (only by origin) - there are
  no iframes in this browser, so there is no third-party embedded context
  that could exploit that the way a real cross-site iframe could.
- **Cookies, `localStorage`, and IndexedDB are now encrypted at rest**,
  the same way `bookmarks.enc`/`downloads.enc` already are. The
  sandboxed renderer process itself never holds the account's
  encryption key - it only ever reports its own already-in-memory
  plaintext bytes back to `app` over the existing IPC channel
  (`ipc::ServerMessage::updated_cookies`/`updated_local_storage`/
  `updated_indexed_db`), and `app` (the sole holder of the key)
  encrypts, merges, and writes `cookies.enc`/`local_storage.enc`/
  `indexed_db.enc`, then decrypts and seeds a freshly-spawned renderer
  from them (`ipc::RenderRequest::initial_cookies`/etc.). This keeps
  the "renderer never receives the recovery code or derived keys"
  boundary intact (see [Trust boundaries](#trust-boundaries)) while
  closing what used to be this section's top gap: a session cookie is
  no longer exposed to local access the same way the plaintext
  recovery code is. Empirically verified end to end with a real,
  independent server (`httpbin.org`): a real `Set-Cookie` response
  produces a `cookies.enc` file whose raw bytes do not contain the
  cookie's real name or value, decrypts correctly with the real
  account key, and correctly re-seeds a second, independent renderer
  process that sends the cookie back on its own real outgoing request
  (see `app`'s own test suite).
- TLS is `reqwest` with `rustls`, not OpenSSL, and there is no custom
  certificate validation logic in this codebase to get wrong.
- Requests use fixed, non-unique `User-Agent` and `Accept-Language` values.
- **`file://` support is real, and deliberately restricted the same way
  real browsers restrict it** - not because this project has iframes or
  general cross-origin script navigation (it has neither), but because a
  malicious `https://` page could still construct a clickable
  `<a href="file:///home/user/.ssh/id_rsa">` link, and without isolation a
  click on it would read (and, given network access, exfiltrate) an
  arbitrary local file through that page's own renderer process. The fix is
  structural, not a per-fetch check that some other code path could miss:
  `app::site_for_url` routes every `file://` URL, regardless of path, to one
  fixed site key (`LOCAL_FILES_SITE`), so `RendererPool` (the same site-
  isolation mechanism that already gives each website its own process - see
  [Renderer sandbox](#renderer-sandbox)) spawns exactly one dedicated
  process for all of them, permanently separate from every real website's
  process. Only that one process is ever launched with `--allow-local-files`,
  which does two things together, never one without the other: it grants the
  sandbox broad, real, unrestricted filesystem read (a root-scoped Landlock
  `PathBeneath` rule on Linux; an unrestricted `(allow file-read* (subpath
  "/"))` Seatbelt rule on macOS - the user's own explicit choice, matching
  what Chrome/Firefox themselves allow `file://` to read), and it removes
  that process's outbound network access entirely (the Landlock
  `NetPort`/`ConnectTcp` rules and the Seatbelt `network-outbound` rules are
  omitted outright, not narrowed). That second half is what makes the first
  half safe: even a fully compromised dedicated `file://` process has no
  socket to exfiltrate anything it reads through. `network::FilteringFetcher`
  gates this at its one universal fetch chokepoint too
  (`enable_local_file_access`/`allow_local_files`) - every subresource type
  (top-level navigation, images, stylesheets, external scripts, a page's own
  `fetch()`) already flows through that same chokepoint, so a malicious local
  HTML file cannot use a `fetch()` call of its own to reach the network
  either, and an ordinary website's renderer process (which never receives
  the flag) rejects any `file://` fetch attempt - including one from its own
  script - before ever touching disk (`network`'s own test suite covers this
  directly).

**Known gaps:**

- `PartitionedCookieJar` has no `SameSite`/`Secure`/`HttpOnly`/expiry
  handling at all; every cookie is treated as a plain session-lifetime
  name=value pair regardless of what its `Set-Cookie` attributes
  actually said.
- **The `.enc` files' own writes are not atomic.** `app::write_secret_file`
  (used for `cookies.enc`/`local_storage.enc`/`indexed_db.enc`, same as
  `account.txt`/`bookmarks.enc`/`downloads.enc`) truncates and writes in
  place, not via a temp-file-then-rename swap. A `SIGKILL` mid-write
  (`RendererPool` evicting a renderer doesn't kill `app` itself, but `app`
  itself has no graceful-shutdown hook either) could in principle leave
  one of these files truncated or corrupt; the next load would then
  fall back to "start empty" for that file (see `load_encrypted_storage`),
  losing that one file's state rather than crashing. This is an existing
  property of every encrypted file in `app`, not something new
  introduced for cookies/`localStorage`/IndexedDB specifically.
- **`app`'s own merge logic (`merge_persisted_json`) is untyped.** It
  can't depend on `network`/`renderer` (the "`app` never links
  `network`" boundary - see [Trust boundaries](#trust-boundaries)), so
  it reimplements each store's real `merge_into` generically over raw
  JSON, keyed by field name(s) documented in each store's own
  `to_bytes`. A future change to any of those three on-disk shapes
  would need a matching update here, with no compiler check tying the
  two together - a real, disclosed coupling, mitigated by cross-
  referencing comments at both ends.
- **`localStorage`'s cross-tab `storage` event has a real staleness window.**
  Because the IPC protocol is strict lockstep (one reply per message, see
  [The IPC boundary](#the-ipc-boundary)), firing the event into another live
  tab's session mutates that tab's in-memory DOM/JS state immediately, but
  `app` will not see any resulting re-render until the next message that
  happens to target that other tab. This is a correctness gap, not a
  confidentiality one - see `script::Session::fire_storage_event`'s own doc
  comment.
- No `Content-Type` or charset handling. Response bytes are treated as UTF-8,
  lossily, regardless of what the server declared. `network::Response` also does
  not expose arbitrary response headers.
- The disk cache has no size limit or eviction, and no ETag or `Vary`
  revalidation. That is not a hole by itself, but it matters if "how much of my
  browsing is recoverable from disk" is part of your threat model.
- The disk cache directory is shared across all renderer processes. It is
  partitioned internally by site and holds no secrets, so this is a hygiene gap
  rather than a leak.
- **On Windows, `file://`'s safety is process-routing-only, not OS-enforced.**
  The broadened-read/zero-network trade the dedicated `file://` process makes
  (see above) is real at the Landlock/Seatbelt level on Linux/macOS, but
  Windows's own sandbox (see [Renderer sandbox](#renderer-sandbox)) has no
  filesystem- or network-access-control equivalent at all yet - just process-
  level hardening. On Windows, the guarantee that an ordinary website's
  renderer process never reaches `file://` rests entirely on `app`'s own
  process-spawning logic (`RendererPool::get_or_spawn` only ever passing
  `--allow-local-files` for `LOCAL_FILES_SITE`) being correct, with no
  independent kernel-level layer to catch a bug in it the way there is on
  Linux or macOS.
- `privacy::is_third_party` is host-based only, with no notion of scheme and no
  handling of a redirect chain that changes top-level context mid-flight.

## Attack surface added by later features

These features landed after the original review. They are described here so an
auditor does not have to discover them.

- **Image, audio, and PDF decoding.** `image` (PNG, JPEG, GIF, BMP), `symphonia`
  (MP3, AAC, MP4/M4A, Ogg/Vorbis, WAV, FLAC), and `pdf-extract` on `lopdf` all
  parse attacker-controlled bytes. All are pure Rust and all run inside the
  sandboxed renderer, which removes the memory-corruption class but leaves
  panics, algorithmic blowups, and memory exhaustion. Images are downscaled to
  1200 px on the long side before crossing IPC, decoded audio is capped at about
  40 MB, and downloads at about 45 MB. There is **no size cap on PDF input**
  beyond the general IPC message limit.
- **Audio output.** Decoded PCM crosses IPC once per element and is played by
  `app` through `cpal`. This is the one place where renderer-produced bulk data
  is handled by the privileged process, though as plain sample buffers with the
  caps above.
- **Downloads.** The renderer fetches the bytes and `app` writes them to the OS
  Downloads folder. The suggested filename comes from page-controlled markup, so
  it is treated as hostile: it is reduced to a single safe path component
  (separators and leading dots stripped) and de-duplicated so it never overwrites
  an existing file. A compromised renderer can still choose file contents and a
  sanitized name in the Downloads folder. There is no `Content-Disposition`
  handling. What the user does with a downloaded file afterwards is out of scope.
- **Userscripts.** Local `.js` files in the data directory, run fully trusted in
  the page's own Boa context after the page's scripts. There is no permission
  model and no isolation from the page. The trust decision is "the user placed
  the file there". Anyone who can write to that directory can run script on
  matching pages.
- **DevTools console.** `EvalConsoleExpression` runs arbitrary JS against the
  live page session, with the same privileges as any page script. It is
  user-initiated from the chrome.
- **Accessibility tree.** `app::accessibility` builds an `accesskit` tree from
  renderer-produced layout data and exposes it to the OS (AT-SPI, UIA,
  NSAccessibility). Assistive technology can, by design, read page text and
  structure. On Linux, any local process with access to the accessibility bus
  can do the same, which is a general property of accessibility APIs.
- **Page signals badge.** `renderer::page_signals` computes "uses JavaScript"
  and "affiliate-style link count" locally from the DOM. It is read-only and has
  no effect on fetching or rendering.
- **`localStorage` and IndexedDB.** Real, per-origin, disk-persisted client
  storage (`renderer::local_storage`, `renderer::indexed_db`) reachable from
  any page's own script - a new, real place for a malicious page to store
  data on the user's disk (bounded by a 5 MiB per-origin quota for
  `localStorage` and 25 MiB for IndexedDB), and a new disk file
  (`local_storage.json`, `indexed_db.json`) an auditor should treat the same
  way as `cookies.json` (see [Network layer](#network-layer)'s known gaps: all
  owner-only permissioned, none encrypted at rest). The `localStorage`
  `Proxy` (for property-style access) and the cross-tab `storage` event are
  new JS-engine-facing surface built on top of Boa's own `Proxy`/`Promise`
  built-ins, not new native code parsing untrusted bytes, so their risk
  profile is closer to the existing DOM/event bindings in `script.rs` than to
  the image/audio/PDF decoders above.

## Sync server

- Persistent, file-backed storage (`FileSyncServer`) with atomic
  temp-file-then-rename writes, so a crash mid-write cannot corrupt a live blob.
  The account ID is hashed into the filename, so a hostile ID cannot traverse
  paths.
- Per-IP rate limiting (30 requests per 60 s) and per-account lockout after
  repeated failed auth (10 failures, 15 minute cooldown), both in memory.
- **Rotating local backups.** Every push snapshots the version it is about to
  overwrite, pruned to the most recent N (default 10,
  `ABYSSAL_SYNC_BACKUP_RETENTION`), recoverable with
  `sync-server --restore <account_id> <version>`. This protects against a bad
  push clobbering the only copy. It does **not** protect against losing the
  whole disk. That needs an off-box copy, which is an operational step outside
  this binary.
- **Plain HTTP, not TLS.** The auth secret and ciphertext both travel over that
  connection. The server must sit behind a TLS-terminating reverse proxy for
  anything beyond localhost development. Nothing in this codebase sets that up.

**Known gaps:**

- **Binds to `0.0.0.0:7878`** on all interfaces. Combined with no TLS, running
  it directly on a public interface exposes credentials in transit. Bind it to a
  private interface or firewall it and front it with a proxy.
- **The per-IP limiter uses the socket's peer address and ignores forwarded
  headers.** Behind a reverse proxy every request appears to come from the proxy,
  so all clients share one 30-per-minute budget. Deployers who add a proxy will
  hit this quickly, and the fix needs a trusted-proxy story.
- **No request body size limit and no per-account quota.** The `PUT` handler
  reads the whole body into memory. Registration is trust-on-first-use, so any
  client can create accounts by pushing to new IDs. Disk and memory use are only
  bounded by the per-IP request rate.
- **Sequential request handling.** The server loop handles one request at a time
  on a single thread, so one slow client can stall everyone.
- The rate-limiter maps are never evicted except by their own expiry, so a
  sustained flood of distinct account IDs grows memory over time.
- No load testing, and no fuzzing of the request parsing. `tiny_http` does the
  HTTP parsing, which reduces but does not remove this crate's surface. The
  account ID and `Authorization` header extraction in `main.rs` is this
  project's own code parsing attacker-controlled data.

## Dependencies and supply chain

- `markup5ever_rcdom` (an "unofficial" third-party republish of html5ever's
  test-only reference DOM) is **vendored** into `html/src/rcdom.rs` rather than
  depended on, closing the previously flagged "depends on a package nobody
  official publishes" gap.
- **`cargo audit --deny warnings` runs in CI** (`.github/workflows/ci.yml`)
  against the RustSec advisory database. `cargo deny` (license, ban, and source
  policy) is not configured yet.
- Everything else is a normal crates.io dependency that has not been
  independently reviewed by this project: `reqwest`/`rustls`, `boa_engine`,
  `image`, `symphonia`, `pdf-extract`, `adblock`, `landlock`/`seccompiler`,
  `argon2`/`chacha20poly1305`, `tiny_http`, `html5ever`, `wgpu`/`winit`,
  `accesskit`, `cpal`, and the rest of `Cargo.lock`. Widely used is not the same
  as audited by us. `Cargo.lock` is committed on purpose, so builds are
  reproducible at the dependency level.
- Two dependencies are pinned exactly (`accesskit = "=0.12.3"` and
  `accesskit_winit = "=0.18.0"`) to stay compatible with winit 0.29. Upgrading
  winit means revisiting both.
- The EasyList and EasyPrivacy snapshots are bundled in the repository and
  compiled into the binary. They are refreshed by hand. Stale lists mean stale
  blocking.
- **No reproducible-build story and no signing** of the release binaries that
  `release.yml` publishes. Someone downloading a release tarball has no
  cryptographic way to verify it was built from the tagged source. This is not
  relevant while the project is not distributed beyond its author.

## Update checking

`renderer::update_check` fetches `GET /repos/{repo}/releases` from GitHub's API
through the same sandboxed, DoH-routed fetcher as everything else, never from
`app` directly, and compares the newest tag with the running version. It only
**prints a notice** (`app`'s `maybe_check_for_update`, at most once per day).
There is no download step, no verification step, and no code that replaces the
running binary.

That scope is deliberate. A self-updating mechanism is itself a supply-chain
target: whatever verifies and applies an update becomes something a compromised
or spoofed release feed could exploit. Building it safely needs a real signing
and release-verification story that this project does not have. "Tell me a newer
version exists and I will go look" avoids that whole class of risk.

`RELEASES_REPO` in `renderer/src/update_check.rs` is `None` until it is set to
the real `owner/name`, so the check reports `CheckFailed` rather than claiming to
be up to date. The check uses the releases **list** endpoint because
`/releases/latest` skips prereleases, and every release here is marked as one.

## Priority list for an external audit

Roughly in order of what would move the needle most:

1. ~~**Set explicit file permissions on `account.txt`**~~ Done: `account.txt`,
   `bookmarks.enc`, and `downloads.enc` are all now written owner-only (`0o600`
   on Unix, via `app::write_secret_file`).
2. **Fuzz the IPC deserialization boundary** in both directions, for every
   message variant.
3. **Add `cargo deny`** to CI alongside the existing `cargo audit`, and decide a
   policy for advisories that have no fix.
4. **Get real macOS and Windows hardware into this project's development
   loop.** Both platforms have real sandbox code now (Seatbelt on macOS; a Job
   Object plus process mitigation policies on Windows -- see
   `renderer::sandbox`'s own module docs), but neither has ever actually run
   there. Running each for real -- and, on macOS, tracing the exact Mach/XPC
   services real TLS verification needs, the same way Linux's syscall
   allowlist was derived from a real trace -- is what would turn "real code,
   unverified" into the same standard Linux's sandbox is already held to.
5. ~~**`setrlimit` limits on the renderer**~~ Done on Linux/macOS
   (`sandbox::resource_limits`) and Windows (the Job Object's memory/CPU
   fields) - a portable backstop against memory exhaustion and runaway CPU
   use, independent of Landlock/seccomp/Seatbelt/mitigation policies. Empirically
   verified enforced on real Linux hardware; real code, unverified like the
   rest of the macOS/Windows sandbox on those two platforms.
6. **Harden `sync-server`:** request body cap, per-account quota, concurrent
   request handling, a trusted-proxy story for the rate limiter, and a bind
   address option.
7. **Re-derive the seccomp allowlist** on the distributions you intend to
   support, and add a CI job that exercises the sandboxed renderer end to end.
8. **`mlock` and `MADV_DONTDUMP`** for derived keys and decrypted plaintext in
   `account`.
9. **Size-cap PDF input** in `renderer::pdf`.
10. **Release signing and reproducible builds** before distributing binaries.
11. Everything under "Known gaps" in each section above, roughly in the order
    listed.

None of this means "do not use it personally in the meantime". It means do not
hand it to anyone else, or treat any specific claim above as verified, until an
audit, or at minimum working through this list, has happened.
