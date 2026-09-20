# Architecture

This document explains how Abyssal Browser is put together: the process model,
the crate graph, how a page load flows through the system, the IPC and sandbox
boundaries, the sync protocol, and where data lives on disk.

It is a map, not a spec. Every crate opens with a `//!` module doc in its
`src/lib.rs` that states exactly what is implemented, what is deliberately left
out, and what to build next. **Those module docs are the most current source of
truth.** If this file and a module doc disagree, trust the module doc and please
open an issue or a PR to fix this file.

## Contents

- [Design principles](#design-principles)
- [Process model](#process-model)
- [Crate graph](#crate-graph)
- [Life of a page load](#life-of-a-page-load)
- [The IPC protocol](#the-ipc-protocol)
- [The renderer sandbox](#the-renderer-sandbox)
- [Site isolation](#site-isolation)
- [`file://` support](#file-support)
- [Rendering pipeline notes](#rendering-pipeline-notes)
- [JavaScript](#javascript)
- [Account, storage, and sync](#account-storage-and-sync)
- [The sync server](#the-sync-server)
- [Data on disk](#data-on-disk)
- [Deliberate omissions](#deliberate-omissions)
- [Where to extend it](#where-to-extend-it)

## Design principles

1. **Isolate the code that touches untrusted bytes.** Anything that parses
   attacker-influenced input (network responses, HTML, CSS, scripts, images,
   audio, PDFs) runs in a sandboxed child process that never holds account
   secrets.
2. **Prefer memory-safe dependencies on the untrusted path.** No C or C++
   library is used to parse untrusted content when a mature pure-Rust option
   exists. This is why JavaScript is Boa rather than V8 or QuickJS, why images
   use the `image` crate with only pure-Rust codecs, and why PDFs are text-only
   (there is no mature pure-Rust PDF renderer).
3. **Make boundaries structural, not conventional.** The dependency graph
   enforces the important rules: `app` does not depend on `network`, and
   `sync` does not depend on `account`. Breaking either would be a visible,
   deliberate change to a `Cargo.toml`.
4. **One place for privacy policy.** Fingerprinting and tracking defaults live in
   the `privacy` crate so they can be audited together.
5. **No telemetry, ever.** This is a project constraint, not a toggle.
6. **Fail closed.** DNS-over-HTTPS failure fails the fetch. A decryption failure
   fails loudly. A blocked subresource simply does not load.
7. **Be honest in the docs.** Each module states its own limits. Simplifications
   are documented where they are made.

## Process model

```
+------------------------------+   stdin/stdout, length-prefixed JSON   +-----------------------------------+
| app  (privileged)            | -------------------------------------> | renderer  (sandboxed, per-site)   |
|                              | <------------------------------------- |                                   |
|  - window, UI, input         |     ipc::ClientMessage / ServerMessage |  - DNS-over-HTTPS + TLS + HTTP    |
|  - account + recovery code   |                                        |  - blocklist + partitioned cache  |
|  - derived encryption keys   |                                        |  - HTML / CSS parse + layout      |
|  - decrypted bookmarks       |                                        |  - JavaScript (Boa)               |
|  - sync client               |                                        |  - image / audio / PDF decoding   |
|  - audio output (cpal)       |                                        |  - Landlock + seccomp-bpf (Linux) |
|  - NO HTTP client linked     |                                        |                                   |
+------------------------------+                                        +-----------------------------------+
```

- **`app`** (package `abyssal`, directory `app/`) is the privileged process. It
  owns the window, tabs, UI chrome, the account, decrypted user data, and the
  sync client. It links no HTTP client. It never runs layout on untrusted
  content, and it only paints trees the renderer already laid out.
- **`renderer`** (binary `abyssal-renderer`) is the untrusted-content process.
  It receives navigation requests and returns a fully laid-out `LayoutBox` tree
  plus metadata. No message type carries the recovery code, derived keys, or
  decrypted user data, so a compromised renderer has nothing of that kind to
  steal.
- **`sync-server`** is a separate, optional binary. It is not part of the
  browser process tree.

## Crate graph

Each crate depends only on the ones listed. Arrows point at dependencies.

```
dom        (independent)
privacy    (independent)
storage    (independent)
text       (independent; wraps fontdue)
account    (independent; never depends on sync, by design)
sync       (independent; never depends on account, by design)

html       -> dom
css        -> dom
network    -> privacy
layout     -> dom, css, text
render     -> layout, text
ipc        -> layout, dom

renderer   -> network, html, css, layout, text, privacy, dom, ipc
app        -> dom, html, css, layout, render, privacy, account, storage,
              sync, text, ipc          (NOT network)
sync-server -> sync
```

The two rules that matter most:

- `app` has no dependency on `network`. Every real fetch, including the update
  check, goes through a renderer process. This held even when `app` took over
  persisting cookies/`localStorage`/IndexedDB (see [The IPC
  protocol](#the-ipc-protocol)): rather than adding the dependency, `app`'s
  own `merge_persisted_json` reimplements each store's real `merge_into`
  generically, over raw JSON.
- `account` and `sync` do not know about each other. `sync` only handles opaque
  ciphertext and an account ID string, so the server side has no code path
  that could decrypt anything. `app` is the only place that knows how to go
  `storage::SyncPayload` -> bytes -> `account::encrypt` -> `sync::push`.

## Life of a page load

1. **Input.** The user types a URL, clicks a link, or presses back. `app`
   resolves it (`resolve_url`, a simplified RFC 3986 approximation using the
   `url` crate) and updates the tab's history.
2. **Pick a renderer.** `app`'s `RendererPool` maps the URL to a site key using
   `privacy::registrable_domain` (a Public Suffix List eTLD+1) and either reuses
   the renderer for that site or spawns a new one lazily.
3. **Request.** `app` sends `ClientMessageKind::Navigate(RenderRequest)` scoped
   to the tab's `TabId`. It carries only what the renderer needs: the URL, the
   top-level host (for third-party classification), the canvas width, the theme,
   and the source of any matching userscripts. No secrets.
4. **Fetch (renderer).** `FilteringFetcher` checks the URL against the
   EasyList/EasyPrivacy blocklist (host and path aware), strips tracking query
   parameters, consults the partitioned disk cache, then `HttpFetcher` resolves
   the hostname over DNS-over-HTTPS and fetches over rustls TLS. Every redirect
   hop is re-checked against the blocklist.
5. **Parse (renderer).** `html` runs `html5ever` and converts the result into
   the shared `dom::Node` tree.
6. **Style (renderer).** `css` builds the user-agent stylesheet, the author
   `<style>` blocks, external `<link rel="stylesheet">` files (fetched through
   the same filtered path), and inline `style=""`, then runs the cascade and
   inheritance to produce a `ComputedStyle` per node.
7. **Script (renderer).** Inline and external `<script>` content and any
   matching userscripts run in Boa against the live DOM. Subresource fetches,
   including scripts, images, and `fetch()`, all use the same filtered fetcher,
   so a third-party tracking script is blocked exactly like a tracking pixel.
8. **Layout (renderer).** `layout` produces a `LayoutBox` tree with concrete
   pixel geometry, wrapped text lines, and stable `dom::NodeId`s.
9. **Reply.** The renderer returns `ServerMessageKind::Rendered(RenderSuccess)`:
   the `LayoutBox` tree, the page title, page signals (uses JavaScript, count of
   affiliate-style links), any captured console messages, and the time until the
   next pending `setTimeout`.
10. **Paint (app).** `render::paint` rasterizes the tree into an RGBA buffer
    (real glyphs, boxes, borders, decoded images) with a scroll offset, and
    `render::window` presents it through wgpu/winit. `app::accessibility`
    rebuilds an `accesskit` tree from the same `LayoutBox` for screen readers.

Clicks do not send pixel coordinates to the renderer. `app` resolves a click to
a `dom::NodeId` locally with `layout::hit_test_node` using the snapshot it
already has, and sends only that ID. The renderer then walks the live DOM's
real ancestor chain to dispatch capture, target, and bubble phases. `app`
dispatches the click first and only follows a link if nothing called
`preventDefault()`.

Step 3's request (`Navigate` specifically) does not block `app`'s own single
UI/event-loop thread while steps 4-9 run on the renderer. Each `RendererProcess`
owns a dedicated background thread that does the actual blocking pipe write/read
(see `run_renderer_io`); `Browser::begin_navigate*` queues the request and
returns immediately, and `Browser::poll_pending_navigations` applies the real
result once it arrives, woken up promptly by a `render::window::WakeHandle`
call from that background thread rather than waiting for the next real input
or scheduled timer. This is what stops one tab's slow page load from freezing
every other open tab (each on its own independent process and thread) and the
window itself. Every OTHER message kind (`Click`, `Focus`, `TextInput`,
`Tick`, ...) still blocks its OWN caller for as long as its own round trip
takes -- a deliberate scope decision, since none of those run untrusted script
long enough (`RuntimeLimits` bounds it) or do real network I/O of their own to
have been an actual source of a multi-second stall the way a real page fetch
is.

## The IPC protocol

Defined in the `ipc` crate.

- **Framing.** A length prefix followed by a JSON body, over the child's
  stdin/stdout. `MAX_MESSAGE_LEN` is 64 MiB. `app` refuses to allocate for
  anything larger, so a compromised renderer cannot force an unbounded
  allocation through a hostile length field.
- **Lockstep.** Every `ClientMessage` gets exactly one `ServerMessage` reply.
  There is no renderer-initiated push. Timers work through `Tick`: the renderer
  reports `next_wake_in_millis` on every reply and `app` schedules its own wake
  through the window event loop (`Frame::wake_at`), with no polling and no
  background thread.
- **Tab scoping.** Every message carries a `TabId`. Tabs on the same site share
  a renderer process, and the renderer keeps one live script session (a Boa
  context plus DOM) per tab.
- **Message kinds** (client to renderer): `Navigate`, `CloseTab`, `Tick`,
  `Click`, `Focus`, `Blur`, `TextInput`, `MoveKeyboardFocus`, `Download`,
  `FetchAudioPcm`, `UpdateMediaPlayback`, `EvalConsoleExpression`,
  `FetchDomSnapshot`, `CheckForUpdate`. Replies: `Rendered`, `Unchanged`,
  `Error`, `Closed`, and one result type each for updates, downloads, audio, and
  DOM snapshots.
- **Payload notes.** Downloads cross the wire base64-encoded (a plain JSON
  `Vec<u8>` would inflate roughly 4 to 5 times and eat into the message cap).
  Decoded images are downscaled to at most 1200 px on the long side before
  crossing.
- **Storage persistence rides the existing reply, rather than a new message
  kind.** `RenderRequest` carries optional `initial_cookies`/
  `initial_local_storage`/`initial_indexed_db` (set only on a freshly-spawned
  process's first `Navigate`); `ServerMessage` carries optional
  `updated_cookies`/`updated_local_storage`/`updated_indexed_db` (set on any
  reply whose store actually changed). `app` is what encrypts and writes
  these, and decrypts and seeds from them - the renderer only ever moves its
  own already-in-memory plaintext bytes across a channel that already
  exists, never the account's encryption key. See `ipc::ServerMessage`'s own
  doc comment for the full reasoning.

## The renderer sandbox

Linux only, implemented in `renderer/src/sandbox.rs` and applied before the
first request is read:

1. **Landlock** (ABI V4, kernel 6.7+ for the network rules, degrading with a
   printed warning on older kernels): read-only access to the TLS trust store
   paths, read/write to only its own cache directory, outbound TCP only to ports
   80 and 443, and no bind.
2. **seccomp-bpf** via `seccompiler`: an allowlist of roughly 55 syscalls, with
   everything else killing the process. The list was derived empirically by
   tracing a real workload, and enforcement was proven by removing one used
   syscall and confirming the renderer died with `SIGSYS` on its next fetch.

seccomp is applied after Landlock because a filter can only ever be narrowed.

The allowlist reflects the environment it was traced in. A new dependency, a new
kind of I/O, or a different libc can need a syscall that is not on the list, and
that shows up as the renderer being killed on that operation. See
[`TESTING.md`](TESTING.md#troubleshooting) for how to recognize and fix it.

On macOS the renderer applies a Seatbelt (`sandbox_init`) profile restricting
filesystem and outbound network access; on Windows it applies a Job Object plus
several `SetProcessMitigationPolicy` hardening policies (dynamic code, win32k
syscalls, extension points, image load, child-process creation). Both are real
code, but unlike Linux's, neither has ever run on the actual OS -- there is no
Mac or Windows machine in this project's own development loop, so both were
written and cross-type-checked (`cargo check --target x86_64-apple-darwin` /
`--target x86_64-pc-windows-gnu`) rather than traced and tested the way Linux's
was. See `renderer::sandbox`'s own module docs for exactly what each does and
doesn't cover, and [`THREAT_MODEL.md`](THREAT_MODEL.md) for the honest caveat.

## Site isolation

`app`'s `RendererPool` (in `app/src/main.rs`) keeps one renderer process per
distinct site that any open tab is showing. Processes are spawned on first need
and killed when no tab references them any more -- "references" means either a
tab's own `renderer_site` (its live, already-loaded session) OR a tab's own
`pending_navigation` (an async `Navigate` still in flight, whose reply hasn't
updated `renderer_site` yet -- see `Life of a page load`'s own note on
asynchronous navigation). Missing that second case was a real bug during
development: an unrelated tab's navigation completing could evict and kill a
DIFFERENT tab's brand new, still-in-flight process before its own reply ever
arrived. Tabs on the same site share a process on purpose, since splitting
them adds overhead with no isolation benefit.

Limits: there are no cross-process iframe boundaries because iframes are not
rendered at all, and the disk cache directory is shared by every renderer
process (though it is partitioned internally by site and holds no secrets).

## `file://` support

`app::site_for_url` routes every `file://` URL, regardless of path, to one
fixed site key (`LOCAL_FILES_SITE`) rather than the real per-eTLD+1 key an
`https://` URL gets - so `RendererPool` spawns exactly ONE renderer process
for all of them, reusing the site-isolation mechanism above as a security
boundary rather than just a crash-isolation one. That one process is spawned
with `--allow-local-files`, which changes two things together (see
`renderer/src/main.rs` and `renderer::sandbox`):

- **`network::FilteringFetcher::enable_local_file_access`** opts it into
  actually serving `file://` fetches at all - every other renderer process
  rejects them outright, at the same chokepoint every fetch (navigation,
  images, stylesheets, scripts, a page's own `fetch()`) already flows
  through.
- **The sandbox** trades broad, unrestricted filesystem read (a root-scoped
  Landlock `PathBeneath` rule on Linux; an unrestricted `file-read*` Seatbelt
  rule on macOS) for giving up outbound network access entirely. Never one
  without the other: broad read access is only safe because this same
  process has no socket to exfiltrate anything it reads through, and no
  other process ever gets that broad read rule.

See `THREAT_MODEL.md`'s network-layer section for the full reasoning,
including the real, disclosed Windows caveat (no OS-level sandbox
enforcement of either half yet on that platform).

## Rendering pipeline notes

- **`css`**: hand-written parser and selector engine. Supports type, class, id,
  attribute (all operators), `>`, `+`, `~` and descendant combinators, selector
  lists, structural pseudo-classes including `:nth-child(An+B)` and `:not()`.
  `:hover` and `:focus` parse but never match. `:visited` is deliberately not
  parsed, closing a history-sniffing side channel. Specificity is the real
  `(id, class, type)` triple.
- **`text`**: `fontdue` rasterization with real font metrics, and one bundled
  font. `font-family` and `@font-face` are deliberately absent, both as a
  fingerprinting-surface decision and to avoid fetching arbitrary font files.
- **`layout`**: block and inline formatting contexts with word-granularity line
  packing, a full box model, adjacent-sibling margin collapsing, floats with
  `clear`, `position: relative/absolute/fixed`, flexbox (row is the full
  algorithm, column is deliberately simpler because the box model has no
  explicit container height), and grid (`fr`, fixed lengths, `repeat()`,
  named areas, `span N`). Numeric line placement such as `grid-column: 2 / 4`
  is not implemented.
- **`render`**: CPU rasterization into an RGBA buffer, then wgpu presents it.
  Mouse-move events do no GPU work at all. This is a hard-won rule: an early
  version rebuilt GPU textures on every mouse-move and exhausted memory. Any
  high-frequency event must have a real reason to trigger GPU work.

## JavaScript

`renderer/src/script.rs` embeds [Boa](https://boajs.dev) (pure Rust). It
provides `setTimeout`/`clearTimeout`, promises and `async` (the job queue is
drained explicitly), `console.*`, `fetch()` (synchronous under the hood but
promise-wrapped, through the filtered fetcher), and a small DOM surface:
`document.title`, `getElementById`, `querySelector(All)`, `createElement`,
`appendChild` (with real move semantics), `get/set/removeAttribute`,
`textContent`, `classList`, `input.value`, and `addEventListener` with capture
and bubble. `RuntimeLimits` bounds loop iterations and recursion depth.

**Web Storage** (`renderer/src/local_storage.rs`) is a real, per-origin,
disk-persisted `localStorage`: the standard method surface
(`getItem`/`setItem`/`removeItem`/`clear`/`key`/`.length`), real property-style
access (`localStorage.foo = "bar"`) via a genuine Boa `Proxy` wrapping that
method surface, and a real cross-tab `storage` event fired into every OTHER
live session on the same origin when one tab's script mutates it (never into
the tab that made the change, matching the real spec). This crate never
writes it to disk itself: it reports its own real, plaintext bytes back to
`app` over the existing IPC channel (`ipc::ServerMessage::
updated_local_storage`), and `app` (the only process that ever holds the
account's encryption key) encrypts, merges, and writes `local_storage.enc`
- see [The IPC protocol](#the-ipc-protocol) and `ipc::ServerMessage`'s own
doc comment for the full design and why persistence had to move there.

**IndexedDB** (`renderer/src/indexed_db.rs`) is a real but deliberately
narrower subset: `indexedDB.open`/`onupgradeneeded`/`onsuccess`,
`createObjectStore`/`deleteObjectStore` with real `keyPath` and
`autoIncrement`, and `transaction`/`objectStore` with `put`/`add`/`get`/
`getAll`/`getAllKeys`/`delete`/`clear`/`count`, all backed by the same
`app`-owned, encrypted disk-persistence pattern as `localStorage`. No
indexes, cursors, key ranges, or cross-connection `versionchange` event yet,
and keys are limited to strings and numbers - see that module's own doc
comment for the exact boundary.

A memory-safe engine removes the memory-corruption exploit class. It does not
make untrusted script safe in a broader sense, and it does not bound wall-clock
time or memory. That is why script still runs inside the sandboxed, site-isolated
renderer.

## Account, storage, and sync

```
storage::SyncPayload  --to_bytes-->  plaintext bytes
        |                                   |
        |                          account::encrypt(key)      (ChaCha20-Poly1305)
        |                                   |
        |                                ciphertext
        |                                   |
        +--(on conflict: decrypt both,      +--> sync::push(account_id, auth_secret, ciphertext, expected_version)
            SyncPayload::merge, retry)
```

- **Account creation** (`account::create_account`) mints a random account ID, a
  15-word BIP-39 recovery code (160 bits of OS CSPRNG entropy), and a random KDF
  salt. There is no email, username, or password.
- **Key derivation** is Argon2id (128 MiB, t=3, p=1) over the recovery code and
  salt, entirely on-device.
- **Two derived secrets**, domain-separated: an encryption key, and an auth
  secret sent to the server. The auth secret cannot be used to derive the
  encryption key, so a server that captures it still cannot decrypt the blob.
- **Encryption** is ChaCha20-Poly1305 with a fresh random nonce per call,
  prepended to the ciphertext. Tampering or a wrong key fails decryption
  loudly.
- **Payload** (`storage::SyncPayload`) holds bookmarks, capped history, and a
  flat settings map. Each setting carries its own timestamp. `merge` combines two
  diverged payloads and keeps data from both sides wherever possible. Download
  records are deliberately **not** synced, since a local file path means nothing
  on another device.
- **Conflicts.** The server keeps an opaque version counter and rejects a stale
  push (`409`). `app` then pulls, decrypts both sides, merges, and retries, up to
  five attempts.
- **Zeroization.** Derived keys and decrypted plaintext are zeroized after use.
  They are not `mlock`ed.

## The sync server

`sync-server` is a small file-backed HTTP server (`tiny_http`). It is
intentionally minimal.

| Method and path | Headers | Body | Success | Errors |
| --- | --- | --- | --- | --- |
| `PUT /accounts/{account_id}` | `Authorization: Bearer <64 hex chars>`, `X-Expected-Version: <n>` (default 0) | ciphertext | `200`, body is the new version | `401` bad auth, `409` version conflict (body is server version), `429` rate limited |
| `GET /accounts/{account_id}` | `Authorization: Bearer <64 hex chars>` | none | `200`, ciphertext body, `X-Version` header | `401`, `404`, `429` |

- **Registration is trust-on-first-use.** The first push for an `account_id`
  stores a SHA-256 hash of the presented auth secret. Later requests must match.
- **Storage.** One file per account, written to a temp file then atomically
  renamed. The account ID is hashed into the filename, so a hostile ID cannot
  traverse paths. Every push first snapshots the version it overwrites into a
  rotating backup set (default 10 per account).
- **Rate limiting.** Per-IP fixed window (30 requests per 60 s) and a per-account
  lockout (10 failed auth attempts, 15 minute cooldown). Both are in-memory.
- **Operator commands.** `--list-backups <account_id>` and
  `--restore <account_id> <version>`. There is deliberately no HTTP route for
  restore.
- **Transport.** Plain HTTP on `0.0.0.0:7878`. TLS must be terminated by a
  reverse proxy. See [`THREAT_MODEL.md`](THREAT_MODEL.md) for the consequences,
  including how the per-IP limiter behaves behind a proxy.

## Data on disk

Client data lives under an OS-standard per-user directory (see the table in
[`README.md`](README.md#where-your-data-lives)). A relative `abyssal-data/`
directory is only a fallback when the relevant environment variables are unset,
and tests always use an isolated temp directory.

| File or directory | Contents | Notes |
| --- | --- | --- |
| `account.txt` | account ID, recovery code, KDF salt (plaintext) | Owner-only (`0o600` on Unix) via `app::write_secret_file`. Still plaintext - tracked in the threat model |
| `bookmarks.enc` | encrypted `SyncPayload` (bookmarks, history, settings) | ChaCha20-Poly1305 under the account-derived key |
| `downloads.enc` | encrypted download records | Local only, never synced |
| `cookies.enc` | encrypted `network::PartitionedCookieJar` bytes | Written by `app`, not `renderer` - see `ipc::ServerMessage`'s own doc comment |
| `local_storage.enc` | encrypted `renderer::local_storage::LocalStorageStore` bytes | Same mechanism as `cookies.enc` |
| `indexed_db.enc` | encrypted `renderer::indexed_db::IndexedDbStore` bytes | Same mechanism as `cookies.enc` |
| `cache/` | partitioned HTTP response cache | Only responses that opt in via `Cache-Control: max-age`. No size cap or eviction yet. Not encrypted - only already-public fetched content |
| `userscripts/` | user-installed `.js` files | Re-read on every navigation |

Downloaded files go to `$HOME/Downloads` (`%USERPROFILE%\Downloads` on Windows),
falling back to a `downloads/` folder in the data directory only if the home
variable is unset.

Server data lives under `ABYSSAL_SYNC_DATA_DIR` (default `sync-server-data/`):
one `.blob` file per account plus `backups/`.

## Deliberate omissions

These are decisions, not oversights. Each is explained in the relevant module
doc.

- **Iframes.** Most in-the-wild iframes are ads and trackers a privacy browser
  wants blocked, and a real implementation needs a new fetch pipeline threaded
  through layout construction for little payoff.
- **`font-family` and `@font-face`.** Fingerprinting surface and untrusted font
  parsing.
- **`:visited`.** History sniffing side channel.
- **Video frame decoding.** No mature pure-Rust decoder for H.264 or VP9.
- **PDF visual rendering.** No mature pure-Rust PDF renderer.
- **Auto-update.** The update checker only notifies. A self-replacing binary is
  itself a supply-chain target and needs a signing story first.
- **WebExtensions.** Only local userscripts. No manifest, permissions model,
  background pages, or store.

## Where to extend it

Each crate's `//!` module doc ends with a prioritized "next steps" list. The
biggest open items, roughly in order of payoff:

1. Getting real macOS and Windows hardware into this project's development
   loop, to actually run (and, on macOS, trace and tighten) the sandboxing
   that already exists in code for both but has never run on either real OS.
2. Fuzzing the `ipc` deserialization boundary.
3. `Content-Type` and charset handling, and response header exposure.
4. `<textarea>` and ARIA in the accessibility tree. POST forms are real now
   (`application/x-www-form-urlencoded` only -- no `multipart/form-data`, so a
   real file-upload `<form>` still won't work).
5. Canvas and WebGL fingerprint noise (needs real API bindings first).
6. A multi-device "restore account from recovery phrase" UI (the BIP-39 decode
   already exists in `account::bip39`).
7. IndexedDB indexes, cursors, and key ranges (`renderer/src/indexed_db.rs`
   covers object stores, `keyPath`, and `autoIncrement` today, deliberately
   short of the full spec).

When you change a boundary, update the relevant module doc, this file, and
[`THREAT_MODEL.md`](THREAT_MODEL.md) in the same pull request.
