# 01. Process model and IPC

This is the single most important thing to understand about this codebase
before touching anything else: **there are two kinds of process, and they
trust each other asymmetrically.**

```
app (privileged, one instance)
    <==  ipc::ClientMessage / ipc::ServerMessage, length-prefixed JSON  ==>
abyssal-renderer (sandboxed, one process per SITE)
```

`app` (package `abyssal`, source in `app/src/main.rs` -- yes, it's one huge
file) is the process you actually run. It owns the window, the account, the
recovery code, derived encryption keys, decrypted bookmarks, and the sync
client. It **never links `network`** -- there is no HTTP client compiled into
it at all, enforced by `app/Cargo.toml` simply not depending on that crate.
Every real fetch, including background stuff like the update checker, goes
through a `renderer` process.

`renderer` (binary `abyssal-renderer`, source in `renderer/src/*.rs`) is
where every byte of untrusted, attacker-influenced content gets touched:
HTML parsing, CSS, layout, JavaScript execution, image/audio/PDF decoding,
the actual network fetch. It runs inside a real OS sandbox (see
`07-sandboxing.md`) and -- this is the load-bearing property -- **it never
receives the account's recovery code, derived encryption keys, or decrypted
bookmarks/settings.** There is no field anywhere in `ipc::RenderRequest` or
any other message `app` sends that carries any of those. If a memory-safety
bug or a hostile page somehow fully compromises a renderer process, there is
nothing in that process worth stealing beyond whatever that one process's
own tabs currently have loaded -- no way to reach into `app`'s secrets. Every
time you add a new field to a message that crosses this boundary, ask
yourself: could this ever legitimately need to be the encryption key, the
recovery code, or plaintext bookmark data? If yes, stop -- that's a real
change to the threat model, not just a new feature.

## Site isolation: `RendererPool`

`app` doesn't talk to one `abyssal-renderer` process -- it talks to a whole
*pool* of them, one per distinct site. This is `RendererPool`
(`app/src/main.rs`), and it's genuinely simple:

```rust
struct RendererPool {
    processes: HashMap<String, RendererProcess>,  // keyed by site, e.g. "example.com"
    cache_dir: PathBuf,
    storage_persistence: StoragePersistence,       // see below
}
```

`get_or_spawn(&mut self, site: &str)` spawns a fresh `RendererProcess` the
first time a site is needed and reuses it for every later tab that also
navigates there. `site_for_url(url)` computes the site key via
`privacy::registrable_domain` -- the real Public Suffix List eTLD+1, not just
the hostname, so `www.example.com` and `example.com` share a process but
`example.com` and `evil.example.com` still do NOT (subdomains of the same
registrable domain do share, by design -- `sub.example.com` and
`example.com` both map to `example.com`).

Why per-site rather than one shared renderer: sandboxing alone protects
`app`'s secrets from a compromised renderer, but it does nothing to stop a
compromised renderer from reading a *different open tab's* DOM, cookies, or
script state if they'd shared a process. One process per site closes exactly
that gap -- a bug triggered by site A's page can't read site B's tab even if
both are open right now.

`evict_unreferenced(&mut self, referenced: &HashSet<String>)` kills any
process no currently-open tab's `renderer_site` field names any more. This
is a real `kill()` -- `SIGKILL`, no graceful-shutdown hook -- which is exactly
why cookies/`localStorage`/IndexedDB persistence has to happen incrementally
after every message rather than "on exit" (see below and `05-*.md` for the
encryption side of this).

**One site key is special: `LOCAL_FILES_SITE`.** `site_for_url` checks the
URL's scheme before it ever computes a registrable domain -- every `file://`
URL, regardless of its actual path, maps to this one fixed key instead. That
routes every local file any tab ever opens to the SAME one dedicated
`RendererProcess`, spawned with a `--allow-local-files` flag no other
process ever receives, which trades broad real filesystem read access for
giving up outbound network access entirely (see `07-sandboxing.md`'s own
section on this for the full reasoning). It's the same `RendererPool`
mechanism above, reused as a security boundary between "the local
filesystem" and "the open internet" rather than just between two different
websites.

## `RendererProcess`: one child, one pipe pair

Each `RendererProcess` owns a real `std::process::Child` plus its piped
stdin/stdout, framed with `ipc::{read_message, write_message}`. The
interesting methods, roughly in the order you'd actually read them:

- **`spawn(cache_dir, storage_persistence)`** -- starts the child with
  `cache_dir` as its one command-line argument (the only filesystem location
  it's allowed to touch -- see `07-sandboxing.md`), piping stdin/stdout but
  **inheriting stderr**, so the renderer's own sandbox-status lines and
  fetch errors show up directly in your terminal. `storage_persistence` is
  a small `StoragePersistence` struct (the account's derived encryption
  key, plus the paths to `cookies.enc`/`local_storage.enc`/
  `indexed_db.enc`) -- cloned into every process this pool spawns.
- **`render(tab_id, request)`** -- sends `Navigate`. On this specific
  process's very first call (`!self.seeded`), it also reads and decrypts
  whatever's currently on disk and stuffs it into `request.initial_cookies`/
  `initial_local_storage`/`initial_indexed_db` before sending -- see the
  "storage persistence" section below.
- **`click`/`focus`/`blur`/`text_input`/`move_keyboard_focus`/
  `activate_focused`/`focus_node`** -- each just wraps the matching
  `ClientMessageKind` variant and calls `send_foreground_action`, which
  respawns-and-retries on a pipe failure (see below) and falls back to
  `Unchanged` if even that fails, rather than surfacing a full error page
  for what's usually a much less disruptive failure than a dead navigation.
- **`tick(tab_id)`** -- sends `Tick`. Deliberately does **not**
  respawn-and-retry: a tick fires in the background, often for a tab
  nobody's even looking at, so silently treating a dead renderer as
  "nothing happened this time" is the right failure mode. The next real
  user action against that tab will discover and recover from the same
  dead process anyway.
- **`check_for_update`** -- sends `CheckForUpdate`, used by the dedicated
  `update_checker_process` (a `RendererProcess` that deliberately isn't
  part of the site pool -- see its own doc comment on why: pool eviction
  would kill it every time no tab happened to reference its "site").
- **`send_with_respawn(message)`** -- the shared "try once, and on a pipe
  failure kill the child, spawn a fresh one, retry exactly once" logic
  `render` and `click`-family methods build on. A respawn loses every
  tab's session state in that renderer (fresh Boa contexts, fresh DOM) --
  this method doesn't try to reconstruct anything beyond resending the one
  message it was asked to send.
- **`try_send(message)`** -- the actual `write_message` + `read_message`
  round trip. This is the **one chokepoint every single message this
  process ever sends a renderer passes through**, which is exactly why it's
  also where `persist_reported_storage` gets called (see below) -- one place
  to intercept every reply, regardless of which higher-level method
  triggered it.

## The `ipc` crate: framing and message shapes

Defined in `ipc/src/lib.rs`. The wire format is a 4-byte length prefix
followed by a JSON body, over the child's stdin/stdout
(`read_message`/`write_message`). `MAX_MESSAGE_LEN` is 64 MiB -- `app`
refuses to allocate for anything bigger than that when it reads a length
prefix from the *less trusted* side, so a compromised renderer can't force
an unbounded allocation just by lying about how much data is coming.

The protocol is **strict lockstep**: every `ClientMessage` gets exactly one
`ServerMessage` reply, always. There is no renderer-initiated push at all --
if the renderer wants `app` to do something later (like fire a
`setTimeout`), it can only ever *report* that fact on its next reply, never
proactively send a message on its own. This is why timers work the way
they do: `RenderSuccess::next_wake_in_millis` tells `app` "this tab has a
pending timer roughly this many milliseconds out," and `app` schedules its
own wake-up via the window event loop (`render::window`'s `Frame::wake_at`)
and sends a real `Tick` when it fires. No polling, no background thread on
either side.

`ClientMessageKind` (client → renderer) variants: `Navigate`, `CloseTab`,
`Tick`, `Click`, `Focus`, `Blur`, `TextInput`, `CheckForUpdate`, `Download`,
`FetchAudioPcm`, `UpdateMediaPlayback`, `EvalConsoleExpression`,
`FetchDomSnapshot`, `MoveKeyboardFocus`, `ActivateFocused`, `FocusNode`.

`ServerMessageKind` (renderer → client) variants: `Rendered(RenderSuccess)`,
`Error(String)`, `Closed`, `Unchanged { next_wake_in_millis }`,
`UpdateCheckResult`, `DownloadResult`, `AudioPcmResult`, `DomSnapshotResult`.

Every `ServerMessage` is `{ tab_id, kind, updated_cookies,
updated_local_storage, updated_indexed_db }` -- the three `updated_*` fields
are `Option<Vec<u8>>`, present only when that particular store actually
changed since the last reply that reported it (see below).

`RenderRequest` (the payload of `Navigate`) carries the URL, an optional
POST body, the top-level host (for first/third-party classification), the
canvas width, the active theme name, the already-filtered list of matching
userscripts' raw source, and the three optional `initial_*` seed fields.

## Storage persistence rides the existing channel

Cookies, `localStorage`, and IndexedDB all used to be written straight to
disk **by the renderer itself**, in plaintext. That changed (see the
`05-account-storage-sync.md` file for the encryption side, and
`git log`/`CHANGELOG.md` if you want the exact history) -- the renderer
never gets the account's encryption key, so it can no longer be the one
writing these files. Instead of adding new message types for this, the
existing `Navigate` request and every `ServerMessage` reply just got three
extra optional fields each:

- `RenderRequest::initial_cookies` / `initial_local_storage` /
  `initial_indexed_db` -- set ONLY by `RendererProcess::render`, ONLY on
  that specific process's first-ever `Navigate`. `app` reads and decrypts
  `cookies.enc`/`local_storage.enc`/`indexed_db.enc` right there and
  attaches the real plaintext bytes. The renderer merges them into its
  live, in-memory stores via each type's own real `merge_into` (see
  `renderer::RendererState::seed_storage_from_request`).
- `ServerMessage::updated_cookies` / `updated_local_storage` /
  `updated_indexed_db` -- set by the renderer, on ANY reply, whenever that
  store's own version counter changed since the last reply that reported
  it (`RendererState::reported_cookies_if_changed` and its two siblings).
  `app`'s `RendererProcess::try_send` checks these on every single
  incoming reply and, if present, encrypts and merges them into the
  matching `.enc` file (`persist_reported_storage` →
  `persist_encrypted_merge`).

Why this design instead of a dedicated message type: it needed zero new
round trips (persistence just rides whatever message was already being
sent for an unrelated reason) and it keeps the "renderer never holds the
key" property completely intact -- the renderer only ever moves its own
already-in-memory plaintext bytes across a channel that already existed.

One real wrinkle worth knowing if you touch this: `app` can't depend on the
`network`/`renderer` crates (the "`app` never links `network`" boundary is
structural, not just a style rule), so it can't call the real, typed
`merge_into` methods on `PartitionedCookieJar`/`LocalStorageStore`/
`IndexedDbStore` directly. `app::merge_persisted_json` reimplements the same
"overwrite only the entries this report has an opinion on" semantics
generically over raw `serde_json::Value`, keyed by field name(s)
(`"origin"` for `localStorage`/IndexedDB, the compound
`["top_level_site", "resource_host"]` for cookies). If you ever change any
of those three types' on-disk JSON shape, you have to update
`merge_persisted_json` by hand -- nothing checks that they stay in sync.

## Life of a page load, end to end

1. **Input.** User types a URL, clicks a link, or presses back.
   `Browser::navigate_without_history_with_body` (in `app/src/main.rs`)
   resolves it and builds an `ipc::RenderRequest`.
2. **Pick a process.** `site_for_url(url)` computes the site key,
   `self.renderers.get_or_spawn(&site)` reuses or spawns.
3. **Send.** `RendererProcess::render` seeds if needed, then sends
   `Navigate` through `send_with_respawn`.
4. **Fetch (renderer).** `renderer::navigate` runs `FilteringFetcher`
   (blocklist, redirect-hop checking, DoH, TLS), parses HTML, builds the
   author stylesheet, runs scripts, resolves images/media/stylesheets, and
   builds a `script::Session`.
5. **Layout (renderer).** The session's DOM gets laid out into a
   `layout::LayoutBox` tree with real pixel geometry.
6. **Reply.** `ServerMessageKind::Rendered(RenderSuccess)` goes back: the
   tree, the title, page signals, console messages, `next_wake_in_millis`,
   and (if anything changed) the three `updated_*` storage fields.
7. **Paint (app).** `render::paint` rasterizes the tree, `render::window`
   presents it, `app::accessibility` rebuilds the `accesskit` tree from the
   same `LayoutBox`.

Clicks are special: `app` never sends pixel coordinates to the renderer at
all. It hit-tests locally against the `LayoutBox` snapshot it already has
(`layout::hit_test_node`) and sends only the resolved `dom::NodeId`. The
renderer then walks the *live* DOM's real parent pointers to build that
node's actual ancestor chain and runs the real three-phase (capture/target/
bubble) event dispatch from there. `app` applies the click's default action
(link navigation) only if nothing along that chain called
`preventDefault()` -- see `03-javascript-engine.md` for the dispatch
mechanics themselves.

## Gotchas for future you

- **A `Click`/`Focus`/etc. for a stale `dom::NodeId` is not an error.** The
  page could have navigated between `app` resolving the hit-test and the
  message arriving. Both sides model this as `Unchanged`, not `Error` -- if
  you're adding a new per-node message kind, follow that pattern.
- **A respawn silently drops all of that process's session state.** Every
  tab on that site loses its live Boa context, its DOM, its pending timers.
  This is accepted as a rare, recoverable failure, not defended against --
  don't build a message kind that assumes state survives a respawn.
- **`seeded` resets to `false` on respawn**, deliberately. A genuinely
  fresh child process really does start with empty in-memory stores and
  genuinely does need re-seeding, so this is correct, not a bug to "fix."
- **If you add a new field to `ClientMessage`/`ServerMessage`, ask whether
  it needs to be OPTIONAL** with a sane default for old messages that don't
  set it (`#[serde(default)]`), especially if it's meant to only fire under
  specific conditions like the storage fields do.
