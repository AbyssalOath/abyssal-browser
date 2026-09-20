# 08. Rust patterns and idioms glossary

This codebase reuses the same handful of patterns over and over, in
different crates, for the same reasons each time. Once you recognize one,
you'll spot it everywhere -- this file is a cheat sheet so you don't have to
rediscover each one from scratch the first time you meet it.

## `Rc<RefCell<T>>` for shared, mutable, single-threaded state

Everywhere something needs to be visible and mutable from more than one
place *within one process*, and that process is single-threaded (every
process in this codebase is -- `app`'s window loop, each renderer's message
loop), it's `Rc<RefCell<T>>`, never `Arc<Mutex<T>>`. Examples:
`FilteringFetcher` (shared between every tab's script's own `fetch()`
closure and the renderer's own top-level fetch), `LocalStorageStore`/
`IndexedDbStore` (shared across every tab in one renderer process, which is
literally what makes two tabs on the same origin see each other's writes
live). If you ever reach for `Arc`/`Mutex` in this codebase, stop and ask
whether you've actually introduced real threading, because nothing here
does that within a single process.

## The version-counter-gated report pattern

`PartitionedCookieJar::version()`, `LocalStorageStore::version()`,
`IndexedDbStore::version()` are all a plain `u64` bumped on every real
mutation, never on a read. The consuming side (now `app`'s
`RendererProcess`, via `RendererState::reported_cookies_if_changed` and
its two siblings) remembers the version as of the last time it actually
reported/persisted, and only does real work (serialize, encrypt, write)
when the current version differs. This is what makes the frequent,
otherwise-unrelated `Tick` a playing `<audio>` element's progress bar sends
every 250ms a genuine no-op for storage persistence, rather than a
serialize-and-encrypt cycle 4 times a second. If you add a new piece of
state that needs "only act when this actually changed" semantics, this is
the established shape: a `version()` getter, bumped exactly at each real
mutation site, never elsewhere.

## Merge-not-overwrite, keyed by ownership

`PartitionedCookieJar::merge_into`, `LocalStorageStore::merge_into`,
`IndexedDbStore::merge_into` all have the identical shape: copy every
key/entry *this* instance has an opinion on into the target, leave
everything else in the target untouched. This exists because several
independent renderer processes (one per site) each only ever create
entries for their own site/origin -- so a later save from site B must never
be allowed to clobber an earlier save's entries for site A, even though
both eventually land in the same on-disk file. If you're persisting
anything that multiple independent writers might touch, this is the
pattern, not "read, replace, write."

One real wrinkle: `app` can't depend on `network`/`renderer` (see below),
so it can't call these real, typed methods directly for the encrypted
`.enc` files -- `app::merge_persisted_json` reimplements the exact same
semantics generically over raw `serde_json::Value`, keyed by field name(s)
each store's own `to_bytes` doc comment documents. If you change any of
those three on-disk JSON shapes, you have to update that function by hand.

## Fail closed, not fail open

Stated as a project rule in `CONTRIBUTING.md`, and it shows up everywhere
in the actual code: a DoH failure fails the whole fetch rather than
silently falling back to plaintext DNS. A malformed/undecryptable
`.enc` file on load just means "start empty" (never "crash," never
"silently pretend it succeeded with wrong data"). A blocked subresource
simply doesn't load -- no error banner, no partial fallback content. When
you add a new failure path, ask which of these two shapes it should be:
"stop doing the risky thing" (fail closed -- the default for anything
privacy/security relevant) or "degrade gracefully and log it" (the
default for content that's just wrong/malformed, not adversarial).

## Hand-built JSON via `serde_json::Value`, not `#[derive(Serialize)]`

`network::PartitionedCookieJar`, `renderer::local_storage::
LocalStorageStore`, and `renderer::indexed_db::IndexedDbStore` all
serialize via hand-built `serde_json::json!({...})` calls and manual
`from_bytes` parsing, specifically so those crates only need to depend on
`serde_json`, not the full `serde` derive machinery. This is a deliberate,
per-crate choice, not a blanket rule -- `storage::SyncPayload` (a different
crate, syncing to a server rather than crossing the app/renderer trust
boundary) uses ordinary `#[derive(Serialize, Deserialize)]` instead. If
you're adding a new on-disk/on-wire format, check what the crate it lives
in already does before picking a style.

## The `derive fresh` vs `cache once` key-derivation tradeoff

`account::derive_key` is deliberately, intentionally *slow* (Argon2id, 128
MiB, t=3) -- that's the whole point, it resists brute force. Every existing
call site except one re-derives it fresh, right before use, and lets the
`Zeroizing` wrapper drop (and wipe) it immediately after -- `save_bookmarks`,
`save_download_history`, and friends all do this, because those are rare,
explicit user actions (add a bookmark, finish a download). The one
exception is `app::StoragePersistence::encryption_key`, cached for the
whole process's lifetime specifically because cookie/`localStorage`
writes can happen on nearly every navigation or script interaction -- 
re-deriving Argon2id that often would visibly stall the single-threaded UI
event loop. If you add a new encrypted-at-rest thing, think about how
*often* it saves before deciding which of these two shapes to copy.

## Boa GC tracing: what needs `Trace`, what can be `empty_trace!()`

Covered in depth in `03-javascript-engine.md`. The short version: any Rust
struct captured into a native JS closure needs `Clone + Finalize + Trace`.
If you can prove it contains zero `JsValue`/`JsObject`/`JsFunction`
anywhere inside (a plain `Rc<RefCell<PlainRustData>>`, a `String`, numbers),
`unsafe impl Trace { empty_trace!(); }` is honest and is the established
pattern (`HostNode`, `HostTimers`, `HostConsole`, `FetchState`,
`LocalStorageState`, `IndexedDbState` all do this, each with a doc comment
explaining *why* it's provably safe for that specific type). If it could
ever hold a live JS value, it needs a real trace implementation instead --
getting this wrong is a genuine use-after-free hazard, not just a lint.

## `unsafe`: isolated, documented, rare

Every `unsafe` block in this codebase has a `// SAFETY:` comment explaining
exactly what invariant makes it sound, right above it -- not a blanket
justification once per file. The real uses cluster in a few predictable
places: raw FFI (`renderer::sandbox`'s macOS `sandbox_init`/Windows Job
Object/mitigation-policy calls, all through officially-generated or
long-stable bindings, never hand-rolled struct layouts), and a couple of
Boa closure-building calls that need the `unsafe` variant of
`NativeFunction::from_closure_with_captures` for their exact signature. If
you're about to write `unsafe`, look for an existing, similar use first --
the SAFETY-comment convention and the general "isolate it, document the
invariant" rule are both hard requirements per `CONTRIBUTING.md`, not
just style preferences.

## Testing conventions

- **Fake vs. real, chosen deliberately per test.** `network::FakeFetcher`
  (register a URL, get a canned response back) is used everywhere a test
  doesn't specifically need real network behavior. A handful of tests in
  `app` and `renderer` deliberately DO hit real servers (`example.com`,
  `httpbin.org`) -- always with a comment explaining *why* a fake couldn't
  prove the thing being tested (e.g. "a real, independent server actually
  receiving a real POST is the one thing a fake fetcher could never
  prove").
- **`test_browser()`/`state_with()`-style helpers** give every test an
  isolated temp directory, never the real `abyssal-data`/OS data
  directory -- critical since `cargo test`'s default parallelism means
  tests sharing real on-disk state would be flaky and could pollute a
  real user's actual browsing history.
- **Cross-compilation type-checking for platforms with no real hardware
  available.** `cargo check --target x86_64-apple-darwin` /
  `--target x86_64-pc-windows-gnu` catches real API mistakes (wrong struct
  fields, wrong constant names) in macOS/Windows-only code without ever
  running on that OS. When the FULL crate can't cross-compile (a
  transitive C dependency like `aws-lc-sys` needs a real cross-linker this
  environment doesn't have), an isolated scratch crate containing just the
  new platform-specific code (with only its own direct dependencies, e.g.
  `libc` or `windows-sys`) works around that and still catches the same
  class of real error.
- **Empirical verification over trusting a success return value**, for
  anything security-relevant. A `setrlimit`/`SetInformationJobObject` call
  reporting success doesn't prove the OS is actually enforcing it -- the
  real check reads `/proc/<pid>/limits` back from a live process. A
  seccomp allowlist change gets proven by actually triggering a `SIGSYS`,
  not just by reasoning that a syscall "should" be covered.

## Naming and doc-comment conventions

Doc comments in this codebase explain **why**, not what -- a well-named
function already says what it does; the comment exists for the part a
reader can't get from the signature (a hidden constraint, a numeric choice
that was measured rather than guessed, a tradeoff that was made
deliberately). If you're writing a comment that just restates the function
name in prose, delete it. Cross-references between files use the exact
`crate::path::Item` or `` `Type::method` `` form so they're
greppable -- follow that when you add your own.

## Where these rules come from

Most of this is written down explicitly in `CONTRIBUTING.md`'s "Project
rules" and "Code style" sections -- that file is the actual source of truth
for what's a hard rule vs. what's just an observed convention; this page
is descriptive, that one is normative.
