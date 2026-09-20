# Abyssal Browser: a study guide

This is a personal reference for understanding how this codebase actually
works, why it's built the way it is, and how the pieces connect to each
other -- written so future changes are easier to make with confidence. It's
not aimed at outside contributors and it's not a replacement for the
project's own "official" docs, which stay authoritative for anything this
guide and the code ever disagree on:

- **`README.md`** -- the pitch, what works today, how to build/run/use it.
- **`ARCHITECTURE.md`** -- the map: process model, crate graph, data flow.
  Every crate's own `//!` module doc comment is the single most current
  source of truth in this codebase -- when in doubt, read the code's own
  comment before trusting anything written here.
- **`THREAT_MODEL.md`** -- the honest security self-review.
- **`TESTING.md`** -- how to run and write tests, troubleshooting.
- **`CONTRIBUTING.md`** -- project rules, dev setup, PR/release process.
- **`CHANGELOG.md`** -- what's actually shipped, in rough chronological order.

This wiki exists because those documents answer "what does this do" and
"what's the rule," but not always "if I wanted to change X, where would I
even start, and what else would I need to understand first." That's what
each numbered file here tries to do for one coherent slice of the system.

## How to use this

Read in order the first time through -- later files sometimes lean on
concepts explained earlier (especially `01`, which almost everything else
assumes you've read). After that, treat it as reference: jump straight to
whichever file covers the area you're about to touch.

| File | Covers | Read this before touching... |
| --- | --- | --- |
| [`01-process-model-and-ipc.md`](01-process-model-and-ipc.md) | The `app`/`renderer` process split, `RendererPool`/`RendererProcess`, the `ipc` crate's message shapes, life of a page load | Anything that crosses the `app`<->`renderer` boundary, or adds a new IPC message/field |
| [`02-dom-html-css-layout-render.md`](02-dom-html-css-layout-render.md) | `dom`, `html`, `css`, `layout`, `render` -- parsing a page into pixels, minus JS | CSS features, layout algorithms, painting, the window itself |
| [`03-javascript-engine.md`](03-javascript-engine.md) | Boa integration, the execution model, DOM/event bindings, `localStorage`/IndexedDB | `renderer/src/script.rs`, adding any new JS API surface |
| [`04-network-and-privacy.md`](04-network-and-privacy.md) | `network` (fetch, DoH, cookies, disk cache) and `privacy` (blocklist, partitioning, fingerprinting defaults) | Fetch behavior, blocklist logic, anything privacy-sensitive |
| [`05-account-storage-sync.md`](05-account-storage-sync.md) | `account` (crypto, recovery code), `storage` (data model), `sync`/`sync-server` (push/pull) | Encryption, the account flow, sync protocol/server |
| [`06-app-ui-and-window.md`](06-app-ui-and-window.md) | `app`'s `Browser`/`Tab`, the toolbar, address bar, `about:` pages, keyboard shortcuts, DevTools | Anything in the window/UI itself |
| [`07-sandboxing.md`](07-sandboxing.md) | Landlock/seccomp (Linux), Seatbelt (macOS), Job Object (Windows), resource limits | `renderer/src/sandbox.rs`, anything that changes what the renderer does on disk/network/syscalls |
| [`08-rust-patterns-glossary.md`](08-rust-patterns-glossary.md) | Recurring patterns and idioms used throughout: `Rc<RefCell<...>>`, version-counter persistence, merge-not-overwrite, fail-closed, testing conventions | Before writing new code, if you want it to look like it belongs here |
| [`09-troubleshooting.md`](09-troubleshooting.md) | Real problems you'll actually hit and how to diagnose them | When something's broken and you're not sure why |

## The one-paragraph mental model

`app` is the privileged process you run: it owns the window, your account,
your decrypted bookmarks, and the encryption keys -- and it **never links an
HTTP client**. Every byte of untrusted content (a fetched page, its HTML,
CSS, JavaScript, images) is handled by a separate `abyssal-renderer`
process, one per site, running inside a real OS sandbox, which **never
receives** your recovery code or encryption keys. The two talk over a
strict request/reply JSON protocol on a pipe. That single asymmetry --
`app` has the secrets and no network access, `renderer` has network access
and no secrets -- is the one idea most worth internalizing before anything
else, because a huge fraction of "why is this built this way" questions
trace back to it. `01-process-model-and-ipc.md` is where that's explained
in full.

## Workspace layout, for orientation

```
dom/        shared Node/Element/Text tree (no deps)
html/       html5ever -> dom::Node
css/        parsing, selectors, cascade, ComputedStyle
text/       font loading, wrapping, glyph rasterization
layout/     block/inline/flex/grid, box model, hit-testing
render/     LayoutBox -> pixels, the window itself (wgpu/winit)
network/    HTTP + DNS-over-HTTPS, filtering, cookies, disk cache
privacy/    blocklist, partitioning, fingerprinting defaults
account/    no-email accounts, key derivation, encryption
storage/    the SyncPayload data model (no crypto, no I/O)
sync/       push/pull of opaque ciphertext
sync-server/ the file-backed HTTP server sync talks to
ipc/        the app<->renderer wire protocol
renderer/   the sandboxed process: fetch, parse, layout, JS, decode
app/        the binary: window, UI, account, sync, the renderer pool
```

Two dependency edges are load-bearing and worth remembering by heart:
`app` never depends on `network`, and `account`/`sync` never depend on each
other. Both are enforced structurally (they're just not in the relevant
`Cargo.toml`), not by convention -- see `ARCHITECTURE.md`'s "Design
principles" for why that distinction matters.

## Keeping this wiki honest

If you change something this wiki describes, update the relevant file in
the same change if you can -- but if a stale sentence here and the actual
code ever disagree, trust the code (and the crate's own `//!` doc comment)
every time. This is a map, written at a point in time, not a spec.
