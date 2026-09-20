# 03. The JavaScript engine

Everything here lives in `renderer/src/script.rs`, which is a big file
(thousands of lines) but a genuinely coherent one. Read its own top-of-file
`//!` doc comment first -- it's one of the most detailed module docs in the
whole codebase and explains several non-obvious design decisions this file
goes into more narratively below.

## Why Boa

[Boa](https://boajs.dev) is a pure-Rust ECMAScript engine, chosen
specifically *because* it's pure Rust. This process already treats
everything about a fetched page as untrusted, attacker-influenced input,
and a JS engine is historically the single largest source of real-world
browser exploits (V8/JavaScriptCore memory-corruption bugs). A memory-safe
engine can't have that class of bug by construction. It can still have
logic bugs (an infinite loop, a stack overflow via recursion) -- that's what
`RuntimeLimits` bounds (500,000 loop iterations, 512 recursion depth, both
named constants at the top of `script.rs` -- `LOOP_ITERATION_LIMIT` and
`RECURSION_LIMIT`, chosen from an actual measured iteration cost, not
guessed).

## The execution model: no real concurrency

There is no event loop in the Node.js sense, no threads, no real async I/O.
Everything happens either:

1. During the **initial script pass** (`Session::new_with_shared_storage`
   runs every `<script>` in document order, then fires `'load'`), or
2. Synchronously, inline, in response to one IPC message: `Tick` (runs due
   timers), `Click` (dispatches a click), `TextInput`/`Focus`/`Blur` (runs
   `input`/`keydown`/`change` handlers), or `EvalConsoleExpression`
   (DevTools).

`fetch()` is the clearest example of what this means in practice: the
actual HTTP request happens **inline**, synchronously, before the native
`fetch()` closure even returns -- through the exact same
`FilteringFetcher` every other request on the tab uses. The result is
then wrapped in an already-settled `JsPromise` (`resolve`/`reject`), which
is what makes `.then()`/`await` on the return value *look* asynchronous to
page script despite there being no real asynchrony underneath at all. Boa's
own promise/microtask queue still needs to be drained explicitly --
`context.run_jobs()` -- after any script execution that might have scheduled
a `.then()` continuation, since `Context::eval` never does this for you.
Miss a `run_jobs()` call after adding a new entry point and you'll get
silently-never-fired `.then()` callbacks, not a crash -- easy to miss in
testing if your test doesn't specifically assert on the callback's effect.

## Why callbacks live in JS state, not Rust state

This is explained at length in `script.rs`'s own module doc, and it's worth
internalizing before you try to add anything that captures a JS function:
Boa's garbage collector is a real **tracing** collector (`boa_gc::Gc`), not
simple refcounting. Holding a `JsFunction` inside a plain Rust struct that
Boa's collector doesn't know how to trace is a real use-after-free hazard --
a GC cycle could free a function this process still holds a dangling handle
to.

So every callback (`setTimeout` callbacks, `addEventListener` callbacks,
both `window`'s own and per-element ones) lives in a plain JS object
reachable from `window` itself, defined in `PRELUDE_JS` (a big JS string
constant near the top of `script.rs`, evaluated once per session). The
Rust side (`HostTimers`) only ever tracks numeric timer IDs and
`std::time::Instant`s -- plain data, safe to hold directly, marked
`unsafe impl Trace` with `empty_trace!()` because there's provably nothing
GC-tracked inside.

If you ever need to capture new Rust state into a native closure, check
whether it could ever contain a `JsValue`/`JsObject`/`JsFunction`. If yes,
it needs real `Trace`/`Finalize` implementations, not `empty_trace!()`. If
you're certain it can't (the existing `HostNode`/`HostTimers`/`HostConsole`/
`FetchState`/`LocalStorageState`/`IndexedDbState` patterns are all "provably
no GC pointers inside" -- see each one's own doc comment for why), then
`empty_trace!()` is fine and is the established pattern.

## DOM surface

`build_document_object`/`build_element_object` construct the JS-visible
`document`/element wrappers. `document.title` (get/set),
`getElementById`/`querySelector(All)` (real selector engine -- reuses
`css::matches`, not a separate parser), `createElement`, `appendChild`
(real DOM move semantics -- `dom::append_child` removes the child from its
old parent first), attribute get/set/remove, `.textContent`, `.classList`,
`.value` on inputs.

Every element lookup builds a **fresh JS wrapper object** around the
underlying `dom::NodeRef` -- `getElementById('x') === getElementById('x')`
is `false` here, unlike a real browser. This is backed by real native data
via `HostNode`'s `NativeObject` impl (`node_from_js_value` recovers the
underlying `dom::NodeRef` from any wrapper), which is what makes passing an
element between functions (`parent.appendChild(child)`) work at all despite
the lack of identity equality. Event listeners are keyed by `dom::NodeId`
(a stable integer), not by the wrapper object, specifically so this
"fresh wrapper every lookup" behavior doesn't break `addEventListener`
across two different lookups of the same real element.

## Event dispatch

`PRELUDE_JS`'s `window.__dispatchEvent(chain, type, extraProps)` is the
real three-phase (capturing → target → bubbling) dispatcher.
`chain` is `[targetId, parentId, ..., rootId]`, built in Rust
(`ancestor_chain`) from live `dom::Node.parent` pointers -- NOT from the
`LayoutBox` tree `app` hit-tested against (that snapshot has no parent
links). The dispatcher supports `stopPropagation`/`stopImmediatePropagation`
but deliberately not `preventDefault` at the *dispatch* level (see the
module doc for why -- `preventDefault` is tracked separately, on the `Event`
object, and read back by `Session::dispatch_click` after dispatch
completes, since whether the click's default action fires is
`app`'s decision, not the renderer's).

Supported real event types: `click`, `keydown`, `input`, `submit`, and (on
`window`, not via the element-chain dispatcher) `storage` -- see below.
`window.__dispatch(type, eventObj)` is the simpler mechanism for
`window`-level events with no DOM ancestor chain at all (`'load'` fires
this way with no `eventObj`; `storage` fires this way *with* one).

## `localStorage`

`renderer/src/local_storage.rs` is the data model
(`LocalStorageStore`, a per-origin `HashMap` with real quota enforcement --
5 MiB, `MAX_BYTES_PER_ORIGIN`). `script.rs` builds the actual JS-visible
object in two layers:

1. `build_local_storage_object` builds `__nativeLocalStorage` -- the real
   method surface (`getItem`/`setItem`/`removeItem`/`clear`/`key`/
   `.length`), registered under an internal name, not `localStorage`
   itself.
2. `PRELUDE_JS` wraps that in a real Boa `Proxy` and installs *that* as
   `window.localStorage`/bare `localStorage`, giving pages real
   property-style access (`localStorage.foo = "bar"`) on top of the method
   surface. The `get` trap returns `undefined` for a missing key (real
   named-property semantics), not `getItem`'s own `null` -- a deliberate,
   documented one-character-of-behavior deviation, chosen because
   `localStorage.foo || fallback` behaves identically either way.

**The cross-tab `storage` event**: `set_item`/`remove_item`/`clear`, after
mutating the store, push a `StorageChange` (origin, key, old value, new
value, source URL) onto a shared queue
(`LocalStorageState::pending_events`). `RendererState::handle_message`'s
tail drains this queue (`dispatch_pending_storage_events`) and, for every
OTHER live `Session` in the same process whose origin matches, calls
`Session::fire_storage_event` -- which evals a small JS snippet that calls
`window.__dispatch('storage', {...})` in *that* session's own `Context`.
Real, spec-shaped fields, never fired back into the tab that made the
change. The one honest caveat: because the IPC protocol is strict lockstep,
mutating another tab's session this way doesn't get reflected back to
`app` until that OTHER tab's own next message -- see `01-process-model-and-
ipc.md`.

Persistence: this crate never writes to disk itself any more. See
`05-account-storage-sync.md` for how `app` now owns encrypting/writing
`local_storage.enc`.

## IndexedDB (`renderer/src/indexed_db.rs`)

A real but deliberately scoped subset: `indexedDB.open`/
`onupgradeneeded`/`onsuccess`, `createObjectStore`/`deleteObjectStore` with
real `keyPath`/`autoIncrement` (including writing the generated key back
into the record when both are set together, matching real spec behavior),
`transaction`/`objectStore` with `put`/`add`/`get`/`getAll`/`getAllKeys`/
`delete`/`clear`/`count`. No indexes, no cursors, no key ranges, no
cross-connection `versionchange` event -- see that module's own doc comment
for the exact line.

The JS-facing layer (`INDEXED_DB_PRELUDE_JS`, also in `script.rs`) is worth
understanding if you ever touch it, because it uses a real trick: every
`IDBRequest` settles via `Promise.resolve().then(...)`, never
synchronously, even though the underlying `__idb*` native call it wraps
already completed by the time the JS-visible `.open()`/`.put()`/etc. call
returns. This matters because real `IDBRequest`s guarantee `onsuccess`/
`onerror` never fire before the calling script has had a chance to assign
them -- deferring via an already-resolved `Promise`'s `.then()` is
guaranteed by spec to run as a microtask, never synchronously, so it
reproduces that guarantee correctly despite this engine having no real
async I/O to wait on.

## `RuntimeLimits`

Set once per `Context`, in `Session::new_with_shared_storage`:
`set_loop_iteration_limit(500_000)`, `set_recursion_limit(512)`. The
500,000 figure isn't arbitrary -- it's derived from a real measured
iteration cost (roughly 3.1µs/iteration in the debug build this workspace
uses for `cargo test`, ~115ns/iteration in `--release`), capping a
worst-case runaway script at about 1.6s in debug and ~57ms in release.
This bounds *script*-level runaway loops specifically. It does NOT bound
native Rust code doing something pathological outside the JS interpreter --
that's what the per-process `setrlimit`/Job Object resource caps in
`renderer::sandbox::resource_limits` exist to catch instead (see
`07-sandboxing.md`).

## If you're adding a new native binding

The two closure-building patterns you'll see throughout this file:

- `NativeFunction::from_copy_closure_with_captures(closure, captured_state)`
  -- the common case, for state that's `Copy` or cheaply `Clone`-able (an
  `Rc<RefCell<...>>`, a small struct of a few fields). Used for almost
  everything: `FetchState`, `LocalStorageState`, `IndexedDbState`,
  `HostTimers`, `HostConsole`.
- `unsafe { NativeFunction::from_closure_with_captures(...) }` -- used where
  the captured state includes something like `HostNode` that needs the
  `unsafe` variant for its exact signature; check an existing call site
  (`build_document_object`'s `title_get`/`title_set`) before reaching for
  this one blind.

Whatever you capture, it needs `Clone + Finalize + Trace` (`JsData` too, if
it's ever stored as native data via `ObjectInitializer::with_native_data`
the way `HostNode` is). Follow the "does this provably contain zero GC
pointers" reasoning above to decide whether `empty_trace!()` is honestly
safe or whether you need a real trace impl.
