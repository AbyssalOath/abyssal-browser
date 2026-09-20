//! JavaScript execution, via [Boa](https://boajs.dev) — a pure-Rust
//! ECMAScript engine, chosen specifically *because* it's pure Rust:
//! this process already treats everything about a fetched page as
//! untrusted, attacker-influenced input, and a JS engine is
//! historically the single largest source of real-world browser
//! exploits. A memory-safe engine can't have V8-style memory-
//! corruption bugs by construction — it can still have logic bugs, but
//! that's a fundamentally smaller risk class, and it's the one this
//! module can actually do something about (see `RuntimeLimits` below).
//!
//! Scope — deliberately narrow, real, and testable rather than broad
//! and half-working:
//!   - **External `<script src="...">` is fetched now** (see
//!     `extract_scripts`/`resolve_and_fetch_scripts`), through the SAME
//!     blocklist-checking, cache-aware `FilteringFetcher` real page
//!     fetches use — a tracker script embedded via `<script
//!     src="https://ads.example.com/x.js">` is checked and can be
//!     blocked exactly like any other third-party subresource.
//!   - **A `Session` persists per tab now** (see that struct):
//!     `RendererState` keeps one alive across messages, not just for
//!     the initial `Navigate`. That's what makes `setTimeout` real
//!     instead of a `ReferenceError`: a callback registered during the
//!     initial script pass can run LATER, when `app` sends
//!     `ipc::ClientMessageKind::Tick` (see `Session::tick`) — see
//!     `ipc`'s module docs for how `app` knows when to send one
//!     (`render::window`'s `Frame::wake_at`/`InputEvent::Tick`, not
//!     polling).
//!   - **`click` dispatch works now, with real bubbling/capturing and
//!     a real `Event` object** (see `dispatch_click` and
//!     `PRELUDE_JS`'s `window.__dispatchEvent`): `app` resolves a
//!     click's pixel coordinates down to a `dom::NodeId` itself
//!     (`layout::hit_test_node`, against the `LayoutBox` snapshot it
//!     already has — see that type's `dom_node_id` field and
//!     `ipc::ClientMessageKind::Click`'s doc comment) and hands back
//!     just that id; this module then walks the LIVE DOM's real parent
//!     pointers to build that node's full ancestor chain
//!     (`ancestor_chain`) and runs the standard three-phase event flow
//!     over it — capturing (root down to the target's parent), then
//!     AT_TARGET, then bubbling (back up to the root) — exactly like a
//!     real browser, including `event.target`/`currentTarget`,
//!     `stopPropagation`, `stopImmediatePropagation`, and
//!     `preventDefault` (see `ClickOutcome::default_prevented`, which
//!     is how `app::Browser::handle_click` finds out a listener called
//!     it, and does something real with that: it's the difference
//!     between a link click still navigating or not). What's still
//!     missing: only `click` ever gets dispatched — no other event
//!     types exist on elements yet.
//!   - **DOM surface**: `document.title` (get/set), `document.
//!     getElementById`/`querySelector`/`querySelectorAll`,
//!     `document.createElement`, and on an element: `.textContent`
//!     (get/set), `.classList.{add,remove,contains}`,
//!     `.{get,set,remove}Attribute`, `.appendChild`,
//!     `.querySelector`/`.querySelectorAll` (scoped to that element's
//!     own descendants, never itself — real `querySelector` semantics),
//!     and `.addEventListener(type, callback, useCapture)`.
//!     `querySelector(All)` reuses `css`'s REAL selector engine
//!     (`css::matches`) — the same combinators/attribute-selectors/
//!     pseudo-classes the stylesheet cascade understands are reachable
//!     from script too, not a separate, smaller parser. `appendChild`
//!     is real DOM move semantics (`dom::append_child` removes the
//!     child from its old parent first — see that function's own doc
//!     comment), so re-appending an already-attached element works
//!     correctly, not just appending a freshly `createElement`d one.
//!     What's still missing: no attribute access beyond a handful of
//!     properties (no `style`/`dataset`/etc.), no `removeChild`/
//!     `insertBefore`/`replaceChild`, no event types besides `click` on
//!     elements and `load` on `window`, and `Element.matches()` (the
//!     single-node version of `querySelector`) isn't exposed even
//!     though `css::matches` already does the real work underneath.
//!     Each call to `getElementById`/`querySelector`/etc. still builds
//!     a FRESH JS wrapper object around the underlying node rather than
//!     caching/reusing one (now backed by real native data via
//!     `HostNode`'s `NativeObject` impl — see `node_from_js_value` —
//!     which is what makes passing one element into ANOTHER function,
//!     e.g. `parent.appendChild(child)`, possible at all; identity
//!     equality is the one thing this still doesn't give you), so
//!     `getElementById('x') === getElementById('x')` is `false` here
//!     even though real DOM identity would say `true` — but listeners
//!     registered through two different wrappers for the SAME node
//!     still share one registry, keyed by `dom::NodeId` rather than by
//!     the wrapper object itself (see `PRELUDE_JS`'s
//!     `__makeEventTarget`), so this limitation doesn't affect
//!     `addEventListener` specifically the way it would something like
//!     a future `element.dataset`.
//!   - **`fetch(url)` is real now** (GET only — no request headers/
//!     method/body, and no `Headers`/streaming `body` on the response
//!     either): see `setup_globals`'s own doc comment on how a
//!     synchronous-underneath, Promise-wrapped implementation works at
//!     all in an engine with no real concurrency, and `FetchState`'s
//!     doc comment for why it shares the exact SAME
//!     `FilteringFetcher` (cookies, disk cache, blocklist) every other
//!     request on the tab already uses — a `fetch()` to a third-party
//!     tracker from a page's own script is blocked exactly like a
//!     third-party `<script src>`/`<img src>` would be. `response.text()`
//!     and `.json()` are both real (the latter by calling the REAL
//!     global `JSON.parse` as an ordinary function call — see
//!     `json_parse`'s doc comment for why NOT by interpolating the body
//!     into `eval`-ed source text).
//!   - **`window.addEventListener`**: `'load'` fires exactly once,
//!     synchronously, after the initial script pass. `'storage'` (see
//!     `StorageChange`/`Session::fire_storage_event`) is the other
//!     real `window`-level event type — fired into every OTHER live
//!     `Session` on the same origin when one tab's script mutates
//!     `localStorage`, matching real cross-tab behavior, though (see
//!     `fire_storage_event`'s own doc comment) `app` won't observe the
//!     resulting DOM change in that OTHER tab until the next message
//!     that happens to target it. No other `window`-level event types
//!     exist.
//!   - **`localStorage` supports real property-style access**
//!     (`localStorage.foo = "bar"`, `localStorage.foo`, `delete
//!     localStorage.foo`, `for...in`) on top of the method surface,
//!     via a real `Proxy` — see `PRELUDE_JS`'s own comments on it and
//!     `local_storage`'s module docs for what's still out of scope
//!     (IndexedDB, covered by the separate `indexed_db` module).
//!
//! **Why `setTimeout` callbacks AND `addEventListener` callbacks (both
//! `window`'s own and per-element ones) live in JS state, not Rust
//! state**: Boa's garbage collector is a real TRACING collector (see
//! `boa_gc::Gc`), not simple refcounting — holding a `JsFunction` value
//! inside a plain Rust struct that Boa's collector doesn't know how to
//! trace is exactly the "use after free" hazard `boa_gc::Trace`'s own
//! docs warn about (a collection cycle could free a function this
//! process still holds a dangling handle to). So all of them live in
//! plain JS objects reachable from `window` itself (see `PRELUDE_JS`)
//! — already correctly traced by Boa's own object graph, since
//! `window` is a real GC root. The Rust side (`HostTimers`) only ever
//! tracks numeric timer ids and `std::time::Instant`s — plain data,
//! safe to hold directly. The DOM bindings (`document.title`,
//! `getElementById`, etc.) have the opposite problem and the opposite
//! fix: they capture `dom::NodeRef` (this crate's own
//! `Rc<RefCell<..>>` tree, a completely separate object graph with no
//! Boa GC pointers inside it at all), wrapped in `HostNode` and marked
//! `empty_trace!()` — safe specifically because there is provably
//! nothing in it for Boa's collector to need to find.
//!
//!   - **Promises/`async`/`await` actually run now.** Boa's own
//!     `Context::eval` never drains its job queue (verified by reading
//!     `boa_engine`'s source — nothing in `eval` calls `run_jobs`), so
//!     without this crate calling `Context::run_jobs()` itself, EVERY
//!     `.then()` callback and EVERY `async function` continuation
//!     would silently never run at all — a script using either would
//!     look like it hung partway through, with no error anywhere.
//!     `Session` now calls `run_jobs()` after the initial script pass,
//!     after `'load'` fires, after every due timer in `tick`, and after
//!     `dispatch_click` — everywhere script can run. Verified with real
//!     tests (`promise_then_callback_runs_after_the_initial_script_pass`,
//!     `async_await_resolves_a_promise_and_continues_the_function`),
//!     not just assumed from the engine's own documentation, since Boa
//!     is a from-scratch ECMAScript implementation (not V8/
//!     SpiderMonkey) and real-world spec coverage for something this
//!     central to modern JS is worth checking directly.
//!
//! Next steps, roughly in order of payoff:
//!   1. `Element.matches(selector)` — trivial to add now (`css::matches`
//!      already does the work `querySelector` uses), just not wired up
//!      as its own single-node method yet. A real element-identity
//!      CACHE (so `getElementById('x') === getElementById('x')` is
//!      `true`) is the harder remaining half of "real element
//!      identity" — the native-data piece landed (see `HostNode`'s doc
//!      comment), but nothing memoizes wrapper objects per node yet.
//!   2. `RuntimeLimits` bounds recursion depth and loop iterations, but
//!      NOT wall-clock time or memory — a script with few iterations
//!      but expensive per-iteration work (e.g. building a huge string)
//!      could still run for a long time or allocate a lot. Not covered
//!      yet. Also worth noting: EACH `Session::tick`/`dispatch_click`
//!      re-applies the same limits fresh per callback, but there's no
//!      OVERALL cap on how many timers can be scheduled at once — a
//!      script that calls `setTimeout` in a tight (bounded) loop could
//!      still queue an unreasonable number of pending callbacks.

use boa_engine::object::builtins::{JsArray, JsPromise};
use boa_engine::object::{JsObject, ObjectInitializer};
use boa_engine::property::Attribute;
use boa_engine::{js_string, Context, JsError, JsNativeError, JsValue, NativeFunction, Source};
use boa_gc::{empty_trace, Finalize, Trace};
use std::cell::RefCell;
use std::rc::Rc;

use crate::devtools;
use crate::indexed_db::{self, IndexedDbStore};
use crate::local_storage::{self, LocalStorageStore};
use crate::media;

/// Chosen from an actual measurement, not a guess: an empty `while`
/// loop runs at roughly 3.1µs/iteration in this workspace's unoptimized
/// `cargo build`/`cargo test` profile (`[profile.dev] opt-level = 0` —
/// see the root `Cargo.toml`) and roughly 115ns/iteration in
/// `--release` (~27x faster — real users only ever run the release
/// binary). 500,000 caps a worst-case runaway script at ~1.6s even in
/// the slow debug profile and ~57ms in release, while still being far
/// more headroom than the handful of DOM calls this MVP's script
/// surface can even meaningfully loop over.
const LOOP_ITERATION_LIMIT: u64 = 500_000;
/// Boa's own crate default (512) is already reasonable; set explicitly
/// here so this value is a deliberate choice on record, not "whatever
/// the dependency happens to default to today."
const RECURSION_LIMIT: usize = 512;

/// Installed once per `Session`, before any page script runs:
///   - `window.addEventListener`/`window.__dispatch`: `'load'`
///     listener storage/firing (see this module's docs on why this —
///     not a Rust struct — is where callbacks have to live).
///   - `window.setTimeout`/`clearTimeout`/`window.__runDueTimer`: the
///     JS-visible half of timer support. `__scheduleNative`/
///     `__cancelNative` (registered as bare globals, not on `window` —
///     they're internal plumbing, not real Web APIs) are the only
///     parts that touch Rust state (`HostTimers`), and they only ever
///     pass plain numbers (a timer id, a delay in milliseconds) across
///     that boundary — the actual callback stays in the `timers` JS
///     object here the whole time.
///   - `window.__makeEventTarget`/`window.__dispatchEvent`: the
///     per-element listener registry `build_event_target` (in
///     `build_element_object`) and `Session::dispatch_click` are built
///     on top of, including real capturing/bubbling and a real
///     `Event` object (`target`/`currentTarget`/`stopPropagation`/
///     `stopImmediatePropagation` — NOT `preventDefault`, see this
///     module's top-level docs) — see this constant's own inline
///     comments below for why the registry is keyed by `dom::NodeId`
///     rather than by any JS object.
const PRELUDE_JS: &str = r#"
(function () {
    var listeners = {};
    window.addEventListener = function (type, callback) {
        if (!listeners[type]) { listeners[type] = []; }
        listeners[type].push(callback);
    };
    // `eventObj` is optional — every existing `'load'` call site omits
    // it (each listener there takes no arguments anyway), which is
    // `undefined` here and simply passed straight through. The
    // `'storage'` event (see `Session::fire_storage_event`) is the one
    // real caller that relies on it, the same way `__dispatchEvent`'s
    // own `extraProps` lets a caller enrich an element-targeted event.
    window.__dispatch = function (type, eventObj) {
        var list = listeners[type];
        if (!list) { return; }
        for (var i = 0; i < list.length; i++) {
            list[i](eventObj);
        }
    };

    var timers = {};
    var nextTimerId = 1;
    window.setTimeout = function (callback, delay) {
        var id = nextTimerId++;
        timers[id] = callback;
        __scheduleNative(id, delay || 0);
        return id;
    };
    window.clearTimeout = function (id) {
        delete timers[id];
        __cancelNative(id);
    };
    window.__runDueTimer = function (id) {
        var cb = timers[id];
        delete timers[id];
        if (cb) { cb(); }
    };

    // Real pages call `setTimeout(...)`/`clearTimeout(...)` as bare
    // globals, not `window.setTimeout(...)` — in a real browser that
    // works because `window` IS the global object. Here `window` is
    // just a regular object registered as a global property (see
    // `setup_globals`), so the bare names need their own aliases.
    setTimeout = window.setTimeout;
    clearTimeout = window.clearTimeout;
    addEventListener = window.addEventListener;

    // `__nativeFetch` (see `setup_globals`) is the real implementation;
    // both `window.fetch` and bare `fetch` are just aliases to it, the
    // same pattern as `setTimeout`/`addEventListener` above.
    window.fetch = __nativeFetch;
    fetch = window.fetch;

    // Per-element listener storage, keyed by `dom::NodeId` (see that
    // type's doc comment) rather than by any JS-visible handle to the
    // element itself — `getElementById` builds a FRESH wrapper object
    // every call (see this module's own scope note), so two lookups of
    // the same element are two different JS objects; a registry keyed
    // by the underlying node's stable id is what makes a listener
    // registered through one lookup still fire when `dispatch_click`
    // (Rust) later names that same id after a completely separate IPC
    // round trip. Lives entirely in JS state for the same Boa-GC-
    // tracing reason `window`'s own listeners/timers do (see this
    // module's top-level docs) — a callback is never held by anything
    // on the Rust side.
    //
    // Each entry is `{ callback, capture }` in ADDITION order (not
    // split into two separate capture/bubble arrays) specifically so
    // the AT_TARGET phase below can replay them in the exact order
    // they were registered, matching the real spec: at the target
    // itself, capture- and bubble-registered listeners are not
    // distinguished, only elsewhere in the chain are they filtered by
    // phase.
    var elementListeners = {};
    window.__makeEventTarget = function (nodeId) {
        return {
            addEventListener: function (type, callback, options) {
                var capture = options === true || (options != null && options.capture === true);
                if (!elementListeners[nodeId]) { elementListeners[nodeId] = {}; }
                if (!elementListeners[nodeId][type]) { elementListeners[nodeId][type] = []; }
                elementListeners[nodeId][type].push({ callback: callback, capture: capture });
            }
        };
    };

    // `chain` is `[targetId, parentId, ..., rootId]` — the target's
    // real DOM ancestor chain, built in Rust (`ancestor_chain`) from
    // live `dom::Node.parent` pointers, NOT derived from the
    // `LayoutBox` tree `app` hit-tested against (that snapshot has no
    // parent links at all — see `layout::LayoutBox`'s doc comment).
    // Implements the real three-phase DOM event flow (capturing, then
    // AT_TARGET, then bubbling) with `stopPropagation`/
    // `stopImmediatePropagation`, but NOT `preventDefault` — see this
    // module's top-level docs for why that's a deliberate, separate
    // gap, not an oversight. `renderer::script::Session::dispatch_click`
    // is this function's only caller — it never runs unless `app`
    // already resolved a real click to this exact chain (see
    // `ipc::ClientMessageKind::Click`'s doc comment), so a chain with
    // no registered listeners anywhere on it (the common case — most
    // elements never call `addEventListener` at all) is expected, not
    // an error; this is a silent no-op for it.
    //
    // `extraProps` (optional — every existing `click` call site omits
    // it, which is `undefined` here and skipped below) lets a caller
    // merge extra properties onto the built event object before
    // dispatch — `handle_text_input`'s `keydown` dispatch uses this to
    // set a real `event.key` (`"a"`, `"Backspace"`, `"Enter"`, ...)
    // without this function needing to know about every possible key
    // itself.
    window.__dispatchEvent = function (chain, type, extraProps) {
        var event = {
            type: type,
            target: __resolveEventTarget(chain[0]),
            currentTarget: null,
            bubbles: true,
            cancelable: true,
            defaultPrevented: false,
            _stopped: false,
            _stoppedImmediate: false,
            preventDefault: function () { if (this.cancelable) { this.defaultPrevented = true; } },
            stopPropagation: function () { this._stopped = true; },
            stopImmediatePropagation: function () { this._stopped = true; this._stoppedImmediate = true; }
        };
        if (extraProps) {
            for (var extraKey in extraProps) { event[extraKey] = extraProps[extraKey]; }
        }

        // Runs every entry at `nodeId` matching `wantCapture` (or, for
        // the AT_TARGET call below, every entry regardless of phase —
        // see `filterByCapture`). A listener that throws is caught and
        // dropped right here rather than letting the exception escape
        // this whole dispatch: one buggy listener must not silently
        // cancel every OTHER listener still waiting in the same chain,
        // capturing ancestors and bubbling ones alike.
        function runAt(nodeId, filterByCapture) {
            var entries = elementListeners[nodeId] && elementListeners[nodeId][type];
            if (!entries) { return; }
            event.currentTarget = __resolveEventTarget(nodeId);
            for (var i = 0; i < entries.length; i++) {
                if (event._stoppedImmediate) { return; }
                if (filterByCapture !== null && entries[i].capture !== filterByCapture) { continue; }
                try { entries[i].callback(event); } catch (e) { /* see this function's doc comment */ }
            }
        }

        for (var i = chain.length - 1; i > 0; i--) {
            if (event._stopped) { return event; }
            runAt(chain[i], true);
        }
        if (event._stopped) { return event; }
        runAt(chain[0], null);
        if (event.bubbles) {
            for (var j = 1; j < chain.length; j++) {
                if (event._stopped) { return event; }
                runAt(chain[j], false);
            }
        }
        return event;
    };

    // Real property-style access (`localStorage.foo = "bar"`,
    // `localStorage.foo`, `delete localStorage.foo`, `for (var k in
    // localStorage)`) on top of `__nativeLocalStorage`'s method
    // surface (`getItem`/`setItem`/`removeItem`/`clear`/`key`/
    // `.length` — see `build_local_storage_object`), via a real `Proxy`
    // rather than any Rust-side interception — Boa (this crate's JS
    // engine) implements `Proxy`/`Reflect` as real, spec-shaped
    // built-ins, so this is the same mechanism a real browser's own
    // `Storage` exotic object conceptually uses, not a hand-rolled
    // approximation.
    //
    // `reservedNames` are the real method/accessor names — real
    // `Storage` objects have these on their PROTOTYPE (never shadowed
    // by a same-named stored key), so `get`/`has` check this set FIRST
    // before falling through to treating `prop` as a stored key; `set`
    // deliberately does NOT special-case them (so
    // `localStorage.getItem = 5` stores a key literally named
    // `"getItem"` rather than truly shadowing the real method) — a
    // documented, low-impact simplification, since no real site
    // intentionally overwrites `Storage`'s own methods this way.
    //
    var reservedNames = {
        getItem: true, setItem: true, removeItem: true, clear: true, key: true, length: true
    };
    window.localStorage = new Proxy(__nativeLocalStorage, {
        // A missing key reports `undefined` here (real named-property
        // read behavior), NOT `getItem`'s own `null` — `getItem` only
        // ever stores real strings, so `null` unambiguously means "no
        // such key" and is safe to remap.
        get: function (target, prop, receiver) {
            if (typeof prop === 'symbol' || reservedNames[prop]) {
                return Reflect.get(target, prop, receiver);
            }
            var value = target.getItem(prop);
            return value === null ? undefined : value;
        },
        set: function (target, prop, value) {
            if (typeof prop === 'symbol') { return Reflect.set(target, prop, value); }
            target.setItem(prop, String(value));
            return true;
        },
        has: function (target, prop) {
            if (typeof prop === 'symbol' || reservedNames[prop]) { return true; }
            return target.getItem(prop) !== null;
        },
        deleteProperty: function (target, prop) {
            if (typeof prop !== 'symbol') { target.removeItem(prop); }
            return true;
        },
        // Enumerates only the REAL stored keys (`for...in`,
        // `Object.keys(localStorage)`) — matching real `Storage`,
        // whose own methods live on the prototype and so never show up
        // in an instance's own enumeration.
        ownKeys: function (target) {
            var keys = [];
            var len = target.length;
            for (var i = 0; i < len; i++) { keys.push(target.key(i)); }
            return keys;
        },
        // Required for the `ownKeys` trap above to satisfy Boa's own
        // Proxy invariant checks (`Object.keys`/`for...in` call this
        // for each name `ownKeys` reports) — every stored key is
        // reported as a real, configurable, enumerable, writable own
        // property, matching a real named `Storage` property exactly.
        getOwnPropertyDescriptor: function (target, prop) {
            if (typeof prop === 'symbol') { return Reflect.getOwnPropertyDescriptor(target, prop); }
            var value = target.getItem(prop);
            if (value === null) { return undefined; }
            return { value: value, writable: true, enumerable: true, configurable: true };
        }
    });
    // Real pages reach `localStorage` as a bare global exactly like
    // `setTimeout`/`fetch` above, not only via `window.localStorage`.
    localStorage = window.localStorage;
})();
"#;

/// Wraps a `dom::NodeRef` so a Boa native closure can capture it. Safe
/// to mark as containing nothing for Boa's collector to trace: see
/// this module's doc comment for why `dom::NodeRef` provably has no
/// Boa GC pointers inside it.
///
/// ALSO used as a real Boa `NativeObject` payload on every element
/// wrapper `build_element_object` builds (via `ObjectInitializer::
/// with_native_data`, not `::new`) — this is what lets a native
/// function recover "which live `dom::NodeRef` does this JS argument
/// actually refer to" (via `node_from_js_value`) when a script passes
/// one element object to another function, e.g.
/// `parent.appendChild(child)`. Before this, an element wrapper was a
/// plain, undifferentiated JS object with no way back to the Rust side
/// at all beyond the closures already bound to ITS OWN methods.
#[derive(Clone)]
struct HostNode(dom::NodeRef);

impl Finalize for HostNode {}
unsafe impl Trace for HostNode {
    empty_trace!();
}
impl boa_engine::JsData for HostNode {}

/// Recovers the `dom::NodeRef` a JS element wrapper object (built by
/// `build_element_object`) was constructed from, given that wrapper as
/// a `JsValue` — `None` for anything that isn't one (a plain object, a
/// primitive, `null`/`undefined`, or an object built some OTHER way
/// that happens to also carry native data of a different Rust type).
fn node_from_js_value(value: &JsValue) -> Option<dom::NodeRef> {
    value
        .as_object()?
        .downcast_ref::<HostNode>()
        .map(|host| host.0.clone())
}

/// Rust-side timer bookkeeping shared between the `__scheduleNative`/
/// `__cancelNative` closures and `Session::tick` — plain `u64`/`Instant`
/// pairs, no Boa GC types at all, so (like `HostNode`) `empty_trace!()`
/// is genuinely sound here, not just convenient.
#[derive(Clone)]
struct HostTimers(std::rc::Rc<std::cell::RefCell<Vec<(u64, std::time::Instant)>>>);

impl Finalize for HostTimers {}
unsafe impl Trace for HostTimers {
    empty_trace!();
}

impl HostTimers {
    fn new() -> Self {
        HostTimers(std::rc::Rc::new(std::cell::RefCell::new(Vec::new())))
    }
}

/// Rust-side accumulator shared between the native `console.log`/
/// `warn`/`error`/`info` closures (see `setup_globals`) and
/// `Session::drain_console_messages`/`eval_console_expression` — plain
/// `ipc::ConsoleMessage`s, no Boa GC types at all, so (like `HostTimers`)
/// `empty_trace!()` is genuinely sound here, not just convenient. A
/// script can log arbitrarily many messages between two `app` replies
/// (e.g. a tight loop inside one `setTimeout` callback); nothing here
/// caps that — `RenderSuccess::console_messages`' own doc comment notes
/// this is a real, if unlikely in practice, size concern for the wire
/// message it rides in.
#[derive(Clone)]
struct HostConsole(std::rc::Rc<std::cell::RefCell<Vec<ipc::ConsoleMessage>>>);

impl Finalize for HostConsole {}
unsafe impl Trace for HostConsole {
    empty_trace!();
}

impl HostConsole {
    fn new() -> Self {
        HostConsole(std::rc::Rc::new(std::cell::RefCell::new(Vec::new())))
    }

    fn push(&self, level: ipc::ConsoleLevel, text: String) {
        self.0
            .borrow_mut()
            .push(ipc::ConsoleMessage { level, text });
    }
}

/// Captured by the native `fetch()` closure (see `setup_globals`) —
/// the SAME `FilteringFetcher` every other request on this tab uses
/// (shared via `Rc<RefCell<..>>` with `RendererState`/`navigate`, not
/// a separate one — see `renderer::navigate`'s doc comment on why),
/// plus this page's own URL (to resolve a relative `fetch("/x")`
/// against, and to compute the `top_level_host` context
/// `fetch_in_context` needs for first/third-party classification —
/// see `network::FilteringFetcher`'s own docs). No Boa GC pointers
/// inside (a `FilteringFetcher` only ever holds plain Rust state:
/// cookies, an optional disk cache, and whatever transport `F` is),
/// so `empty_trace!()` is sound here for the same reason it is for
/// `HostNode`/`HostTimers` — see this module's top-level docs.
struct FetchState<F: network::Fetcher> {
    fetcher: Rc<RefCell<network::FilteringFetcher<F>>>,
    page_url: String,
}

impl<F: network::Fetcher> Clone for FetchState<F> {
    fn clone(&self) -> Self {
        FetchState {
            fetcher: Rc::clone(&self.fetcher),
            page_url: self.page_url.clone(),
        }
    }
}

impl<F: network::Fetcher> Finalize for FetchState<F> {}
unsafe impl<F: network::Fetcher> Trace for FetchState<F> {
    empty_trace!();
}

/// Captured by the native `localStorage.*` closures (see
/// `setup_globals`) — a shared handle to the SAME `LocalStorageStore`
/// every tab in this renderer process uses (mirroring `FetchState`'s
/// own `fetcher` field exactly — see `local_storage`'s own module
/// docs for why sharing it, rather than giving each `Session` its own,
/// is what makes two tabs on the same origin see each other's writes
/// live, the same way real browser tabs do), plus this page's own
/// ORIGIN (not the full URL — `local_storage::LocalStorageStore` keys
/// by origin, computed once here via the real `url` crate rather than
/// re-parsed on every single `getItem`/`setItem` call). No Boa GC
/// pointers inside, so `empty_trace!()` is sound for the same reason
/// it is for `FetchState`.
struct LocalStorageState {
    store: Rc<RefCell<LocalStorageStore>>,
    origin: String,
    /// This page's own URL — the `storage` event's real `url` field is
    /// the URL of the document whose script made the change (see
    /// `StorageChange::url`'s own doc comment), not the origin string
    /// `store` is already keyed by.
    page_url: String,
    /// Shared (via `Rc<RefCell<..>>`, same pattern as `store` itself)
    /// with this `Session`'s own `storage_events` field — every real
    /// mutation the `getItem`/`setItem`/`removeItem`/`clear` closures
    /// below make gets pushed here, and `Session::drain_storage_events`
    /// (called from `RendererState::handle_message`'s tail) is the only
    /// thing that ever removes anything from it. See
    /// `StorageChange`'s own doc comment for why this queue — rather
    /// than firing the event inline, right here — is what the cross-tab
    /// case needs.
    pending_events: Rc<RefCell<Vec<StorageChange>>>,
}

impl Clone for LocalStorageState {
    fn clone(&self) -> Self {
        LocalStorageState {
            store: Rc::clone(&self.store),
            origin: self.origin.clone(),
            page_url: self.page_url.clone(),
            pending_events: Rc::clone(&self.pending_events),
        }
    }
}

impl Finalize for LocalStorageState {}
unsafe impl Trace for LocalStorageState {
    empty_trace!();
}

/// Captured by the native `__idb*` closures (see `setup_globals`) —
/// mirrors `LocalStorageState` exactly (a shared handle to the SAME
/// `IndexedDbStore` every tab in this renderer process uses, plus this
/// page's own origin), minus a `pending_events` queue: see
/// `indexed_db`'s own module docs on why IndexedDB has no cross-tab
/// notification in this implementation.
struct IndexedDbState {
    store: Rc<RefCell<IndexedDbStore>>,
    origin: String,
}

impl Clone for IndexedDbState {
    fn clone(&self) -> Self {
        IndexedDbState {
            store: Rc::clone(&self.store),
            origin: self.origin.clone(),
        }
    }
}

impl Finalize for IndexedDbState {}
unsafe impl Trace for IndexedDbState {
    empty_trace!();
}

/// One real, spec-shaped `storage` DOM event's worth of detail —
/// `key`/`oldValue`/`newValue` exactly matching `StorageEvent`'s own
/// fields (`key: None` is `clear()`'s real shape: MDN/the spec both
/// document a `clear()`-triggered event as `key: null, oldValue: null,
/// newValue: null`, not one event per cleared key), plus the acting
/// document's own `url` and the `origin` `RendererState::
/// dispatch_pending_storage_events` needs to find every OTHER live
/// `Session` on the same origin — a real browser fires this event in
/// every OTHER `Document` that can see the same storage area, NEVER in
/// the one whose own script made the change.
///
/// Deliberately never constructed for a call that didn't actually
/// change anything (`setItem` with the value it already had,
/// `removeItem` on a missing key, `clear()` on an already-empty
/// origin) — matching real browsers, which likewise only fire this
/// event on a genuine change.
#[derive(Debug, Clone)]
pub struct StorageChange {
    pub origin: String,
    pub url: String,
    pub key: Option<String>,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
}

fn arg_as_string(args: &[JsValue], index: usize) -> String {
    args.get(index)
        .and_then(|v| v.as_string())
        .map(|s| s.to_std_string_escaped())
        .unwrap_or_default()
}

fn arg_as_u64(args: &[JsValue], index: usize) -> u64 {
    args.get(index)
        .and_then(|v| v.as_number())
        .unwrap_or(0.0)
        .max(0.0) as u64
}

/// An IndexedDB KEY argument (a string or number — see `indexed_db`'s
/// own module docs on why those are the only supported key types):
/// `None` for a missing/`undefined`/`null` argument (real "no explicit
/// key was given," e.g. an auto-incrementing `put(value)` with no
/// second argument), `Some(Err(..))` for anything else JS-shaped that
/// isn't a real IndexedDB key at all.
fn idb_key_arg(
    args: &[JsValue],
    index: usize,
    ctx: &mut Context,
) -> Result<Option<serde_json::Value>, JsError> {
    match args.get(index) {
        None => Ok(None),
        Some(v) if v.is_undefined() || v.is_null() => Ok(None),
        Some(v) => v.to_json(ctx).map(Some).map_err(|_| {
            JsNativeError::typ()
                .with_message(
                    "ConstraintError: IndexedDB keys must be a string or a number in this browser",
                )
                .into()
        }),
    }
}

/// An IndexedDB RECORD argument (the value being `put`/`add`ed) — see
/// `indexed_db`'s own module docs on why this only supports
/// JSON-representable values, not the full structured-clone algorithm
/// a real browser's IndexedDB uses.
fn idb_value_arg(
    args: &[JsValue],
    index: usize,
    ctx: &mut Context,
) -> Result<serde_json::Value, JsError> {
    let value = args.get(index).cloned().unwrap_or_else(JsValue::undefined);
    value.to_json(ctx).map_err(|_| {
        JsNativeError::typ()
            .with_message(
                "DataCloneError: this value isn't JSON-representable, which is the only kind \
                 of value this browser's IndexedDB can store (no Date/Map/Set/functions/\
                 undefined properties)",
            )
            .into()
    })
}

/// Turns a real `indexed_db::IdbError` into a real, catchable JS
/// exception carrying the SAME `DOMException` name a real browser
/// would throw for it — see that enum's own doc comment for exactly
/// which real name each variant maps to.
fn idb_error_to_js(error: indexed_db::IdbError) -> JsError {
    let message = match error {
        indexed_db::IdbError::NotFound => {
            "NotFoundError: no such IndexedDB database or object store"
        }
        indexed_db::IdbError::ConstraintError => {
            "ConstraintError: a key constraint was not satisfied"
        }
        indexed_db::IdbError::QuotaExceeded => {
            "QuotaExceededError: IndexedDB is full for this origin"
        }
    };
    JsNativeError::typ().with_message(message).into()
}

/// Renders one JS value the way `console.log`/a DevTools console REPL
/// result would: a bare string prints unquoted (matching real
/// `console.log("hi")`), `undefined`/`null` print their literal names
/// (not representable in JSON, so `to_json` alone can't cover them),
/// and everything JSON-representable (numbers, booleans, plain objects,
/// arrays) goes through Boa's own `JsValue::to_json` for a real,
/// structural rendering (`{"a":1}`, `[1,2,3]`) rather than a flat
/// `[object Object]`. Anything `to_json` can't handle (a function, a
/// value containing one, a symbol) falls back to JS's own `ToString`
/// (a function prints its own source-derived `"function foo() {...}"`
/// form) rather than failing outright — a console that can't stringify
/// SOMETHING is a worse debugging experience than a slightly-generic
/// fallback string.
fn console_display_string(value: &JsValue, context: &mut Context) -> String {
    if value.is_undefined() {
        return "undefined".to_string();
    }
    if value.is_null() {
        return "null".to_string();
    }
    if let Some(s) = value.as_string() {
        return s.to_std_string_escaped();
    }
    match value.to_json(context) {
        Ok(json) => serde_json::to_string(&json).unwrap_or_else(|_| "[object]".to_string()),
        Err(_) => value
            .to_string(context)
            .map(|s| s.to_std_string_escaped())
            .unwrap_or_else(|_| "[object]".to_string()),
    }
}

/// `console.log(a, b, c)`'s real multi-argument behavior: each
/// argument rendered via `console_display_string`, space-joined —
/// `console.log("x =", 5)` reads as `x = 5`, not `["x =",5]`.
fn format_console_args(args: &[JsValue], context: &mut Context) -> String {
    args.iter()
        .map(|v| console_display_string(v, context))
        .collect::<Vec<_>>()
        .join(" ")
}

/// One `<script>` element's content, in document order — either the
/// inline source text, or an unresolved `src` attribute value still
/// needing to be resolved against the page's own URL and fetched (see
/// `resolve_and_fetch_scripts`).
#[derive(Debug, Clone, PartialEq)]
pub enum ScriptSource {
    Inline(String),
    External(String),
}

/// Collects every `<script>` element's content, in document order,
/// distinguishing inline source text from an external `src` still
/// needing resolution/fetching.
pub fn extract_scripts(document: &dom::NodeRef) -> Vec<ScriptSource> {
    let mut scripts = Vec::new();
    collect_scripts(document, &mut scripts);
    scripts
}

enum ScriptNodeKind {
    NotAScript,
    Inline,
    External(String),
}

fn collect_scripts(node: &dom::NodeRef, out: &mut Vec<ScriptSource>) {
    let (kind, children) = {
        let node_ref = node.borrow();
        match &node_ref.node_type {
            dom::NodeType::Element(el) if el.tag_name == "script" => {
                let kind = match el.attributes.get("src") {
                    Some(src) => ScriptNodeKind::External(src.clone()),
                    None => ScriptNodeKind::Inline,
                };
                (kind, node_ref.children.clone())
            }
            _ => (ScriptNodeKind::NotAScript, node_ref.children.clone()),
        }
    };
    match kind {
        // A <script> element's own children are its source text (for
        // an inline script) or ignored fallback content (for an
        // external one) — never markup to recurse into further.
        ScriptNodeKind::Inline => out.push(ScriptSource::Inline(text_content(node))),
        ScriptNodeKind::External(src) => out.push(ScriptSource::External(src)),
        ScriptNodeKind::NotAScript => {
            for child in &children {
                collect_scripts(child, out);
            }
        }
    }
}

/// Resolves every `ScriptSource::External` against `page_url` and
/// fetches it through `fetcher` — the SAME blocklist-checking,
/// cache-aware `FilteringFetcher` real page fetches use, with the
/// page's own host as the third-party context (see
/// `privacy::RequestContext`). `ScriptSource::Inline` text passes
/// through unchanged. A script that fails to resolve, fails to fetch,
/// or gets blocked is logged and DROPPED — the rest of the page's
/// scripts still run, in the same relative order they appeared in the
/// document.
pub fn resolve_and_fetch_scripts<F: network::Fetcher>(
    scripts: &[ScriptSource],
    page_url: &str,
    fetcher: &mut network::FilteringFetcher<F>,
) -> Vec<String> {
    let page_host = match url::Url::parse(page_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
    {
        Some(host) => host,
        None => {
            eprintln!(
                "renderer: could not determine the page's own host from {page_url:?} — skipping all \
                 external scripts on this page rather than risk misjudging first/third-party."
            );
            return scripts
                .iter()
                .filter_map(|s| match s {
                    ScriptSource::Inline(text) => Some(text.clone()),
                    ScriptSource::External(_) => None,
                })
                .collect();
        }
    };

    let mut out = Vec::with_capacity(scripts.len());
    for source in scripts {
        match source {
            ScriptSource::Inline(text) => out.push(text.clone()),
            ScriptSource::External(src) => match resolve_script_url(page_url, src) {
                Some(url) => match fetcher.fetch_in_context(&url, Some(&page_host)) {
                    // Lossy: a malformed/mislabeled script response
                    // degrades to replacement characters rather than
                    // dropping the whole script (`response.body` is
                    // raw bytes now — see `network::Response`'s doc
                    // comment).
                    Ok(response) => out.push(String::from_utf8_lossy(&response.body).into_owned()),
                    Err(e) => eprintln!("renderer: failed to fetch external script {url:?}: {e:?} (skipping)"),
                },
                None => eprintln!("renderer: could not resolve script src {src:?} against page URL {page_url:?} (skipping)"),
            },
        }
    }
    out
}

fn resolve_script_url(page_url: &str, src: &str) -> Option<String> {
    url::Url::parse(page_url)
        .and_then(|base| base.join(src))
        .ok()
        .map(|u| u.to_string())
}

/// A live, per-tab script execution context: a Boa `Context`, the DOM
/// it's bound to, and any pending `setTimeout` callbacks — kept alive
/// by `RendererState` (keyed by `ipc::TabId`) across multiple messages,
/// unlike everything else in this crate's original single-shot design.
/// This IS the "persistent session" `ipc`'s module docs describe.
pub struct Session {
    context: Context,
    document: dom::NodeRef,
    timers: HostTimers,
    canvas_width: f32,
    theme: css::Theme,
    /// Every `<img>` this page successfully fetched and decoded (see
    /// `images::resolve_and_fetch_images`), keyed by that element's
    /// `dom::NodeId` — fixed for the whole session's lifetime, since
    /// this DOM surface has no way for a script to add a NEW `<img>`
    /// element that would need fetching later. Threaded into every
    /// `relayout` call so a script mutation doesn't lose already-loaded
    /// images.
    images: std::collections::HashMap<dom::NodeId, layout::ImageContent>,
    /// Every `<link rel="stylesheet" href="...">` this page successfully
    /// fetched, keyed by that element's `dom::NodeId` and holding its
    /// raw (not-yet-parsed) CSS text — see `stylesheets::resolve_and_fetch_stylesheets`.
    /// Parsed fresh on every `relayout` (via
    /// `css::extract_author_stylesheet_with_external`) rather than
    /// once here, for the same reason inline `<style>` blocks are
    /// re-extracted every time — see this struct's `relayout` doc
    /// comment.
    external_css: std::collections::HashMap<dom::NodeId, String>,
    /// This page's own URL — needed for two things a bare
    /// `dom::NodeRef` tree can't provide on its own: resolving a
    /// `<form>`'s (possibly relative) `action` against it
    /// (`build_form_submission`), and (via `FetchState`, a separate
    /// copy captured into the `fetch()` closure itself — see that
    /// type's own doc comment) resolving `fetch()`'s own relative URLs.
    page_url: String,
    /// This page's own real origin (scheme + host + port) — see
    /// `origin()`'s own doc comment for why `RendererState` needs this
    /// exposed at all (finding sibling same-origin sessions for the
    /// cross-tab `storage` event).
    origin: String,
    /// Whichever element currently has KEYBOARD focus, if any — `None`
    /// is the common case (most pages have nothing focused). Broader
    /// than just a text-editable `<input>` (see `layout::
    /// is_text_like_input`): a link, button, or checkbox reached via
    /// `Tab`/`Shift+Tab` (see `move_keyboard_focus`) is `focused` here
    /// too, exactly like a text input a real mouse click focused (see
    /// `focus`) — `layout::LayoutBox::focused` (and so `render`'s real
    /// visible focus ring) is set from this SAME field regardless of
    /// which kind of element it names. `cursor` is only ever meaningful
    /// when this happens to be a text-like input. Real focus lives
    /// here, in the renderer, rather than in `app`, for the same reason
    /// everything else about a page's state does: `app` never touches
    /// the DOM directly (see this workspace's own process-split
    /// architecture), so a focused element's identity has to live
    /// wherever the DOM itself does.
    focused: Option<dom::NodeId>,
    /// The text cursor's position within `focused`'s current value, as
    /// a character index (not a byte offset — see
    /// `text::char_byte_offset` for the conversion `handle_text_input`
    /// needs when actually splicing the string). Meaningless (and
    /// ignored by `relayout`) whenever `focused` is `None` OR names
    /// something other than a text-like input.
    cursor: usize,
    /// Every `<audio>`/`<video>` element's STATIC content (kind,
    /// `controls`, decoded duration, a video's poster), keyed by
    /// `dom::NodeId` — see `media::resolve_and_decode_media`. Fixed for
    /// the session's lifetime, same reasoning as `images`. Threaded
    /// into every `relayout` alongside `media_playback` (the DYNAMIC
    /// half — see `layout::MediaContent`'s own doc comment on the
    /// static/dynamic split).
    media_assets: std::collections::HashMap<dom::NodeId, layout::MediaAsset>,
    /// Each successfully decoded element's actual PCM samples — kept
    /// SEPARATELY from `media_assets` (which only needs to cross into
    /// `layout::LayoutBox`, never the raw samples themselves) because
    /// this is what `fetch_audio_pcm` hands back the FIRST time `app`
    /// needs to actually play a given element (see
    /// `ipc::ClientMessageKind::FetchAudioPcm`'s own doc comment) — an
    /// `Rc` so answering that message doesn't need to clone potentially
    /// many megabytes of samples just to serialize them.
    decoded_audio: std::collections::HashMap<dom::NodeId, Rc<media::DecodedAudio>>,
    /// Each media element's CURRENT playback state, as last reported by
    /// `app` via `ipc::ClientMessageKind::UpdateMediaPlayback` — `app`
    /// is the only thing that actually knows this (real playback
    /// happens there, via `cpal`; this process has no audio OUTPUT of
    /// its own at all). Applied onto the freshly-laid-out tree by
    /// `relayout` via `layout::apply_media_playback`.
    media_playback: std::collections::HashMap<dom::NodeId, layout::MediaPlaybackState>,
    /// Every `console.log`/`warn`/`error`/`info` call this session has
    /// made that `app` hasn't been told about yet — see
    /// `drain_console_messages`, the only way anything ever removes
    /// entries from here. Shared (via the `Rc<RefCell<..>>` inside
    /// `HostConsole`) with the native `console.*` closures themselves
    /// (see `setup_globals`) — pushing onto it from JS is exactly why
    /// this needs to be a `HostConsole`, not a plain `Vec` field.
    console: HostConsole,
    /// Shared with `LocalStorageState::pending_events` (the SAME
    /// `Rc<RefCell<..>>`, not a copy) — see `drain_storage_events`'s
    /// own doc comment.
    storage_events: Rc<RefCell<Vec<StorageChange>>>,
}

impl Session {
    /// Starts a fresh session for a newly navigated page: builds a new
    /// `Context` with `RuntimeLimits` applied, installs the DOM/
    /// window/timer bindings, and runs every script in `scripts` in
    /// order (a throwing/malformed one is logged and skipped — the
    /// rest still run), then fires `'load'` listeners once. The
    /// session stays alive afterward so a later `setTimeout` callback
    /// has a live `Context`/DOM to run against — see `tick`. `images`
    /// is whatever `images::resolve_and_fetch_images` already resolved
    /// for this page's `<img>` elements — this constructor doesn't do
    /// any fetching of its own.
    /// `fetcher`/`page_url` are what the JS-visible `fetch()` binding
    /// (see `setup_globals`) needs — a shared handle to the SAME
    /// fetcher every other request on this tab uses, and this page's
    /// own URL to resolve relative URLs and compute the third-party
    /// context against. `Session` itself stays a plain, non-generic
    /// struct even though this constructor is generic over `F` — `F`
    /// never needs to appear in any FIELD here, since past this point
    /// it only lives inside the type-erased `Context`'s own object
    /// graph (the native `fetch` closure this builds), not in any Rust
    /// type this struct has to name.
    ///
    /// Ten positional parameters trips clippy's arity lint; a config
    /// struct would just move the same information one level of
    /// indirection away rather than removing it, and every caller
    /// (production and the ~50 in this module's own tests) already
    /// names each one explicitly at the call site — allowed
    /// deliberately rather than restructured for its own sake.
    ///
    /// Gives this session its OWN fresh, empty, never-persisted
    /// `local_storage::LocalStorageStore` — fine for the ~50 tests
    /// that call this and don't care about `localStorage` at all, but
    /// NOT what a real navigation wants (a real page's `localStorage`
    /// needs to be shared with every other tab on the same origin AND
    /// survive a restart) — see `new_with_shared_storage`, which
    /// `renderer::navigate` (the one production caller) uses instead.
    #[allow(clippy::too_many_arguments)]
    pub fn new<F: network::Fetcher + 'static>(
        document: dom::NodeRef,
        scripts: &[String],
        canvas_width: f32,
        theme: css::Theme,
        images: std::collections::HashMap<dom::NodeId, layout::ImageContent>,
        external_css: std::collections::HashMap<dom::NodeId, String>,
        fetcher: Rc<RefCell<network::FilteringFetcher<F>>>,
        page_url: String,
        media_assets: std::collections::HashMap<dom::NodeId, layout::MediaAsset>,
        decoded_audio: std::collections::HashMap<dom::NodeId, media::DecodedAudio>,
    ) -> Session {
        Self::new_with_shared_storage(
            document,
            scripts,
            canvas_width,
            theme,
            images,
            external_css,
            fetcher,
            page_url,
            media_assets,
            decoded_audio,
            Rc::new(RefCell::new(LocalStorageStore::default())),
            Rc::new(RefCell::new(IndexedDbStore::default())),
        )
    }

    /// The real implementation `new` (fresh, unshared, unpersisted
    /// `localStorage`/IndexedDB) builds on — see that method's own doc
    /// comment. Both `local_storage` and `indexed_db` are shared
    /// (`Rc<RefCell<..>>`, not owned outright) the exact same way
    /// `fetcher` already is, and for the same reason: every tab in this
    /// renderer process (one process per SITE — see
    /// `app::RendererPool`) needs to see the same storage for pages on
    /// the same origin, live, the way real browser tabs do.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_shared_storage<F: network::Fetcher + 'static>(
        document: dom::NodeRef,
        scripts: &[String],
        canvas_width: f32,
        theme: css::Theme,
        images: std::collections::HashMap<dom::NodeId, layout::ImageContent>,
        external_css: std::collections::HashMap<dom::NodeId, String>,
        fetcher: Rc<RefCell<network::FilteringFetcher<F>>>,
        page_url: String,
        media_assets: std::collections::HashMap<dom::NodeId, layout::MediaAsset>,
        decoded_audio: std::collections::HashMap<dom::NodeId, media::DecodedAudio>,
        local_storage: Rc<RefCell<LocalStorageStore>>,
        indexed_db: Rc<RefCell<IndexedDbStore>>,
    ) -> Session {
        let mut context = Context::default();
        context
            .runtime_limits_mut()
            .set_loop_iteration_limit(LOOP_ITERATION_LIMIT);
        context
            .runtime_limits_mut()
            .set_recursion_limit(RECURSION_LIMIT);

        let timers = HostTimers::new();
        let console = HostConsole::new();
        // Real `Origin` serialization (scheme + host + port), computed
        // ONCE here rather than re-parsed on every single `localStorage`
        // call — see `LocalStorageState`'s own doc comment. Falls back
        // to the raw page URL on a parse failure (shouldn't happen for
        // a real fetched http(s) URL) rather than panicking — a
        // same-page-scoped-by-a-slightly-wrong-key degradation, not a
        // crash, matching this crate's usual fallback philosophy.
        let origin = url::Url::parse(&page_url)
            .map(|u| u.origin().ascii_serialization())
            .unwrap_or_else(|_| page_url.clone());
        let storage_events: Rc<RefCell<Vec<StorageChange>>> = Rc::new(RefCell::new(Vec::new()));
        setup_globals(
            &mut context,
            document.clone(),
            timers.clone(),
            console.clone(),
            FetchState {
                fetcher,
                page_url: page_url.clone(),
            },
            LocalStorageState {
                store: local_storage,
                origin: origin.clone(),
                page_url: page_url.clone(),
                pending_events: Rc::clone(&storage_events),
            },
            IndexedDbState {
                store: indexed_db,
                origin: origin.clone(),
            },
        );

        for script in scripts {
            if let Err(e) = context.eval(Source::from_bytes(script.as_bytes())) {
                eprintln!("renderer: script error (continuing with the rest of the page): {e}");
            }
        }
        // Drains any Promise reactions / async-function continuations
        // queued by the scripts that just ran, BEFORE firing 'load' —
        // see this module's own doc comment on why this crate must
        // call this explicitly (`Context::eval` never does).
        context.run_jobs();
        if let Err(e) = context.eval(Source::from_bytes(
            "if (window.__dispatch) { window.__dispatch('load'); }",
        )) {
            eprintln!("renderer: internal error firing 'load' listeners: {e}");
        }
        context.run_jobs();

        Session {
            context,
            document,
            timers,
            canvas_width,
            theme,
            images,
            external_css,
            page_url,
            origin,
            focused: None,
            cursor: 0,
            media_assets,
            decoded_audio: decoded_audio
                .into_iter()
                .map(|(id, audio)| (id, Rc::new(audio)))
                .collect(),
            media_playback: std::collections::HashMap::new(),
            console,
            storage_events,
        }
    }

    /// This session's own origin (scheme + host + port, real `url`-
    /// crate serialization — see the constructor's own comment on why
    /// it's computed once, there, rather than re-parsed here) —
    /// `RendererState::dispatch_pending_storage_events` uses this to
    /// find every OTHER live session on the SAME origin as a
    /// `StorageChange` it just drained.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Removes and returns every `StorageChange` this session's own
    /// `localStorage` calls have queued up since the last drain — see
    /// `LocalStorageState::pending_events`'s own doc comment. Called
    /// once per message, from `RendererState::handle_message`'s tail,
    /// on whichever session actually ran script this time.
    pub fn drain_storage_events(&mut self) -> Vec<StorageChange> {
        std::mem::take(&mut *self.storage_events.borrow_mut())
    }

    /// Fires a real `storage` DOM event (`window.addEventListener(
    /// 'storage', ...)`) into THIS session's own live `Context` — the
    /// caller (`RendererState::dispatch_pending_storage_events`) is
    /// responsible for only calling this on sessions whose `origin()`
    /// actually matches `change.origin`, and for never calling this on
    /// the session that made the change itself (a real browser never
    /// fires `storage` back into the document whose own script caused
    /// it — see MDN/the spec on `StorageEvent`).
    ///
    /// Each field is serialized through `serde_json::to_string` rather
    /// than hand-built with string concatenation — `key`/`oldValue`/
    /// `newValue` are arbitrary, attacker-influenceable page content
    /// (a script can call `setItem` with a key or value containing a
    /// quote, a backslash, a newline, anything), and JSON's own string
    /// escaping is exactly what's needed to embed them safely as JS
    /// source; `None` serializes to the bare literal `null`, which is
    /// valid JS too.
    ///
    /// Mutates this OTHER session's DOM/JS state immediately, but (see
    /// this crate's `ipc` module's own doc comment on there being no
    /// unsolicited push from `abyssal-renderer` back to `app`) `app`
    /// won't actually see any resulting re-render until the NEXT
    /// message that happens to target this tab — e.g. its own next
    /// `Tick`. This is a real, inherent limitation of the current
    /// one-reply-per-message IPC protocol, not a bug in this function;
    /// it's the same staleness a background `setTimeout` callback in an
    /// unfocused tab already has today.
    pub fn fire_storage_event(&mut self, change: &StorageChange) {
        let key_literal = serde_json::to_string(&change.key).unwrap_or_else(|_| "null".into());
        let old_literal =
            serde_json::to_string(&change.old_value).unwrap_or_else(|_| "null".into());
        let new_literal =
            serde_json::to_string(&change.new_value).unwrap_or_else(|_| "null".into());
        let url_literal = serde_json::to_string(&change.url).unwrap_or_else(|_| "\"\"".into());
        let script = format!(
            "if (window.__dispatch) {{ window.__dispatch('storage', {{ type: 'storage', \
             key: {key_literal}, oldValue: {old_literal}, newValue: {new_literal}, \
             url: {url_literal}, storageArea: (typeof localStorage !== 'undefined' ? localStorage : null) }}); }}"
        );
        if let Err(e) = self.context.eval(Source::from_bytes(script.as_bytes())) {
            eprintln!("renderer: internal error firing a 'storage' event listener: {e}");
        }
        self.context.run_jobs();
    }

    /// Runs every timer due AS OF NOW, looping (re-checking the real
    /// clock each time, not a single snapshot from when `tick` was
    /// called) until none remain due — so a timer that reschedules
    /// another at 0ms delay runs within this SAME `tick` call rather
    /// than waiting for a separate external one. Returns whether
    /// anything actually ran, so the caller (`RendererState::handle_message`)
    /// knows whether to re-layout and send an updated tree, or reply
    /// `Unchanged`. The same `RuntimeLimits` from `new` still apply to
    /// each callback.
    pub fn tick(&mut self) -> bool {
        let mut ran_anything = false;
        loop {
            let now = std::time::Instant::now();
            let due_id = {
                let mut timers = self.timers.0.borrow_mut();
                let index = timers.iter().position(|(_, fire_at)| *fire_at <= now);
                index.map(|i| timers.remove(i).0)
            };
            let Some(id) = due_id else { break };
            ran_anything = true;
            let script = format!("window.__runDueTimer({id})");
            if let Err(e) = self.context.eval(Source::from_bytes(script.as_bytes())) {
                eprintln!("renderer: error running a setTimeout callback (id {id}): {e}");
            }
        }
        if ran_anything {
            // A timer callback may itself have used `async`/`await` or
            // chained a `.then()` — see this module's doc comment on
            // why draining the job queue is this crate's own
            // responsibility, not something `eval` does implicitly.
            self.context.run_jobs();
        }
        ran_anything
    }

    /// Re-runs style + layout against the (possibly script-mutated)
    /// DOM — the same pipeline a fresh `Navigate` uses, just without
    /// re-fetching or re-running scripts. Combines the built-in
    /// `user_agent_stylesheet` with whatever
    /// the page's OWN `<style>` blocks contain (see
    /// `css::extract_author_stylesheet`) every time, not just once at
    /// `Session::new` — a script that injects/mutates a `<style>`
    /// element's content between calls (this DOM surface doesn't
    /// support that yet, but nothing stops a FUTURE one from adding it)
    /// would otherwise see stale rules; re-extracting here costs one
    /// small DOM walk per relayout and keeps this correct by
    /// construction rather than by remembering to invalidate a cache.
    /// Also splices in every already-FETCHED external stylesheet (see
    /// `external_css`) at the exact `<link>` element that requested
    /// it, in real document order alongside `<style>` blocks — see
    /// `css::extract_author_stylesheet_with_external`.
    pub fn relayout(&self, font: &text::Font) -> layout::LayoutBox {
        let mut stylesheet = css::user_agent_stylesheet(self.theme);
        stylesheet.extend(css::extract_author_stylesheet_with_external(
            &self.document,
            &self.external_css,
        ));
        let mut tree = layout::build_layout_tree_with_media(
            &self.document,
            &stylesheet,
            &self.images,
            &self.media_assets,
        );
        // Threading `focused`/`cursor` through here (rather than a
        // separate pass) is what makes the currently-focused input's
        // text cursor show up in every relayout, not just the one
        // immediately after `focus`/`handle_text_input` runs — a
        // Tick-triggered relayout (an unrelated `setTimeout` firing,
        // say) must not make the cursor disappear.
        let focus = self.focused.map(|id| (id, self.cursor));
        layout::layout_with_focus(&mut tree, self.canvas_width, font, focus);
        // Playback state doesn't affect geometry at all (unlike
        // `focus`, which resolves a pixel cursor position), so it's
        // applied as a separate pass over the already-laid-out tree —
        // see `layout::apply_media_playback`'s own doc comment.
        layout::apply_media_playback(&mut tree, &self.media_playback);
        tree
    }

    /// Drains and returns every `console.*` call (or REPL echo/result —
    /// see `eval_console_expression`) accumulated since the last call
    /// to this — see `ipc::RenderSuccess::console_messages`'s own doc
    /// comment on why this is a drain, not a clone: `app` needs each
    /// message exactly once, and `render_success` calls this on every
    /// single reply, so cloning instead would mean re-sending the same
    /// growing backlog forever.
    pub fn drain_console_messages(&self) -> Vec<ipc::ConsoleMessage> {
        std::mem::take(&mut self.console.0.borrow_mut())
    }

    /// DevTools console REPL: runs `code` as a top-level script against
    /// this session's LIVE `Context`/DOM (real mutations, real
    /// `console.*` calls along the way — both show up together, in
    /// true execution order, the next time `drain_console_messages`
    /// runs), then pushes the typed expression itself (echoed, `> `-
    /// prefixed, so a scrollback that mixes page logs and REPL input
    /// stays readable) and its result — or, if it threw, the error
    /// message at `ipc::ConsoleLevel::Error` instead. See
    /// `ipc::ClientMessageKind::EvalConsoleExpression`'s own doc
    /// comment for why this is always followed by a real `relayout`
    /// (an expression can mutate the DOM just as validly as any other
    /// script) rather than being treated as a side-channel that can't
    /// affect the page.
    pub fn eval_console_expression(&mut self, code: &str) {
        self.console
            .push(ipc::ConsoleLevel::Log, format!("> {code}"));
        let result = self.context.eval(Source::from_bytes(code.as_bytes()));
        self.context.run_jobs();
        match result {
            Ok(value) => {
                let text = console_display_string(&value, &mut self.context);
                self.console.push(ipc::ConsoleLevel::Log, text);
            }
            Err(e) => {
                self.console.push(ipc::ConsoleLevel::Error, e.to_string());
            }
        }
    }

    /// Builds a full snapshot of this session's REAL DOM tree — see
    /// `ipc::ClientMessageKind::FetchDomSnapshot`'s own doc comment for
    /// why this is separate from `relayout`'s layout tree.
    pub fn dom_snapshot(&self) -> ipc::DomNode {
        devtools::build_dom_snapshot(&self.document)
    }

    /// Answers `ipc::ClientMessageKind::FetchAudioPcm` — the already-
    /// decoded samples for `dom_node_id`, if any (`None` covers both
    /// "not a media element at all" and "decoding never succeeded for
    /// it" — `app` doesn't need to distinguish the two, see
    /// `RendererState::handle_message`'s `FetchAudioPcm` arm).
    pub fn fetch_audio_pcm(&self, dom_node_id: dom::NodeId) -> Option<Rc<media::DecodedAudio>> {
        self.decoded_audio.get(&dom_node_id).cloned()
    }

    /// Records this media element's CURRENT playback state (see
    /// `ipc::ClientMessageKind::UpdateMediaPlayback`), for the NEXT
    /// `relayout` to reflect. Returns whether `dom_node_id` actually
    /// names a known media element — `RendererState::handle_message`
    /// answers `Unchanged` rather than `Rendered` when it doesn't (an
    /// expected race, e.g. a stale update after the page navigated
    /// away, not a protocol error).
    pub fn update_media_playback(
        &mut self,
        dom_node_id: dom::NodeId,
        playing: bool,
        muted: bool,
        current_time_secs: f32,
    ) -> bool {
        if !self.media_assets.contains_key(&dom_node_id) {
            return false;
        }
        self.media_playback.insert(
            dom_node_id,
            layout::MediaPlaybackState {
                playing,
                muted,
                current_time_secs,
            },
        );
        true
    }

    pub fn title(&self) -> Option<String> {
        find_title(&self.document)
    }

    /// See `crate::page_signals`'s own module docs — recomputed fresh
    /// from the CURRENT live DOM on every call (same "don't cache what
    /// script can still mutate" reasoning `title` above already
    /// follows), not cached once at `Session::new` time.
    pub fn page_signals(&self) -> ipc::PageSignals {
        crate::page_signals::compute(&self.document)
    }

    /// Milliseconds from now until the next pending timer is due, if
    /// any — what `RendererState` reports back as
    /// `RenderSuccess::next_wake_in_millis`/`ServerMessageKind::Unchanged`'s
    /// re-arm time, so `app` knows when to send the next `Tick`.
    pub fn next_wake_in_millis(&self) -> Option<u64> {
        let now = std::time::Instant::now();
        self.timers
            .0
            .borrow()
            .iter()
            .map(|(_, fire_at)| fire_at.saturating_duration_since(now).as_millis() as u64)
            .min()
    }

    /// Dispatches a real, three-phase (capturing, AT_TARGET, bubbling)
    /// `click` event at the DOM node `dom_node_id` names — see
    /// `PRELUDE_JS`'s `window.__dispatchEvent` for the actual event-flow
    /// logic and what the `Event` object it builds supports (including
    /// `preventDefault`). `ClickOutcome::resolved` says whether that
    /// node still exists in this session's CURRENT DOM at all —
    /// `RendererState::handle_message` uses that (not whether any
    /// listener actually fired, which isn't observable from here) to
    /// decide `Rendered` vs `Unchanged`, per `ipc::ClientMessageKind::
    /// Click`'s doc comment. A node id that doesn't resolve is an
    /// expected, harmless race (the page navigated, or a script
    /// replaced that part of the DOM, between the click and this
    /// message arriving), not an error — and dispatching to a chain
    /// with no registered listeners anywhere on it is ALSO harmless
    /// (see `PRELUDE_JS`), which is why this doesn't need to know in
    /// advance whether any node in the chain ever had a listener, only
    /// whether the target itself still exists.
    pub fn dispatch_click(&mut self, dom_node_id: dom::NodeId) -> ClickOutcome {
        let Some(target) = find_by_node_id(&self.document, dom_node_id) else {
            return ClickOutcome {
                resolved: false,
                default_prevented: false,
                submit_url: None,
                submit_body: None,
            };
        };
        let chain = ancestor_chain(&target);
        let default_prevented = self.dispatch_event(&chain, "click", None);
        let mut submit_url = None;
        let mut submit_body = None;
        // A checkbox/radio's own "default action" — toggling checked
        // (or, for a radio, becoming the one checked member of its
        // name-group) — is real HTML's `click` default action, so it's
        // skipped exactly like a link's navigation is when a listener
        // calls `preventDefault()` (see `apply_checkable_default_action`'s
        // own doc comment for the toggle logic itself and why this
        // needs no new IPC message at all, unlike text input). A
        // submit control's default action — submitting its form — gets
        // the same treatment, and the same `submit`-event-then-build
        // sequence `handle_text_input`'s `Enter` case already uses.
        if !default_prevented {
            self.apply_checkable_default_action(&target);
            if is_submit_control(&target) {
                if let Some(form) = find_ancestor_form(&target) {
                    let form_chain = ancestor_chain(&form);
                    let submit_prevented = self.dispatch_event(&form_chain, "submit", None);
                    if !submit_prevented {
                        if let Some((url, body)) = self.build_form_submission(&form) {
                            submit_url = Some(url);
                            submit_body = body;
                        }
                    }
                }
            }
        }
        ClickOutcome {
            resolved: true,
            default_prevented,
            submit_url,
            submit_body,
        }
    }

    /// If `target` is a checkbox/radio (see `layout::checkable_kind`),
    /// applies its real click default action and fires a real `change`
    /// event afterward — a no-op for every other element. A checkbox
    /// simply toggles its own `checked` attribute; a radio additionally
    /// un-checks every other radio sharing its `name` within the
    /// nearest ancestor `<form>` (or the whole document, if it isn't
    /// inside one — matching real HTML's own radio-group scoping)
    /// before checking itself — real browsers never let two radios in
    /// the same named group end up checked at once, and this is the
    /// one place that invariant is enforced.
    fn apply_checkable_default_action(&mut self, target: &dom::NodeRef) {
        let kind = match &target.borrow().node_type {
            dom::NodeType::Element(el) => layout::checkable_kind(el),
            _ => None,
        };
        let Some(kind) = kind else {
            return;
        };

        match kind {
            layout::CheckableKind::Checkbox => {
                let was_checked = get_attribute(target, "checked").is_some();
                set_checked(target, !was_checked);
            }
            layout::CheckableKind::Radio => {
                let name = match &target.borrow().node_type {
                    dom::NodeType::Element(el) => el.attributes.get("name").cloned(),
                    _ => None,
                };
                if let Some(name) = name {
                    let scope = find_ancestor_form(target).unwrap_or_else(|| self.document.clone());
                    uncheck_other_radios_in_group(&scope, &name, target);
                }
                set_checked(target, true);
            }
        }

        self.dispatch_event(&ancestor_chain(target), "change", None);
    }

    /// Dispatches one event at `chain` (see `PRELUDE_JS`'s
    /// `__dispatchEvent`) and reports whether `preventDefault` was
    /// called anywhere in its capturing/target/bubbling flow — the
    /// shared primitive `dispatch_click`, `handle_text_input`'s
    /// `keydown`/`input` dispatch, and its `submit` dispatch all build
    /// on. `extra_props_js` (if any) is raw JS source for the INSIDE of
    /// an object literal (e.g. `key: "a"`) merged onto the event object
    /// before dispatch — every caller is responsible for its own
    /// escaping of anything not a fixed string literal (see
    /// `js_string_literal`, used for the one piece of user-typed text
    /// that ever flows through here).
    fn dispatch_event(
        &mut self,
        chain: &[u64],
        event_type: &str,
        extra_props_js: Option<&str>,
    ) -> bool {
        let chain_literal = chain
            .iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let extra = match extra_props_js {
            Some(props) => format!("{{{props}}}"),
            None => "null".to_string(),
        };
        let script = format!("window.__dispatchEvent([{chain_literal}], '{event_type}', {extra})");

        let event_value = match self.context.eval(Source::from_bytes(script.as_bytes())) {
            Ok(value) => value,
            Err(e) => {
                eprintln!("renderer: error dispatching a {event_type} event: {e}");
                return false;
            }
        };
        // A listener may itself have used `async`/`await` or chained a
        // `.then()` — see this module's doc comment on `run_jobs`.
        self.context.run_jobs();
        // `__dispatchEvent` always returns the `Event` object it built
        // (see its own doc comment) — reading `defaultPrevented` back
        // off it here is what lets a caller know whether to still
        // perform this event's default action (link navigation for
        // `click`, the actual text edit for `keydown`, real navigation
        // for `submit`) after dispatching, instead of deciding that up
        // front and skipping dispatch entirely — see `dispatch_click`'s
        // own doc comment on why that ordering matters.
        event_value
            .as_object()
            .and_then(|obj| {
                obj.get(js_string!("defaultPrevented"), &mut self.context)
                    .ok()
            })
            .and_then(|value| value.as_boolean())
            .unwrap_or(false)
    }

    /// Gives a text-editable `<input>` (see `layout::is_text_like_input`)
    /// focus, and places its text cursor at whichever character
    /// boundary is closest to `click_x` — see
    /// `ipc::ClientMessageKind::Focus`'s own doc comment for the full
    /// contract (`click_x`'s coordinate space, and why the renderer —
    /// not `app` — resolves it into a local offset). Returns `false`
    /// (a `Focus` `app` sent for a node that doesn't resolve, or isn't
    /// actually a text input — e.g. a race with a script mutation, or
    /// `app`'s own hit-test finding a DIFFERENT kind of element) without
    /// changing this session's focus at all.
    pub fn focus(&mut self, dom_node_id: dom::NodeId, click_x: f32, font: &text::Font) -> bool {
        let Some(node) = find_by_node_id(&self.document, dom_node_id) else {
            return false;
        };
        let is_text_input = matches!(
            &node.borrow().node_type,
            dom::NodeType::Element(el) if layout::is_text_like_input(el)
        );
        if !is_text_input {
            return false;
        }

        // A fresh relayout (discarded after this call — only its
        // GEOMETRY is needed) is how this resolves the input's own
        // on-screen content-box x without `app` ever having to know or
        // send it — the same "re-derive it locally" pattern
        // `dispatch_click`'s own `ancestor_chain` walk uses for a
        // click's target chain.
        let tree = self.relayout(font);
        let content_x = find_content_x(&tree, dom_node_id).unwrap_or(0.0);
        let value = get_attribute(&node, "value").unwrap_or_default();
        let local_x = (click_x - content_x).max(0.0);

        self.focused = Some(dom_node_id);
        self.cursor = text::char_index_for_x(font, &value, layout::DEFAULT_FONT_SIZE, local_x);
        true
    }

    /// Removes keyboard focus from whatever element currently has it,
    /// of any kind (see `focused`'s own doc comment) — a harmless no-op
    /// either way (see `ipc::ClientMessageKind::Blur`'s own doc
    /// comment).
    pub fn blur(&mut self) {
        self.focused = None;
    }

    /// Every element `Tab`/`Shift+Tab` should visit, in real document
    /// order — see `layout::is_keyboard_focusable`'s own doc comment
    /// for exactly which elements that is and the positive-`tabindex`-
    /// reordering scope cut. Recomputed fresh on every `MoveKeyboardFocus`
    /// (not cached) since a script can add/remove/disable focusable
    /// elements between two Tab presses.
    fn focusable_nodes(&self) -> Vec<dom::NodeId> {
        let mut out = Vec::new();
        collect_focusable_nodes(&self.document, &mut out);
        out
    }

    /// `Tab` (`ipc::FocusDirection::Next`) or `Shift+Tab` (`Previous`)
    /// — moves keyboard focus to the next/previous real focusable
    /// element (see `focusable_nodes`), WRAPPING past either end rather
    /// than stopping (real browsers wrap too, once DevTools/the address
    /// bar are accounted for as separate stops outside the page itself
    /// — which, in THIS browser, `app` already keeps entirely separate
    /// from this call in the first place, since it only sends this
    /// while the PAGE itself has keyboard focus). Returns the new focus
    /// target, or `None` if the page has no focusable elements at all
    /// (in which case `self.focused` is cleared too, rather than left
    /// pointing at a stale target). Landing on a text-like input places
    /// its cursor at the END of its current value — this DOM surface
    /// has no text-selection model at all (see `cursor`'s own doc
    /// comment), so "select everything" (many real browsers' actual
    /// default) isn't an option; end-of-text is the simpler, still
    /// reasonable choice.
    pub fn move_keyboard_focus(&mut self, direction: ipc::FocusDirection) -> Option<dom::NodeId> {
        let nodes = self.focusable_nodes();
        if nodes.is_empty() {
            self.focused = None;
            return None;
        }
        let current_index = self
            .focused
            .and_then(|id| nodes.iter().position(|&n| n == id));
        let next_index = match (direction, current_index) {
            (ipc::FocusDirection::Next, None) => 0,
            (ipc::FocusDirection::Next, Some(i)) => (i + 1) % nodes.len(),
            (ipc::FocusDirection::Previous, None) => nodes.len() - 1,
            (ipc::FocusDirection::Previous, Some(i)) => (i + nodes.len() - 1) % nodes.len(),
        };
        let new_focus = nodes[next_index];
        self.focused = Some(new_focus);
        self.cursor = find_by_node_id(&self.document, new_focus)
            .and_then(|node| get_attribute(&node, "value"))
            .map(|v| v.chars().count())
            .unwrap_or(0);
        Some(new_focus)
    }

    /// `Enter`/`Space` pressed while keyboard focus (see
    /// `move_keyboard_focus`) sits on something OTHER than a text-like
    /// input (text inputs have their own real key handling — see
    /// `ipc::ClientMessageKind::TextInput` — where Enter submits a form
    /// and Space just types a literal space character) — dispatches a
    /// real `click` event at the focused node, reusing `dispatch_click`
    /// wholesale: a keyboard "activation" and a mouse click are the
    /// SAME event as far as this crate's whole event model is concerned
    /// (real HTML doesn't distinguish them either — a `click` listener
    /// fires either way), which is also what makes a focused checkbox's
    /// default action (toggling) already work here with no extra code.
    /// A no-op (matching `dispatch_click`'s own "unresolved" shape) when
    /// nothing is focused at all.
    pub fn activate_focused(&mut self) -> ClickOutcome {
        let Some(dom_node_id) = self.focused else {
            return ClickOutcome {
                resolved: false,
                default_prevented: false,
                submit_url: None,
                submit_body: None,
            };
        };
        self.dispatch_click(dom_node_id)
    }

    /// Directly sets keyboard focus to `dom_node_id`, whatever it is —
    /// see `ipc::ClientMessageKind::FocusNode`'s own doc comment for
    /// why this is a separate, direct-by-id operation from
    /// `move_keyboard_focus`'s relative Tab/Shift+Tab movement (a real
    /// assistive technology names an exact target, it doesn't "Tab
    /// to" one). Returns whether `dom_node_id` actually resolves to a
    /// real, currently keyboard-focusable element (see `layout::
    /// is_keyboard_focusable`) in this session's CURRENT DOM — `false`
    /// leaves `self.focused` untouched entirely, same "an expected
    /// race, not an error" treatment `focus`/`move_keyboard_focus`
    /// already give a stale or unresolvable target.
    pub fn focus_node(&mut self, dom_node_id: dom::NodeId) -> bool {
        let Some(node) = find_by_node_id(&self.document, dom_node_id) else {
            return false;
        };
        let is_focusable = matches!(
            &node.borrow().node_type,
            dom::NodeType::Element(el) if layout::is_keyboard_focusable(el)
        );
        if !is_focusable {
            return false;
        }
        self.focused = Some(dom_node_id);
        self.cursor = get_attribute(&node, "value")
            .map(|v| v.chars().count())
            .unwrap_or(0);
        true
    }

    /// Applies one keystroke to whatever text input currently has
    /// focus — see `ipc::ClientMessageKind::TextInput`'s own doc
    /// comment for the full real-DOM-event-order contract (`keydown`
    /// first, then the actual edit and an `input` event, unless
    /// `keydown`'s `preventDefault()` was called) and
    /// `TextInputOutcome::submit_url`'s doc comment for the `Enter`/
    /// `<form>` case. `resolved: false` (nothing else in the outcome
    /// meaningful) covers both "nothing is focused right now" and "the
    /// focused node no longer resolves" (a script removed it, or the
    /// page navigated) — the second case also clears `self.focused`
    /// defensively, so a later message doesn't keep trying against a
    /// node that's already gone.
    pub fn handle_text_input(&mut self, action: ipc::TextInputAction) -> TextInputOutcome {
        let unresolved = TextInputOutcome {
            resolved: false,
            submit_url: None,
            submit_body: None,
        };
        let Some(focused_id) = self.focused else {
            return unresolved;
        };
        let Some(node) = find_by_node_id(&self.document, focused_id) else {
            self.focused = None;
            return unresolved;
        };

        // Clamps against whatever the value ACTUALLY is right now —
        // defensive against a script mutating `.value` directly (see
        // `build_element_object`'s own `value` accessor) between this
        // input's own focus/last keystroke and now, which this
        // session's `self.cursor` wouldn't otherwise know about.
        let char_count = get_attribute(&node, "value")
            .unwrap_or_default()
            .chars()
            .count();
        self.cursor = self.cursor.min(char_count);

        let chain = ancestor_chain(&node);
        let key = key_string(action);
        let key_props = format!("key: {}", js_string_literal(&key));
        let keydown_prevented = self.dispatch_event(&chain, "keydown", Some(&key_props));

        let mut submit_url = None;
        let mut submit_body = None;
        if !keydown_prevented {
            if let ipc::TextInputAction::Enter = action {
                if let Some(form) = find_ancestor_form(&node) {
                    let form_chain = ancestor_chain(&form);
                    let submit_prevented = self.dispatch_event(&form_chain, "submit", None);
                    if !submit_prevented {
                        if let Some((url, body)) = self.build_form_submission(&form) {
                            submit_url = Some(url);
                            submit_body = body;
                        }
                    }
                }
            } else {
                let old_value = get_attribute(&node, "value").unwrap_or_default();
                let mut chars: Vec<char> = old_value.chars().collect();
                match action {
                    ipc::TextInputAction::InsertChar(c) => {
                        let at = self.cursor.min(chars.len());
                        chars.insert(at, c);
                        self.cursor = at + 1;
                    }
                    ipc::TextInputAction::Backspace => {
                        if self.cursor > 0 {
                            chars.remove(self.cursor - 1);
                            self.cursor -= 1;
                        }
                    }
                    ipc::TextInputAction::ArrowLeft => {
                        self.cursor = self.cursor.saturating_sub(1);
                    }
                    ipc::TextInputAction::ArrowRight => {
                        self.cursor = (self.cursor + 1).min(chars.len());
                    }
                    ipc::TextInputAction::Home => self.cursor = 0,
                    ipc::TextInputAction::End => self.cursor = chars.len(),
                    ipc::TextInputAction::Enter => unreachable!("handled above"),
                }
                let new_value: String = chars.into_iter().collect();
                if new_value != old_value {
                    set_attribute(&node, "value", &new_value);
                    self.dispatch_event(&chain, "input", None);
                }
            }
        }

        TextInputOutcome {
            resolved: true,
            submit_url,
            submit_body,
        }
    }

    /// Builds what a real form submission would navigate to: `form`'s
    /// own `action` attribute (or this page's own URL, if unset —
    /// matching real HTML's default) resolved against `page_url`, and
    /// every named descendant text-like/`hidden`/checked-checkbox-or-
    /// radio `<input>`'s CURRENT value (see `collect_form_field_values`).
    /// `None` if `action`/`page_url` fails to resolve to a real URL at
    /// all.
    ///
    /// Branches on `form`'s `method` attribute, matching real HTML:
    ///   - GET (the default — no `method`, or any value other than
    ///     `"post"`, matching a real browser's own unrecognized-value
    ///     fallback): fields become a query string on the action URL
    ///     (replacing any query it already had), and the returned body
    ///     is `None`.
    ///   - POST: the action URL is returned UNCHANGED (no query-string
    ///     mutation), and the fields become the returned
    ///     `application/x-www-form-urlencoded` body instead — see
    ///     `ipc::RenderRequest::body`'s own doc comment for where this
    ///     goes next. Only this one encoding is built; a real
    ///     `enctype="multipart/form-data"` file-upload form still won't
    ///     work (there's no `<input type="file">` support at all to
    ///     feed one anyway).
    fn build_form_submission(&self, form: &dom::NodeRef) -> Option<(String, Option<Vec<u8>>)> {
        let (action, is_post) = match &form.borrow().node_type {
            dom::NodeType::Element(el) => (
                el.attributes.get("action").cloned(),
                el.attributes
                    .get("method")
                    .is_some_and(|m| m.eq_ignore_ascii_case("post")),
            ),
            _ => (None, false),
        };
        let base = url::Url::parse(&self.page_url).ok()?;
        let action_url = match action {
            Some(a) => base.join(&a).ok()?,
            None => base,
        };

        let mut fields = Vec::new();
        collect_form_field_values(form, &mut fields);

        if is_post {
            let body = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(fields.iter().map(|(k, v)| (k.as_str(), v.as_str())))
                .finish();
            Some((action_url.to_string(), Some(body.into_bytes())))
        } else {
            let mut result = action_url;
            result
                .query_pairs_mut()
                .clear()
                .extend_pairs(fields.iter().map(|(k, v)| (k.as_str(), v.as_str())));
            Some((result.to_string(), None))
        }
    }
}

/// What one `ipc::ClientMessageKind::TextInput` actually did — see
/// `ipc::RenderSuccess::submit_url`'s own doc comment for
/// `submit_url`'s exact meaning.
pub struct TextInputOutcome {
    pub resolved: bool,
    pub submit_url: Option<String>,
    pub submit_body: Option<Vec<u8>>,
}

/// The real DOM `KeyboardEvent.key` value for one `ipc::TextInputAction`
/// — a single character for `InsertChar`, the real spec-defined named
/// values (`"Backspace"`, `"ArrowLeft"`, ...) for everything else, so a
/// script's own `if (event.key === 'Enter')`-style check works exactly
/// like it would in a real browser.
fn key_string(action: ipc::TextInputAction) -> String {
    match action {
        ipc::TextInputAction::InsertChar(c) => c.to_string(),
        ipc::TextInputAction::Backspace => "Backspace".to_string(),
        ipc::TextInputAction::ArrowLeft => "ArrowLeft".to_string(),
        ipc::TextInputAction::ArrowRight => "ArrowRight".to_string(),
        ipc::TextInputAction::Home => "Home".to_string(),
        ipc::TextInputAction::End => "End".to_string(),
        ipc::TextInputAction::Enter => "Enter".to_string(),
    }
}

/// Escapes `s` for safe embedding as a double-quoted JS string literal
/// inside `eval`-ed source text. The only thing this crate ever embeds
/// this way is a single LOCAL, user-typed character (`key_string`'s
/// `InsertChar` case) — never remote/attacker-controlled page content
/// (see `json_parse`'s own doc comment for that separate, real
/// injection concern this crate takes seriously elsewhere) — but a
/// typed `"`/`\`/newline character still has to not break the
/// surrounding JS syntax, so this escapes properly regardless of the
/// (lower) stakes here.
fn js_string_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// True for a real HTML form-submit control: a `<button>` with no
/// `type` attribute or `type="submit"` (real HTML defaults a
/// `<button>` to `type="submit"` — `type="button"`/`"reset"` opt out),
/// or an `<input type="submit">`. What `dispatch_click` uses to decide
/// whether a click should attempt a real form submission, the same
/// way `handle_text_input` uses `find_ancestor_form` for `Enter`.
/// `<input type="image">` (also a real, if rare, submit control in
/// HTML) isn't covered — this crate has no image-input rendering to
/// have made one clickable in the first place.
fn is_submit_control(node: &dom::NodeRef) -> bool {
    match &node.borrow().node_type {
        dom::NodeType::Element(el) if el.tag_name == "button" => el
            .attributes
            .get("type")
            .is_none_or(|t| t.eq_ignore_ascii_case("submit")),
        dom::NodeType::Element(el) if el.tag_name == "input" => el
            .attributes
            .get("type")
            .is_some_and(|t| t.eq_ignore_ascii_case("submit")),
        _ => false,
    }
}

/// Walks up from `node` (NOT including it) looking for the nearest
/// ancestor `<form>` — what `handle_text_input` uses to decide whether
/// an `Enter` keystroke should attempt a real form submission at all.
fn find_ancestor_form(node: &dom::NodeRef) -> Option<dom::NodeRef> {
    let mut current = node
        .borrow()
        .parent
        .as_ref()
        .and_then(|weak| weak.upgrade());
    while let Some(n) = current {
        if matches!(&n.borrow().node_type, dom::NodeType::Element(el) if el.tag_name == "form") {
            return Some(n);
        }
        current = n.borrow().parent.as_ref().and_then(|weak| weak.upgrade());
    }
    None
}

/// Collects `(name, value)` for every descendant form field that a
/// real GET form submission would include, in document order — see
/// `Session::build_form_action_url`'s own doc comment for how these
/// become a real query string. Covers text-like/`hidden` `<input>`s
/// (always) and checkbox/radio `<input>`s (only when CHECKED — an
/// unchecked one contributes nothing at all, matching real HTML), each
/// with a `name` attribute; a checkbox/radio's value defaults to the
/// real HTML default `"on"` when no `value` attribute is set (unlike a
/// text-like input, whose value defaults to empty). Deliberately does
/// NOT collect `submit`/`button` inputs — this DOM surface has no
/// concept of "which button was pressed" to attach to a submission.
fn collect_form_field_values(node: &dom::NodeRef, out: &mut Vec<(String, String)>) {
    if let dom::NodeType::Element(el) = &node.borrow().node_type {
        let is_hidden = el
            .attributes
            .get("type")
            .is_some_and(|t| t.eq_ignore_ascii_case("hidden"));
        let checkable = layout::checkable_kind(el);
        let include = layout::is_text_like_input(el)
            || is_hidden
            || (checkable.is_some() && el.attributes.contains_key("checked"));
        if include {
            if let Some(name) = el.attributes.get("name") {
                let value = el.attributes.get("value").cloned().unwrap_or_else(|| {
                    if checkable.is_some() {
                        "on".to_string()
                    } else {
                        String::new()
                    }
                });
                out.push((name.clone(), value));
            }
        }
    }
    let children = node.borrow().children.clone();
    for child in &children {
        collect_form_field_values(child, out);
    }
}

/// Sets or removes the `checked` ATTRIBUTE (presence-based, matching
/// real HTML — see `layout::CheckableInputContent`'s own doc comment
/// on why this crate has no separate IDL-vs-attribute `checked`
/// concept) — the empty string is an arbitrary but conventional choice
/// for a present-but-valueless boolean attribute; nothing here ever
/// reads the VALUE back, only whether the key exists at all.
fn set_checked(node: &dom::NodeRef, checked: bool) {
    if checked {
        set_attribute(node, "checked", "");
    } else {
        remove_attribute(node, "checked");
    }
}

/// Un-checks every OTHER radio button under `scope` sharing `name` —
/// `except` (the one just clicked) is left untouched here; its own
/// caller (`apply_checkable_default_action`) checks it separately,
/// after this returns, so the two operations can't race each other in
/// a way that briefly leaves either zero or two radios checked at
/// once (not that anything here is concurrent — it's about keeping
/// the WRITE ORDER obviously correct to read, not a real race).
fn uncheck_other_radios_in_group(scope: &dom::NodeRef, name: &str, except: &dom::NodeRef) {
    let is_same_group_radio = matches!(
        &scope.borrow().node_type,
        dom::NodeType::Element(el)
            if layout::checkable_kind(el) == Some(layout::CheckableKind::Radio)
                && el.attributes.get("name").map(String::as_str) == Some(name)
    );
    if is_same_group_radio && !std::rc::Rc::ptr_eq(scope, except) {
        set_checked(scope, false);
    }
    let children = scope.borrow().children.clone();
    for child in &children {
        uncheck_other_radios_in_group(child, name, except);
    }
}

/// Finds the resolved CONTENT-box x of the `LayoutBox` built from
/// `node_id`, if it's anywhere in `tree` — what `Session::focus` uses
/// to turn an absolute `click_x` into a local offset within the
/// input's own value text, without `app` ever having to know that
/// box's on-screen geometry itself.
fn find_content_x(tree: &layout::LayoutBox, node_id: dom::NodeId) -> Option<f32> {
    if tree.dom_node_id == node_id {
        return Some(tree.rect.x + tree.border.left + tree.padding.left);
    }
    tree.children
        .iter()
        .find_map(|child| find_content_x(child, node_id))
}

/// What a `click` dispatch actually did — kept as two separate fields
/// (rather than, say, folding "unresolved" into `default_prevented:
/// false`) because `RendererState::handle_message` and
/// `app::Browser::handle_click` each care about a DIFFERENT one of
/// them: whether the target still existed decides `Rendered` vs
/// `Unchanged` on the wire; whether `preventDefault` was called decides
/// whether `app` still performs the click's default action.
pub struct ClickOutcome {
    pub resolved: bool,
    pub default_prevented: bool,
    /// Set the same way `TextInputOutcome::submit_url` is — see that
    /// field's own doc comment — when the clicked node was a form's
    /// submit control (see `is_submit_control`) and the click wasn't
    /// prevented.
    pub submit_url: Option<String>,
    pub submit_body: Option<Vec<u8>>,
}

/// Builds `[target_id, parent_id, ..., root_id]` — `node`'s real DOM
/// ancestor chain, target first, walking LIVE `Node.parent` pointers
/// (never the `LayoutBox` tree `app` hit-tested against to find `node`
/// in the first place — that snapshot has no parent links at all, see
/// `layout::LayoutBox`'s doc comment). Only Element nodes are
/// included: nothing else (`Document`, `Text`, `Comment`) can ever
/// have a listener registered on it in this DOM surface (see
/// `build_element_object`), so nothing else needs to appear in the
/// chain `PRELUDE_JS`'s `__dispatchEvent` walks — a non-Element
/// ancestor is skipped over rather than ending the walk, purely
/// defensively (today's DOM shape never actually produces one between
/// two elements).
fn ancestor_chain(node: &dom::NodeRef) -> Vec<u64> {
    let mut chain = Vec::new();
    let mut current = Some(node.clone());
    while let Some(n) = current {
        if matches!(n.borrow().node_type, dom::NodeType::Element(_)) {
            chain.push(n.borrow().id.0);
        }
        current = n.borrow().parent.as_ref().and_then(|weak| weak.upgrade());
    }
    chain
}

/// Convenience wrapper for callers (and most of this module's own
/// tests) that only care about running scripts against a DOM once and
/// don't need the session to persist afterward — builds a `Session`,
/// runs `scripts` against it, and drops it immediately. `document` is
/// mutated in place (via its own `Rc<RefCell<..>>` interior mutability)
/// regardless of the `Session` being discarded, since the DOM tree —
/// not the `Session` — is where the mutations actually live. Canvas
/// width/theme are irrelevant to callers that never call `relayout`,
/// so fixed placeholder values are used here.
pub fn run_scripts(document: &dom::NodeRef, scripts: &[String]) {
    if scripts.is_empty() {
        return;
    }
    // A `FakeFetcher` with nothing registered — `run_scripts` is a
    // best-effort test/demo convenience (see its own doc comment), not
    // a real navigation, so a script here that calls `fetch()` just
    // gets a rejected promise, same as any other genuinely unreachable
    // URL would produce.
    let fetcher = Rc::new(RefCell::new(network::FilteringFetcher::new(
        network::FakeFetcher::new(),
        privacy::Blocklist::with_seed_list(),
    )));
    let _session = Session::new(
        document.clone(),
        scripts,
        800.0,
        css::Theme::Dark,
        std::collections::HashMap::new(),
        std::collections::HashMap::new(),
        fetcher,
        "https://example.com/".to_string(),
        std::collections::HashMap::new(),
        std::collections::HashMap::new(),
    );
}

fn setup_globals<F: network::Fetcher + 'static>(
    context: &mut Context,
    document: dom::NodeRef,
    timers: HostTimers,
    console: HostConsole,
    fetch_state: FetchState<F>,
    local_storage_state: LocalStorageState,
    indexed_db_state: IndexedDbState,
) {
    let document_for_event_target = document.clone();
    let document_object = build_document_object(context, document);
    context
        .register_global_property(js_string!("document"), document_object, Attribute::all())
        .expect("registering a fresh global property never fails");

    let window_object = ObjectInitializer::new(context).build();
    context
        .register_global_property(js_string!("window"), window_object, Attribute::all())
        .expect("registering a fresh global property never fails");

    let schedule = NativeFunction::from_copy_closure_with_captures(
        |_this, args, timers: &HostTimers, _ctx| {
            let id = arg_as_u64(args, 0);
            let delay_ms = arg_as_u64(args, 1);
            let fire_at = std::time::Instant::now() + std::time::Duration::from_millis(delay_ms);
            timers.0.borrow_mut().push((id, fire_at));
            Ok(JsValue::undefined())
        },
        timers.clone(),
    );
    context
        .register_global_callable(js_string!("__scheduleNative"), 2, schedule)
        .expect("registering a fresh global callable never fails");

    let cancel = NativeFunction::from_copy_closure_with_captures(
        |_this, args, timers: &HostTimers, _ctx| {
            let id = arg_as_u64(args, 0);
            timers
                .0
                .borrow_mut()
                .retain(|(existing_id, _)| *existing_id != id);
            Ok(JsValue::undefined())
        },
        timers,
    );
    context
        .register_global_callable(js_string!("__cancelNative"), 1, cancel)
        .expect("registering a fresh global callable never fails");

    // A real `console` object (not bare globals like `__scheduleNative`/
    // `__cancelNative` above — `console.log` is real, user-facing JS
    // API surface a page's own script calls directly, unlike those two
    // internal-only hooks `PRELUDE_JS` calls on its behalf) with real
    // `log`/`info`/`warn`/`error` methods, each just tagging its
    // `HostConsole::push` call with a different `ipc::ConsoleLevel` —
    // see that enum's own doc comment for how `app`'s DevTools panel
    // uses the distinction.
    let console_log = NativeFunction::from_copy_closure_with_captures(
        |_this, args, console: &HostConsole, ctx| {
            console.push(ipc::ConsoleLevel::Log, format_console_args(args, ctx));
            Ok(JsValue::undefined())
        },
        console.clone(),
    );
    let console_info = NativeFunction::from_copy_closure_with_captures(
        |_this, args, console: &HostConsole, ctx| {
            console.push(ipc::ConsoleLevel::Info, format_console_args(args, ctx));
            Ok(JsValue::undefined())
        },
        console.clone(),
    );
    let console_warn = NativeFunction::from_copy_closure_with_captures(
        |_this, args, console: &HostConsole, ctx| {
            console.push(ipc::ConsoleLevel::Warn, format_console_args(args, ctx));
            Ok(JsValue::undefined())
        },
        console.clone(),
    );
    let console_error = NativeFunction::from_copy_closure_with_captures(
        |_this, args, console: &HostConsole, ctx| {
            console.push(ipc::ConsoleLevel::Error, format_console_args(args, ctx));
            Ok(JsValue::undefined())
        },
        console,
    );
    let console_object = ObjectInitializer::new(context)
        .function(console_log, js_string!("log"), 0)
        .function(console_info, js_string!("info"), 0)
        .function(console_warn, js_string!("warn"), 0)
        .function(console_error, js_string!("error"), 0)
        .build();
    context
        .register_global_property(js_string!("console"), console_object, Attribute::all())
        .expect("registering a fresh global property never fails");

    // `fetch(url)` — real, synchronous-under-the-hood but JS-visible-
    // async: this engine has no actual concurrent I/O (no event loop,
    // no threads — see this module's own docs on the execution model),
    // so the underlying HTTP request happens INLINE, right here,
    // before this native call even returns, through the exact same
    // blocklist-checking, cookie-jar-sharing, cache-aware
    // `FilteringFetcher` every other request on this tab already uses
    // (see `FetchState`'s own doc comment) — a third-party tracker
    // `fetch()` call from a page's own script is blocked exactly like
    // a third-party `<script src>`/`<img src>` would be. The RESULT is
    // then wrapped in an already-settled `JsPromise` (`resolve`/
    // `reject`), which is what makes `.then()`/`await` on the return
    // value work correctly despite there being no real asynchrony
    // underneath — see `build_response_object` for the (deliberately
    // narrow — no request headers/method/body, GET only) `Response`
    // shape this resolves to.
    let fetch_fn = NativeFunction::from_copy_closure_with_captures(
        |_this, args, state: &FetchState<F>, ctx| {
            let requested = arg_as_string(args, 0);
            let Some(base) = url::Url::parse(&state.page_url).ok() else {
                let err = JsNativeError::typ().with_message(format!(
                    "could not parse the page's own URL {:?}",
                    state.page_url
                ));
                return Ok(JsValue::from(JsPromise::reject(err, ctx)));
            };
            let Some(resolved_url) = base.join(&requested).ok().map(|u| u.to_string()) else {
                let err = JsNativeError::typ()
                    .with_message(format!("Failed to parse URL from {requested:?}"));
                return Ok(JsValue::from(JsPromise::reject(err, ctx)));
            };
            let page_host = base.host_str().map(str::to_string);
            let result = state
                .fetcher
                .borrow_mut()
                .fetch_in_context(&resolved_url, page_host.as_deref());
            match result {
                Ok(response) => {
                    let response_obj = build_response_object(ctx, response);
                    Ok(JsValue::from(JsPromise::resolve(response_obj, ctx)))
                }
                Err(e) => {
                    let message = match e {
                        network::FetchError::Blocked(host) => {
                            format!("blocked by privacy filter: {host}")
                        }
                        network::FetchError::NotFound(url) => format!("not found: {url}"),
                        network::FetchError::Network(msg) => format!("network error: {msg}"),
                    };
                    let err = JsNativeError::typ().with_message(message);
                    Ok(JsValue::from(JsPromise::reject(err, ctx)))
                }
            }
        },
        fetch_state,
    );
    context
        .register_global_callable(js_string!("__nativeFetch"), 1, fetch_fn)
        .expect("registering a fresh global callable never fails");

    // Registered under an internal name, NOT `localStorage` itself —
    // `PRELUDE_JS` wraps this in a real `Proxy` and installs THAT as
    // `window.localStorage`/bare `localStorage`, which is what gives
    // scripts real property-style access (`localStorage.foo = "bar"`)
    // on top of the method surface this object alone provides. No page
    // script has any legitimate reason to reach this name directly.
    let local_storage_object = build_local_storage_object(context, local_storage_state);
    context
        .register_global_property(
            js_string!("__nativeLocalStorage"),
            local_storage_object,
            Attribute::all(),
        )
        .expect("registering a fresh global property never fails");

    register_indexed_db_natives(context, indexed_db_state);

    // Internal plumbing `PRELUDE_JS`'s `__dispatchEvent` uses to build
    // `event.target`/`event.currentTarget` — the same "look up a node
    // and build a fresh wrapper object for it" operation
    // `getElementById` does (see `build_document_object`), just keyed
    // by `dom::NodeId` (`find_by_node_id`) instead of an `id="..."`
    // attribute (`find_by_id`). Not exposed as a real Web API — no
    // page script has any legitimate reason to call this directly.
    let resolve_event_target = unsafe {
        NativeFunction::from_closure_with_captures(
            |_this, args, doc: &HostNode, ctx| {
                let node_id = dom::NodeId(arg_as_u64(args, 0));
                match find_by_node_id(&doc.0, node_id) {
                    Some(node) => Ok(JsValue::from(build_element_object(ctx, node))),
                    None => Ok(JsValue::null()),
                }
            },
            HostNode(document_for_event_target),
        )
    };
    context
        .register_global_callable(js_string!("__resolveEventTarget"), 1, resolve_event_target)
        .expect("registering a fresh global callable never fails");

    if let Err(e) = context.eval(Source::from_bytes(PRELUDE_JS)) {
        eprintln!(
            "renderer: internal error installing the window/addEventListener/timer prelude: {e}"
        );
    }
    if let Err(e) = context.eval(Source::from_bytes(INDEXED_DB_PRELUDE_JS)) {
        eprintln!("renderer: internal error installing the indexedDB prelude: {e}");
    }
}

/// Registers every `__idb*` native function `INDEXED_DB_PRELUDE_JS`'s
/// `indexedDB` global is built out of — the IndexedDB equivalent of
/// `build_local_storage_object`, just registered as several bare
/// global callables (like `__nativeFetch`/`__scheduleNative`) rather
/// than methods on one object, since the JS-side shape (a real
/// `IDBDatabase`/`IDBObjectStore`/`IDBTransaction` object graph, not a
/// single flat object) is built entirely in `INDEXED_DB_PRELUDE_JS`
/// itself. Every real mutation (`__idbPut`/`__idbDelete`/`__idbClear`/
/// `__idbCreateObjectStore`/`__idbDeleteObjectStore`/`__idbOpen`'s own
/// upgrade path/`__idbDeleteDatabase`) goes straight through
/// `indexed_db::IndexedDbStore`'s already-synchronous, already-real
/// methods — there is no separate "pending transaction" state here to
/// keep in sync, matching `indexed_db`'s own module docs on why there's
/// no real rollback.
fn register_indexed_db_natives(context: &mut Context, state: IndexedDbState) {
    macro_rules! register {
        ($name:literal, $arity:literal, $body:expr) => {
            let f = NativeFunction::from_copy_closure_with_captures($body, state.clone());
            context
                .register_global_callable(js_string!($name), $arity, f)
                .expect("registering a fresh global callable never fails");
        };
    }

    register!("__idbOpen", 2, |_this,
                               args,
                               state: &IndexedDbState,
                               ctx| {
        let name = arg_as_string(args, 0);
        let requested_version = match args.get(1) {
            Some(v) if !v.is_undefined() && !v.is_null() => Some(v.to_number(ctx)? as u64),
            _ => None,
        };
        let outcome = state
            .store
            .borrow_mut()
            .open(&state.origin, &name, requested_version);
        let json = serde_json::json!({
            "oldVersion": outcome.old_version,
            "newVersion": outcome.new_version,
            "needsUpgrade": outcome.needs_upgrade,
        });
        JsValue::from_json(&json, ctx)
    });

    register!(
        "__idbDatabaseVersion",
        1,
        |_this, args, state: &IndexedDbState, _ctx| {
            let name = arg_as_string(args, 0);
            Ok(JsValue::from(
                state.store.borrow().database_version(&state.origin, &name) as f64,
            ))
        }
    );

    register!(
        "__idbCreateObjectStore",
        4,
        |_this, args, state: &IndexedDbState, _ctx| {
            let db_name = arg_as_string(args, 0);
            let store_name = arg_as_string(args, 1);
            let key_path = args
                .get(2)
                .filter(|v| !v.is_undefined() && !v.is_null())
                .and_then(|v| v.as_string())
                .map(|s| s.to_std_string_escaped());
            let auto_increment = args.get(3).is_some_and(JsValue::to_boolean);
            state
                .store
                .borrow_mut()
                .create_object_store(
                    &state.origin,
                    &db_name,
                    &store_name,
                    key_path,
                    auto_increment,
                )
                .map(|()| JsValue::undefined())
                .map_err(idb_error_to_js)
        }
    );

    register!(
        "__idbDeleteObjectStore",
        2,
        |_this, args, state: &IndexedDbState, _ctx| {
            let db_name = arg_as_string(args, 0);
            let store_name = arg_as_string(args, 1);
            state
                .store
                .borrow_mut()
                .delete_object_store(&state.origin, &db_name, &store_name)
                .map(|()| JsValue::undefined())
                .map_err(idb_error_to_js)
        }
    );

    register!(
        "__idbObjectStoreNames",
        1,
        |_this, args, state: &IndexedDbState, ctx| {
            let db_name = arg_as_string(args, 0);
            let names = state
                .store
                .borrow()
                .object_store_names(&state.origin, &db_name);
            let elements: Vec<JsValue> = names
                .into_iter()
                .map(|n| JsValue::from(js_string!(n)))
                .collect();
            Ok(JsValue::from(JsArray::from_iter(elements, ctx)))
        }
    );

    register!("__idbPut", 5, |_this, args, state: &IndexedDbState, ctx| {
        let db_name = arg_as_string(args, 0);
        let store_name = arg_as_string(args, 1);
        let value = idb_value_arg(args, 2, ctx)?;
        let key = idb_key_arg(args, 3, ctx)?;
        let is_add = args.get(4).is_some_and(JsValue::to_boolean);
        let result_key = state
            .store
            .borrow_mut()
            .put(&state.origin, &db_name, &store_name, value, key, is_add)
            .map_err(idb_error_to_js)?;
        JsValue::from_json(&result_key, ctx)
    });

    register!("__idbGet", 3, |_this, args, state: &IndexedDbState, ctx| {
        let db_name = arg_as_string(args, 0);
        let store_name = arg_as_string(args, 1);
        let Some(key) = idb_key_arg(args, 2, ctx)? else {
            return Err(JsNativeError::typ()
                .with_message("ConstraintError: IndexedDB get() requires a key")
                .into());
        };
        let result = state
            .store
            .borrow()
            .get(&state.origin, &db_name, &store_name, &key)
            .map_err(idb_error_to_js)?;
        match result {
            Some(value) => JsValue::from_json(&value, ctx),
            None => Ok(JsValue::null()),
        }
    });

    register!("__idbGetAll", 2, |_this,
                                 args,
                                 state: &IndexedDbState,
                                 ctx| {
        let db_name = arg_as_string(args, 0);
        let store_name = arg_as_string(args, 1);
        let values = state
            .store
            .borrow()
            .get_all(&state.origin, &db_name, &store_name)
            .map_err(idb_error_to_js)?;
        JsValue::from_json(&serde_json::Value::Array(values), ctx)
    });

    register!(
        "__idbGetAllKeys",
        2,
        |_this, args, state: &IndexedDbState, ctx| {
            let db_name = arg_as_string(args, 0);
            let store_name = arg_as_string(args, 1);
            let keys = state
                .store
                .borrow()
                .get_all_keys(&state.origin, &db_name, &store_name)
                .map_err(idb_error_to_js)?;
            JsValue::from_json(&serde_json::Value::Array(keys), ctx)
        }
    );

    register!("__idbDelete", 3, |_this,
                                 args,
                                 state: &IndexedDbState,
                                 ctx| {
        let db_name = arg_as_string(args, 0);
        let store_name = arg_as_string(args, 1);
        let Some(key) = idb_key_arg(args, 2, ctx)? else {
            return Err(JsNativeError::typ()
                .with_message("ConstraintError: IndexedDB delete() requires a key")
                .into());
        };
        state
            .store
            .borrow_mut()
            .delete(&state.origin, &db_name, &store_name, &key)
            .map(|()| JsValue::undefined())
            .map_err(idb_error_to_js)
    });

    register!("__idbClear", 2, |_this,
                                args,
                                state: &IndexedDbState,
                                _ctx| {
        let db_name = arg_as_string(args, 0);
        let store_name = arg_as_string(args, 1);
        state
            .store
            .borrow_mut()
            .clear(&state.origin, &db_name, &store_name)
            .map(|()| JsValue::undefined())
            .map_err(idb_error_to_js)
    });

    register!("__idbCount", 2, |_this,
                                args,
                                state: &IndexedDbState,
                                _ctx| {
        let db_name = arg_as_string(args, 0);
        let store_name = arg_as_string(args, 1);
        state
            .store
            .borrow()
            .count(&state.origin, &db_name, &store_name)
            .map(|count| JsValue::from(count as f64))
            .map_err(idb_error_to_js)
    });

    register!(
        "__idbDeleteDatabase",
        1,
        |_this, args, state: &IndexedDbState, _ctx| {
            let db_name = arg_as_string(args, 0);
            state
                .store
                .borrow_mut()
                .delete_database(&state.origin, &db_name);
            Ok(JsValue::undefined())
        }
    );
}

/// The real `indexedDB` global — built entirely in JS on top of the
/// `__idb*` native functions `register_indexed_db_natives` registers,
/// the same layering `PRELUDE_JS` uses for `window.localStorage`'s own
/// `Proxy`. Every `IDBRequest` this returns settles asynchronously,
/// via a real, already-resolved `Promise`'s `.then()` (guaranteed by
/// spec to run as a microtask, never synchronously) — never
/// synchronously within the very call that created it — matching real
/// `IDBRequest`'s own guarantee that `onsuccess`/`onerror` never fire
/// before the calling script has had a chance to assign them. See
/// `indexed_db`'s own module docs for exactly what subset of the real
/// API this covers (no indexes, no cursors, no key ranges, no
/// cross-connection `versionchange`).
const INDEXED_DB_PRELUDE_JS: &str = r#"
(function () {
    function makeRequest() {
        return {
            result: undefined,
            error: null,
            onsuccess: null,
            onerror: null,
            _successListeners: [],
            _errorListeners: [],
            addEventListener: function (type, cb) {
                if (type === 'success') { this._successListeners.push(cb); }
                else if (type === 'error') { this._errorListeners.push(cb); }
            }
        };
    }

    function fireSuccess(req, value) {
        req.result = value;
        req.error = null;
        var event = { type: 'success', target: req };
        if (req.onsuccess) { try { req.onsuccess(event); } catch (e) {} }
        for (var i = 0; i < req._successListeners.length; i++) {
            try { req._successListeners[i](event); } catch (e) {}
        }
    }

    function fireError(req, error) {
        req.error = error;
        var event = { type: 'error', target: req };
        if (req.onerror) { try { req.onerror(event); } catch (e) {} }
        for (var i = 0; i < req._errorListeners.length; i++) {
            try { req._errorListeners[i](event); } catch (e) {}
        }
    }

    // Deferred exactly one real microtask — see this constant's own
    // doc comment on why an already-resolved `Promise`'s `.then()`,
    // not an immediate call, is what real `IDBRequest` semantics need.
    function settle(req, isSuccess, value) {
        Promise.resolve().then(function () {
            if (isSuccess) { fireSuccess(req, value); } else { fireError(req, value); }
        });
    }

    function runRequest(fn) {
        var req = makeRequest();
        var value;
        try {
            value = fn();
        } catch (e) {
            settle(req, false, e);
            return req;
        }
        settle(req, true, value);
        return req;
    }

    function buildObjectStore(dbName, storeName) {
        return {
            name: storeName,
            put: function (value, key) {
                return runRequest(function () { return __idbPut(dbName, storeName, value, key, false); });
            },
            add: function (value, key) {
                return runRequest(function () { return __idbPut(dbName, storeName, value, key, true); });
            },
            get: function (key) {
                return runRequest(function () { return __idbGet(dbName, storeName, key); });
            },
            getAll: function () {
                return runRequest(function () { return __idbGetAll(dbName, storeName); });
            },
            getAllKeys: function () {
                return runRequest(function () { return __idbGetAllKeys(dbName, storeName); });
            },
            delete: function (key) {
                return runRequest(function () { __idbDelete(dbName, storeName, key); return undefined; });
            },
            clear: function () {
                return runRequest(function () { __idbClear(dbName, storeName); return undefined; });
            },
            count: function () {
                return runRequest(function () { return __idbCount(dbName, storeName); });
            }
        };
    }

    function buildTransaction(dbName, storeNames, mode) {
        var tx = {
            mode: mode || 'readonly',
            oncomplete: null,
            onerror: null,
            onabort: null,
            objectStore: function (storeName) {
                return buildObjectStore(dbName, storeName);
            }
        };
        // A real transaction auto-commits once every request it was
        // given has settled and no more are queued within the same
        // task — every `__idb*` call this file makes is already
        // synchronous and immediately committed (see `indexed_db`'s
        // own module docs on why there's no real rollback), so "done"
        // is simply "one microtask later," same as `settle` above.
        Promise.resolve().then(function () {
            if (tx.oncomplete) { try { tx.oncomplete({ type: 'complete', target: tx }); } catch (e) {} }
        });
        return tx;
    }

    function buildDatabase(name, version) {
        return {
            name: name,
            version: version,
            get objectStoreNames() {
                var names = __idbObjectStoreNames(name);
                names.contains = function (n) { return names.indexOf(n) !== -1; };
                return names;
            },
            createObjectStore: function (storeName, options) {
                var keyPath = (options && options.keyPath !== undefined) ? options.keyPath : null;
                var autoIncrement = !!(options && options.autoIncrement);
                __idbCreateObjectStore(name, storeName, keyPath, autoIncrement);
                return buildObjectStore(name, storeName);
            },
            deleteObjectStore: function (storeName) {
                __idbDeleteObjectStore(name, storeName);
            },
            transaction: function (storeNames, mode) {
                return buildTransaction(name, storeNames, mode);
            },
            close: function () {}
        };
    }

    window.indexedDB = {
        open: function (name, version) {
            var req = makeRequest();
            var outcome = __idbOpen(name, version);
            Promise.resolve().then(function () {
                var db = buildDatabase(name, outcome.newVersion);
                if (outcome.needsUpgrade) {
                    req.result = db;
                    var upgradeEvent = {
                        type: 'upgradeneeded',
                        target: req,
                        oldVersion: outcome.oldVersion,
                        newVersion: outcome.newVersion
                    };
                    if (req.onupgradeneeded) { try { req.onupgradeneeded(upgradeEvent); } catch (e) {} }
                }
                fireSuccess(req, db);
            });
            return req;
        },
        deleteDatabase: function (name) {
            return runRequest(function () { __idbDeleteDatabase(name); return undefined; });
        }
    };
    indexedDB = window.indexedDB;
})();
"#;

/// Builds `__nativeLocalStorage` — the real method surface
/// (`getItem`/`setItem`/`removeItem`/`clear`/`key`/`.length`) that
/// `PRELUDE_JS` then wraps in a `Proxy` and installs as the actual
/// `localStorage`/`window.localStorage` a page script sees, giving it
/// real property-style access too (see `PRELUDE_JS`'s own comments on
/// that `Proxy`). Also the point where every real mutation gets
/// recorded into `state.pending_events` as a `StorageChange`, for the
/// cross-tab `storage` event (see that type's own doc comment). A real
/// `setItem` that exceeds `local_storage::MAX_BYTES_PER_ORIGIN` throws
/// a real, catchable `QuotaExceededError`-shaped exception — same as a
/// real browser's `localStorage.setItem` at capacity.
fn build_local_storage_object(context: &mut Context, state: LocalStorageState) -> JsObject {
    let get_item = NativeFunction::from_copy_closure_with_captures(
        |_this, args, state: &LocalStorageState, _ctx| {
            let key = arg_as_string(args, 0);
            let store = state.store.borrow();
            Ok(match store.get(&state.origin, &key) {
                Some(value) => JsValue::from(js_string!(value)),
                None => JsValue::null(),
            })
        },
        state.clone(),
    );

    let set_item = NativeFunction::from_copy_closure_with_captures(
        |_this, args, state: &LocalStorageState, _ctx| {
            let key = arg_as_string(args, 0);
            let value = arg_as_string(args, 1);
            let previous = {
                let mut store = state.store.borrow_mut();
                match store.set(&state.origin, key.clone(), value.clone()) {
                    Ok(previous) => previous,
                    Err(local_storage::QuotaExceeded) => {
                        return Err(JsNativeError::typ()
                            .with_message(
                                "QuotaExceededError: localStorage is full for this origin",
                            )
                            .into());
                    }
                }
            };
            if previous.as_deref() != Some(value.as_str()) {
                state.pending_events.borrow_mut().push(StorageChange {
                    origin: state.origin.clone(),
                    url: state.page_url.clone(),
                    key: Some(key),
                    old_value: previous,
                    new_value: Some(value),
                });
            }
            Ok(JsValue::undefined())
        },
        state.clone(),
    );

    let remove_item = NativeFunction::from_copy_closure_with_captures(
        |_this, args, state: &LocalStorageState, _ctx| {
            let key = arg_as_string(args, 0);
            let previous = state.store.borrow_mut().remove(&state.origin, &key);
            if let Some(previous) = previous {
                state.pending_events.borrow_mut().push(StorageChange {
                    origin: state.origin.clone(),
                    url: state.page_url.clone(),
                    key: Some(key),
                    old_value: Some(previous),
                    new_value: None,
                });
            }
            Ok(JsValue::undefined())
        },
        state.clone(),
    );

    let clear = NativeFunction::from_copy_closure_with_captures(
        |_this, _args, state: &LocalStorageState, _ctx| {
            let cleared_something = state.store.borrow_mut().clear(&state.origin);
            if cleared_something {
                state.pending_events.borrow_mut().push(StorageChange {
                    origin: state.origin.clone(),
                    url: state.page_url.clone(),
                    key: None,
                    old_value: None,
                    new_value: None,
                });
            }
            Ok(JsValue::undefined())
        },
        state.clone(),
    );

    let key_fn = NativeFunction::from_copy_closure_with_captures(
        |_this, args, state: &LocalStorageState, _ctx| {
            let index = arg_as_u64(args, 0) as usize;
            let store = state.store.borrow();
            Ok(match store.key_at(&state.origin, index) {
                Some(key) => JsValue::from(js_string!(key)),
                None => JsValue::null(),
            })
        },
        state.clone(),
    );

    let length_get = NativeFunction::from_copy_closure_with_captures(
        |_this, _args, state: &LocalStorageState, _ctx| {
            let store = state.store.borrow();
            Ok(JsValue::from(store.len(&state.origin) as u32))
        },
        state,
    )
    .to_js_function(context.realm());

    ObjectInitializer::new(context)
        .function(get_item, js_string!("getItem"), 1)
        .function(set_item, js_string!("setItem"), 2)
        .function(remove_item, js_string!("removeItem"), 1)
        .function(clear, js_string!("clear"), 0)
        .function(key_fn, js_string!("key"), 1)
        .accessor(
            js_string!("length"),
            Some(length_get),
            None,
            Attribute::all(),
        )
        .build()
}

fn build_document_object(context: &mut Context, document: dom::NodeRef) -> JsObject {
    let title_get = unsafe {
        NativeFunction::from_closure_with_captures(
            |_this, _args, doc: &HostNode, _ctx| {
                Ok(JsValue::from(js_string!(
                    find_title(&doc.0).unwrap_or_default()
                )))
            },
            HostNode(document.clone()),
        )
    }
    .to_js_function(context.realm());

    let title_set = unsafe {
        NativeFunction::from_closure_with_captures(
            |_this, args, doc: &HostNode, _ctx| {
                set_title(&doc.0, &arg_as_string(args, 0));
                Ok(JsValue::undefined())
            },
            HostNode(document.clone()),
        )
    }
    .to_js_function(context.realm());

    let get_element_by_id = unsafe {
        NativeFunction::from_closure_with_captures(
            |_this, args, doc: &HostNode, ctx| {
                let id = arg_as_string(args, 0);
                match find_by_id(&doc.0, &id) {
                    Some(node) => Ok(JsValue::from(build_element_object(ctx, node))),
                    None => Ok(JsValue::null()),
                }
            },
            HostNode(document.clone()),
        )
    };

    let query_selector_fn = unsafe {
        NativeFunction::from_closure_with_captures(
            |_this, args, doc: &HostNode, ctx| {
                let selector = arg_as_string(args, 0);
                Ok(match query_selector_first(&doc.0, &selector) {
                    Some(found) => JsValue::from(build_element_object(ctx, found)),
                    None => JsValue::null(),
                })
            },
            HostNode(document.clone()),
        )
    };
    let query_selector_all_fn = unsafe {
        NativeFunction::from_closure_with_captures(
            |_this, args, doc: &HostNode, ctx| {
                let selector = arg_as_string(args, 0);
                let elements: Vec<JsValue> = query_selector_all(&doc.0, &selector)
                    .into_iter()
                    .map(|found| JsValue::from(build_element_object(ctx, found)))
                    .collect();
                Ok(JsValue::from(JsArray::from_iter(elements, ctx)))
            },
            HostNode(document.clone()),
        )
    };

    // `createElement` builds a brand-new, DETACHED element node (not
    // yet part of `document` at all — real DOM behavior too: the
    // caller has to `appendChild`/etc. it somewhere before it shows up
    // anywhere). Wrapping it through the SAME `build_element_object`
    // every other element uses is what makes the returned object
    // immediately usable with `appendChild`, `setAttribute`, and
    // everything else — no separate "unattached element" type needed.
    let create_element = NativeFunction::from_copy_closure(|_this, args, ctx| {
        let tag_name = arg_as_string(args, 0);
        let node = dom::Node::new_element(&tag_name);
        Ok(JsValue::from(build_element_object(ctx, node)))
    });

    ObjectInitializer::new(context)
        .accessor(
            js_string!("title"),
            Some(title_get),
            Some(title_set),
            Attribute::all(),
        )
        .function(get_element_by_id, js_string!("getElementById"), 1)
        .function(query_selector_fn, js_string!("querySelector"), 1)
        .function(query_selector_all_fn, js_string!("querySelectorAll"), 1)
        .function(create_element, js_string!("createElement"), 1)
        .build()
}

fn build_element_object(context: &mut Context, node: dom::NodeRef) -> JsObject {
    // `<input>.value` — real DOM exposes this as its own IDL property,
    // separate from `getAttribute('value')` (which, per spec, only
    // ever reflects the ORIGINAL `value="..."` attribute, not later
    // edits) — this crate doesn't model that distinction (see this
    // module's own doc comment on `TextInputContent`/`handle_text_input`),
    // so `.value` here is just a friendlier name for the exact same
    // `value` attribute `getAttribute`/`setAttribute` already read and
    // write. Real-world scripts overwhelmingly use `.value` directly
    // (to clear a field, read it for validation, etc.), so exposing it
    // costs little and matters a lot for compatibility.
    let value_get = unsafe {
        NativeFunction::from_closure_with_captures(
            |_this, _args, n: &HostNode, _ctx| {
                Ok(JsValue::from(js_string!(
                    get_attribute(&n.0, "value").unwrap_or_default()
                )))
            },
            HostNode(node.clone()),
        )
    }
    .to_js_function(context.realm());
    let value_set = unsafe {
        NativeFunction::from_closure_with_captures(
            |_this, args, n: &HostNode, _ctx| {
                set_attribute(&n.0, "value", &arg_as_string(args, 0));
                Ok(JsValue::undefined())
            },
            HostNode(node.clone()),
        )
    }
    .to_js_function(context.realm());

    let get_attribute_fn = unsafe {
        NativeFunction::from_closure_with_captures(
            |_this, args, n: &HostNode, _ctx| {
                Ok(match get_attribute(&n.0, &arg_as_string(args, 0)) {
                    Some(value) => JsValue::from(js_string!(value)),
                    None => JsValue::null(),
                })
            },
            HostNode(node.clone()),
        )
    };
    let set_attribute_fn = unsafe {
        NativeFunction::from_closure_with_captures(
            |_this, args, n: &HostNode, _ctx| {
                set_attribute(&n.0, &arg_as_string(args, 0), &arg_as_string(args, 1));
                Ok(JsValue::undefined())
            },
            HostNode(node.clone()),
        )
    };
    let remove_attribute_fn = unsafe {
        NativeFunction::from_closure_with_captures(
            |_this, args, n: &HostNode, _ctx| {
                remove_attribute(&n.0, &arg_as_string(args, 0));
                Ok(JsValue::undefined())
            },
            HostNode(node.clone()),
        )
    };

    let append_child_fn = unsafe {
        NativeFunction::from_closure_with_captures(
            |_this, args, n: &HostNode, _ctx| {
                let Some(child) = args.first().and_then(node_from_js_value) else {
                    // Real `appendChild` throws a `TypeError` for a
                    // non-Node argument; this DOM surface doesn't model
                    // exceptions from native calls that finely yet (see
                    // module docs) — silently doing nothing is the same
                    // "degrade rather than crash" fallback used
                    // elsewhere in this crate for a malformed call.
                    return Ok(JsValue::undefined());
                };
                dom::append_child(&n.0, child);
                Ok(args.first().cloned().unwrap_or_else(JsValue::undefined))
            },
            HostNode(node.clone()),
        )
    };

    let query_selector_fn = unsafe {
        NativeFunction::from_closure_with_captures(
            |_this, args, n: &HostNode, ctx| {
                let selector = arg_as_string(args, 0);
                Ok(match query_selector_first(&n.0, &selector) {
                    Some(found) => JsValue::from(build_element_object(ctx, found)),
                    None => JsValue::null(),
                })
            },
            HostNode(node.clone()),
        )
    };
    let query_selector_all_fn = unsafe {
        NativeFunction::from_closure_with_captures(
            |_this, args, n: &HostNode, ctx| {
                let selector = arg_as_string(args, 0);
                let elements: Vec<JsValue> = query_selector_all(&n.0, &selector)
                    .into_iter()
                    .map(|found| JsValue::from(build_element_object(ctx, found)))
                    .collect();
                Ok(JsValue::from(JsArray::from_iter(elements, ctx)))
            },
            HostNode(node.clone()),
        )
    };

    let text_get = unsafe {
        NativeFunction::from_closure_with_captures(
            |_this, _args, n: &HostNode, _ctx| Ok(JsValue::from(js_string!(text_content(&n.0)))),
            HostNode(node.clone()),
        )
    }
    .to_js_function(context.realm());

    let text_set = unsafe {
        NativeFunction::from_closure_with_captures(
            |_this, args, n: &HostNode, _ctx| {
                set_text_content(&n.0, &arg_as_string(args, 0));
                Ok(JsValue::undefined())
            },
            HostNode(node.clone()),
        )
    }
    .to_js_function(context.realm());

    let add_fn = unsafe {
        NativeFunction::from_closure_with_captures(
            |_this, args, n: &HostNode, _ctx| {
                class_list_add(&n.0, &arg_as_string(args, 0));
                Ok(JsValue::undefined())
            },
            HostNode(node.clone()),
        )
    };
    let remove_fn = unsafe {
        NativeFunction::from_closure_with_captures(
            |_this, args, n: &HostNode, _ctx| {
                class_list_remove(&n.0, &arg_as_string(args, 0));
                Ok(JsValue::undefined())
            },
            HostNode(node.clone()),
        )
    };
    let contains_fn = unsafe {
        NativeFunction::from_closure_with_captures(
            |_this, args, n: &HostNode, _ctx| {
                Ok(JsValue::from(class_list_contains(
                    &n.0,
                    &arg_as_string(args, 0),
                )))
            },
            HostNode(node.clone()),
        )
    };

    let class_list = ObjectInitializer::new(context)
        .function(add_fn, js_string!("add"), 1)
        .function(remove_fn, js_string!("remove"), 1)
        .function(contains_fn, js_string!("contains"), 1)
        .build();

    // Built via `window.__makeEventTarget` (see `PRELUDE_JS`) rather
    // than as its own native function here: the listener storage it
    // closes over has to be plain JS state keyed by this node's
    // `dom::NodeId` (see that type's doc comment and `PRELUDE_JS`'s own
    // comment on why), and that storage already exists as one shared
    // JS object — reusing it here is simpler than re-implementing the
    // same registry as a second native closure.
    let node_id = node.borrow().id.0;
    let add_event_listener = build_event_target(context, node_id)
        .and_then(|target| target.get(js_string!("addEventListener"), context).ok())
        .unwrap_or_else(JsValue::undefined);

    // `with_native_data` (not `::new`) is what makes this wrapper
    // DOWNCASTABLE back to the `dom::NodeRef` it wraps (via
    // `node_from_js_value`) — the piece that was missing before and is
    // what makes `appendChild(otherElement)` possible at all: a native
    // function receiving one element wrapper as an argument needs a
    // way to recover which live node it refers to, not just call
    // methods already bound to IT specifically.
    ObjectInitializer::with_native_data(HostNode(node.clone()), context)
        .accessor(
            js_string!("textContent"),
            Some(text_get),
            Some(text_set),
            Attribute::all(),
        )
        .accessor(
            js_string!("value"),
            Some(value_get),
            Some(value_set),
            Attribute::all(),
        )
        .property(js_string!("classList"), class_list, Attribute::all())
        .property(
            js_string!("addEventListener"),
            add_event_listener,
            Attribute::all(),
        )
        .function(get_attribute_fn, js_string!("getAttribute"), 1)
        .function(set_attribute_fn, js_string!("setAttribute"), 2)
        .function(remove_attribute_fn, js_string!("removeAttribute"), 1)
        .function(append_child_fn, js_string!("appendChild"), 1)
        .function(query_selector_fn, js_string!("querySelector"), 1)
        .function(query_selector_all_fn, js_string!("querySelectorAll"), 1)
        .build()
}

fn build_event_target(context: &mut Context, node_id: u64) -> Option<JsObject> {
    let script = format!("window.__makeEventTarget({node_id})");
    match context.eval(Source::from_bytes(script.as_bytes())) {
        Ok(value) => value.as_object().cloned(),
        Err(e) => {
            eprintln!("renderer: internal error building an element's event target (its addEventListener will be missing): {e}");
            None
        }
    }
}

/// The object `fetch()`'s Promise resolves to — deliberately narrow:
/// `ok`/`status` (real fetch semantics: `ok` is true for any 2xx, NOT
/// tied to the promise settling — a 404 still resolves, it just has
/// `ok: false`, matching the real Fetch API's "only a network-level
/// failure rejects" behavior) plus `text()`/`json()`, each ANOTHER
/// promise (real fetch shape too — reading the body is itself async).
/// No `headers`, no streaming `body` reader, no `.blob()`/`.arrayBuffer()`.
fn build_response_object(context: &mut Context, response: network::Response) -> JsObject {
    let status = response.status;
    let ok = (200..300).contains(&status);
    let body = response.body;

    let text_fn = NativeFunction::from_copy_closure_with_captures(
        |_this, _args, body: &Vec<u8>, ctx| {
            let text = String::from_utf8_lossy(body).into_owned();
            Ok(JsValue::from(JsPromise::resolve(js_string!(text), ctx)))
        },
        body.clone(),
    );
    let json_fn = NativeFunction::from_copy_closure_with_captures(
        |_this, _args, body: &Vec<u8>, ctx| {
            let text = String::from_utf8_lossy(body).into_owned();
            match json_parse(ctx, &text) {
                Ok(value) => Ok(JsValue::from(JsPromise::resolve(value, ctx))),
                Err(e) => Ok(JsValue::from(JsPromise::reject(e, ctx))),
            }
        },
        body,
    );

    ObjectInitializer::new(context)
        .property(js_string!("ok"), ok, Attribute::all())
        .property(js_string!("status"), i32::from(status), Attribute::all())
        .function(text_fn, js_string!("text"), 0)
        .function(json_fn, js_string!("json"), 0)
        .build()
}

/// Calls the REAL global `JSON.parse` (looked up and invoked as an
/// ordinary JS function call, not re-implemented here) on `text` —
/// deliberately not a hand-rolled parser, and deliberately not built
/// by interpolating `text` into a string of JS source and `eval`-ing
/// it (`response.json()`'s whole point is parsing untrusted,
/// attacker-influenced response bodies — interpolating one into
/// source text handed to `eval` would let a crafted body escape its
/// string literal and run arbitrary script, exactly the injection
/// class this avoids by passing `text` as a real argument value
/// instead).
fn json_parse(context: &mut Context, text: &str) -> Result<JsValue, JsError> {
    let missing_json =
        || JsError::from(JsNativeError::typ().with_message("JSON.parse is unavailable"));
    let json_ns = context
        .global_object()
        .get(js_string!("JSON"), context)?
        .as_object()
        .cloned()
        .ok_or_else(missing_json)?;
    let parse_fn = json_ns
        .get(js_string!("parse"), context)?
        .as_object()
        .cloned()
        .ok_or_else(missing_json)?;
    parse_fn.call(
        &JsValue::undefined(),
        &[JsValue::from(js_string!(text))],
        context,
    )
}

// --- Plain DOM helpers (no Boa types below this line) ---

/// Pre-order walk collecting every DESCENDANT element matching
/// `selector` (via `css::matches`) — real `querySelectorAll`
/// semantics: `context_node` itself is never included, even if it
/// would match (real DOM `querySelectorAll` only ever searches
/// descendants of the node/document it's called on). Shared by both
/// `document.querySelectorAll` and an element's own
/// `.querySelectorAll`.
fn query_selector_all(context_node: &dom::NodeRef, selector: &str) -> Vec<dom::NodeRef> {
    let mut out = Vec::new();
    let children = context_node.borrow().children.clone();
    for child in &children {
        collect_selector_matches(child, selector, &mut out);
    }
    out
}

fn collect_selector_matches(node: &dom::NodeRef, selector: &str, out: &mut Vec<dom::NodeRef>) {
    if matches!(node.borrow().node_type, dom::NodeType::Element(_)) && css::matches(selector, node)
    {
        out.push(node.clone());
    }
    let children = node.borrow().children.clone();
    for child in &children {
        collect_selector_matches(child, selector, out);
    }
}

/// The first-match half of `query_selector_all` — same "descendants
/// only, never the context node itself" scoping, stopping at the
/// first (document-order, depth-first) match instead of collecting
/// all of them.
fn query_selector_first(context_node: &dom::NodeRef, selector: &str) -> Option<dom::NodeRef> {
    let children = context_node.borrow().children.clone();
    children
        .iter()
        .find_map(|child| find_first_selector_match(child, selector))
}

fn find_first_selector_match(node: &dom::NodeRef, selector: &str) -> Option<dom::NodeRef> {
    if matches!(node.borrow().node_type, dom::NodeType::Element(_)) && css::matches(selector, node)
    {
        return Some(node.clone());
    }
    let children = node.borrow().children.clone();
    children
        .iter()
        .find_map(|child| find_first_selector_match(child, selector))
}

fn get_attribute(node: &dom::NodeRef, name: &str) -> Option<String> {
    match &node.borrow().node_type {
        dom::NodeType::Element(el) => el.attributes.get(name).cloned(),
        _ => None,
    }
}

fn set_attribute(node: &dom::NodeRef, name: &str, value: &str) {
    if let dom::NodeType::Element(el) = &mut node.borrow_mut().node_type {
        el.attributes.insert(name.to_string(), value.to_string());
    }
}

fn remove_attribute(node: &dom::NodeRef, name: &str) {
    if let dom::NodeType::Element(el) = &mut node.borrow_mut().node_type {
        el.attributes.remove(name);
    }
}

fn find_by_id(node: &dom::NodeRef, id: &str) -> Option<dom::NodeRef> {
    let is_match = matches!(
        &node.borrow().node_type,
        dom::NodeType::Element(el) if el.attributes.get("id").map(String::as_str) == Some(id)
    );
    if is_match {
        return Some(node.clone());
    }
    let children = node.borrow().children.clone();
    children.iter().find_map(|child| find_by_id(child, id))
}

/// Finds the node with structural identity `id` (see `dom::NodeId`'s
/// doc comment) — NOT the same lookup as `find_by_id`, which matches
/// an HTML `id="..."` attribute instead. Any node type can match here
/// (an element, or a text node — `layout::hit_test_node` only ever
/// resolves to an element's id in practice, but nothing here assumes
/// that, since a stale id from a since-mutated DOM should just fail to
/// resolve, not panic on an unexpected node type).
fn find_by_node_id(node: &dom::NodeRef, id: dom::NodeId) -> Option<dom::NodeRef> {
    if node.borrow().id == id {
        return Some(node.clone());
    }
    let children = node.borrow().children.clone();
    children.iter().find_map(|child| find_by_node_id(child, id))
}

/// The recursive half of `Session::focusable_nodes` — depth-first,
/// document order, matching every other DOM-order walk in this module
/// (`query_selector_all`, `find_by_node_id`, ...).
fn collect_focusable_nodes(node: &dom::NodeRef, out: &mut Vec<dom::NodeId>) {
    if let dom::NodeType::Element(el) = &node.borrow().node_type {
        if layout::is_keyboard_focusable(el) {
            out.push(node.borrow().id);
        }
    }
    let children = node.borrow().children.clone();
    for child in &children {
        collect_focusable_nodes(child, out);
    }
}

fn find_title_node(node: &dom::NodeRef) -> Option<dom::NodeRef> {
    let is_title =
        matches!(&node.borrow().node_type, dom::NodeType::Element(el) if el.tag_name == "title");
    if is_title {
        return Some(node.clone());
    }
    let children = node.borrow().children.clone();
    children.iter().find_map(find_title_node)
}

fn find_title(document: &dom::NodeRef) -> Option<String> {
    let node = find_title_node(document)?;
    let trimmed = text_content(&node).trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// Updates the EXISTING `<title>` element's text. Does nothing if the
/// page has no `<title>` at all — real DOM would create one; this
/// minimal binding doesn't (see this module's "next steps").
fn set_title(document: &dom::NodeRef, new_title: &str) {
    if let Some(node) = find_title_node(document) {
        set_text_content(&node, new_title);
    }
}

/// Real `textContent` semantics: the concatenation of every descendant
/// TEXT node's data, depth-first — not just this node's direct
/// children's text.
fn text_content(node: &dom::NodeRef) -> String {
    let (text_value, children) = {
        let node_ref = node.borrow();
        match &node_ref.node_type {
            dom::NodeType::Text(t) => (Some(t.clone()), Vec::new()),
            _ => (None, node_ref.children.clone()),
        }
    };
    match text_value {
        Some(t) => t,
        None => children
            .iter()
            .map(text_content)
            .collect::<Vec<_>>()
            .join(""),
    }
}

/// Real `textContent` setter semantics: replace ALL of this node's
/// children with a single new text node.
fn set_text_content(node: &dom::NodeRef, text: &str) {
    node.borrow_mut().children.clear();
    dom::append_child(node, dom::Node::new_text(text));
}

fn get_class_attribute(node: &dom::NodeRef) -> String {
    match &node.borrow().node_type {
        dom::NodeType::Element(el) => el.attributes.get("class").cloned().unwrap_or_default(),
        _ => String::new(),
    }
}

fn set_class_attribute(node: &dom::NodeRef, value: String) {
    if let dom::NodeType::Element(el) = &mut node.borrow_mut().node_type {
        el.attributes.insert("class".to_string(), value);
    }
}

fn class_list_add(node: &dom::NodeRef, class_name: &str) {
    let mut classes: Vec<String> = get_class_attribute(node)
        .split_whitespace()
        .map(String::from)
        .collect();
    if !classes.iter().any(|c| c == class_name) {
        classes.push(class_name.to_string());
    }
    set_class_attribute(node, classes.join(" "));
}

fn class_list_remove(node: &dom::NodeRef, class_name: &str) {
    let classes: Vec<String> = get_class_attribute(node)
        .split_whitespace()
        .filter(|c| *c != class_name)
        .map(String::from)
        .collect();
    set_class_attribute(node, classes.join(" "));
}

fn class_list_contains(node: &dom::NodeRef, class_name: &str) -> bool {
    get_class_attribute(node)
        .split_whitespace()
        .any(|c| c == class_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(html: &str) -> dom::NodeRef {
        html::parse(html)
    }

    /// A fresh, empty `FakeFetcher`-backed fetcher for tests that don't
    /// care about `fetch()` themselves — same shared-`Rc` shape
    /// `Session::new` needs, just built fresh per test rather than
    /// wired to any real navigation.
    fn test_fetcher() -> Rc<RefCell<network::FilteringFetcher<network::FakeFetcher>>> {
        Rc::new(RefCell::new(network::FilteringFetcher::new(
            network::FakeFetcher::new(),
            privacy::Blocklist::with_seed_list(),
        )))
    }

    #[test]
    fn extract_scripts_distinguishes_inline_from_external_in_document_order() {
        let document = parse(
            r#"<html><head>
                <script>1;</script>
                <script src="a.js">ignored fallback text</script>
            </head><body><script>2;</script></body></html>"#,
        );
        let scripts = extract_scripts(&document);
        assert_eq!(
            scripts,
            vec![
                ScriptSource::Inline("1;".to_string()),
                ScriptSource::External("a.js".to_string()),
                ScriptSource::Inline("2;".to_string()),
            ]
        );
    }

    #[test]
    fn resolve_and_fetch_scripts_fetches_external_and_passes_through_inline() {
        let mut fake = network::FakeFetcher::new();
        fake.register(
            "https://example.com/a.js",
            "document.title = 'from external';",
        );
        let mut fetcher =
            network::FilteringFetcher::new(fake, privacy::Blocklist::with_seed_list());

        let scripts = vec![
            ScriptSource::Inline("var x = 1;".to_string()),
            ScriptSource::External("/a.js".to_string()),
        ];
        let resolved =
            resolve_and_fetch_scripts(&scripts, "https://example.com/index.html", &mut fetcher);

        assert_eq!(
            resolved,
            vec![
                "var x = 1;".to_string(),
                "document.title = 'from external';".to_string()
            ]
        );
    }

    #[test]
    fn resolve_and_fetch_scripts_skips_a_blocked_third_party_script_but_keeps_the_rest() {
        let mut fake = network::FakeFetcher::new();
        fake.register(
            "http://g.doubleclick.net/tracker.js",
            "document.title = 'SHOULD NOT RUN';",
        );
        let mut fetcher =
            network::FilteringFetcher::new(fake, privacy::Blocklist::with_seed_list());

        let scripts = vec![
            ScriptSource::External("http://g.doubleclick.net/tracker.js".to_string()),
            ScriptSource::Inline("document.title = 'inline still ran';".to_string()),
        ];
        let resolved =
            resolve_and_fetch_scripts(&scripts, "https://news.example.com/", &mut fetcher);

        assert_eq!(
            resolved,
            vec!["document.title = 'inline still ran';".to_string()]
        );
    }

    #[test]
    fn resolve_and_fetch_scripts_skips_a_script_that_fails_to_fetch() {
        let fake = network::FakeFetcher::new(); // nothing registered
        let mut fetcher =
            network::FilteringFetcher::new(fake, privacy::Blocklist::with_seed_list());

        let scripts = vec![ScriptSource::External(
            "https://example.com/missing.js".to_string(),
        )];
        let resolved = resolve_and_fetch_scripts(&scripts, "https://example.com/", &mut fetcher);
        assert!(resolved.is_empty());
    }

    #[test]
    fn document_title_can_be_read_and_mutated() {
        let document = parse("<html><head><title>Before</title></head><body></body></html>");
        run_scripts(
            &document,
            &["document.title = document.title + ' After';".to_string()],
        );
        assert_eq!(find_title(&document), Some("Before After".to_string()));
    }

    #[test]
    fn get_element_by_id_and_text_content_round_trip() {
        let document = parse(r#"<html><body><p id="greeting">old text</p></body></html>"#);
        run_scripts(
            &document,
            &["document.getElementById('greeting').textContent = 'new text';".to_string()],
        );
        let node = find_by_id(&document, "greeting").unwrap();
        assert_eq!(text_content(&node), "new text");
    }

    #[test]
    fn get_element_by_id_returns_null_for_a_missing_id_without_throwing() {
        let document = parse("<html><body></body></html>");
        run_scripts(
            &document,
            &["if (document.getElementById('nope') === null) { document.title = 'confirmed null'; }".to_string()],
        );
        assert_eq!(find_title(&document), None);
    }

    #[test]
    fn class_list_add_remove_and_contains_work() {
        let document = parse(r#"<html><body><div id="box" class="a b"></div></body></html>"#);
        run_scripts(
            &document,
            &[r#"
                var box = document.getElementById('box');
                box.classList.remove('a');
                box.classList.add('c');
                document.title = box.classList.contains('b') + ',' + box.classList.contains('a');
            "#
            .to_string()],
        );
        assert_eq!(
            get_class_attribute(&find_by_id(&document, "box").unwrap()),
            "b c"
        );
    }

    #[test]
    fn get_set_and_remove_attribute_work() {
        let document = parse(
            r#"<html><head><title>Start</title></head><body><div id="box"></div></body></html>"#,
        );
        run_scripts(
            &document,
            &[r#"
                var box = document.getElementById('box');
                box.setAttribute('data-x', 'hello');
                document.title = box.getAttribute('data-x') + ',' + (box.getAttribute('nope') === null);
                box.removeAttribute('data-x');
                document.title += ',' + (box.getAttribute('data-x') === null);
            "#
            .to_string()],
        );
        assert_eq!(find_title(&document), Some("hello,true,true".to_string()));
    }

    #[test]
    fn document_query_selector_finds_the_first_match_in_document_order() {
        let document = parse(
            r#"<html><head><title>Start</title></head><body><p class="item">first</p><p class="item">second</p></body></html>"#,
        );
        run_scripts(
            &document,
            &["document.title = document.querySelector('.item').textContent;".to_string()],
        );
        assert_eq!(find_title(&document), Some("first".to_string()));
    }

    #[test]
    fn document_query_selector_returns_null_for_no_match() {
        let document = parse("<html><head><title>Start</title></head><body></body></html>");
        run_scripts(
            &document,
            &["if (document.querySelector('.nope') === null) { document.title = 'confirmed null'; }".to_string()],
        );
        assert_eq!(find_title(&document), Some("confirmed null".to_string()));
    }

    #[test]
    fn document_query_selector_all_finds_every_match_and_supports_array_methods() {
        let document = parse(
            r#"<html><head><title>Start</title></head><body><p class="item">a</p><span>skip</span><p class="item">b</p></body></html>"#,
        );
        run_scripts(
            &document,
            &[r#"
                var items = document.querySelectorAll('.item');
                var joined = '';
                items.forEach(function(el) { joined += el.textContent; });
                document.title = items.length + ':' + joined;
            "#
            .to_string()],
        );
        assert_eq!(find_title(&document), Some("2:ab".to_string()));
    }

    #[test]
    fn element_query_selector_only_searches_its_own_descendants() {
        let document = parse(
            r#"<html><head><title>Start</title></head><body>
                <div id="scope"><p class="item">inside</p></div>
                <p class="item">outside</p>
            </body></html>"#,
        );
        run_scripts(
            &document,
            &[
                "document.title = document.getElementById('scope').querySelector('.item').textContent;"
                    .to_string(),
            ],
        );
        assert_eq!(find_title(&document), Some("inside".to_string()));
    }

    #[test]
    fn a_complex_real_world_selector_matches_through_query_selector() {
        // Proves `css`'s real selector engine (combinators, attribute
        // selectors, IDs) is genuinely reachable from script, not just
        // from the stylesheet cascade.
        let document = parse(
            r#"<html><head><title>Start</title></head><body><nav id="main"><a href="/x" class="link">X</a></nav></body></html>"#,
        );
        run_scripts(
            &document,
            &[
                "document.title = document.querySelector('#main > a[href]').textContent;"
                    .to_string(),
            ],
        );
        assert_eq!(find_title(&document), Some("X".to_string()));
    }

    #[test]
    fn create_element_and_append_child_add_a_new_node_to_the_live_dom() {
        let document = parse(r#"<html><body><div id="container"></div></body></html>"#);
        run_scripts(
            &document,
            &[r#"
                var p = document.createElement('p');
                p.textContent = 'created';
                document.getElementById('container').appendChild(p);
            "#
            .to_string()],
        );
        let container = find_by_id(&document, "container").unwrap();
        assert_eq!(text_content(&container), "created");
        assert_eq!(container.borrow().children.len(), 1);
    }

    #[test]
    fn append_child_moves_an_already_attached_element_rather_than_duplicating_it() {
        let document = parse(
            r#"<html><body><div id="a"><span id="moved">hi</span></div><div id="b"></div></body></html>"#,
        );
        run_scripts(
            &document,
            &[r#"
                var moved = document.getElementById('moved');
                document.getElementById('b').appendChild(moved);
            "#
            .to_string()],
        );
        let a = find_by_id(&document, "a").unwrap();
        let b = find_by_id(&document, "b").unwrap();
        assert_eq!(
            a.borrow().children.len(),
            0,
            "should have been removed from its old parent"
        );
        assert_eq!(b.borrow().children.len(), 1);
    }

    #[test]
    fn appended_element_is_reachable_by_query_selector_after_relayout() {
        // End-to-end: a script-created element must actually show up
        // in the rendered LAYOUT tree, not just the live DOM this
        // process keeps to itself.
        let document = parse(r#"<html><body><div id="container"></div></body></html>"#);
        let session = Session::new(
            document.clone(),
            &[r#"
                var p = document.createElement('p');
                p.textContent = 'new content';
                document.getElementById('container').appendChild(p);
            "#
            .to_string()],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );
        let font = text::load_default_font();
        let tree = session.relayout(&font);
        assert!(collect_all_text(&tree).contains("new content"));
    }

    fn session_for(html: &str) -> Session {
        Session::new(
            parse(html),
            &[],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        )
    }

    #[test]
    fn focusable_nodes_finds_links_buttons_and_inputs_in_document_order() {
        let session = session_for(
            r#"<html><body>
                <a href="/a">a</a>
                <span>not focusable</span>
                <button>b</button>
                <input id="text-input">
                <input type="hidden" id="hidden-input">
            </body></html>"#,
        );
        let nodes = session.focusable_nodes();
        assert_eq!(
            nodes.len(),
            3,
            "hidden input and plain span should be excluded"
        );
    }

    #[test]
    fn move_keyboard_focus_next_visits_focusable_elements_in_order_and_wraps() {
        let mut session = session_for(
            r#"<html><body>
                <a href="/a" id="first">a</a>
                <button id="second">b</button>
            </body></html>"#,
        );
        let first = find_by_id(&session.document, "first").unwrap().borrow().id;
        let second = find_by_id(&session.document, "second").unwrap().borrow().id;

        assert_eq!(
            session.move_keyboard_focus(ipc::FocusDirection::Next),
            Some(first)
        );
        assert_eq!(
            session.move_keyboard_focus(ipc::FocusDirection::Next),
            Some(second)
        );
        assert_eq!(
            session.move_keyboard_focus(ipc::FocusDirection::Next),
            Some(first),
            "Tab past the last focusable element should wrap back to the first"
        );
    }

    #[test]
    fn move_keyboard_focus_previous_wraps_backward_from_nothing_focused() {
        let mut session = session_for(
            r#"<html><body>
                <a href="/a" id="first">a</a>
                <button id="second">b</button>
            </body></html>"#,
        );
        let second = find_by_id(&session.document, "second").unwrap().borrow().id;

        assert_eq!(
            session.move_keyboard_focus(ipc::FocusDirection::Previous),
            Some(second),
            "Shift+Tab with nothing focused should land on the LAST focusable element"
        );
    }

    #[test]
    fn move_keyboard_focus_with_nothing_focusable_clears_focus_and_returns_none() {
        let mut session = session_for("<html><body><p>nothing to focus here</p></body></html>");
        assert_eq!(session.move_keyboard_focus(ipc::FocusDirection::Next), None);
    }

    #[test]
    fn move_keyboard_focus_onto_a_text_input_places_the_cursor_at_the_end() {
        let mut session = session_for(r#"<html><body><input value="hello"></body></html>"#);
        session.move_keyboard_focus(ipc::FocusDirection::Next);
        assert_eq!(session.cursor, "hello".chars().count());
    }

    #[test]
    fn activate_focused_dispatches_a_real_click_at_the_focused_node() {
        let document = parse(
            r#"<html><head><title>Before</title></head><body><button id="btn">go</button></body></html>"#,
        );
        let mut session = Session::new(
            document,
            &["document.getElementById('btn').addEventListener('click', function() { document.title = 'clicked'; });".to_string()],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );
        session.move_keyboard_focus(ipc::FocusDirection::Next);
        let outcome = session.activate_focused();
        assert!(outcome.resolved);
        assert_eq!(session.title(), Some("clicked".to_string()));
    }

    #[test]
    fn activate_focused_with_nothing_focused_is_unresolved() {
        let mut session = session_for("<html><body><button>go</button></body></html>");
        let outcome = session.activate_focused();
        assert!(!outcome.resolved);
    }

    #[test]
    fn focus_node_directly_sets_focus_to_a_real_focusable_element() {
        let mut session = session_for(
            r#"<html><body>
                <a href="/a" id="first">a</a>
                <button id="second">b</button>
            </body></html>"#,
        );
        let second_id = find_by_id(&session.document, "second").unwrap().borrow().id;

        assert!(session.focus_node(second_id));
        assert_eq!(session.focused, Some(second_id));
    }

    #[test]
    fn focus_node_on_a_non_focusable_element_fails_and_changes_nothing() {
        let mut session =
            session_for(r#"<html><body><div id="d">not focusable</div></body></html>"#);
        let div_id = find_by_id(&session.document, "d").unwrap().borrow().id;

        assert!(!session.focus_node(div_id));
        assert_eq!(session.focused, None);
    }

    #[test]
    fn focus_node_places_a_text_inputs_cursor_at_the_end_of_its_value() {
        let mut session = session_for(r#"<html><body><input id="i" value="hello"></body></html>"#);
        let input_id = find_by_id(&session.document, "i").unwrap().borrow().id;

        assert!(session.focus_node(input_id));
        assert_eq!(session.cursor, "hello".chars().count());
    }

    #[test]
    fn a_throwing_script_does_not_prevent_later_scripts_from_running() {
        let document = parse("<html><head><title>Start</title></head><body></body></html>");
        run_scripts(
            &document,
            &[
                "throw new Error('boom');".to_string(),
                "document.title = 'Recovered';".to_string(),
            ],
        );
        assert_eq!(find_title(&document), Some("Recovered".to_string()));
    }

    #[test]
    fn a_syntax_error_in_one_script_does_not_prevent_later_scripts_from_running() {
        let document = parse("<html><head><title>Start</title></head><body></body></html>");
        run_scripts(
            &document,
            &[
                "this is not valid javascript {{{".to_string(),
                "document.title = 'Recovered';".to_string(),
            ],
        );
        assert_eq!(find_title(&document), Some("Recovered".to_string()));
    }

    #[test]
    fn an_infinite_loop_is_stopped_quickly_instead_of_hanging() {
        let document = parse("<html><head><title>Start</title></head><body></body></html>");
        let start = std::time::Instant::now();
        run_scripts(&document, &["while (true) {}".to_string()]);
        // Calibrated against this crate's own unoptimized `cargo test`
        // profile (measured ~3.1s per million loop iterations there,
        // vs. ~115ms in `--release` — see `LOOP_ITERATION_LIMIT`'s doc
        // comment), with the ~1.6s worst case measured in isolation.
        // 90s (rather than something closer to that 1.6s) is
        // deliberate: this whole test binary's ~190 tests run
        // concurrently by default, and on a loaded CI runner or dev
        // machine this one test's own CPU time (the only thing
        // `LOOP_ITERATION_LIMIT` actually bounds) gets stretched by
        // scheduling contention it has no control over. A local flake
        // once measured this test alone at 1.54s and the full
        // workspace suite running concurrently at >4s; a real run on a
        // shared, 2-vCPU GitHub Actions Linux runner (building the
        // entire workspace from scratch immediately beforehand, in the
        // SAME job, then running the whole suite at default
        // parallelism) blew past the original 20s bound on top of
        // that, which is why this needed raising again rather than
        // trusting locally-observed contention to bound CI's own. What
        // this assertion is actually guarding against is a genuine
        // infinite hang (the loop limit not firing at all), which 90s
        // still catches with enormous margin over even a badly-
        // contended worst case -- and the elapsed time is included in
        // the failure message specifically so the NEXT time this needs
        // recalibrating, the real number is right there instead of
        // requiring a re-run with instrumentation added after the fact.
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(90),
            "the loop-iteration limit should stop this quickly, took {elapsed:?}"
        );
    }

    /// `Context::eval` never drains Boa's own job queue (verified by
    /// reading `boa_engine`'s own source — `eval` has no `run_jobs`
    /// call anywhere in it) — a `.then()` callback would silently
    /// never run at all without `Session` calling `run_jobs()` itself
    /// after every script/timer/event dispatch (see those call sites).
    /// This test is what actually PROVES that wiring works, not just
    /// documents the theory.
    #[test]
    fn promise_then_callback_runs_after_the_initial_script_pass() {
        let document = parse("<html><head><title>Start</title></head></html>");
        run_scripts(
            &document,
            &[
                "Promise.resolve(42).then(function(v) { document.title = 'got ' + v; });"
                    .to_string(),
            ],
        );
        assert_eq!(find_title(&document), Some("got 42".to_string()));
    }

    /// Same concern as the plain-Promise test above, but for `async`/
    /// `await` syntax specifically — Boa is a from-scratch ECMAScript
    /// implementation (not V8/SpiderMonkey), so real-world spec
    /// coverage for a feature this central to modern JS is worth
    /// verifying directly rather than assuming.
    #[test]
    fn async_await_resolves_a_promise_and_continues_the_function() {
        let document = parse("<html><head><title>Start</title></head></html>");
        run_scripts(
            &document,
            &[r#"
                async function go() {
                    var v = await Promise.resolve(7);
                    document.title = 'async got ' + v;
                }
                go();
            "#
            .to_string()],
        );
        assert_eq!(find_title(&document), Some("async got 7".to_string()));
    }

    #[test]
    fn template_literals_interpolate_expressions() {
        let document = parse("<html><head><title>Start</title></head></html>");
        run_scripts(
            &document,
            &["var x = 5; document.title = `value is ${x}`;".to_string()],
        );
        assert_eq!(find_title(&document), Some("value is 5".to_string()));
    }

    #[test]
    fn local_storage_set_item_then_get_item_round_trips() {
        let document = parse("<html><head><title>Start</title></head></html>");
        run_scripts(
            &document,
            &[r#"
                localStorage.setItem('theme', 'dark');
                document.title = localStorage.getItem('theme');
            "#
            .to_string()],
        );
        assert_eq!(find_title(&document), Some("dark".to_string()));
    }

    #[test]
    fn local_storage_get_item_returns_real_null_for_a_missing_key() {
        let document = parse("<html><head><title>Start</title></head></html>");
        run_scripts(
            &document,
            &[r#"
                document.title = (localStorage.getItem('nope') === null) ? 'yes-null' : 'not-null';
            "#
            .to_string()],
        );
        assert_eq!(find_title(&document), Some("yes-null".to_string()));
    }

    #[test]
    fn local_storage_remove_item_deletes_a_key() {
        let document = parse("<html><head><title>Start</title></head></html>");
        run_scripts(
            &document,
            &[r#"
                localStorage.setItem('k', 'v');
                localStorage.removeItem('k');
                document.title = (localStorage.getItem('k') === null) ? 'removed' : 'still-there';
            "#
            .to_string()],
        );
        assert_eq!(find_title(&document), Some("removed".to_string()));
    }

    #[test]
    fn local_storage_clear_empties_every_key() {
        let document = parse("<html><head><title>Start</title></head></html>");
        run_scripts(
            &document,
            &[r#"
                localStorage.setItem('a', '1');
                localStorage.setItem('b', '2');
                localStorage.clear();
                document.title = 'length=' + localStorage.length;
            "#
            .to_string()],
        );
        assert_eq!(find_title(&document), Some("length=0".to_string()));
    }

    #[test]
    fn local_storage_length_and_key_reflect_real_insertion_order() {
        let document = parse("<html><head><title>Start</title></head></html>");
        run_scripts(
            &document,
            &[r#"
                localStorage.setItem('first', '1');
                localStorage.setItem('second', '2');
                document.title = localStorage.length + ':' + localStorage.key(0) + ':' + localStorage.key(1);
            "#
            .to_string()],
        );
        assert_eq!(find_title(&document), Some("2:first:second".to_string()));
    }

    #[test]
    fn local_storage_set_item_past_the_quota_throws_a_catchable_exception() {
        let document = parse("<html><head><title>Start</title></head></html>");
        run_scripts(
            &document,
            &[r#"
                var big = 'x'.repeat(6 * 1024 * 1024);
                try {
                    localStorage.setItem('huge', big);
                    document.title = 'did-not-throw';
                } catch (e) {
                    document.title = 'threw';
                }
            "#
            .to_string()],
        );
        assert_eq!(find_title(&document), Some("threw".to_string()));
    }

    #[test]
    fn local_storage_property_style_set_and_get_round_trip() {
        let document = parse("<html><head><title>Start</title></head></html>");
        run_scripts(
            &document,
            &[r#"
                localStorage.theme = 'dark';
                document.title = localStorage.theme;
            "#
            .to_string()],
        );
        assert_eq!(find_title(&document), Some("dark".to_string()));
    }

    #[test]
    fn local_storage_property_style_and_method_style_see_the_same_data() {
        let document = parse("<html><head><title>Start</title></head></html>");
        run_scripts(
            &document,
            &[r#"
                localStorage.setItem('k', 'via-method');
                var viaProperty = localStorage.k;
                localStorage.k2 = 'via-property';
                var viaMethod = localStorage.getItem('k2');
                document.title = viaProperty + ':' + viaMethod;
            "#
            .to_string()],
        );
        assert_eq!(
            find_title(&document),
            Some("via-method:via-property".to_string())
        );
    }

    #[test]
    fn local_storage_property_style_read_of_a_missing_key_is_undefined() {
        let document = parse("<html><head><title>Start</title></head></html>");
        run_scripts(
            &document,
            &[r#"
                document.title = (localStorage.nope === undefined) ? 'yes-undefined' : 'not-undefined';
            "#
            .to_string()],
        );
        assert_eq!(find_title(&document), Some("yes-undefined".to_string()));
    }

    #[test]
    fn local_storage_delete_operator_removes_a_property_style_key() {
        let document = parse("<html><head><title>Start</title></head></html>");
        run_scripts(
            &document,
            &[r#"
                localStorage.k = 'v';
                delete localStorage.k;
                document.title = (localStorage.getItem('k') === null) ? 'removed' : 'still-there';
            "#
            .to_string()],
        );
        assert_eq!(find_title(&document), Some("removed".to_string()));
    }

    #[test]
    fn local_storage_in_operator_and_for_in_see_real_stored_keys() {
        let document = parse("<html><head><title>Start</title></head></html>");
        run_scripts(
            &document,
            &[r#"
                localStorage.a = '1';
                localStorage.b = '2';
                var hasA = 'a' in localStorage;
                var hasMissing = 'missing' in localStorage;
                var seen = [];
                for (var k in localStorage) { seen.push(k); }
                document.title = hasA + ':' + hasMissing + ':' + seen.sort().join(',');
            "#
            .to_string()],
        );
        assert_eq!(find_title(&document), Some("true:false:a,b".to_string()));
    }

    #[test]
    fn indexed_db_open_create_store_put_and_get_round_trip() {
        let document = parse("<html><head><title>Start</title></head></html>");
        run_scripts(
            &document,
            &[r#"
                var req = indexedDB.open('mydb', 1);
                req.onupgradeneeded = function () {
                    req.result.createObjectStore('things');
                };
                req.onsuccess = function () {
                    var db = req.result;
                    var tx = db.transaction('things', 'readwrite');
                    var putReq = tx.objectStore('things').put('hello', 'k');
                    putReq.onsuccess = function () {
                        var getReq = tx.objectStore('things').get('k');
                        getReq.onsuccess = function () {
                            document.title = 'got:' + getReq.result;
                        };
                    };
                };
            "#
            .to_string()],
        );
        assert_eq!(find_title(&document), Some("got:hello".to_string()));
    }

    #[test]
    fn indexed_db_get_of_a_missing_key_is_real_null() {
        let document = parse("<html><head><title>Start</title></head></html>");
        run_scripts(
            &document,
            &[r#"
                var req = indexedDB.open('mydb', 1);
                req.onupgradeneeded = function () {
                    req.result.createObjectStore('things');
                };
                req.onsuccess = function () {
                    var getReq = req.result.transaction('things').objectStore('things').get('nope');
                    getReq.onsuccess = function () {
                        document.title = (getReq.result === null) ? 'yes-null' : 'not-null';
                    };
                };
            "#
            .to_string()],
        );
        assert_eq!(find_title(&document), Some("yes-null".to_string()));
    }

    #[test]
    fn indexed_db_auto_increment_key_path_assigns_and_writes_back_real_ids() {
        let document = parse("<html><head><title>Start</title></head></html>");
        run_scripts(
            &document,
            &[r#"
                var req = indexedDB.open('mydb', 1);
                req.onupgradeneeded = function () {
                    req.result.createObjectStore('things', { keyPath: 'id', autoIncrement: true });
                };
                req.onsuccess = function () {
                    var store = req.result.transaction('things', 'readwrite').objectStore('things');
                    var addReq1 = store.add({ name: 'first' });
                    addReq1.onsuccess = function () {
                        var addReq2 = store.add({ name: 'second' });
                        addReq2.onsuccess = function () {
                            var allReq = store.getAll();
                            allReq.onsuccess = function () {
                                var items = allReq.result;
                                document.title = addReq1.result + ':' + addReq2.result + ':' +
                                    items[0].id + ':' + items[0].name + ':' + items[1].id + ':' + items[1].name;
                            };
                        };
                    };
                };
            "#
            .to_string()],
        );
        assert_eq!(
            find_title(&document),
            Some("1:2:1:first:2:second".to_string())
        );
    }

    #[test]
    fn indexed_db_add_on_an_existing_key_fires_a_real_error_not_success() {
        let document = parse("<html><head><title>Start</title></head></html>");
        run_scripts(
            &document,
            &[r#"
                var req = indexedDB.open('mydb', 1);
                req.onupgradeneeded = function () {
                    req.result.createObjectStore('things');
                };
                req.onsuccess = function () {
                    var store = req.result.transaction('things', 'readwrite').objectStore('things');
                    var first = store.add('v1', 'k');
                    first.onsuccess = function () {
                        var second = store.add('v2', 'k');
                        second.onsuccess = function () { document.title = 'should-not-succeed'; };
                        second.onerror = function () { document.title = 'errored:' + second.error; };
                    };
                };
            "#
            .to_string()],
        );
        let title = find_title(&document).unwrap();
        assert!(
            title.starts_with("errored:"),
            "expected a real error, got {title:?}"
        );
        assert!(title.contains("ConstraintError"), "got {title:?}");
    }

    #[test]
    fn indexed_db_delete_and_clear_and_count_work_end_to_end() {
        let document = parse("<html><head><title>Start</title></head></html>");
        run_scripts(
            &document,
            &[r#"
                var req = indexedDB.open('mydb', 1);
                req.onupgradeneeded = function () {
                    req.result.createObjectStore('things');
                };
                req.onsuccess = function () {
                    var store = req.result.transaction('things', 'readwrite').objectStore('things');
                    store.put('v1', 'a');
                    var putB = store.put('v2', 'b');
                    putB.onsuccess = function () {
                        var delReq = store.delete('a');
                        delReq.onsuccess = function () {
                            var countReq = store.count();
                            countReq.onsuccess = function () {
                                var afterDeleteCount = countReq.result;
                                var clearReq = store.clear();
                                clearReq.onsuccess = function () {
                                    var countReq2 = store.count();
                                    countReq2.onsuccess = function () {
                                        document.title = afterDeleteCount + ':' + countReq2.result;
                                    };
                                };
                            };
                        };
                    };
                };
            "#
            .to_string()],
        );
        assert_eq!(find_title(&document), Some("1:0".to_string()));
    }

    #[test]
    fn indexed_db_reopening_the_same_version_skips_onupgradeneeded_but_keeps_existing_data() {
        let document = parse("<html><head><title>Start</title></head></html>");
        run_scripts(
            &document,
            &[r#"
                var upgradeCount = 0;
                function openAndPut(onDone) {
                    var req = indexedDB.open('mydb', 1);
                    req.onupgradeneeded = function () {
                        upgradeCount++;
                        req.result.createObjectStore('things');
                    };
                    req.onsuccess = function () {
                        var store = req.result.transaction('things', 'readwrite').objectStore('things');
                        var putReq = store.put('v', 'k');
                        putReq.onsuccess = function () { onDone(req.result); };
                    };
                }
                openAndPut(function () {
                    var req2 = indexedDB.open('mydb', 1);
                    req2.onupgradeneeded = function () { upgradeCount++; };
                    req2.onsuccess = function () {
                        var getReq = req2.result.transaction('things').objectStore('things').get('k');
                        getReq.onsuccess = function () {
                            document.title = upgradeCount + ':' + getReq.result;
                        };
                    };
                });
            "#
            .to_string()],
        );
        assert_eq!(find_title(&document), Some("1:v".to_string()));
    }

    #[test]
    fn indexed_db_object_store_names_and_transaction_oncomplete_are_real() {
        let document = parse("<html><head><title>Start</title></head></html>");
        run_scripts(
            &document,
            &[r#"
                var req = indexedDB.open('mydb', 1);
                req.onupgradeneeded = function () {
                    req.result.createObjectStore('a');
                    req.result.createObjectStore('b');
                };
                req.onsuccess = function () {
                    var names = req.result.objectStoreNames;
                    var tx = req.result.transaction(['a'], 'readonly');
                    tx.oncomplete = function () {
                        document.title = names.length + ':' + names.contains('a') + ':' +
                            names.contains('missing') + ':committed';
                    };
                };
            "#
            .to_string()],
        );
        assert_eq!(
            find_title(&document),
            Some("2:true:false:committed".to_string())
        );
    }

    /// `fetch()` performs its underlying HTTP request SYNCHRONOUSLY
    /// (see `setup_globals`'s own doc comment on why — no real
    /// concurrency exists in this engine), so by the time
    /// `Session::new` returns, every `.then()` chain a script started
    /// during its initial pass — including one waiting on `fetch()`'s
    /// own promise — has already fully settled. No extra `tick()`/
    /// `run_jobs()` call is needed in these tests for that reason.
    #[test]
    fn fetch_resolves_with_ok_status_and_a_real_text_body() {
        let document = parse("<html><head><title>Start</title></head></html>");
        let mut fake = network::FakeFetcher::new();
        fake.register("https://example.com/data.txt", "hello from fetch");
        let fetcher = Rc::new(RefCell::new(network::FilteringFetcher::new(
            fake,
            privacy::Blocklist::with_seed_list(),
        )));
        let _session = Session::new(
            document.clone(),
            &[r#"
                fetch('/data.txt').then(function(response) {
                    if (response.ok && response.status === 200) {
                        return response.text();
                    }
                    return 'unexpected response';
                }).then(function(text) {
                    document.title = text;
                });
            "#
            .to_string()],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            fetcher,
            "https://example.com/index.html".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );
        assert_eq!(find_title(&document), Some("hello from fetch".to_string()));
    }

    #[test]
    fn fetch_response_json_parses_the_real_body() {
        let document = parse("<html><head><title>Start</title></head></html>");
        let mut fake = network::FakeFetcher::new();
        fake.register("https://example.com/data.json", r#"{"greeting":"hi"}"#);
        let fetcher = Rc::new(RefCell::new(network::FilteringFetcher::new(
            fake,
            privacy::Blocklist::with_seed_list(),
        )));
        let _session = Session::new(
            document.clone(),
            &[r#"
                fetch('/data.json')
                    .then(function(r) { return r.json(); })
                    .then(function(obj) { document.title = obj.greeting; });
            "#
            .to_string()],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            fetcher,
            "https://example.com/index.html".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );
        assert_eq!(find_title(&document), Some("hi".to_string()));
    }

    #[test]
    fn fetch_uses_async_await_syntax_too() {
        let document = parse("<html><head><title>Start</title></head></html>");
        let mut fake = network::FakeFetcher::new();
        fake.register("https://example.com/data.txt", "via await");
        let fetcher = Rc::new(RefCell::new(network::FilteringFetcher::new(
            fake,
            privacy::Blocklist::with_seed_list(),
        )));
        let _session = Session::new(
            document.clone(),
            &[r#"
                async function go() {
                    var response = await fetch('/data.txt');
                    var text = await response.text();
                    document.title = text;
                }
                go();
            "#
            .to_string()],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            fetcher,
            "https://example.com/index.html".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );
        assert_eq!(find_title(&document), Some("via await".to_string()));
    }

    #[test]
    fn fetch_rejects_for_a_url_that_fails_to_fetch() {
        let document = parse("<html><head><title>Start</title></head></html>");
        let fetcher = test_fetcher(); // nothing registered
        let _session = Session::new(
            document.clone(),
            &[r#"
                fetch('/missing.txt').then(function() {
                    document.title = 'should not resolve';
                }).catch(function() {
                    document.title = 'rejected as expected';
                });
            "#
            .to_string()],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            fetcher,
            "https://example.com/index.html".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );
        assert_eq!(
            find_title(&document),
            Some("rejected as expected".to_string())
        );
    }

    #[test]
    fn fetch_blocks_a_third_party_tracker_request_the_same_as_any_other_subresource() {
        let document = parse("<html><head><title>Start</title></head></html>");
        let mut fake = network::FakeFetcher::new();
        fake.register(
            "http://g.doubleclick.net/collect",
            "should never be readable",
        );
        let fetcher = Rc::new(RefCell::new(network::FilteringFetcher::new(
            fake,
            privacy::Blocklist::with_seed_list(),
        )));
        let _session = Session::new(
            document.clone(),
            &[r#"
                fetch('http://g.doubleclick.net/collect').then(function() {
                    document.title = 'should not have been allowed through';
                }).catch(function() {
                    document.title = 'blocked as expected';
                });
            "#
            .to_string()],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            fetcher,
            "https://news.example.com/".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );
        assert_eq!(
            find_title(&document),
            Some("blocked as expected".to_string())
        );
    }

    #[test]
    fn fetch_resolves_a_relative_url_against_the_pages_own_directory() {
        // Real URL resolution: a relative URL with no leading `/`
        // resolves against the DIRECTORY of the base URL (dropping its
        // last path segment), not the host root — 'api/data' from
        // '/app/index.html' should hit '/app/api/data', not
        // '/api/data'.
        let document = parse("<html><head><title>Start</title></head></html>");
        let mut fake = network::FakeFetcher::new();
        fake.register("https://example.com/app/api/data", "relative url worked");
        let fetcher = Rc::new(RefCell::new(network::FilteringFetcher::new(
            fake,
            privacy::Blocklist::with_seed_list(),
        )));
        let _session = Session::new(
            document.clone(),
            &[r#"
                fetch('api/data').then(function(r) { return r.text(); })
                    .then(function(text) { document.title = text; });
            "#
            .to_string()],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            fetcher,
            "https://example.com/app/index.html".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );
        assert_eq!(
            find_title(&document),
            Some("relative url worked".to_string())
        );
    }

    #[test]
    fn window_load_listener_fires_exactly_once_after_all_scripts_run() {
        let document = parse("<html><head><title>Start</title></head><body></body></html>");
        run_scripts(
            &document,
            &[r#"
                var count = 0;
                window.addEventListener('load', function () { count++; document.title = 'load fired ' + count; });
            "#
            .to_string()],
        );
        assert_eq!(find_title(&document), Some("load fired 1".to_string()));
    }

    #[test]
    fn no_scripts_means_no_context_is_even_created() {
        let document = parse("<html><head><title>Untouched</title></head><body></body></html>");
        run_scripts(&document, &[]);
        assert_eq!(find_title(&document), Some("Untouched".to_string()));
    }

    #[test]
    fn set_timeout_does_not_run_immediately_but_does_run_on_a_later_tick() {
        let document = parse("<html><head><title>Start</title></head><body></body></html>");
        let mut session = Session::new(
            document.clone(),
            &["setTimeout(function() { document.title = 'timer fired'; }, 10);".to_string()],
            800.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );
        assert_eq!(
            find_title(&document),
            Some("Start".to_string()),
            "must not run synchronously during the initial pass"
        );
        assert!(
            session.next_wake_in_millis().is_some(),
            "a pending timer should be reported"
        );

        std::thread::sleep(std::time::Duration::from_millis(30));
        let ran = session.tick();
        assert!(ran);
        assert_eq!(find_title(&document), Some("timer fired".to_string()));
        assert_eq!(
            session.next_wake_in_millis(),
            None,
            "no timers should remain pending after it fired"
        );
    }

    #[test]
    fn tick_before_the_due_time_runs_nothing() {
        let document = parse("<html><head><title>Start</title></head><body></body></html>");
        let mut session = Session::new(
            document.clone(),
            &[
                "setTimeout(function() { document.title = 'should not have fired'; }, 10000);"
                    .to_string(),
            ],
            800.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );
        let ran = session.tick();
        assert!(!ran);
        assert_eq!(find_title(&document), Some("Start".to_string()));
    }

    #[test]
    fn clear_timeout_prevents_a_pending_timer_from_ever_running() {
        let document = parse("<html><head><title>Start</title></head><body></body></html>");
        let mut session = Session::new(
            document.clone(),
            &["var id = setTimeout(function() { document.title = 'should not run'; }, 10); clearTimeout(id);".to_string()],
            800.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );
        assert_eq!(
            session.next_wake_in_millis(),
            None,
            "a cleared timer must not still be reported as pending"
        );

        std::thread::sleep(std::time::Duration::from_millis(30));
        let ran = session.tick();
        assert!(!ran);
        assert_eq!(find_title(&document), Some("Start".to_string()));
    }

    #[test]
    fn a_timer_that_reschedules_itself_at_zero_delay_all_runs_within_one_tick() {
        let document = parse("<html><head><title>0</title></head><body></body></html>");
        let mut session = Session::new(
            document.clone(),
            &[r#"
                function step() {
                    var n = parseInt(document.title, 10) + 1;
                    document.title = String(n);
                    if (n < 3) { setTimeout(step, 0); }
                }
                setTimeout(step, 0);
            "#
            .to_string()],
            800.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );
        let ran = session.tick();
        assert!(ran);
        assert_eq!(
            find_title(&document),
            Some("3".to_string()),
            "chained zero-delay timers should all resolve within one tick call"
        );
    }

    #[test]
    fn relayout_reflects_a_dom_mutation_made_by_a_timer() {
        let document = parse(r#"<html><body><p id="target">old</p></body></html>"#);
        let mut session = Session::new(
            document.clone(),
            &["setTimeout(function() { document.getElementById('target').textContent = 'new'; }, 0);".to_string()],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );
        session.tick();
        let font = text::load_default_font();
        let tree = session.relayout(&font);
        let rendered_text = collect_all_text(&tree);
        assert!(
            rendered_text.contains("new"),
            "expected the timer's mutation in the relaid-out tree, got: {rendered_text:?}"
        );
    }

    #[test]
    fn dispatch_click_runs_a_registered_click_listener() {
        let document = parse(
            r#"<html><head><title>Start</title></head><body><button id="btn">Click</button></body></html>"#,
        );
        let button_id = find_by_id(&document, "btn").unwrap().borrow().id;
        let mut session = Session::new(
            document.clone(),
            &["document.getElementById('btn').addEventListener('click', function() { document.title = 'clicked'; });".to_string()],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );

        let resolved = session.dispatch_click(button_id).resolved;
        assert!(resolved);
        assert_eq!(find_title(&document), Some("clicked".to_string()));
    }

    #[test]
    fn dispatch_click_on_an_unknown_node_id_is_a_harmless_no_op() {
        let document = parse("<html><head><title>Start</title></head><body></body></html>");
        let mut session = Session::new(
            document.clone(),
            &[],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );

        let resolved = session.dispatch_click(dom::NodeId(999_999)).resolved;
        assert!(!resolved);
        assert_eq!(find_title(&document), Some("Start".to_string()));
    }

    #[test]
    fn dispatch_click_only_fires_listeners_registered_on_the_exact_node_hit() {
        let document = parse(
            r#"<html><head><title>Start</title></head><body><button id="a">A</button><button id="b">B</button></body></html>"#,
        );
        let a_id = find_by_id(&document, "a").unwrap().borrow().id;
        let b_id = find_by_id(&document, "b").unwrap().borrow().id;
        let mut session = Session::new(
            document.clone(),
            &["document.getElementById('a').addEventListener('click', function() { document.title = 'a clicked'; });".to_string()],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );

        let resolved_b = session.dispatch_click(b_id).resolved;
        assert!(
            resolved_b,
            "button b still exists in the DOM even though it has no listener of its own"
        );
        assert_eq!(
            find_title(&document),
            Some("Start".to_string()),
            "b has no listener, so clicking it must not fire a's"
        );

        let resolved_a = session.dispatch_click(a_id).resolved;
        assert!(resolved_a);
        assert_eq!(find_title(&document), Some("a clicked".to_string()));
    }

    #[test]
    fn multiple_listeners_on_the_same_node_and_type_all_fire() {
        let document = parse(
            r#"<html><head><title>Start</title></head><body><button id="btn">Click</button></body></html>"#,
        );
        let button_id = find_by_id(&document, "btn").unwrap().borrow().id;
        let mut session = Session::new(
            document.clone(),
            &[r#"
                var el = document.getElementById('btn');
                var count = 0;
                el.addEventListener('click', function() { count++; });
                el.addEventListener('click', function() { document.title = 'count=' + count; });
            "#
            .to_string()],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );

        session.dispatch_click(button_id);
        assert_eq!(find_title(&document), Some("count=1".to_string()));
    }

    #[test]
    fn a_click_listener_can_schedule_a_timer() {
        let document = parse(
            r#"<html><head><title>Start</title></head><body><button id="btn">Click</button></body></html>"#,
        );
        let button_id = find_by_id(&document, "btn").unwrap().borrow().id;
        let mut session = Session::new(
            document.clone(),
            &["document.getElementById('btn').addEventListener('click', function() { setTimeout(function() { document.title = 'later'; }, 10); });".to_string()],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );

        session.dispatch_click(button_id);
        assert!(
            session.next_wake_in_millis().is_some(),
            "the click listener's setTimeout should now be pending"
        );

        std::thread::sleep(std::time::Duration::from_millis(30));
        session.tick();
        assert_eq!(find_title(&document), Some("later".to_string()));
    }

    #[test]
    fn dispatch_click_bubbles_from_the_target_up_to_an_ancestors_listener() {
        let document = parse(
            r#"<html><head><title>Start</title></head><body><div id="outer"><span id="inner">Click</span></div></body></html>"#,
        );
        let inner_id = find_by_id(&document, "inner").unwrap().borrow().id;
        let mut session = Session::new(
            document.clone(),
            &["document.getElementById('outer').addEventListener('click', function() { document.title = 'outer got it'; });".to_string()],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );

        let resolved = session.dispatch_click(inner_id).resolved;
        assert!(resolved);
        assert_eq!(find_title(&document), Some("outer got it".to_string()));
    }

    #[test]
    fn dispatch_click_runs_capturing_then_target_then_bubbling_in_order() {
        let document = parse(
            r#"<html><head><title>Start</title></head><body><div id="outer"><span id="inner">Click</span></div></body></html>"#,
        );
        let inner_id = find_by_id(&document, "inner").unwrap().borrow().id;
        let mut session = Session::new(
            document.clone(),
            &[r#"
                document.title = '';
                document.getElementById('outer').addEventListener('click', function() { document.title += 'capture-outer,'; }, true);
                document.getElementById('inner').addEventListener('click', function() { document.title += 'target-inner,'; });
                document.getElementById('outer').addEventListener('click', function() { document.title += 'bubble-outer,'; });
            "#
            .to_string()],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );

        session.dispatch_click(inner_id);
        assert_eq!(
            find_title(&document),
            Some("capture-outer,target-inner,bubble-outer,".to_string())
        );
    }

    #[test]
    fn stop_propagation_prevents_bubbling_to_an_ancestors_listener() {
        let document = parse(
            r#"<html><head><title>Start</title></head><body><div id="outer"><span id="inner">Click</span></div></body></html>"#,
        );
        let inner_id = find_by_id(&document, "inner").unwrap().borrow().id;
        let mut session = Session::new(
            document.clone(),
            &[r#"
                document.getElementById('inner').addEventListener('click', function(event) { event.stopPropagation(); });
                document.getElementById('outer').addEventListener('click', function() { document.title = 'should not run'; });
            "#
            .to_string()],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );

        session.dispatch_click(inner_id);
        assert_eq!(find_title(&document), Some("Start".to_string()));
    }

    #[test]
    fn stop_immediate_propagation_prevents_a_later_listener_on_the_same_node() {
        let document = parse(
            r#"<html><head><title>Start</title></head><body><button id="btn">Click</button></body></html>"#,
        );
        let button_id = find_by_id(&document, "btn").unwrap().borrow().id;
        let mut session = Session::new(
            document.clone(),
            &[r#"
                var el = document.getElementById('btn');
                el.addEventListener('click', function(event) { event.stopImmediatePropagation(); });
                el.addEventListener('click', function() { document.title = 'should not run'; });
            "#
            .to_string()],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );

        session.dispatch_click(button_id);
        assert_eq!(find_title(&document), Some("Start".to_string()));
    }

    #[test]
    fn event_target_is_the_original_element_even_inside_an_ancestors_listener() {
        let document = parse(
            r#"<html><head><title>Start</title></head><body><div id="outer"><span id="inner">inner text</span></div></body></html>"#,
        );
        let inner_id = find_by_id(&document, "inner").unwrap().borrow().id;
        let mut session = Session::new(
            document.clone(),
            &["document.getElementById('outer').addEventListener('click', function(event) { document.title = event.target.textContent; });".to_string()],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );

        session.dispatch_click(inner_id);
        assert_eq!(find_title(&document), Some("inner text".to_string()));
    }

    #[test]
    fn event_type_is_click() {
        let document = parse(
            r#"<html><head><title>Start</title></head><body><button id="btn">Click</button></body></html>"#,
        );
        let button_id = find_by_id(&document, "btn").unwrap().borrow().id;
        let mut session = Session::new(
            document.clone(),
            &["document.getElementById('btn').addEventListener('click', function(event) { document.title = event.type; });".to_string()],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );

        session.dispatch_click(button_id);
        assert_eq!(find_title(&document), Some("click".to_string()));
    }

    #[test]
    fn a_throwing_listener_does_not_prevent_other_listeners_from_running() {
        let document = parse(
            r#"<html><head><title>Start</title></head><body><div id="outer"><span id="inner">Click</span></div></body></html>"#,
        );
        let inner_id = find_by_id(&document, "inner").unwrap().borrow().id;
        let mut session = Session::new(
            document.clone(),
            &[r#"
                document.getElementById('inner').addEventListener('click', function() { throw new Error('boom'); });
                document.getElementById('outer').addEventListener('click', function() { document.title = 'outer still ran'; });
            "#
            .to_string()],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );

        session.dispatch_click(inner_id);
        assert_eq!(find_title(&document), Some("outer still ran".to_string()));
    }

    #[test]
    fn dispatch_click_reports_default_prevented_when_a_listener_calls_it() {
        let document = parse(
            r#"<html><head><title>Start</title></head><body><button id="btn">Click</button></body></html>"#,
        );
        let button_id = find_by_id(&document, "btn").unwrap().borrow().id;
        let mut session = Session::new(
            document.clone(),
            &["document.getElementById('btn').addEventListener('click', function(event) { event.preventDefault(); });".to_string()],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );

        let outcome = session.dispatch_click(button_id);
        assert!(outcome.resolved);
        assert!(outcome.default_prevented);
    }

    #[test]
    fn dispatch_click_reports_default_not_prevented_when_no_listener_calls_it() {
        let document = parse(
            r#"<html><head><title>Start</title></head><body><button id="btn">Click</button></body></html>"#,
        );
        let button_id = find_by_id(&document, "btn").unwrap().borrow().id;
        let mut session = Session::new(
            document.clone(),
            &["document.getElementById('btn').addEventListener('click', function() { document.title = 'ran'; });".to_string()],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );

        let outcome = session.dispatch_click(button_id);
        assert!(outcome.resolved);
        assert!(!outcome.default_prevented);
        assert_eq!(find_title(&document), Some("ran".to_string()));
    }

    #[test]
    fn prevent_default_called_by_an_ancestors_bubble_listener_still_reports_default_prevented() {
        let document = parse(
            r#"<html><head><title>Start</title></head><body><div id="outer"><span id="inner">Click</span></div></body></html>"#,
        );
        let inner_id = find_by_id(&document, "inner").unwrap().borrow().id;
        let mut session = Session::new(
            document.clone(),
            &["document.getElementById('outer').addEventListener('click', function(event) { event.preventDefault(); });".to_string()],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );

        let outcome = session.dispatch_click(inner_id);
        assert!(outcome.resolved);
        assert!(outcome.default_prevented, "preventDefault called anywhere in the chain should be reported, not just at the target");
    }

    #[test]
    fn a_missing_prevent_default_call_does_not_throw_or_break_dispatch() {
        // Confirms `event.preventDefault` really is a callable function
        // now (not just documented as existing) — a script calling it
        // must not raise, and must not be swallowed by the try/catch
        // the way a genuinely missing method would be (see
        // `a_throwing_listener_does_not_prevent_other_listeners_from_running`
        // for that other case).
        let document = parse(
            r#"<html><head><title>Start</title></head><body><button id="btn">Click</button></body></html>"#,
        );
        let button_id = find_by_id(&document, "btn").unwrap().borrow().id;
        let mut session = Session::new(
            document.clone(),
            &["document.getElementById('btn').addEventListener('click', function(event) { event.preventDefault(); document.title = 'both ran'; });".to_string()],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );

        let outcome = session.dispatch_click(button_id);
        assert!(outcome.default_prevented);
        assert_eq!(find_title(&document), Some("both ran".to_string()));
    }

    fn collect_all_text(node: &layout::LayoutBox) -> String {
        let mut out = String::new();
        if let Some(text) = &node.text {
            out.push_str(&text.raw);
            out.push(' ');
        }
        for child in &node.children {
            out.push_str(&collect_all_text(child));
        }
        out
    }

    fn find_text_input(node: &layout::LayoutBox) -> Option<&layout::LayoutBox> {
        if node.text_input.is_some() {
            return Some(node);
        }
        node.children.iter().find_map(find_text_input)
    }

    #[test]
    fn focus_resolves_to_a_real_cursor_position() {
        let document = parse(r#"<html><body><input id="q" value="hello"></body></html>"#);
        let input_id = find_by_id(&document, "q").unwrap().borrow().id;
        let mut session = Session::new(
            document.clone(),
            &[],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );
        let font = text::load_default_font();

        // Click far to the right of the text — should land the cursor
        // at the END of "hello", not somewhere in the middle.
        let focused = session.focus(input_id, 10_000.0, &font);
        assert!(focused, "a real text input should accept focus");

        let tree = session.relayout(&font);
        let input_box = find_text_input(&tree).unwrap();
        let content = input_box.text_input.as_ref().unwrap();
        assert!(
            content.cursor_x.is_some(),
            "the focused input should have a resolved cursor"
        );
    }

    #[test]
    fn focus_on_a_non_input_element_fails_and_changes_nothing() {
        let document = parse(r#"<html><body><div id="d"></div></body></html>"#);
        let div_id = find_by_id(&document, "d").unwrap().borrow().id;
        let mut session = Session::new(
            document.clone(),
            &[],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );
        let font = text::load_default_font();
        assert!(!session.focus(div_id, 0.0, &font));
    }

    #[test]
    fn typing_a_character_inserts_it_at_the_cursor() {
        let document = parse(r#"<html><body><input id="q" value="ac"></body></html>"#);
        let input_id = find_by_id(&document, "q").unwrap().borrow().id;
        let mut session = Session::new(
            document.clone(),
            &[],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );
        let font = text::load_default_font();
        session.focus(input_id, 0.0, &font); // cursor lands at index 0
        let outcome = session.handle_text_input(ipc::TextInputAction::InsertChar('b'));

        assert!(outcome.resolved);
        assert_eq!(
            get_attribute(&find_by_id(&document, "q").unwrap(), "value"),
            Some("bac".to_string())
        );
    }

    #[test]
    fn backspace_removes_the_character_before_the_cursor() {
        let document = parse(r#"<html><body><input id="q" value="abc"></body></html>"#);
        let input_id = find_by_id(&document, "q").unwrap().borrow().id;
        let mut session = Session::new(
            document.clone(),
            &[],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );
        let font = text::load_default_font();
        session.focus(input_id, 10_000.0, &font); // cursor at the end
        session.handle_text_input(ipc::TextInputAction::Backspace);

        assert_eq!(
            get_attribute(&find_by_id(&document, "q").unwrap(), "value"),
            Some("ab".to_string())
        );
    }

    #[test]
    fn keydown_fires_with_a_real_key_property_before_the_edit() {
        let document = parse(
            r#"<html><head><title>Start</title></head><body><input id="q" value=""></body></html>"#,
        );
        let input_id = find_by_id(&document, "q").unwrap().borrow().id;
        let mut session = Session::new(
            document.clone(),
            &["document.getElementById('q').addEventListener('keydown', function(e) { document.title = 'key=' + e.key; });".to_string()],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );
        let font = text::load_default_font();
        session.focus(input_id, 0.0, &font);
        session.handle_text_input(ipc::TextInputAction::InsertChar('z'));

        assert_eq!(find_title(&document), Some("key=z".to_string()));
    }

    #[test]
    fn preventing_keydown_blocks_the_actual_edit() {
        let document = parse(r#"<html><body><input id="q" value=""></body></html>"#);
        let input_id = find_by_id(&document, "q").unwrap().borrow().id;
        let mut session = Session::new(
            document.clone(),
            &["document.getElementById('q').addEventListener('keydown', function(e) { e.preventDefault(); });".to_string()],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );
        let font = text::load_default_font();
        session.focus(input_id, 0.0, &font);
        session.handle_text_input(ipc::TextInputAction::InsertChar('z'));

        assert_eq!(
            get_attribute(&find_by_id(&document, "q").unwrap(), "value"),
            Some(String::new()),
            "preventDefault on keydown should stop the character from being inserted"
        );
    }

    #[test]
    fn input_event_fires_after_a_real_value_change() {
        let document = parse(
            r#"<html><head><title>Start</title></head><body><input id="q" value=""></body></html>"#,
        );
        let input_id = find_by_id(&document, "q").unwrap().borrow().id;
        let mut session = Session::new(
            document.clone(),
            &["document.getElementById('q').addEventListener('input', function() { document.title = 'input fired: ' + document.getElementById('q').value; });".to_string()],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );
        let font = text::load_default_font();
        session.focus(input_id, 0.0, &font);
        session.handle_text_input(ipc::TextInputAction::InsertChar('x'));

        assert_eq!(
            find_title(&document),
            Some("input fired: x".to_string()),
            "the 'input' event's listener should see the ALREADY-updated .value"
        );
    }

    #[test]
    fn arrow_keys_move_the_cursor_without_firing_input() {
        let document = parse(
            r#"<html><head><title>Start</title></head><body><input id="q" value="ab"></body></html>"#,
        );
        let input_id = find_by_id(&document, "q").unwrap().borrow().id;
        let mut session = Session::new(
            document.clone(),
            &["document.getElementById('q').addEventListener('input', function() { document.title = 'should not fire'; });".to_string()],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );
        let font = text::load_default_font();
        session.focus(input_id, 0.0, &font);
        session.handle_text_input(ipc::TextInputAction::ArrowRight);

        assert_eq!(
            find_title(&document),
            Some("Start".to_string()),
            "moving the cursor must not change .value, so 'input' should not fire"
        );
    }

    #[test]
    fn enter_submits_the_ancestor_form_and_reports_the_action_url() {
        let document = parse(
            r#"<html><body><form action="/search"><input id="q" name="term" value="cats"></form></body></html>"#,
        );
        let input_id = find_by_id(&document, "q").unwrap().borrow().id;
        let mut session = Session::new(
            document.clone(),
            &[],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/index.html".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );
        let font = text::load_default_font();
        session.focus(input_id, 0.0, &font);
        let outcome = session.handle_text_input(ipc::TextInputAction::Enter);

        assert!(outcome.resolved);
        assert_eq!(
            outcome.submit_url.as_deref(),
            Some("https://example.com/search?term=cats")
        );
    }

    #[test]
    fn preventing_submit_suppresses_the_action_url() {
        let document = parse(
            r#"<html><body><form action="/search">
                <input id="q" name="term" value="cats">
            </form></body></html>"#,
        );
        let input_id = find_by_id(&document, "q").unwrap().borrow().id;
        let mut session = Session::new(
            document.clone(),
            &["document.querySelector('form').addEventListener('submit', function(e) { e.preventDefault(); });".to_string()],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/index.html".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );
        let font = text::load_default_font();
        session.focus(input_id, 0.0, &font);
        let outcome = session.handle_text_input(ipc::TextInputAction::Enter);

        assert!(outcome.resolved);
        assert_eq!(outcome.submit_url, None);
    }

    #[test]
    fn enter_with_no_ancestor_form_reports_no_submit_url() {
        let document = parse(r#"<html><body><input id="q" value="cats"></body></html>"#);
        let input_id = find_by_id(&document, "q").unwrap().borrow().id;
        let mut session = Session::new(
            document.clone(),
            &[],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );
        let font = text::load_default_font();
        session.focus(input_id, 0.0, &font);
        let outcome = session.handle_text_input(ipc::TextInputAction::Enter);

        assert!(outcome.resolved);
        assert_eq!(outcome.submit_url, None);
    }

    #[test]
    fn blur_removes_the_cursor() {
        let document = parse(r#"<html><body><input id="q" value="hi"></body></html>"#);
        let input_id = find_by_id(&document, "q").unwrap().borrow().id;
        let mut session = Session::new(
            document.clone(),
            &[],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );
        let font = text::load_default_font();
        session.focus(input_id, 0.0, &font);
        session.blur();

        let tree = session.relayout(&font);
        let input_box = find_text_input(&tree).unwrap();
        assert_eq!(input_box.text_input.as_ref().unwrap().cursor_x, None);
    }

    #[test]
    fn text_input_on_a_session_with_nothing_focused_is_unresolved() {
        let document = parse(r#"<html><body><input id="q" value="hi"></body></html>"#);
        let mut session = Session::new(
            document,
            &[],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );
        let outcome = session.handle_text_input(ipc::TextInputAction::InsertChar('x'));
        assert!(!outcome.resolved);
    }

    #[test]
    fn a_script_can_read_and_write_value_directly() {
        let document = parse(
            r#"<html><head><title>Start</title></head><body><input id="q" value="old"></body></html>"#,
        );
        run_scripts(
            &document,
            &[r#"
                var el = document.getElementById('q');
                document.title = el.value;
                el.value = 'new';
            "#
            .to_string()],
        );
        assert_eq!(find_title(&document), Some("old".to_string()));
        assert_eq!(
            get_attribute(&find_by_id(&document, "q").unwrap(), "value"),
            Some("new".to_string())
        );
    }

    #[test]
    fn clicking_an_unchecked_checkbox_checks_it() {
        let document = parse(r#"<html><body><input id="c" type="checkbox"></body></html>"#);
        let checkbox_id = find_by_id(&document, "c").unwrap().borrow().id;
        let mut session = Session::new(
            document.clone(),
            &[],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );

        let outcome = session.dispatch_click(checkbox_id);
        assert!(outcome.resolved);
        assert_eq!(
            get_attribute(&find_by_id(&document, "c").unwrap(), "checked"),
            Some(String::new())
        );
    }

    #[test]
    fn clicking_an_already_checked_checkbox_unchecks_it() {
        let document = parse(r#"<html><body><input id="c" type="checkbox" checked></body></html>"#);
        let checkbox_id = find_by_id(&document, "c").unwrap().borrow().id;
        let mut session = Session::new(
            document.clone(),
            &[],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );

        session.dispatch_click(checkbox_id);
        assert_eq!(
            get_attribute(&find_by_id(&document, "c").unwrap(), "checked"),
            None,
            "a second click should toggle it back off"
        );
    }

    #[test]
    fn preventing_the_click_default_stops_the_checkbox_from_toggling() {
        let document = parse(r#"<html><body><input id="c" type="checkbox"></body></html>"#);
        let checkbox_id = find_by_id(&document, "c").unwrap().borrow().id;
        let mut session = Session::new(
            document.clone(),
            &["document.getElementById('c').addEventListener('click', function(e) { e.preventDefault(); });".to_string()],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );

        session.dispatch_click(checkbox_id);
        assert_eq!(
            get_attribute(&find_by_id(&document, "c").unwrap(), "checked"),
            None,
            "preventDefault on click should stop the checkbox's own default action"
        );
    }

    #[test]
    fn change_event_fires_after_a_checkbox_toggles() {
        let document = parse(
            r#"<html><head><title>Start</title></head><body><input id="c" type="checkbox"></body></html>"#,
        );
        let checkbox_id = find_by_id(&document, "c").unwrap().borrow().id;
        let mut session = Session::new(
            document.clone(),
            &["document.getElementById('c').addEventListener('change', function() { document.title = 'checked=[' + document.getElementById('c').getAttribute('checked') + ']'; });".to_string()],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );

        session.dispatch_click(checkbox_id);
        // Wrapped in brackets rather than left as a bare trailing empty
        // string — `find_title` trims the title text, which would
        // otherwise silently eat the very thing this test is checking.
        assert_eq!(find_title(&document), Some("checked=[]".to_string()));
    }

    #[test]
    fn clicking_a_radio_checks_it_and_unchecks_its_group_siblings() {
        let document = parse(
            r#"<html><body>
                <input id="a" type="radio" name="color" checked>
                <input id="b" type="radio" name="color">
            </body></html>"#,
        );
        let b_id = find_by_id(&document, "b").unwrap().borrow().id;
        let mut session = Session::new(
            document.clone(),
            &[],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );

        session.dispatch_click(b_id);

        assert_eq!(
            get_attribute(&find_by_id(&document, "a").unwrap(), "checked"),
            None,
            "checking b should have unchecked its group sibling a"
        );
        assert_eq!(
            get_attribute(&find_by_id(&document, "b").unwrap(), "checked"),
            Some(String::new())
        );
    }

    #[test]
    fn clicking_an_already_checked_radio_stays_checked_rather_than_toggling_off() {
        let document =
            parse(r#"<html><body><input id="a" type="radio" name="color" checked></body></html>"#);
        let a_id = find_by_id(&document, "a").unwrap().borrow().id;
        let mut session = Session::new(
            document.clone(),
            &[],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );

        session.dispatch_click(a_id);
        assert_eq!(
            get_attribute(&find_by_id(&document, "a").unwrap(), "checked"),
            Some(String::new()),
            "real radio buttons never un-check via a plain click on an already-checked one"
        );
    }

    #[test]
    fn radio_groups_in_different_forms_are_scoped_independently() {
        let document = parse(
            r#"<html><body>
                <form id="f1"><input id="a" type="radio" name="color" checked></form>
                <form id="f2"><input id="b" type="radio" name="color" checked></form>
            </body></html>"#,
        );
        let a_id = find_by_id(&document, "a").unwrap().borrow().id;
        let mut session = Session::new(
            document.clone(),
            &[],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );

        // Clicking a's radio should NOT uncheck b's, since they're in
        // DIFFERENT forms despite sharing a `name` — real HTML scopes
        // a radio group to its nearest form, not the whole document.
        session.dispatch_click(a_id);
        assert_eq!(
            get_attribute(&find_by_id(&document, "b").unwrap(), "checked"),
            Some(String::new()),
            "a radio in a different form must not be affected"
        );
    }

    #[test]
    fn clicking_a_checkbox_that_isnt_one_is_a_harmless_no_op() {
        let document = parse(r#"<html><body><button id="btn">Click</button></body></html>"#);
        let button_id = find_by_id(&document, "btn").unwrap().borrow().id;
        let mut session = Session::new(
            document.clone(),
            &[],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );

        let outcome = session.dispatch_click(button_id);
        assert!(outcome.resolved);
        assert!(!outcome.default_prevented);
    }

    /// `Session::build_form_submission` is the piece this test cares
    /// about (checkbox/radio inclusion, `"on"` defaulting, and skipping
    /// unchecked fields) — calling it directly, rather than via
    /// `handle_text_input(Enter)`, keeps this test from also needing a
    /// focused text input just to reach it.
    #[test]
    fn form_submission_includes_only_checked_checkboxes_with_on_default_value() {
        let document = parse(
            r#"<html><body><form action="/save">
                <input type="checkbox" name="subscribe" checked>
                <input type="checkbox" name="marketing">
                <input type="radio" name="plan" value="pro" checked>
                <input type="radio" name="plan" value="free">
            </form></body></html>"#,
        );
        let session = Session::new(
            document.clone(),
            &[],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/index.html".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );

        let form = find_by_id_with_tag(&document, "form").unwrap();
        let (url, body) = session.build_form_submission(&form).unwrap();

        assert_eq!(url, "https://example.com/save?subscribe=on&plan=pro");
        assert_eq!(body, None, "a GET form has no body at all");
    }

    #[test]
    fn a_post_form_sends_fields_as_a_url_encoded_body_and_leaves_the_action_url_alone() {
        let document = parse(
            r#"<html><body><form action="/login" method="post">
                <input type="text" name="username" value="alice">
                <input type="password" name="password" value="hunter2">
            </form></body></html>"#,
        );
        let session = Session::new(
            document.clone(),
            &[],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/index.html".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );

        let form = find_by_id_with_tag(&document, "form").unwrap();
        let (url, body) = session.build_form_submission(&form).unwrap();

        assert_eq!(
            url, "https://example.com/login",
            "a POST's action URL must not be mutated with a query string"
        );
        assert_eq!(
            String::from_utf8(body.unwrap()).unwrap(),
            "username=alice&password=hunter2"
        );
    }

    #[test]
    fn method_post_is_case_insensitive_and_anything_else_falls_back_to_get() {
        let document = parse(
            r#"<html><body>
                <form id="upper" action="/a" method="POST"><input name="x" value="1"></form>
                <form id="weird" action="/b" method="put"><input name="x" value="1"></form>
            </body></html>"#,
        );
        let session = Session::new(
            document.clone(),
            &[],
            300.0,
            css::Theme::Dark,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            test_fetcher(),
            "https://example.com/index.html".to_string(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        );

        let upper = find_by_id(&document, "upper").unwrap();
        let (_, upper_body) = session.build_form_submission(&upper).unwrap();
        assert!(upper_body.is_some(), "method=\"POST\" should still POST");

        let weird = find_by_id(&document, "weird").unwrap();
        let (weird_url, weird_body) = session.build_form_submission(&weird).unwrap();
        assert_eq!(weird_body, None, "an unrecognized method falls back to GET");
        assert_eq!(weird_url, "https://example.com/b?x=1");
    }

    fn find_by_id_with_tag(node: &dom::NodeRef, tag: &str) -> Option<dom::NodeRef> {
        let is_match =
            matches!(&node.borrow().node_type, dom::NodeType::Element(el) if el.tag_name == tag);
        if is_match {
            return Some(node.clone());
        }
        let children = node.borrow().children.clone();
        children.iter().find_map(|c| find_by_id_with_tag(c, tag))
    }
}
