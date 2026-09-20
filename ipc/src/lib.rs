//! `ipc` — the wire protocol between the main `app` process and the
//! sandboxed `renderer` process it spawns as a child (over the child's
//! stdin/stdout pipes).
//!
//! Why this exists at all: `app`'s main process holds the account's
//! recovery code, its derived encryption keys, and the decrypted
//! bookmarks/settings — real secrets, worth isolating from whatever
//! processes the actual bytes a remote server sends back. `renderer`
//! is where that untrusted-content processing lives (DNS-over-HTTPS +
//! TLS + HTTP fetch, HTML parsing, CSS, and layout — see the
//! `renderer` crate itself), sandboxed via OS primitives (Landlock on
//! Linux — see `renderer::sandbox`) so that even a memory-safety bug
//! triggered by a malicious page can't read the account/bookmarks
//! files or reach anywhere on disk beyond its own response cache.
//!
//! Every message is scoped to a `TabId` — `app` runs multiple tabs
//! (see its own `Tab`/`Browser` split) over a POOL of renderer
//! processes now, one per distinct site any open tab is showing (see
//! `app`'s `RendererPool`'s doc comment for why: site isolation — two
//! tabs on different sites never share a process any more). Tabs on
//! the SAME site still share one process, though, so the renderer
//! still needs a way to tell them apart within it.
//! `renderer::RendererState` keeps a per-tab `script::Session` alive
//! across messages now (a live Boa `Context` + DOM), addressed by
//! exactly this `TabId` — a script can keep running (via `setTimeout`)
//! after the page that spawned it has already been handed back to
//! `app`.
//!
//! **Still lockstep, but no longer purely request/response**: every
//! `ClientMessage` still gets exactly one `ServerMessage` reply (no
//! multiplexing, no renderer-initiated push `app` didn't ask for —
//! that fuller redesign is still deferred, see "Next steps"), but
//! `ClientMessageKind::Tick` is `app` PROACTIVELY asking "has anything
//! come due yet?" on a schedule the renderer itself dictates
//! (`next_wake_in_millis` on every reply). This is what makes
//! `setTimeout` real: `render::window`'s existing resize-debounce timer
//! mechanism (`ControlFlow::WaitUntil`) already proved a single-
//! threaded, purely reactive event loop can wake itself at a specific
//! future instant with no polling and no background thread — `Tick`
//! reuses exactly that primitive (see `render::window::InputEvent::Tick`
//! and `Frame::wake_at`) instead of needing the harder architecture
//! change unsolicited pushes would require.
//!
//! `LayoutBox` (from the `layout` crate) is the payload of a successful
//! render: it's already been fully laid out (concrete pixel rects,
//! wrapped text lines) by the time it crosses this boundary, so `app`
//! never has to run layout — which touches attacker-influenced text
//! wrapping — on untrusted content itself. That's also why `dom`,
//! `css`, and `layout`'s plain-data types gained `serde` derives:
//! `LayoutBox` embeds a `css::ComputedStyle` and a `dom::NodeType` per
//! box, and needs all three serializable to cross this boundary as JSON.
//!
//! `ClientMessageKind::Click` closes the gap an earlier version of
//! this doc comment described (mapping a click's pixel coordinates
//! back to which live DOM node was hit): `dom::NodeId` gives every
//! node a stable identity (see that type's own doc comment for why
//! it's a monotonic counter, not an address), `layout::LayoutBox`
//! carries the id of the node it was built from, and `app` resolves a
//! click to a specific id itself (`layout::hit_test_node`) entirely
//! from the snapshot it already has. The renderer then does its OWN
//! real DOM walk (`renderer::script::ancestor_chain`, over live
//! `dom::Node.parent` pointers this message never needed to carry) to
//! run a real three-phase (capturing/target/bubbling) event dispatch
//! with a real `Event` object, including `event.preventDefault()` —
//! see `renderer::script`'s module docs and
//! `RenderSuccess::default_prevented`'s doc comment for exactly how
//! that comes back across this boundary and what `app` does with it.
//!
//! Next steps, roughly in order of payoff:
//!   1. The disk cache and cookie jar currently live inside the
//!      renderer's own `network::FilteringFetcher` instance, entirely
//!      unknown to `app` — fine for now (see `renderer`'s module docs
//!      for why that's a deliberate, scoped choice), but a real
//!      "clear browsing data" UI feature will need a way to ask the
//!      renderer to clear them, which doesn't exist in this protocol yet.
//!   2. True unsolicited push (multiplexed reads, a background thread
//!      on `app`'s side) — `Tick` covers `setTimeout` without it, but
//!      an eventual `postMessage`/`WebSocket`/streaming-response
//!      feature would need it for real.
//!
//! (Landlock-only sandboxing used to be listed as a gap here — the
//! renderer now also applies a seccomp-bpf syscall allowlist on top of
//! it, on Linux. See `renderer::sandbox`'s own module docs for
//! what that covers and its own remaining next steps, e.g. macOS/
//! Windows equivalents.)

use std::io::{Read, Write};

use serde::{de::DeserializeOwned, Serialize};

/// A message larger than this is refused outright rather than
/// allocated — `app`'s reader treats every message from `renderer` as
/// coming from the LESS trusted side of this boundary (the whole point
/// of the split), so it can't let a compromised or simply buggy
/// renderer make it allocate an unbounded buffer via a corrupted or
/// hostile length prefix. 64 MiB is generous for even a large page's
/// full layout tree.
pub const MAX_MESSAGE_LEN: u32 = 64 * 1024 * 1024;

/// Identifies one of `app`'s tabs to the renderer. `app` assigns these
/// — a monotonically increasing counter, NOT a tab's position in its
/// own `Vec<Tab>` (see `Browser::allocate_tab_id`'s doc comment for
/// why that distinction matters) — and the renderer's only job is to
/// keep different tabs' state apart from each other; it never needs to
/// know anything else about what a `TabId` "means" to `app`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, serde::Deserialize)]
pub struct TabId(pub u64);

/// One message from `app` to the renderer, always scoped to a tab.
///
/// `Clone` exists for `app::RendererProcess`'s own threaded I/O
/// worker: queuing a message onto that worker's channel needs an
/// OWNED copy (the worker runs on a separate thread from whatever
/// built this), and a `send_with_respawn`-style retry after a broken
/// pipe needs to queue the exact same message a second time.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct ClientMessage {
    pub tab_id: TabId,
    pub kind: ClientMessageKind,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub enum ClientMessageKind {
    /// Navigate this tab to a new page, discarding whatever it was
    /// showing before (and whatever `script::Session` state — pending
    /// timers included — it had) — a fresh page fully replaces the old
    /// one, same as today.
    Navigate(RenderRequest),
    /// This tab was closed in `app` — the renderer drops its
    /// `script::Session` (Boa `Context`, DOM, and any pending timers),
    /// so a long browsing session doesn't leak one abandoned session's
    /// worth of memory per tab ever closed.
    CloseTab,
    /// "Time has passed — run any of this tab's `setTimeout` callbacks
    /// that are due now." `app` sends this when a wake-up it scheduled
    /// (see `RenderSuccess::next_wake_in_millis`) has arrived. A `Tick`
    /// for a tab with no live session (never navigated, or already
    /// closed) is answered with `ServerMessageKind::Unchanged` rather
    /// than an error — a stale, already-fired wake-up racing a tab
    /// close is an expected, harmless timing window, not a protocol bug.
    Tick,
    /// "The user clicked on this DOM node — run its real, three-phase
    /// `click` event flow." `app` resolves a click's pixel coordinates
    /// down to a specific `dom::NodeId` itself, entirely locally,
    /// against the `LayoutBox` snapshot it already has (see
    /// `layout::hit_test_node`) — the renderer never learns the click's
    /// actual on-screen position, only which node was hit; it does its
    /// OWN separate walk of the live DOM's real ancestor chain from
    /// there (`renderer::script::ancestor_chain`) to run capturing and
    /// bubbling correctly. Like `Tick`, a `Click` for a tab with no
    /// live session, or for a node id that no longer exists in that
    /// session's current DOM (e.g. the page navigated between the
    /// click and this message arriving), is answered with
    /// `ServerMessageKind::Unchanged` rather than an error. Unlike
    /// `Tick`, a `Click` that DOES find a live session and a resolvable
    /// node always answers `Rendered` — a click is always the direct
    /// result of a deliberate, low-frequency user action (unlike a
    /// background `Tick`), so there's no need for an
    /// `Unchanged`-style "did anything actually change" optimization in
    /// that case. See `renderer::script`'s module docs for exactly what
    /// the resulting `Event` object supports (`target`/`currentTarget`/
    /// `stopPropagation`/`stopImmediatePropagation`/`preventDefault`) —
    /// whether `preventDefault` was actually called comes back on the
    /// `Rendered` reply's `RenderSuccess::default_prevented`, which is
    /// what lets `app::Browser::handle_click` dispatch a link click's
    /// `click` event FIRST and only navigate afterward if nothing
    /// called it, instead of deciding up front (before any script even
    /// runs) whether a click "is a link click" and routing it down only
    /// one of two separate paths. If the clicked node is a form's
    /// submit control (a `<button>` with no `type` or `type="submit"`,
    /// or `<input type="submit">`), an un-prevented click ALSO submits
    /// that form the same way `TextInput(Enter)` does — see
    /// `RenderSuccess::submit_url`.
    Click { dom_node_id: dom::NodeId },
    /// "Give this text-editable `<input>` focus, and place its text
    /// cursor at whatever character boundary is closest to `click_x`"
    /// — `app` sends this after a `Click` resolves to a node it can
    /// see (from its own `LayoutBox` snapshot) is a text input (see
    /// `layout::TextInputContent`), the same "resolve locally, hand
    /// the renderer only what it needs" pattern `Click` itself already
    /// uses. `click_x` is in the SAME un-scrolled layout-tree
    /// coordinate space `hit_test_node` uses, and is expected to
    /// already be relative to nothing but the page origin — the
    /// renderer re-derives the input's own content-box x itself (via
    /// a fresh `Session::relayout`) to turn this into a local offset,
    /// so `app` never needs to know that box's on-screen geometry
    /// itself. Answered `Unchanged` (like `Click`) if the node id
    /// doesn't resolve to a live, text-editable input in this
    /// session's CURRENT DOM — an expected race, not an error.
    Focus {
        dom_node_id: dom::NodeId,
        click_x: f32,
    },
    /// Removes focus from whatever text input currently has it (if
    /// any) — sent when the user clicks elsewhere on the page, clicks
    /// the address bar, or presses Escape while a page input is
    /// focused. A harmless no-op (still answered `Rendered`, since the
    /// cursor disappearing IS a real visual change) when nothing was
    /// focused to begin with.
    Blur,
    /// One keystroke directed at whatever text input currently has
    /// focus (see `Focus`) — `app` routes the SAME raw keyboard
    /// primitives it already has for the address bar
    /// (`render::window::InputEvent`) here instead, whenever a page
    /// input (not the address bar) has focus. A real `keydown` event
    /// dispatches first (see `renderer::script`'s module docs), THEN
    /// (if not prevented) the actual edit happens and a real `input`
    /// event follows — matching real DOM event order. `TextInput::Enter`
    /// additionally dispatches `submit` on the nearest ancestor
    /// `<form>`, if any (see `RenderSuccess::submit_url`). Answered
    /// `Unchanged` if nothing is currently focused in this session —
    /// an expected race (e.g. the input was removed by a script, or
    /// this message is stale after a `Blur`), not an error.
    TextInput(TextInputAction),
    /// "Is there a newer release than `current_version`?" — routed
    /// through the renderer (see `renderer::update_check`) rather than
    /// `app` making this HTTP call itself, since `app` deliberately
    /// never links an HTTP client (see its own `Cargo.toml`) and there's
    /// no reason to make an exception for this one check: it's still a
    /// real fetch of a remote, adversary-influenceable-in-principle
    /// response, so it goes through the exact same sandboxed
    /// `network::Fetcher` path as everything else. Not scoped to any
    /// real tab — `app` sends this against a dedicated renderer process
    /// it keeps just for update checks (never a site's own process),
    /// and the enclosing `ClientMessage::tab_id` is ignored entirely on
    /// the renderer side (see `RendererState::handle_message`'s
    /// `CheckForUpdate` arm).
    CheckForUpdate { current_version: String },
    /// "Fetch `url` and hand back its raw bytes to save to disk" — the
    /// `<a download>` attribute's action (see `layout::LinkHit::
    /// download`), routed through the renderer for the same reason
    /// `CheckForUpdate` is: it's a real fetch of a remote response,
    /// so it goes through the exact same sandboxed, blocklist-and-DoH-
    /// routed `network::Fetcher` path as a normal navigation — never a
    /// separate, unsandboxed download path in the privileged `app`
    /// process. Unlike `CheckForUpdate`, this IS routed to the site's
    /// own renderer process (`app` resolves `url`'s site via the same
    /// `site_for_url`/`RendererPool::get_or_spawn` a real navigation
    /// uses), so a download shares that site's cookies/blocklist
    /// context — a real browser downloading a same-site file behaves
    /// the same way.
    Download {
        url: String,
        /// Same meaning as `RenderRequest::top_level_host` — the page
        /// the download link was clicked on, for third-party/first-
        /// party blocklist decisions.
        top_level_host: Option<String>,
    },
    /// "Hand back this `<audio>`/`<video>` element's already-decoded
    /// PCM audio, if any" — sent the first time `app` needs to
    /// actually play a given element (the user clicked its play
    /// button and `app` doesn't have a local copy of the samples yet).
    /// Never triggers a NEW fetch/decode: `renderer::media` decodes
    /// every media element's audio track eagerly at `Navigate` time
    /// (see `renderer`'s own `navigate` function), caching the result
    /// in that tab's `script::Session` keyed by `dom_node_id` — this
    /// just retrieves whatever's already there (or reports why nothing
    /// is, e.g. no `src`, an unsupported format, or a file over
    /// `renderer::media`'s size cap).
    FetchAudioPcm { dom_node_id: dom::NodeId },
    /// "This `<audio>`/`<video>` element's playback state just
    /// changed" — sent whenever `app`'s own real playback (via
    /// `cpal`; see that crate's own module docs) starts, stops, seeks,
    /// or (on a periodic progress tick while playing) simply advances,
    /// so the NEXT render reflects it (a filled-in scrubber, a
    /// pause icon instead of play — see `layout::MediaContent`).
    /// `app` is the only thing that actually knows this (`renderer`
    /// has no audio OUTPUT of its own at all), so this is the one
    /// direction that information can only ever flow: `app` -> here,
    /// never decided by this crate on its own. Answered the same way
    /// `Focus`/`Blur`/`Click` are: `Rendered` with the updated tree,
    /// or `Unchanged` if `dom_node_id` doesn't resolve in this
    /// session's CURRENT DOM (an expected race, not an error).
    UpdateMediaPlayback {
        dom_node_id: dom::NodeId,
        playing: bool,
        muted: bool,
        current_time_secs: f32,
    },
    /// DevTools console REPL: run `code` as a top-level script against
    /// this tab's LIVE session (same `Context`/DOM a real `<script>`
    /// tag would run against — nothing sandboxed further than that),
    /// then report both the typed expression's own result (or thrown
    /// error) AND any `console.log`/`warn`/`error`/`info` calls it made
    /// along the way, in real execution order — see `RenderSuccess::
    /// console_messages`. Always answered `Rendered` (never `Unchanged`),
    /// even for a no-op expression like `1`: this is always a deliberate
    /// one-off action from the DevTools UI, exactly like `Click` always
    /// is (see that variant's own doc comment) — except when the tab has
    /// no live session at all (never navigated, or the renderer
    /// respawned), which answers `Unchanged` the same way every other
    /// message kind does for that case.
    EvalConsoleExpression { code: String },
    /// "Hand back a snapshot of this tab's REAL DOM tree" — for the
    /// DevTools Elements panel. Deliberately a SEPARATE tree from
    /// `RenderSuccess::layout_tree`: the layout tree already excludes
    /// `display: none` elements (including `<head>`/`<script>`/
    /// `<style>`, see `layout::build_layout_tree_inner`'s own doc
    /// comment) entirely, because it exists to be PAINTED — but a real
    /// DOM inspector needs to show the actual tree structure regardless
    /// of what's visible. Sent once when the Elements panel opens (and
    /// again on its manual refresh button — see `app::Browser`'s own
    /// devtools code) rather than after every render, so an open
    /// DevTools panel doesn't add a round trip to every ordinary click/
    /// keystroke/timer tick; a page mutated by script since the last
    /// snapshot just shows stale until refreshed, a documented gap, not
    /// a bug.
    FetchDomSnapshot,
    /// `Tab`/`Shift+Tab` pressed while the PAGE (not the address bar,
    /// find bar, or DevTools console — `app` never sends this while any
    /// of those has keyboard focus) is what keystrokes go to — see
    /// `renderer::script::Session::move_keyboard_focus`'s own doc
    /// comment for the real focus-order/wraparound semantics. Always
    /// answered `Rendered` when there's a live session (moving focus is
    /// always a real, visible change — the ring appears somewhere new,
    /// or disappears if the page has nothing focusable at all — the
    /// same "always Rendered, no `Unchanged` optimization" reasoning
    /// `Click` documents for itself), `Unchanged` otherwise.
    MoveKeyboardFocus { direction: FocusDirection },
    /// `Enter`/`Space` pressed while keyboard focus (see
    /// `MoveKeyboardFocus`) sits on something other than a text-like
    /// input — see `renderer::script::Session::activate_focused`'s own
    /// doc comment for why this reuses the exact same `click` event
    /// path a mouse click already does, `default_prevented` included
    /// (so `app` can navigate a keyboard-activated link exactly the way
    /// `Click`'s own reply already lets it navigate a clicked one).
    /// Answered `Rendered` if something was actually focused to
    /// activate, `Unchanged` otherwise (nothing focused, or no live
    /// session) — same "no need to distinguish those two cases on the
    /// wire" reasoning `Click`'s own doc comment gives for an
    /// unresolvable node id.
    ActivateFocused,
    /// A real assistive technology directly requested keyboard focus on
    /// ONE SPECIFIC element (`accesskit::Action::Focus`, via
    /// `app::accessibility`'s tree — see that module's own doc
    /// comment) — unlike `MoveKeyboardFocus`, which moves RELATIVE to
    /// whatever's currently focused, this sets it directly. See
    /// `renderer::script::Session::focus_node`'s own doc comment.
    /// Answered `Rendered` if `dom_node_id` actually resolves to a
    /// real, currently keyboard-focusable element in this session's
    /// CURRENT DOM, `Unchanged` otherwise (a stale id from a page
    /// mutation the assistive technology's own tree hasn't caught up
    /// to yet, or no live session at all) — same "expected race, not
    /// an error" reasoning every other node-id-bearing message here
    /// already documents.
    FocusNode { dom_node_id: dom::NodeId },
}

/// Which way `Tab`/`Shift+Tab` moves keyboard focus — see
/// `ClientMessageKind::MoveKeyboardFocus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
pub enum FocusDirection {
    Next,
    Previous,
}

/// One editing action for whichever `<input>` currently has focus —
/// see `ClientMessageKind::TextInput`.
#[derive(Debug, Clone, Copy, Serialize, serde::Deserialize)]
pub enum TextInputAction {
    /// A character was typed, already resolved through the keyboard
    /// layout — the same `render::window::InputEvent::CharTyped`
    /// payload, forwarded rather than re-derived.
    InsertChar(char),
    Backspace,
    ArrowLeft,
    ArrowRight,
    Home,
    End,
    /// Submits the nearest ancestor `<form>` (if any) after dispatching
    /// a real, cancelable `submit` event — see
    /// `RenderSuccess::submit_url`.
    Enter,
}

/// The answer to `ClientMessageKind::CheckForUpdate` — see that
/// variant's doc comment. `renderer::update_check` does the actual
/// fetch/parse/compare; this crate only carries the answer across the
/// process boundary.
#[derive(Debug, Clone, PartialEq, Serialize, serde::Deserialize)]
pub enum UpdateCheckOutcome {
    UpToDate,
    /// A newer released version exists. `html_url` is the GitHub
    /// release page for it — `app` doesn't do anything more than print
    /// both (see `Browser::maybe_check_for_update`); there's no
    /// download/install step (see this project's README for why
    /// "check and notify" is the deliberate scope, not "auto-update").
    NewVersionAvailable {
        version: String,
        html_url: String,
    },
    /// The check itself couldn't complete (network error, no release
    /// repository configured yet, a response that didn't parse as
    /// expected, ...). Deliberately distinct from `UpToDate` — reporting
    /// "up to date" when the check actually failed would be a false,
    /// reassuring claim (see `renderer::update_check`'s module docs).
    CheckFailed(String),
}

/// A successfully fetched download's bytes plus what `app` should
/// suggest as its filename — see `ClientMessageKind::Download`.
#[derive(Debug, Serialize, serde::Deserialize)]
pub struct DownloadSuccess {
    /// Base64-encoded raw file bytes (`bytes`/`new` are the only way to
    /// get at them) — NOT a plain `Vec<u8>`, which serde_json would
    /// otherwise expand into a JSON array of numbers roughly 4-5x the
    /// original size (one `,`-separated small integer per byte).
    /// Base64 costs only ~1.33x, which matters concretely here: this
    /// message is read by `app` through `read_message`, which refuses
    /// (rather than allocates for) anything over `MAX_MESSAGE_LEN` (64
    /// MiB) — the plain-`Vec<u8>` encoding would cap real downloads at
    /// roughly 12-15 MB where base64 allows roughly 45-48 MB, both
    /// before accounting for the rest of the JSON envelope's own
    /// (comparatively tiny) overhead.
    encoded_bytes: String,
    /// Derived from the URL's own path when nothing more specific is
    /// available (this crate has no `Content-Disposition` header
    /// parsing yet — `network::Response` doesn't expose arbitrary
    /// response headers at all today, only `Set-Cookie`/`Cache-Control`
    /// specifically, so this is a real, documented, current limit,
    /// not an oversight). `app` combines this with the clicked link's
    /// own `download="..."` attribute value (if it had a non-empty
    /// one), which takes priority — see `Browser::download`.
    pub suggested_filename: String,
}

impl DownloadSuccess {
    pub fn new(bytes: &[u8], suggested_filename: String) -> Self {
        use base64::Engine;
        DownloadSuccess {
            encoded_bytes: base64::engine::general_purpose::STANDARD.encode(bytes),
            suggested_filename,
        }
    }

    /// Decodes the actual file bytes. `Err` only if this `DownloadSuccess`
    /// somehow didn't come from `new` (e.g. hand-constructed in a test
    /// with invalid base64) — a well-formed one built by `new` always
    /// decodes successfully.
    pub fn bytes(&self) -> Result<Vec<u8>, base64::DecodeError> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.decode(&self.encoded_bytes)
    }
}

/// The answer to `ClientMessageKind::Download` — see that variant's
/// doc comment.
#[derive(Debug, Serialize, serde::Deserialize)]
pub enum DownloadOutcome {
    Downloaded(DownloadSuccess),
    /// A network error, a blocklist hit, or the file being too large to
    /// fit in one IPC message (see `DownloadSuccess`'s own doc comment
    /// on the practical size cap that implies) — `app` shows this
    /// verbatim rather than attempting to distinguish the cases.
    Failed(String),
}

/// Decoded PCM audio for one `<audio>`/`<video>` element — see
/// `ClientMessageKind::FetchAudioPcm`. Interleaved 16-bit signed
/// samples (e.g. `[left, right, left, right, ...]` for stereo), the
/// same representation `cpal` (`app`'s real audio-output crate) wants
/// directly, so `app` never has to reformat this before playing it.
#[derive(Debug, Serialize, serde::Deserialize)]
pub struct AudioPcmData {
    /// Base64-encoded little-endian `i16` samples — NOT a plain
    /// `Vec<i16>`/`Vec<u8>`, for the exact same reason
    /// `DownloadSuccess::encoded_bytes` isn't: serde_json would expand
    /// either into a JSON array of numbers several times the size of
    /// the underlying bytes, eating into `MAX_MESSAGE_LEN`'s real
    /// headroom. `renderer::media`'s own decoded-audio size cap is
    /// chosen with this same base64 (~1.33x) overhead already in mind.
    encoded_samples: String,
    pub sample_rate: u32,
    pub channels: u16,
}

impl AudioPcmData {
    pub fn new(samples: &[i16], sample_rate: u32, channels: u16) -> Self {
        use base64::Engine;
        let bytes: Vec<u8> = samples.iter().flat_map(|s| s.to_le_bytes()).collect();
        AudioPcmData {
            encoded_samples: base64::engine::general_purpose::STANDARD.encode(bytes),
            sample_rate,
            channels,
        }
    }

    /// Decodes back to interleaved `i16` samples. `Err` only if this
    /// `AudioPcmData` didn't come from `new` (e.g. malformed base64,
    /// or an odd number of bytes that can't split evenly into `i16`s)
    /// — a well-formed one built by `new` always decodes successfully.
    pub fn samples(&self) -> Result<Vec<i16>, String> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.encoded_samples)
            .map_err(|e| format!("invalid base64: {e}"))?;
        if bytes.len() % 2 != 0 {
            return Err(format!(
                "decoded byte length {} is not a whole number of i16 samples",
                bytes.len()
            ));
        }
        Ok(bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| i16::from_le_bytes([pair[0], pair[1]]))
            .collect())
    }
}

/// The answer to `ClientMessageKind::FetchAudioPcm` — see that
/// variant's doc comment.
#[derive(Debug, Serialize, serde::Deserialize)]
pub enum AudioPcmOutcome {
    Ready(AudioPcmData),
    /// Nothing was ever successfully decoded for this element (no
    /// `src`, an unreachable/blocked URL, an unsupported container/
    /// codec, or a file over `renderer::media`'s size cap) — `app`
    /// shows this verbatim rather than attempting to distinguish the
    /// cases.
    Failed(String),
}

/// Which `console.*` method produced a `ConsoleMessage` — `app`'s
/// DevTools console panel color-codes entries by this (see
/// `app::Browser::paint_devtools_panel`), same as a real browser's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
pub enum ConsoleLevel {
    Log,
    Info,
    Warn,
    Error,
}

/// One `console.log`/`warn`/`error`/`info` call (or, for `Log`, the
/// DevTools console's own echo of a typed expression / its result —
/// see `ClientMessageKind::EvalConsoleExpression`), in the exact order
/// it happened. `renderer::script::Session` accumulates these in a
/// plain `Vec` as a page's scripts run; `RenderSuccess::console_messages`
/// carries only whatever's NEW since the last reply for this tab
/// (drained, not cloned — see that field's own doc comment), and `app`
/// appends each batch onto its own per-tab, per-navigation running log.
#[derive(Debug, Clone, PartialEq, Serialize, serde::Deserialize)]
pub struct ConsoleMessage {
    pub level: ConsoleLevel,
    pub text: String,
}

/// A snapshot of one node in a tab's REAL DOM tree — see
/// `ClientMessageKind::FetchDomSnapshot`'s own doc comment for why this
/// is a separate tree from `RenderSuccess::layout_tree`. `node_id` lets
/// `app` reuse the SAME id space `LayoutBox::dom_node_id` does (via
/// `layout::find_box_by_dom_node_id`) to find a selected element's real
/// painted geometry for the box-model panel, without this crate needing
/// to know anything about layout at all.
#[derive(Debug, Clone, PartialEq, Serialize, serde::Deserialize)]
pub struct DomNode {
    pub node_id: dom::NodeId,
    pub kind: DomNodeKind,
    pub children: Vec<DomNode>,
}

#[derive(Debug, Clone, PartialEq, Serialize, serde::Deserialize)]
pub enum DomNodeKind {
    Document,
    /// Attributes sorted by name — `HashMap` iteration order isn't
    /// stable, and a DOM inspector re-fetched after every navigation
    /// (or refresh click) jittering its attribute order for no reason
    /// would be a small, needless annoyance.
    Element {
        tag_name: String,
        attributes: Vec<(String, String)>,
    },
    Text(String),
    Comment(String),
}

/// The answer to `ClientMessageKind::FetchDomSnapshot`.
#[derive(Debug, Serialize, serde::Deserialize)]
pub enum DomSnapshotOutcome {
    Ready(DomNode),
    /// No live session for this tab (an expected race — e.g. the tab
    /// was closed, or the renderer respawned between the DevTools panel
    /// opening and this reply — not a protocol error).
    Unavailable,
}

/// What the renderer hands back for one `ClientMessage`, tagged with
/// the same `tab_id` it answers (redundant while every reply is
/// synchronous and in-order, but it's what lets `RendererProcess`
/// assert a reply actually answers the message it thinks it does,
/// rather than silently trusting ordering alone).
///
/// The three `updated_*` fields are how cookies/`localStorage`/
/// IndexedDB get persisted to disk now, despite the renderer never
/// holding the account's encryption key: `renderer::RendererState`
/// reports its own real, PLAINTEXT bytes here (in exactly the shape
/// `network::PartitionedCookieJar::to_bytes`/`local_storage::
/// LocalStorageStore::to_bytes`/`indexed_db::IndexedDbStore::to_bytes`
/// already produce) whenever that store's own version counter changed
/// since the last reply that reported it — `Some` on a real change,
/// `None` the common case (nothing changed, and every OTHER field on
/// this struct already existed before persistence needed a wire
/// representation at all, so no existing reply shape had to move).
/// `app::RendererProcess::try_send` is what actually encrypts these
/// (with the account's own derived key, which only `app` ever holds)
/// and merges them into `cookies.enc`/`local_storage.enc`/
/// `indexed_db.enc` on disk — see that function's own doc comment.
/// This keeps the single most load-bearing security property in this
/// codebase intact: the renderer can only ever hand over its own
/// ALREADY-PLAINTEXT-IN-ITS-OWN-MEMORY bytes over this already-
/// existing IPC channel, never the encryption key itself, which it
/// never receives in the first place (see `RenderRequest`'s own
/// `initial_*` fields for the reverse direction).
#[derive(Serialize, serde::Deserialize)]
pub struct ServerMessage {
    pub tab_id: TabId,
    pub kind: ServerMessageKind,
    #[serde(default)]
    pub updated_cookies: Option<Vec<u8>>,
    #[serde(default)]
    pub updated_local_storage: Option<Vec<u8>>,
    #[serde(default)]
    pub updated_indexed_db: Option<Vec<u8>>,
}

// `Rendered(RenderSuccess)` dwarfs the other variants (a full laid-out
// page vs. a string or a unit-like ack) — normally worth boxing, but
// every value here is immediately serialized to JSON and sent across
// the IPC pipe (see `ServerMessage`'s own doc comment), never kept
// around or passed by value locally, so the extra stack space this
// lint warns about isn't actually paid anywhere real.
#[allow(clippy::large_enum_variant)]
#[derive(Serialize, serde::Deserialize)]
pub enum ServerMessageKind {
    Rendered(RenderSuccess),
    /// A human-readable failure description (network error, blocked by
    /// the blocklist, etc.) — `app` builds its own local "Failed to
    /// load" page from this, the same way it already does today; the
    /// renderer doesn't need to build that page itself.
    Error(String),
    /// Acknowledges a `CloseTab` — `app` doesn't currently act on this
    /// beyond draining it from the pipe (see this crate's module docs
    /// on why every `ClientMessage` gets exactly one reply), but it
    /// exists as its own variant rather than reusing `Error`/`Rendered`
    /// so a future consumer can tell "the tab was closed" apart from
    /// either of those on the wire.
    Closed,
    /// Reply to a `Tick` that didn't actually change anything visible
    /// — no point re-sending a full `LayoutBox` tree that's identical
    /// to what `app` already has. Still carries `next_wake_in_millis`
    /// so `app` can re-arm its wake-up if the tab still has (or again
    /// has) a pending timer.
    Unchanged {
        next_wake_in_millis: Option<u64>,
    },
    /// Reply to `ClientMessageKind::CheckForUpdate`.
    UpdateCheckResult(UpdateCheckOutcome),
    /// Reply to `ClientMessageKind::Download`.
    DownloadResult(DownloadOutcome),
    /// Reply to `ClientMessageKind::FetchAudioPcm`.
    AudioPcmResult(AudioPcmOutcome),
    /// Reply to `ClientMessageKind::FetchDomSnapshot`.
    DomSnapshotResult(DomSnapshotOutcome),
}

/// What `app` asks the renderer to do: fetch `url` and hand back a
/// fully laid-out page (or an error).
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct RenderRequest {
    pub url: String,
    /// `Some(bytes)` for a POST form submission — `bytes` is the
    /// `application/x-www-form-urlencoded`-encoded field values (see
    /// `renderer::script::Session::build_form_submission`), sent as
    /// the request body instead of being folded into `url`'s query
    /// string the way a GET submission's fields already are. `None`
    /// for every ordinary navigation (a typed URL, a link click, a GET
    /// form) — the case that existed before this field did, and still
    /// the overwhelming majority of navigations.
    #[serde(default)]
    pub body: Option<Vec<u8>>,
    /// The top-level page's host, for third-party/first-party
    /// decisions (see `privacy::RequestContext`) — `None` when `url`
    /// itself IS the top-level navigation, matching how `app` already
    /// calls `FilteringFetcher::fetch_in_context` today.
    pub top_level_host: Option<String>,
    /// The width to lay the page out against — `renderer` does the
    /// full layout pass (see this crate's module docs), so it needs
    /// this the same way `layout::layout` always has.
    pub canvas_width: f32,
    /// The active theme's canonical name (`css::Theme::as_str`) — the
    /// renderer builds the user-agent stylesheet itself, so it needs
    /// to know which one to use.
    pub theme: String,
    /// Raw JS source for every locally-installed userscript (see
    /// `app::userscripts`) whose own `@match` rules matched `url` —
    /// `app` reads the actual `.js` files and evaluates match patterns
    /// itself (pure, local logic that needs real filesystem access
    /// `renderer` deliberately never has — see this crate's own module
    /// docs on the process split), and hands over only their raw text,
    /// already filtered to the ones that apply here. Run AFTER the
    /// page's own scripts (see `renderer::navigate`), the same
    /// "document-idle" timing real userscript managers default to —
    /// this crate has no earlier injection point (`document-start`/
    /// `document-end`) at all. Empty for the overwhelming majority of
    /// navigations (most users have no userscripts installed, and most
    /// installed ones don't match most sites).
    pub user_scripts: Vec<String>,
    /// Present ONLY on the very first `Navigate` a freshly-spawned
    /// renderer process ever receives (see `app::RendererProcess::
    /// render`'s own seeding logic) — the real, already-decrypted-by-
    /// `app` bytes to seed this process's cookie jar from, in exactly
    /// the shape `network::PartitionedCookieJar::to_bytes` produces.
    /// `None` on every later navigate to an already-warm process (it
    /// already has this state in memory — re-sending it would be
    /// redundant at best and could stomp a change this same process
    /// made in the meantime at worst), and `None` on a fresh install
    /// (nothing on disk yet) or if decryption failed. See
    /// `ServerMessage`'s `updated_cookies` for the reverse direction.
    #[serde(default)]
    pub initial_cookies: Option<Vec<u8>>,
    /// Same shape and lifecycle as `initial_cookies`, for
    /// `local_storage::LocalStorageStore::to_bytes`.
    #[serde(default)]
    pub initial_local_storage: Option<Vec<u8>>,
    /// Same shape and lifecycle as `initial_cookies`, for
    /// `indexed_db::IndexedDbStore::to_bytes`.
    #[serde(default)]
    pub initial_indexed_db: Option<Vec<u8>>,
}

/// The renderer's answer to a `Navigate` (always) or a `Tick` that DID
/// change something (see `ServerMessageKind::Unchanged` for the "tick,
/// but nothing happened" case). Carries no `TabId` of its own since the
/// enclosing `ServerMessage` already does.
#[derive(Serialize, serde::Deserialize)]
pub struct RenderSuccess {
    pub layout_tree: layout::LayoutBox,
    pub title: Option<String>,
    /// If `Some`, this tab now has a `setTimeout` pending roughly this
    /// many milliseconds from now. `app` is expected to schedule a
    /// wake-up for approximately that long from when it RECEIVED this
    /// message (see `render::window`'s `Frame::wake_at`) and send
    /// `ClientMessageKind::Tick` for this tab when it fires — this
    /// field is what replaces a true "the renderer pushes updates"
    /// mechanism (see this crate's module docs on why that's still
    /// deferred) with something `app`'s existing reactive, single-
    /// threaded event loop can act on without polling.
    pub next_wake_in_millis: Option<u64>,
    /// `true` only when THIS reply is the result of a
    /// `ClientMessageKind::Click` whose event dispatch called
    /// `event.preventDefault()` somewhere in its capturing/target/
    /// bubbling chain (see `renderer::script`'s module docs) — always
    /// `false` for a `Navigate` or `Tick` reply, neither of which has
    /// any "default action" of its own to prevent. `app::Browser::
    /// handle_click` checks this BEFORE performing a click's default
    /// action (link navigation) rather than deciding up front whether
    /// a click even needs to reach the renderer at all — see that
    /// method's doc comment.
    pub default_prevented: bool,
    /// `Some(url)` when THIS reply is the result of a real, un-prevented
    /// form submission: a `ClientMessageKind::TextInput(TextInputAction::
    /// Enter)` whose focused input sat inside a `<form>`, or a
    /// `ClientMessageKind::Click` on that form's submit button/input —
    /// see `renderer::script::Session::build_form_submission`. For a GET
    /// form (the default, or an explicit `method="get"`), this is the
    /// full URL to navigate to, fields already folded into its query
    /// string; for a POST form, this is the bare `action` URL with
    /// `submit_body` (below) carrying the fields instead — `app` checks
    /// `submit_body` to know which shape it got. `app`'s `TextInput`/
    /// `Enter` and `Click` handlers navigate there when this is `Some`,
    /// the same way `default_prevented` gates a link click's own
    /// navigation — always `None` for every other message kind, and for
    /// a submission that WAS prevented or wasn't inside a `<form>` at all.
    pub submit_url: Option<String>,
    /// Accompanies `submit_url` — `Some(bytes)` for a POST form (the
    /// `application/x-www-form-urlencoded` field values to send as the
    /// request body), `None` for a GET form (fields are already part of
    /// `submit_url` itself). Always `None` whenever `submit_url` is.
    pub submit_body: Option<Vec<u8>>,
    /// Every `console.log`/`warn`/`error`/`info` call (and, for an
    /// `EvalConsoleExpression` reply, the REPL's own echo/result — see
    /// that variant's own doc comment) that happened since the LAST
    /// reply for this tab — drained from `script::Session`'s own
    /// accumulator each time this is built (see `renderer::render_success`),
    /// never re-sent. Empty for the overwhelming majority of replies
    /// (most pages never call `console.*` at all, and most clicks/ticks
    /// don't either); `app` appends whatever's here onto its own
    /// per-tab running log rather than treating an empty `Vec` as
    /// "nothing to show."
    pub console_messages: Vec<ConsoleMessage>,
    /// Local, purely-derived transparency signals about the CURRENT
    /// document — see `PageSignals`'s own doc comment. Recomputed by
    /// `renderer::page_signals::compute` on every reply that carries a
    /// `RenderSuccess` (`Navigate`, a `Tick` that changed something, a
    /// `Click`, ...), not cached once at `Navigate` time, so a script
    /// that mutates the DOM after the fact (e.g. injecting a new
    /// affiliate link) is still reflected on the next render.
    pub page_signals: PageSignals,
}

/// Small, local-only signals about a fetched page that `app` surfaces
/// as a chrome badge (see `app::paint_address_bar`) — never sent
/// anywhere, never used to block or alter what's fetched or rendered.
/// Deliberately conservative/heuristic rather than exhaustive (see
/// `renderer::page_signals` for the actual detection logic): a `false`/
/// `0` here means "nothing detected," not "verified absent."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct PageSignals {
    /// Whether the document contains at least one `<script>` element
    /// (inline or external, regardless of whether an external one's
    /// fetch actually succeeded) — a structural fact about the
    /// document, not a claim about what any script actually does.
    pub uses_javascript: bool,
    /// How many `<a>` elements look like affiliate/tracked-referral
    /// links, by URL pattern (known affiliate-network domains, common
    /// tracking query parameters like `tag=`/`irclickid=`) or an
    /// explicit `rel="sponsored"` — see `renderer::page_signals::
    /// is_affiliate_href`'s own doc comment for the exact heuristic and
    /// its known blind spots.
    pub affiliate_link_count: usize,
}

/// Writes one length-prefixed JSON message: a 4-byte little-endian
/// length, then that many bytes of JSON. Flushes afterward so the
/// reader on the other end of a pipe doesn't block waiting for bytes
/// still sitting in a userspace buffer.
pub fn write_message<W: Write, T: Serialize>(writer: &mut W, value: &T) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(value)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let len = u32::try_from(bytes.len()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "message too large to frame",
        )
    })?;
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(&bytes)?;
    writer.flush()
}

/// Reads one length-prefixed JSON message written by `write_message`.
/// Refuses (rather than allocates for) a length prefix over
/// `MAX_MESSAGE_LEN` — see that constant's doc comment.
pub fn read_message<R: Read, T: DeserializeOwned>(reader: &mut R) -> std::io::Result<T> {
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes)?;
    let len = u32::from_le_bytes(len_bytes);
    if len > MAX_MESSAGE_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("message length {len} exceeds MAX_MESSAGE_LEN ({MAX_MESSAGE_LEN})"),
        ));
    }
    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf)?;
    serde_json::from_slice(&buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn sample_request() -> RenderRequest {
        RenderRequest {
            url: "https://example.com/page".to_string(),
            body: None,
            top_level_host: Some("example.com".to_string()),
            canvas_width: 1024.0,
            theme: "dark".to_string(),
            user_scripts: Vec::new(),
            initial_cookies: None,
            initial_local_storage: None,
            initial_indexed_db: None,
        }
    }

    fn sample_layout_tree() -> layout::LayoutBox {
        let font = text::load_default_font();
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        let p = dom::Node::new_element("p");
        let text_node = dom::Node::new_text("hello world");
        dom::append_child(&p, text_node);
        dom::append_child(&document, p);

        let mut tree = layout::build_layout_tree(&document, &stylesheet);
        layout::layout(&mut tree, 300.0, &font);
        tree
    }

    #[test]
    fn request_round_trips_through_the_wire_format() {
        let request = sample_request();

        let mut buf = Vec::new();
        write_message(&mut buf, &request).unwrap();

        let decoded: RenderRequest = read_message(&mut Cursor::new(buf)).unwrap();
        assert_eq!(decoded.url, request.url);
        assert_eq!(decoded.top_level_host, request.top_level_host);
        assert_eq!(decoded.canvas_width, request.canvas_width);
        assert_eq!(decoded.theme, request.theme);
    }

    #[test]
    fn client_message_navigate_round_trips_with_its_tab_id() {
        let message = ClientMessage {
            tab_id: TabId(7),
            kind: ClientMessageKind::Navigate(sample_request()),
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &message).unwrap();
        let decoded: ClientMessage = read_message(&mut Cursor::new(buf)).unwrap();

        assert_eq!(decoded.tab_id, TabId(7));
        match decoded.kind {
            ClientMessageKind::Navigate(request) => {
                assert_eq!(request.url, "https://example.com/page")
            }
            _ => panic!("expected Navigate"),
        }
    }

    #[test]
    fn client_message_tick_round_trips() {
        let message = ClientMessage {
            tab_id: TabId(4),
            kind: ClientMessageKind::Tick,
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &message).unwrap();
        let decoded: ClientMessage = read_message(&mut Cursor::new(buf)).unwrap();

        assert_eq!(decoded.tab_id, TabId(4));
        assert!(matches!(decoded.kind, ClientMessageKind::Tick));
    }

    #[test]
    fn client_message_click_round_trips_with_its_node_id() {
        let message = ClientMessage {
            tab_id: TabId(6),
            kind: ClientMessageKind::Click {
                dom_node_id: dom::NodeId(42),
            },
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &message).unwrap();
        let decoded: ClientMessage = read_message(&mut Cursor::new(buf)).unwrap();

        assert_eq!(decoded.tab_id, TabId(6));
        match decoded.kind {
            ClientMessageKind::Click { dom_node_id } => assert_eq!(dom_node_id, dom::NodeId(42)),
            _ => panic!("expected Click"),
        }
    }

    #[test]
    fn client_message_close_tab_round_trips() {
        let message = ClientMessage {
            tab_id: TabId(3),
            kind: ClientMessageKind::CloseTab,
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &message).unwrap();
        let decoded: ClientMessage = read_message(&mut Cursor::new(buf)).unwrap();

        assert_eq!(decoded.tab_id, TabId(3));
        assert!(matches!(decoded.kind, ClientMessageKind::CloseTab));
    }

    #[test]
    fn server_message_error_round_trips_with_its_tab_id() {
        let message = ServerMessage {
            tab_id: TabId(1),
            kind: ServerMessageKind::Error("network unreachable".to_string()),
            updated_cookies: None,
            updated_local_storage: None,
            updated_indexed_db: None,
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &message).unwrap();
        let decoded: ServerMessage = read_message(&mut Cursor::new(buf)).unwrap();

        assert_eq!(decoded.tab_id, TabId(1));
        match decoded.kind {
            ServerMessageKind::Error(msg) => assert_eq!(msg, "network unreachable"),
            _ => panic!("expected Error variant"),
        }
    }

    #[test]
    fn server_message_closed_round_trips() {
        let message = ServerMessage {
            tab_id: TabId(2),
            kind: ServerMessageKind::Closed,
            updated_cookies: None,
            updated_local_storage: None,
            updated_indexed_db: None,
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &message).unwrap();
        let decoded: ServerMessage = read_message(&mut Cursor::new(buf)).unwrap();

        assert_eq!(decoded.tab_id, TabId(2));
        assert!(matches!(decoded.kind, ServerMessageKind::Closed));
    }

    #[test]
    fn server_message_rendered_with_a_layout_tree_round_trips() {
        let tree = sample_layout_tree();
        let message = ServerMessage {
            tab_id: TabId(9),
            kind: ServerMessageKind::Rendered(RenderSuccess {
                layout_tree: tree,
                title: Some("Hello".to_string()),
                next_wake_in_millis: Some(1500),
                default_prevented: false,
                submit_url: None,
                submit_body: None,
                console_messages: Vec::new(),
                page_signals: PageSignals {
                    uses_javascript: false,
                    affiliate_link_count: 0,
                },
            }),
            updated_cookies: None,
            updated_local_storage: None,
            updated_indexed_db: None,
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &message).unwrap();
        let decoded: ServerMessage = read_message(&mut Cursor::new(buf)).unwrap();

        assert_eq!(decoded.tab_id, TabId(9));
        match decoded.kind {
            ServerMessageKind::Rendered(success) => {
                assert_eq!(success.title, Some("Hello".to_string()));
                assert_eq!(success.next_wake_in_millis, Some(1500));
                assert!(
                    success.layout_tree.rect.width > 0.0
                        || !success.layout_tree.children.is_empty()
                );
            }
            _ => panic!("expected Rendered variant"),
        }
    }

    #[test]
    fn server_message_unchanged_round_trips_with_a_re_arm_time() {
        let message = ServerMessage {
            tab_id: TabId(5),
            kind: ServerMessageKind::Unchanged {
                next_wake_in_millis: Some(250),
            },
            updated_cookies: None,
            updated_local_storage: None,
            updated_indexed_db: None,
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &message).unwrap();
        let decoded: ServerMessage = read_message(&mut Cursor::new(buf)).unwrap();

        assert_eq!(decoded.tab_id, TabId(5));
        match decoded.kind {
            ServerMessageKind::Unchanged {
                next_wake_in_millis,
            } => assert_eq!(next_wake_in_millis, Some(250)),
            _ => panic!("expected Unchanged variant"),
        }
    }

    #[test]
    fn different_tab_ids_are_not_equal() {
        assert_ne!(TabId(1), TabId(2));
        assert_eq!(TabId(1), TabId(1));
    }

    #[test]
    fn refuses_a_length_prefix_over_the_max_message_size() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(MAX_MESSAGE_LEN + 1).to_le_bytes());
        // No actual payload bytes needed — the length check happens
        // before any attempt to read/allocate the body.
        let result: std::io::Result<RenderRequest> = read_message(&mut Cursor::new(buf));
        assert!(result.is_err());
    }

    #[test]
    fn a_truncated_message_is_a_read_error_not_a_panic() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&100u32.to_le_bytes());
        buf.extend_from_slice(b"not enough bytes");
        let result: std::io::Result<RenderRequest> = read_message(&mut Cursor::new(buf));
        assert!(result.is_err());
    }

    #[test]
    fn download_success_round_trips_arbitrary_bytes_through_base64() {
        let bytes = vec![0u8, 1, 2, 255, 254, 128, 7];
        let success = DownloadSuccess::new(&bytes, "report.pdf".to_string());
        assert_eq!(success.bytes().unwrap(), bytes);
        assert_eq!(success.suggested_filename, "report.pdf");
    }

    #[test]
    fn audio_pcm_data_round_trips_samples_including_negative_values() {
        let samples: Vec<i16> = vec![0, 1, -1, i16::MIN, i16::MAX, -12345, 12345];
        let data = AudioPcmData::new(&samples, 44100, 2);
        assert_eq!(data.samples().unwrap(), samples);
        assert_eq!(data.sample_rate, 44100);
        assert_eq!(data.channels, 2);
    }

    #[test]
    fn audio_pcm_data_survives_a_real_message_round_trip() {
        let samples: Vec<i16> = vec![100, -200, 300, -400];
        let outcome = AudioPcmOutcome::Ready(AudioPcmData::new(&samples, 48000, 1));
        let mut buf = Vec::new();
        serde_json::to_writer(&mut buf, &outcome).unwrap();
        let read_back: AudioPcmOutcome = serde_json::from_slice(&buf).unwrap();
        match read_back {
            AudioPcmOutcome::Ready(data) => {
                assert_eq!(data.samples().unwrap(), samples);
                assert_eq!(data.sample_rate, 48000);
            }
            AudioPcmOutcome::Failed(e) => panic!("expected Ready, got Failed({e})"),
        }
    }

    #[test]
    fn download_success_survives_a_real_message_round_trip() {
        let bytes = vec![10u8, 20, 30, 40, 50];
        let message = ClientMessage {
            tab_id: TabId(1),
            kind: ClientMessageKind::Download {
                url: "https://example.com/file.bin".to_string(),
                top_level_host: Some("example.com".to_string()),
            },
        };
        // Round-trip the CLIENT message (proves the request side frames
        // correctly); the SERVER reply is what actually carries bytes,
        // exercised directly below since building a real `ServerMessage`
        // here needs a `LayoutBox` this crate's own dev-deps don't
        // reach for elsewhere — `renderer`'s own tests cover the full
        // request+reply round trip end to end.
        let mut buf = Vec::new();
        write_message(&mut buf, &message).unwrap();
        let read_back: ClientMessage = read_message(&mut Cursor::new(buf)).unwrap();
        assert!(matches!(read_back.kind, ClientMessageKind::Download { .. }));

        let outcome =
            DownloadOutcome::Downloaded(DownloadSuccess::new(&bytes, "x.bin".to_string()));
        let mut buf = Vec::new();
        serde_json::to_writer(&mut buf, &outcome).unwrap();
        let read_back: DownloadOutcome = serde_json::from_slice(&buf).unwrap();
        match read_back {
            DownloadOutcome::Downloaded(success) => assert_eq!(success.bytes().unwrap(), bytes),
            DownloadOutcome::Failed(e) => panic!("expected Downloaded, got Failed({e})"),
        }
    }

    #[test]
    fn move_keyboard_focus_round_trips_through_a_real_message() {
        let message = ClientMessage {
            tab_id: TabId(1),
            kind: ClientMessageKind::MoveKeyboardFocus {
                direction: FocusDirection::Previous,
            },
        };
        let mut buf = Vec::new();
        write_message(&mut buf, &message).unwrap();
        let decoded: ClientMessage = read_message(&mut Cursor::new(buf)).unwrap();
        match decoded.kind {
            ClientMessageKind::MoveKeyboardFocus { direction } => {
                assert_eq!(direction, FocusDirection::Previous)
            }
            _ => panic!("expected MoveKeyboardFocus"),
        }
    }

    #[test]
    fn activate_focused_round_trips_through_a_real_message() {
        let message = ClientMessage {
            tab_id: TabId(1),
            kind: ClientMessageKind::ActivateFocused,
        };
        let mut buf = Vec::new();
        write_message(&mut buf, &message).unwrap();
        let decoded: ClientMessage = read_message(&mut Cursor::new(buf)).unwrap();
        assert!(matches!(decoded.kind, ClientMessageKind::ActivateFocused));
    }

    #[test]
    fn focus_node_round_trips_through_a_real_message() {
        let message = ClientMessage {
            tab_id: TabId(1),
            kind: ClientMessageKind::FocusNode {
                dom_node_id: dom::NodeId(42),
            },
        };
        let mut buf = Vec::new();
        write_message(&mut buf, &message).unwrap();
        let decoded: ClientMessage = read_message(&mut Cursor::new(buf)).unwrap();
        match decoded.kind {
            ClientMessageKind::FocusNode { dom_node_id } => {
                assert_eq!(dom_node_id, dom::NodeId(42))
            }
            _ => panic!("expected FocusNode"),
        }
    }

    #[test]
    fn eval_console_expression_round_trips_through_a_real_message() {
        let message = ClientMessage {
            tab_id: TabId(3),
            kind: ClientMessageKind::EvalConsoleExpression {
                code: "1 + 1".to_string(),
            },
        };
        let mut buf = Vec::new();
        write_message(&mut buf, &message).unwrap();
        let decoded: ClientMessage = read_message(&mut Cursor::new(buf)).unwrap();
        assert_eq!(decoded.tab_id, TabId(3));
        match decoded.kind {
            ClientMessageKind::EvalConsoleExpression { code } => assert_eq!(code, "1 + 1"),
            _ => panic!("expected EvalConsoleExpression"),
        }
    }

    #[test]
    fn console_messages_round_trip_in_a_render_success() {
        let tree = sample_layout_tree();
        let message = ServerMessage {
            tab_id: TabId(4),
            kind: ServerMessageKind::Rendered(RenderSuccess {
                layout_tree: tree,
                title: None,
                next_wake_in_millis: None,
                default_prevented: false,
                submit_url: None,
                submit_body: None,
                console_messages: vec![
                    ConsoleMessage {
                        level: ConsoleLevel::Log,
                        text: "hello".to_string(),
                    },
                    ConsoleMessage {
                        level: ConsoleLevel::Error,
                        text: "uh oh".to_string(),
                    },
                ],
                page_signals: PageSignals {
                    uses_javascript: false,
                    affiliate_link_count: 0,
                },
            }),
            updated_cookies: None,
            updated_local_storage: None,
            updated_indexed_db: None,
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &message).unwrap();
        let decoded: ServerMessage = read_message(&mut Cursor::new(buf)).unwrap();

        match decoded.kind {
            ServerMessageKind::Rendered(success) => {
                assert_eq!(success.console_messages.len(), 2);
                assert_eq!(success.console_messages[0].level, ConsoleLevel::Log);
                assert_eq!(success.console_messages[0].text, "hello");
                assert_eq!(success.console_messages[1].level, ConsoleLevel::Error);
                assert_eq!(success.console_messages[1].text, "uh oh");
            }
            _ => panic!("expected Rendered variant"),
        }
    }

    #[test]
    fn dom_snapshot_outcome_round_trips_a_nested_tree() {
        let tree = DomNode {
            node_id: dom::NodeId(1),
            kind: DomNodeKind::Element {
                tag_name: "div".to_string(),
                attributes: vec![("class".to_string(), "wrapper".to_string())],
            },
            children: vec![
                DomNode {
                    node_id: dom::NodeId(2),
                    kind: DomNodeKind::Text("hi".to_string()),
                    children: Vec::new(),
                },
                DomNode {
                    node_id: dom::NodeId(3),
                    kind: DomNodeKind::Comment("note".to_string()),
                    children: Vec::new(),
                },
            ],
        };
        let outcome = DomSnapshotOutcome::Ready(tree.clone());
        let mut buf = Vec::new();
        serde_json::to_writer(&mut buf, &outcome).unwrap();
        let decoded: DomSnapshotOutcome = serde_json::from_slice(&buf).unwrap();
        match decoded {
            DomSnapshotOutcome::Ready(decoded_tree) => assert_eq!(decoded_tree, tree),
            DomSnapshotOutcome::Unavailable => panic!("expected Ready"),
        }
    }

    #[test]
    fn dom_snapshot_result_round_trips_through_a_real_message() {
        let message = ServerMessage {
            tab_id: TabId(7),
            kind: ServerMessageKind::DomSnapshotResult(DomSnapshotOutcome::Unavailable),
            updated_cookies: None,
            updated_local_storage: None,
            updated_indexed_db: None,
        };
        let mut buf = Vec::new();
        write_message(&mut buf, &message).unwrap();
        let decoded: ServerMessage = read_message(&mut Cursor::new(buf)).unwrap();
        assert_eq!(decoded.tab_id, TabId(7));
        match decoded.kind {
            ServerMessageKind::DomSnapshotResult(DomSnapshotOutcome::Unavailable) => {}
            _ => panic!("expected DomSnapshotResult(Unavailable)"),
        }
    }
}
