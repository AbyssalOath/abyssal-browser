//! `app` — the binary. A genuinely interactive browser now, not just
//! a single-page render demo. This process is the PRIVILEGED half of
//! a multi-process split — ONE `app`, and a whole POOL of `renderer`
//! processes, one per distinct site any open tab is currently showing
//! (see `RendererPool`'s doc comment: real site isolation, not just
//! sandboxing):
//!
//!     app (this process, owns account/keys/sync/window/UI)
//!         <==== ipc (length-prefixed JSON over a pipe) ====>
//!     renderer for site A (sandboxed child process)  ─┐
//!     renderer for site B (sandboxed child process)  ─┤ RendererPool
//!     renderer for site C (sandboxed child process)  ─┘ (spawned/evicted
//!         network::HttpFetcher (real DNS-over-HTTPS/TLS/HTTP)         on demand)
//!             -> FilteringFetcher (privacy::should_block + tracking-param stripping)
//!             ->  html::parse (real html5ever tree construction)  ->  (dom tree)
//!             ->  css::user_agent_stylesheet (dark mode by default)
//!             ->  layout::build_layout_tree + layout::layout (box model, real inline flow)
//!
//!     account::create_account + derive_key
//!         ->  storage::SyncPayload (bookmarks/settings)
//!         ->  account::encrypt  ->  sync::push/pull  ->  account::decrypt
//!
//!     render::paint (real glyph rendering, scroll-aware, back in THIS process)
//!         ->  render::window::run_window (a real, interactive window)
//!
//! Why the split: this process holds the account's recovery code, its
//! derived encryption keys, and decrypted bookmarks/settings — real
//! secrets. Everything that touches UNTRUSTED, attacker-influenced
//! bytes (the real network fetch, HTML parsing, CSS, layout, JS) happens
//! in a `renderer` process instead, which never receives those secrets
//! over `ipc` at all, and is sandboxed (Landlock, on Linux — see
//! `renderer::sandbox`) so that even a memory-safety bug triggered by
//! a malicious page can't read this process's data files or open a
//! connection anywhere but a normal web port. Why a POOL rather than
//! one shared renderer: sandboxing alone protects `app`'s secrets from
//! a compromised renderer, but it does nothing to stop a compromised
//! renderer from reading a DIFFERENT open tab's DOM/cookies/script
//! state if they'd shared a process — site isolation (one process per
//! site, tabs on the same site sharing one) closes exactly that gap.
//! See `ipc`'s and `renderer`'s own module docs for the full design
//! and its honest limits (Linux-only for now; Landlock restricts
//! files/ports, not syscalls — seccomp-bpf is the noted next step).
//!
//! This process itself no longer links `network` at all — real
//! fetching is code this binary literally does not contain (see
//! `app`'s `Cargo.toml`). It still builds and lays out a handful of
//! locally-generated, TRUSTED pseudo-pages directly (`about:demo`,
//! `about:bookmarks`, `about:settings`) via the same `html`/`css`/
//! `layout` crates `renderer` uses — that's fine and deliberate: those
//! pages are built from this process's own data, not from the network,
//! so there's nothing to sandbox there.
//!
//! Usage: `cargo run -p abyssal -- <url>` opens straight to a real
//! page. With no argument, opens a small built-in demo page (no
//! network access needed) — which itself has a real link on it, so
//! clicking it demonstrates real navigation without needing to type
//! anything. Requires the `abyssal-renderer` binary to exist next to
//! this one (`cargo build --workspace` builds both).
//!
//! What's interactive now, all owned by the `Browser` struct below:
//!   - **Tabs**: a real tab bar (`Browser::paint_tab_bar`) — click a
//!     tab to switch to it, click its `x` to close it (a no-op on the
//!     last remaining tab — this app has no multi-window support, so
//!     there's nowhere for "close the last tab" to go), click `+` for
//!     a new one. Ctrl+T/Ctrl+W/Ctrl+Tab/Ctrl+Shift+Tab do the same
//!     from the keyboard. Each tab keeps its OWN page, scroll
//!     position, back/forward history, and address bar state fully
//!     resident (see the `Tab` struct) — switching tabs is instant and
//!     never re-fetches anything, matching real browsers. What's
//!     genuinely singular across every tab (the account, synced
//!     bookmarks/settings, the fetcher, theme, window size) lives on
//!     `Browser` itself instead — see its own doc comment for why
//!     duplicating those per-tab would be an actual correctness bug,
//!     not just wasted memory.
//!   - **Clicking a link** hit-tests the layout tree
//!     (`layout::hit_test_link`) and navigates to its `href`, resolved
//!     against the current URL (see `resolve_url` — a real but
//!     deliberately simplified RFC 3986 approximation, not a full
//!     implementation) — UNLESS the click's own `click` event
//!     (dispatched first — see `handle_click`'s body and `ipc::
//!     ClientMessageKind::Click`'s doc comment) had
//!     `event.preventDefault()` called on it somewhere in its
//!     capturing/target/bubbling chain, exactly like a real browser. A
//!     `settings:` href is the one special case that skips JS dispatch
//!     entirely — see the Settings bullet below.
//!   - **Scrolling** (mouse wheel) adjusts a vertical offset that
//!     `render::paint`'s `scroll_y` parameter applies — the page's own
//!     layout never changes size, only which vertical slice of it is
//!     visible.
//!   - **The address bar**, pinned below the tab bar, with real
//!     click-to-position/select-all-on-focus/arrow-key cursor movement
//!     (see `Tab::address_bar_cursor`/`address_bar_selection`) and
//!     Alt+Left/Right (or the `<`/`>` buttons) for history navigation —
//!     see `render::window::InputEvent`'s doc comment for the key
//!     handling. Typed commands: `bookmark`, `bookmarks`, `settings`,
//!     `history`, `back`, `forward`, and `set <name> <value>` (see the
//!     Settings bullet).
//!   - **History** (`about:history`, or type `history`): every
//!     successfully loaded real page is recorded (title + timestamp —
//!     see `storage::SyncPayload::record_visit`), newest first, capped
//!     to the most recent `storage::MAX_HISTORY_ENTRIES` so the synced
//!     blob doesn't grow without bound. `about:`/failed-navigation
//!     pseudo-pages are never recorded. `history:clear` on the page
//!     itself erases it.
//!   - **Settings** (`about:settings`, or type `settings`): theme,
//!     fingerprint-resistance level, and WebRTC are plain clickable
//!     links (`render_settings_html`/`handle_settings_link`) — no real
//!     form-widget rendering exists, so every option is just an `<a
//!     href="settings:...">` the click handler intercepts instead of
//!     fetching. The sync server URL is free text, so it's set via the
//!     typed `set sync-server-url <url>` command instead of a link.
//!     Settings live in the same `storage::SyncPayload` as bookmarks,
//!     so a change syncs to other devices exactly like a bookmark does.
//!   - **Find in page** (`Ctrl+F`): a small floating bar (see
//!     `paint_find_bar`) filters live as you type, `Enter`/`Shift+Enter`
//!     cycle to the next/previous match (wrapping), and every match is
//!     highlighted directly in the page (`render::paint_with_find`) —
//!     the current one in a distinct color from the others, matching a
//!     real browser's find bar. Matched against each wrapped line's own
//!     text (see `render::find_matches_in_tree`'s doc comment for the
//!     one real limitation this implies: a match split across a
//!     visual line wrap isn't found) rather than a full logical-text
//!     search. `Escape` closes it; opening it (or navigating anywhere
//!     else) cancels any in-progress address-bar edit and closes a
//!     previous find session rather than leaving stale state around.
//!   - **Downloads** (`about:downloads`, or type `downloads`): clicking
//!     an `<a download>` link (see `layout::LinkHit::download`) fetches
//!     it through the sandboxed renderer (`renderer::download` —
//!     never `app` itself, matching every other real fetch) and saves
//!     it to the real OS Downloads folder (`real_downloads_dir`) instead
//!     of navigating, respecting `preventDefault()` exactly like a
//!     normal link click would. Recorded locally (`DownloadRecord`,
//!     encrypted at rest with the same account-derived key as
//!     bookmarks — see that type's own doc comment for why it's
//!     deliberately NOT synced) for the `about:downloads` page to list.
//!     No `Content-Disposition` awareness yet (`network::Response`
//!     doesn't expose arbitrary headers today) and no download progress
//!     UI — a download blocks the same way a slow page load already
//!     does, and files over roughly 45 MB fail cleanly rather than
//!     downloading at all (see `ipc::DownloadSuccess`'s own doc comment
//!     for exactly why that cap exists). Each listed file's saved path
//!     is a real, clickable `file://` link (see `render_downloads_html`
//!     and `LOCAL_FILES_SITE`) that opens it through the browser's own
//!     dedicated local-file renderer process.
//!   - **`<audio>`/`<video>`**: real sound, real transport controls
//!     (play/pause/seek/mute — `layout::hit_test_media_control`), NO
//!     moving pictures — `renderer::media` only ever decodes a media
//!     file's AUDIO track (no pure-Rust decoder exists for the video
//!     codecs real `<video>` files actually use), so a `<video>` shows
//!     its poster (or a plain placeholder) the whole time, same as a
//!     paused real one would look, just never advancing. Decoding
//!     happens in the sandboxed renderer (`symphonia`, pure Rust);
//!     actual audio OUTPUT happens here, in `app`, via `cpal`
//!     (`media_playback`'s own module docs) — decoded PCM crosses the
//!     IPC boundary once per element (`ipc::ClientMessageKind::
//!     FetchAudioPcm`), then plays from an in-memory buffer, not a
//!     stream, so there's a real, documented duration/size cap (see
//!     `renderer::media`'s own doc comment) rather than progressive
//!     playback of an arbitrarily long file. No JS scripting API
//!     (`HTMLMediaElement.play()`/`.currentTime`/`timeupdate`, ...) —
//!     only the native `controls` bar can drive playback, a deliberate,
//!     documented follow-up rather than an oversight.
//!
//! Expect real-world pages to render roughly, not with full fidelity:
//! no CSS specificity beyond tag/class selectors, no flexbox/grid/
//! floats, no images, one bundled font, and no JS engine at all —
//! anything relying on JavaScript to render its content (most modern
//! sites) will show up empty or broken.
//!
//! `account`'s crypto is real now (Argon2id + ChaCha20Poly1305, not a
//! placeholder — see account/src/lib.rs). That's necessary but not
//! sufficient for "secure to real users": there's still no security
//! audit. See the README's "Honest security status" section before
//! promoting this anywhere.

mod accessibility;
mod media_playback;
mod userscripts;

use render::window::{Frame, InputEvent};

/// Height, in canvas pixels, reserved at the top of the window for the
/// address bar. Page content occupies everything below `CHROME_HEIGHT`
/// (this plus `TAB_BAR_HEIGHT`).
const ADDRESS_BAR_HEIGHT: f32 = 32.0;
const ADDRESS_BAR_FONT_SIZE: f32 = 16.0;

/// Layout of the address bar's chrome, left to right: a back button, a
/// forward button, a reload button, then the editable text field, and
/// (right-aligned, computed in `Browser::bookmark_button_x`/
/// `account_button_x` since they depend on the live `canvas_width`
/// rather than being fixed from the left edge) a bookmark-star button
/// and an account button. Left-side positions are kept as constants
/// (rather than computed) so painting and click hit-testing can't
/// drift apart from each other; the right-side ones use a shared
/// method for the same reason (see those methods' own doc comments).
const NAV_BUTTON_WIDTH: f32 = 24.0;
const NAV_BUTTON_MARGIN: f32 = 4.0;
const BACK_BUTTON_X: f32 = NAV_BUTTON_MARGIN;
const FORWARD_BUTTON_X: f32 = BACK_BUTTON_X + NAV_BUTTON_WIDTH + NAV_BUTTON_MARGIN;
const RELOAD_BUTTON_X: f32 = FORWARD_BUTTON_X + NAV_BUTTON_WIDTH + NAV_BUTTON_MARGIN;
const ADDRESS_TEXT_START_X: f32 = RELOAD_BUTTON_X + NAV_BUTTON_WIDTH + NAV_BUTTON_MARGIN * 2.0;

/// Right-edge margin for the "JS" / "N aff" page-signals badge (see
/// `Browser::paint_page_signals_badge`) — the same fixed-margin-from-
/// the-edge approach the find bar (`FIND_BAR_MARGIN`) already uses.
const PAGE_SIGNALS_BADGE_MARGIN: f32 = 12.0;

/// Height of the tab strip, sitting above the address bar. `CHROME_HEIGHT`
/// (tab strip + address bar) is what every "where does page content
/// start" calculation actually uses — `TAB_BAR_HEIGHT`/`ADDRESS_BAR_HEIGHT`
/// individually only matter for positioning within the chrome itself.
const TAB_BAR_HEIGHT: f32 = 28.0;
const TAB_FONT_SIZE: f32 = 14.0;
const CHROME_HEIGHT: f32 = TAB_BAR_HEIGHT + ADDRESS_BAR_HEIGHT;

/// The find-in-page bar (`Ctrl+F`) is a small floating overlay in the
/// top-right of the PAGE CONTENT area — deliberately NOT folded into
/// `CHROME_HEIGHT` the way the tab/address bars are, since it only
/// appears sometimes; giving it a fixed slice of `CHROME_HEIGHT` would
/// mean every scroll/click/viewport-height calculation in this file
/// would need to account for whether it's currently open. Floating
/// instead costs nothing extra to draw and simply overlaps whatever
/// page content is underneath it, matching how most real browsers'
/// find bars are also an overlay rather than reflowing the page.
const FIND_BAR_WIDTH: f32 = 260.0;
const FIND_BAR_HEIGHT: f32 = 32.0;
const FIND_BAR_MARGIN: f32 = 8.0;
const FIND_BAR_FONT_SIZE: f32 = 14.0;

/// DevTools (`F12`) is a bottom-DOCKED panel, unlike the find bar — it
/// genuinely reduces the page's own visible viewport height (see every
/// `viewport_height`/`clamp_scroll` call site) rather than floating
/// over the content, matching how a real browser's docked DevTools
/// panel works. Fixed height rather than resizable (a real browser
/// lets you drag its border) — a documented scope cut, not an oversight.
const DEVTOOLS_PANEL_HEIGHT: f32 = 260.0;
const DEVTOOLS_TAB_BAR_HEIGHT: f32 = 24.0;
const DEVTOOLS_FONT_SIZE: f32 = 12.0;
const DEVTOOLS_ROW_HEIGHT: f32 = 16.0;
const DEVTOOLS_INDENT: f32 = 12.0;
const DEVTOOLS_PADDING: f32 = 6.0;
/// Height of the console's own REPL input row, pinned to the bottom of
/// the Console tab (the scrolling log fills whatever's left above it).
const DEVTOOLS_CONSOLE_INPUT_HEIGHT: f32 = 20.0;
/// Fraction of the Elements tab's width given to the DOM tree pane; the
/// rest goes to the box-model/computed-style pane for whatever's
/// currently selected.
const DEVTOOLS_ELEMENTS_TREE_WIDTH_FRACTION: f32 = 0.5;
/// Width of each of the DevTools panel's own top-strip tab labels
/// ("Console"/"Elements") — painting and `handle_devtools_tab_bar_click`
/// share these constants so they can't drift apart.
const DEVTOOLS_TAB_LABEL_WIDTH: f32 = 80.0;
/// Width of each right-aligned action button ("Pick"/"Refresh") in the
/// DevTools tab strip, only shown while the Elements tab is active.
const DEVTOOLS_ACTION_BUTTON_WIDTH: f32 = 60.0;

const DEVTOOLS_PANEL_BACKGROUND: render::Color = render::Color {
    r: 20,
    g: 20,
    b: 20,
    a: 255,
};
const DEVTOOLS_TAB_BAR_BACKGROUND: render::Color = render::Color {
    r: 30,
    g: 30,
    b: 30,
    a: 255,
};
const DEVTOOLS_INPUT_BACKGROUND: render::Color = render::Color {
    r: 12,
    g: 12,
    b: 12,
    a: 255,
};
const DEVTOOLS_ACTIVE_TAB_COLOR: render::Color = render::Color {
    r: 230,
    g: 230,
    b: 230,
    a: 255,
};
const DEVTOOLS_INACTIVE_TAB_COLOR: render::Color = render::Color {
    r: 130,
    g: 130,
    b: 130,
    a: 255,
};
const DEVTOOLS_TREE_TEXT_COLOR: render::Color = render::Color {
    r: 200,
    g: 200,
    b: 200,
    a: 255,
};
const DEVTOOLS_MUTED_COLOR: render::Color = render::Color {
    r: 120,
    g: 120,
    b: 120,
    a: 255,
};
const DEVTOOLS_INFO_COLOR: render::Color = render::Color {
    r: 120,
    g: 180,
    b: 255,
    a: 255,
};
const DEVTOOLS_WARN_COLOR: render::Color = render::Color {
    r: 230,
    g: 180,
    b: 60,
    a: 255,
};
const DEVTOOLS_ERROR_COLOR: render::Color = render::Color {
    r: 235,
    g: 90,
    b: 90,
    a: 255,
};
const DEVTOOLS_DIVIDER_COLOR: render::Color = render::Color {
    r: 60,
    g: 60,
    b: 60,
    a: 255,
};
const DEVTOOLS_SELECTED_ROW_COLOR: render::Color = render::Color {
    r: 45,
    g: 65,
    b: 90,
    a: 255,
};
/// The on-page highlight overlay for the Elements tab's selected node
/// — a real browser's own selection highlight is likewise a
/// semi-transparent tint, not a solid fill, so the page content stays
/// legible underneath it. `DEVTOOLS_HIGHLIGHT_COVERAGE` is this color's
/// blend strength (see `blend_rect`), not its own alpha channel (which
/// `blend_pixel` ignores on the source color — see that method's own
/// doc comment).
const DEVTOOLS_HIGHLIGHT_COLOR: render::Color = render::Color {
    r: 80,
    g: 140,
    b: 255,
    a: 255,
};
const DEVTOOLS_HIGHLIGHT_COVERAGE: u8 = 90;

const BOX_MODEL_LABEL_FONT_SIZE: f32 = 10.0;
const BOX_MODEL_LABEL_COLOR: render::Color = render::Color {
    r: 20,
    g: 20,
    b: 20,
    a: 255,
};
/// Nested box-model band colors, outermost to innermost — the same
/// margin/border/padding/content color convention real DevTools uses.
const BOX_MODEL_MARGIN_COLOR: render::Color = render::Color {
    r: 220,
    g: 170,
    b: 110,
    a: 255,
};
const BOX_MODEL_BORDER_COLOR: render::Color = render::Color {
    r: 220,
    g: 210,
    b: 140,
    a: 255,
};
const BOX_MODEL_PADDING_COLOR: render::Color = render::Color {
    r: 160,
    g: 210,
    b: 140,
    a: 255,
};
const BOX_MODEL_CONTENT_COLOR: render::Color = render::Color {
    r: 140,
    g: 180,
    b: 230,
    a: 255,
};

/// Tabs are evenly divided across the available width (clamped to this
/// min/max), and a fixed-width "+" button always follows the last one.
/// TODO: no overflow handling — past enough tabs, `MIN_TAB_WIDTH` stops
/// being respected and tabs just keep shrinking rather than scrolling
/// or collapsing into an overflow menu the way real browsers do. A
/// documented simplification (matching e.g. this codebase's "no true
/// pillarboxing" TODO elsewhere), not an oversight.
const MIN_TAB_WIDTH: f32 = 80.0;
const MAX_TAB_WIDTH: f32 = 200.0;
const NEW_TAB_BUTTON_WIDTH: f32 = TAB_BAR_HEIGHT;
const TAB_CLOSE_ZONE_WIDTH: f32 = 20.0;
const TAB_TEXT_PADDING: f32 = 8.0;

/// `storage::Settings` keys this app actually reads/writes. Centralized
/// here (rather than repeating string literals at every call site) so
/// the settings page, the `set <key> <value>` address-bar command, and
/// `Browser::apply_setting` can never drift onto different spellings
/// for the same setting.
const SETTING_THEME: &str = "theme";
const SETTING_FINGERPRINT_RESISTANCE: &str = "fingerprint_resistance";
const SETTING_WEBRTC: &str = "webrtc";
const SETTING_SYNC_SERVER_URL: &str = "sync_server_url";

const DEMO_HTML: &str = r#"
<html>
<head><title>Abyssal Browser</title></head>
<body>
<h1>Abyssal Browser</h1>
<blockquote style="border-left: 3px solid #888; margin: 16px 0; padding: 4px 16px;">
<p>"When you gaze long into the Abyss, the Abyss also gazes into you."</p>
<p>- F. Nietzsche</p>
</blockquote>
<p>This is a built-in demo page, shown because no URL was given on the
command line (usage: <code>cargo run -p abyssal -- &lt;url&gt;</code>),
or because a new tab was just opened. No network access is needed to
see this page.</p>
<p>Click the address bar above to type a URL, or click this link to
try real navigation: <a href="https://example.com">example.com</a>.</p>
</body>
</html>
"#;

/// The browser's own window icon — bundled into the binary (like
/// `text::load_default_font`'s font) rather than read from a path at
/// runtime, so there's no "installed somewhere on disk" requirement at
/// all for something this small and unchanging. See `load_window_icon`
/// for why a failure to decode this is a warning, not a panic (unlike
/// the bundled font, which every page needs to render text at all, a
/// missing/broken icon is purely cosmetic).
const ICON_BYTES: &[u8] = include_bytes!("../assets/icon.png");

/// Decodes the bundled icon into the raw RGBA pixels `render::window::
/// run_window` actually wants — real PNG decoding (the `image` crate,
/// already an existing, vetted dependency of `renderer`, just not
/// previously a DIRECT one of this crate), but of a small, fixed,
/// TRUSTED asset compiled into this binary, not of anything
/// network-fetched or otherwise untrusted — there's no sandboxing
/// concern here the way there is for a page's own `<img>` bytes (see
/// `renderer::images`' own module docs on why THAT decode specifically
/// has to happen in the sandboxed process). `None` (logged, not
/// panicked) if the bundled asset somehow fails to decode — a browser
/// that starts with no window icon is a cosmetic regression, not a
/// reason to refuse to run at all.
fn load_window_icon() -> Option<render::window::WindowIcon> {
    match image::load_from_memory(ICON_BYTES) {
        Ok(image) => {
            let rgba = image.to_rgba8();
            let (width, height) = rgba.dimensions();
            Some(render::window::WindowIcon {
                rgba: rgba.into_raw(),
                width,
                height,
            })
        }
        Err(e) => {
            eprintln!("Could not decode the bundled window icon (continuing without one): {e}");
            None
        }
    }
}

fn main() {
    let requested_url = std::env::args().nth(1);
    let mut browser = Browser::new(requested_url.as_deref());
    // `Browser::new` already navigated (or loaded the demo page), so
    // its real title is known now — use that as the window's starting
    // title rather than a hardcoded placeholder (the synthetic
    // `Resized` event `run_window` calls the handler with at startup
    // doesn't itself carry a title update — see `handle_event`).
    let initial_title = browser.window_title();
    let icon = load_window_icon();

    render::window::run_window(&initial_title, icon, move |event| {
        browser.handle_event(event)
    });
    // blocks until the window is closed
}

/// One tab's own page state — everything a real browser keeps
/// independently per tab: the loaded page, its scroll position, its
/// own back/forward history, and its own address bar (including any
/// in-progress edit, so switching away mid-edit and back preserves
/// exactly what you were typing). Deliberately a plain data bag with
/// only small, self-contained helper methods — the actual navigation
/// logic (`Browser::navigate`, `load_demo_page`, etc.) lives on
/// `Browser`, since it needs shared state (the fetcher, theme, font)
/// alongside a specific tab's fields, and `Browser` already holds both.
struct Tab {
    /// Identifies this tab to the sandboxed renderer process (see
    /// `ipc::TabId`'s doc comment) — stable for the tab's whole
    /// lifetime, assigned once by `Browser::allocate_tab_id` and never
    /// reused, deliberately NOT this tab's position in `Browser::tabs`
    /// (which shifts whenever another tab closes — see
    /// `Browser::close_tab`'s index-adjustment logic elsewhere in this
    /// file). Using the `Vec` position as the renderer-facing identity
    /// would silently reassign one tab's identity to another the
    /// moment an earlier tab closed.
    id: ipc::TabId,
    current_url: String,
    layout_tree: layout::LayoutBox,
    cached_title: Option<String>,
    /// `None` for a tab that's never navigated (or a local `about:`/
    /// failed-load page — see `Browser::navigate`, whose `Err` arm
    /// leaves this untouched at `None`), `Some` from the first real
    /// `Rendered` reply onward. Purely a chrome badge (see
    /// `Browser::paint_address_bar`) — see `ipc::PageSignals`'s own
    /// doc comment for what it does and doesn't mean.
    cached_page_signals: Option<ipc::PageSignals>,

    address_bar_text: String,
    editing_address_bar: bool,
    /// Cursor position within `address_bar_text`, as a CHARACTER index
    /// (not a byte offset — see `char_byte_offset`), so it stays valid
    /// across non-ASCII text without landing mid-codepoint.
    address_bar_cursor: usize,
    /// `Some((start, end))` (character indices, `start <= end`) while a
    /// range is selected — e.g. immediately after clicking into the bar
    /// to focus it, which selects all of its text so the next keystroke
    /// replaces it outright instead of mashing onto the end (that
    /// mashing — typing "back" into the middle of a stale URL — was the
    /// actual bug this exists to fix, not just missing visual polish).
    address_bar_selection: Option<(usize, usize)>,

    /// Each entry is the URL being left plus that page's own scroll
    /// offset at the moment of leaving it, so going back restores the
    /// page as it was, not just re-fetches it at the top.
    history_back: Vec<(String, f32)>,
    history_forward: Vec<(String, f32)>,

    scroll_y: f32,

    /// `Some(instant)` when this tab's renderer-side `script::Session`
    /// has a pending `setTimeout` due at that time — set from
    /// `RenderSuccess::next_wake_in_millis`/`ServerMessageKind::
    /// Unchanged`'s field (added to `Instant::now()` at the moment the
    /// reply was RECEIVED, not when it fires), cleared (`None`) when
    /// the tab has nothing pending. `Browser::earliest_wake_at` takes
    /// the minimum of this across every tab to decide the single
    /// `Frame::wake_at` deadline the window event loop actually arms
    /// (see `render::window`'s module docs on why only one deadline
    /// can be in flight at a time) — an inactive tab's timer firing in
    /// the background works the same way an active one's does, this
    /// field is exactly what makes that possible.
    next_wake_at: Option<std::time::Instant>,

    /// The eTLD+1 "site" (see `privacy::registrable_domain`) of the
    /// renderer PROCESS currently holding this tab's live
    /// `renderer::script::Session`, if any — `None` for a tab that's
    /// never navigated to a real page, or that's currently showing a
    /// local `about:` page (see `leave_renderer_backed_page`). This is
    /// what routes a `Tick`/`Click`/`CloseTab` to the CORRECT renderer
    /// process out of `Browser::renderers`' whole pool — see that
    /// field's own doc comment for why there's a pool at all rather
    /// than one shared process. Deliberately independent of
    /// `next_wake_at`: a tab can have a live session with NO pending
    /// timer (this `Some`, that `None`), so neither can substitute for
    /// the other.
    renderer_site: Option<String>,

    /// The text-editable `<input>` (see `layout::is_text_like_input`)
    /// currently focused on the PAGE itself, if any — entirely separate
    /// from `editing_address_bar` (browser chrome, never sent to the
    /// renderer at all). Real focus/cursor STATE lives in the
    /// renderer's own `script::Session` (see `ipc::ClientMessageKind::
    /// Focus`'s doc comment on why: `app` never touches the DOM
    /// directly) — this is just enough for `handle_event` to know
    /// whether a keystroke should go to the page (via
    /// `RendererProcess::text_input`) instead of being ignored or,
    /// while `editing_address_bar` is ALSO false, doing nothing at all.
    /// Cleared on navigation, on blurring for any reason (clicking
    /// elsewhere, clicking the address bar, pressing Escape), and
    /// whenever a `Focus`/click resolves to something that ISN'T a text
    /// input.
    focused_page_input: Option<dom::NodeId>,
    /// Whichever DOM node currently has KEYBOARD focus on the page, of
    /// ANY focusable kind (a link, button, checkbox, or text input —
    /// see `layout::is_keyboard_focusable`) — a superset of
    /// `focused_page_input` (which stays narrowly text-input-only, for
    /// keystroke routing) that mirrors the renderer's own broadened
    /// `script::Session::focused` field (see that field's own doc
    /// comment). Driven by `Tab`/`Shift+Tab` (`Browser::
    /// handle_focus_move`) and by a mouse click landing on a text
    /// input (kept in sync right alongside `focused_page_input` there);
    /// `Enter`/`Space` activates whatever this names when it ISN'T also
    /// `focused_page_input` (see `Browser::activate_page_keyboard_focus`).
    /// Cleared on navigation and on blur, same as `focused_page_input`.
    keyboard_focus: Option<dom::NodeId>,

    /// `true` while this tab's find-in-page bar is open (`Ctrl+F`) —
    /// takes over `CharTyped`/`Backspace`/`Enter`/`FindPrevious`/
    /// `Escape` the same way `editing_address_bar` already does for the
    /// address bar, and mutually exclusive with it (opening find closes
    /// an in-progress address-bar edit, and vice versa — see
    /// `enter_find_mode`/`InputEvent::Find`'s handling).
    finding_in_page: bool,
    find_query: String,
    /// Every current match's on-page rect, recomputed (`Browser::
    /// refresh_find_matches`) whenever `find_query` changes OR the page
    /// itself changes (a fresh navigation, a script mutating the DOM) —
    /// NOT incrementally maintained, so it can go briefly stale between
    /// a DOM mutation and the next recompute; acceptable for a find bar,
    /// which recomputes on every query edit and match-jump anyway.
    find_matches: Vec<render::MatchRect>,
    /// Index into `find_matches` — always `< find_matches.len()` when
    /// that's non-empty; meaningless (and ignored by both painting and
    /// `find_next`/`find_previous`) when it's empty.
    find_current_index: usize,

    /// Each media element's decoded PCM, fetched (once) the first time
    /// its play button is clicked — see `Browser::toggle_media_play_pause`
    /// and `RendererProcess::fetch_audio_pcm`. Kept around for the rest
    /// of this tab's life on this page so pause/resume/seek never need
    /// to re-fetch it.
    media_pcm_cache: std::collections::HashMap<dom::NodeId, media_playback::CachedPcm>,
    /// A LIVE `cpal` stream for whichever media elements are CURRENTLY
    /// playing — present only while playing; pausing removes (and so
    /// drops, stopping) the entry, first saving its `current_time_secs`
    /// into `media_position` so a later resume picks up where it left
    /// off (see `media_playback::ActiveStream`'s own doc comment on why
    /// dropping is the only way to actually stop one).
    active_playback: std::collections::HashMap<dom::NodeId, media_playback::ActiveStream>,
    /// Each media element's current playback position in seconds —
    /// persists across pause/resume (unlike `active_playback`, which
    /// only exists while actually playing), updated on every play,
    /// pause, seek, and periodic progress tick.
    media_position: std::collections::HashMap<dom::NodeId, f32>,
    /// Each media element's current mute flag — persists across pause/
    /// resume, same reasoning as `media_position`.
    media_muted: std::collections::HashMap<dom::NodeId, bool>,
    /// When this tab's next media-progress tick is due, if anything in
    /// `active_playback` is currently playing — `None` whenever it
    /// isn't. Set on every successful `play_media` and rescheduled by
    /// `Browser::handle_media_progress_tick` after each tick that finds
    /// something still playing; independent of `next_wake_at` (JS
    /// timers), since a page playing audio might have no `setTimeout`
    /// pending at all, and vice versa.
    next_media_tick_at: Option<std::time::Instant>,

    /// `true` while this tab's DevTools panel (`F12`) is showing —
    /// unlike `finding_in_page`/`editing_address_bar`, this persists
    /// across navigation (see `reset_devtools_page_state`'s own doc
    /// comment), matching a real browser: DevTools stays open as you
    /// browse, it's the PAGE-SCOPED content inside it (console log, DOM
    /// snapshot, selection) that resets.
    devtools_open: bool,
    devtools_tab: DevtoolsTab,
    /// Every `console.*` call (and REPL echo/result) since this page
    /// loaded — see `ipc::RenderSuccess::console_messages`'s own doc
    /// comment on how entries arrive here. Cleared on navigation, not
    /// on closing/reopening the panel — matching a real browser's
    /// console, which keeps scrollback across a panel toggle.
    console_log: Vec<ipc::ConsoleMessage>,
    /// Text currently typed into the console's REPL input line, not yet
    /// submitted — a plain, append/pop-only buffer (no cursor, no
    /// arrow-key editing/history), the same deliberate simplicity
    /// `find_query` already uses for its own input line.
    console_input: String,
    /// `true` while the console's REPL input line has keyboard focus —
    /// a fourth mode alongside `finding_in_page`/`editing_address_bar`/
    /// `focused_page_input`, checked first in `handle_event`'s text-
    /// editing arms (see that method) since DevTools is a modal-ish
    /// overlay above the page.
    console_input_focused: bool,
    /// How many of the OLDEST entries in `console_log` are scrolled
    /// past (in ROWS, not pixels — `paint_devtools_panel` converts) —
    /// mouse wheel scroll, while the DevTools panel is open with the
    /// Console tab active, adjusts this INSTEAD OF the page's own
    /// `scroll_y` (see `InputEvent::Scroll`'s handling) since this
    /// codebase tracks no mouse position to decide which one the
    /// pointer is actually over — a documented simplification, not an
    /// oversight.
    console_scroll_rows: usize,
    /// The most recent DOM tree fetched via `ipc::ClientMessageKind::
    /// FetchDomSnapshot` for the Elements panel — `None` before the
    /// first fetch (panel never opened on this page yet) or after a
    /// navigation clears it. Deliberately NOT auto-refreshed after
    /// every render (see that message kind's own doc comment on the
    /// cost that would add to every ordinary click/tick) — refreshed
    /// only when the panel opens, the Elements tab is switched to, or
    /// the panel's own manual refresh control is clicked.
    dom_snapshot: Option<ipc::DomNode>,
    /// The DOM node currently selected in the Elements tree, if any —
    /// drives both the box-model/computed-style side panel and the
    /// on-page highlight overlay (`paint_devtools_highlight`).
    devtools_selected_node: Option<dom::NodeId>,
    /// Row-scroll offset for the Elements tab's DOM tree pane — separate
    /// from `console_scroll_rows` since the two tabs are never visible
    /// at once.
    elements_tree_scroll_rows: usize,
    /// `true` while "Pick an element" is armed (Elements tab's own
    /// button) — the NEXT page click (anywhere, even outside the
    /// DevTools panel) selects whatever element it hit instead of
    /// running that click's normal link/JS/media-control dispatch, then
    /// turns itself back off. See `Browser::handle_click`'s own doc
    /// comment for exactly where this is checked relative to every
    /// other click path.
    devtools_picking: bool,
}

/// Which sub-panel of the DevTools bottom panel is showing — see
/// `Tab::devtools_tab`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DevtoolsTab {
    Console,
    Elements,
}

impl Tab {
    /// A blank tab, not yet showing any real page — always immediately
    /// followed by a `Browser` method (`load_demo_page_without_history`,
    /// `navigate`, ...) that gives it real content. Mirrors the same
    /// two-step "placeholder, then load" pattern `Browser::new` used
    /// even before tabs existed, since `Tab` must be a complete, valid
    /// value before any of those `&mut self` methods can run.
    fn blank(id: ipc::TabId) -> Tab {
        let placeholder_document = dom::Node::new_document();
        let placeholder_tree =
            layout::build_layout_tree(&placeholder_document, &css::Stylesheet::default());
        Tab {
            id,
            current_url: String::new(),
            layout_tree: placeholder_tree,
            cached_title: None,
            cached_page_signals: None,
            address_bar_text: String::new(),
            editing_address_bar: false,
            address_bar_cursor: 0,
            address_bar_selection: None,
            history_back: Vec::new(),
            history_forward: Vec::new(),
            scroll_y: 0.0,
            next_wake_at: None,
            renderer_site: None,
            focused_page_input: None,
            keyboard_focus: None,
            finding_in_page: false,
            find_query: String::new(),
            find_matches: Vec::new(),
            find_current_index: 0,
            media_pcm_cache: std::collections::HashMap::new(),
            active_playback: std::collections::HashMap::new(),
            media_position: std::collections::HashMap::new(),
            media_muted: std::collections::HashMap::new(),
            next_media_tick_at: None,
            devtools_open: false,
            devtools_tab: DevtoolsTab::Console,
            console_log: Vec::new(),
            console_input: String::new(),
            console_input_focused: false,
            console_scroll_rows: 0,
            dom_snapshot: None,
            devtools_selected_node: None,
            elements_tree_scroll_rows: 0,
            devtools_picking: false,
        }
    }

    fn window_title(&self) -> String {
        self.cached_title
            .clone()
            .unwrap_or_else(|| "New Tab".to_string())
    }

    /// Replaces the address bar's text (e.g. after navigating), resetting
    /// the cursor to the end and clearing any selection — the cursor/
    /// selection are character indices into the OLD text, so leaving
    /// them as-is after swapping the text out from under them could
    /// point past the end of the new string or land mid-word.
    fn set_address_bar_text(&mut self, text: String) {
        self.address_bar_cursor = text.chars().count();
        self.address_bar_text = text;
        self.address_bar_selection = None;
    }

    /// Inserts `c` at the cursor, first deleting the active selection (if
    /// any) — standard "typing replaces the selection" behavior, and
    /// exactly what turns click-to-select-all into "just type the new
    /// URL" instead of needing a separate select-all/delete step.
    fn insert_into_address_bar(&mut self, c: char) {
        self.delete_address_bar_selection();
        let byte_idx = text::char_byte_offset(&self.address_bar_text, self.address_bar_cursor);
        self.address_bar_text.insert(byte_idx, c);
        self.address_bar_cursor += 1;
    }

    /// If a selection is active, deletes the selected range, moves the
    /// cursor to where it started, and reports `true`. Returns `false`
    /// (and does nothing) if there's no selection — callers use that to
    /// fall back to their own single-character delete logic (e.g.
    /// `Backspace`'s "delete the char before the cursor").
    fn delete_address_bar_selection(&mut self) -> bool {
        let Some((start, end)) = self.address_bar_selection.take() else {
            return false;
        };
        let start_b = text::char_byte_offset(&self.address_bar_text, start);
        let end_b = text::char_byte_offset(&self.address_bar_text, end);
        self.address_bar_text.replace_range(start_b..end_b, "");
        self.address_bar_cursor = start;
        true
    }

    /// Records where we're leaving FROM before loading something new —
    /// including this page's own current scroll offset, so a later
    /// `go_back` can restore it instead of always landing at the top.
    fn record_navigation_history(&mut self) {
        if !self.current_url.is_empty() {
            self.history_back
                .push((self.current_url.clone(), self.scroll_y));
        }
        self.history_forward.clear();
    }
}

/// The path to the `abyssal-renderer` binary this process spawns —
/// assumed to sit right next to this one (true for `cargo build
/// --workspace`, which puts every workspace binary into the same
/// `target/{debug,release}/` directory; a packaged install just needs
/// to preserve that layout). A REAL `cargo run`/installed `abyssal`
/// binary always finds it on the first try; the one-directory-up
/// fallback exists purely so this module's own `#[cfg(test)]` tests
/// (which construct a real `Browser` and spawn real renderer
/// subprocesses — see this module's test module) can find it too, from
/// underneath `cargo test`'s own `target/{debug,release}/deps/`.
fn renderer_binary_path() -> std::path::PathBuf {
    let exe_name = if cfg!(windows) {
        "abyssal-renderer.exe"
    } else {
        "abyssal-renderer"
    };
    let current_exe = std::env::current_exe()
        .unwrap_or_else(|e| panic!("failed to determine this binary's own path: {e}"));
    let exe_dir = current_exe
        .parent()
        .expect("an executable's path always has a parent directory");

    let sibling = exe_dir.join(exe_name);
    if sibling.is_file() {
        return sibling;
    }
    if let Some(parent_dir) = exe_dir.parent() {
        let one_up = parent_dir.join(exe_name);
        if one_up.is_file() {
            return one_up;
        }
    }
    // Neither exists — return the normal (sibling) path anyway so
    // every caller's own error message names the location a real
    // install is actually expected to use, not the test-only fallback.
    sibling
}

/// What a `RendererProcess` needs to seed itself from, and persist
/// changes to, its cookies/`localStorage`/IndexedDB — see
/// `ipc::ServerMessage`'s own doc comment for why this has to live in
/// `app` (the only process that ever holds `encryption_key`) rather
/// than in `renderer` itself, which used to write these three files
/// directly, in plaintext, before this existed.
///
/// `encryption_key` is derived ONCE (`Browser::new_with_data_dir_and_
/// downloads_dir`) and cloned into every `RendererProcess` this
/// browser ever spawns, rather than re-derived per save the way
/// `save_bookmarks`/`save_download_history` still do: those only run
/// on rare, explicit user actions (adding a bookmark, finishing a
/// download), but a cookie or `localStorage` write can happen on
/// nearly every single navigation or script-driven interaction — Argon2id
/// is DELIBERATELY expensive (128 MiB, t=3; see `account`'s own module
/// docs), so re-running it that often would visibly stall this
/// process's single-threaded UI event loop. Caching it here is a
/// real, disclosed tradeoff against the "derive right before use, use
/// immediately, let it drop" hygiene every OTHER call site keeps: it
/// stays in memory (zeroized on drop, like any other `Zeroizing`) for
/// this whole process's lifetime instead of a single call's.
#[derive(Clone)]
struct StoragePersistence {
    encryption_key: zeroize::Zeroizing<[u8; 32]>,
    cookies_path: std::path::PathBuf,
    local_storage_path: std::path::PathBuf,
    indexed_db_path: std::path::PathBuf,
}

/// A handle to ONE sandboxed renderer child process (there can be
/// several now — see `RendererPool` — one per distinct site any open
/// tab is showing): its stdin/stdout pipes, framed with
/// `ipc::{read_message, write_message}`. Owns the `Child` itself so it
/// can be killed cleanly (see `Drop`) and respawned if the pipe ever
/// breaks (a crash, or the sandbox killing it for a denied operation)
/// — one respawn-and-retry per `render` call, so a single bad page
/// can't permanently break navigation for the rest of the session.
struct RendererProcess {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    stdout: std::io::BufReader<std::process::ChildStdout>,
    cache_dir: std::path::PathBuf,
    storage_persistence: StoragePersistence,
    /// Whether this is the ONE dedicated, permanently-isolated `file://`
    /// process (see `LOCAL_FILES_SITE` and `site_for_url`) -- passed
    /// through to `abyssal-renderer` as `--allow-local-files` on every
    /// spawn, including a respawn after a pipe failure
    /// (`send_with_respawn`), so that a crash-and-restart of this one
    /// process can never silently downgrade it into an ordinary,
    /// network-enabled renderer, and so an ordinary site's process can
    /// never accidentally come back up WITH local file access after a
    /// respawn of its own.
    local_file_access: bool,
    /// Whether this specific child process has already been seeded
    /// with its cookies/`localStorage`/IndexedDB from disk (see
    /// `render`'s own doc comment) — starts `false` for every
    /// freshly-spawned process, including one `send_with_respawn`
    /// itself creates after a pipe failure, which is exactly correct:
    /// a genuinely fresh child process really does start with empty
    /// in-memory stores and genuinely does need seeding again.
    seeded: bool,
}

impl RendererProcess {
    fn spawn(
        cache_dir: &std::path::Path,
        storage_persistence: StoragePersistence,
        local_file_access: bool,
    ) -> std::io::Result<Self> {
        let mut command = std::process::Command::new(renderer_binary_path());
        command.arg(cache_dir);
        if local_file_access {
            command.arg("--allow-local-files");
        }
        let mut child = command
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            // Inherited (not piped/suppressed): the renderer's own
            // sandbox-status line and per-fetch error logging stay
            // visible in the terminal, same as before this process
            // split existed.
            .stderr(std::process::Stdio::inherit())
            .spawn()?;
        let stdin = child.stdin.take().expect("spawned with piped stdin");
        let stdout =
            std::io::BufReader::new(child.stdout.take().expect("spawned with piped stdout"));
        Ok(RendererProcess {
            child,
            stdin,
            stdout,
            cache_dir: cache_dir.to_path_buf(),
            storage_persistence,
            local_file_access,
            seeded: false,
        })
    }

    /// Sends a `Navigate` for `tab_id` and returns either the rendered
    /// page or a human-readable error. See `send_with_respawn` for the
    /// pipe-failure/respawn-and-retry behavior this builds on.
    ///
    /// On this process's very first `Navigate` (`!self.seeded`), reads
    /// and decrypts whatever's currently on disk and attaches it to
    /// `request` as `initial_cookies`/`initial_local_storage`/
    /// `initial_indexed_db` — see those fields' own doc comments on
    /// `ipc::RenderRequest`. Every LATER navigate on this same (already
    /// warm) process leaves them `None`: the renderer already has this
    /// state in memory by then. `self.seeded` is set unconditionally
    /// here, before the message is even sent, deliberately: if
    /// `send_with_respawn` ends up respawning the child on a pipe
    /// failure, it resends this SAME already-seeded `request` to the
    /// fresh child, which is exactly the seed data that fresh child
    /// actually needs — a second seeding attempt from THIS call would
    /// be redundant, not incorrect, but there's no reason to re-read
    /// and re-decrypt three files for it.
    fn render(
        &mut self,
        tab_id: ipc::TabId,
        mut request: ipc::RenderRequest,
    ) -> Result<ipc::RenderSuccess, String> {
        if !self.seeded {
            let sp = &self.storage_persistence;
            request.initial_cookies = load_encrypted_storage(&sp.cookies_path, &sp.encryption_key);
            request.initial_local_storage =
                load_encrypted_storage(&sp.local_storage_path, &sp.encryption_key);
            request.initial_indexed_db =
                load_encrypted_storage(&sp.indexed_db_path, &sp.encryption_key);
            self.seeded = true;
        }
        let message = ipc::ClientMessage {
            tab_id,
            kind: ipc::ClientMessageKind::Navigate(request),
        };
        let response = self.send_with_respawn(&message)?;
        Self::expect_render_outcome(response)
    }

    /// Sends `ClientMessageKind::Click` for `tab_id`/`dom_node_id` —
    /// "run any `click` listeners registered on this DOM node" — and
    /// hands back whichever `ServerMessageKind` came back, unexamined
    /// (see `Browser::handle_click`, this call's only caller, for how
    /// each variant is applied: `Rendered`, or `Unchanged` for the
    /// expected "node id didn't resolve" race — see
    /// `ipc::ClientMessageKind::Click`'s doc comment). DOES
    /// respawn-and-retry on a pipe failure, the same as `render` (see
    /// `send_with_respawn`) and UNLIKE `tick`: a click is always a
    /// direct, foreground user action, not a background wake-up nobody
    /// may even be watching, so silently swallowing a dead renderer
    /// here would make a real click just do nothing with no
    /// explanation. If even a respawn can't recover the pipe, this
    /// falls back to `Unchanged` (treating the click as a no-op) rather
    /// than surfacing a full navigation-style error page for what's
    /// usually a much less disruptive failure than a failed page load.
    fn click(&mut self, tab_id: ipc::TabId, dom_node_id: dom::NodeId) -> ipc::ServerMessageKind {
        self.send_foreground_action(tab_id, ipc::ClientMessageKind::Click { dom_node_id })
    }

    /// Sends `ClientMessageKind::Focus` — "give this text-editable
    /// `<input>` focus, with its cursor placed under `click_x`" — see
    /// that variant's own doc comment. Same respawn/fallback contract
    /// as `click` (see `send_foreground_action`): a click resolving to
    /// a text input is just as much a direct foreground user action as
    /// an ordinary click.
    fn focus(
        &mut self,
        tab_id: ipc::TabId,
        dom_node_id: dom::NodeId,
        click_x: f32,
    ) -> ipc::ServerMessageKind {
        self.send_foreground_action(
            tab_id,
            ipc::ClientMessageKind::Focus {
                dom_node_id,
                click_x,
            },
        )
    }

    /// Sends `ClientMessageKind::Blur` — see that variant's own doc
    /// comment. Same respawn/fallback contract as `click`.
    fn blur(&mut self, tab_id: ipc::TabId) -> ipc::ServerMessageKind {
        self.send_foreground_action(tab_id, ipc::ClientMessageKind::Blur)
    }

    /// Sends `ClientMessageKind::TextInput` — one keystroke directed at
    /// whatever text input currently has focus. Same respawn/fallback
    /// contract as `click`.
    fn text_input(
        &mut self,
        tab_id: ipc::TabId,
        action: ipc::TextInputAction,
    ) -> ipc::ServerMessageKind {
        self.send_foreground_action(tab_id, ipc::ClientMessageKind::TextInput(action))
    }

    /// Shared by `click`/`focus`/`blur`/`text_input`: sends `kind` for
    /// `tab_id` and hands back whichever `ServerMessageKind` came back,
    /// unexamined — each caller's own doc comment covers how its
    /// specific variants get applied. DOES respawn-and-retry on a pipe
    /// failure, the same as `render` (see `send_with_respawn`) and
    /// UNLIKE `tick`: every one of these is always a direct, foreground
    /// user action, not a background wake-up nobody may even be
    /// watching, so silently swallowing a dead renderer here would make
    /// the action just do nothing with no explanation. If even a
    /// respawn can't recover the pipe, this falls back to `Unchanged`
    /// (treating the action as a no-op) rather than surfacing a full
    /// navigation-style error page for what's usually a much less
    /// disruptive failure than a failed page load.
    fn send_foreground_action(
        &mut self,
        tab_id: ipc::TabId,
        kind: ipc::ClientMessageKind,
    ) -> ipc::ServerMessageKind {
        let message = ipc::ClientMessage { tab_id, kind };
        match self.send_with_respawn(&message) {
            Ok(response) => response.kind,
            Err(e) => {
                eprintln!("Renderer unavailable even after respawning ({e}) — treating this action as a no-op.");
                ipc::ServerMessageKind::Unchanged {
                    next_wake_in_millis: None,
                }
            }
        }
    }

    /// The shared "send, and on a pipe failure kill+respawn the child
    /// and retry exactly once" logic `render` and `click` both need —
    /// pulled out so the two don't drift: a pipe failure (the renderer
    /// crashed, or its sandbox killed it) always gets the SAME one
    /// retry, regardless of which kind of message triggered it. A
    /// respawn loses every tab's session state in the renderer (see
    /// `renderer::RendererState`'s doc comment) — this call doesn't
    /// attempt to re-establish anything beyond the one message it was
    /// asked to send.
    fn send_with_respawn(
        &mut self,
        message: &ipc::ClientMessage,
    ) -> Result<ipc::ServerMessage, String> {
        match self.try_send(message) {
            Ok(response) => return Ok(response),
            Err(io_err) => {
                eprintln!("Renderer process communication failed ({io_err}) — respawning and retrying once.");
            }
        }

        let _ = self.child.kill();
        let _ = self.child.wait();
        match Self::spawn(
            &self.cache_dir,
            self.storage_persistence.clone(),
            self.local_file_access,
        ) {
            Ok(fresh) => {
                *self = fresh;
                self.try_send(message)
                    .map_err(|e| format!("renderer unavailable even after respawning: {e}"))
            }
            Err(e) => Err(format!("failed to respawn the renderer process: {e}")),
        }
    }

    /// Tells the renderer this tab is gone, so it can drop that tab's
    /// session state (see `ipc::ClientMessageKind::CloseTab`). Doesn't
    /// respawn-and-retry on a pipe failure the way `render` does — if
    /// the renderer is already unreachable, the state `app` was trying
    /// to have it drop is already gone with it, and the next `render`
    /// call will discover (and recover from) the same failure anyway.
    fn close_tab(&mut self, tab_id: ipc::TabId) {
        let message = ipc::ClientMessage {
            tab_id,
            kind: ipc::ClientMessageKind::CloseTab,
        };
        if let Err(e) = self.try_send(&message) {
            eprintln!("Failed to notify the renderer that tab {tab_id:?} closed (harmless if it's already gone): {e}");
        }
    }

    /// `Ok` means the IPC round-trip itself succeeded and returns
    /// whatever `ServerMessage` came back — callers decide what shape
    /// they expected. `Err` means the PIPE failed (broken pipe, EOF,
    /// malformed framing), which is what `render` treats as "go
    /// respawn".
    ///
    /// This is the ONE place every single message this process ever
    /// sends a renderer (`render`, `click`, `tick`, `check_for_update`,
    /// every other method below) actually crosses the pipe, which
    /// makes it the natural place to persist `ServerMessage`'s
    /// `updated_cookies`/`updated_local_storage`/`updated_indexed_db`
    /// fields (see that struct's own doc comment) — real, encrypted
    /// disk writes, transparent to every caller above this method,
    /// the same way `renderer::RendererState`'s own `handle_message`
    /// used to do this internally before that responsibility moved
    /// here.
    fn try_send(&mut self, message: &ipc::ClientMessage) -> std::io::Result<ipc::ServerMessage> {
        ipc::write_message(&mut self.stdin, message)?;
        let response: ipc::ServerMessage = ipc::read_message(&mut self.stdout)?;
        self.persist_reported_storage(&response);
        Ok(response)
    }

    /// Encrypts and merges whichever of `response`'s `updated_*` fields
    /// are `Some` into the matching `.enc` file on disk — see
    /// `persist_encrypted_merge`'s own doc comment for the actual
    /// encrypt/merge/write mechanics. A no-op (no disk I/O at all) for
    /// the overwhelming majority of replies, which report no change to
    /// any of the three.
    fn persist_reported_storage(&self, response: &ipc::ServerMessage) {
        let sp = &self.storage_persistence;
        if let Some(bytes) = &response.updated_cookies {
            persist_encrypted_merge(
                &sp.cookies_path,
                &sp.encryption_key,
                bytes,
                &["top_level_site", "resource_host"],
            );
        }
        if let Some(bytes) = &response.updated_local_storage {
            persist_encrypted_merge(
                &sp.local_storage_path,
                &sp.encryption_key,
                bytes,
                &["origin"],
            );
        }
        if let Some(bytes) = &response.updated_indexed_db {
            persist_encrypted_merge(&sp.indexed_db_path, &sp.encryption_key, bytes, &["origin"]);
        }
    }

    /// Narrows a `ServerMessage` down to what `render` specifically
    /// expects (`Rendered`/`Error`) — a `Closed` or `Unchanged` reply
    /// here would mean the renderer and `app` have disagreed about
    /// which message this answers, which should never happen given the
    /// strict lockstep `ipc`'s module docs describe, but is reported as
    /// an error rather than panicking if it somehow did.
    fn expect_render_outcome(response: ipc::ServerMessage) -> Result<ipc::RenderSuccess, String> {
        match response.kind {
            ipc::ServerMessageKind::Rendered(success) => Ok(success),
            ipc::ServerMessageKind::Error(message) => Err(message),
            ipc::ServerMessageKind::Closed => Err(
                "renderer protocol error: got a Closed acknowledgement in reply to a Navigate"
                    .to_string(),
            ),
            ipc::ServerMessageKind::Unchanged { .. } => {
                Err("renderer protocol error: got an Unchanged reply to a Navigate".to_string())
            }
            ipc::ServerMessageKind::UpdateCheckResult(_) => Err(
                "renderer protocol error: got an UpdateCheckResult reply to a Navigate".to_string(),
            ),
            ipc::ServerMessageKind::DownloadResult(_) => {
                Err("renderer protocol error: got a DownloadResult reply to a Navigate".to_string())
            }
            ipc::ServerMessageKind::AudioPcmResult(_) => Err(
                "renderer protocol error: got an AudioPcmResult reply to a Navigate".to_string(),
            ),
            ipc::ServerMessageKind::DomSnapshotResult(_) => Err(
                "renderer protocol error: got a DomSnapshotResult reply to a Navigate".to_string(),
            ),
        }
    }

    /// Sends `ClientMessageKind::Tick` for `tab_id` — "has anything
    /// this tab's `setTimeout`s scheduled come due yet?" — and hands
    /// back whichever `ServerMessageKind` came back, unexamined (see
    /// `Browser::handle_tick`, its only caller, for how each variant is
    /// applied). Deliberately does NOT respawn-and-retry on a pipe
    /// failure the way `render` does: a `Tick` fires in the background,
    /// often for a tab the user isn't even looking at, so silently
    /// treating a dead renderer as "nothing happened this time" (rather
    /// than tearing down and reconnecting mid-background-timer) is the
    /// right failure mode here — the next real `render` call (a user
    /// action) will discover and recover from the same failure anyway.
    fn tick(&mut self, tab_id: ipc::TabId) -> ipc::ServerMessageKind {
        let message = ipc::ClientMessage {
            tab_id,
            kind: ipc::ClientMessageKind::Tick,
        };
        match self.try_send(&message) {
            Ok(response) => response.kind,
            Err(e) => {
                eprintln!(
                    "Renderer process communication failed during a background Tick for {tab_id:?} ({e}) — \
                     treating as unchanged rather than respawning for a timer nobody may even be watching."
                );
                ipc::ServerMessageKind::Unchanged {
                    next_wake_in_millis: None,
                }
            }
        }
    }

    /// Sends `ClientMessageKind::CheckForUpdate` — "is there a newer
    /// release than `current_version`?" (see that variant's own doc
    /// comment on why this goes through the sandboxed renderer rather
    /// than `app` fetching it directly). Not scoped to any real tab, so
    /// the `TabId` here is a fixed placeholder the renderer ignores
    /// entirely — see `renderer::RendererState::handle_message`'s
    /// `CheckForUpdate` arm. Like `tick`, deliberately does NOT respawn-
    /// and-retry on a pipe failure: a failed background check just
    /// means "find out on the next scheduled check" (see
    /// `Browser::maybe_check_for_update`), not something worth tearing
    /// down and reconnecting a process over.
    fn check_for_update(&mut self, current_version: &str) -> Option<ipc::UpdateCheckOutcome> {
        let message = ipc::ClientMessage {
            tab_id: ipc::TabId(u64::MAX),
            kind: ipc::ClientMessageKind::CheckForUpdate {
                current_version: current_version.to_string(),
            },
        };
        match self.try_send(&message) {
            Ok(response) => match response.kind {
                ipc::ServerMessageKind::UpdateCheckResult(outcome) => Some(outcome),
                _ => {
                    eprintln!(
                        "renderer protocol error: got an unexpected reply kind to CheckForUpdate"
                    );
                    None
                }
            },
            Err(e) => {
                eprintln!(
                    "Renderer process communication failed during a background update check ({e}) — \
                     will retry on the next scheduled check."
                );
                None
            }
        }
    }

    /// Sends `ClientMessageKind::Download` for `tab_id` — see that
    /// variant's doc comment. Unlike `tick`/`check_for_update`, DOES
    /// respawn-and-retry on a pipe failure (see `send_with_respawn`):
    /// a download is a deliberate, user-initiated action (the user
    /// clicked a link), the same category `render`'s own respawn
    /// behavior already exists for, not a background operation where
    /// silently giving up until next time is the right call.
    fn download(
        &mut self,
        tab_id: ipc::TabId,
        url: &str,
        top_level_host: Option<String>,
    ) -> Option<ipc::DownloadOutcome> {
        let message = ipc::ClientMessage {
            tab_id,
            kind: ipc::ClientMessageKind::Download {
                url: url.to_string(),
                top_level_host,
            },
        };
        match self.send_with_respawn(&message) {
            Ok(response) => match response.kind {
                ipc::ServerMessageKind::DownloadResult(outcome) => Some(outcome),
                _ => {
                    eprintln!("renderer protocol error: got an unexpected reply kind to Download");
                    None
                }
            },
            Err(e) => {
                eprintln!("Download failed for {url}: renderer unavailable ({e})");
                None
            }
        }
    }

    /// Sends `ClientMessageKind::FetchAudioPcm` for `tab_id` — see that
    /// variant's doc comment. Like `download`, DOES respawn-and-retry:
    /// this only ever runs in direct response to the user clicking a
    /// media element's play button.
    fn fetch_audio_pcm(
        &mut self,
        tab_id: ipc::TabId,
        dom_node_id: dom::NodeId,
    ) -> Option<ipc::AudioPcmOutcome> {
        let message = ipc::ClientMessage {
            tab_id,
            kind: ipc::ClientMessageKind::FetchAudioPcm { dom_node_id },
        };
        match self.send_with_respawn(&message) {
            Ok(response) => match response.kind {
                ipc::ServerMessageKind::AudioPcmResult(outcome) => Some(outcome),
                _ => {
                    eprintln!(
                        "renderer protocol error: got an unexpected reply kind to FetchAudioPcm"
                    );
                    None
                }
            },
            Err(e) => {
                eprintln!("Fetching decoded audio failed: renderer unavailable ({e})");
                None
            }
        }
    }

    /// Sends `ClientMessageKind::UpdateMediaPlayback` for `tab_id` —
    /// see that variant's doc comment. Like `tick`, deliberately does
    /// NOT respawn-and-retry on a pipe failure: this fires on every
    /// periodic progress tick while something is playing in the
    /// background, so silently treating a dead renderer as "no visible
    /// change this time" (rather than tearing down and reconnecting
    /// mid-playback) is the right failure mode — the next real user
    /// action (a click) will discover and recover from the same
    /// failure anyway.
    fn update_media_playback(
        &mut self,
        tab_id: ipc::TabId,
        dom_node_id: dom::NodeId,
        playing: bool,
        muted: bool,
        current_time_secs: f32,
    ) -> ipc::ServerMessageKind {
        let message = ipc::ClientMessage {
            tab_id,
            kind: ipc::ClientMessageKind::UpdateMediaPlayback {
                dom_node_id,
                playing,
                muted,
                current_time_secs,
            },
        };
        match self.try_send(&message) {
            Ok(response) => response.kind,
            Err(e) => {
                eprintln!(
                    "Renderer process communication failed during a background media playback update ({e}) — \
                     treating as unchanged rather than respawning for playback nobody may even be watching."
                );
                ipc::ServerMessageKind::Unchanged {
                    next_wake_in_millis: None,
                }
            }
        }
    }

    /// Sends `ClientMessageKind::EvalConsoleExpression` for `tab_id` —
    /// see that variant's own doc comment. Like `click`/`download`,
    /// DOES respawn-and-retry: this only ever runs in direct response
    /// to the user pressing Enter in the DevTools console's REPL input,
    /// same "a direct foreground action deserves one recovery attempt"
    /// reasoning as every other user-triggered send in this `impl`.
    fn eval_console_expression(
        &mut self,
        tab_id: ipc::TabId,
        code: &str,
    ) -> ipc::ServerMessageKind {
        self.send_foreground_action(
            tab_id,
            ipc::ClientMessageKind::EvalConsoleExpression {
                code: code.to_string(),
            },
        )
    }

    /// Sends `ClientMessageKind::FetchDomSnapshot` for `tab_id` — see
    /// that variant's own doc comment. DOES respawn-and-retry, same
    /// reasoning as `fetch_audio_pcm`: only ever sent in direct
    /// response to opening/refreshing the DevTools Elements panel.
    fn fetch_dom_snapshot(&mut self, tab_id: ipc::TabId) -> Option<ipc::DomSnapshotOutcome> {
        let message = ipc::ClientMessage {
            tab_id,
            kind: ipc::ClientMessageKind::FetchDomSnapshot,
        };
        match self.send_with_respawn(&message) {
            Ok(response) => match response.kind {
                ipc::ServerMessageKind::DomSnapshotResult(outcome) => Some(outcome),
                _ => {
                    eprintln!(
                        "renderer protocol error: got an unexpected reply kind to FetchDomSnapshot"
                    );
                    None
                }
            },
            Err(e) => {
                eprintln!("Fetching a DOM snapshot failed: renderer unavailable ({e})");
                None
            }
        }
    }

    /// Sends `ClientMessageKind::MoveKeyboardFocus` for `tab_id` — see
    /// that variant's own doc comment. Like `click`, DOES respawn-and-
    /// retry: `Tab`/`Shift+Tab` is a direct, deliberate foreground user
    /// action, not a background wake-up nobody may even be watching.
    fn move_keyboard_focus(
        &mut self,
        tab_id: ipc::TabId,
        direction: ipc::FocusDirection,
    ) -> ipc::ServerMessageKind {
        self.send_foreground_action(
            tab_id,
            ipc::ClientMessageKind::MoveKeyboardFocus { direction },
        )
    }

    /// Sends `ClientMessageKind::ActivateFocused` for `tab_id` — see
    /// that variant's own doc comment. Same respawn/fallback contract
    /// as `click` (`Enter`/`Space` activating whatever has keyboard
    /// focus is just as much a direct foreground action).
    fn activate_focused(&mut self, tab_id: ipc::TabId) -> ipc::ServerMessageKind {
        self.send_foreground_action(tab_id, ipc::ClientMessageKind::ActivateFocused)
    }

    /// Sends `ClientMessageKind::FocusNode` for `tab_id` — see that
    /// variant's own doc comment. Same respawn/fallback contract as
    /// `click`: a real assistive technology requesting focus on a
    /// specific element is just as much a direct foreground action.
    fn focus_node(
        &mut self,
        tab_id: ipc::TabId,
        dom_node_id: dom::NodeId,
    ) -> ipc::ServerMessageKind {
        self.send_foreground_action(tab_id, ipc::ClientMessageKind::FocusNode { dom_node_id })
    }
}

impl Drop for RendererProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// **Site isolation**: a pool of `RendererProcess`es keyed by site
/// (`privacy::registrable_domain` of a page's host — the SAME eTLD+1
/// notion that already governs storage partitioning and third-party
/// classification, reused here for process isolation), rather than the
/// single shared renderer process this replaced. Two tabs showing
/// DIFFERENT sites now genuinely never share a process — a
/// memory-safety bug triggered by a malicious page in one process
/// can't read another open tab's DOM, cookies, or script state,
/// something a single shared renderer (still sandboxed from `app`
/// itself, but not from OTHER tabs) could never promise. Tabs on the
/// SAME site still share one process — real browsers do this too
/// (there's no isolation BENEFIT to splitting same-site tabs apart,
/// only memory/process overhead), and it's a natural fit for how
/// `renderer::RendererState` already multiplexes tabs by `ipc::TabId`
/// within one process.
///
/// A process is spawned lazily, the first time some tab actually needs
/// that site (`get_or_spawn`), and killed once no tab references it
/// any more (`evict_unreferenced`, called by `Browser` after any
/// operation that could orphan one: navigating a tab away, closing a
/// tab, or a tab leaving to an `about:` page) — a site's process
/// exists for exactly as long as some open tab is actually showing it,
/// not for the rest of the session.
///
/// Doesn't (yet) isolate the DISK cache directory per site — every
/// process still shares the one `cache_dir` passed to `spawn`. That's
/// fine for now: `network::disk_cache` already partitions entries by
/// top-level site internally (see that module's docs), and Landlock
/// already restricts each process to read/write only within that
/// shared directory (see `renderer::sandbox`) — a compromised
/// process could in principle read another site's CACHED response
/// bytes off disk (already-public web content, not secrets) even
/// though it can no longer read another site's LIVE session state in
/// memory. Real per-process cache subdirectories would close even that
/// gap; not done here because the in-memory isolation is the property
/// that actually matters (cookies, DOM, script state) and the disk
/// cache holds no secrets to begin with.
struct RendererPool {
    processes: std::collections::HashMap<String, RendererProcess>,
    cache_dir: std::path::PathBuf,
    /// Cloned into every `RendererProcess` this pool spawns — see
    /// `StoragePersistence`'s own doc comment.
    storage_persistence: StoragePersistence,
}

impl RendererPool {
    fn new(cache_dir: std::path::PathBuf, storage_persistence: StoragePersistence) -> Self {
        RendererPool {
            processes: std::collections::HashMap::new(),
            cache_dir,
            storage_persistence,
        }
    }

    /// A clone of this pool's own `StoragePersistence` — for the ONE
    /// other place outside this pool that also spawns a real
    /// `RendererProcess` (`Browser::maybe_check_for_update`'s dedicated
    /// process), so both use the exact same encryption key and file
    /// paths rather than each computing their own.
    fn storage_persistence(&self) -> StoragePersistence {
        self.storage_persistence.clone()
    }

    /// Returns the process for `site`, spawning a fresh one first if
    /// this is the first tab to ever need it. `Err` only if spawning a
    /// genuinely NEW process failed — an already-running site's
    /// process is always returned successfully here regardless of its
    /// own health (a dead pipe is `RendererProcess::render`/`click`'s
    /// own respawn-and-retry logic to discover and recover from, not
    /// this method's).
    fn get_or_spawn(&mut self, site: &str) -> Result<&mut RendererProcess, String> {
        if !self.processes.contains_key(site) {
            // `site == LOCAL_FILES_SITE` is the ONLY thing that ever
            // grants a process local file access — see that constant's
            // own doc comment for why routing every `file://` URL to
            // this one fixed, dedicated site key (rather than, say, the
            // literal path) is itself the isolation mechanism: no real
            // website's site key can ever equal it, so no real site's
            // process is ever spawned with this flag set.
            let local_file_access = site == LOCAL_FILES_SITE;
            let process = RendererProcess::spawn(
                &self.cache_dir,
                self.storage_persistence.clone(),
                local_file_access,
            )
            .map_err(|e| format!("failed to spawn a renderer process for site {site:?}: {e}"))?;
            self.processes.insert(site.to_string(), process);
        }
        Ok(self
            .processes
            .get_mut(site)
            .expect("just spawned or already present"))
    }

    /// Returns the process for `site` ONLY if one already exists —
    /// used by callers (`Tick`/`Click`/`CloseTab` routing) that are
    /// naming a site a tab's OWN `renderer_site` field already claims
    /// to have a live session on; if that's somehow wrong (the process
    /// crashed and got evicted out from under it — shouldn't happen,
    /// see this struct's own doc comment on when eviction runs, but
    /// isn't a protocol error if it somehow did), `None` here is the
    /// caller's signal to treat it as a harmless miss rather than
    /// spawning a brand new process just to immediately `CloseTab` it.
    fn get(&mut self, site: &str) -> Option<&mut RendererProcess> {
        self.processes.get_mut(site)
    }

    /// Kills and drops every process no tab in `referenced` names —
    /// see this struct's own doc comment on why a site's process
    /// shouldn't outlive every tab that was showing it.
    fn evict_unreferenced(&mut self, referenced: &std::collections::HashSet<String>) {
        self.processes.retain(|site, _| referenced.contains(site));
    }

    #[cfg(test)]
    fn open_site_count(&self) -> usize {
        self.processes.len()
    }
}

/// The fixed `RendererPool` site key EVERY `file://` URL routes to,
/// regardless of which path it names — `site_for_url` never returns the
/// real path as the site key the way it would fall through to for some
/// other unparseable-host URL. That's deliberate, not an approximation:
/// this key is what makes "one dedicated, permanently-isolated
/// `file://` process" real rather than aspirational. Two tabs open on
/// two different local files still share this ONE process (mirroring
/// how two tabs on the same real site already share one process) —
/// there is no isolation benefit to splitting them apart, and doing so
/// would just mean more copies of the one process that gets broad
/// filesystem read access.
///
/// Deliberately not a value any real `privacy::registrable_domain`
/// output or unparseable-URL fallback string could ever collide with:
/// a registrable domain is always `label.tld`-shaped (no `:`, no
/// `/`), and this contains both.
const LOCAL_FILES_SITE: &str = "file://";

/// The `privacy::registrable_domain` of `url`'s host — the "site" a
/// tab showing `url` belongs to for `RendererPool` purposes. Falls
/// back to the whole URL string (a harmless, just-never-deduplicated
/// bucket of its own) for a URL with no parseable host at all — a page
/// that can't even be parsed into a host can't be fetched either, so
/// this never actually has to spawn a real process for that bucket in
/// practice; `RendererProcess::render`'s own fetch failure is what
/// actually surfaces to the user.
///
/// `file://` URLs are handled before any of that: they have no `host`
/// component at all (`file:///home/user/foo.html` -- three slashes, no
/// authority), so without this explicit check they'd each fall through
/// to the "whole URL string" fallback above and every distinct local
/// file would get its OWN renderer process — defeating the entire
/// point of routing them all to one dedicated, isolated process (see
/// `LOCAL_FILES_SITE`'s own doc comment). Checked by scheme, not by
/// trying and failing to find a host, so it can never be confused with
/// a genuinely host-less non-file URL.
fn site_for_url(url: &str) -> String {
    let Ok(parsed) = url::Url::parse(url) else {
        return url.to_string();
    };
    if parsed.scheme() == "file" {
        return LOCAL_FILES_SITE.to_string();
    }
    parsed
        .host_str()
        .map(privacy::registrable_domain)
        .unwrap_or_else(|| url.to_string())
}

/// Owns everything about the browser window: the tabs, and everything
/// that must stay SINGULAR across all of them — the account, synced
/// bookmarks/settings, the renderer process POOL (see `RendererPool` —
/// singular as in "one pool," not "one process"; each SITE still gets
/// its own), theme/fingerprint-resistance/WebRTC preferences, and the
/// window's own size.
/// Duplicating any of THIS per-tab (the naive reading of "each tab is
/// its own little browser") would be a real correctness bug, not just
/// wasted memory: bookmark a page in one tab, and a second tab's
/// independent copy of `bookmarks` wouldn't know about it, or worse,
/// could overwrite it on its own next save. `render::window::run_window`
/// knows none of this — it just calls `handle_event` and displays
/// whatever `Frame` comes back (see render/src/window.rs's module docs
/// for that boundary).
struct Browser {
    /// The pool of sandboxed child processes that do the actual
    /// fetch+parse+layout of any real (network) page — one per
    /// distinct site any open tab is showing (see `RendererPool`'s own
    /// doc comment for why: site isolation).
    renderers: RendererPool,
    theme: css::Theme,
    /// Cached alongside `theme`/`webrtc_access` rather than re-read from
    /// `bookmarks.settings` on every use — all three are set from
    /// settings at startup (see `Browser::new`) and kept in sync by
    /// `apply_setting`, the only place that ever changes them.
    fingerprint_resistance: privacy::FingerprintResistanceLevel,
    webrtc_access: privacy::ApiAccess,
    font: text::Font,
    background: render::Color,

    tabs: Vec<Tab>,
    /// Index into `tabs` — always valid (`close_tab` keeps it in
    /// bounds, and `tabs` is never empty; see `close_tab`'s doc comment
    /// for why closing the last tab is a no-op rather than emptying it).
    active_tab_index: usize,
    /// Feeds `allocate_tab_id` — a plain incrementing counter, never
    /// reused even after a tab closes, so a `TabId` is never handed out
    /// twice in one session (see `ipc::TabId`'s doc comment for why the
    /// renderer needs identities that don't get reused, only reordered
    /// `Vec` positions do).
    next_tab_id: u64,

    canvas_width: u32,
    canvas_height: u32,

    account: account::Account,
    bookmarks: storage::SyncPayload,
    sync_version: u64,

    /// Every file downloaded so far this browser has ever seen (see
    /// `DownloadRecord`'s own doc comment for why this is a SEPARATE,
    /// unsynced, locally-encrypted file rather than living in
    /// `bookmarks` alongside history/settings) — backs the
    /// `about:downloads` page.
    downloads: Vec<DownloadRecord>,
    /// Where `Browser::download` saves files — resolved ONCE at
    /// construction (see `new`/`new_with_data_dir`), not recomputed
    /// per download, so tests get a stable, isolated directory instead
    /// of every download re-deriving the REAL OS Downloads folder.
    downloads_dir: std::path::PathBuf,

    /// Where `Browser::navigate_without_history` looks for real,
    /// locally-installed userscripts (see `userscripts`'s own module
    /// docs) — always `data_dir.join("userscripts")`, re-read from
    /// disk on every navigation rather than cached (see that module's
    /// doc comment on why). A missing directory (no userscripts
    /// installed) is the common case and never an error.
    userscripts_dir: std::path::PathBuf,

    /// Base directory for this browser's on-disk state: `account.txt`,
    /// `bookmarks.enc`, and the `cache/` subdirectory (an unencrypted
    /// on-disk HTTP response cache — see
    /// `network::FilteringFetcher::enable_disk_cache` — the renderer
    /// pool is granted read/write access to, see `renderer::sandbox`;
    /// clearing it isn't wired to any UI yet, so for now the only way
    /// is to delete the directory manually). Real usage always gets
    /// `real_data_dir()`'s OS-standard location (see `new`); tests use
    /// their own isolated temp directory instead (see `new_with_data_dir`
    /// and the test module's
    /// own `test_browser`) — sharing the real one across test runs
    /// would both pollute a real user's actual browsing history with
    /// test navigations and make history-count assertions flaky from
    /// run to run.
    data_dir: std::path::PathBuf,

    /// A dedicated sandboxed renderer process used ONLY for
    /// `maybe_check_for_update` — deliberately NOT one of `renderers`'
    /// per-site pool entries: `RendererPool::evict_unreferenced` kills
    /// any process no open tab's `renderer_site` currently names, which
    /// would tear this one down (and force a respawn on every single
    /// check) since it never corresponds to any tab at all. Spawned
    /// lazily on the first due check, then kept for the life of the
    /// session like any other long-lived resource here.
    update_checker_process: Option<RendererProcess>,
    /// When the next periodic "is a newer version out?" check is due —
    /// see `maybe_check_for_update`. `None` would mean "never check
    /// again," which nothing in this codebase currently sets; `Browser::new`
    /// arms the first one a few seconds out so it doesn't compete with
    /// initial startup, and every check reschedules the next one
    /// `UPDATE_CHECK_INTERVAL` later regardless of outcome.
    next_update_check_at: Option<std::time::Instant>,
}

/// How often `maybe_check_for_update` re-checks for a newer release.
/// Arbitrary but reasonable for a personal browser that isn't
/// restarted constantly: frequent enough to notice a new release
/// within about a day of it shipping, infrequent enough that it's
/// never a noticeable source of background network activity.
const UPDATE_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

/// How often `Browser::handle_media_progress_tick` refreshes a
/// playing media element's on-screen scrubber/time display. Frequent
/// enough that the progress bar looks live, infrequent enough that it
/// isn't a noticeable source of background IPC traffic — real audio
/// PLAYBACK itself is continuous regardless (driven by `cpal`'s own
/// real-time callback, not by this tick at all); this only governs how
/// often the UI catches up to it.
const MEDIA_PROGRESS_TICK_INTERVAL: std::time::Duration = std::time::Duration::from_millis(250);

impl Browser {
    /// Real entry point — uses `real_data_dir()` (a proper, OS-standard
    /// per-user location) as this browser's on-disk state, and the
    /// REAL OS downloads folder (`real_downloads_dir`) for saved
    /// files. See `new_with_data_dir_and_downloads_dir` for the actual
    /// constructor logic.
    fn new(initial_url: Option<&str>) -> Self {
        let data_dir = real_data_dir();
        let downloads_dir = real_downloads_dir(&data_dir);
        Self::new_with_data_dir_and_downloads_dir(initial_url, data_dir, downloads_dir)
    }

    /// Test entry point (see `test_browser`) — saved files go under
    /// `data_dir.join("downloads")` rather than `real_downloads_dir`'s
    /// real `$HOME`/`%USERPROFILE%`-resolved folder, so a test
    /// downloading something never writes into the machine's ACTUAL
    /// Downloads folder (which is very likely to exist and be
    /// writable on any real dev/CI machine, unlike the fallback
    /// `real_downloads_dir` only reaches for when that env var is
    /// entirely unset).
    #[cfg(test)]
    fn new_with_data_dir(initial_url: Option<&str>, data_dir: std::path::PathBuf) -> Self {
        let downloads_dir = data_dir.join("downloads");
        Self::new_with_data_dir_and_downloads_dir(initial_url, data_dir, downloads_dir)
    }

    fn new_with_data_dir_and_downloads_dir(
        initial_url: Option<&str>,
        data_dir: std::path::PathBuf,
        downloads_dir: std::path::PathBuf,
    ) -> Self {
        let account = load_or_create_account(&data_dir);
        let bookmarks = load_or_init_bookmarks(&account, &data_dir);
        let downloads = load_download_history(&account, &data_dir);
        // The renderer pool is this browser's ONLY path to the network
        // — there's no in-process fallback fetcher (see this file's
        // module docs for why: an in-process fallback would defeat the
        // whole point of sandboxing real fetches into a separate
        // process). Processes are spawned lazily, per site, as tabs
        // actually need them (see `RendererPool::get_or_spawn`) — but
        // the BINARY itself missing is checked eagerly here, still
        // fatal with the same actionable message as before, so a
        // packaging mistake surfaces at startup rather than on the
        // first real navigation.
        if !renderer_binary_path().is_file() {
            panic!(
                "the abyssal-renderer binary was not found at {:?}\n\
                 Build it with `cargo build --workspace` (or `cargo build -p renderer`) \
                 before running `abyssal`.",
                renderer_binary_path(),
            );
        }
        // Derived ONCE here, then cloned into every `RendererProcess`
        // this browser ever spawns (see `StoragePersistence`'s own doc
        // comment on why this can't just be re-derived per save the
        // way `save_bookmarks` still does).
        let storage_persistence = StoragePersistence {
            encryption_key: account::derive_key(&account.recovery_code, &account.kdf_salt),
            cookies_path: data_dir.join("cookies.enc"),
            local_storage_path: data_dir.join("local_storage.enc"),
            indexed_db_path: data_dir.join("indexed_db.enc"),
        };
        let renderers = RendererPool::new(data_dir.join("cache"), storage_persistence);
        let userscripts_dir = data_dir.join("userscripts");
        // Settings (theme/fingerprint-resistance/WebRTC) are read back
        // from the just-loaded `bookmarks.settings` here rather than
        // always starting from each type's own default — a choice made
        // in a previous session (or synced from another device) should
        // actually take effect on the next launch, not just live for
        // the session it was set in.
        let theme = bookmarks
            .settings
            .get(SETTING_THEME)
            .and_then(css::Theme::parse)
            .unwrap_or_default();
        let fingerprint_resistance = bookmarks
            .settings
            .get(SETTING_FINGERPRINT_RESISTANCE)
            .and_then(privacy::FingerprintResistanceLevel::parse)
            .unwrap_or_default();
        let webrtc_access = match bookmarks.settings.get(SETTING_WEBRTC) {
            Some("allowed") => privacy::ApiAccess::Restricted,
            _ => privacy::ApiAccess::Disabled,
        };
        let font = text::load_default_font();
        let background = render::parse_color(theme.background_hex()).unwrap_or(render::Color {
            r: 255,
            g: 255,
            b: 255,
            a: 255,
        });

        let mut browser = Browser {
            account,
            bookmarks,
            sync_version: 0,
            downloads,
            downloads_dir,
            userscripts_dir,
            renderers,
            theme,
            fingerprint_resistance,
            webrtc_access,
            font,
            background,
            // The first tab gets TabId(0) directly rather than via
            // `allocate_tab_id` (which needs `&mut self` on an already-
            // constructed `Browser`) — `next_tab_id: 1` below keeps
            // every id handed out from here on consistent with it.
            tabs: vec![Tab::blank(ipc::TabId(0))],
            active_tab_index: 0,
            next_tab_id: 1,
            canvas_width: 800,
            canvas_height: 600,
            data_dir,
            update_checker_process: None,
            // A few seconds out, not immediately — lets the window's
            // first real paint happen before this spawns its own
            // renderer process and makes a real network call.
            next_update_check_at: Some(
                std::time::Instant::now() + std::time::Duration::from_secs(5),
            ),
        };

        browser.sync_pull(); // best-effort; harmless if no server is running

        match initial_url {
            Some(url) => {
                println!("Fetching {url} (real DNS-over-HTTPS/TLS/HTTP)...");
                browser.navigate(url);
            }
            None => {
                println!(
                    "No URL given (usage: cargo run -p abyssal -- <url>) — \
                     showing the built-in demo page. Click its link to try real navigation."
                );
                browser.load_demo_page();
            }
        }
        browser
    }

    fn active_tab(&self) -> &Tab {
        &self.tabs[self.active_tab_index]
    }

    fn active_tab_mut(&mut self) -> &mut Tab {
        &mut self.tabs[self.active_tab_index]
    }

    /// Finds a tab by its stable `ipc::TabId` rather than its (possibly
    /// stale, possibly not the ACTIVE one) `Vec` position — used by the
    /// media-playback methods below, which have to work for a
    /// BACKGROUND tab's audio too (real browsers keep playing a
    /// background tab's audio, matching how `next_wake_at`/JS timers
    /// already work per-tab-id rather than only for the active tab).
    fn tab_mut(&mut self, tab_id: ipc::TabId) -> Option<&mut Tab> {
        self.tabs.iter_mut().find(|tab| tab.id == tab_id)
    }

    /// Hands out a fresh, never-reused `TabId` — see `Tab::id`'s doc
    /// comment for why this has to be independent of a tab's position
    /// in `self.tabs`.
    fn allocate_tab_id(&mut self) -> ipc::TabId {
        let id = ipc::TabId(self.next_tab_id);
        self.next_tab_id += 1;
        id
    }

    /// Opens a fresh tab showing the built-in demo page (matching what
    /// a bare `cargo run` with no URL shows) and makes it active —
    /// real browsers land a new tab somewhere useful rather than blank.
    fn open_new_tab(&mut self) {
        let id = self.allocate_tab_id();
        self.tabs.push(Tab::blank(id));
        self.active_tab_index = self.tabs.len() - 1;
        self.load_demo_page_without_history();
    }

    /// Closes the tab at `index`. Closing the LAST remaining tab is a
    /// no-op rather than closing the window — this app has no
    /// multi-window support, so a real browser's equivalent behavior
    /// (closing the whole window) has nowhere to go here. Tells the
    /// renderer to drop this tab's own session state (see
    /// `ipc::ClientMessageKind::CloseTab`'s doc comment) before it's
    /// forgotten here too.
    fn close_tab(&mut self, index: usize) {
        if self.tabs.len() <= 1 || index >= self.tabs.len() {
            return;
        }
        let closed_tab_id = self.tabs[index].id;
        let closed_site = self.tabs[index].renderer_site.clone();
        self.tabs.remove(index);
        if self.active_tab_index >= self.tabs.len() {
            self.active_tab_index = self.tabs.len() - 1;
        } else if self.active_tab_index > index {
            self.active_tab_index -= 1;
        }
        if let Some(site) = closed_site {
            if let Some(renderer) = self.renderers.get(&site) {
                renderer.close_tab(closed_tab_id);
            }
            // The closed tab may have been the LAST one showing this
            // site — see `RendererPool`'s doc comment on why that
            // process shouldn't keep running once nothing references it.
            self.evict_unreferenced_renderer_processes();
        }
    }

    /// Runs `RendererPool::evict_unreferenced` against the CURRENT set
    /// of sites any tab's `renderer_site` still names — call this after
    /// any operation that could have made a site's process
    /// unreferenced: navigating a tab away from it, closing a tab that
    /// was on it, or a tab leaving to a local `about:` page.
    fn evict_unreferenced_renderer_processes(&mut self) {
        let referenced: std::collections::HashSet<String> = self
            .tabs
            .iter()
            .filter_map(|tab| tab.renderer_site.clone())
            .collect();
        self.renderers.evict_unreferenced(&referenced);
    }

    /// Loads the built-in demo page directly (no fetch at all — not
    /// even through `FakeFetcher`, since there's no reason to pretend
    /// this is a network response). `current_url` becomes a
    /// non-navigable placeholder (`about:demo`) — clicking the
    /// demo's own link still works fine, since that goes through
    /// `navigate` with a real absolute URL, not through this method.
    fn load_demo_page(&mut self) {
        self.active_tab_mut().record_navigation_history();
        self.load_demo_page_without_history();
    }

    /// The three `about:` pages (demo, bookmarks, settings) never go
    /// through the renderer at all — they're built and laid out
    /// directly, in this process, from local HTML. If this tab was
    /// PREVIOUSLY showing a real fetched page, though, the renderer may
    /// still be holding that old page's `script::Session` (and a
    /// pending `setTimeout`) alive under this tab's id, since nothing
    /// told it otherwise — a real `Navigate` drops the old session as a
    /// side effect (see `renderer::RendererState::handle_message`), but
    /// these local loaders never send one. Without this, an old page's
    /// timer could keep firing in the background and this tab would
    /// keep waking up for it — harmless in that it can't affect what's
    /// now on screen (an `about:` page's `layout_tree` is never touched
    /// by a stray `Tick` reply), but a real resource leak and a
    /// pointless wake-up loop. Calling this from every `about:` loader
    /// closes that session out explicitly instead.
    fn leave_renderer_backed_page(&mut self) {
        if let Some(site) = self.active_tab().renderer_site.clone() {
            let tab_id = self.active_tab().id;
            if let Some(renderer) = self.renderers.get(&site) {
                renderer.close_tab(tab_id);
            }
            self.active_tab_mut().next_wake_at = None;
            self.active_tab_mut().renderer_site = None;
            // This tab may have been the LAST one on `site` — see
            // `RendererPool`'s doc comment on why that process
            // shouldn't keep running once nothing references it.
            self.evict_unreferenced_renderer_processes();
        }
    }

    fn load_demo_page_without_history(&mut self) {
        self.exit_find_mode();
        self.stop_all_media_playback();
        self.reset_devtools_page_state();
        self.leave_renderer_backed_page();
        let document = html::parse(DEMO_HTML);
        let stylesheet = css::user_agent_stylesheet(self.theme);
        self.active_tab_mut().layout_tree = layout::build_layout_tree(&document, &stylesheet);
        self.relayout();
        self.active_tab_mut().current_url = "about:demo".to_string();
        let url = self.active_tab().current_url.clone();
        self.active_tab_mut().set_address_bar_text(url);
        self.active_tab_mut().cached_title = extract_title(&document);
        self.active_tab_mut().scroll_y = 0.0;
    }

    /// Renders the current bookmarks as a real page — built from the
    /// same `html::parse` + `layout` pipeline as everything else, not a
    /// separate UI widget, so the existing click-to-navigate machinery
    /// works on it for free.
    fn load_bookmarks_page(&mut self) {
        self.active_tab_mut().record_navigation_history();
        self.load_bookmarks_page_without_history();
    }

    fn load_bookmarks_page_without_history(&mut self) {
        self.exit_find_mode();
        self.stop_all_media_playback();
        self.reset_devtools_page_state();
        self.leave_renderer_backed_page();
        let html = render_bookmarks_html(&self.bookmarks);
        let document = html::parse(&html);
        let stylesheet = css::user_agent_stylesheet(self.theme);
        self.active_tab_mut().layout_tree = layout::build_layout_tree(&document, &stylesheet);
        self.relayout();
        self.active_tab_mut().current_url = "about:bookmarks".to_string();
        let url = self.active_tab().current_url.clone();
        self.active_tab_mut().set_address_bar_text(url);
        self.active_tab_mut().cached_title = Some("Bookmarks".to_string());
        self.active_tab_mut().scroll_y = 0.0;
    }

    /// Renders the settings page — same "it's just an HTML page, not a
    /// separate widget toolkit" approach as bookmarks, which is what
    /// lets every option be a plain clickable link handled by the
    /// existing hit-testing/click machinery (see `handle_settings_link`)
    /// instead of needing real form controls this codebase has no
    /// support for rendering.
    fn load_settings_page(&mut self) {
        self.active_tab_mut().record_navigation_history();
        self.load_settings_page_without_history();
    }

    fn load_settings_page_without_history(&mut self) {
        self.exit_find_mode();
        self.stop_all_media_playback();
        self.reset_devtools_page_state();
        self.leave_renderer_backed_page();
        let html = render_settings_html(self);
        let document = html::parse(&html);
        let stylesheet = css::user_agent_stylesheet(self.theme);
        self.active_tab_mut().layout_tree = layout::build_layout_tree(&document, &stylesheet);
        self.relayout();
        self.active_tab_mut().current_url = "about:settings".to_string();
        let url = self.active_tab().current_url.clone();
        self.active_tab_mut().set_address_bar_text(url);
        self.active_tab_mut().cached_title = Some("Settings".to_string());
        self.active_tab_mut().scroll_y = 0.0;
    }

    /// Renders the account panel — same "it's just an HTML page" approach
    /// as bookmarks/settings/history (see `load_bookmarks_page`).
    /// `account:sync` (see `handle_click`'s href interception) is the
    /// one interactive element on it.
    fn load_account_page(&mut self) {
        self.active_tab_mut().record_navigation_history();
        self.load_account_page_without_history();
    }

    fn load_account_page_without_history(&mut self) {
        self.exit_find_mode();
        self.stop_all_media_playback();
        self.reset_devtools_page_state();
        self.leave_renderer_backed_page();
        let html = render_account_html(self);
        let document = html::parse(&html);
        let stylesheet = css::user_agent_stylesheet(self.theme);
        self.active_tab_mut().layout_tree = layout::build_layout_tree(&document, &stylesheet);
        self.relayout();
        self.active_tab_mut().current_url = "about:account".to_string();
        let url = self.active_tab().current_url.clone();
        self.active_tab_mut().set_address_bar_text(url);
        self.active_tab_mut().cached_title = Some("Account".to_string());
        self.active_tab_mut().scroll_y = 0.0;
    }

    /// Renders the visited-page history log as a real page — same "it's
    /// just an HTML page" approach as bookmarks/settings (see
    /// `load_bookmarks_page`), newest visit first. `history:clear` (see
    /// `handle_click`'s href interception) is the one interactive
    /// element on it.
    fn load_history_page(&mut self) {
        self.active_tab_mut().record_navigation_history();
        self.load_history_page_without_history();
    }

    fn load_history_page_without_history(&mut self) {
        self.exit_find_mode();
        self.stop_all_media_playback();
        self.reset_devtools_page_state();
        self.leave_renderer_backed_page();
        let html = render_history_html(&self.bookmarks);
        let document = html::parse(&html);
        let stylesheet = css::user_agent_stylesheet(self.theme);
        self.active_tab_mut().layout_tree = layout::build_layout_tree(&document, &stylesheet);
        self.relayout();
        self.active_tab_mut().current_url = "about:history".to_string();
        let url = self.active_tab().current_url.clone();
        self.active_tab_mut().set_address_bar_text(url);
        self.active_tab_mut().cached_title = Some("History".to_string());
        self.active_tab_mut().scroll_y = 0.0;
    }

    /// Renders the downloaded-files list as a real page — same
    /// pattern as bookmarks/settings/history.
    fn load_downloads_page(&mut self) {
        self.active_tab_mut().record_navigation_history();
        self.load_downloads_page_without_history();
    }

    fn load_downloads_page_without_history(&mut self) {
        self.exit_find_mode();
        self.stop_all_media_playback();
        self.reset_devtools_page_state();
        self.leave_renderer_backed_page();
        let html = render_downloads_html(&self.downloads);
        let document = html::parse(&html);
        let stylesheet = css::user_agent_stylesheet(self.theme);
        self.active_tab_mut().layout_tree = layout::build_layout_tree(&document, &stylesheet);
        self.relayout();
        self.active_tab_mut().current_url = "about:downloads".to_string();
        let url = self.active_tab().current_url.clone();
        self.active_tab_mut().set_address_bar_text(url);
        self.active_tab_mut().cached_title = Some("Downloads".to_string());
        self.active_tab_mut().scroll_y = 0.0;
    }

    /// Fetches `url` (a real fetch, through the same sandboxed,
    /// blocklist-and-DoH-routed process a normal navigation uses — see
    /// `renderer::download`) and saves its bytes to disk instead of
    /// rendering them, in response to a clicked `<a download>` link
    /// (see `handle_click`). `download_attr_value` is that attribute's
    /// own value (possibly empty, for a bare `download` with no
    /// value) — used as the suggested filename when non-empty, taking
    /// priority over the URL-derived one the renderer itself falls
    /// back to (`ipc::DownloadSuccess::suggested_filename`), matching
    /// real browsers' own precedence.
    fn download(&mut self, url: &str, download_attr_value: &str) {
        let site = site_for_url(url);
        let top_level_host = url::Url::parse(&self.active_tab().current_url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_string));
        let tab_id = self.active_tab().id;
        let renderer = match self.renderers.get_or_spawn(&site) {
            Ok(renderer) => renderer,
            Err(e) => {
                eprintln!("Couldn't start a download for {url}: {e}");
                return;
            }
        };
        let Some(outcome) = renderer.download(tab_id, url, top_level_host) else {
            // `RendererProcess::download` already printed a reason.
            return;
        };

        let success = match outcome {
            ipc::DownloadOutcome::Downloaded(success) => success,
            ipc::DownloadOutcome::Failed(reason) => {
                eprintln!("Download failed for {url}: {reason}");
                return;
            }
        };
        let bytes = match success.bytes() {
            Ok(bytes) => bytes,
            Err(e) => {
                eprintln!("Downloaded data for {url} failed to decode: {e}");
                return;
            }
        };

        let filename_hint = if download_attr_value.is_empty() {
            success.suggested_filename.as_str()
        } else {
            download_attr_value
        };
        let filename = sanitize_download_filename(filename_hint);
        if let Err(e) = std::fs::create_dir_all(&self.downloads_dir) {
            eprintln!(
                "Couldn't create downloads directory {:?}: {e}",
                self.downloads_dir
            );
            return;
        }
        let path = unique_download_path(&self.downloads_dir, &filename);
        if let Err(e) = std::fs::write(&path, &bytes) {
            eprintln!("Failed to save download to {path:?}: {e}");
            return;
        }

        println!("Downloaded {url} -> {}", path.display());
        let saved_filename = path
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or(&filename)
            .to_string();
        self.downloads.push(DownloadRecord {
            url: url.to_string(),
            filename: saved_filename,
            size_bytes: bytes.len(),
            saved_path: path,
            downloaded_at_unix: now_unix(),
        });
        save_download_history(&self.account, &self.downloads, &self.data_dir);
    }

    /// Dispatches a click that landed on a media element's own
    /// `controls` bar (see `layout::hit_test_media_control`) — a real
    /// browser's native media controls aren't part of the page's own
    /// scriptable click-event target chain, so unlike a normal link or
    /// `<a download>`, this never goes through `click`-event dispatch
    /// (and so can't be `preventDefault()`-ed by page script) at all.
    /// Dispatched against the ACTIVE tab specifically — a click only
    /// ever happens on whatever's currently visible. The background-
    /// tab-audio case (real browsers keep playing a background tab's
    /// sound) is handled separately, by `handle_media_progress_tick`
    /// operating on an explicit `tab_id` instead of "the active tab."
    fn handle_media_control_click(
        &mut self,
        dom_node_id: dom::NodeId,
        hit: layout::MediaControlHit,
    ) {
        let tab_id = self.active_tab().id;
        match hit {
            layout::MediaControlHit::PlayPause => self.toggle_media_play_pause(tab_id, dom_node_id),
            layout::MediaControlHit::ToggleMute => self.toggle_media_mute(tab_id, dom_node_id),
            layout::MediaControlHit::Seek(fraction) => {
                self.seek_media(tab_id, dom_node_id, fraction)
            }
        }
    }

    fn toggle_media_play_pause(&mut self, tab_id: ipc::TabId, dom_node_id: dom::NodeId) {
        let is_playing = self
            .tab_mut(tab_id)
            .is_some_and(|tab| tab.active_playback.contains_key(&dom_node_id));
        if is_playing {
            self.pause_media(tab_id, dom_node_id);
        } else {
            self.play_media(tab_id, dom_node_id);
        }
    }

    /// Stops (drops) this element's live `cpal` stream, if any, saving
    /// where it left off into `media_position` first so a later
    /// `play_media` resumes rather than restarting at 0 — see
    /// `media_playback::ActiveStream`'s own doc comment on why
    /// dropping is the only real way to pause one.
    fn pause_media(&mut self, tab_id: ipc::TabId, dom_node_id: dom::NodeId) {
        if let Some(tab) = self.tab_mut(tab_id) {
            if let Some(stream) = tab.active_playback.remove(&dom_node_id) {
                tab.media_position
                    .insert(dom_node_id, stream.current_time_secs());
            }
        }
        self.report_media_playback(tab_id, dom_node_id, false);
    }

    /// Starts (or resumes) real playback for this element — fetching
    /// and caching its decoded PCM first if this is the first time
    /// it's ever been played in this tab (see `fetch_and_cache_pcm`).
    /// A no-op (with a printed reason) if there's nothing playable at
    /// all, or the local audio device can't be opened.
    fn play_media(&mut self, tab_id: ipc::TabId, dom_node_id: dom::NodeId) {
        let already_cached = self
            .tab_mut(tab_id)
            .is_some_and(|tab| tab.media_pcm_cache.contains_key(&dom_node_id));
        if !already_cached && !self.fetch_and_cache_pcm(tab_id, dom_node_id) {
            return;
        }

        let Some(tab) = self.tab_mut(tab_id) else {
            return;
        };
        let start_time_secs = tab.media_position.get(&dom_node_id).copied().unwrap_or(0.0);
        let muted = tab.media_muted.get(&dom_node_id).copied().unwrap_or(false);
        let outcome = {
            let pcm = tab
                .media_pcm_cache
                .get(&dom_node_id)
                .expect("just ensured this is cached above");
            media_playback::start_playback(pcm, start_time_secs, muted)
        };
        match outcome {
            Ok(stream) => {
                tab.active_playback.insert(dom_node_id, stream);
                tab.next_media_tick_at =
                    Some(std::time::Instant::now() + MEDIA_PROGRESS_TICK_INTERVAL);
                self.report_media_playback(tab_id, dom_node_id, true);
            }
            Err(e) => eprintln!("Couldn't start audio playback: {e}"),
        }
    }

    fn toggle_media_mute(&mut self, tab_id: ipc::TabId, dom_node_id: dom::NodeId) {
        let Some(tab) = self.tab_mut(tab_id) else {
            return;
        };
        let new_muted = !tab.media_muted.get(&dom_node_id).copied().unwrap_or(false);
        tab.media_muted.insert(dom_node_id, new_muted);
        if let Some(stream) = tab.active_playback.get(&dom_node_id) {
            stream.set_muted(new_muted);
        }
        let playing = tab.active_playback.contains_key(&dom_node_id);
        self.report_media_playback(tab_id, dom_node_id, playing);
    }

    /// Seeks to `fraction` (`0.0..=1.0`) of this element's known
    /// duration — stops whatever was playing (same as `pause_media`)
    /// and, if it WAS playing, immediately restarts from the new
    /// position; if it was paused, just remembers the new position for
    /// the next `play_media`.
    fn seek_media(&mut self, tab_id: ipc::TabId, dom_node_id: dom::NodeId, fraction: f32) {
        let already_cached = self
            .tab_mut(tab_id)
            .is_some_and(|tab| tab.media_pcm_cache.contains_key(&dom_node_id));
        if !already_cached && !self.fetch_and_cache_pcm(tab_id, dom_node_id) {
            return;
        }
        let duration_secs = self
            .tab_mut(tab_id)
            .and_then(|tab| tab.media_pcm_cache.get(&dom_node_id))
            .map(media_playback::CachedPcm::duration_secs)
            .unwrap_or(0.0);
        let new_time_secs = fraction.clamp(0.0, 1.0) * duration_secs;

        let was_playing = self
            .tab_mut(tab_id)
            .is_some_and(|tab| tab.active_playback.remove(&dom_node_id).is_some());
        if let Some(tab) = self.tab_mut(tab_id) {
            tab.media_position.insert(dom_node_id, new_time_secs);
        }

        if was_playing {
            self.play_media(tab_id, dom_node_id);
        } else {
            self.report_media_playback(tab_id, dom_node_id, false);
        }
    }

    /// Fetches (once) and caches this element's decoded PCM via
    /// `ipc::ClientMessageKind::FetchAudioPcm` — returns whether
    /// something playable is now cached. A no-op success if it's
    /// already cached from a previous play.
    fn fetch_and_cache_pcm(&mut self, tab_id: ipc::TabId, dom_node_id: dom::NodeId) -> bool {
        let Some(site) = self
            .tab_mut(tab_id)
            .and_then(|tab| tab.renderer_site.clone())
        else {
            return false;
        };
        let Some(renderer) = self.renderers.get(&site) else {
            return false;
        };
        let Some(outcome) = renderer.fetch_audio_pcm(tab_id, dom_node_id) else {
            // `RendererProcess::fetch_audio_pcm` already printed a reason.
            return false;
        };
        let data = match outcome {
            ipc::AudioPcmOutcome::Ready(data) => data,
            ipc::AudioPcmOutcome::Failed(reason) => {
                eprintln!("No playable audio for this element: {reason}");
                return false;
            }
        };
        let samples = match data.samples() {
            Ok(samples) => samples,
            Err(e) => {
                eprintln!("Decoded audio data failed to decode: {e}");
                return false;
            }
        };
        let Some(tab) = self.tab_mut(tab_id) else {
            return false;
        };
        tab.media_pcm_cache.insert(
            dom_node_id,
            media_playback::CachedPcm {
                samples: std::sync::Arc::new(samples),
                sample_rate: data.sample_rate,
                channels: data.channels,
            },
        );
        true
    }

    /// Tells the renderer this element's playback state just changed
    /// (see `ipc::ClientMessageKind::UpdateMediaPlayback`) and applies
    /// whatever comes back — the one path that actually updates the
    /// visible play/pause icon and scrubber position, since `app`
    /// itself never builds the `LayoutBox` tree. A harmless no-op if
    /// `tab_id` no longer exists (e.g. the tab was closed) or has no
    /// live renderer process (e.g. it navigated to an `about:` page).
    fn report_media_playback(
        &mut self,
        tab_id: ipc::TabId,
        dom_node_id: dom::NodeId,
        playing: bool,
    ) {
        let Some(tab) = self.tab_mut(tab_id) else {
            return;
        };
        let current_time_secs = tab.media_position.get(&dom_node_id).copied().unwrap_or(0.0);
        let muted = tab.media_muted.get(&dom_node_id).copied().unwrap_or(false);
        let Some(site) = tab.renderer_site.clone() else {
            return;
        };
        let Some(renderer) = self.renderers.get(&site) else {
            return;
        };
        let kind =
            renderer.update_media_playback(tab_id, dom_node_id, playing, muted, current_time_secs);
        let now = std::time::Instant::now();
        self.apply_server_message_kind_to_tab(tab_id, kind, now);
    }

    /// Fetches `url` (through the same privacy-filtering path as
    /// always — real DNS-over-HTTPS, redirect-hop blocklist checking,
    /// tracking-param stripping), parses it, and lays it out. On
    /// failure, shows a small built-in error page instead of crashing
    /// or silently doing nothing, same as a real browser would.
    fn navigate(&mut self, url: &str) {
        self.active_tab_mut().record_navigation_history();
        self.navigate_without_history(url);
    }

    /// Like `navigate`, but for a real POST form submission (see
    /// `handle_click`/`send_text_input_to_focused_page_input`, its two
    /// callers) — `body` is the `application/x-www-form-urlencoded`
    /// field values `renderer::script::Session::build_form_submission`
    /// already built. Still records history: pressing back after
    /// submitting a login form should return to the login page, the
    /// same as it already does for a GET form submitted via `navigate`.
    fn navigate_with_body(&mut self, url: &str, body: Vec<u8>) {
        self.active_tab_mut().record_navigation_history();
        self.navigate_without_history_with_body(url, Some(body));
    }

    /// Sends `url` to the sandboxed renderer process and uses whatever
    /// comes back. The renderer does the ENTIRE untrusted-content
    /// pipeline (fetch, HTML parse, CSS, layout) and hands back an
    /// already-laid-out `layout::LayoutBox` tree plus a title — this
    /// process never parses a byte of the actual page itself. On
    /// failure (network error, blocked by the blocklist, or the
    /// renderer process itself being unreachable), builds the same
    /// small local "Failed to load" page as always, from a plain error
    /// STRING the renderer/`RendererProcess` provided — never from
    /// anything resembling the response body itself.
    fn navigate_without_history(&mut self, url: &str) {
        self.navigate_without_history_with_body(url, None);
    }

    /// The real implementation both `navigate_without_history` (GET)
    /// and `navigate_with_body` (POST) build on — see
    /// `ipc::RenderRequest::body`'s own doc comment for what `body`
    /// means on the wire.
    fn navigate_without_history_with_body(&mut self, url: &str, body: Option<Vec<u8>>) {
        self.exit_find_mode();
        self.stop_all_media_playback();
        self.reset_devtools_page_state();
        // Re-read from disk every time (see `userscripts`'s own module
        // doc comment on why), then filtered down to whichever ones'
        // own `@match` rules actually apply to THIS navigation — the
        // renderer never sees, and never needs to evaluate, the ones
        // that don't.
        let installed_userscripts = userscripts::load_all(&self.userscripts_dir);
        let user_scripts: Vec<String> = userscripts::scripts_for_url(&installed_userscripts, url)
            .into_iter()
            .map(str::to_string)
            .collect();
        let request = ipc::RenderRequest {
            url: url.to_string(),
            body,
            // Always `None`: this app only ever fetches top-level
            // navigations today (no subresource loading at this level
            // — no images yet; external `<script src>` fetches happen
            // INSIDE the renderer, against the page's own URL, not
            // through this field), matching the `None` this call site
            // has always passed.
            top_level_host: None,
            canvas_width: self.canvas_width as f32,
            theme: self.theme.as_str().to_string(),
            user_scripts,
            // Filled in by `RendererProcess::render` itself, only on
            // that process's first-ever `Navigate` — see that method's
            // own doc comment and `ipc::RenderRequest::initial_cookies`.
            initial_cookies: None,
            initial_local_storage: None,
            initial_indexed_db: None,
        };

        let tab_id = self.active_tab().id;
        let old_site = self.active_tab().renderer_site.clone();
        let new_site = site_for_url(url);
        let now = std::time::Instant::now();

        let render_result = match self.renderers.get_or_spawn(&new_site) {
            Ok(renderer) => renderer.render(tab_id, request),
            Err(e) => Err(e),
        };

        let (layout_tree, title, page_signals, next_wake_at, live_site) = match render_result {
            Ok(success) => {
                let wake_at = success
                    .next_wake_in_millis
                    .map(|ms| now + std::time::Duration::from_millis(ms));
                (
                    success.layout_tree,
                    success.title,
                    Some(success.page_signals),
                    wake_at,
                    Some(new_site),
                )
            }
            Err(message) => {
                eprintln!("Failed to load {url}: {message}");
                let html = format!(
                    "<html><head><title>Failed to load</title></head><body>\
                     <h1>Failed to load</h1><p>{}</p><p>{}</p></body></html>",
                    html_escape(url),
                    html_escape(&message),
                );
                let document = html::parse(&html);
                let stylesheet = css::user_agent_stylesheet(self.theme);
                let tree = layout::build_layout_tree(&document, &stylesheet);
                // No session exists anywhere for this tab now — either
                // the renderer's own `Navigate` arm dropped it after a
                // fetch/blocklist failure, or `get_or_spawn` never
                // reached the renderer at all (failed to spawn). No
                // real page signals for a locally-built error page
                // either — `None` clears any stale badge from whatever
                // this tab showed before.
                (tree, Some("Failed to load".to_string()), None, None, None)
            }
        };

        // A fresh navigation fully replaces whatever `script::Session`
        // (pending timers included) this tab had, but if that session
        // lived in a DIFFERENT site's process (a real site-to-site
        // navigation), that OLD process never heard about this at all
        // — it only drops a tab's session as a side effect of a
        // `Navigate` IT receives (see `renderer::RendererState::
        // handle_message`), and this one didn't. Tell it explicitly.
        if old_site.is_some() && old_site != live_site {
            if let Some(old) = &old_site {
                if let Some(old_renderer) = self.renderers.get(old) {
                    old_renderer.close_tab(tab_id);
                }
            }
        }

        // Captured before `live_site` moves into `renderer_site` below —
        // see this function's tail for why this specifically means
        // "record a history entry."
        let fetch_succeeded = live_site.is_some();

        self.active_tab_mut().layout_tree = layout_tree;
        self.relayout();

        self.active_tab_mut().current_url = url.to_string();
        let current_url = self.active_tab().current_url.clone();
        self.active_tab_mut().set_address_bar_text(current_url);
        self.active_tab_mut().cached_title = title;
        self.active_tab_mut().cached_page_signals = page_signals;
        self.active_tab_mut().scroll_y = 0.0;
        self.active_tab_mut().next_wake_at = next_wake_at;
        self.active_tab_mut().renderer_site = live_site;
        // A fresh navigation means a fresh DOM — whatever was focused
        // on the OLD page (if anything) no longer means anything, and
        // the new renderer-side session already starts with nothing
        // focused (see `script::Session::new`) regardless.
        self.active_tab_mut().focused_page_input = None;
        self.active_tab_mut().keyboard_focus = None;

        // The OLD site (if any) may now be unreferenced by every open
        // tab — see `RendererPool`'s doc comment on why that process
        // shouldn't keep running once nothing shows it any more. Also
        // catches the "just-spawned new site's fetch immediately
        // failed" case, which would otherwise leak that process too.
        self.evict_unreferenced_renderer_processes();

        // Only a genuinely successful fetch counts as a visit — a
        // failed navigation (network error, blocked, unreachable
        // renderer) isn't really "browsing history" the way a real
        // loaded page is, and would otherwise pollute it with whatever
        // URL the user mistyped or a dead link pointed at.
        if fetch_succeeded {
            let title = self.active_tab().cached_title.clone();
            self.bookmarks.record_visit(url, title.as_deref());
            save_bookmarks(&self.account, &self.bookmarks, &self.data_dir);
        }
    }

    /// Routes a history-stack entry back to whichever loader produced it —
    /// `navigate`'s real fetches and the three `about:` pseudo-pages all
    /// end up as `current_url` values that can land in `history_back`/
    /// `history_forward`, so going back/forward has to be able to
    /// re-enter any of them, not just re-fetch a URL. Restores `scroll_y`
    /// to the position the page had when it was left, after the loader
    /// (which always resets scroll to 0 for a fresh load) runs.
    fn go_to_history_entry(&mut self, url: &str, scroll_y: f32) {
        match url {
            "about:demo" => self.load_demo_page_without_history(),
            "about:bookmarks" => self.load_bookmarks_page_without_history(),
            "about:settings" => self.load_settings_page_without_history(),
            "about:account" => self.load_account_page_without_history(),
            "about:history" => self.load_history_page_without_history(),
            "about:downloads" => self.load_downloads_page_without_history(),
            _ => self.navigate_without_history(url),
        }
        self.active_tab_mut().scroll_y = scroll_y;
        self.clamp_scroll();
    }

    fn go_back(&mut self) {
        let entry = self.active_tab_mut().history_back.pop();
        if let Some((url, scroll_y)) = entry {
            let current_url = self.active_tab().current_url.clone();
            let current_scroll = self.active_tab().scroll_y;
            self.active_tab_mut()
                .history_forward
                .push((current_url, current_scroll));
            self.go_to_history_entry(&url, scroll_y);
        }
    }

    fn go_forward(&mut self) {
        let entry = self.active_tab_mut().history_forward.pop();
        if let Some((url, scroll_y)) = entry {
            let current_url = self.active_tab().current_url.clone();
            let current_scroll = self.active_tab().scroll_y;
            self.active_tab_mut()
                .history_back
                .push((current_url, current_scroll));
            self.go_to_history_entry(&url, scroll_y);
        }
    }

    /// Re-runs the positioning pass against the current canvas width,
    /// then re-clamps scroll (the page's natural height may have
    /// changed — e.g. after a navigation, or a width change on
    /// resize). Always applies to the ACTIVE tab — an inactive tab's
    /// layout stays exactly as it was until it's switched to and
    /// something (a resize while it's active, a fresh navigation)
    /// actually needs it recomputed.
    fn relayout(&mut self) {
        let canvas_width = self.canvas_width as f32;
        let tab = &mut self.tabs[self.active_tab_index];
        layout::layout(&mut tab.layout_tree, canvas_width, &self.font);
        self.clamp_scroll();
    }

    fn clamp_scroll(&mut self) {
        let viewport_height =
            (self.canvas_height as f32 - CHROME_HEIGHT - self.devtools_reserved_height()).max(0.0);
        let tab = &mut self.tabs[self.active_tab_index];
        let max_scroll = (tab.layout_tree.rect.height - viewport_height).max(0.0);
        tab.scroll_y = tab.scroll_y.clamp(0.0, max_scroll);
    }

    /// How much of the window's bottom edge the DevTools panel is
    /// currently occupying — `DEVTOOLS_PANEL_HEIGHT` while the ACTIVE
    /// tab has it open, `0.0` otherwise. Every "how tall is the page's
    /// own viewport" calculation subtracts this alongside `CHROME_HEIGHT`,
    /// same as the top chrome — see `DEVTOOLS_PANEL_HEIGHT`'s own doc
    /// comment on why this is bottom-DOCKED rather than a floating
    /// overlay like the find bar.
    fn devtools_reserved_height(&self) -> f32 {
        if self.active_tab().devtools_open {
            DEVTOOLS_PANEL_HEIGHT
        } else {
            0.0
        }
    }

    /// The earliest pending `setTimeout` wake-up across EVERY tab, not
    /// just the active one — a background tab's timer has to keep
    /// firing even while the user is looking at a different tab, the
    /// same way a real browser's would. This is recomputed fresh on
    /// every `Frame` (see `frame`, below) rather than merged/accumulated
    /// anywhere, matching `render::window::Frame::wake_at`'s own doc
    /// comment on why that's the caller's job, not that module's.
    fn earliest_wake_at(&self) -> Option<std::time::Instant> {
        self.tabs
            .iter()
            .filter_map(|tab| tab.next_wake_at)
            .chain(self.tabs.iter().filter_map(|tab| tab.next_media_tick_at))
            .chain(self.next_update_check_at)
            .min()
    }

    /// Builds a `Frame` the uniform way every `handle_event` arm needs:
    /// repaint the active tab, optionally update the window title, and
    /// always attach the CURRENT earliest wake-up across all tabs (see
    /// `earliest_wake_at`) — so a caller that only meant to, say, move
    /// the text cursor doesn't have to separately remember to keep a
    /// pending background timer armed; it falls out of using this
    /// helper instead of constructing `Frame` by hand.
    fn frame(&mut self, title: Option<String>) -> Frame {
        Frame {
            canvas: self.repaint(),
            title,
            wake_at: self.earliest_wake_at(),
            accessibility_update: self.build_accessibility_tree_update(),
        }
    }

    /// Builds this frame's real accessible tree for a screen reader (or
    /// any other assistive technology) — see `accessibility`'s own
    /// module docs for the full story. `CHROME_HEIGHT - scroll_y` is
    /// the same page-content vertical offset `repaint` itself applies
    /// when painting (see that method's own comment on why negative
    /// scroll shifts content down to make room for the chrome above
    /// it) — an assistive technology needs the SAME real on-screen
    /// position painting uses, not the layout tree's own internal
    /// coordinate space.
    fn build_accessibility_tree_update(&self) -> accesskit::TreeUpdate {
        let tab = self.active_tab();
        accessibility::build_tree_update(
            &tab.layout_tree,
            tab.keyboard_focus,
            CHROME_HEIGHT - tab.scroll_y,
        )
    }

    /// Applies one `ServerMessageKind` reply — from a `Tick` OR a
    /// `Click` (see `handle_tick` and `handle_click`, its two callers)
    /// — to the NAMED tab, which is not necessarily the active one (a
    /// background tab's `Tick` reply still has to update ITS OWN
    /// state; a `Click` reply is always for the active tab in practice,
    /// but this doesn't need to assume that). Returns whether the
    /// tab's visible content actually changed (`Rendered`) — callers
    /// use that to decide whether the ACTIVE tab specifically needs
    /// re-painting/re-clamping, since a background tab's own change
    /// doesn't need either right now.
    fn apply_server_message_kind_to_tab(
        &mut self,
        tab_id: ipc::TabId,
        kind: ipc::ServerMessageKind,
        now: std::time::Instant,
    ) -> bool {
        match kind {
            ipc::ServerMessageKind::Rendered(success) => {
                let wake_at = success
                    .next_wake_in_millis
                    .map(|ms| now + std::time::Duration::from_millis(ms));
                if let Some(tab) = self.tabs.iter_mut().find(|tab| tab.id == tab_id) {
                    tab.layout_tree = success.layout_tree;
                    tab.cached_title = success.title;
                    tab.cached_page_signals = Some(success.page_signals);
                    tab.next_wake_at = wake_at;
                    // Every reply (not just an explicit DevTools eval —
                    // see `ipc::RenderSuccess::console_messages`'s own
                    // doc comment) can carry new console output, e.g. a
                    // background `setTimeout` callback that calls
                    // `console.log`. Appended unconditionally, whether
                    // or not the DevTools console panel is even open
                    // right now — so opening it later still shows
                    // everything logged since this page loaded.
                    if !success.console_messages.is_empty() {
                        tab.console_log.extend(success.console_messages);
                        // Auto-scrolls to the newest entry, same as a
                        // real browser's console — `paint_devtools_panel`
                        // clamps this down to a valid row range itself,
                        // so `usize::MAX` here just means "the bottom,
                        // whatever that resolves to."
                        tab.console_scroll_rows = usize::MAX;
                    }
                }
                true
            }
            ipc::ServerMessageKind::Unchanged {
                next_wake_in_millis,
            } => {
                let wake_at =
                    next_wake_in_millis.map(|ms| now + std::time::Duration::from_millis(ms));
                if let Some(tab) = self.tabs.iter_mut().find(|tab| tab.id == tab_id) {
                    tab.next_wake_at = wake_at;
                }
                false
            }
            ipc::ServerMessageKind::Error(message) => {
                eprintln!("renderer reported an error for {tab_id:?} (ignoring): {message}");
                if let Some(tab) = self.tabs.iter_mut().find(|tab| tab.id == tab_id) {
                    tab.next_wake_at = None;
                }
                false
            }
            ipc::ServerMessageKind::Closed => {
                eprintln!("renderer protocol error: got a Closed acknowledgement in reply to a Tick/Click for {tab_id:?}");
                false
            }
            ipc::ServerMessageKind::UpdateCheckResult(_) => {
                eprintln!(
                    "renderer protocol error: got an UpdateCheckResult in reply to a Tick/Click for {tab_id:?}"
                );
                false
            }
            ipc::ServerMessageKind::DownloadResult(_) => {
                eprintln!(
                    "renderer protocol error: got a DownloadResult in reply to a Tick/Click for {tab_id:?}"
                );
                false
            }
            ipc::ServerMessageKind::AudioPcmResult(_) => {
                eprintln!(
                    "renderer protocol error: got an AudioPcmResult in reply to a Tick/Click for {tab_id:?}"
                );
                false
            }
            ipc::ServerMessageKind::DomSnapshotResult(_) => {
                eprintln!(
                    "renderer protocol error: got a DomSnapshotResult in reply to a Tick/Click for {tab_id:?}"
                );
                false
            }
        }
    }

    /// Handles `InputEvent::Tick` — `render::window` telling this
    /// process that a previously requested wake-up (see `frame`/
    /// `earliest_wake_at`) has arrived. Sends `ipc::ClientMessageKind::
    /// Tick` to every tab whose `next_wake_at` is now due (there can be
    /// more than one if two tabs' timers happened to coincide), applies
    /// whatever each one reports back, and returns whether the ACTIVE
    /// tab's visible output changed (so the caller knows whether to
    /// bother re-painting titles) — a background tab's mutation still
    /// updates its own `layout_tree`/`cached_title` either way, ready
    /// for whenever it's switched to.
    ///
    /// Always returns `true` if anything was due at all — even a
    /// `Tick` that changed nothing visible still has to produce a
    /// `Frame` (see `handle_event`'s `Tick` arm) purely to carry
    /// `earliest_wake_at`'s updated value back to `render::window`,
    /// since that's the ONLY channel `Frame::wake_at` has for
    /// re-arming a still/again-pending timer (a `None` `Frame` leaves
    /// the window's wake-up deadline untouched — see that module's docs).
    fn handle_tick(&mut self) -> bool {
        let now = std::time::Instant::now();
        // `renderer_site` travels alongside the tab id here since each
        // due tab's `Tick` has to reach the SAME site's process its
        // session actually lives in — see `RendererPool`'s doc comment.
        let due: Vec<(ipc::TabId, Option<String>)> = self
            .tabs
            .iter()
            .filter(|tab| tab.next_wake_at.is_some_and(|wake_at| wake_at <= now))
            .map(|tab| (tab.id, tab.renderer_site.clone()))
            .collect();

        let mut ticked = false;
        if !due.is_empty() {
            let active_tab_id = self.active_tab().id;
            let mut active_tab_changed = false;
            for (tab_id, site) in due {
                let Some(site) = site else {
                    // A due tab with no `renderer_site` would mean it has a
                    // pending timer with no session to run it in at all —
                    // shouldn't happen (both are only ever set together),
                    // but clearing it here rather than looping on it forever
                    // is the safe response if it somehow did.
                    eprintln!("a due tab ({tab_id:?}) has no renderer_site — clearing its wake-up rather than looping on it");
                    if let Some(tab) = self.tabs.iter_mut().find(|tab| tab.id == tab_id) {
                        tab.next_wake_at = None;
                    }
                    continue;
                };
                let Some(renderer) = self.renderers.get(&site) else {
                    // The process this tab's `renderer_site` names doesn't
                    // exist any more — an eviction sweep shouldn't be able
                    // to remove a still-referenced site, but if it somehow
                    // did (or the two got out of sync some other way),
                    // clearing this tab's stale pointers is the safe
                    // response rather than spawning a fresh, sessionless
                    // process just to `Tick` it.
                    if let Some(tab) = self.tabs.iter_mut().find(|tab| tab.id == tab_id) {
                        tab.next_wake_at = None;
                        tab.renderer_site = None;
                    }
                    continue;
                };
                let outcome = renderer.tick(tab_id);
                if self.apply_server_message_kind_to_tab(tab_id, outcome, now)
                    && tab_id == active_tab_id
                {
                    active_tab_changed = true;
                }
            }

            if active_tab_changed {
                self.clamp_scroll();
            }
            ticked = true;
        }

        // Independent of any tab's own timers — see
        // `maybe_check_for_update`'s own doc comment.
        let checked_for_update = self.maybe_check_for_update(now);
        let media_progressed = self.handle_media_progress_tick(now);

        ticked || checked_for_update || media_progressed
    }

    /// For every tab with anything currently playing (`next_media_tick_at`
    /// due), either notices it's reached the end (dropping its stream
    /// and reporting `playing: false`) or refreshes its on-screen
    /// current-time/scrubber (reporting `playing: true` with the
    /// latest position read from the real `cpal` stream) — then
    /// reschedules `next_media_tick_at` if anything in that tab is
    /// STILL playing afterward. Runs across ALL tabs, not just the
    /// active one: a background tab's audio keeps playing (and its
    /// progress keeps advancing) exactly like a real browser's would.
    fn handle_media_progress_tick(&mut self, now: std::time::Instant) -> bool {
        let due_tab_ids: Vec<ipc::TabId> = self
            .tabs
            .iter()
            .filter(|tab| tab.next_media_tick_at.is_some_and(|at| at <= now))
            .map(|tab| tab.id)
            .collect();
        if due_tab_ids.is_empty() {
            return false;
        }

        for tab_id in due_tab_ids {
            let Some(tab) = self.tab_mut(tab_id) else {
                continue;
            };
            let ended: Vec<dom::NodeId> = tab
                .active_playback
                .iter()
                .filter(|(_, stream)| stream.has_ended())
                .map(|(id, _)| *id)
                .collect();
            let still_playing: Vec<(dom::NodeId, f32)> = tab
                .active_playback
                .iter()
                .filter(|(id, _)| !ended.contains(id))
                .map(|(id, stream)| (*id, stream.current_time_secs()))
                .collect();

            // All mutation of `tab`'s own maps happens here, through
            // this ONE held borrow — `self.report_media_playback`
            // (which needs its own `&mut self`) is only called
            // afterward, once this borrow has ended (see below).
            for dom_node_id in &ended {
                if let Some(stream) = tab.active_playback.remove(dom_node_id) {
                    tab.media_position
                        .insert(*dom_node_id, stream.current_time_secs());
                }
            }
            for (dom_node_id, current_time_secs) in &still_playing {
                tab.media_position.insert(*dom_node_id, *current_time_secs);
            }
            tab.next_media_tick_at = if tab.active_playback.is_empty() {
                None
            } else {
                Some(now + MEDIA_PROGRESS_TICK_INTERVAL)
            };

            for dom_node_id in ended {
                self.report_media_playback(tab_id, dom_node_id, false);
            }
            for (dom_node_id, _) in still_playing {
                self.report_media_playback(tab_id, dom_node_id, true);
            }
        }
        true
    }

    /// Runs the periodic "is a newer release available?" check if
    /// `next_update_check_at` is due, through a dedicated renderer
    /// process this browser keeps just for it (see
    /// `update_checker_process`'s own doc comment on why that can't be
    /// one of `renderers`' per-site pool entries). Reschedules the next
    /// check `UPDATE_CHECK_INTERVAL` out regardless of outcome —
    /// including a failed one (see `RendererProcess::check_for_update`'s
    /// doc comment on why that isn't retried sooner). Returns whether a
    /// check actually ran, so `handle_tick` knows to still produce a
    /// `Frame` purely to re-arm the window's wake-up deadline even when
    /// no tab had anything due (see that method's own doc comment on why
    /// that's necessary at all).
    fn maybe_check_for_update(&mut self, now: std::time::Instant) -> bool {
        let Some(due_at) = self.next_update_check_at else {
            return false;
        };
        if due_at > now {
            return false;
        }
        self.next_update_check_at = Some(now + UPDATE_CHECK_INTERVAL);

        let process = match &mut self.update_checker_process {
            Some(process) => process,
            None => match RendererProcess::spawn(
                &self.data_dir.join("cache"),
                self.renderers.storage_persistence(),
                false,
            ) {
                Ok(process) => self.update_checker_process.insert(process),
                Err(e) => {
                    eprintln!(
                        "Couldn't spawn a renderer process for the update check ({e}) — \
                         will retry on the next scheduled check."
                    );
                    return true;
                }
            },
        };

        if let Some(outcome) = process.check_for_update(env!("CARGO_PKG_VERSION")) {
            match outcome {
                ipc::UpdateCheckOutcome::NewVersionAvailable { version, html_url } => {
                    println!(
                        "A newer version of Abyssal Browser is available: {version} — {html_url}"
                    );
                }
                ipc::UpdateCheckOutcome::UpToDate => {}
                ipc::UpdateCheckOutcome::CheckFailed(reason) => {
                    eprintln!("Update check failed (harmless, will retry later): {reason}");
                }
            }
        }
        true
    }

    /// Paints the active tab's page (scrolled) plus the tab bar and
    /// address bar chrome on top, and the find-in-page bar/highlights
    /// when a find session is active.
    fn repaint(&mut self) -> render::Canvas {
        let mut canvas = render::Canvas::new(
            self.canvas_width as usize,
            self.canvas_height as usize,
            self.background,
        );

        // Page content starts CHROME_HEIGHT pixels down; folding that
        // into the same scroll_y parameter `render::paint_with_find`
        // takes is simpler than adding a second offset parameter —
        // negative scroll shifts content DOWN, which is exactly what's
        // needed to make room for the chrome above it.
        let tab = self.active_tab();
        // An empty query wouldn't match anything anyway (see
        // `render::find_all_matches`), but skipping it here also avoids
        // the do-nothing tree walk `paint_with_find` would otherwise do
        // on every single repaint while the find bar is open but empty.
        let find_highlight =
            (tab.finding_in_page && !tab.find_query.is_empty()).then(|| render::FindHighlight {
                query: &tab.find_query,
                current_match_index: tab.find_current_index,
            });
        render::paint_with_find(
            &mut canvas,
            &tab.layout_tree,
            &self.font,
            tab.scroll_y - CHROME_HEIGHT,
            find_highlight.as_ref(),
        );

        self.paint_tab_bar(&mut canvas);
        self.paint_address_bar(&mut canvas);
        if self.active_tab().finding_in_page {
            self.paint_find_bar(&mut canvas);
        }
        if self.active_tab().devtools_open {
            // The highlight sits ON the page content (so it visibly
            // outlines the selected element in place), painted BEFORE
            // the panel itself, which then opaquely covers the bottom
            // band regardless of what page content or highlight
            // happened to paint into it.
            self.paint_devtools_highlight(&mut canvas);
            self.paint_devtools_panel(&mut canvas);
        }

        canvas
    }

    /// Draws the find-in-page bar: a small floating overlay in the
    /// top-right of the page content area (see `FIND_BAR_WIDTH`'s own
    /// doc comment for why it floats rather than joining `CHROME_HEIGHT`),
    /// showing the typed query and a live "N/M" match count (or "No
    /// matches", or nothing at all for an empty query).
    fn paint_find_bar(&self, canvas: &mut render::Canvas) {
        let tab = self.active_tab();
        let bar_x = (self.canvas_width as f32 - FIND_BAR_WIDTH - FIND_BAR_MARGIN).max(0.0);
        let bar_y = CHROME_HEIGHT + FIND_BAR_MARGIN;

        canvas.fill_rect(
            bar_x,
            bar_y,
            FIND_BAR_WIDTH,
            FIND_BAR_HEIGHT,
            render::Color {
                r: 25,
                g: 25,
                b: 25,
                a: 255,
            },
        );

        let status = if tab.find_query.is_empty() {
            String::new()
        } else if tab.find_matches.is_empty() {
            "No matches".to_string()
        } else {
            format!("{}/{}", tab.find_current_index + 1, tab.find_matches.len())
        };
        let label = format!("Find: {}  {status}", tab.find_query);
        render::paint_text_line(
            canvas,
            bar_x + 8.0,
            bar_y + (FIND_BAR_HEIGHT - FIND_BAR_FONT_SIZE) / 2.0,
            &label,
            FIND_BAR_FONT_SIZE,
            render::Color {
                r: 230,
                g: 230,
                b: 230,
                a: 255,
            },
            &self.font,
        );
    }

    /// Paints the bottom-docked DevTools panel (`F12`) — background,
    /// tab strip, then whichever of Console/Elements is active. Only
    /// ever called while `devtools_open` (checked by the caller,
    /// `repaint`), same convention `paint_find_bar` already follows for
    /// its own `finding_in_page` gate.
    fn paint_devtools_panel(&self, canvas: &mut render::Canvas) {
        let panel_top = self.canvas_height as f32 - DEVTOOLS_PANEL_HEIGHT;
        let width = self.canvas_width as f32;

        canvas.fill_rect(
            0.0,
            panel_top,
            width,
            DEVTOOLS_PANEL_HEIGHT,
            DEVTOOLS_PANEL_BACKGROUND,
        );
        self.paint_devtools_tab_bar(canvas, panel_top, width);

        let content_top = panel_top + DEVTOOLS_TAB_BAR_HEIGHT;
        match self.active_tab().devtools_tab {
            DevtoolsTab::Console => self.paint_devtools_console_tab(canvas, content_top, width),
            DevtoolsTab::Elements => self.paint_devtools_elements_tab(canvas, content_top, width),
        }
    }

    /// The DevTools panel's own top strip — see
    /// `handle_devtools_tab_bar_click`'s doc comment for the matching
    /// hit regions.
    fn paint_devtools_tab_bar(&self, canvas: &mut render::Canvas, panel_top: f32, width: f32) {
        let tab = self.active_tab();
        canvas.fill_rect(
            0.0,
            panel_top,
            width,
            DEVTOOLS_TAB_BAR_HEIGHT,
            DEVTOOLS_TAB_BAR_BACKGROUND,
        );
        let label_y = panel_top + (DEVTOOLS_TAB_BAR_HEIGHT - DEVTOOLS_FONT_SIZE) / 2.0;

        let console_color = if tab.devtools_tab == DevtoolsTab::Console {
            DEVTOOLS_ACTIVE_TAB_COLOR
        } else {
            DEVTOOLS_INACTIVE_TAB_COLOR
        };
        render::paint_text_line(
            canvas,
            DEVTOOLS_PADDING,
            label_y,
            "Console",
            DEVTOOLS_FONT_SIZE,
            console_color,
            &self.font,
        );
        let elements_color = if tab.devtools_tab == DevtoolsTab::Elements {
            DEVTOOLS_ACTIVE_TAB_COLOR
        } else {
            DEVTOOLS_INACTIVE_TAB_COLOR
        };
        render::paint_text_line(
            canvas,
            DEVTOOLS_TAB_LABEL_WIDTH + DEVTOOLS_PADDING,
            label_y,
            "Elements",
            DEVTOOLS_FONT_SIZE,
            elements_color,
            &self.font,
        );

        if tab.devtools_tab == DevtoolsTab::Elements {
            let refresh_x = width - DEVTOOLS_ACTION_BUTTON_WIDTH;
            let pick_x = refresh_x - DEVTOOLS_ACTION_BUTTON_WIDTH;
            let pick_label = if tab.devtools_picking {
                "Picking..."
            } else {
                "Pick"
            };
            render::paint_text_line(
                canvas,
                pick_x + DEVTOOLS_PADDING,
                label_y,
                pick_label,
                DEVTOOLS_FONT_SIZE,
                DEVTOOLS_ACTIVE_TAB_COLOR,
                &self.font,
            );
            render::paint_text_line(
                canvas,
                refresh_x + DEVTOOLS_PADDING,
                label_y,
                "Refresh",
                DEVTOOLS_FONT_SIZE,
                DEVTOOLS_ACTIVE_TAB_COLOR,
                &self.font,
            );
        }
    }

    /// The Console tab: a scrolling, color-coded log above a REPL input
    /// row pinned to the bottom — see `Tab::console_log`/`console_input`'s
    /// own doc comments.
    fn paint_devtools_console_tab(
        &self,
        canvas: &mut render::Canvas,
        content_top: f32,
        width: f32,
    ) {
        let tab = self.active_tab();
        let content_height = DEVTOOLS_PANEL_HEIGHT - DEVTOOLS_TAB_BAR_HEIGHT;
        let log_height = content_height - DEVTOOLS_CONSOLE_INPUT_HEIGHT;
        let visible_rows = Self::devtools_visible_log_rows();
        let start = tab.console_scroll_rows.min(self.max_console_scroll_rows());

        for (row, message) in tab
            .console_log
            .iter()
            .skip(start)
            .take(visible_rows)
            .enumerate()
        {
            let y = content_top + row as f32 * DEVTOOLS_ROW_HEIGHT;
            let color = match message.level {
                ipc::ConsoleLevel::Log => DEVTOOLS_TREE_TEXT_COLOR,
                ipc::ConsoleLevel::Info => DEVTOOLS_INFO_COLOR,
                ipc::ConsoleLevel::Warn => DEVTOOLS_WARN_COLOR,
                ipc::ConsoleLevel::Error => DEVTOOLS_ERROR_COLOR,
            };
            render::paint_text_line(
                canvas,
                DEVTOOLS_PADDING,
                y + (DEVTOOLS_ROW_HEIGHT - DEVTOOLS_FONT_SIZE) / 2.0,
                &message.text,
                DEVTOOLS_FONT_SIZE,
                color,
                &self.font,
            );
        }

        let input_y = content_top + log_height;
        canvas.fill_rect(
            0.0,
            input_y,
            width,
            DEVTOOLS_CONSOLE_INPUT_HEIGHT,
            DEVTOOLS_INPUT_BACKGROUND,
        );
        let input_label = format!("> {}", tab.console_input);
        render::paint_text_line(
            canvas,
            DEVTOOLS_PADDING,
            input_y + (DEVTOOLS_CONSOLE_INPUT_HEIGHT - DEVTOOLS_FONT_SIZE) / 2.0,
            &input_label,
            DEVTOOLS_FONT_SIZE,
            if tab.console_input_focused {
                DEVTOOLS_ACTIVE_TAB_COLOR
            } else {
                DEVTOOLS_TREE_TEXT_COLOR
            },
            &self.font,
        );
    }

    /// The Elements tab: a DOM tree on the left, and (for whatever's
    /// selected) a box-model diagram + computed style list on the
    /// right — see `handle_devtools_elements_click`'s doc comment for
    /// the matching hit regions.
    fn paint_devtools_elements_tab(
        &self,
        canvas: &mut render::Canvas,
        content_top: f32,
        width: f32,
    ) {
        let tab = self.active_tab();
        let tree_width = width * DEVTOOLS_ELEMENTS_TREE_WIDTH_FRACTION;
        let content_height = DEVTOOLS_PANEL_HEIGHT - DEVTOOLS_TAB_BAR_HEIGHT;
        canvas.fill_rect(
            tree_width,
            content_top,
            1.0,
            content_height,
            DEVTOOLS_DIVIDER_COLOR,
        );

        let Some(root) = tab.dom_snapshot.as_ref() else {
            render::paint_text_line(
                canvas,
                DEVTOOLS_PADDING,
                content_top + DEVTOOLS_PADDING,
                "No DOM snapshot yet — click Refresh.",
                DEVTOOLS_FONT_SIZE,
                DEVTOOLS_MUTED_COLOR,
                &self.font,
            );
            return;
        };
        let mut rows = Vec::new();
        flatten_dom_tree(root, 0, &mut rows);
        let visible_rows = Self::devtools_visible_tree_rows();
        let start = tab
            .elements_tree_scroll_rows
            .min(self.max_elements_scroll_rows());

        for (row_index, (depth, node)) in rows.iter().skip(start).take(visible_rows).enumerate() {
            let y = content_top + row_index as f32 * DEVTOOLS_ROW_HEIGHT;
            if tab.devtools_selected_node == Some(node.node_id) {
                canvas.fill_rect(
                    0.0,
                    y,
                    tree_width,
                    DEVTOOLS_ROW_HEIGHT,
                    DEVTOOLS_SELECTED_ROW_COLOR,
                );
            }
            let label = dom_node_label(node);
            let x = DEVTOOLS_PADDING + *depth as f32 * DEVTOOLS_INDENT;
            render::paint_text_line(
                canvas,
                x,
                y + (DEVTOOLS_ROW_HEIGHT - DEVTOOLS_FONT_SIZE) / 2.0,
                &label,
                DEVTOOLS_FONT_SIZE,
                DEVTOOLS_TREE_TEXT_COLOR,
                &self.font,
            );
        }

        let detail_x = tree_width + DEVTOOLS_PADDING;
        match tab
            .devtools_selected_node
            .and_then(|id| layout::find_box_by_dom_node_id(&tab.layout_tree, id))
        {
            Some(layout_box) => {
                self.paint_box_model(canvas, detail_x, content_top, width - detail_x, layout_box)
            }
            None => {
                let message = if tab.devtools_selected_node.is_some() {
                    "Not rendered (display: none, or removed since the last refresh)."
                } else {
                    "Select an element to inspect it."
                };
                render::paint_text_line(
                    canvas,
                    detail_x,
                    content_top + DEVTOOLS_PADDING,
                    message,
                    DEVTOOLS_FONT_SIZE,
                    DEVTOOLS_MUTED_COLOR,
                    &self.font,
                );
            }
        }
    }

    /// A Chrome-style nested-rectangle box-model diagram (margin/border/
    /// padding/content, outermost to innermost) for `b`, plus its
    /// computed style properties listed below it. The diagram's bands
    /// are a FIXED width each (not drawn to true scale against the
    /// element's real pixel size) — like real DevTools' own diagram,
    /// which also isn't strictly to scale once a box gets large; only
    /// the printed numbers are exact.
    fn paint_box_model(
        &self,
        canvas: &mut render::Canvas,
        x: f32,
        y: f32,
        available_width: f32,
        b: &layout::LayoutBox,
    ) {
        let diagram_size = (available_width - DEVTOOLS_PADDING * 2.0).clamp(60.0, 140.0);
        let band = 16.0_f32.min(diagram_size / 8.0);

        let margin_rect = (x, y, diagram_size, diagram_size);
        canvas.fill_rect(
            margin_rect.0,
            margin_rect.1,
            margin_rect.2,
            margin_rect.3,
            BOX_MODEL_MARGIN_COLOR,
        );
        let border_rect = (
            x + band,
            y + band,
            (diagram_size - band * 2.0).max(0.0),
            (diagram_size - band * 2.0).max(0.0),
        );
        canvas.fill_rect(
            border_rect.0,
            border_rect.1,
            border_rect.2,
            border_rect.3,
            BOX_MODEL_BORDER_COLOR,
        );
        let padding_rect = (
            x + band * 2.0,
            y + band * 2.0,
            (diagram_size - band * 4.0).max(0.0),
            (diagram_size - band * 4.0).max(0.0),
        );
        canvas.fill_rect(
            padding_rect.0,
            padding_rect.1,
            padding_rect.2,
            padding_rect.3,
            BOX_MODEL_PADDING_COLOR,
        );
        let content_rect = (
            x + band * 3.0,
            y + band * 3.0,
            (diagram_size - band * 6.0).max(0.0),
            (diagram_size - band * 6.0).max(0.0),
        );
        canvas.fill_rect(
            content_rect.0,
            content_rect.1,
            content_rect.2,
            content_rect.3,
            BOX_MODEL_CONTENT_COLOR,
        );

        self.paint_edge_labels(canvas, margin_rect, b.margin);
        self.paint_edge_labels(canvas, border_rect, b.border);
        self.paint_edge_labels(canvas, padding_rect, b.padding);

        let content_width =
            (b.rect.width - b.border.horizontal() - b.padding.horizontal()).max(0.0);
        let content_height = (b.rect.height - b.border.vertical() - b.padding.vertical()).max(0.0);
        let size_label = format!("{content_width:.0} x {content_height:.0}");
        let size_label_width =
            text::measure_text_width(&self.font, &size_label, BOX_MODEL_LABEL_FONT_SIZE);
        render::paint_text_line(
            canvas,
            content_rect.0 + (content_rect.2 - size_label_width) / 2.0,
            content_rect.1 + (content_rect.3 - BOX_MODEL_LABEL_FONT_SIZE) / 2.0,
            &size_label,
            BOX_MODEL_LABEL_FONT_SIZE,
            BOX_MODEL_LABEL_COLOR,
            &self.font,
        );

        let style_x = x + diagram_size + DEVTOOLS_PADDING;
        let style_top = y + diagram_size + DEVTOOLS_PADDING;
        let mut properties: Vec<(&String, &String)> = b.style.properties.iter().collect();
        properties.sort_by(|a, other| a.0.cmp(other.0));
        let max_rows =
            ((DEVTOOLS_PANEL_HEIGHT - DEVTOOLS_TAB_BAR_HEIGHT - diagram_size - DEVTOOLS_PADDING)
                / DEVTOOLS_ROW_HEIGHT)
                .max(0.0) as usize;
        for (i, (key, value)) in properties.iter().take(max_rows).enumerate() {
            let row_y = style_top + i as f32 * DEVTOOLS_ROW_HEIGHT;
            render::paint_text_line(
                canvas,
                style_x,
                row_y,
                &format!("{key}: {value}"),
                DEVTOOLS_FONT_SIZE,
                DEVTOOLS_TREE_TEXT_COLOR,
                &self.font,
            );
        }
    }

    /// Prints all four edge widths of `rect` (an `EdgeSizes`'s worth of
    /// numbers, one centered along each of that rect's four sides) —
    /// shared by `paint_box_model`'s margin/border/padding bands so
    /// they can't drift out of sync with each other visually.
    fn paint_edge_labels(
        &self,
        canvas: &mut render::Canvas,
        rect: (f32, f32, f32, f32),
        edges: layout::EdgeSizes,
    ) {
        let (x, y, w, h) = rect;
        let size = BOX_MODEL_LABEL_FONT_SIZE;
        let top = format!("{:.0}", edges.top);
        let right = format!("{:.0}", edges.right);
        let bottom = format!("{:.0}", edges.bottom);
        let left = format!("{:.0}", edges.left);
        let color = BOX_MODEL_LABEL_COLOR;

        let top_w = text::measure_text_width(&self.font, &top, size);
        render::paint_text_line(
            canvas,
            x + (w - top_w) / 2.0,
            y + 1.0,
            &top,
            size,
            color,
            &self.font,
        );

        let right_w = text::measure_text_width(&self.font, &right, size);
        render::paint_text_line(
            canvas,
            x + w - right_w - 2.0,
            y + h / 2.0 - size / 2.0,
            &right,
            size,
            color,
            &self.font,
        );

        let bottom_w = text::measure_text_width(&self.font, &bottom, size);
        render::paint_text_line(
            canvas,
            x + (w - bottom_w) / 2.0,
            y + h - size - 1.0,
            &bottom,
            size,
            color,
            &self.font,
        );

        render::paint_text_line(
            canvas,
            x + 2.0,
            y + h / 2.0 - size / 2.0,
            &left,
            size,
            color,
            &self.font,
        );
    }

    /// A translucent highlight over the currently DevTools-selected
    /// element's real on-page geometry — painted over the PAGE content
    /// (after it, before the DevTools panel itself), so it sits exactly
    /// where a real box-model highlight would in a real browser.
    /// Adjusts for `scroll_y` the same way `repaint`'s own page-content
    /// offset does. A no-op when nothing's selected, or the selected
    /// node isn't in the current layout tree at all (see
    /// `layout::find_box_by_dom_node_id`'s own doc comment).
    fn paint_devtools_highlight(&self, canvas: &mut render::Canvas) {
        let tab = self.active_tab();
        let Some(selected) = tab.devtools_selected_node else {
            return;
        };
        let Some(b) = layout::find_box_by_dom_node_id(&tab.layout_tree, selected) else {
            return;
        };
        let top = b.rect.y - tab.scroll_y + CHROME_HEIGHT;
        let bottom = top + b.rect.height;
        let viewport_bottom = self.canvas_height as f32 - self.devtools_reserved_height();
        // Clip to the visible page viewport — an off-screen (scrolled
        // away, or under the DevTools panel itself) selection still
        // exists but shouldn't paint outside the area it can actually
        // be seen in.
        if bottom <= CHROME_HEIGHT || top >= viewport_bottom {
            return;
        }
        let clipped_top = top.max(CHROME_HEIGHT);
        let clipped_height = (bottom.min(viewport_bottom) - clipped_top).max(0.0);
        blend_rect(
            canvas,
            b.rect.x,
            clipped_top,
            b.rect.width,
            clipped_height,
            DEVTOOLS_HIGHLIGHT_COLOR,
            DEVTOOLS_HIGHLIGHT_COVERAGE,
        );
    }

    /// Evenly divides the available width (canvas width minus the "+"
    /// button) across every open tab, clamped to a sane min/max — see
    /// `MIN_TAB_WIDTH`'s doc comment for the overflow case this doesn't
    /// handle.
    fn tab_width(&self) -> f32 {
        let available = (self.canvas_width as f32 - NEW_TAB_BUTTON_WIDTH).max(0.0);
        let count = self.tabs.len().max(1) as f32;
        (available / count).clamp(MIN_TAB_WIDTH, MAX_TAB_WIDTH)
    }

    fn paint_tab_bar(&self, canvas: &mut render::Canvas) {
        let bar_background = render::Color {
            r: 15,
            g: 15,
            b: 15,
            a: 255,
        };
        canvas.fill_rect(
            0.0,
            0.0,
            self.canvas_width as f32,
            TAB_BAR_HEIGHT,
            bar_background,
        );

        let width = self.tab_width();
        let text_y = (TAB_BAR_HEIGHT - TAB_FONT_SIZE) / 2.0;

        for (i, tab) in self.tabs.iter().enumerate() {
            let x = i as f32 * width;
            let is_active = i == self.active_tab_index;

            let tab_background = if is_active {
                render::Color {
                    r: 35,
                    g: 35,
                    b: 35,
                    a: 255,
                }
            } else {
                render::Color {
                    r: 15,
                    g: 15,
                    b: 15,
                    a: 255,
                }
            };
            canvas.fill_rect(x, 0.0, width, TAB_BAR_HEIGHT, tab_background);
            // A thin separator so adjacent inactive tabs (same
            // background as the bar itself) still read as distinct.
            canvas.fill_rect(
                x,
                0.0,
                1.0,
                TAB_BAR_HEIGHT,
                render::Color {
                    r: 0,
                    g: 0,
                    b: 0,
                    a: 255,
                },
            );

            // Closing the last tab is a no-op (see `close_tab`), so no
            // close button is drawn on it — a button that does nothing
            // when clicked would just be confusing.
            let has_close_button = self.tabs.len() > 1;
            let max_text_width = (width
                - TAB_TEXT_PADDING
                - if has_close_button {
                    TAB_CLOSE_ZONE_WIDTH
                } else {
                    0.0
                })
            .max(0.0);
            let title = truncate_to_width(
                &self.font,
                &tab.window_title(),
                TAB_FONT_SIZE,
                max_text_width,
            );
            let text_color = if is_active {
                render::Color {
                    r: 230,
                    g: 230,
                    b: 230,
                    a: 255,
                }
            } else {
                render::Color {
                    r: 150,
                    g: 150,
                    b: 150,
                    a: 255,
                }
            };
            render::paint_text_line(
                canvas,
                x + TAB_TEXT_PADDING,
                text_y,
                &title,
                TAB_FONT_SIZE,
                text_color,
                &self.font,
            );

            if has_close_button {
                let close_color = render::Color {
                    r: 150,
                    g: 150,
                    b: 150,
                    a: 255,
                };
                render::paint_text_line(
                    canvas,
                    x + width - TAB_CLOSE_ZONE_WIDTH + 4.0,
                    text_y,
                    "x",
                    TAB_FONT_SIZE,
                    close_color,
                    &self.font,
                );
            }
        }

        let new_tab_x = width * self.tabs.len() as f32;
        let plus_color = render::Color {
            r: 180,
            g: 180,
            b: 180,
            a: 255,
        };
        render::paint_text_line(
            canvas,
            new_tab_x + NEW_TAB_BUTTON_WIDTH / 2.0 - TAB_FONT_SIZE / 4.0,
            text_y,
            "+",
            TAB_FONT_SIZE,
            plus_color,
            &self.font,
        );
    }

    fn paint_address_bar(&self, canvas: &mut render::Canvas) {
        let tab = self.active_tab();
        let bar_background = if tab.editing_address_bar {
            render::Color {
                r: 45,
                g: 45,
                b: 70,
                a: 255,
            } // tinted while editing, for minimal visual feedback
        } else {
            render::Color {
                r: 25,
                g: 25,
                b: 25,
                a: 255,
            }
        };
        canvas.fill_rect(
            0.0,
            TAB_BAR_HEIGHT,
            self.canvas_width as f32,
            ADDRESS_BAR_HEIGHT,
            bar_background,
        );

        let enabled_color = render::Color {
            r: 210,
            g: 210,
            b: 210,
            a: 255,
        };
        let disabled_color = render::Color {
            r: 80,
            g: 80,
            b: 80,
            a: 255,
        };
        let back_color = if tab.history_back.is_empty() {
            disabled_color
        } else {
            enabled_color
        };
        let forward_color = if tab.history_forward.is_empty() {
            disabled_color
        } else {
            enabled_color
        };
        self.paint_chrome_button(
            canvas,
            BACK_BUTTON_X,
            false,
            back_color,
            render::icons::paint_back_arrow,
        );
        self.paint_chrome_button(
            canvas,
            FORWARD_BUTTON_X,
            false,
            forward_color,
            render::icons::paint_forward_arrow,
        );
        self.paint_chrome_button(
            canvas,
            RELOAD_BUTTON_X,
            false,
            enabled_color,
            render::icons::paint_reload_icon,
        );

        let bookmarked = self.bookmarks.is_bookmarked(&tab.current_url);
        let bookmark_color = if bookmarked {
            render::Color {
                r: 210,
                g: 180,
                b: 90,
                a: 255,
            } // same gold as the "JS" page-signals badge
        } else {
            render::Color {
                r: 130,
                g: 130,
                b: 130,
                a: 255,
            }
        };
        self.paint_chrome_button(
            canvas,
            self.bookmark_button_x(),
            bookmarked,
            bookmark_color,
            render::icons::paint_star,
        );
        self.paint_chrome_button(
            canvas,
            self.account_button_x(),
            false,
            enabled_color,
            render::icons::paint_account_icon,
        );

        let text_y = TAB_BAR_HEIGHT + (ADDRESS_BAR_HEIGHT - ADDRESS_BAR_FONT_SIZE) / 2.0;

        // Selection highlight paints BEHIND the text (plain `fill_rect`
        // overwrites pixels rather than blending), so it has to happen
        // before `paint_text_line` runs, not after.
        if tab.editing_address_bar {
            if let Some((start, end)) = tab.address_bar_selection {
                let x0 = ADDRESS_TEXT_START_X + self.address_bar_prefix_width(start);
                let x1 = ADDRESS_TEXT_START_X + self.address_bar_prefix_width(end);
                let selection_color = render::Color {
                    r: 70,
                    g: 90,
                    b: 150,
                    a: 255,
                };
                canvas.fill_rect(
                    x0,
                    text_y,
                    (x1 - x0).max(1.0),
                    ADDRESS_BAR_FONT_SIZE,
                    selection_color,
                );
            }
        }

        let text_color = render::Color {
            r: 220,
            g: 220,
            b: 220,
            a: 255,
        };
        render::paint_text_line(
            canvas,
            ADDRESS_TEXT_START_X,
            text_y,
            &tab.address_bar_text,
            ADDRESS_BAR_FONT_SIZE,
            text_color,
            &self.font,
        );

        // A real blinking-free cursor: a thin bar at the character
        // boundary `address_bar_cursor` points to. Only drawn when
        // there's no active selection (a selection's own highlight
        // already shows where things stand) and only while editing —
        // there's nothing to place a cursor in otherwise.
        if tab.editing_address_bar && tab.address_bar_selection.is_none() {
            let cursor_x =
                ADDRESS_TEXT_START_X + self.address_bar_prefix_width(tab.address_bar_cursor);
            let cursor_color = render::Color {
                r: 220,
                g: 220,
                b: 220,
                a: 255,
            };
            canvas.fill_rect(cursor_x, text_y, 1.5, ADDRESS_BAR_FONT_SIZE, cursor_color);
        }

        self.paint_page_signals_badge(canvas, tab, text_y);
    }

    /// Right-aligned "JS" / "N aff" transparency badge — see
    /// `ipc::PageSignals`'s own doc comment for what these mean and
    /// don't mean. Silent (paints nothing) whenever there's no page
    /// loaded yet, or the page trips neither signal, so a plain,
    /// script-free page's address bar looks exactly as it always did.
    fn paint_page_signals_badge(&self, canvas: &mut render::Canvas, tab: &Tab, text_y: f32) {
        let Some(signals) = tab.cached_page_signals else {
            return;
        };

        let mut segments: Vec<(String, render::Color)> = Vec::new();
        if signals.uses_javascript {
            segments.push((
                "JS".to_string(),
                render::Color {
                    r: 210,
                    g: 180,
                    b: 90,
                    a: 255,
                },
            ));
        }
        if signals.affiliate_link_count > 0 {
            segments.push((
                format!("{} aff", signals.affiliate_link_count),
                render::Color {
                    r: 210,
                    g: 130,
                    b: 90,
                    a: 255,
                },
            ));
        }
        if segments.is_empty() {
            return;
        }

        let joined = segments
            .iter()
            .map(|(text, _)| text.as_str())
            .collect::<Vec<_>>()
            .join("  ");
        let total_width = text::measure_text_width(&self.font, &joined, ADDRESS_BAR_FONT_SIZE);
        // Right edge is the bookmark button's left edge now, not the
        // raw canvas edge — see `bookmark_button_x`'s doc comment;
        // without this the badge would paint underneath the bookmark/
        // account buttons on a narrow window.
        let right_edge = self.bookmark_button_x() - NAV_BUTTON_MARGIN;
        let mut x = (right_edge - PAGE_SIGNALS_BADGE_MARGIN - total_width).max(0.0);

        for (text, color) in &segments {
            render::paint_text_line(
                canvas,
                x,
                text_y,
                text,
                ADDRESS_BAR_FONT_SIZE,
                *color,
                &self.font,
            );
            x += text::measure_text_width(&self.font, text, ADDRESS_BAR_FONT_SIZE)
                + text::measure_text_width(&self.font, "  ", ADDRESS_BAR_FONT_SIZE);
        }
    }

    /// Paints one square chrome button at `x` (vertically centered in
    /// the address bar row): a background rect — so it actually reads
    /// as a pressable button rather than a bare glyph floating in the
    /// address bar, which is what this whole pass (back/forward/
    /// reload/bookmark/account) is fixing — plus one of `render::icons`'
    /// vector icons centered on top of it. `highlighted` lifts the
    /// background to a lighter shade for a toggled-on state (the
    /// bookmark star once the page is actually bookmarked); every
    /// other state (enabled/disabled, which page signal fired, ...) is
    /// communicated by `icon_color` alone, the same convention this
    /// file's chrome already used before this pass (see e.g.
    /// `paint_page_signals_badge`'s per-signal colors).
    fn paint_chrome_button(
        &self,
        canvas: &mut render::Canvas,
        x: f32,
        highlighted: bool,
        icon_color: render::Color,
        paint_icon: fn(&mut render::Canvas, f32, f32, f32, render::Color),
    ) {
        let y = TAB_BAR_HEIGHT + (ADDRESS_BAR_HEIGHT - NAV_BUTTON_WIDTH) / 2.0;
        let background = if highlighted {
            render::Color {
                r: 55,
                g: 55,
                b: 65,
                a: 255,
            }
        } else {
            render::Color {
                r: 40,
                g: 40,
                b: 40,
                a: 255,
            }
        };
        canvas.fill_rect(x, y, NAV_BUTTON_WIDTH, NAV_BUTTON_WIDTH, background);
        let cx = x + NAV_BUTTON_WIDTH / 2.0;
        let cy = y + NAV_BUTTON_WIDTH / 2.0;
        paint_icon(canvas, cx, cy, NAV_BUTTON_WIDTH * 0.62, icon_color);
    }

    /// Right-aligned account-button position — the account/bookmark
    /// buttons sit at the far right of the address bar row (mirroring
    /// `BACK_BUTTON_X`/`FORWARD_BUTTON_X`'s fixed-from-the-left-edge
    /// layout), but can't be `const` themselves since they depend on
    /// the live `canvas_width`. A method (used identically by painting
    /// and by `handle_click`) keeps the two from drifting apart, the
    /// same guarantee the left-side constants document for themselves.
    fn account_button_x(&self) -> f32 {
        self.canvas_width as f32 - NAV_BUTTON_MARGIN - NAV_BUTTON_WIDTH
    }

    /// Sits immediately left of the account button — see
    /// `account_button_x`'s doc comment.
    fn bookmark_button_x(&self) -> f32 {
        self.account_button_x() - NAV_BUTTON_MARGIN - NAV_BUTTON_WIDTH
    }

    /// Pixel width of the first `char_count` characters of the address
    /// bar's text, at the address bar's own font size — the building
    /// block both the cursor and the selection highlight use to turn a
    /// character index into an x coordinate.
    fn address_bar_prefix_width(&self, char_count: usize) -> f32 {
        let prefix: String = self
            .active_tab()
            .address_bar_text
            .chars()
            .take(char_count)
            .collect();
        text::measure_text_width(&self.font, &prefix, ADDRESS_BAR_FONT_SIZE)
    }

    fn handle_event(&mut self, event: InputEvent) -> Option<Frame> {
        match event {
            InputEvent::Resized { width, height } => {
                // Fingerprint resistance carries over into the
                // interactive window too: at the default `Strict`
                // level, every size actually laid out against is
                // letterboxed to a fixed bucket first, not the exact
                // continuous pixel size the OS reports mid-drag (see
                // `privacy::FingerprintResistanceLevel`) — the
                // Settings page controls this.
                let (canvas_width, canvas_height) = self
                    .fingerprint_resistance
                    .resolve_window_size(width, height);
                self.canvas_width = canvas_width;
                self.canvas_height = canvas_height;
                self.relayout();
                Some(self.frame(None))
            }

            InputEvent::MouseMoved { .. } => {
                // No hover effects in this minimal scope — `None`
                // means the caller does ZERO GPU work for this event,
                // which matters a lot given how often it fires (every
                // pixel of cursor movement). Returning a cloned
                // `Frame` here instead (an earlier version of this
                // code did) still triggered a full texture re-upload
                // on every single mouse-move, which is what caused a
                // real system-freezing resource spike — see
                // render/src/window.rs's `run_window` doc comment.
                None
            }

            InputEvent::MouseClick { x, y } => self.handle_click(x, y),

            InputEvent::Scroll { delta_y } => {
                if self.active_tab().devtools_open {
                    // See `Tab::console_scroll_rows`'s own doc comment
                    // on why the DevTools panel unconditionally captures
                    // scroll input while open, rather than only when the
                    // pointer happens to be over it (this codebase
                    // tracks no mouse position at all).
                    self.scroll_devtools_panel(delta_y);
                } else {
                    self.active_tab_mut().scroll_y += delta_y;
                    self.clamp_scroll();
                }
                Some(self.frame(None))
            }

            InputEvent::CharTyped(c) => {
                if self.active_tab().console_input_focused {
                    self.active_tab_mut().console_input.push(c);
                    return Some(self.frame(None));
                }
                if self.active_tab().finding_in_page {
                    self.active_tab_mut().find_query.push(c);
                    self.refresh_find_matches();
                    return Some(self.frame(None));
                }
                if self.active_tab().editing_address_bar {
                    self.active_tab_mut().insert_into_address_bar(c);
                    return Some(self.frame(None));
                }
                if self.active_tab().focused_page_input.is_some() {
                    return self.send_text_input_to_focused_page_input(
                        ipc::TextInputAction::InsertChar(c),
                    );
                }
                // Space activates whatever keyboard focus (see
                // `Tab::keyboard_focus`) is on, when that ISN'T a text
                // input (the branch just above already handles that
                // case — a literal space character) — real HTML
                // behavior for a focused button/link/checkbox.
                if c == ' ' && self.active_tab().keyboard_focus.is_some() {
                    return self.activate_page_keyboard_focus();
                }
                Some(self.frame(None))
            }

            InputEvent::Backspace => {
                if self.active_tab().console_input_focused {
                    self.active_tab_mut().console_input.pop();
                    return Some(self.frame(None));
                }
                if self.active_tab().finding_in_page {
                    self.active_tab_mut().find_query.pop();
                    self.refresh_find_matches();
                    return Some(self.frame(None));
                }
                let tab = self.active_tab_mut();
                if tab.editing_address_bar {
                    if !tab.delete_address_bar_selection() && tab.address_bar_cursor > 0 {
                        let delete_at = tab.address_bar_cursor - 1;
                        let start_b = text::char_byte_offset(&tab.address_bar_text, delete_at);
                        let end_b =
                            text::char_byte_offset(&tab.address_bar_text, tab.address_bar_cursor);
                        tab.address_bar_text.replace_range(start_b..end_b, "");
                        tab.address_bar_cursor = delete_at;
                    }
                    return Some(self.frame(None));
                }
                if self.active_tab().focused_page_input.is_some() {
                    return self
                        .send_text_input_to_focused_page_input(ipc::TextInputAction::Backspace);
                }
                Some(self.frame(None))
            }

            InputEvent::ArrowLeft => {
                let tab = self.active_tab_mut();
                if tab.editing_address_bar {
                    tab.address_bar_selection = None;
                    tab.address_bar_cursor = tab.address_bar_cursor.saturating_sub(1);
                    return Some(self.frame(None));
                }
                if tab.focused_page_input.is_some() {
                    return self
                        .send_text_input_to_focused_page_input(ipc::TextInputAction::ArrowLeft);
                }
                None
            }

            InputEvent::ArrowRight => {
                let tab = self.active_tab_mut();
                if tab.editing_address_bar {
                    tab.address_bar_selection = None;
                    let len = tab.address_bar_text.chars().count();
                    tab.address_bar_cursor = (tab.address_bar_cursor + 1).min(len);
                    return Some(self.frame(None));
                }
                if tab.focused_page_input.is_some() {
                    return self
                        .send_text_input_to_focused_page_input(ipc::TextInputAction::ArrowRight);
                }
                None
            }

            InputEvent::Home => {
                let tab = self.active_tab_mut();
                if tab.editing_address_bar {
                    tab.address_bar_selection = None;
                    tab.address_bar_cursor = 0;
                    return Some(self.frame(None));
                }
                if tab.focused_page_input.is_some() {
                    return self.send_text_input_to_focused_page_input(ipc::TextInputAction::Home);
                }
                None
            }

            InputEvent::End => {
                let tab = self.active_tab_mut();
                if tab.editing_address_bar {
                    tab.address_bar_selection = None;
                    tab.address_bar_cursor = tab.address_bar_text.chars().count();
                    return Some(self.frame(None));
                }
                if tab.focused_page_input.is_some() {
                    return self.send_text_input_to_focused_page_input(ipc::TextInputAction::End);
                }
                None
            }

            InputEvent::NavigateBack => {
                self.active_tab_mut().editing_address_bar = false;
                self.go_back();
                Some(self.frame(Some(self.window_title())))
            }

            InputEvent::NavigateForward => {
                self.active_tab_mut().editing_address_bar = false;
                self.go_forward();
                Some(self.frame(Some(self.window_title())))
            }

            InputEvent::Reload => {
                self.active_tab_mut().editing_address_bar = false;
                self.reload();
                Some(self.frame(Some(self.window_title())))
            }

            InputEvent::ToggleBookmark => {
                self.toggle_bookmark_current_page();
                Some(self.frame(None))
            }

            InputEvent::NewTab => {
                self.open_new_tab();
                Some(self.frame(Some(self.window_title())))
            }

            InputEvent::CloseTab => {
                self.close_tab(self.active_tab_index);
                Some(self.frame(Some(self.window_title())))
            }

            InputEvent::NextTab => {
                self.active_tab_index = (self.active_tab_index + 1) % self.tabs.len();
                Some(self.frame(Some(self.window_title())))
            }

            InputEvent::FocusNext => self.handle_focus_move(ipc::FocusDirection::Next),
            InputEvent::FocusPrevious => self.handle_focus_move(ipc::FocusDirection::Previous),

            InputEvent::PreviousTab => {
                self.active_tab_index =
                    (self.active_tab_index + self.tabs.len() - 1) % self.tabs.len();
                Some(self.frame(Some(self.window_title())))
            }

            InputEvent::Find => {
                self.enter_find_mode();
                Some(self.frame(None))
            }

            InputEvent::ToggleDevTools => {
                let now_open = !self.active_tab().devtools_open;
                self.active_tab_mut().devtools_open = now_open;
                if !now_open {
                    // Closing takes back the keyboard focus/pick-mode
                    // it might have held, and gives the page's own
                    // viewport its full height back immediately.
                    self.active_tab_mut().console_input_focused = false;
                    self.active_tab_mut().devtools_picking = false;
                } else if self.active_tab().devtools_tab == DevtoolsTab::Elements {
                    self.refresh_dom_snapshot();
                }
                self.clamp_scroll();
                Some(self.frame(None))
            }

            InputEvent::AccessibilityAction(request) => self.handle_accessibility_action(request),

            InputEvent::FindPrevious => {
                if self.active_tab().finding_in_page {
                    self.find_previous();
                }
                Some(self.frame(None))
            }

            InputEvent::Enter => {
                if self.active_tab().console_input_focused {
                    return self.submit_devtools_console_input();
                }
                if self.active_tab().finding_in_page {
                    self.find_next();
                    return Some(self.frame(None));
                }
                if self.active_tab().editing_address_bar {
                    self.active_tab_mut().editing_address_bar = false;
                    let typed = self.active_tab().address_bar_text.trim().to_string();
                    if typed.eq_ignore_ascii_case("bookmark") {
                        self.bookmark_current_page();
                        let url = self.active_tab().current_url.clone();
                        self.active_tab_mut().set_address_bar_text(url);
                    } else if typed.eq_ignore_ascii_case("bookmarks") {
                        self.load_bookmarks_page();
                    } else if typed.eq_ignore_ascii_case("settings") {
                        self.load_settings_page();
                    } else if typed.eq_ignore_ascii_case("history") {
                        self.load_history_page();
                    } else if typed.eq_ignore_ascii_case("downloads") {
                        self.load_downloads_page();
                    } else if typed.eq_ignore_ascii_case("account") {
                        self.load_account_page();
                    } else if typed.eq_ignore_ascii_case("back") {
                        self.go_back();
                        let url = self.active_tab().current_url.clone();
                        self.active_tab_mut().set_address_bar_text(url);
                    } else if typed.eq_ignore_ascii_case("forward") {
                        self.go_forward();
                        let url = self.active_tab().current_url.clone();
                        self.active_tab_mut().set_address_bar_text(url);
                    } else if let Some((_, rest)) = typed
                        .split_once(' ')
                        .filter(|(cmd, _)| cmd.eq_ignore_ascii_case("set"))
                    {
                        self.handle_set_command(rest.trim());
                    } else {
                        self.navigate(&normalize_typed_url(&typed));
                    }
                    return Some(self.frame(Some(self.window_title())));
                }
                if self.active_tab().focused_page_input.is_some() {
                    return self.send_text_input_to_focused_page_input(ipc::TextInputAction::Enter);
                }
                if self.active_tab().keyboard_focus.is_some() {
                    return self.activate_page_keyboard_focus();
                }
                Some(self.frame(None))
            }

            InputEvent::Escape => {
                if self.active_tab().console_input_focused {
                    self.active_tab_mut().console_input_focused = false;
                } else if self.active_tab().finding_in_page {
                    self.exit_find_mode();
                } else if self.active_tab().editing_address_bar {
                    self.active_tab_mut().editing_address_bar = false;
                    let url = self.active_tab().current_url.clone();
                    self.active_tab_mut().set_address_bar_text(url);
                } else if self.active_tab().focused_page_input.is_some() {
                    // Real browsers don't standardize an Escape action
                    // inside a plain text field beyond "stop editing it"
                    // — unlike the address bar (which also reverts to
                    // the loaded URL), a page input just loses focus,
                    // keeping whatever was typed.
                    self.blur_page_input_if_focused();
                }
                Some(self.frame(None))
            }

            InputEvent::Tick => {
                // `handle_tick` always returns `true` when anything was
                // actually due (see its own doc comment for why this
                // has to produce a `Frame` even when nothing VISIBLE
                // changed — it's the only way to re-arm the window's
                // wake-up deadline). A spurious `Tick` with nothing due
                // (there shouldn't be one, but see `render::window`'s
                // module docs on why this can't be guaranteed absolutely)
                // is a harmless no-op: `None` here just means "nothing
                // to do, and nothing new to schedule either."
                if self.handle_tick() {
                    let title = if self.active_tab().editing_address_bar {
                        None
                    } else {
                        Some(self.window_title())
                    };
                    Some(self.frame(title))
                } else {
                    None
                }
            }
        }
    }

    /// Opens this tab's find-in-page bar (`Ctrl+F`) — mutually
    /// exclusive with address-bar editing and a focused page input:
    /// opening find cancels an in-progress address-bar edit (reverting
    /// it to the loaded URL, same as clicking the page does — see
    /// `handle_click`) and blurs any focused page input, the same way
    /// switching between any two of this browser's "what do keystrokes
    /// go to right now" modes always does. A no-op beyond that if
    /// already open (typing already works regardless).
    fn enter_find_mode(&mut self) {
        if self.active_tab().editing_address_bar {
            self.active_tab_mut().editing_address_bar = false;
            let url = self.active_tab().current_url.clone();
            self.active_tab_mut().set_address_bar_text(url);
        }
        self.blur_page_input_if_focused();
        self.active_tab_mut().console_input_focused = false;
        self.active_tab_mut().finding_in_page = true;
    }

    /// Closes the find bar and forgets its query/matches entirely —
    /// pressing `Ctrl+F` again afterward starts a fresh, empty search
    /// rather than remembering the last one, matching most real
    /// browsers' find bars (which also clear on close).
    fn exit_find_mode(&mut self) {
        let tab = self.active_tab_mut();
        tab.finding_in_page = false;
        tab.find_query.clear();
        tab.find_matches.clear();
        tab.find_current_index = 0;
    }

    /// Stops (drops) every live playback stream for the ACTIVE tab and
    /// clears its cached PCM/position/mute state entirely — called
    /// whenever that tab navigates to a new page (real browsers stop
    /// playing media on navigation too), since a fresh page's media
    /// elements are entirely different DOM nodes; nothing meaningfully
    /// carries over, the same reasoning `exit_find_mode` already
    /// applies to stale find-in-page state on navigation.
    fn stop_all_media_playback(&mut self) {
        let tab = self.active_tab_mut();
        tab.active_playback.clear();
        tab.media_pcm_cache.clear();
        tab.media_position.clear();
        tab.media_muted.clear();
        tab.next_media_tick_at = None;
    }

    /// Clears everything about the DevTools panel that's scoped to the
    /// PAGE that's being left, not the panel itself — the console log
    /// (a fresh page's script hasn't logged anything yet), the DOM
    /// snapshot (it described the OLD page's tree), the selected node,
    /// the console's own in-progress input and scroll positions, and
    /// picker mode. Deliberately does NOT touch `devtools_open`/
    /// `devtools_tab` — a real browser's DevTools stays open across a
    /// navigation, same reasoning `stop_all_media_playback` already
    /// documents for why ITS state doesn't carry over either.
    fn reset_devtools_page_state(&mut self) {
        let tab = self.active_tab_mut();
        tab.console_log.clear();
        tab.console_input.clear();
        tab.console_input_focused = false;
        tab.console_scroll_rows = 0;
        tab.dom_snapshot = None;
        tab.devtools_selected_node = None;
        tab.elements_tree_scroll_rows = 0;
        tab.devtools_picking = false;
    }

    /// Recomputes the active tab's `find_matches` from its CURRENT
    /// query against its CURRENT page, jumps back to the first match,
    /// and scrolls it into view — called on every query edit (see the
    /// `CharTyped`/`Backspace` arms above), so the find bar's "N of M"
    /// count and highlighting stay live as the user types, the same way
    /// a real browser's does.
    fn refresh_find_matches(&mut self) {
        let query = self.active_tab().find_query.clone();
        let matches =
            render::find_matches_in_tree(&self.active_tab().layout_tree, &query, &self.font);
        let tab = self.active_tab_mut();
        tab.find_matches = matches;
        tab.find_current_index = 0;
        self.scroll_to_current_find_match();
    }

    /// Scrolls so the active tab's CURRENT match (`find_current_index`)
    /// is roughly vertically centered in the viewport — a no-op if
    /// there are no matches at all (nothing to scroll to).
    fn scroll_to_current_find_match(&mut self) {
        let tab = self.active_tab();
        let Some(rect) = tab.find_matches.get(tab.find_current_index).copied() else {
            return;
        };
        let viewport_height =
            (self.canvas_height as f32 - CHROME_HEIGHT - self.devtools_reserved_height()).max(0.0);
        let target_scroll = (rect.y - viewport_height / 2.0).max(0.0);
        self.active_tab_mut().scroll_y = target_scroll;
        self.clamp_scroll();
    }

    /// Cycles to the next match (wrapping past the last back to the
    /// first) and scrolls it into view — `Enter` while the find bar is
    /// focused. A no-op when there are no matches.
    fn find_next(&mut self) {
        let tab = self.active_tab_mut();
        if tab.find_matches.is_empty() {
            return;
        }
        tab.find_current_index = (tab.find_current_index + 1) % tab.find_matches.len();
        self.scroll_to_current_find_match();
    }

    /// Same as `find_next`, but backwards — `Shift+Enter`
    /// (`InputEvent::FindPrevious`) while the find bar is focused.
    fn find_previous(&mut self) {
        let tab = self.active_tab_mut();
        if tab.find_matches.is_empty() {
            return;
        }
        tab.find_current_index =
            (tab.find_current_index + tab.find_matches.len() - 1) % tab.find_matches.len();
        self.scroll_to_current_find_match();
    }

    /// Sends `Blur` for the active tab and clears its own
    /// `focused_page_input` — a no-op (no message sent at all) when
    /// nothing was focused to begin with. Any result render (the
    /// cursor disappearing) is applied but not surfaced as a `Frame`
    /// here — callers that need a fresh paint already return one of
    /// their own right after calling this.
    fn blur_page_input_if_focused(&mut self) {
        let Some(_dom_node_id) = self.active_tab().focused_page_input else {
            return;
        };
        let tab_id = self.active_tab().id;
        self.active_tab_mut().focused_page_input = None;
        // `Blur` clears the renderer's OWN `Session.focused` too (see
        // that field's own doc comment on its broadened, any-element
        // meaning) — mirroring that here keeps `keyboard_focus` from
        // pointing at a node the renderer no longer considers focused
        // at all.
        self.active_tab_mut().keyboard_focus = None;
        if let Some(site) = self.active_tab().renderer_site.clone() {
            if let Some(renderer) = self.renderers.get(&site) {
                let outcome = renderer.blur(tab_id);
                let now = std::time::Instant::now();
                self.apply_server_message_kind_to_tab(tab_id, outcome, now);
            }
        }
    }

    /// `Tab` (`ipc::FocusDirection::Next`) / `Shift+Tab` (`Previous`) —
    /// moves keyboard focus among the PAGE's own real focusable
    /// elements (see `ipc::ClientMessageKind::MoveKeyboardFocus`'s own
    /// doc comment). A harmless no-op while any browser-chrome text
    /// field (the address bar, find bar, or DevTools console) has
    /// keyboard focus instead — real Tab behavior there would mean
    /// moving focus OUT to some other piece of UI, which this browser
    /// has no broader focus-traversal model for at all; leaving the
    /// keystroke to do nothing is safer than moving PAGE focus out from
    /// under a chrome text field the user is actively typing into.
    fn handle_focus_move(&mut self, direction: ipc::FocusDirection) -> Option<Frame> {
        if self.active_tab().editing_address_bar
            || self.active_tab().finding_in_page
            || self.active_tab().console_input_focused
        {
            return Some(self.frame(None));
        }
        let tab_id = self.active_tab().id;
        let Some(site) = self.active_tab().renderer_site.clone() else {
            return Some(self.frame(None));
        };
        let Some(renderer) = self.renderers.get(&site) else {
            return Some(self.frame(None));
        };
        let outcome = renderer.move_keyboard_focus(tab_id, direction);
        let now = std::time::Instant::now();
        self.apply_server_message_kind_to_tab(tab_id, outcome, now);
        self.sync_page_keyboard_focus();
        self.clamp_scroll();
        Some(self.frame(None))
    }

    /// Reconciles `Tab::keyboard_focus`/`focused_page_input` with
    /// wherever the renderer's own `script::Session::focused` actually
    /// landed after the last render (see `layout::LayoutBox::focused`'s
    /// own doc comment) — called after anything that could have moved
    /// it: `Tab`/`Shift+Tab`, or activating a focused element (which
    /// can itself change focus, e.g. a link navigating to a whole new
    /// page). `app` never tracks a NodeId across messages on faith;
    /// the layout tree it just received back IS the answer.
    fn sync_page_keyboard_focus(&mut self) {
        let tab = self.active_tab();
        let focused_id = layout::find_focused_dom_node_id(&tab.layout_tree);
        let is_text_input = focused_id
            .and_then(|id| find_layout_box_by_id(&tab.layout_tree, id))
            .is_some_and(|b| b.text_input.is_some());
        let tab = self.active_tab_mut();
        tab.keyboard_focus = focused_id;
        tab.focused_page_input = if is_text_input { focused_id } else { None };
    }

    /// `Enter`/`Space` pressed while `Tab::keyboard_focus` names
    /// something other than a text-like input (see
    /// `Browser::handle_event`'s own `Enter`/`CharTyped` arms for
    /// exactly when this is reached instead of the normal text-input
    /// path) — sends `ActivateFocused`, then, if the resulting `click`
    /// wasn't prevented and landed on a real link, follows it exactly
    /// the way `handle_click` follows a mouse-clicked one (respecting
    /// `download`, `javascript:`/`mailto:`/etc. non-navigable hrefs —
    /// see `is_navigable_href`). A harmless no-op if nothing is
    /// focused, or this tab has no live renderer session.
    fn activate_page_keyboard_focus(&mut self) -> Option<Frame> {
        let Some(node_id) = self.active_tab().keyboard_focus else {
            return Some(self.frame(None));
        };
        let tab_id = self.active_tab().id;
        let Some(site) = self.active_tab().renderer_site.clone() else {
            return Some(self.frame(None));
        };
        let Some(renderer) = self.renderers.get(&site) else {
            return Some(self.frame(None));
        };
        let outcome = renderer.activate_focused(tab_id);
        let default_prevented = matches!(
            &outcome,
            ipc::ServerMessageKind::Rendered(success) if success.default_prevented
        );
        let now = std::time::Instant::now();
        self.apply_server_message_kind_to_tab(tab_id, outcome, now);
        self.sync_page_keyboard_focus();
        self.clamp_scroll();

        if !default_prevented {
            if let Some(frame) = self.follow_link_if_any(node_id) {
                return Some(frame);
            }
        }

        Some(self.frame(Some(self.window_title())))
    }

    /// Follows `node_id`'s own `<a href>`, if it is one — the SAME
    /// download-vs-navigate/`is_navigable_href` logic `handle_click`
    /// has inline for a mouse click, factored out since both
    /// `activate_page_keyboard_focus` and a real assistive
    /// technology's `accesskit::Action::Default` (see
    /// `handle_accessibility_action`) need to do exactly the same
    /// thing given only a target node id, not a click position.
    /// `None` when `node_id` isn't a link at all (the caller's own
    /// default action, if any, still applies).
    fn follow_link_if_any(&mut self, node_id: dom::NodeId) -> Option<Frame> {
        let b = find_layout_box_by_id(&self.active_tab().layout_tree, node_id)?;
        let dom::NodeType::Element(el) = &b.node_type else {
            return None;
        };
        if el.tag_name != "a" {
            return None;
        }
        if let Some(download_hint) = el.attributes.get("download").cloned() {
            if let Some(href) = el.attributes.get("href") {
                let resolved = resolve_url(&self.active_tab().current_url, href);
                self.download(&resolved, &download_hint);
                return Some(self.frame(Some(self.window_title())));
            }
            return None;
        }
        let href = el.attributes.get("href")?;
        if is_navigable_href(href) {
            let resolved = resolve_url(&self.active_tab().current_url, href);
            self.navigate(&resolved);
            return Some(self.frame(Some(self.window_title())));
        }
        None
    }

    /// Handles one `accesskit::ActionRequest` from a real assistive
    /// technology — see `render::window::InputEvent::AccessibilityAction`'s
    /// own doc comment. Only `Focus` and `Default` (real HTML's
    /// "typically click") are meaningfully supported today; every
    /// other `accesskit::Action` (scrolling, text selection, custom
    /// actions, ...) is a harmless no-op — this browser's accessible
    /// tree (see `accessibility::build_tree_update`) never advertises
    /// support for any of those via `NodeBuilder::add_action`, so a
    /// well-behaved AT shouldn't send them at all; this is just the
    /// safe fallback if one does anyway.
    fn handle_accessibility_action(&mut self, request: accesskit::ActionRequest) -> Option<Frame> {
        let node_id = dom::NodeId(request.target.0);
        match request.action {
            accesskit::Action::Focus => {
                let tab_id = self.active_tab().id;
                let Some(site) = self.active_tab().renderer_site.clone() else {
                    return Some(self.frame(None));
                };
                let Some(renderer) = self.renderers.get(&site) else {
                    return Some(self.frame(None));
                };
                let outcome = renderer.focus_node(tab_id, node_id);
                let now = std::time::Instant::now();
                self.apply_server_message_kind_to_tab(tab_id, outcome, now);
                self.sync_page_keyboard_focus();
                self.clamp_scroll();
                Some(self.frame(None))
            }
            accesskit::Action::Default => {
                let tab_id = self.active_tab().id;
                let Some(site) = self.active_tab().renderer_site.clone() else {
                    return Some(self.frame(None));
                };
                let Some(renderer) = self.renderers.get(&site) else {
                    return Some(self.frame(None));
                };
                let outcome = renderer.click(tab_id, node_id);
                let default_prevented = matches!(
                    &outcome,
                    ipc::ServerMessageKind::Rendered(success) if success.default_prevented
                );
                let now = std::time::Instant::now();
                self.apply_server_message_kind_to_tab(tab_id, outcome, now);
                self.clamp_scroll();
                if !default_prevented {
                    if let Some(frame) = self.follow_link_if_any(node_id) {
                        return Some(frame);
                    }
                }
                Some(self.frame(Some(self.window_title())))
            }
            _ => Some(self.frame(None)),
        }
    }

    /// Routes one keystroke to whatever text input currently has focus
    /// on the PAGE itself (not the address bar) — `None` if nothing is
    /// focused there, so every `handle_event` keyboard arm can fall
    /// back to its own existing "address bar or nothing" behavior with
    /// a single extra check. Applies the resulting render, and — only
    /// for `Enter` — navigates to `RenderSuccess::submit_url` when the
    /// renderer reports one (a real, un-prevented form submission —
    /// see that field's own doc comment; `submit_body` decides whether
    /// this is a GET or a real POST).
    fn send_text_input_to_focused_page_input(
        &mut self,
        action: ipc::TextInputAction,
    ) -> Option<Frame> {
        let _dom_node_id = self.active_tab().focused_page_input?;
        let tab_id = self.active_tab().id;
        let site = self.active_tab().renderer_site.clone()?;
        let renderer = self.renderers.get(&site)?;
        let outcome = renderer.text_input(tab_id, action);

        let (submit_url, submit_body) = match &outcome {
            ipc::ServerMessageKind::Rendered(success) => {
                (success.submit_url.clone(), success.submit_body.clone())
            }
            _ => (None, None),
        };
        let now = std::time::Instant::now();
        self.apply_server_message_kind_to_tab(tab_id, outcome, now);
        self.clamp_scroll();

        if let Some(url) = submit_url {
            // A real navigation replaces the whole page — whatever was
            // focused on it means nothing afterward.
            self.active_tab_mut().focused_page_input = None;
            match submit_body {
                Some(body) => self.navigate_with_body(&url, body),
                None => self.navigate(&url),
            }
            return Some(self.frame(Some(self.window_title())));
        }

        Some(self.frame(None))
    }

    fn handle_click(&mut self, x: f32, y: f32) -> Option<Frame> {
        if y < TAB_BAR_HEIGHT {
            return self.handle_tab_bar_click(x);
        }

        if y < CHROME_HEIGHT {
            // Chrome (the address bar, nav buttons) always takes focus
            // away from any page input — a click up here is never
            // itself a page interaction.
            self.blur_page_input_if_focused();
            self.active_tab_mut().console_input_focused = false;

            if (BACK_BUTTON_X..BACK_BUTTON_X + NAV_BUTTON_WIDTH).contains(&x) {
                self.active_tab_mut().editing_address_bar = false;
                self.go_back();
                return Some(self.frame(Some(self.window_title())));
            }
            if (FORWARD_BUTTON_X..FORWARD_BUTTON_X + NAV_BUTTON_WIDTH).contains(&x) {
                self.active_tab_mut().editing_address_bar = false;
                self.go_forward();
                return Some(self.frame(Some(self.window_title())));
            }
            if (RELOAD_BUTTON_X..RELOAD_BUTTON_X + NAV_BUTTON_WIDTH).contains(&x) {
                self.active_tab_mut().editing_address_bar = false;
                self.reload();
                return Some(self.frame(Some(self.window_title())));
            }
            let bookmark_x = self.bookmark_button_x();
            if (bookmark_x..bookmark_x + NAV_BUTTON_WIDTH).contains(&x) {
                self.active_tab_mut().editing_address_bar = false;
                self.toggle_bookmark_current_page();
                return Some(self.frame(None));
            }
            let account_x = self.account_button_x();
            if (account_x..account_x + NAV_BUTTON_WIDTH).contains(&x) {
                self.active_tab_mut().editing_address_bar = false;
                self.load_account_page();
                return Some(self.frame(Some(self.window_title())));
            }

            if self.active_tab().editing_address_bar {
                // Already focused: a second click positions the cursor
                // under the pointer instead of re-selecting everything —
                // matches how every real text field behaves once it
                // already has focus.
                let click_x = x - ADDRESS_TEXT_START_X;
                let index = self.char_index_for_x(click_x);
                let tab = self.active_tab_mut();
                tab.address_bar_cursor = index;
                tab.address_bar_selection = None;
            } else {
                // First click focuses the bar and selects all of its
                // text, so the very next keystroke replaces the whole
                // (likely stale) URL rather than appending to it — see
                // `address_bar_selection`'s doc comment for the bug this
                // fixes.
                let tab = self.active_tab_mut();
                tab.editing_address_bar = true;
                let len = tab.address_bar_text.chars().count();
                tab.address_bar_cursor = len;
                tab.address_bar_selection = if len > 0 { Some((0, len)) } else { None };
            }
            return Some(self.frame(None));
        }

        // The DevTools panel (`F12`) is bottom-DOCKED, not an overlay
        // like the find bar — a click anywhere in its band is ALWAYS a
        // DevTools interaction, never page content, checked before
        // anything else below (including address-bar-edit cancellation,
        // which a devtools click shouldn't trigger either).
        let devtools_panel_top = self.canvas_height as f32 - self.devtools_reserved_height();
        if self.active_tab().devtools_open && y >= devtools_panel_top {
            return self.handle_devtools_click(x, y - devtools_panel_top);
        }

        let was_editing = self.active_tab().editing_address_bar;
        self.active_tab_mut().editing_address_bar = false;
        self.active_tab_mut().console_input_focused = false;
        if was_editing {
            // Clicking the page while editing cancels the edit,
            // reverting to whatever's actually loaded.
            let url = self.active_tab().current_url.clone();
            self.active_tab_mut().set_address_bar_text(url);
        }

        // Convert the click back into the layout tree's own
        // (un-scrolled) coordinate space — the inverse of the offset
        // `repaint` applies when painting (see its comment).
        let content_y = y - CHROME_HEIGHT + self.active_tab().scroll_y;

        // DevTools "Pick an element" mode (armed from the Elements tab)
        // takes over the VERY NEXT page click entirely — no link
        // navigation, no JS `click` dispatch, no media controls, just
        // "which element did this hit" — see `Tab::devtools_picking`'s
        // own doc comment.
        if self.active_tab().devtools_picking {
            self.active_tab_mut().devtools_picking = false;
            if let Some(node_id) =
                layout::hit_test_node(&self.active_tab().layout_tree, x, content_y)
            {
                self.active_tab_mut().devtools_selected_node = Some(node_id);
            }
            return Some(self.frame(None));
        }

        // A media element's own native `controls` bar (see
        // `layout::hit_test_media_control`'s doc comment on why this
        // never goes through JS `click` dispatch at all) — checked
        // before general link hit-testing since it's the same category
        // of "local browser chrome, not a page interaction" special
        // case as `settings:`/`history:` below.
        if let Some((dom_node_id, control_hit)) =
            layout::hit_test_media_control(&self.active_tab().layout_tree, x, content_y)
        {
            self.handle_media_control_click(dom_node_id, control_hit);
            return Some(self.frame(Some(self.window_title())));
        }

        let hit = layout::hit_test_link(&self.active_tab().layout_tree, x, content_y);
        let href = hit.as_ref().map(|h| h.href.clone());

        // A settings-page pseudo-link (see `render_settings_html`) is
        // handled entirely locally and never was a real page
        // interaction to begin with (same category of special case as
        // `mailto:`/`tel:`/`javascript:` in `is_navigable_href`, just
        // one that actually does something) — it short-circuits before
        // any JS dispatch, same as always.
        if let Some(command) = href.as_deref().and_then(|h| h.strip_prefix("settings:")) {
            self.handle_settings_link(command);
            return Some(self.frame(Some(self.window_title())));
        }

        // Same category of local-only pseudo-link as `settings:` above —
        // the history page's one interactive element (see
        // `render_history_html`).
        if href.as_deref() == Some("history:clear") {
            self.bookmarks.clear_history();
            save_bookmarks(&self.account, &self.bookmarks, &self.data_dir);
            self.sync_push();
            self.load_history_page_without_history();
            return Some(self.frame(Some(self.window_title())));
        }

        // Same category of local-only pseudo-link as `settings:`/
        // `history:clear` above — the account page's one interactive
        // element (see `render_account_html`). `sync_pull` (rather
        // than `sync_push`) is the right single call for a manual
        // "sync now": it merges the server's data in AND pushes back
        // any local-only changes that merge produced (see its own doc
        // comment), so this one link covers both directions.
        if href.as_deref() == Some("account:sync") {
            self.sync_pull();
            self.load_account_page_without_history();
            return Some(self.frame(Some(self.window_title())));
        }

        // Dispatch the real `click` event FIRST — see
        // `ipc::ClientMessageKind::Click`'s and `renderer::script`'s
        // module docs — and only THEN decide whether to still perform
        // the click's default action (link navigation), based on
        // whether any listener called `event.preventDefault()`. An
        // earlier version of this method decided "is this a link
        // click?" up front and skipped JS dispatch entirely for one,
        // which made `preventDefault` structurally unable to ever
        // cancel a navigation — exactly backwards from how a real
        // browser's event loop works.
        let mut default_prevented = false;
        let mut content_changed = false;
        let mut submit_url = None;
        let mut submit_body = None;
        let clicked_node_id = layout::hit_test_node(&self.active_tab().layout_tree, x, content_y);
        // Checked against the layout tree `app` ALREADY has, from
        // before this click dispatches — a text input's own box never
        // changes shape as a *result* of a plain `click` listener in
        // any way that would matter here (it's still the same input
        // either way), so there's no need to wait for a fresh render
        // just to decide whether to also focus it.
        let clicked_is_text_input = clicked_node_id.is_some_and(|id| {
            find_layout_box_by_id(&self.active_tab().layout_tree, id)
                .is_some_and(|b| b.text_input.is_some())
        });

        if let Some(dom_node_id) = clicked_node_id {
            let tab_id = self.active_tab().id;
            // A click only ever dispatches into the process the ACTIVE
            // tab's session already lives in — no `renderer_site` means
            // no live session to dispatch to at all (e.g. an `about:`
            // page's own elements, which are never renderer-backed —
            // see `leave_renderer_backed_page`), same as a `Click` the
            // renderer itself couldn't resolve a session for.
            if let Some(site) = self.active_tab().renderer_site.clone() {
                if let Some(renderer) = self.renderers.get(&site) {
                    let outcome = renderer.click(tab_id, dom_node_id);
                    if let ipc::ServerMessageKind::Rendered(success) = &outcome {
                        default_prevented = success.default_prevented;
                        submit_url = success.submit_url.clone();
                        submit_body = success.submit_body.clone();
                    }
                    let now = std::time::Instant::now();
                    content_changed = self.apply_server_message_kind_to_tab(tab_id, outcome, now);
                }
            }
        }

        // Focus/blur happens AFTER the click itself dispatches (real
        // browsers do both, but the click listener runs first) — see
        // `ipc::ClientMessageKind::Focus`'s own doc comment for why
        // `x` (unmodified — only vertical position is affected by
        // scroll/chrome, per `render::window`'s own module docs on
        // there being no horizontal scrolling at all) is exactly the
        // coordinate the renderer needs.
        if clicked_is_text_input {
            if let Some(dom_node_id) = clicked_node_id {
                let tab_id = self.active_tab().id;
                if let Some(site) = self.active_tab().renderer_site.clone() {
                    if let Some(renderer) = self.renderers.get(&site) {
                        let outcome = renderer.focus(tab_id, dom_node_id, x);
                        let now = std::time::Instant::now();
                        if self.apply_server_message_kind_to_tab(tab_id, outcome, now) {
                            content_changed = true;
                        }
                        self.active_tab_mut().focused_page_input = Some(dom_node_id);
                        // Keeps `keyboard_focus` (the broader, any-
                        // element notion — see its own doc comment) in
                        // sync with the renderer's `Session.focused`,
                        // which the `focus` call just above ALSO set to
                        // this same node — so a later `Tab` continues
                        // from wherever the user last clicked, and
                        // Enter/Space would (harmlessly) fall through
                        // to the normal text-input path rather than an
                        // unrelated stale activation target.
                        self.active_tab_mut().keyboard_focus = Some(dom_node_id);
                    }
                }
            }
        } else {
            self.blur_page_input_if_focused();
        }

        if !default_prevented {
            // A submit-button click resolving to a real form
            // submission (see `ipc::ClientMessageKind::Click`'s own
            // doc comment) — checked before link navigation below
            // since a submit control is never ALSO a link, but placed
            // here (rather than earlier) so it still respects
            // `default_prevented` the same way link navigation does.
            if let Some(url) = submit_url {
                match submit_body {
                    Some(body) => self.navigate_with_body(&url, body),
                    None => self.navigate(&url),
                }
                return Some(self.frame(Some(self.window_title())));
            }
            if let Some(hit) = &hit {
                // `download` is this link's default action taking the
                // place of navigation entirely — same
                // preventDefault-respecting placement as the plain
                // navigation branch below (a `download` link can have
                // a `click` listener that cancels it, exactly like any
                // other link), not an early special case.
                if let Some(download_hint) = &hit.download {
                    let resolved = resolve_url(&self.active_tab().current_url, &hit.href);
                    self.download(&resolved, download_hint);
                    return Some(self.frame(Some(self.window_title())));
                }
                if is_navigable_href(&hit.href) {
                    let resolved = resolve_url(&self.active_tab().current_url, &hit.href);
                    self.navigate(&resolved);
                    return Some(self.frame(Some(self.window_title())));
                }
            }
        }

        if content_changed {
            self.clamp_scroll();
            return Some(self.frame(Some(self.window_title())));
        }

        Some(self.frame(None))
    }

    /// Handles a click anywhere inside the DevTools panel — `y` is
    /// already relative to the PANEL's own top edge (0..
    /// `DEVTOOLS_PANEL_HEIGHT`), converted by `handle_click`, the only
    /// caller.
    fn handle_devtools_click(&mut self, x: f32, y: f32) -> Option<Frame> {
        if y < DEVTOOLS_TAB_BAR_HEIGHT {
            return self.handle_devtools_tab_bar_click(x);
        }
        let content_y = y - DEVTOOLS_TAB_BAR_HEIGHT;
        match self.active_tab().devtools_tab {
            DevtoolsTab::Console => self.handle_devtools_console_click(content_y),
            DevtoolsTab::Elements => self.handle_devtools_elements_click(x, content_y),
        }
    }

    /// The DevTools panel's own tab strip: "Console"/"Elements" labels,
    /// plus (only meaningful, and only painted, while Elements is
    /// active) a "Pick" and a "Refresh" button at the right edge — see
    /// `paint_devtools_panel` for the matching layout these hit regions
    /// mirror.
    fn handle_devtools_tab_bar_click(&mut self, x: f32) -> Option<Frame> {
        if x < DEVTOOLS_TAB_LABEL_WIDTH {
            self.active_tab_mut().devtools_tab = DevtoolsTab::Console;
            return Some(self.frame(None));
        }
        if x < DEVTOOLS_TAB_LABEL_WIDTH * 2.0 {
            self.active_tab_mut().devtools_tab = DevtoolsTab::Elements;
            self.refresh_dom_snapshot();
            return Some(self.frame(None));
        }
        if self.active_tab().devtools_tab == DevtoolsTab::Elements {
            let width = self.canvas_width as f32;
            let refresh_x = width - DEVTOOLS_ACTION_BUTTON_WIDTH;
            let pick_x = refresh_x - DEVTOOLS_ACTION_BUTTON_WIDTH;
            if (pick_x..refresh_x).contains(&x) {
                self.active_tab_mut().devtools_picking = true;
                return Some(self.frame(None));
            }
            if x >= refresh_x {
                self.refresh_dom_snapshot();
                return Some(self.frame(None));
            }
        }
        Some(self.frame(None))
    }

    /// `content_y` is relative to the top of the Console tab's content
    /// area (below the DevTools tab strip). The bottom
    /// `DEVTOOLS_CONSOLE_INPUT_HEIGHT` pixels are the REPL input row;
    /// clicking it takes keyboard focus (see `take_devtools_console_focus`)
    /// the same way clicking the address bar takes focus away from
    /// everything else. Clicking the scrolling log above it just blurs
    /// the input (matching "click elsewhere to defocus a text field").
    fn handle_devtools_console_click(&mut self, content_y: f32) -> Option<Frame> {
        let content_height = DEVTOOLS_PANEL_HEIGHT - DEVTOOLS_TAB_BAR_HEIGHT;
        let input_row_top = content_height - DEVTOOLS_CONSOLE_INPUT_HEIGHT;
        if content_y >= input_row_top {
            self.take_devtools_console_focus();
        } else {
            self.active_tab_mut().console_input_focused = false;
        }
        Some(self.frame(None))
    }

    /// Takes keyboard focus for the DevTools console's REPL input line
    /// — blurs every other "what do keystrokes go to" mode first
    /// (a page input, an in-progress address-bar edit, find-in-page),
    /// same "exactly one thing has focus" discipline `enter_find_mode`
    /// already follows.
    fn take_devtools_console_focus(&mut self) {
        self.blur_page_input_if_focused();
        if self.active_tab().editing_address_bar {
            self.active_tab_mut().editing_address_bar = false;
            let url = self.active_tab().current_url.clone();
            self.active_tab_mut().set_address_bar_text(url);
        }
        if self.active_tab().finding_in_page {
            self.exit_find_mode();
        }
        self.active_tab_mut().console_input_focused = true;
    }

    /// `content_y`/`x` are relative to the Elements tab's content area.
    /// The left `DEVTOOLS_ELEMENTS_TREE_WIDTH_FRACTION` of the width is
    /// the DOM tree (click a row to select that node); the rest is the
    /// read-only box-model/computed-style pane, which has nothing to
    /// click.
    fn handle_devtools_elements_click(&mut self, x: f32, content_y: f32) -> Option<Frame> {
        let width = self.canvas_width as f32;
        let tree_width = width * DEVTOOLS_ELEMENTS_TREE_WIDTH_FRACTION;
        if x >= tree_width {
            return Some(self.frame(None));
        }
        let tab = self.active_tab();
        let Some(root) = tab.dom_snapshot.as_ref() else {
            return Some(self.frame(None));
        };
        let mut rows = Vec::new();
        flatten_dom_tree(root, 0, &mut rows);
        let row_index = (content_y / DEVTOOLS_ROW_HEIGHT) as usize + tab.elements_tree_scroll_rows;
        if let Some((_, node)) = rows.get(row_index) {
            let node_id = node.node_id;
            self.active_tab_mut().devtools_selected_node = Some(node_id);
        }
        Some(self.frame(None))
    }

    /// Submits whatever's currently typed into the DevTools console's
    /// REPL input (`Enter` while `console_input_focused`) — sends it to
    /// the active tab's live renderer session via
    /// `ClientMessageKind::EvalConsoleExpression`, applies the result
    /// (which, like any other `Rendered` reply, can carry BOTH a
    /// mutated layout tree AND new console messages — see that
    /// variant's own doc comment), and clears the input line
    /// afterward. A no-op (beyond clearing nothing) if the input is
    /// empty, or if this tab has no live renderer session at all (never
    /// navigated, or currently on a local `about:` page — there's no
    /// live JS context to evaluate against).
    fn submit_devtools_console_input(&mut self) -> Option<Frame> {
        let code = self.active_tab().console_input.trim().to_string();
        if code.is_empty() {
            return Some(self.frame(None));
        }
        self.active_tab_mut().console_input.clear();
        let tab_id = self.active_tab().id;
        let Some(site) = self.active_tab().renderer_site.clone() else {
            return Some(self.frame(None));
        };
        let Some(renderer) = self.renderers.get(&site) else {
            return Some(self.frame(None));
        };
        let outcome = renderer.eval_console_expression(tab_id, &code);
        let now = std::time::Instant::now();
        self.apply_server_message_kind_to_tab(tab_id, outcome, now);
        self.clamp_scroll();
        Some(self.frame(Some(self.window_title())))
    }

    /// Scrolls whichever DevTools sub-panel is currently active (see
    /// `Tab::console_scroll_rows`'s own doc comment) by `delta_y`
    /// pixels, converted to whole rows and clamped so it can never
    /// scroll past either end.
    fn scroll_devtools_panel(&mut self, delta_y: f32) {
        let row_delta = (delta_y / DEVTOOLS_ROW_HEIGHT).round() as i64;
        match self.active_tab().devtools_tab {
            DevtoolsTab::Console => {
                let max_scroll = self.max_console_scroll_rows() as i64;
                let tab = self.active_tab_mut();
                let current = tab.console_scroll_rows.min(max_scroll as usize) as i64;
                tab.console_scroll_rows = (current + row_delta).clamp(0, max_scroll) as usize;
            }
            DevtoolsTab::Elements => {
                let max_scroll = self.max_elements_scroll_rows() as i64;
                let tab = self.active_tab_mut();
                let current = tab.elements_tree_scroll_rows.min(max_scroll as usize) as i64;
                tab.elements_tree_scroll_rows = (current + row_delta).clamp(0, max_scroll) as usize;
            }
        }
    }

    /// How many rows of `console_log` are visible in the Console tab's
    /// content area at once — shared by scrolling and painting so
    /// they can't disagree about how much fits.
    fn devtools_visible_log_rows() -> usize {
        ((DEVTOOLS_PANEL_HEIGHT - DEVTOOLS_TAB_BAR_HEIGHT - DEVTOOLS_CONSOLE_INPUT_HEIGHT)
            / DEVTOOLS_ROW_HEIGHT) as usize
    }

    /// How many rows of the Elements tab's DOM tree are visible at
    /// once — see `Self::devtools_visible_log_rows`'s own doc comment.
    fn devtools_visible_tree_rows() -> usize {
        ((DEVTOOLS_PANEL_HEIGHT - DEVTOOLS_TAB_BAR_HEIGHT) / DEVTOOLS_ROW_HEIGHT) as usize
    }

    fn max_console_scroll_rows(&self) -> usize {
        self.active_tab()
            .console_log
            .len()
            .saturating_sub(Self::devtools_visible_log_rows())
    }

    fn max_elements_scroll_rows(&self) -> usize {
        let Some(root) = self.active_tab().dom_snapshot.as_ref() else {
            return 0;
        };
        let mut rows = Vec::new();
        flatten_dom_tree(root, 0, &mut rows);
        rows.len()
            .saturating_sub(Self::devtools_visible_tree_rows())
    }

    /// Fetches a fresh DOM snapshot for the active tab's Elements panel
    /// — see `ipc::ClientMessageKind::FetchDomSnapshot`'s own doc
    /// comment for why this only happens here (opening/switching to the
    /// Elements tab, or its manual refresh button) rather than after
    /// every render. A tab with no live renderer session (never
    /// navigated, or currently on a local `about:` page) simply has
    /// nothing to show — silently leaves `dom_snapshot` as `None`
    /// rather than treating that as an error.
    fn refresh_dom_snapshot(&mut self) {
        let tab_id = self.active_tab().id;
        self.active_tab_mut().elements_tree_scroll_rows = 0;
        let Some(site) = self.active_tab().renderer_site.clone() else {
            self.active_tab_mut().dom_snapshot = None;
            return;
        };
        let Some(renderer) = self.renderers.get(&site) else {
            self.active_tab_mut().dom_snapshot = None;
            return;
        };
        let snapshot = match renderer.fetch_dom_snapshot(tab_id) {
            Some(ipc::DomSnapshotOutcome::Ready(tree)) => Some(tree),
            Some(ipc::DomSnapshotOutcome::Unavailable) | None => None,
        };
        self.active_tab_mut().dom_snapshot = snapshot;
    }

    /// Handles a click within the tab strip: the "+" button, a tab's
    /// close zone, or switching to the clicked tab. `x` is the only
    /// coordinate that matters — the caller already established
    /// `y < TAB_BAR_HEIGHT`.
    fn handle_tab_bar_click(&mut self, x: f32) -> Option<Frame> {
        let width = self.tab_width();
        let new_tab_button_x = width * self.tabs.len() as f32;
        if x >= new_tab_button_x && x < new_tab_button_x + NEW_TAB_BUTTON_WIDTH {
            self.open_new_tab();
            return Some(self.frame(Some(self.window_title())));
        }

        let index = (x / width) as usize;
        if index >= self.tabs.len() {
            // Clicked past the last tab and past the "+" button (e.g.
            // in leftover space after tabs hit MAX_TAB_WIDTH) — no-op.
            return Some(self.frame(None));
        }

        let tab_start_x = index as f32 * width;
        let in_close_zone = self.tabs.len() > 1 && x >= tab_start_x + width - TAB_CLOSE_ZONE_WIDTH;
        if in_close_zone {
            self.close_tab(index);
        } else {
            self.active_tab_index = index;
        }
        Some(self.frame(Some(self.window_title())))
    }

    /// Maps a click's x coordinate (relative to the start of the address
    /// bar's text, i.e. already offset by `ADDRESS_TEXT_START_X`) to the
    /// nearest character boundary — see `text::char_index_for_x` (this
    /// used to be its own hand-rolled copy of that same algorithm,
    /// before page `<input>` support needed the identical logic and it
    /// got hoisted into `text` as a shared utility).
    fn char_index_for_x(&self, target_x: f32) -> usize {
        text::char_index_for_x(
            &self.font,
            &self.active_tab().address_bar_text,
            ADDRESS_BAR_FONT_SIZE,
            target_x,
        )
    }

    fn window_title(&self) -> String {
        self.active_tab().window_title()
    }

    fn bookmark_current_page(&mut self) {
        let title = self.window_title();
        let url = self.active_tab().current_url.clone();
        self.bookmarks.add_bookmark(&title, &url);
        save_bookmarks(&self.account, &self.bookmarks, &self.data_dir);
        println!("Bookmarked \"{title}\" -> {url}");
        self.sync_push();
    }

    /// The bookmark star button/`Ctrl+D`'s actual behavior — unlike
    /// `bookmark_current_page` (always adds, used by the address bar's
    /// "bookmark" text command), this flips between bookmarked and not
    /// so pressing the same star twice un-bookmarks the page rather
    /// than being a harmless no-op (`add_bookmark` is already
    /// idempotent — see its own doc comment — so a second press
    /// without this would just silently do nothing, which isn't what a
    /// toggle button should do).
    fn toggle_bookmark_current_page(&mut self) {
        let url = self.active_tab().current_url.clone();
        if self.bookmarks.is_bookmarked(&url) {
            self.bookmarks.remove_bookmark(&url);
            println!("Un-bookmarked {url}");
            save_bookmarks(&self.account, &self.bookmarks, &self.data_dir);
            self.sync_push();
        } else {
            self.bookmark_current_page();
        }
    }

    /// The reload button/`Ctrl+R`/`F5`'s behavior: re-runs whatever
    /// loaded the CURRENT page (a real fetch, or one of the `about:`
    /// pseudo-pages — see `go_to_history_entry`, which this reuses
    /// directly) without touching `history_back`/`history_forward` at
    /// all, the same way a real browser's reload never pushes a new
    /// history entry or clears the forward stack.
    fn reload(&mut self) {
        let url = self.active_tab().current_url.clone();
        let scroll_y = self.active_tab().scroll_y;
        self.go_to_history_entry(&url, scroll_y);
    }

    /// Handles a click on one of the settings page's own `settings:foo:bar`
    /// links (see `render_settings_html`/`setting_row`) — `foo` names
    /// which setting, `bar` is the value to switch it to. Applies the
    /// change and re-renders the settings page IN PLACE (no new history
    /// entry) so clicking through several toggles doesn't pile up a
    /// stack of `about:settings` entries to click back through.
    fn handle_settings_link(&mut self, command: &str) {
        let Some((command_name, value)) = command.split_once(':') else {
            return;
        };
        let key = match command_name {
            "set-theme" => SETTING_THEME,
            "set-fingerprint-resistance" => SETTING_FINGERPRINT_RESISTANCE,
            "set-webrtc" => SETTING_WEBRTC,
            _ => return,
        };
        self.apply_setting(key, value);
        self.load_settings_page_without_history();
    }

    /// Handles a typed `set <name> <value>` address-bar command (the
    /// free-text escape hatch for settings a clickable link can't
    /// represent well, like `sync-server-url`, and a faster path for
    /// anyone who'd rather type than click). Unlike a settings-page
    /// link click, this DOES push a new `about:settings` history entry
    /// — typing a command from an arbitrary page is closer to
    /// navigating somewhere than to editing a page already on screen.
    fn handle_set_command(&mut self, rest: &str) {
        let mut parts = rest.splitn(2, ' ');
        let typed_key = parts.next().unwrap_or("").trim();
        let value = parts.next().unwrap_or("").trim();
        let key = match typed_key.to_ascii_lowercase().as_str() {
            "theme" => SETTING_THEME,
            "fingerprint-resistance" => SETTING_FINGERPRINT_RESISTANCE,
            "webrtc" => SETTING_WEBRTC,
            "sync-server-url" => SETTING_SYNC_SERVER_URL,
            _ => {
                eprintln!("Unknown setting {typed_key:?} (expected theme, fingerprint-resistance, webrtc, or sync-server-url)");
                self.load_settings_page();
                return;
            }
        };
        if !self.apply_setting(key, value) {
            eprintln!("Invalid value {value:?} for setting {typed_key:?}");
        }
        self.load_settings_page();
    }

    /// The one place that actually changes a setting: validates
    /// `value` for `key`, updates whichever in-memory field(s) drive
    /// live behavior (`theme`/`background`, `fingerprint_resistance`,
    /// `webrtc_access`) so the change takes effect immediately rather
    /// than only on next launch, then writes it into
    /// `bookmarks.settings` and pushes through the same save+sync path
    /// `bookmark_current_page` uses — a settings change reaches other
    /// synced devices exactly like a bookmark does, since both live in
    /// the same `storage::SyncPayload` (see `Settings::merge`). Returns
    /// `false` (and changes nothing) for an unrecognized value, so
    /// callers can tell a genuine invalid-input case apart from success.
    fn apply_setting(&mut self, key: &str, value: &str) -> bool {
        match key {
            SETTING_THEME => {
                let Some(theme) = css::Theme::parse(value) else {
                    return false;
                };
                self.theme = theme;
                self.background =
                    render::parse_color(theme.background_hex()).unwrap_or(self.background);
            }
            SETTING_FINGERPRINT_RESISTANCE => {
                let Some(level) = privacy::FingerprintResistanceLevel::parse(value) else {
                    return false;
                };
                self.fingerprint_resistance = level;
            }
            SETTING_WEBRTC => {
                self.webrtc_access = match value {
                    "allowed" => privacy::ApiAccess::Restricted,
                    "blocked" => privacy::ApiAccess::Disabled,
                    _ => return false,
                };
            }
            SETTING_SYNC_SERVER_URL => {
                if value.trim().is_empty() {
                    return false;
                }
                // No live field to update here (`sync_server_url()`
                // reads `bookmarks.settings` fresh every call) — but
                // note the chicken-and-egg edge case this creates: the
                // confirmatory `sync_push()` below targets the NEW
                // server immediately, so switching to an unreachable
                // one saves locally (fine) but can't use the OLD
                // server to tell other devices about the change —
                // there's no server both sides agree on anymore.
            }
            _ => return false,
        }
        self.bookmarks.settings.set(key, value);
        save_bookmarks(&self.account, &self.bookmarks, &self.data_dir);
        self.sync_push();
        true
    }

    /// The sync server URL currently in effect — from `Settings` if the
    /// user has ever set one (locally or synced from another device),
    /// falling back to `DEFAULT_SYNC_SERVER_URL` otherwise. Read fresh
    /// on every push/pull rather than cached, so changing it in
    /// settings takes effect on the very next sync attempt.
    fn sync_server_url(&self) -> String {
        self.bookmarks
            .settings
            .get(SETTING_SYNC_SERVER_URL)
            .unwrap_or(DEFAULT_SYNC_SERVER_URL)
            .to_string()
    }

    /// Pushes the local bookmarks/settings to the sync server. `sync`
    /// itself can only ever detect a stale push (`SyncError::Conflict`)
    /// — it never sees plaintext, so it can't merge anything (see its
    /// own module docs). When that happens, THIS is the retry loop
    /// that does the actual merging: pull whatever's on the server
    /// now, fold it into the local payload via
    /// `storage::SyncPayload::merge` (keeping both sides' changes
    /// instead of one clobbering the other), and push the merged
    /// result. Bounded to `MAX_PUSH_ATTEMPTS` retries so a pathological
    /// case (another device pushing on every single one of our
    /// retries) can't loop forever — that's the same tradeoff any
    /// optimistic-concurrency retry loop makes.
    fn sync_push(&mut self) {
        use sync::{SyncError, SyncTransport};
        const MAX_PUSH_ATTEMPTS: u32 = 5;

        let key = account::derive_key(&self.account.recovery_code, &self.account.kdf_salt);
        let auth_secret =
            account::derive_auth_secret(&self.account.recovery_code, &self.account.kdf_salt);
        let sync_server_url = self.sync_server_url();
        let mut server = sync::HttpSyncClient::new(&sync_server_url);

        for _ in 0..MAX_PUSH_ATTEMPTS {
            let ciphertext = account::encrypt(&key, &self.bookmarks.to_bytes());
            match server.push(
                &self.account.account_id,
                &auth_secret,
                ciphertext,
                self.sync_version,
            ) {
                Ok(new_version) => {
                    self.sync_version = new_version;
                    println!("Synced bookmarks to {sync_server_url}");
                    return;
                }
                Err(SyncError::Conflict { .. }) => {
                    match server.pull(&self.account.account_id, &auth_secret) {
                        Ok(blob) => {
                            self.sync_version = blob.version;
                            match account::decrypt(&key, &blob.ciphertext) {
                                Ok(decrypted) => match storage::SyncPayload::from_bytes(&decrypted)
                                {
                                    Some(remote) => {
                                        self.bookmarks = self.bookmarks.merge(&remote);
                                        save_bookmarks(
                                            &self.account,
                                            &self.bookmarks,
                                            &self.data_dir,
                                        );
                                        // Loop again: push the merged result against
                                        // the version we just learned.
                                    }
                                    None => {
                                        eprintln!("Sync push conflict: server data didn't parse — giving up rather than overwriting it blind.");
                                        return;
                                    }
                                },
                                Err(_) => {
                                    eprintln!("Sync push conflict: server data didn't decrypt — giving up rather than overwriting it blind.");
                                    return;
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!(
                                "Sync push conflict, but re-pulling the current data failed: {e:?}"
                            );
                            return;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Sync push skipped (server unreachable): {e:?}");
                    return;
                }
            }
        }
        eprintln!("Sync push gave up after {MAX_PUSH_ATTEMPTS} consecutive conflicts");
    }

    /// Pulls the server's current bookmarks/settings and MERGES them
    /// into the local copy (see `storage::SyncPayload::merge`), rather
    /// than overwriting local state outright — the local copy may hold
    /// changes made while offline (e.g. a bookmark added on this
    /// device before this pull's very first successful connection)
    /// that the server doesn't know about yet, and those need to
    /// survive this pull, not be silently replaced by it. If merging
    /// in the remote side actually changed anything local-only, that
    /// merged result is pushed right back — otherwise this device's
    /// local-only additions would only reach the server on whatever
    /// the NEXT unrelated sync happens to be (e.g. the next bookmark).
    fn sync_pull(&mut self) {
        use sync::SyncTransport;
        let key = account::derive_key(&self.account.recovery_code, &self.account.kdf_salt);
        let auth_secret =
            account::derive_auth_secret(&self.account.recovery_code, &self.account.kdf_salt);
        let sync_server_url = self.sync_server_url();
        let server = sync::HttpSyncClient::new(&sync_server_url);
        match server.pull(&self.account.account_id, &auth_secret) {
            Ok(blob) => {
                self.sync_version = blob.version;
                if let Ok(decrypted) = account::decrypt(&key, &blob.ciphertext) {
                    if let Some(remote) = storage::SyncPayload::from_bytes(&decrypted) {
                        let merged = self.bookmarks.merge(&remote);
                        let local_had_unsynced_changes = merged != remote;
                        self.bookmarks = merged;
                        save_bookmarks(&self.account, &self.bookmarks, &self.data_dir);
                        println!("Pulled and merged bookmarks from {sync_server_url}");
                        if local_had_unsynced_changes {
                            self.sync_push();
                        }
                    }
                }
            }
            Err(e) => eprintln!("Sync pull skipped (server unreachable or no data yet): {e:?}"),
        }
    }
}

/// Resolve `href` against `base_url` — real, spec-correct RFC 3986
/// resolution via the `url` crate (absolute URLs, protocol-relative,
/// root-relative, plain relative, dot-segments, AND query strings/
/// fragments, unlike the hand-rolled approximation this replaces).
/// Falls back to returning `href` unchanged if `base_url` doesn't
/// parse as a URL at all (the `about:demo`/`about:bookmarks`/
/// `about:settings` pseudo-pages only ever contain absolute hrefs in
/// practice, so this fallback path is a safety net, not something
/// expected to matter day to day) or if joining fails.
/// Finds the `LayoutBox` built from `dom_node_id` anywhere in `tree` —
/// used by `handle_click` to check whether a clicked node is a
/// text-editable `<input>` (i.e. `text_input.is_some()`) without
/// needing a second round trip to the renderer just to ask.
fn find_layout_box_by_id(
    tree: &layout::LayoutBox,
    dom_node_id: dom::NodeId,
) -> Option<&layout::LayoutBox> {
    if tree.dom_node_id == dom_node_id {
        return Some(tree);
    }
    tree.children
        .iter()
        .find_map(|child| find_layout_box_by_id(child, dom_node_id))
}

fn resolve_url(base_url: &str, href: &str) -> String {
    match url::Url::parse(base_url).and_then(|base| base.join(href)) {
        Ok(resolved) => resolved.to_string(),
        Err(_) => href.to_string(),
    }
}

/// `#fragment`, `mailto:`, `tel:`, and `javascript:` links should
/// never trigger a page fetch — the first is an in-page anchor (not
/// implemented, but definitely not something to "navigate" to as a
/// URL), and the rest aren't HTTP(S) resources at all.
fn is_navigable_href(href: &str) -> bool {
    !(href.starts_with('#')
        || href.starts_with("mailto:")
        || href.starts_with("tel:")
        || href.starts_with("javascript:"))
}

/// If the user typed something with no scheme (`example.com` rather
/// than `https://example.com`), assume https — the same default
/// every mainstream browser's address bar uses.
fn normalize_typed_url(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    }
}

/// Find the first `<title>` element in the DOM and return its
/// (trimmed) text content, if any. Doesn't handle multiple `<title>`
/// elements beyond taking the first one found (depth-first), which is
/// what real browsers do too.
///
/// TODO: this is a one-off ad hoc traversal. If more DOM-querying
/// needs pop up (and they will — favicons, meta descriptions, etc. all
/// follow the same "find the first matching element" shape), this
/// deserves to become a real `querySelector`-style helper living in
/// `dom` instead of more copy-pasted walk functions like this one.
fn extract_title(node: &dom::NodeRef) -> Option<String> {
    let node_ref = node.borrow();
    if let dom::NodeType::Element(el) = &node_ref.node_type {
        if el.tag_name == "title" {
            let text: String = node_ref
                .children
                .iter()
                .filter_map(|c| match &c.borrow().node_type {
                    // NOTE: must clone here, not return a `&str` — the
                    // `Ref` from `c.borrow()` is a temporary that gets
                    // dropped at the end of this match, so a borrowed
                    // `&str` tied to it can't outlive this closure call.
                    dom::NodeType::Text(t) => Some(t.clone()),
                    _ => None,
                })
                .collect();
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    node_ref.children.iter().find_map(extract_title)
}

fn render_bookmarks_html(payload: &storage::SyncPayload) -> String {
    let mut items = String::new();
    if payload.bookmarks.is_empty() {
        items.push_str(
            "<p>No bookmarks yet. Type \"bookmark\" in the address bar on any page to save it.</p>",
        );
    } else {
        for bookmark in &payload.bookmarks {
            items.push_str(&format!(
                "<p><a href=\"{}\">{}</a></p>\n",
                html_escape(&bookmark.url),
                html_escape(&bookmark.title),
            ));
        }
    }
    format!(
        "<html><head><title>Bookmarks</title></head><body><h1>Bookmarks</h1>{items}</body></html>"
    )
}

/// Renders the history page: newest visit first, each entry showing
/// its title (falling back to the bare URL for a page with none — see
/// `storage::HistoryEntry::title`'s own doc comment) as a link back to
/// that URL, plus a coarse "how long ago" (`format_relative_time`).
/// `history:clear` (handled by `handle_click`'s href interception,
/// alongside `settings:`) is the one interactive element beyond the
/// visit links themselves.
fn render_history_html(payload: &storage::SyncPayload) -> String {
    let mut items = String::new();
    if payload.history.is_empty() {
        items.push_str("<p>No history yet.</p>");
    } else {
        for entry in payload.history.iter().rev() {
            let label = entry.title.as_deref().unwrap_or(&entry.url);
            items.push_str(&format!(
                "<p><a href=\"{}\">{}</a> — {}</p>\n",
                html_escape(&entry.url),
                html_escape(label),
                html_escape(&format_relative_time(entry.visited_at_unix)),
            ));
        }
    }
    format!(
        "<html><head><title>History</title></head><body><h1>History</h1>\
         <p><a href=\"history:clear\">Clear history</a></p>\
         {items}</body></html>"
    )
}

/// Renders the downloaded-files list: newest first, each showing its
/// filename, saved path, size, and how long ago it finished. The path
/// is a real `file://` link now that this browser has real `file://`
/// navigation support (see `LOCAL_FILES_SITE`) -- clicking it opens the
/// downloaded file itself through the same dedicated, isolated process
/// every other local file navigation uses. Falls back to plain,
/// non-clickable text only in the near-impossible case
/// `url::Url::from_file_path` rejects the path outright (a relative
/// path -- `saved_path` is always the absolute path `downloads::save_to`
/// actually wrote to -- or one with no OS-recognizable form at all).
fn render_downloads_html(downloads: &[DownloadRecord]) -> String {
    let mut items = String::new();
    if downloads.is_empty() {
        items.push_str("<p>No downloads yet.</p>");
    } else {
        for record in downloads.iter().rev() {
            let path_text = html_escape(&record.saved_path.display().to_string());
            let path_html = match url::Url::from_file_path(&record.saved_path) {
                Ok(file_url) => format!(
                    "<a href=\"{}\">{path_text}</a>",
                    html_escape(file_url.as_str())
                ),
                Err(()) => path_text,
            };
            items.push_str(&format!(
                "<p><b>{}</b> ({}) -- {}<br>{}</p>\n",
                html_escape(&record.filename),
                html_escape(&format_size(record.size_bytes)),
                html_escape(&format_relative_time(record.downloaded_at_unix)),
                path_html,
            ));
        }
    }
    format!(
        "<html><head><title>Downloads</title></head><body><h1>Downloads</h1>{items}</body></html>"
    )
}

/// A translucent filled rectangle — `render::Canvas::fill_rect` always
/// overwrites pixels outright (see that method's own doc comment), so
/// the DevTools on-page highlight overlay (which must show the page
/// content underneath it, not hide it) blends each pixel instead, via
/// the same `blend_pixel` real (antialiased) text painting already
/// uses.
fn blend_rect(
    canvas: &mut render::Canvas,
    x: f32,
    y: f32,
    w: f32,
    h: f32,
    color: render::Color,
    coverage: u8,
) {
    let x0 = x.max(0.0) as usize;
    let y0 = y.max(0.0) as usize;
    let x1 = (x + w).max(0.0) as usize;
    let y1 = (y + h).max(0.0) as usize;
    for py in y0..y1 {
        for px in x0..x1 {
            canvas.blend_pixel(px, py, color, coverage);
        }
    }
}

/// A one-line, DevTools-tree-style label for a DOM snapshot node:
/// `<tag id="..." class="...">` for an element (real DevTools' own
/// abbreviated form), a quoted preview for non-blank text, `#text` for
/// whitespace-only text (matching real DevTools, which also collapses
/// those to a plain placeholder), and an HTML-comment-shaped label for
/// a comment.
fn dom_node_label(node: &ipc::DomNode) -> String {
    match &node.kind {
        ipc::DomNodeKind::Document => "#document".to_string(),
        ipc::DomNodeKind::Element {
            tag_name,
            attributes,
        } => {
            let mut label = format!("<{tag_name}");
            if let Some((_, id)) = attributes.iter().find(|(k, _)| k == "id") {
                label.push_str(&format!(" id=\"{id}\""));
            }
            if let Some((_, class)) = attributes.iter().find(|(k, _)| k == "class") {
                label.push_str(&format!(" class=\"{class}\""));
            }
            label.push('>');
            label
        }
        ipc::DomNodeKind::Text(text) => {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                "#text".to_string()
            } else {
                let preview: String = trimmed.chars().take(40).collect();
                format!("\"{preview}\"")
            }
        }
        ipc::DomNodeKind::Comment(text) => format!("<!-- {} -->", text.trim()),
    }
}

/// Flattens a DOM snapshot into document order with each node's depth,
/// the exact traversal `paint_devtools_elements_tab` and
/// `handle_devtools_elements_click` BOTH use — sharing this one
/// function is what keeps a click's row index pointing at the same
/// node its highlighted row is actually showing.
fn flatten_dom_tree<'a>(
    node: &'a ipc::DomNode,
    depth: usize,
    out: &mut Vec<(usize, &'a ipc::DomNode)>,
) {
    out.push((depth, node));
    for child in &node.children {
        flatten_dom_tree(child, depth + 1, out);
    }
}

/// A coarse, human-readable file size — bytes/KB/MB, one decimal place
/// above 1 KB. Plain arithmetic, same "not worth a dependency for
/// something this approximate" reasoning as `format_relative_time`.
fn format_size(bytes: usize) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    let bytes_f = bytes as f64;
    if bytes_f < KB {
        format!("{bytes} B")
    } else if bytes_f < MB {
        format!("{:.1} KB", bytes_f / KB)
    } else {
        format!("{:.1} MB", bytes_f / MB)
    }
}

/// A coarse, human-readable "how long ago" for a unix timestamp — kept
/// to plain arithmetic over `std::time` rather than pulling in a real
/// date/time-formatting dependency for something this approximate; a
/// history page listing "3 hours ago" doesn't need calendar dates.
fn format_relative_time(visited_at_unix: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(visited_at_unix);
    let elapsed = now.saturating_sub(visited_at_unix);

    fn plural(n: u64, unit: &str) -> String {
        format!("{n} {unit}{}", if n == 1 { "" } else { "s" })
    }

    if elapsed < 60 {
        "just now".to_string()
    } else if elapsed < 3600 {
        format!("{} ago", plural(elapsed / 60, "minute"))
    } else if elapsed < 86400 {
        format!("{} ago", plural(elapsed / 3600, "hour"))
    } else {
        format!("{} ago", plural(elapsed / 86400, "day"))
    }
}

/// Renders the settings page: current values plus, for every option
/// other than the current one, a `settings:<command>:<value>` link
/// `Browser::handle_settings_link` intercepts and applies — the same
/// "it's just an HTML page" approach `render_bookmarks_html` uses, so
/// no separate form-widget rendering is needed for a handful of
/// mutually-exclusive choices.
fn render_settings_html(browser: &Browser) -> String {
    let theme_row = setting_row(
        "Theme",
        "set-theme",
        &[("dark", "Dark"), ("light", "Light")],
        browser.theme.as_str(),
    );

    let fingerprint_row = setting_row(
        "Fingerprint resistance",
        "set-fingerprint-resistance",
        &[("strict", "Strict (recommended)"), ("standard", "Standard")],
        browser.fingerprint_resistance.as_str(),
    );

    let webrtc_current = match browser.webrtc_access {
        privacy::ApiAccess::Disabled => "blocked",
        privacy::ApiAccess::Restricted => "allowed",
    };
    let webrtc_row = setting_row(
        "WebRTC",
        "set-webrtc",
        &[("blocked", "Blocked (recommended)"), ("allowed", "Allowed")],
        webrtc_current,
    );

    format!(
        "<html><head><title>Settings</title></head><body>\
         <h1>Settings</h1>\
         {theme_row}\
         {fingerprint_row}\
         {webrtc_row}\
         <p>WebRTC has no live effect yet — there's no JS engine to expose it \
         through, so this only stores the preference for when one exists.</p>\
         <p>Sync server: <code>{}</code><br>\
         Change it by typing <code>set sync-server-url &lt;url&gt;</code> in the \
         address bar — a free-text URL isn't something a clickable link can \
         represent well.</p>\
         </body></html>",
        html_escape(&browser.sync_server_url()),
    )
}

/// Renders the account panel — the account button's destination (see
/// `Browser::load_account_page`). Shows the two pieces of identity
/// this browser's sync actually runs on (`account_id`, the public
/// handle the sync server knows this device by, and `recovery_code`,
/// the ONLY secret that ever derives the encryption/auth keys — see
/// `account`'s own module docs) plus a manual `account:sync` link,
/// the same "just an HTML page with one pseudo-link" shape as
/// `render_settings_html`/`render_history_html`.
fn render_account_html(browser: &Browser) -> String {
    format!(
        "<html><head><title>Account</title></head><body>\
         <h1>Account</h1>\
         <p>Account ID: <code>{}</code></p>\
         <p>Recovery code: <code>{}</code><br>\
         This is the ONLY way to recover this account's synced bookmarks/settings/history \
         on another device — write it down somewhere safe. Anyone with it can decrypt this \
         account's synced data, so treat it like a password, not a username.</p>\
         <p><a href=\"account:sync\">Sync now</a></p>\
         <p>Syncs to <code>{}</code> — change it by typing \
         <code>settings</code> in the address bar, then \
         <code>set sync-server-url &lt;url&gt;</code>.</p>\
         </body></html>",
        html_escape(&browser.account.account_id),
        html_escape(&browser.account.recovery_code),
        html_escape(&browser.sync_server_url()),
    )
}

/// One setting's label plus its option links: the CURRENT value is
/// shown as plain bold text (not a link — clicking "the option you
/// already have" to no effect would be confusing), every other option
/// is a `settings:<command>:<value>` link.
fn setting_row(
    label: &str,
    command: &str,
    options: &[(&str, &str)],
    current_value: &str,
) -> String {
    let mut choices = String::new();
    for (value, display) in options {
        if *value == current_value {
            choices.push_str(&format!("<b>{}</b> ", html_escape(display)));
        } else {
            choices.push_str(&format!(
                "<a href=\"settings:{command}:{value}\">{}</a> ",
                html_escape(display)
            ));
        }
    }
    format!("<p>{}: {choices}</p>\n", html_escape(label))
}

/// Truncates `text` to fit within `max_width` pixels at `font_size`,
/// appending "..." if it had to cut anything — the tab bar's only
/// defense against a long page title overflowing its fixed-width tab
/// (there's no text wrapping/ellipsis-via-CSS available for UI chrome
/// like this, so it's done by hand exactly once, for this one element).
/// Plain ASCII dots rather than a Unicode ellipsis glyph, since the one
/// bundled font's glyph coverage for it isn't guaranteed (see `text`'s
/// module docs on font limitations).
fn truncate_to_width(font: &text::Font, text: &str, font_size: f32, max_width: f32) -> String {
    if text::measure_text_width(font, text, font_size) <= max_width {
        return text.to_string();
    }
    const ELLIPSIS: &str = "...";
    let ellipsis_width = text::measure_text_width(font, ELLIPSIS, font_size);
    let mut result = String::new();
    let mut width = ellipsis_width;
    for ch in text.chars() {
        let ch_width = text::measure_text_width(font, &ch.to_string(), font_size);
        if width + ch_width > max_width {
            break;
        }
        result.push(ch);
        width += ch_width;
    }
    result.push_str(ELLIPSIS);
    result
}

/// Converts a character index into `s` into a byte offset, suitable for
/// `String::insert`/`replace_range` — those take byte offsets, but the
/// address bar's cursor/selection are tracked in character indices (see
/// `Tab::address_bar_cursor`'s doc comment) so they stay meaningful
/// across multi-byte UTF-8 text. `char_idx == s.chars().count()` (one
/// past the last character) correctly yields `s.len()`, matching how an
/// end-of-string cursor position should behave.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Used only when no `sync_server_url` setting has ever been set
/// locally or synced from another device — see `Browser::sync_server_url`.
const DEFAULT_SYNC_SERVER_URL: &str = "http://localhost:7878";

fn account_file_path(data_dir: &std::path::Path) -> std::path::PathBuf {
    data_dir.join("account.txt")
}

fn bookmarks_file_path(data_dir: &std::path::Path) -> std::path::PathBuf {
    data_dir.join("bookmarks.enc")
}

fn load_or_create_account(data_dir: &std::path::Path) -> account::Account {
    let path = account_file_path(data_dir);
    if let Ok(text) = std::fs::read_to_string(&path) {
        let mut lines = text.lines();
        if let (Some(account_id), Some(recovery_code), Some(salt_hex)) =
            (lines.next(), lines.next(), lines.next())
        {
            if let Some(kdf_salt) = hex_decode_16(salt_hex) {
                return account::Account {
                    account_id: account_id.to_string(),
                    recovery_code: recovery_code.to_string(),
                    kdf_salt,
                };
            }
        }
        eprintln!("{path:?} exists but is malformed — creating a new account instead.");
    }
    let account = account::create_account();
    println!("No local account found — created {}.", account.account_id);
    // The recovery code itself is deliberately NOT printed here — a
    // terminal's scrollback/history/session-log isn't a safe place
    // for the one secret that derives every key this browser ever
    // encrypts anything with (see `account`'s own module docs). It's
    // saved to `account.txt` (see `save_account`, now written
    // owner-only — see `write_secret_file`) and viewable any time
    // from the Account page (the account button, or typing "account"
    // in the address bar — see `render_account_html`).
    println!(
        "View and save its recovery code from the Account button in the toolbar before you \
         rely on sync — it's the only way to recover this account's data on another device."
    );
    save_account(&account, data_dir);
    account
}

fn save_account(account: &account::Account, data_dir: &std::path::Path) {
    let path = account_file_path(data_dir);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let contents = format!(
        "{}\n{}\n{}\n",
        account.account_id,
        account.recovery_code,
        hex_encode(&account.kdf_salt)
    );
    if let Err(e) = write_secret_file(&path, contents.as_bytes()) {
        eprintln!("Failed to save account to {path:?}: {e}");
    }
}

/// Writes `contents` to `path` restricted to the owner only on Unix
/// (mode `0o600`) — `account.txt` holds the recovery code that
/// derives every key this browser ever encrypts anything with (see
/// `account`'s own module docs), so a stray default-umask-mode file
/// readable by other local users/processes was this project's own
/// `THREAT_MODEL.md`-flagged "most concretely actionable finding."
/// Also used for `bookmarks.enc`/download history: those are already
/// encrypted, so this is defense-in-depth for them rather than
/// closing a real gap, but there's no reason for any of this
/// browser's own local state to be world/group-readable by default.
///
/// Sets the mode BOTH at creation (`OpenOptions::mode`, so a
/// brand-new file is never briefly at the looser default mode) AND
/// via an explicit `set_permissions` afterward on the open handle
/// (`fchmod`, so no path-based TOCTOU window) — the latter is also
/// what actually fixes a pre-existing file from a browser version
/// before this pass, since `mode()` only applies when `open` itself
/// creates the file, never to one that already existed.
fn write_secret_file(path: &std::path::Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Reads and decrypts `path` (one of `cookies.enc`/`local_storage.enc`/
/// `indexed_db.enc`) into real plaintext bytes, in exactly the shape
/// `network::PartitionedCookieJar::to_bytes`/`local_storage::
/// LocalStorageStore::to_bytes`/`indexed_db::IndexedDbStore::to_bytes`
/// produce — `RendererProcess::render`'s own seeding logic feeds the
/// result straight into `ipc::RenderRequest::initial_cookies`/etc.
/// `None` for a missing file (a fresh install, or nothing of this kind
/// has ever been persisted yet) or a decryption failure (corrupt file,
/// or an old file encrypted with a different key) — either way, "start
/// empty" is the same graceful degradation every other persisted store
/// in this codebase already has, not a fatal error.
fn load_encrypted_storage(path: &std::path::Path, key: &[u8; 32]) -> Option<Vec<u8>> {
    let encrypted = std::fs::read(path).ok()?;
    account::decrypt(key, &encrypted).ok().map(|z| z.to_vec())
}

/// Encrypts and persists one renderer's reported cookie/`localStorage`/
/// IndexedDB bytes to `path`, merged with whatever is CURRENTLY on
/// disk rather than overwriting it outright — the encrypted-at-rest
/// equivalent of `network::PartitionedCookieJar::save_merged_to_file`/
/// `local_storage::LocalStorageStore::save_merged_to_file`/
/// `indexed_db::IndexedDbStore::save_merged_to_file` (all now unused
/// and removed — this process is the only writer left), done here in
/// `app` (which holds the account's encryption key) instead of in
/// `renderer` (which never does — see `ipc::ServerMessage`'s own doc
/// comment). The real, TYPED `merge_into` each of those three types
/// still has is not available here: `app` must never depend on
/// `network`/`renderer` (the "app never links network" boundary this
/// whole codebase enforces structurally — see `ARCHITECTURE.md`), so
/// `merge_persisted_json` reimplements the exact same "overwrite only
/// the entries this report has an opinion on" semantics generically,
/// over raw JSON, using only the key field name(s) each format's own
/// `to_bytes` doc comment already documents.
///
/// Best-effort, matching every other persisted file in this codebase:
/// a missing/corrupt/undecryptable on-disk file just means "nothing to
/// merge with yet" (real for a fresh install, or if a previous run's
/// key ever changed), and a write failure is logged, not fatal — losing
/// one save is a much smaller problem than crashing the whole browser
/// over it.
fn persist_encrypted_merge(
    path: &std::path::Path,
    key: &[u8; 32],
    reported_bytes: &[u8],
    key_fields: &[&str],
) {
    let on_disk_plaintext = load_encrypted_storage(path, key).unwrap_or_default();
    let merged = merge_persisted_json(&on_disk_plaintext, reported_bytes, key_fields);
    let ciphertext = account::encrypt(key, &merged);
    if let Err(e) = write_secret_file(path, &ciphertext) {
        eprintln!("Failed to persist encrypted storage to {path:?}: {e}");
    }
}

/// Merges `reported` (one renderer process's own current view, as real
/// JSON array bytes) into `on_disk_bytes` (the same shape), replacing
/// any on-disk entry whose `key_fields` match a reported entry and
/// leaving every other on-disk entry untouched — generic, format-
/// agnostic reimplementation of the real `merge_into` method each of
/// `network::PartitionedCookieJar`/`local_storage::LocalStorageStore`/
/// `indexed_db::IndexedDbStore` already has; see `persist_encrypted_merge`'s
/// own doc comment for why this can't just call those directly.
/// `key_fields` is `&["origin"]` for `localStorage`/IndexedDB entries,
/// `&["top_level_site", "resource_host"]` for cookie entries (a
/// compound key — see `network::PartitionedCookieJar::to_bytes`'s own
/// doc comment for why cookies need one). Malformed `reported` bytes
/// (should never happen from this codebase's own renderer, but this is
/// still a cross-process boundary) leave `on_disk_bytes` completely
/// untouched rather than risk discarding real data over a parse
/// failure.
fn merge_persisted_json(on_disk_bytes: &[u8], reported: &[u8], key_fields: &[&str]) -> Vec<u8> {
    fn composite_key(entry: &serde_json::Value, key_fields: &[&str]) -> Option<Vec<String>> {
        key_fields
            .iter()
            .map(|field| {
                entry
                    .get(*field)
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
            })
            .collect()
    }

    let Ok(reported_entries) = serde_json::from_slice::<Vec<serde_json::Value>>(reported) else {
        return on_disk_bytes.to_vec();
    };
    let mut on_disk: Vec<serde_json::Value> =
        serde_json::from_slice(on_disk_bytes).unwrap_or_default();

    for reported_entry in reported_entries {
        let Some(key) = composite_key(&reported_entry, key_fields) else {
            continue;
        };
        on_disk.retain(|existing| composite_key(existing, key_fields).as_ref() != Some(&key));
        on_disk.push(reported_entry);
    }

    serde_json::to_vec(&on_disk).unwrap_or_else(|_| on_disk_bytes.to_vec())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode_16(hex: &str) -> Option<[u8; 16]> {
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn load_or_init_bookmarks(
    account: &account::Account,
    data_dir: &std::path::Path,
) -> storage::SyncPayload {
    let Ok(encrypted) = std::fs::read(bookmarks_file_path(data_dir)) else {
        return storage::SyncPayload::new();
    };
    let key = account::derive_key(&account.recovery_code, &account.kdf_salt);
    let Ok(decrypted) = account::decrypt(&key, &encrypted) else {
        eprintln!("Local bookmarks file failed to decrypt — starting with an empty set.");
        return storage::SyncPayload::new();
    };
    storage::SyncPayload::from_bytes(&decrypted).unwrap_or_default()
}

fn save_bookmarks(
    account: &account::Account,
    payload: &storage::SyncPayload,
    data_dir: &std::path::Path,
) {
    let path = bookmarks_file_path(data_dir);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let key = account::derive_key(&account.recovery_code, &account.kdf_salt);
    let ciphertext = account::encrypt(&key, &payload.to_bytes());
    if let Err(e) = write_secret_file(&path, &ciphertext) {
        eprintln!("Failed to save bookmarks to {path:?}: {e}");
    }
}

/// One downloaded file. Deliberately NOT part of `storage::SyncPayload`
/// (unlike bookmarks/settings/history) — `saved_path` is a path on
/// THIS device's filesystem, which is meaningless (or actively
/// misleading) on another device, so there's nothing sensible to sync.
/// Still encrypted at rest with the same account-derived key
/// bookmarks/history use (see `load_download_history`/
/// `save_download_history`) — the URLs/filenames here are as
/// privacy-sensitive as browsing history, even though they never leave
/// this device.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct DownloadRecord {
    url: String,
    filename: String,
    saved_path: std::path::PathBuf,
    downloaded_at_unix: u64,
    size_bytes: usize,
}

/// On-disk shape of the local, unsynced download-history file (see
/// `DownloadRecord`'s own doc comment) — a struct rather than a bare
/// `Vec<DownloadRecord>` so the file format can grow fields later
/// (e.g. a schema version) without a breaking change, the same reason
/// `storage::SyncPayload` itself is a struct and not a bare `Vec`.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct DownloadHistory {
    downloads: Vec<DownloadRecord>,
}

fn download_history_file_path(data_dir: &std::path::Path) -> std::path::PathBuf {
    data_dir.join("downloads.enc")
}

fn load_download_history(
    account: &account::Account,
    data_dir: &std::path::Path,
) -> Vec<DownloadRecord> {
    let Ok(encrypted) = std::fs::read(download_history_file_path(data_dir)) else {
        return Vec::new();
    };
    let key = account::derive_key(&account.recovery_code, &account.kdf_salt);
    let Ok(decrypted) = account::decrypt(&key, &encrypted) else {
        eprintln!("Local download history failed to decrypt — starting with an empty list.");
        return Vec::new();
    };
    serde_json::from_slice::<DownloadHistory>(&decrypted)
        .map(|history| history.downloads)
        .unwrap_or_default()
}

fn save_download_history(
    account: &account::Account,
    downloads: &[DownloadRecord],
    data_dir: &std::path::Path,
) {
    let path = download_history_file_path(data_dir);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let history = DownloadHistory {
        downloads: downloads.to_vec(),
    };
    let plaintext = match serde_json::to_vec(&history) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Failed to serialize download history: {e}");
            return;
        }
    };
    let key = account::derive_key(&account.recovery_code, &account.kdf_salt);
    let ciphertext = account::encrypt(&key, &plaintext);
    if let Err(e) = write_secret_file(&path, &ciphertext) {
        eprintln!("Failed to save download history to {path:?}: {e}");
    }
}

/// Where downloaded files are saved in REAL usage (see `Browser::new`):
/// `$HOME/Downloads` (or `%USERPROFILE%\Downloads` on Windows) —
/// falling back to `data_dir.join("downloads")` only if that
/// environment variable itself isn't set at all (an unusual, degraded
/// environment). A bounded simplification, not a full XDG Base
/// Directory implementation: a Linux desktop that's customized its
/// actual Downloads location (via `~/.config/user-dirs.dirs`) isn't
/// detected, and files land in the OS-conventional default location
/// instead. NOT used by tests (see `Browser::new_with_data_dir`) —
/// this reaches for the machine's REAL home directory, which almost
/// certainly exists and is writable on any dev/CI machine, unlike the
/// data-dir fallback this only takes when `$HOME` is entirely unset.
fn real_downloads_dir(data_dir: &std::path::Path) -> std::path::PathBuf {
    let home_var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    match std::env::var_os(home_var) {
        Some(home) => std::path::PathBuf::from(home).join("Downloads"),
        None => data_dir.join("downloads"),
    }
}

/// This browser's real on-disk data directory (`account.txt`,
/// `bookmarks.enc`, the disk `cache/`, `userscripts/`) — a proper,
/// OS-standard per-user location, NOT a bare relative path. That
/// distinction matters in practice, not just in principle: a relative
/// `"abyssal-data"` resolves against whatever the process's current
/// directory happens to be, which is the project root under
/// `cargo run`, but is NOT predictable when launched via the installed
/// `.desktop` entry (see `packaging/linux`) — different desktop
/// environments/file managers set a launched app's working directory
/// differently, and none of them are the project root. In practice
/// this showed up as the SAME real account/bookmarks looking freshly
/// reinstalled ("No local account found — created acct_...") every
/// time the browser was launched a different way, because each launch
/// method was quietly reading and writing a different folder. Same
/// `$HOME`/`%USERPROFILE%`-based resolution style as
/// `real_downloads_dir` (no extra dependency for something this
/// simple) rather than a full XDG Base Directory /
/// `directories`-crate implementation — falls back to the OLD bare
/// `"abyssal-data"` behavior only if the relevant environment variable
/// is entirely unset (an unusual, degraded environment, same fallback
/// philosophy as `real_downloads_dir`). NOT used by tests (see
/// `Browser::new_with_data_dir`), which always get their own isolated
/// temp directory regardless of platform.
fn real_data_dir() -> std::path::PathBuf {
    if cfg!(windows) {
        if let Some(appdata) = std::env::var_os("APPDATA") {
            return std::path::PathBuf::from(appdata).join("Abyssal Browser");
        }
    } else if cfg!(target_os = "macos") {
        if let Some(home) = std::env::var_os("HOME") {
            return std::path::PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("Abyssal Browser");
        }
    } else if let Some(xdg_data_home) = std::env::var_os("XDG_DATA_HOME") {
        return std::path::PathBuf::from(xdg_data_home).join("abyssal-browser");
    } else if let Some(home) = std::env::var_os("HOME") {
        return std::path::PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("abyssal-browser");
    }
    std::path::PathBuf::from("abyssal-data")
}

/// Reduces `name` to a single safe path COMPONENT before it's ever
/// joined onto a real directory: strips directory separators (so a
/// hostile `download="../../etc/passwd"` attribute, or a URL-derived
/// name that happens to contain one, can never escape the downloads
/// directory) and leading dots (a name that's entirely dots, or that
/// starts with one, is either meaningless as a real filename or a
/// hidden file nobody actually asked for), falling back to a generic
/// name if nothing usable is left.
fn sanitize_download_filename(name: &str) -> String {
    let stripped: String = name.chars().filter(|c| *c != '/' && *c != '\\').collect();
    let trimmed = stripped.trim().trim_start_matches('.');
    if trimmed.is_empty() {
        "download".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Picks a path inside `dir` for `filename` that doesn't already
/// exist, appending " (1)", " (2)", ... before the extension if it
/// does — the same "never silently overwrite" behavior real browsers'
/// downloads use.
fn unique_download_path(dir: &std::path::Path, filename: &str) -> std::path::PathBuf {
    let candidate = dir.join(filename);
    if !candidate.exists() {
        return candidate;
    }
    let as_path = std::path::Path::new(filename);
    let stem = as_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("download");
    let extension = as_path.extension().and_then(|s| s.to_str());
    let mut n = 1u32;
    loop {
        let numbered = match extension {
            Some(ext) => format!("{stem} ({n}).{ext}"),
            None => format!("{stem} ({n})"),
        };
        let candidate = dir.join(&numbered);
        if !candidate.exists() {
            return candidate;
        }
        n += 1;
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Real, end-to-end tests of site isolation (`RendererPool`) against
/// an actual `Browser` — spawning REAL `abyssal-renderer` subprocesses
/// and making REAL network fetches (to stable, IANA-reserved test
/// domains — `example.com`/`example.org`/`example.net`, never
/// content this project controls), the same way a real run would.
/// This is possible as a genuinely fast-to-write `cargo test` (not
/// just a scratchpad harness, unlike some of this crate's earlier
/// verification) specifically because `Browser::new`/`navigate`/
/// `close_tab`/etc. never touch `render::window` at all — opening an
/// actual GUI window is a separate step `main()` only takes
/// afterward, so nothing here needs a display.
#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh, isolated `Browser` for tests — its own account/
    /// bookmarks/cache directory under the OS temp dir, never the real
    /// `"abyssal-data"` `Browser::new` uses. Without this, every test
    /// that navigates would read and write the SAME on-disk files as
    /// an actual real run of this browser from this same working
    /// directory: fake test navigations (`example.com`, `example.org`,
    /// ...) would pollute a real user's actual saved history, AND
    /// history-count assertions across tests run in parallel (the
    /// `cargo test` default) would be flaky depending on what other
    /// tests happened to have already written to the shared file.
    ///
    /// Deliberately does NOT clean up its directory afterward (unlike
    /// e.g. `sync`'s/`network`'s own `TempDir` test helpers) — doing
    /// that properly would mean this function returning a guard
    /// alongside the `Browser` that every one of this module's ~20
    /// existing call sites would need to hold onto, for a cleanup
    /// that's purely a disk-space nicety in the OS temp directory (which
    /// the OS/a reboot eventually reclaims on its own), not a
    /// correctness or privacy concern the way sharing the real data
    /// directory would be.
    fn test_browser() -> Browser {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let data_dir =
            std::env::temp_dir().join(format!("abyssal-test-data-{}-{n}", std::process::id()));
        Browser::new_with_data_dir(None, data_dir)
    }

    #[cfg(unix)]
    #[test]
    fn account_txt_is_saved_owner_only_not_world_or_group_readable() {
        use std::os::unix::fs::PermissionsExt;

        let browser = test_browser();
        let path = account_file_path(&browser.data_dir);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "account.txt holds the recovery code that derives every key this browser \
             encrypts anything with — it must never be readable by another local user"
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_secret_file_locks_down_a_pre_existing_looser_mode_file_too() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "abyssal-test-secret-file-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("secret.txt");
        std::fs::write(&path, b"old contents").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        write_secret_file(&path, b"new contents").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), b"new contents");
    }

    #[test]
    fn site_for_url_computes_the_registrable_domain() {
        assert_eq!(site_for_url("https://www.example.com/page"), "example.com");
        assert_eq!(site_for_url("https://example.com/"), "example.com");
        assert_eq!(site_for_url("http://sub.example.co.uk/x"), "example.co.uk");
    }

    #[test]
    fn the_bundled_window_icon_decodes_to_real_consistent_rgba_pixels() {
        let icon = load_window_icon().expect("the bundled icon.png should always decode");
        assert!(icon.width > 0 && icon.height > 0);
        assert_eq!(
            icon.rgba.len() as u64,
            icon.width as u64 * icon.height as u64 * 4,
            "RGBA byte count should match width*height*4 exactly"
        );
    }

    #[test]
    fn site_for_url_falls_back_to_the_whole_string_for_an_unparseable_url() {
        assert_eq!(site_for_url("not a url at all"), "not a url at all");
    }

    #[test]
    fn site_for_url_routes_every_file_url_to_the_one_dedicated_site_key() {
        // Two DIFFERENT local files must still land on the SAME site
        // key (see `LOCAL_FILES_SITE`'s own doc comment) -- otherwise
        // every distinct file:// path would get its own renderer
        // process, defeating the whole point of a single dedicated,
        // isolated process for all of them.
        assert_eq!(site_for_url("file:///home/user/a.html"), LOCAL_FILES_SITE);
        assert_eq!(site_for_url("file:///home/user/b/c.html"), LOCAL_FILES_SITE);
        assert_ne!(LOCAL_FILES_SITE, site_for_url("https://example.com/"));
    }

    /// `app`'s own tests can only exercise real, spawned renderer
    /// subprocesses against real external URLs (see e.g.
    /// `a_real_navigation_through_the_pool_still_produces_a_real_title`)
    /// — there's no fake-fetcher injection point at this layer, so a
    /// page containing an `<input>` isn't something these tests can
    /// control. `find_layout_box_by_id` is the one PURE piece of this
    /// session's click-to-focus wiring, so it gets its own isolated
    /// test here; the actual focus/cursor/keydown/input/submit LOGIC
    /// is exhaustively covered against real Boa+layout+DOM code in
    /// `renderer::script`'s and `renderer`'s own test modules instead.
    #[test]
    fn find_layout_box_by_id_locates_a_nested_box_by_its_dom_node_id() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        let outer = dom::Node::new_element("div");
        let inner = dom::Node::new_element("input");
        let inner_id = inner.borrow().id;
        dom::append_child(&outer, inner);
        dom::append_child(&document, outer);

        let tree = layout::build_layout_tree(&document, &stylesheet);
        let found = find_layout_box_by_id(&tree, inner_id).expect("should find the nested input");
        assert!(found.text_input.is_some());

        assert!(find_layout_box_by_id(&tree, dom::NodeId(999_999)).is_none());
    }

    #[test]
    fn navigating_two_tabs_to_different_sites_spawns_two_renderer_processes() {
        let mut browser = test_browser();
        browser.navigate("https://example.com/");
        browser.open_new_tab();
        browser.navigate("https://example.org/");
        assert_eq!(browser.renderers.open_site_count(), 2);
    }

    #[test]
    fn sanitize_download_filename_strips_path_traversal_and_separators() {
        assert_eq!(sanitize_download_filename("../../etc/passwd"), "etcpasswd");
        assert_eq!(sanitize_download_filename("a/b\\c"), "abc");
    }

    #[test]
    fn sanitize_download_filename_falls_back_for_nothing_usable() {
        assert_eq!(sanitize_download_filename(""), "download");
        assert_eq!(sanitize_download_filename("..."), "download");
        assert_eq!(sanitize_download_filename("/"), "download");
    }

    #[test]
    fn sanitize_download_filename_keeps_an_ordinary_name_unchanged() {
        assert_eq!(sanitize_download_filename("report.pdf"), "report.pdf");
    }

    #[test]
    fn unique_download_path_uses_the_plain_name_when_nothing_exists_yet() {
        let dir = std::env::temp_dir().join(format!(
            "abyssal-download-path-test-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(
            unique_download_path(&dir, "report.pdf"),
            dir.join("report.pdf")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unique_download_path_appends_a_number_before_the_extension_on_collision() {
        let dir = std::env::temp_dir().join(format!(
            "abyssal-download-path-test-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("report.pdf"), b"existing").unwrap();

        assert_eq!(
            unique_download_path(&dir, "report.pdf"),
            dir.join("report (1).pdf")
        );

        std::fs::write(dir.join("report (1).pdf"), b"existing too").unwrap();
        assert_eq!(
            unique_download_path(&dir, "report.pdf"),
            dir.join("report (2).pdf")
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unique_download_path_handles_a_name_with_no_extension() {
        let dir = std::env::temp_dir().join(format!(
            "abyssal-download-path-test-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("README"), b"existing").unwrap();

        assert_eq!(unique_download_path(&dir, "README"), dir.join("README (1)"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn format_size_uses_bytes_kb_or_mb_as_appropriate() {
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(2048), "2.0 KB");
        assert_eq!(format_size(5 * 1024 * 1024), "5.0 MB");
    }

    #[test]
    fn render_downloads_html_shows_a_placeholder_when_empty() {
        assert!(render_downloads_html(&[]).contains("No downloads yet"));
    }

    #[test]
    fn render_downloads_html_lists_newest_first_with_filename_size_and_path() {
        let downloads = vec![
            DownloadRecord {
                url: "https://example.com/old.pdf".to_string(),
                filename: "old.pdf".to_string(),
                saved_path: std::path::PathBuf::from("/tmp/old.pdf"),
                downloaded_at_unix: 100,
                size_bytes: 1024,
            },
            DownloadRecord {
                url: "https://example.com/new.pdf".to_string(),
                filename: "new.pdf".to_string(),
                saved_path: std::path::PathBuf::from("/tmp/new.pdf"),
                downloaded_at_unix: 200,
                size_bytes: 2048,
            },
        ];
        let html = render_downloads_html(&downloads);
        assert!(html.contains("new.pdf"));
        assert!(html.contains("old.pdf"));
        assert!(html.contains("/tmp/new.pdf"));
        let new_pos = html.find("new.pdf").unwrap();
        let old_pos = html.find("old.pdf").unwrap();
        assert!(
            new_pos < old_pos,
            "the most recently downloaded file should be listed first"
        );
    }

    #[test]
    fn render_downloads_html_links_the_saved_path_as_a_real_file_url() {
        // `std::env::temp_dir()` rather than a hardcoded `/tmp/...`
        // literal: a real, OS-native ABSOLUTE path on every platform
        // this project targets, including Windows, where `/tmp/...`
        // is not absolute at all (no drive letter) and
        // `url::Url::from_file_path` correctly refuses it -- which is
        // exactly the real-world bug a hardcoded Unix path would have
        // hidden from this very test (it did, until this ran on real
        // Windows CI: see `THREAT_MODEL.md`'s renderer-sandbox
        // section).
        let saved_path = std::env::temp_dir().join("abyssal-test-report.pdf");
        let expected_href = url::Url::from_file_path(&saved_path)
            .expect("a real OS temp dir is always a valid absolute path")
            .to_string();
        let downloads = vec![DownloadRecord {
            url: "https://example.com/report.pdf".to_string(),
            filename: "report.pdf".to_string(),
            saved_path: saved_path.clone(),
            downloaded_at_unix: 100,
            size_bytes: 1024,
        }];
        let html = render_downloads_html(&downloads);
        let expected = format!(
            "<a href=\"{expected_href}\">{}</a>",
            html_escape(&saved_path.display().to_string())
        );
        assert!(
            html.contains(&expected),
            "expected a real clickable file:// link to the saved path, got: {html}"
        );
    }

    #[test]
    fn download_fetches_a_real_url_saves_it_to_disk_and_records_it() {
        let mut browser = test_browser();
        browser.download("https://example.com/", "");

        assert_eq!(browser.downloads.len(), 1);
        let record = &browser.downloads[0];
        assert_eq!(record.url, "https://example.com/");
        // No `download` attribute value was given, so the filename came
        // from the renderer's own URL-derived fallback (see
        // `renderer::download::filename_from_url`) — a trailing slash
        // with nothing after it has no usable path segment at all, so
        // it falls all the way back to the generic name.
        assert_eq!(record.filename, "download");
        assert!(record.size_bytes > 0);
        assert!(
            record.saved_path.exists(),
            "the file should actually exist on disk at the recorded path"
        );
        assert_eq!(
            std::fs::read(&record.saved_path).unwrap().len(),
            record.size_bytes
        );
    }

    #[test]
    fn download_uses_the_download_attributes_value_over_the_url_derived_name() {
        let mut browser = test_browser();
        browser.download("https://example.com/", "my-page.html");

        assert_eq!(browser.downloads[0].filename, "my-page.html");
    }

    #[test]
    fn a_second_download_of_the_same_suggested_name_does_not_overwrite_the_first() {
        let mut browser = test_browser();
        browser.download("https://example.com/", "same-name.html");
        browser.download("https://example.org/", "same-name.html");

        assert_eq!(browser.downloads.len(), 2);
        assert_ne!(
            browser.downloads[0].saved_path,
            browser.downloads[1].saved_path
        );
        assert!(browser.downloads[0].saved_path.exists());
        assert!(browser.downloads[1].saved_path.exists());
    }

    #[test]
    fn download_history_persists_across_a_fresh_browser_pointed_at_the_same_data_dir() {
        let data_dir = std::env::temp_dir().join(format!(
            "abyssal-download-history-test-{}",
            std::process::id()
        ));
        {
            let mut browser = Browser::new_with_data_dir(None, data_dir.clone());
            browser.download("https://example.com/", "persisted.html");
            assert_eq!(browser.downloads.len(), 1);
        }

        let reopened = Browser::new_with_data_dir(None, data_dir.clone());
        assert_eq!(reopened.downloads.len(), 1);
        assert_eq!(reopened.downloads[0].filename, "persisted.html");

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[test]
    fn loading_the_downloads_page_shows_a_prior_download() {
        let mut browser = test_browser();
        browser.download("https://example.com/", "shown.html");

        browser.load_downloads_page();

        assert_eq!(browser.active_tab().current_url, "about:downloads");
        assert_eq!(browser.window_title(), "Downloads");
    }

    fn tiny_cached_pcm() -> media_playback::CachedPcm {
        media_playback::CachedPcm {
            samples: std::sync::Arc::new(vec![0i16; 100]),
            sample_rate: 44_100,
            channels: 2,
        }
    }

    #[test]
    fn toggle_media_mute_persists_even_with_nothing_playing() {
        let mut browser = test_browser();
        let tab_id = browser.active_tab().id;
        let node_id = dom::NodeId(1);

        assert!(!browser.active_tab().media_muted.contains_key(&node_id));
        browser.toggle_media_mute(tab_id, node_id);
        assert_eq!(browser.active_tab().media_muted.get(&node_id), Some(&true));
        browser.toggle_media_mute(tab_id, node_id);
        assert_eq!(browser.active_tab().media_muted.get(&node_id), Some(&false));
    }

    #[test]
    fn pause_media_with_nothing_playing_is_a_harmless_no_op() {
        let mut browser = test_browser();
        let tab_id = browser.active_tab().id;
        browser.pause_media(tab_id, dom::NodeId(1)); // should not panic
        assert!(browser.active_tab().active_playback.is_empty());
    }

    #[test]
    fn seek_media_with_nothing_cached_and_no_live_session_is_a_harmless_no_op() {
        let mut browser = test_browser();
        let tab_id = browser.active_tab().id;
        // No `renderer_site` on the demo page, so `fetch_and_cache_pcm`
        // can't reach a renderer — should return early, not panic.
        browser.seek_media(tab_id, dom::NodeId(1), 0.5);
        assert!(browser.active_tab().media_position.is_empty());
    }

    #[test]
    fn handle_media_progress_tick_with_nothing_playing_reports_no_change() {
        let mut browser = test_browser();
        assert!(!browser.handle_media_progress_tick(std::time::Instant::now()));
    }

    /// `play_media`/`pause_media`/`seek_media` all depend on this
    /// environment having a REAL, usable audio output device to fully
    /// exercise (see `media_playback`'s own tests for why that's not
    /// guaranteed everywhere) — this test verifies whichever path
    /// actually happens is internally consistent, rather than
    /// asserting one specific outcome. A `CachedPcm` is inserted
    /// directly (bypassing the IPC fetch step, which `renderer`'s own
    /// tests already cover) so this can run with no live renderer
    /// session at all.
    ///
    /// `#[ignore]`d for the same reason as `media_playback`'s own
    /// `start_playback_*` tests (see their doc comments): this calls
    /// `play_media`, which calls the real `media_playback::
    /// start_playback`, which opens a real `cpal` stream. The graceful
    /// `Err`/no-op handling this test's own name describes only
    /// covers a clean `cpal::Error` -- on a real, headless Windows CI
    /// runner this instead crashed the whole test binary with a native
    /// `STATUS_ACCESS_VIOLATION`, which is exactly the class of
    /// failure Rust's `Result`/panic machinery cannot catch no matter
    /// how gracefully the CALLING code (this test included) is
    /// written.
    #[test]
    #[ignore = "calls play_media, which opens a real audio device; crashes with STATUS_ACCESS_VIOLATION on headless Windows CI -- run manually with real audio hardware"]
    fn play_then_pause_media_is_internally_consistent_regardless_of_audio_hardware() {
        let mut browser = test_browser();
        let tab_id = browser.active_tab().id;
        let node_id = dom::NodeId(1);
        browser
            .active_tab_mut()
            .media_pcm_cache
            .insert(node_id, tiny_cached_pcm());

        browser.play_media(tab_id, node_id);

        if !browser.active_tab().active_playback.contains_key(&node_id) {
            println!("skipping the rest: no usable audio output in this environment");
            return;
        }
        assert!(
            browser.active_tab().next_media_tick_at.is_some(),
            "starting playback should have armed a progress-tick wake-up"
        );

        std::thread::sleep(std::time::Duration::from_millis(50));
        browser.pause_media(tab_id, node_id);

        assert!(
            !browser.active_tab().active_playback.contains_key(&node_id),
            "pausing should stop (drop) the live stream"
        );
        assert!(
            browser
                .active_tab()
                .media_position
                .get(&node_id)
                .copied()
                .unwrap_or(0.0)
                >= 0.0,
            "pausing should have recorded a position to resume from"
        );
    }

    /// Deliberately does NOT call `play_media` here (an earlier version
    /// did, "to also cover `active_playback`/`next_media_tick_at`
    /// clearing") -- that calls the real, hardware-dependent
    /// `media_playback::start_playback` and crashed real, headless
    /// Windows CI with a native `STATUS_ACCESS_VIOLATION` (see
    /// `play_then_pause_media_is_internally_consistent_regardless_of_
    /// audio_hardware`'s own doc comment for the same failure mode).
    /// `active_playback`/`next_media_tick_at` clearing on a REAL,
    /// non-empty stream is still covered there, on a real audio
    /// device, when one exists; this test covers what it safely can
    /// without touching hardware at all -- `media_pcm_cache`/
    /// `media_position`/`media_muted` are populated directly, so
    /// clearing them on navigate-away is proven regardless of this
    /// environment's audio situation. `active_playback` is asserted
    /// empty too, but that's trivially true without a real stream ever
    /// having been inserted -- not meaningful coverage on its own here.
    #[test]
    fn navigating_away_stops_and_clears_all_media_playback_state() {
        let mut browser = test_browser();
        let node_id = dom::NodeId(1);
        browser
            .active_tab_mut()
            .media_pcm_cache
            .insert(node_id, tiny_cached_pcm());
        browser.active_tab_mut().media_muted.insert(node_id, true);
        browser.active_tab_mut().media_position.insert(node_id, 5.0);

        browser.load_bookmarks_page();

        assert!(browser.active_tab().active_playback.is_empty());
        assert!(browser.active_tab().media_pcm_cache.is_empty());
        assert!(browser.active_tab().media_position.is_empty());
        assert!(browser.active_tab().media_muted.is_empty());
        assert!(browser.active_tab().next_media_tick_at.is_none());
    }

    /// `RELEASES_REPO` is `None` in `renderer::update_check` until this
    /// project actually has a GitHub home (see that module's own doc
    /// comment) — so this hits real IPC to a real spawned renderer
    /// process end to end, but never makes a real network call (the
    /// renderer reports `CheckFailed` before ever trying to fetch
    /// anything), keeping this test hermetic.
    #[test]
    fn maybe_check_for_update_spawns_its_own_dedicated_process_and_reschedules() {
        let mut browser = test_browser();
        assert!(browser.update_checker_process.is_none());

        let now = std::time::Instant::now();
        browser.next_update_check_at = Some(now); // force it due
        let ran = browser.maybe_check_for_update(now);

        assert!(ran, "a due check should report that it ran");
        assert!(
            browser.update_checker_process.is_some(),
            "should have spawned its own dedicated process rather than reusing/needing a tab's"
        );
        assert!(
            browser.next_update_check_at.unwrap() > now,
            "should reschedule the next check into the future regardless of outcome"
        );
    }

    #[test]
    fn maybe_check_for_update_is_a_no_op_before_its_due_time() {
        let mut browser = test_browser();
        let now = std::time::Instant::now();
        browser.next_update_check_at = Some(now + std::time::Duration::from_secs(3600));

        assert!(!browser.maybe_check_for_update(now));
        assert!(browser.update_checker_process.is_none());
    }

    #[test]
    fn earliest_wake_at_considers_a_due_update_check_even_with_no_tab_timers() {
        let mut browser = test_browser();
        for tab in &mut browser.tabs {
            tab.next_wake_at = None;
        }
        let due_at = std::time::Instant::now() + std::time::Duration::from_secs(30);
        browser.next_update_check_at = Some(due_at);

        assert_eq!(browser.earliest_wake_at(), Some(due_at));
    }

    #[test]
    fn navigating_two_tabs_to_the_same_site_shares_one_renderer_process() {
        let mut browser = test_browser();
        browser.navigate("https://example.com/");
        browser.open_new_tab();
        browser.navigate("https://example.com/");
        assert_eq!(
            browser.renderers.open_site_count(),
            1,
            "two tabs on the same site should never get two separate processes"
        );
    }

    #[test]
    fn navigating_a_tabs_only_reference_to_a_site_away_evicts_its_process() {
        let mut browser = test_browser();
        browser.navigate("https://example.com/");
        assert_eq!(browser.renderers.open_site_count(), 1);
        browser.navigate("https://example.org/");
        assert_eq!(
            browser.renderers.open_site_count(),
            1,
            "example.com's process should have been evicted once nothing referenced it any more, not left running"
        );
    }

    #[test]
    fn a_second_tab_on_the_same_site_keeps_its_process_alive_after_the_first_navigates_away() {
        let mut browser = test_browser();
        browser.navigate("https://example.com/");
        browser.open_new_tab();
        browser.navigate("https://example.com/");
        browser.active_tab_index = 0;
        browser.navigate("https://example.org/");
        assert_eq!(
            browser.renderers.open_site_count(),
            2,
            "example.com's process must survive for the second tab still showing it"
        );
    }

    #[test]
    fn closing_the_last_tab_on_a_site_evicts_its_process() {
        let mut browser = test_browser();
        browser.navigate("https://example.com/");
        browser.open_new_tab();
        browser.navigate("https://example.org/");
        assert_eq!(browser.renderers.open_site_count(), 2);
        browser.close_tab(1);
        assert_eq!(browser.renderers.open_site_count(), 1);
    }

    #[test]
    fn leaving_a_renderer_backed_page_for_an_about_page_evicts_an_unreferenced_site() {
        let mut browser = test_browser();
        browser.navigate("https://example.com/");
        assert_eq!(browser.renderers.open_site_count(), 1);
        browser.load_demo_page();
        assert_eq!(browser.renderers.open_site_count(), 0);
    }

    #[test]
    fn a_real_navigation_through_the_pool_still_produces_a_real_title() {
        let mut browser = test_browser();
        browser.navigate("https://example.com/");
        assert_eq!(browser.window_title(), "Example Domain");
    }

    /// End-to-end proof that `file://` support works through the exact
    /// same real pipeline as any other navigation -- `Browser::navigate`
    /// -> `site_for_url` routes it to `LOCAL_FILES_SITE` ->
    /// `RendererPool::get_or_spawn` spawns a REAL `abyssal-renderer`
    /// child process with `--allow-local-files` -> that process's own
    /// sandbox (broad Landlock read, zero network -- see
    /// `renderer::sandbox`) and `FilteringFetcher` (see
    /// `enable_local_file_access`) actually read a real file off this
    /// machine's real disk and render it, the same as any `https://`
    /// navigation renders real bytes a real server sent.
    #[test]
    fn a_real_file_url_is_read_off_disk_and_rendered_through_a_dedicated_process() {
        let dir = std::env::temp_dir().join(format!(
            "abyssal-test-local-file-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("page.html");
        std::fs::write(
            &file_path,
            "<html><head><title>Local File Title</title></head>\
             <body><p>hello from disk</p></body></html>",
        )
        .unwrap();

        let mut browser = test_browser();
        browser.navigate(&format!("file://{}", file_path.display()));

        assert_eq!(browser.window_title(), "Local File Title");
        let mut text = String::new();
        collect_page_text(&browser.active_tab().layout_tree, &mut text);
        assert!(
            text.contains("hello from disk"),
            "expected the real file's own body text to render, got: {text}"
        );
        assert_eq!(
            browser.renderers.open_site_count(),
            1,
            "a single file:// navigation should spawn exactly one dedicated process"
        );
    }

    /// The dedicated `file://` process's own `--allow-local-files` flag
    /// (and the broad-read/zero-network sandbox and `FilteringFetcher`
    /// state that comes with it) is only ever granted to a process
    /// spawned for `LOCAL_FILES_SITE` -- `RendererPool::get_or_spawn`
    /// computes that flag from the site key itself, so an ordinary
    /// website's process (any OTHER site key) can never get it, and
    /// `network`'s own tests (`a_file_url_is_rejected_when_local_file_
    /// access_is_not_enabled`) already prove what such a process does
    /// with a `file://` fetch attempt when the flag is absent: it's
    /// rejected before ever touching disk. This test proves the OTHER
    /// half at this layer -- that a real navigation to an ordinary site
    /// never lands on `LOCAL_FILES_SITE` in the first place.
    #[test]
    fn an_ordinary_site_navigation_never_spawns_the_dedicated_local_files_process() {
        let mut browser = test_browser();
        browser.navigate("https://example.com/");
        assert!(
            !browser.renderers.processes.contains_key(LOCAL_FILES_SITE),
            "an ordinary https:// navigation must never spawn the dedicated file:// process"
        );
    }

    fn collect_page_text(node: &layout::LayoutBox, out: &mut String) {
        if let Some(text) = &node.text {
            out.push_str(&text.raw);
        }
        for child in &node.children {
            collect_page_text(child, out);
        }
    }

    #[test]
    fn navigate_with_body_sends_a_real_post_and_the_response_reflects_the_posted_field() {
        let mut browser = test_browser();
        // httpbin.org/post echoes back whatever it received (including
        // the request body) as a JSON page — a real, independent
        // server actually receiving and reflecting a real POST is the
        // one thing a fake/local fetcher could never prove: that this
        // browser's OWN pipeline (`app::navigate_with_body` ->
        // `ipc::RenderRequest::body` -> `renderer::navigate` ->
        // `network::FilteringFetcher::fetch_in_context_with_body` ->
        // a real `reqwest` POST) actually produces bytes on the wire
        // that look like a real form submission, not just that this
        // crate's own internal types agree with each other.
        browser.navigate_with_body(
            "https://httpbin.org/post",
            b"abyssal_test_field=abyssal_test_value".to_vec(),
        );

        let mut text = String::new();
        collect_page_text(&browser.active_tab().layout_tree, &mut text);
        assert!(
            text.contains("abyssal_test_field") && text.contains("abyssal_test_value"),
            "expected the real POST body to be echoed back in httpbin's response, got: {text}"
        );
    }

    #[test]
    fn a_real_set_cookie_response_is_persisted_encrypted_and_readable_with_the_real_key() {
        // A real, independent server actually setting a real Set-Cookie
        // header is the one thing a fake fetcher could never prove
        // here: that this browser's OWN pipeline (`renderer`'s real
        // `Set-Cookie` handling -> `ipc::ServerMessage::updated_cookies`
        // -> `RendererProcess::try_send` -> `persist_encrypted_merge`)
        // produces a REAL encrypted file on disk, not just that this
        // crate's own types agree with each other.
        let mut browser = test_browser();
        browser.navigate("https://httpbin.org/cookies/set/abyssal_test_cookie/abyssal_test_value");

        let cookies_path = browser.data_dir.join("cookies.enc");
        let encrypted = std::fs::read(&cookies_path)
            .unwrap_or_else(|e| panic!("expected {cookies_path:?} to exist: {e}"));

        // Genuinely encrypted, not just written somewhere non-obvious:
        // the real cookie name/value must not appear anywhere in the
        // raw on-disk bytes.
        let raw_text = String::from_utf8_lossy(&encrypted);
        assert!(
            !raw_text.contains("abyssal_test_cookie") && !raw_text.contains("abyssal_test_value"),
            "the real cookie value must not be readable in the raw file bytes"
        );

        // But it IS readable with the real, derived account key — the
        // same key `Browser` itself computed at startup (see
        // `StoragePersistence`) — proving this isn't just corrupted or
        // wrongly-shaped data that happens to not contain the substring.
        let key = account::derive_key(&browser.account.recovery_code, &browser.account.kdf_salt);
        let plaintext =
            account::decrypt(&key, &encrypted).expect("should decrypt with the real key");
        let entries: Vec<serde_json::Value> = serde_json::from_slice(&plaintext).unwrap();
        let found = entries.iter().any(|entry| {
            entry.get("resource_host").and_then(|v| v.as_str()) == Some("httpbin.org")
                && entry
                    .get("cookies")
                    .and_then(|c| c.get("abyssal_test_cookie"))
                    .and_then(|v| v.as_str())
                    == Some("abyssal_test_value")
        });
        assert!(
            found,
            "expected the real cookie in the decrypted entries, got: {entries:?}"
        );
    }

    #[test]
    fn a_fresh_renderer_process_is_seeded_with_a_previously_persisted_cookie() {
        // Simulates what happens across a real restart: one Browser
        // instance persists a real cookie (via the pipeline the test
        // above already proved is genuinely encrypted), then a SECOND,
        // independent `Browser` pointed at the SAME data directory
        // (mirroring a real app restart, or evicting and re-spawning a
        // renderer process mid-session) should come back up already
        // logged in, seeded from the encrypted file the first instance
        // wrote — never from a plaintext file the renderer read itself.
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let data_dir = std::env::temp_dir().join(format!(
            "abyssal-test-data-cookie-reseed-{}-{n}",
            std::process::id()
        ));

        let mut first = Browser::new_with_data_dir(None, data_dir.clone());
        first
            .navigate("https://httpbin.org/cookies/set/abyssal_reseed_cookie/abyssal_reseed_value");
        drop(first);

        let mut second = Browser::new_with_data_dir(None, data_dir);
        second.navigate("https://httpbin.org/cookies");

        let mut text = String::new();
        collect_page_text(&second.active_tab().layout_tree, &mut text);
        assert!(
            text.contains("abyssal_reseed_cookie") && text.contains("abyssal_reseed_value"),
            "expected the second Browser instance's renderer to have sent back the cookie \
             persisted by the first one, got page text: {text}"
        );
    }

    #[test]
    fn the_built_in_demo_page_shows_the_real_quote_with_no_network_access() {
        let browser = test_browser();
        // `test_browser` already opens the demo page (no URL given) -
        // this goes through the exact same `html::parse` ->
        // `css::user_agent_stylesheet` -> `layout::build_layout_tree`
        // pipeline any real fetched page does, so a real parse/layout
        // panic here would be a real bug, not a test-only concern.
        let mut text = String::new();
        collect_page_text(&browser.active_tab().layout_tree, &mut text);
        assert!(
            text.contains("gaze long into the Abyss"),
            "expected the demo page to show the real quote, got: {text}"
        );
        assert!(text.contains("Nietzsche"));
    }

    #[test]
    fn a_successful_navigation_records_a_history_entry_with_its_title() {
        let mut browser = test_browser();
        browser.navigate("https://example.com/");

        assert_eq!(browser.bookmarks.history.len(), 1);
        assert_eq!(browser.bookmarks.history[0].url, "https://example.com/");
        assert_eq!(
            browser.bookmarks.history[0].title,
            Some("Example Domain".to_string())
        );
    }

    #[test]
    fn a_failed_navigation_does_not_get_recorded_in_history() {
        let mut browser = test_browser();
        // No renderer process anywhere can resolve this as a real host —
        // exercises the same "Failed to load" path
        // `handle_message_navigate_reports_a_fetch_failure_as_an_error`
        // covers at the renderer layer, from `app`'s side this time.
        browser.navigate("https://this-domain-should-not-exist-abyssal-test.invalid/");
        assert!(
            browser.bookmarks.history.is_empty(),
            "a failed fetch shouldn't pollute browsing history"
        );
    }

    #[test]
    fn about_pages_are_never_recorded_in_history() {
        let mut browser = test_browser();
        browser.load_demo_page();
        browser.load_bookmarks_page();
        browser.load_settings_page();
        browser.load_history_page();
        assert!(browser.bookmarks.history.is_empty());
    }

    #[test]
    fn render_history_html_lists_entries_newest_first_with_a_clear_link() {
        let mut payload = storage::SyncPayload::new();
        payload.record_visit("https://first.example", Some("First"));
        payload.record_visit("https://second.example", None);

        let html = render_history_html(&payload);
        assert!(html.contains("history:clear"));
        // Newest (second.example, no title -> falls back to the bare
        // URL) appears before the older "First" entry.
        let second_pos = html.find("second.example").unwrap();
        let first_pos = html.find("First").unwrap();
        assert!(
            second_pos < first_pos,
            "the most recently visited page should be listed first"
        );
    }

    #[test]
    fn render_history_html_shows_a_placeholder_when_empty() {
        let html = render_history_html(&storage::SyncPayload::new());
        assert!(html.contains("No history yet"));
    }

    #[test]
    fn format_relative_time_reports_coarse_buckets() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(format_relative_time(now), "just now");
        assert_eq!(format_relative_time(now - 90), "1 minute ago");
        assert_eq!(format_relative_time(now - 7200), "2 hours ago");
        assert_eq!(format_relative_time(now - 3 * 86400), "3 days ago");
    }

    #[test]
    fn ctrl_f_opens_the_find_bar_and_cancels_an_in_progress_address_bar_edit() {
        let mut browser = test_browser();
        browser.active_tab_mut().editing_address_bar = true;
        browser.active_tab_mut().address_bar_text = "some in-progress edit".to_string();

        browser.handle_event(InputEvent::Find);

        assert!(browser.active_tab().finding_in_page);
        assert!(!browser.active_tab().editing_address_bar);
    }

    #[test]
    fn typing_a_query_while_finding_populates_matches() {
        let mut browser = test_browser(); // demo page, contains "the" at least twice
        browser.handle_event(InputEvent::Find);

        for c in "the".chars() {
            browser.handle_event(InputEvent::CharTyped(c));
        }

        assert_eq!(browser.active_tab().find_query, "the");
        assert!(
            browser.active_tab().find_matches.len() >= 2,
            "expected at least 2 matches of \"the\" on the demo page, got {}",
            browser.active_tab().find_matches.len()
        );
    }

    #[test]
    fn backspace_while_finding_edits_the_query_and_refreshes_matches() {
        let mut browser = test_browser();
        browser.handle_event(InputEvent::Find);
        for c in "thexyz".chars() {
            browser.handle_event(InputEvent::CharTyped(c));
        }
        assert!(browser.active_tab().find_matches.is_empty()); // "thexyz" matches nothing

        for _ in 0..3 {
            browser.handle_event(InputEvent::Backspace);
        }

        assert_eq!(browser.active_tab().find_query, "the");
        assert!(!browser.active_tab().find_matches.is_empty());
    }

    #[test]
    fn find_next_and_find_previous_cycle_through_matches_with_wraparound() {
        let mut browser = test_browser();
        browser.handle_event(InputEvent::Find);
        for c in "the".chars() {
            browser.handle_event(InputEvent::CharTyped(c));
        }
        let match_count = browser.active_tab().find_matches.len();
        assert!(match_count >= 2);

        assert_eq!(browser.active_tab().find_current_index, 0);
        browser.handle_event(InputEvent::Enter);
        assert_eq!(browser.active_tab().find_current_index, 1);

        browser.handle_event(InputEvent::FindPrevious);
        assert_eq!(browser.active_tab().find_current_index, 0);

        // Wraps backward from the first match to the last.
        browser.handle_event(InputEvent::FindPrevious);
        assert_eq!(browser.active_tab().find_current_index, match_count - 1);
    }

    #[test]
    fn escape_while_finding_closes_the_bar_and_clears_the_query() {
        let mut browser = test_browser();
        browser.handle_event(InputEvent::Find);
        browser.handle_event(InputEvent::CharTyped('t'));

        browser.handle_event(InputEvent::Escape);

        assert!(!browser.active_tab().finding_in_page);
        assert!(browser.active_tab().find_query.is_empty());
        assert!(browser.active_tab().find_matches.is_empty());
    }

    #[test]
    fn navigating_away_closes_an_open_find_bar() {
        let mut browser = test_browser();
        browser.handle_event(InputEvent::Find);
        browser.handle_event(InputEvent::CharTyped('t'));
        assert!(browser.active_tab().finding_in_page);

        browser.load_bookmarks_page();

        assert!(!browser.active_tab().finding_in_page);
    }

    #[test]
    fn find_previous_outside_a_find_session_is_a_harmless_no_op() {
        let mut browser = test_browser();
        assert!(browser.handle_event(InputEvent::FindPrevious).is_some());
        assert!(!browser.active_tab().finding_in_page);
    }

    #[test]
    fn each_tabs_renderer_site_matches_the_page_it_actually_navigated_to() {
        // Not just "two processes exist" (see the count-based tests
        // above) but that EACH tab is tracked against the CORRECT one
        // — the field `handle_tick`/`handle_click` actually route
        // through to reach the right process for a given tab.
        let mut browser = test_browser();
        browser.navigate("https://example.com/");
        browser.open_new_tab();
        browser.navigate("https://example.net/");

        assert_eq!(browser.renderers.open_site_count(), 2);
        assert_eq!(
            browser.tabs[0].renderer_site.as_deref(),
            Some("example.com")
        );
        assert_eq!(
            browser.tabs[1].renderer_site.as_deref(),
            Some("example.net")
        );
    }

    #[test]
    fn dom_node_label_formats_an_element_with_id_and_class() {
        let node = ipc::DomNode {
            node_id: dom::NodeId(1),
            kind: ipc::DomNodeKind::Element {
                tag_name: "div".to_string(),
                attributes: vec![
                    ("class".to_string(), "y z".to_string()),
                    ("id".to_string(), "x".to_string()),
                ],
            },
            children: Vec::new(),
        };
        assert_eq!(dom_node_label(&node), "<div id=\"x\" class=\"y z\">");
    }

    #[test]
    fn dom_node_label_shows_hash_text_for_whitespace_only_text_nodes() {
        let node = ipc::DomNode {
            node_id: dom::NodeId(1),
            kind: ipc::DomNodeKind::Text("   \n  ".to_string()),
            children: Vec::new(),
        };
        assert_eq!(dom_node_label(&node), "#text");
    }

    #[test]
    fn dom_node_label_previews_non_blank_text_in_quotes() {
        let node = ipc::DomNode {
            node_id: dom::NodeId(1),
            kind: ipc::DomNodeKind::Text("hello world".to_string()),
            children: Vec::new(),
        };
        assert_eq!(dom_node_label(&node), "\"hello world\"");
    }

    #[test]
    fn flatten_dom_tree_visits_nodes_in_document_order_with_depth() {
        let leaf = ipc::DomNode {
            node_id: dom::NodeId(3),
            kind: ipc::DomNodeKind::Text("x".to_string()),
            children: Vec::new(),
        };
        let child = ipc::DomNode {
            node_id: dom::NodeId(2),
            kind: ipc::DomNodeKind::Element {
                tag_name: "span".to_string(),
                attributes: Vec::new(),
            },
            children: vec![leaf],
        };
        let root = ipc::DomNode {
            node_id: dom::NodeId(1),
            kind: ipc::DomNodeKind::Document,
            children: vec![child],
        };

        let mut rows = Vec::new();
        flatten_dom_tree(&root, 0, &mut rows);

        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].0, 0);
        assert_eq!(rows[0].1.node_id, dom::NodeId(1));
        assert_eq!(rows[1].0, 1);
        assert_eq!(rows[1].1.node_id, dom::NodeId(2));
        assert_eq!(rows[2].0, 2);
        assert_eq!(rows[2].1.node_id, dom::NodeId(3));
    }

    #[test]
    fn toggling_devtools_reserves_and_releases_viewport_height() {
        let mut browser = test_browser();
        assert_eq!(browser.devtools_reserved_height(), 0.0);

        browser.handle_event(InputEvent::ToggleDevTools);
        assert!(browser.active_tab().devtools_open);
        assert_eq!(browser.devtools_reserved_height(), DEVTOOLS_PANEL_HEIGHT);

        browser.handle_event(InputEvent::ToggleDevTools);
        assert!(!browser.active_tab().devtools_open);
        assert_eq!(browser.devtools_reserved_height(), 0.0);
    }

    #[test]
    fn console_scroll_is_clamped_to_the_rows_that_dont_fit() {
        let mut browser = test_browser();
        let visible = Browser::devtools_visible_log_rows();
        for i in 0..(visible + 10) {
            browser
                .active_tab_mut()
                .console_log
                .push(ipc::ConsoleMessage {
                    level: ipc::ConsoleLevel::Log,
                    text: format!("line {i}"),
                });
        }
        assert_eq!(browser.max_console_scroll_rows(), 10);

        browser.scroll_devtools_panel(1_000_000.0);
        assert_eq!(browser.active_tab().console_scroll_rows, 10);

        browser.scroll_devtools_panel(-1_000_000.0);
        assert_eq!(browser.active_tab().console_scroll_rows, 0);
    }

    #[test]
    fn typing_while_the_console_input_is_focused_does_not_touch_the_address_bar() {
        let mut browser = test_browser();
        browser.active_tab_mut().console_input_focused = true;

        browser.handle_event(InputEvent::CharTyped('1'));
        browser.handle_event(InputEvent::CharTyped('+'));
        browser.handle_event(InputEvent::CharTyped('1'));

        assert_eq!(browser.active_tab().console_input, "1+1");
        assert!(!browser.active_tab().editing_address_bar);
    }

    #[test]
    fn backspace_while_console_focused_edits_the_console_input() {
        let mut browser = test_browser();
        browser.active_tab_mut().console_input_focused = true;
        browser.active_tab_mut().console_input = "abc".to_string();

        browser.handle_event(InputEvent::Backspace);

        assert_eq!(browser.active_tab().console_input, "ab");
    }

    #[test]
    fn escape_blurs_the_console_input_without_clearing_its_text() {
        let mut browser = test_browser();
        browser.active_tab_mut().console_input_focused = true;
        browser.active_tab_mut().console_input = "abc".to_string();

        browser.handle_event(InputEvent::Escape);

        assert!(!browser.active_tab().console_input_focused);
        assert_eq!(browser.active_tab().console_input, "abc");
    }

    #[test]
    fn submit_devtools_console_input_with_nothing_typed_is_a_harmless_no_op() {
        let mut browser = test_browser();
        browser.navigate("https://example.com/");
        let before = browser.active_tab().console_log.len();

        browser.submit_devtools_console_input();

        assert_eq!(browser.active_tab().console_log.len(), before);
    }

    #[test]
    fn submit_devtools_console_input_without_a_live_session_is_a_harmless_no_op() {
        let mut browser = test_browser();
        browser.active_tab_mut().console_input = "1".to_string();

        browser.submit_devtools_console_input();

        assert!(browser.active_tab().console_log.is_empty());
    }

    #[test]
    fn submit_devtools_console_input_evals_a_real_expression_on_a_real_page() {
        let mut browser = test_browser();
        browser.navigate("https://example.com/");

        browser.active_tab_mut().console_input = "1 + 2".to_string();
        browser.submit_devtools_console_input();

        let log = &browser.active_tab().console_log;
        assert!(
            log.iter().any(|m| m.text == "> 1 + 2"),
            "expected the typed expression to be echoed, got: {log:?}"
        );
        assert!(
            log.iter().any(|m| m.text == "3"),
            "expected the real evaluated result, got: {log:?}"
        );
        assert!(browser.active_tab().console_input.is_empty());
    }

    #[test]
    fn refresh_dom_snapshot_on_a_real_page_captures_its_real_structure() {
        let mut browser = test_browser();
        browser.navigate("https://example.com/");

        browser.refresh_dom_snapshot();

        let root = browser
            .active_tab()
            .dom_snapshot
            .as_ref()
            .expect("a real, navigated page should produce a real DOM snapshot");
        let mut rows = Vec::new();
        flatten_dom_tree(root, 0, &mut rows);
        assert!(
            rows.iter().any(|(_, node)| matches!(
                &node.kind,
                ipc::DomNodeKind::Element { tag_name, .. } if tag_name == "h1"
            )),
            "example.com's real DOM should contain an <h1>"
        );
    }

    #[test]
    fn refresh_dom_snapshot_without_a_live_session_leaves_it_none() {
        let mut browser = test_browser();
        browser.refresh_dom_snapshot();
        assert!(browser.active_tab().dom_snapshot.is_none());
    }

    #[test]
    fn selecting_a_real_dom_node_id_resolves_to_its_real_layout_box() {
        let mut browser = test_browser();
        browser.navigate("https://example.com/");
        browser.refresh_dom_snapshot();

        let root = browser.active_tab().dom_snapshot.clone().unwrap();
        let mut rows = Vec::new();
        flatten_dom_tree(&root, 0, &mut rows);
        let h1_id = rows
            .iter()
            .find_map(|(_, node)| match &node.kind {
                ipc::DomNodeKind::Element { tag_name, .. } if tag_name == "h1" => {
                    Some(node.node_id)
                }
                _ => None,
            })
            .expect("example.com should have a real <h1>");

        let found = layout::find_box_by_dom_node_id(&browser.active_tab().layout_tree, h1_id);
        assert!(
            found.is_some(),
            "the <h1>'s real dom node id should resolve to a real painted box"
        );
    }

    #[test]
    fn navigating_away_clears_devtools_page_state_but_keeps_the_panel_open() {
        let mut browser = test_browser();
        browser.navigate("https://example.com/");
        browser.handle_event(InputEvent::ToggleDevTools);
        browser
            .active_tab_mut()
            .console_log
            .push(ipc::ConsoleMessage {
                level: ipc::ConsoleLevel::Log,
                text: "hi".to_string(),
            });
        browser.refresh_dom_snapshot();
        browser.active_tab_mut().devtools_selected_node = Some(dom::NodeId(1));
        assert!(browser.active_tab().dom_snapshot.is_some());

        browser.navigate("https://example.net/");

        assert!(
            browser.active_tab().devtools_open,
            "DevTools itself should stay open across a navigation, like a real browser's"
        );
        assert!(browser.active_tab().console_log.is_empty());
        assert!(browser.active_tab().dom_snapshot.is_none());
        assert!(browser.active_tab().devtools_selected_node.is_none());
    }

    #[test]
    fn clicking_the_devtools_tab_bar_switches_between_console_and_elements() {
        let mut browser = test_browser();
        browser.navigate("https://example.com/");
        browser.active_tab_mut().devtools_open = true;
        assert_eq!(browser.active_tab().devtools_tab, DevtoolsTab::Console);

        let panel_top = browser.canvas_height as f32 - DEVTOOLS_PANEL_HEIGHT;
        browser.handle_click(DEVTOOLS_TAB_LABEL_WIDTH + 5.0, panel_top + 5.0);

        assert_eq!(browser.active_tab().devtools_tab, DevtoolsTab::Elements);
    }

    #[test]
    fn clicking_the_console_input_row_takes_keyboard_focus() {
        let mut browser = test_browser();
        browser.active_tab_mut().devtools_open = true;

        let panel_top = browser.canvas_height as f32 - DEVTOOLS_PANEL_HEIGHT;
        let input_row_y = panel_top + DEVTOOLS_PANEL_HEIGHT - 2.0;
        browser.handle_click(10.0, input_row_y);

        assert!(browser.active_tab().console_input_focused);
    }

    #[test]
    fn clicking_the_page_while_picking_selects_something_and_turns_picking_off() {
        let mut browser = test_browser();
        browser.navigate("https://example.com/");
        browser.active_tab_mut().devtools_open = true;
        browser.active_tab_mut().devtools_picking = true;

        browser.handle_click(50.0, CHROME_HEIGHT + 10.0);

        assert!(
            !browser.active_tab().devtools_picking,
            "picking mode should always turn itself off after the next page click"
        );
    }

    #[test]
    fn clicking_the_refresh_button_refetches_the_dom_snapshot() {
        let mut browser = test_browser();
        browser.navigate("https://example.com/");
        browser.active_tab_mut().devtools_open = true;
        browser.active_tab_mut().devtools_tab = DevtoolsTab::Elements;
        assert!(browser.active_tab().dom_snapshot.is_none());

        let panel_top = browser.canvas_height as f32 - DEVTOOLS_PANEL_HEIGHT;
        let width = browser.canvas_width as f32;
        browser.handle_click(width - DEVTOOLS_ACTION_BUTTON_WIDTH / 2.0, panel_top + 5.0);

        assert!(browser.active_tab().dom_snapshot.is_some());
    }

    #[test]
    fn clicking_the_reload_button_refetches_the_current_page_without_touching_history() {
        let mut browser = test_browser();
        browser.navigate("https://example.com/");
        browser.navigate("https://example.com/");
        // Two real navigations to the same URL give `history_back` one
        // entry (the first visit) — reload must leave that alone: it's
        // re-running the CURRENT entry, not creating a new one.
        let back_len_before = browser.active_tab().history_back.len();

        browser.handle_click(RELOAD_BUTTON_X + 1.0, CHROME_HEIGHT - 5.0);

        assert_eq!(browser.window_title(), "Example Domain");
        assert_eq!(browser.active_tab().current_url, "https://example.com/");
        assert_eq!(browser.active_tab().history_back.len(), back_len_before);
    }

    #[test]
    fn clicking_the_bookmark_star_toggles_the_current_pages_bookmark() {
        let mut browser = test_browser();
        browser.navigate("https://example.com/");
        let bookmark_x = browser.bookmark_button_x();
        assert!(!browser.bookmarks.is_bookmarked("https://example.com/"));

        browser.handle_click(bookmark_x + 1.0, CHROME_HEIGHT - 5.0);
        assert!(browser.bookmarks.is_bookmarked("https://example.com/"));

        browser.handle_click(bookmark_x + 1.0, CHROME_HEIGHT - 5.0);
        assert!(!browser.bookmarks.is_bookmarked("https://example.com/"));
    }

    #[test]
    fn the_reload_keyboard_shortcut_refetches_the_current_page() {
        let mut browser = test_browser();
        browser.navigate("https://example.com/");

        browser.handle_event(InputEvent::Reload);

        assert_eq!(browser.window_title(), "Example Domain");
        assert_eq!(browser.active_tab().current_url, "https://example.com/");
    }

    #[test]
    fn the_bookmark_keyboard_shortcut_toggles_the_current_pages_bookmark() {
        let mut browser = test_browser();
        browser.navigate("https://example.com/");

        browser.handle_event(InputEvent::ToggleBookmark);
        assert!(browser.bookmarks.is_bookmarked("https://example.com/"));

        browser.handle_event(InputEvent::ToggleBookmark);
        assert!(!browser.bookmarks.is_bookmarked("https://example.com/"));
    }

    #[test]
    fn clicking_the_account_button_opens_the_account_page() {
        let mut browser = test_browser();
        let account_x = browser.account_button_x();

        browser.handle_click(account_x + 1.0, CHROME_HEIGHT - 5.0);

        assert_eq!(browser.active_tab().current_url, "about:account");
        assert!(browser
            .active_tab()
            .address_bar_text
            .contains("about:account"));
    }

    #[test]
    fn focus_next_on_a_real_page_lands_on_its_one_real_link() {
        let mut browser = test_browser();
        browser.navigate("https://example.com/");

        browser.handle_event(InputEvent::FocusNext);

        let node_id = browser
            .active_tab()
            .keyboard_focus
            .expect("Tab should have focused example.com's one real link");
        let focused_box = find_layout_box_by_id(&browser.active_tab().layout_tree, node_id)
            .expect("the focused node id should resolve to a real box");
        assert!(focused_box.focused);
        assert!(matches!(
            &focused_box.node_type,
            dom::NodeType::Element(el) if el.tag_name == "a"
        ));
    }

    #[test]
    fn focus_next_wraps_back_to_the_same_single_focusable_element() {
        let mut browser = test_browser();
        browser.navigate("https://example.com/");

        browser.handle_event(InputEvent::FocusNext);
        let first = browser.active_tab().keyboard_focus;
        browser.handle_event(InputEvent::FocusNext);
        let second = browser.active_tab().keyboard_focus;

        assert!(first.is_some());
        assert_eq!(
            first, second,
            "with only one focusable element, Tab should wrap back to it"
        );
    }

    #[test]
    fn tab_is_a_no_op_while_a_chrome_text_field_has_focus() {
        let mut browser = test_browser();
        browser.navigate("https://example.com/");

        browser.active_tab_mut().editing_address_bar = true;
        browser.handle_event(InputEvent::FocusNext);
        assert!(browser.active_tab().keyboard_focus.is_none());
        browser.active_tab_mut().editing_address_bar = false;

        browser.handle_event(InputEvent::Find);
        browser.handle_event(InputEvent::FocusNext);
        assert!(browser.active_tab().keyboard_focus.is_none());
        browser.exit_find_mode();

        browser.active_tab_mut().devtools_open = true;
        browser.active_tab_mut().console_input_focused = true;
        browser.handle_event(InputEvent::FocusNext);
        assert!(browser.active_tab().keyboard_focus.is_none());
    }

    #[test]
    fn enter_activates_a_keyboard_focused_link_and_navigates_to_it() {
        let mut browser = test_browser();
        browser.navigate("https://example.com/");
        browser.handle_event(InputEvent::FocusNext);
        assert!(browser.active_tab().keyboard_focus.is_some());

        browser.handle_event(InputEvent::Enter);

        assert_eq!(
            browser.active_tab().current_url,
            "https://iana.org/domains/example"
        );
    }

    #[test]
    fn space_also_activates_a_keyboard_focused_link() {
        let mut browser = test_browser();
        browser.navigate("https://example.com/");
        browser.handle_event(InputEvent::FocusNext);

        browser.handle_event(InputEvent::CharTyped(' '));

        assert_eq!(
            browser.active_tab().current_url,
            "https://iana.org/domains/example"
        );
    }

    #[test]
    fn navigating_away_clears_keyboard_focus() {
        let mut browser = test_browser();
        browser.navigate("https://example.com/");
        browser.handle_event(InputEvent::FocusNext);
        assert!(browser.active_tab().keyboard_focus.is_some());

        browser.navigate("https://example.net/");

        assert!(browser.active_tab().keyboard_focus.is_none());
    }

    #[test]
    fn a_real_installed_userscript_runs_on_a_real_matching_page() {
        let mut browser = test_browser();
        std::fs::create_dir_all(&browser.userscripts_dir).unwrap();
        std::fs::write(
            browser.userscripts_dir.join("append-to-title.js"),
            "// ==UserScript==\n\
             // @match https://example.com/*\n\
             // ==/UserScript==\n\
             document.title = document.title + ' + userscript ran';",
        )
        .unwrap();

        browser.navigate("https://example.com/");

        assert_eq!(
            browser.window_title(),
            "Example Domain + userscript ran",
            "the real installed userscript should have actually run on a real matching page"
        );
    }

    #[test]
    fn local_storage_actually_works_inside_the_real_sandboxed_renderer_process() {
        // Unlike the FakeFetcher-backed tests in `renderer`'s own test
        // suite, `test_browser()` spawns a REAL `abyssal-renderer`
        // subprocess under REAL Landlock/seccomp — exactly the
        // environment that caught this session's earlier `SIGSYS`
        // bugs (`clock_gettime`, then `fchmod` for cookie persistence,
        // which `local_storage::LocalStorageStore::save_merged_to_file`
        // reuses verbatim). A real userscript is the only way to get
        // real, controlled JS running against a real navigated page
        // without hosting a page of our own — see
        // `a_real_installed_userscript_runs_on_a_real_matching_page`,
        // the existing test this borrows the pattern from.
        let mut browser = test_browser();
        std::fs::create_dir_all(&browser.userscripts_dir).unwrap();
        std::fs::write(
            browser.userscripts_dir.join("local-storage-check.js"),
            "// ==UserScript==\n\
             // @match https://example.com/*\n\
             // ==/UserScript==\n\
             localStorage.setItem('abyssal-test-key', 'abyssal-test-value');\n\
             document.title = document.title + ' + ' + localStorage.getItem('abyssal-test-key');",
        )
        .unwrap();

        browser.navigate("https://example.com/");

        assert_eq!(
            browser.window_title(),
            "Example Domain + abyssal-test-value",
            "localStorage.setItem/getItem should really work inside the sandboxed renderer"
        );
    }

    #[test]
    fn an_installed_userscript_that_does_not_match_this_page_does_not_run() {
        let mut browser = test_browser();
        std::fs::create_dir_all(&browser.userscripts_dir).unwrap();
        std::fs::write(
            browser.userscripts_dir.join("append-to-title.js"),
            "// ==UserScript==\n\
             // @match https://example.org/*\n\
             // ==/UserScript==\n\
             document.title = document.title + ' + userscript ran';",
        )
        .unwrap();

        browser.navigate("https://example.com/");

        assert_eq!(
            browser.window_title(),
            "Example Domain",
            "a userscript whose @match doesn't cover this page should never run on it"
        );
    }
}
