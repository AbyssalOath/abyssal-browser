# 06. `app`: UI, window, and browser chrome

Everything here lives in `app/src/main.rs` (one large file) and
`render/src/window.rs`/`render/src/icons.rs`. This page covers the parts of
`app` that aren't the renderer-process plumbing (`01-process-model-and-
ipc.md`) or account/sync (`05-account-storage-sync.md`) -- the window
itself, the `Browser`/`Tab` state, the toolbar, the address bar, keyboard
shortcuts, and the various `about:` pages.

## The window event loop: `render::window`

`render/src/window.rs` is deliberately **DOM-agnostic** -- it knows nothing
about `dom`/`layout`/`script`. It defines two types and one function:

- `InputEvent` -- every real thing that can happen: resize, mouse move/
  click/scroll, typed characters, named keys (`Backspace`/`Enter`/`Escape`/
  arrows/`Home`/`End`), the real keyboard shortcuts already resolved into
  named variants (`NavigateBack` for Alt+Left, `NewTab` for Ctrl+T, `Find`
  for Ctrl+F, `ToggleDevTools` for F12, `ToggleBookmark` for Ctrl+D, and so
  on -- see the type itself for the full list), accessibility actions
  (wraps `accesskit::Action` directly rather than defining a parallel
  vocabulary), and `Tick` (a synthetic "wake up, nothing really happened"
  event, sent only because a *previous* `Frame` asked for it).
- `Frame` -- what `app`'s handler hands back after processing one event: a
  `Canvas` of pixels, an optional new window title, an optional
  `wake_at: Option<Instant>` (the single mechanism `setTimeout` is built
  on -- winit's own `ControlFlow::WaitUntil`, no polling, no background
  thread), and a full `accesskit` tree description.
- `run_window(handler)` -- the actual winit/wgpu event loop, calling
  `handler` once per real event and presenting whatever `Frame` comes back.

This separation is why `render` never depends on `app`, `dom`, or `script`
-- it's a genuinely reusable "turn events into pixels" shell that `app`'s
`Browser::handle_event` (see below) is the sole real implementation of.

## `Browser` and `Tab`

`Browser` (in `app/src/main.rs`) is the one struct that owns everything
that must stay singular across every open tab: the `RendererPool`, the
account, the synced bookmarks/settings, theme/fingerprint/WebRTC
preferences, and the window's own canvas size. `Tab` is everything that's
genuinely per-tab: its `ipc::TabId` (stable for the tab's life, never
reused -- deliberately NOT its position in `Browser::tabs`, which shifts
whenever another tab closes), the current URL, the last laid-out
`layout::LayoutBox` tree, cached title/page-signals, address bar editing
state (text, cursor, selection), back/forward history (each entry pairs a
URL with that page's own scroll offset, so going back restores scroll
position too, not just content), `next_wake_at` (this tab's own pending
timer, if any -- `Browser::earliest_wake_at` takes the minimum across every
tab to decide the ONE `Frame::wake_at` deadline actually armed, since only
one can be in flight at a time), `renderer_site` (which pool entry
currently owns this tab's live session), and separate focus-tracking for
the page's own focused input vs. the browser chrome's own text fields
(the address bar, find bar, DevTools console are all "chrome" focus,
entirely separate from `focused_page_input`/keyboard-focused DOM node,
which live in the renderer's own `script::Session` -- `app` never touches
the DOM directly, so it can't track page-side focus itself beyond "there is
one, here's its id").

`Browser::handle_event` is the one big dispatch function every
`InputEvent` goes through -- worth reading start to finish once to see how
chrome-vs-page routing actually works (is the address bar being edited? is
a page input focused? neither, so does this go to the page as a keyboard
shortcut or fall through to the renderer as a real keystroke?).

## The toolbar

`render::icons` draws every chrome icon (back/forward, reload, bookmark,
account) as hand-authored **vector shapes** -- short vertex lists filled via
`Canvas::fill_triangle`/`fill_circle`/`fill_polygon`, scaled/translated at
paint time. There is deliberately no icon font and no raster image
anywhere in this crate's dependency tree; every icon is drawn the same way
any other box/border/glyph on the page is. `Browser::paint_chrome_button`
is the shared "hit-testable button with an icon" primitive the toolbar
buttons are all built from; `Browser::paint_tab_bar`/`paint_address_bar`
paint the rest of the chrome.

## The address bar

Two roles in one widget: typing a URL and navigating it (bare domains like
`example.org` get `https://` assumed -- see `resolve_url`), or typing one of
a fixed set of real commands instead:

`bookmark` (toggle bookmarking the current page), `bookmarks`/`history`/
`downloads`/`settings`/`account` (open the matching `about:` page),
`back`/`forward` (history navigation), `set theme light|dark`, `set
fingerprint-resistance strict|standard`, `set webrtc allowed|blocked`, `set
sync-server-url <url>`. `Browser::apply_setting` is the one place that
actually applies a parsed `set` command and keeps the cached
`theme`/`fingerprint_resistance`/`webrtc_access` fields in sync with what
got written into `bookmarks.settings` (the synced settings map) -- see
`SETTING_THEME`/`SETTING_FINGERPRINT_RESISTANCE`/`SETTING_WEBRTC`/
`SETTING_SYNC_SERVER_URL`, the four setting-key constants, centralized so
the address-bar parser, the settings page's own links, and
`apply_setting` itself can never drift onto different string spellings for
the same key.

## `about:` pages

Every one of `bookmarks`/`history`/`settings`/`account`/`downloads` (plus
the built-in demo page -- `about:demo`, `Browser::load_demo_page`) is built
from the exact same `html::parse` → `css::user_agent_stylesheet` →
`layout::build_layout_tree` pipeline any real fetched page goes through --
these are NOT a separate UI widget system, they're real, synthetic HTML
strings built by Rust `format!()` calls (`render_settings_html`,
`render_account_html`, etc.) and rendered through the ordinary path. That's
deliberately why click-to-navigate, styling, and everything else about
normal page rendering works on them "for free" -- a link inside
`about:settings` is a real `<a href="settings:...">` the ordinary click
handler resolves.

The account page specifically (`render_account_html`) is worth knowing:
it shows the real account ID and real recovery code in plaintext, plus a
plain `<a href="account:sync">Sync now</a>` pseudo-link -- see
`05-account-storage-sync.md` for what actually happens when that's
clicked.

## Keyboard shortcuts and keyboard-only navigation

The full list lives in `InputEvent` itself (see above) -- `winit`'s own key
event, with modifiers, gets resolved into one of those named variants
*before* `app` ever sees it, so `Browser::handle_event`'s job is just
"given this already-classified event, and given current chrome/page focus
state, do the right thing," not raw key-code parsing.

Keyboard-only page navigation (`Tab`/`Shift+Tab` to move a visible focus
ring across links/buttons/inputs, `Enter`/`Space` to activate) is real,
driven by `layout::is_keyboard_focusable`, and is genuinely separate from
mouse hit-testing -- this is also most of what makes the `accesskit`
integration (real screen-reader support) work, since assistive technology
fundamentally needs a keyboard-navigable focus order to expose at all.

## DevTools

`F12` toggles a real panel with two tabs: Console (a live REPL -- typed
expressions get sent to the renderer via
`ClientMessageKind::EvalConsoleExpression` and run against the actual live
page session) and Elements (a real DOM tree view, box-model inspector, and
"pick an element on the page" mode -- `paint_devtools_elements_tab`/
`paint_box_model`/`paint_devtools_highlight` are the relevant paint
functions if you're extending this).

## Downloads, userscripts, media

Downloads: `<a download>` triggers a real fetch through the renderer,
`app` writes the bytes to the OS Downloads folder with a sanitized,
de-duplicated filename (the suggested filename comes from page-controlled
markup, so it's treated as hostile -- reduced to one safe path component,
never allowed to overwrite an existing file). Records are stored encrypted
(`downloads.enc`) and deliberately never synced (a local file path means
nothing on another device).

Userscripts: real `.js` files under `<data dir>/userscripts/`, re-read from
disk on every navigation (not cached -- see `userscripts` module docs for
why), filtered by `@match` patterns, run fully trusted after the page's own
scripts.

Media: decoding happens in the sandboxed renderer (`renderer::media`, via
`symphonia`); actual audio *output* happens here in `app`, through `cpal` --
this is the one place raw, renderer-produced bulk data (decoded PCM
samples) crosses back into the privileged process, as plain sample buffers
with real size caps, not as anything resembling executable content.

## Gotchas for future you

- **`app` never touches the DOM directly, ever.** If you're tempted to add
  a feature that needs to know something about page content beyond what
  `layout::LayoutBox`/`ipc::PageSignals` already expose, the real answer is
  almost always "add a field to what the renderer reports," not "read the
  DOM from `app`."
- **Chrome focus and page focus are two completely separate state
  machines.** A keystroke has to be routed to exactly one of them (or
  neither) by `handle_event` -- get this wrong and you'll see either dead
  keys or keystrokes leaking into the wrong place.
- **A `Tab`'s `renderer_site` can be `None`** (never navigated yet, or
  currently showing a local `about:` page) -- anything that routes a
  message to "this tab's renderer" needs to handle that case, not assume a
  live session always exists.
