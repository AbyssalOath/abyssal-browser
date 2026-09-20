# Abyssal Browser

A privacy-focused desktop web browser written from scratch in Rust. Tracker
blocking, storage partitioning, and fingerprint resistance sit alongside a
hand-built render pipeline (HTML, CSS, layout, and a pure-Rust JavaScript
engine), a sandboxed and site-isolated renderer process, and an email-free,
zero-knowledge sync system.

[![CI](https://github.com/AbyssalOath/abyssal-browser/actions/workflows/ci.yml/badge.svg)](https://github.com/AbyssalOath/abyssal-browser/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/AbyssalOath/abyssal-browser)](https://github.com/AbyssalOath/abyssal-browser/releases/latest)
![Status: experimental](https://img.shields.io/badge/status-experimental-orange)
![Rust: stable](https://img.shields.io/badge/rust-stable-blue)

> **Status: experimental, pre-1.0, and not security audited.**
> Abyssal Browser is a personal engineering project. It renders simple pages
> roughly, not correctly, and most modern JavaScript-heavy sites will come up
> empty or broken. It is **not** Tor, does not provide strong anonymity, and
> should not be used as your only browser or to protect anything sensitive.
> Read [Security status](#security-status) before recommending it to anyone.

## Contents

- [Highlights](#highlights)
- [What works today](#what-works-today)
- [Getting started](#getting-started)
- [Using the browser](#using-the-browser)
- [Running the sync server](#running-the-sync-server)
- [Workspace layout](#workspace-layout)
- [Privacy principles](#privacy-principles)
- [Security status](#security-status)
- [Platform support](#platform-support)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License and third-party assets](#license-and-third-party-assets)

## Highlights

- **Two-process design.** The privileged `app` process holds your account
  secrets, UI, and sync logic, and never links an HTTP client. Everything that
  touches untrusted content (network fetch, HTML/CSS parsing, layout,
  JavaScript, image/audio/PDF decoding) runs in a separate `renderer` process.
- **Sandboxed renderer.** Landlock filesystem/network rules plus a seccomp-bpf
  syscall allowlist on Linux (battle-tested on real hardware), and real but
  not-yet-hardware-verified equivalents on macOS (Seatbelt) and Windows (a Job
  Object plus process mitigation policies) - see
  [Platform support](#platform-support). One renderer process per site
  (eTLD+1) on every platform, so a bug triggered by one site cannot read
  another tab's DOM or script state.
- **Memory-safe by preference.** The parsing and decoding path for untrusted
  bytes (HTML, images, audio, PDF text, JavaScript) uses pure-Rust libraries
  rather than C or C++ dependencies wherever a mature option exists.
- **Tracker and ad blocking.** Real EasyList and EasyPrivacy rules via the
  `adblock` crate, applied to every request and every redirect hop, plus
  tracking query-parameter stripping.
- **Storage partitioning.** Cookies and the opt-in disk cache are keyed by
  (top-level site, resource host) using a Public Suffix List eTLD+1.
- **Fingerprint resistance.** Window-size letterboxing and normalized headers,
  timezone, and locale. All defaults live in one crate (`privacy`) so there is
  one place to audit.
- **DNS-over-HTTPS by default.** Hostnames resolve through DoH and the fetch
  **fails closed** if DoH fails. It never silently falls back to plaintext DNS.
- **Email-free, zero-knowledge sync.** A random account ID and a 15-word
  BIP-39 recovery code. Argon2id derives the keys on-device, ChaCha20-Poly1305
  encrypts bookmarks, history, and settings, and the server only ever stores
  ciphertext.
- **No telemetry, by policy.** No analytics, crash reporting, or usage
  tracking anywhere in the codebase, and none should be added.

## What works today

| Area | Status |
| --- | --- |
| Navigation | Tabs, a toolbar with hand-drawn vector icons (back/forward, reload, bookmark, account - no icon fonts or raster images), address bar with cursor and selection, click-to-navigate, mouse-wheel scroll, find-in-page (`Ctrl+F`) |
| `file://` | Real support, restricted like a real browser: routed to one dedicated renderer process (see `ARCHITECTURE.md`) with broad real filesystem read but zero outbound network access, so it can never exfiltrate what it reads and no ordinary website's process is ever granted it |
| HTML | Full HTML5 parsing via `html5ever` |
| CSS | Author `<style>`, inline `style=""`, and external `<link rel="stylesheet">`; id/class/attribute/combinator/structural selectors; real cascade and inheritance; `width`/`height`/`min-`/`max-`; `position`; `float`/`clear`; flexbox; grid (`fr`, `repeat()`, named areas, `span`) |
| Text | One bundled monospace font, real font metrics, word wrapping. No shaping (no kerning, ligatures, or RTL) and no `font-family` support (deliberate, see `text` module docs) |
| Images | PNG, JPEG, GIF, and BMP decoded in the sandbox, downscaled before crossing IPC |
| JavaScript | Pure-Rust [Boa](https://boajs.dev) engine: inline and external scripts, `setTimeout`, promises and `async`, `fetch()`, a small DOM surface, real `click`/`keydown`/`input`/`submit` events with capture and bubble phases |
| Storage | Real, per-origin `localStorage` (method calls and `foo.bar = "x"` property access, shared live across tabs on the same origin, including a real cross-tab `storage` event) and a real but scoped subset of IndexedDB (object stores, `keyPath`, `autoIncrement`; no indexes, cursors, or key ranges yet). Both persisted to disk **encrypted with your account's own key** (`local_storage.enc`/`indexed_db.enc`), the same way bookmarks are - the sandboxed renderer process itself never holds that key |
| Cookies | Real `Cookie`/`Set-Cookie` handling, partitioned by (top-level site, resource host) so a tracker on two different sites cannot correlate a user through them. Persisted encrypted (`cookies.enc`) the same way as `localStorage`/IndexedDB above |
| Forms | Single-line text inputs, checkboxes, radios, real GET and POST (`application/x-www-form-urlencoded`) submission. No `<textarea>`, no `multipart/form-data` (so file-upload forms still do not work) |
| Media | `<audio>` and the audio track of `<video>` with click-driven controls. No moving pictures |
| PDF | Text-only reader mode. No images or visual fidelity |
| DevTools | `F12`: Console (with REPL) and Elements (DOM tree, box model, computed style, pick-from-page) |
| Accessibility | Keyboard focus navigation plus a real OS accessibility tree (AT-SPI, UIA, NSAccessibility) via `accesskit`. No ARIA support yet |
| Userscripts | Local Tampermonkey-style `.js` files with `// @match` patterns, run at document-idle |
| Downloads | `<a download>` links saved to your OS Downloads folder, with sanitized and de-duplicated filenames |
| Account and sync | No-email account created automatically on first launch; encrypted bookmarks, history, and settings synced against the bundled `sync-server` |

**Not supported yet:** iframes, WebRTC, WebGL/Canvas, `<textarea>`,
`multipart/form-data` (file upload) forms, `<picture>`/`srcset`, ARIA,
extension manifests, multi-window, and the fuller parts of IndexedDB (indexes,
cursors, key ranges). See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the full
boundary between what exists and what is deliberately left out.

## Getting started

There are two ways to get a running browser: download a packaged release (no
Rust toolchain needed), or build it yourself from source. Either way, once it
is running, jump to [Using the browser](#using-the-browser) for what to do
next.

> Every release, including the newest one, is marked a GitHub **pre-release**
> (see [Security status](#security-status)) - it will not show up as the
> repository's "Latest release" banner. Get it from the
> [Releases page](https://github.com/AbyssalOath/abyssal-browser/releases)
> directly, and pick the newest tag.

### Option 1: Download a packaged release

Each tagged release publishes one archive per platform, built by
`.github/workflows/release.yml` (see [Platform support](#platform-support)
for what is verified where). Download the one for your OS from the
[Releases page](https://github.com/AbyssalOath/abyssal-browser/releases),
then:

**Linux (x86_64)** - `abyssal-browser-linux-x86_64.tar.gz`

```bash
tar xzf abyssal-browser-linux-x86_64.tar.gz
cd abyssal-browser-linux-x86_64          # or wherever you extracted it
./install.sh                             # optional: adds a launcher entry and icon, no root needed
./abyssal                                # or run it directly without installing
```

The tarball already contains `abyssal` and `abyssal-renderer` side by side,
which is all the browser needs to run - `install.sh` only adds desktop
integration (an application-menu entry and icon), it is not required to run
the browser. You still need the system libraries `winit`/`wgpu`/`cpal` link
against; see [Prerequisites](#prerequisites) below if the binary fails to
start.

**macOS (Intel or Apple Silicon)** - `abyssal-browser-macos-x86_64.zip` or
`abyssal-browser-macos-arm64.zip`

```bash
unzip abyssal-browser-macos-x86_64.zip      # or the arm64 archive on Apple Silicon
```

This unpacks `Abyssal Browser.app`. Drag it to `/Applications`, or run it in
place. The app is **unsigned and unnotarized** (no Apple Developer account),
so Gatekeeper blocks a plain double-click the first time: right-click the app
and choose **Open**, or run
`xattr -dr com.apple.quarantine "Abyssal Browser.app"` first.

**Windows (x86_64)** - `abyssal-browser-windows-x86_64.zip`

```powershell
Expand-Archive abyssal-browser-windows-x86_64.zip
```

This unpacks `abyssal.exe` and `abyssal-renderer.exe` into the same folder -
keep them together, and run `abyssal.exe`. Windows SmartScreen may warn about
an unrecognized publisher on first launch, since the binary is unsigned;
choose **More info -> Run anyway** if you trust the source you downloaded it
from.

None of the packaged releases include the sync server (`sync-server`) - it is
meant to be self-hosted separately, see
[Running the sync server](#running-the-sync-server). Sync itself is optional;
the browser works fully offline with no account server contacted at all
unless you push or pull.

### Option 2: Build from source

#### Prerequisites

- A recent stable Rust toolchain ([rustup](https://rustup.rs)).
- On Debian/Ubuntu, the system libraries `winit`, `wgpu`, and `cpal` link
  against:

  ```bash
  sudo apt install libx11-dev libxkbcommon-dev libwayland-dev pkg-config \
                   libasound2-dev libgl1-mesa-dev
  sudo apt install mesa-vulkan-drivers vulkan-tools   # GPU driver plus vulkaninfo
  ```

  Run `vulkaninfo` first if the window fails to open with an adapter-related
  panic (`request_adapter` returning `None`). It should print your GPU's name.
- macOS and Windows need no extra system libraries beyond a working Rust
  toolchain and (on Windows) the usual MSVC or MinGW build tools that
  `rustup` already sets up.

#### Build and run

```bash
git clone https://github.com/AbyssalOath/abyssal-browser.git
cd abyssal-browser

cargo build --workspace                  # REQUIRED at least once, see below
cargo run -p abyssal                     # built-in demo page, no network needed
cargo run -p abyssal -- https://example.com   # real fetch over the network
```

`abyssal` spawns a separate `abyssal-renderer` binary for every real
navigation and looks for it next to its own executable. There is no Cargo
dependency between the two crates, so `cargo run -p abyssal` alone will not
build the renderer. Run `cargo build --workspace` (or `cargo build -p renderer`)
first, or the app will exit at startup with a message explaining exactly this.

For a real, launcher/Dock/Start-menu-visible install with the actual bundled
icon rather than just a `target/release/abyssal` binary, see
[`packaging/README.md`](packaging/README.md) (`cargo build --release` plus one
platform-specific script). This is the same packaging the release workflow
runs, just locally.

#### Test

```bash
cargo test --workspace
```

Some `app` tests spawn real renderer subprocesses and make real network
requests to `example.com`, `example.org`, and `example.net`, so they need the
workspace built first and outbound internet access. See
[`TESTING.md`](TESTING.md).

## Using the browser

### Keyboard shortcuts

| Shortcut | Action |
| --- | --- |
| `Ctrl+T` / `Ctrl+W` | New tab / close tab |
| `Ctrl+Tab` / `Ctrl+Shift+Tab` | Next / previous tab |
| `Alt+Left` / `Alt+Right` | Back / forward |
| `Ctrl+F` | Find in page (`Enter` / `Shift+Enter` for next / previous, `Esc` to close) |
| `F12` | Toggle DevTools (Console and Elements) |
| `Tab` / `Shift+Tab` | Move keyboard focus across links, buttons, and inputs |
| `Enter` / `Space` | Activate the focused element |

### Address bar commands

Type these into the address bar instead of a URL:

| Command | Action |
| --- | --- |
| `bookmark` | Bookmark the current page |
| `bookmarks`, `history`, `downloads`, `settings`, `account` | Open the matching `about:` page |
| `back`, `forward` | History navigation |
| `set theme light\|dark` | Change the theme |
| `set fingerprint-resistance strict\|standard` | Letterboxing on or off |
| `set webrtc allowed\|blocked` | Records the WebRTC policy (no WebRTC stack exists yet) |
| `set sync-server-url <url>` | Point sync at a different server |

Internal pages: `about:bookmarks`, `about:history`, `about:downloads`,
`about:settings`, `about:account`.

### Account and sync, start to finish

There is no sign-up screen. On first launch, the browser creates a no-email
account for you automatically (`load_or_create_account` in `app/src/main.rs`):
a random account ID and a 15-word BIP-39 recovery code. You do not need to do
anything for this step - it already happened by the time the window opens.

1. **Back up your recovery code immediately.** Click the account button in the
   toolbar, or type `account` in the address bar. The Account page shows your
   account ID and recovery code. Write the recovery code down somewhere safe
   (a password manager, printed on paper). It is the only credential this
   account has, and there is no "forgot password" flow - see the warning
   below.
2. **Browse normally.** Bookmarking (`bookmark`), history, and settings all
   work with no account or network step at all. Nothing about browsing itself
   requires sync, and no network traffic beyond the pages you visit leaves
   your device unless you push or pull.
3. **Turn on sync, if you want it.** Sync needs a server to push encrypted
   data to - either your own (see
   [Running the sync server](#running-the-sync-server)) or one you trust.
   Point the client at it by typing `settings` then
   `set sync-server-url <url>` in the address bar (the default is
   `http://localhost:7878`, which only works if you are running a server on
   the same machine). Then, on the Account page, click **Sync now**. Every
   bookmark you add afterward pushes automatically.
4. **Recover on another device.** Install the browser there, let it create
   its own local account on first launch, then overwrite that with your
   original account by restoring `account.txt` from a backup, or by using the
   same recovery code (a "restore from recovery phrase" UI is not built yet -
   see [`ARCHITECTURE.md`](ARCHITECTURE.md) - so this currently means copying
   the file yourself). Point it at the same sync server and sync to pull your
   data down.

### Where your data lives

The browser stores state in an OS-standard per-user directory, **not** in the
repository:

| OS | Location |
| --- | --- |
| Linux | `$XDG_DATA_HOME/abyssal-browser`, or `~/.local/share/abyssal-browser` |
| macOS | `~/Library/Application Support/Abyssal Browser` |
| Windows | `%APPDATA%\Abyssal Browser` |

That directory holds `account.txt` (your account ID, **recovery code**, and KDF
salt), `bookmarks.enc`, `downloads.enc`, `cookies.enc`, `local_storage.enc`,
and `indexed_db.enc` (all encrypted at rest with your account's own key),
`cache/` (the HTTP disk cache, not encrypted - it holds only already-public
fetched web content), and `userscripts/`. Downloads go to your OS Downloads
folder.

> **Back up your recovery code.** There is no "forgot password" flow. Losing it
> means the encrypted data is unrecoverable, which is the cost of a server that
> cannot read your data. `account.txt` is written owner-only (`0o600` on Unix),
> but it still holds the recovery code in plaintext, so anyone with access to
> your user account can read it. See [`THREAT_MODEL.md`](THREAT_MODEL.md).

### Userscripts

Drop a `.js` file into `<data dir>/userscripts/` with a header like:

```js
// ==UserScript==
// @name   Example
// @match  https://example.com/*
// ==/UserScript==
```

Scripts are re-read on every navigation and run after the page's own scripts.
They are fully trusted (you placed them there yourself) and get exactly the
same DOM surface as page scripts, with no `GM_*` APIs.

## Running the sync server

Sync is optional. The client points at `http://localhost:7878` by default.

```bash
cargo run -p sync-server
```

| Environment variable | Default | Purpose |
| --- | --- | --- |
| `ABYSSAL_SYNC_DATA_DIR` | `sync-server-data` | Where account blobs and backups are stored |
| `ABYSSAL_SYNC_BACKUP_RETENTION` | `10` | Backups kept per account |

Operator commands:

```bash
sync-server --list-backups <account_id>
sync-server --restore <account_id> <version>
```

> **Read this before exposing it to a network.** The server speaks **plain
> HTTP**, binds to `0.0.0.0:7878`, and has never been load-tested or audited.
> Anything beyond localhost development needs a TLS-terminating reverse proxy
> in front of it. Also note that its per-IP rate limiter keys on the socket's
> peer address, so behind a proxy every client appears to come from the proxy.
> Details in [`THREAT_MODEL.md`](THREAT_MODEL.md).

## Workspace layout

```
abyssal-browser/
  Cargo.toml        workspace root (Cargo.lock is committed on purpose)
  app/              binary `abyssal`: window, UI, account, sync, tab/renderer pool
  renderer/         binary `abyssal-renderer`: sandboxed untrusted-content pipeline
  ipc/              length-prefixed JSON protocol between app and renderer
  network/          HTTP + DNS-over-HTTPS, filtering, partitioning, disk cache
  privacy/          blocklist, partition keys, letterboxing, header/API policy
  html/             html5ever -> dom::Node conversion (vendored rcdom)
  dom/              shared Node/Element/Text tree
  css/              parsing, selectors, cascade, ComputedStyle, themes
  text/             font loading, wrapping, glyph rasterization
  layout/           block, inline, flex, grid, floats, positioning, hit-testing
  render/           LayoutBox -> pixels, wgpu/winit window, accesskit hookup
  account/          no-email accounts, Argon2id KDF, ChaCha20-Poly1305, BIP-39
  storage/          bookmarks, history, settings data model (what gets synced)
  sync/             push/pull of opaque ciphertext, conflict detection
  sync-server/      file-backed HTTP server that `sync` talks to
  packaging/        Linux .desktop, macOS .app builder, icon pipeline
  assets/           master icon
```

Two boundaries are deliberate and worth knowing before you change anything:

- **`account` and `sync` never depend on each other.** `sync` only ever holds
  opaque `Vec<u8>` ciphertext and an account ID string, so it has no way to
  decrypt anything. Only `app` knows how to go from `storage::SyncPayload` to
  bytes to `account::encrypt` to `sync::push`. Keeping that boundary strict is
  what makes "the server is zero-knowledge" true rather than just a claim.
- **`app` never links `network`.** Every real fetch happens in the sandboxed
  renderer. This is enforced by the dependency graph, not by convention.

The full dependency graph and data flow are in
[`ARCHITECTURE.md`](ARCHITECTURE.md).

## Privacy principles

Stated explicitly so they stay true as the codebase grows:

- **No telemetry.** No analytics, crash reporting, or usage tracking, and none
  should be added. That is a constraint on the project, not a setting. The only
  traffic that ever leaves the device, apart from the pages you visit, is sync
  traffic, and only if you created an account, and only as opaque ciphertext.
- **WebRTC is disabled by default.** ICE candidate gathering can reveal your
  real IP address even through a VPN or Tor. No WebRTC stack exists today, but
  `privacy::default_web_api_policy()` records the decision now so whoever wires
  up Web APIs later has one source of truth.
- **Every fingerprinting-relevant default lives in `privacy`.** Letterboxing,
  header, timezone, and locale normalization, and the Web API policy table are
  in one crate so there is one place to audit.
- **`:visited` is deliberately not implemented**, closing a known
  history-sniffing side channel.
- **DNS goes to Cloudflare.** DoH queries go to Cloudflare's resolver. That
  hides hostnames from your local network but means Cloudflare sees them. This
  is a tradeoff, not a claim of anonymity.

## Security status

Abyssal Browser has a privacy-conscious architecture. That is **not** the same
claim as "secure enough to hand to real users", and only the first is true
today.

- No professional third-party security audit has been done.
- The renderer sandbox is real on all three platforms now, but only Linux's
  (Landlock and seccomp-bpf) has ever actually run -- there's no Mac or Windows
  machine in this project's own development loop, so macOS (Seatbelt) and
  Windows (Job Object plus process mitigation policies) were written and
  cross-type-checked against the real platform APIs, not traced and tested.
  Neither is as thorough as Linux's yet either (see
  [`THREAT_MODEL.md`](THREAT_MODEL.md) for exactly what each does and doesn't
  cover).
- The renderer now has a memory/CPU cap (`setrlimit` on Linux/macOS, a Job
  Object memory/CPU limit on Windows) as a portable backstop independent of
  Landlock/seccomp/Seatbelt - see [Platform support](#platform-support).
- The crypto uses standard, well-reviewed primitives with deliberately tuned
  parameters, but the way this project uses them has not been reviewed.
- The IPC deserialization boundary has not been fuzzed.
- `sync-server` speaks plain HTTP and needs a TLS proxy for anything beyond
  localhost.

[`THREAT_MODEL.md`](THREAT_MODEL.md) is the detailed self-review: trust
boundaries, what the sandbox does and does not cover, and a prioritized list
for a real external audit. [`SECURITY.md`](SECURITY.md) explains how to report
a vulnerability.

None of this means stop building. It means do not market it as done.

## Platform support

| Platform | Build | Renderer sandbox | In CI |
| --- | --- | --- | --- |
| Linux x86_64 | Yes | Landlock and seccomp-bpf (Landlock network rules need kernel 6.7+) -- battle-tested on real hardware | Every push/PR, and every tagged release |
| macOS (Intel + Apple Silicon) | Yes, `packaging/macos/build_app.sh` | Seatbelt (`sandbox_init`), filesystem + network only -- real code, never run on a real Mac | Every tagged release only (native runners, both architectures) |
| Windows x86_64 | Yes, icon embedded via `winresource` (native builds only -- see `app/build.rs`) | Job Object + process mitigation policies, no AppContainer yet -- real code, never run on a real Windows machine | Every tagged release only (native runner) |

Packaging notes (Linux launcher, unsigned macOS `.app`, Windows icon) are in
[`packaging/README.md`](packaging/README.md).

## Documentation

| File | What it covers |
| --- | --- |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Process model, crate graph, IPC, sandbox, sync protocol, data on disk |
| [`THREAT_MODEL.md`](THREAT_MODEL.md) | Self-review, trust boundaries, known gaps, audit priorities |
| [`SECURITY.md`](SECURITY.md) | How to report a vulnerability |
| [`TESTING.md`](TESTING.md) | Running tests, CI, manual test checklist, troubleshooting |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Dev setup, project rules, PR process, releasing |
| [`CHANGELOG.md`](CHANGELOG.md) | Notable changes |
| `<crate>/src/lib.rs` | Every crate opens with a `//!` module doc that states what is implemented, what is deliberately left out, and what to build next. These are the most current source of truth |
| [`docs/wiki/`](docs/wiki/00-START-HERE.md) | A personal study guide to how the codebase actually works, not official documentation. A rendered, sidebar-navigable version lives in `docs/wiki-site/` - open `docs/wiki-site/index.html` in any real browser, or in Abyssal Browser itself via its own `file://` support (`cargo run -p abyssal -- file:///path/to/docs/wiki-site/index.html`). Regenerate the HTML after editing a `docs/wiki/*.md` file with `python3 docs/generate_wiki_site.py` |

## Contributing

Issues and pull requests are welcome, with one caveat: this is a small personal
project, so response times are best effort. Please read
[`CONTRIBUTING.md`](CONTRIBUTING.md) first, especially the project rules (no
telemetry, no C dependencies on the untrusted-content path, keep the
`account`/`sync` and `app`/`network` boundaries intact). Please do not open
public issues for security vulnerabilities. See [`SECURITY.md`](SECURITY.md).

## License and third-party assets

Abyssal Browser's own code is licensed under the **GNU Affero General Public
License v3.0 (AGPLv3)** - see [`LICENSE`](LICENSE). In short: you can run,
study, modify, and redistribute this code, including as part of a service
others use over a network, but a modified version (including one offered as a
network service) must also make its complete corresponding source available
under the same license. This is a copyleft license, not a permissive one -
read the full text before building a product on top of this codebase.

Bundled third-party material keeps its own license:

| Asset | Location | License |
| --- | --- | --- |
| Inconsolata font | `text/assets/` | SIL Open Font License 1.1 (`OFL.txt` must ship with the font) |
| BIP-39 English wordlist | `account/assets/` | MIT (`BIP39-LICENSE.txt`) |
| EasyList and EasyPrivacy snapshots | `privacy/assets/` | See the [EasyList license page](https://easylist.to/pages/licence.html) |
| Vendored `rcdom` from html5ever | `html/src/rcdom.rs` | MIT or Apache-2.0 (`html/LICENSE-MIT`, `html/LICENSE-APACHE`) |
| Cargo dependencies | `Cargo.lock` | Each under its own license |

The EasyList and EasyPrivacy filter lists are distributed under their own
copyleft-style terms, compatible with bundling and redistribution but worth
checking yourself before redistributing binaries.
