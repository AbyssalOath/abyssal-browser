# Changelog

All notable changes to Abyssal Browser are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project has not made a stable release. Every tagged version before 1.0 is
published as a GitHub **pre-release**, and any pre-1.0 version may change
behavior, on-disk formats, or the IPC and sync protocols without notice.

## [Unreleased]

Everything below is this project's full development history so far
(workspace crates are at version `0.1.0`), collected here rather than split
across dated releases because none has been tagged yet. Entries are grouped
by area rather than by date.

### Added

**Architecture and process model**

- Cargo workspace of 15 crates: `dom`, `html`, `css`, `text`, `layout`,
  `render`, `network`, `privacy`, `account`, `storage`, `sync`, `sync-server`,
  `ipc`, `renderer`, and the `app` binary (package `abyssal`).
- Two-process design: the privileged `app` process never links an HTTP client,
  and a separate `abyssal-renderer` process does all fetching, parsing, styling,
  layout, scripting, and decoding of untrusted content.
- Length-prefixed JSON IPC over stdin/stdout with a 64 MiB message cap, strict
  lockstep replies, and per-tab scoping (`ipc`).
- Site isolation: `RendererPool` runs one renderer process per eTLD+1 and
  spawns and reaps them on demand. Same-site tabs share a process.
- Linux renderer sandbox: Landlock (filesystem plus TCP port restrictions) and a
  seccomp-bpf syscall allowlist (about 55 syscalls) derived empirically from a
  traced workload.
- Renderer sandboxing on macOS (a Seatbelt/`sandbox_init` profile restricting
  filesystem and network access) and Windows (a Job Object plus several
  `SetProcessMitigationPolicy` hardening policies), both real code
  cross-type-checked against the platform APIs but never run on the real OS -
  see `renderer::sandbox`'s own module docs and `THREAT_MODEL.md` for the
  honest caveat.

**Rendering engine**

- Real HTML5 parsing through `html5ever`, with `markup5ever_rcdom` vendored into
  `html/src/rcdom.rs` instead of depended on.
- CSS: id, class, attribute (all operators), and type selectors; descendant,
  `>`, `+`, `~` combinators; selector lists; structural pseudo-classes including
  `:nth-child(An+B)` and `:not()`; real specificity, cascade, and inheritance;
  author `<style>`, inline `style=""`, and external `<link rel="stylesheet">`.
  `:hover` and `:focus` parse but never match, and `:visited` is deliberately
  not parsed.
- Layout: block and inline formatting contexts with word-granularity wrapping,
  a full box model, adjacent-sibling margin collapsing, `width`/`height`/`min-`/
  `max-` sizing, `float`/`clear`, `position: relative/absolute/fixed`, flexbox
  (full row algorithm, simpler column), and grid (`fr`, `repeat()`, named areas,
  `span N`).
- Text: `fontdue` rasterization with real font metrics and a bundled Inconsolata
  font.
- Rendering to an RGBA buffer presented through `wgpu` and `winit`, with live
  relayout on resize and light and dark themes.
- Images: PNG, JPEG, GIF, and BMP decoded with pure-Rust codecs inside the
  sandbox and downscaled before crossing IPC.
- PDF reader mode: per-page text extraction wrapped in synthetic HTML, detected
  by magic number rather than URL or header.

**JavaScript**

- Pure-Rust [Boa](https://boajs.dev) engine in the renderer, running inline and
  external scripts with a persistent per-tab session.
- `setTimeout`/`clearTimeout` driven by a `Tick` message and the window event
  loop, with no polling and no background thread.
- Promises and `async` (job queue drained explicitly), `console.*`, and a
  Promise-wrapped `fetch()` through the filtered fetcher.
- DOM surface: `document.title`, `getElementById`, `querySelector(All)`,
  `createElement`, `appendChild` with move semantics, attribute accessors,
  `textContent`, `classList`, and `input.value`.
- Events: `addEventListener` with capture, target, and bubble phases, a real
  `Event` object, `stopPropagation`, `stopImmediatePropagation`, and
  `preventDefault`. Supported types are `click`, `keydown`, `input`,
  `submit`, and (on `window`) `storage`.
- Loop-iteration and recursion limits (`RuntimeLimits`).
- Real, per-origin, disk-persisted `localStorage`: the full method surface
  (`getItem`/`setItem`/`removeItem`/`clear`/`key`/`.length`), real
  property-style access (`localStorage.foo = "bar"`) via a genuine Boa
  `Proxy`, and a real cross-tab `storage` event fired into every other live
  tab on the same origin.
- A real but deliberately scoped subset of IndexedDB: `indexedDB.open`/
  `onupgradeneeded`/`onsuccess`, `createObjectStore`/`deleteObjectStore` with
  real `keyPath` and `autoIncrement`, and `transaction`/`objectStore` with
  `put`/`add`/`get`/`getAll`/`getAllKeys`/`delete`/`clear`/`count`, all
  disk-persisted the same way `localStorage` is. No indexes, cursors, key
  ranges, or cross-connection `versionchange` event yet.

**Browser features**

- Tabs, back/forward history with scroll restoration, and an address bar with
  cursor, selection, and typed commands (`bookmark`, `bookmarks`, `history`,
  `downloads`, `settings`, `account`, `back`, `forward`, `set <name> <value>`).
- A toolbar with back/forward, reload, bookmark, and account buttons, drawn
  as hand-authored vector shapes (`render::icons`) rather than an icon font
  or raster images.
- Click-to-navigate, mouse-wheel scrolling, find-in-page (`Ctrl+F`), and keyboard
  shortcuts for tabs and history.
- Form controls: single-line text inputs with a real cursor, checkboxes, radio
  groups, and real GET and POST (`application/x-www-form-urlencoded`) form
  submission. `multipart/form-data` (file upload) is still not implemented.
- Real `Cookie`/`Set-Cookie` handling in `network::PartitionedCookieJar`,
  wired through `FilteringFetcher::fetch_in_context` and partitioned by
  (top-level site, resource host).
- Cookies/`localStorage`/IndexedDB now persist to disk encrypted with the
  account's own key (`cookies.enc`/`local_storage.enc`/`indexed_db.enc`,
  alongside `bookmarks.enc`), with the sandboxed renderer never holding
  that key itself - it reports its own real bytes over the existing IPC
  channel, and `app` (the one process that holds the key) does the
  actual encrypt/merge/write and decrypt/seed. See `THREAT_MODEL.md`'s
  network-layer section for the full design and its real, disclosed
  tradeoffs.
- `file://` URL support, routed through the SAME `FilteringFetcher` chokepoint
  as every other fetch (navigation, images, stylesheets, scripts) rather than
  special-cased in one place. Only the one dedicated, permanently-isolated
  renderer process `file://` navigations are routed to (`app`'s
  `LOCAL_FILES_SITE`) is ever granted real, unrestricted filesystem read
  access - the same process trades away all outbound network access to make
  that safe, so a malicious `https://` page's own renderer process can never
  reach `file://` and no compromise of it can exfiltrate local files over the
  network it doesn't have. See `THREAT_MODEL.md`'s network-layer section for
  the full design.
- `about:bookmarks`, `about:history` (capped and synced), `about:settings`,
  `about:account`, and `about:downloads`.
- Downloads manager: `<a download>` fetched through the renderer and saved to the
  OS Downloads folder with sanitized, de-duplicated filenames. Records are
  encrypted at rest and not synced.
- `<audio>` and `<video>` audio-track playback with click-driven transport
  controls. Decoding uses `symphonia` in the sandbox, and output uses `cpal` in
  `app`.
- DevTools (`F12`): Console with a live REPL, and Elements with a DOM tree, box
  model, computed style, and pick-from-page mode.
- Accessibility: `Tab`/`Shift+Tab` keyboard focus with a visible ring, and an OS
  accessibility tree through `accesskit` for screen readers.
- Local userscripts (`<data dir>/userscripts/`) with Tampermonkey-style
  `// @match` headers, run at document-idle.
- Page signals badge: whether a page uses JavaScript and how many links look like
  affiliate or tracked-referral links.
- Data stored in an OS-standard per-user directory, rather than a path relative
  to the working directory.
- Window and application icons for Linux, macOS, and Windows, plus a Linux
  `.desktop` installer, a macOS `.app` builder, and a Windows icon resource
  embedded via `winresource` when built natively on Windows (`packaging/`,
  `app/build.rs`).

**Privacy**

- Real EasyList and EasyPrivacy blocking through the `adblock` crate, matched on
  host and path and applied to every request and every redirect hop.
- Tracking query-parameter stripping.
- Storage and cache partitioning by (top-level site, resource host) using a
  Public Suffix List eTLD+1.
- DNS-over-HTTPS by default (Cloudflare, bootstrapped by IP) that fails closed.
- Window-size letterboxing, and normalized `User-Agent`, `Accept-Language`,
  timezone, and locale (`strict` and `standard` levels).
- A default Web API policy table that records WebRTC, geolocation, and
  battery/sensor APIs as disabled.
- No telemetry, as a documented project constraint.

**Account and sync**

- No-email accounts: random account ID, 15-word BIP-39 recovery code, random KDF
  salt, created automatically on first launch with no sign-up step, viewable
  from the toolbar's account button or the `account` address-bar command.
- Argon2id key derivation (128 MiB, t=3, p=1) and ChaCha20-Poly1305 encryption,
  with keys and plaintext zeroized after use and a domain-separated auth secret.
- Encrypted bookmarks, history, and settings, with a mergeable payload and a
  conflict-retry loop.
- `account.txt`, `bookmarks.enc`, and `downloads.enc` are written owner-only
  (`0o600` on Unix, via `app::write_secret_file`), including locking down a
  pre-existing looser-permission file.
- `sync-server`: file-backed HTTP server with atomic writes, per-IP rate limiting,
  per-account lockout, rotating backups, and `--list-backups` and `--restore`
  operator commands.
- Check-and-notify update checker (`renderer::update_check`). It never downloads
  or replaces anything.

**Project infrastructure**

- GitHub Actions: CI (rustfmt, build, test, clippy, `cargo audit`) on every
  push and pull request against Linux, and a tag-driven release workflow that
  builds and tests natively on four runners (Linux x86_64, Windows x86_64,
  and macOS Intel and Apple Silicon) and publishes one archive per platform
  to a single GitHub pre-release. Fixed on this project's first real CI run:
  Linux jobs were missing `libasound2-dev` (needed by `cpal`/`alsa-sys`,
  added alongside the existing winit/wgpu system packages); the macOS release
  job ran `cargo test --release` with no preceding `cargo build --release`,
  so `abyssal`'s own test suite couldn't find a plainly-named
  `abyssal-renderer` binary to spawn (only a hashed one under
  `target/release/deps/`); `cargo audit` was failing on newly-disclosed
  advisories in `h2`, `quick-xml`, `rustls`, and a yanked `chacha20` release,
  all fixed by `cargo update`, plus four already-latest, genuinely
  unmaintained transitive dependencies (`derivative`, `instant`, `paste`,
  `ttf-parser`) with no available fix, narrowly ignored by advisory ID in
  `.cargo/audit.toml` (not by crate name, so a real future vulnerability in
  any of them still fails CI) rather than silently disabled; and the Windows
  release job hit a real native `STATUS_ACCESS_VIOLATION` crash inside
  `app::media_playback`'s real `cpal`/WASAPI stream-opening tests, caused by
  a raw FFI crash on a headless runner with no real audio hardware, which
  bypasses Rust's own `Result`/panic handling entirely -- fixed by marking
  those two hardware-touching tests `#[ignore]` (their actual logic is
  already fully covered by hardware-free unit tests in the same file; see
  `THREAT_MODEL.md`'s renderer-sandbox section for the full writeup).
  See `THREAT_MODEL.md`'s renderer-sandbox section for the full, honest
  writeup of that last one.
- Documentation: `README.md`, `ARCHITECTURE.md`, `THREAT_MODEL.md`,
  `SECURITY.md`, `TESTING.md`, `CONTRIBUTING.md`, and this changelog.
- Licensed the project's own code under the GNU Affero General Public
  License v3.0 (`LICENSE`).

### Security

- Vendored `markup5ever_rcdom` to remove a dependency on an unofficial
  third-party republish.
- Added `cargo audit --deny warnings` to CI.
- Added the seccomp-bpf layer on top of Landlock for the renderer.
- Made site isolation real by giving each site its own renderer process.
- Wrote real, cross-type-checked (never hardware-tested) sandboxing for the
  macOS and Windows renderer processes, closing the "no sandbox at all on
  those platforms" gap, though neither is verified the way Linux's is yet.
- Set explicit owner-only (`0o600`) file permissions on `account.txt`,
  `bookmarks.enc`, and `downloads.enc`.
- Added a portable per-renderer resource-limit backstop: real `setrlimit`
  (`RLIMIT_AS`/`RLIMIT_CPU`) on Linux and macOS, and Job Object memory/CPU
  fields on Windows, capping virtual memory at 1.5 GiB and cumulative CPU
  time at 30 minutes, independent of Landlock/seccomp/Seatbelt/mitigation
  policies. Empirically confirmed enforced on real Linux hardware (checked
  a running renderer's own `/proc/<pid>/limits`).
- Encrypted cookies/`localStorage`/IndexedDB at rest with the account's own
  key, closing the gap where those three (unlike bookmarks/downloads) used
  to be plaintext on disk, without giving the sandboxed renderer process
  the encryption key itself.
- Added `file://` support without reopening the "malicious page exfiltrates
  local files" attack class real browsers restrict `file://` specifically to
  prevent: the one renderer process granted broad filesystem read (Landlock
  root-scoped `PathBeneath` on Linux, an unrestricted `file-read*` Seatbelt
  rule on macOS) is the SAME process that gives up outbound network access
  entirely, and it is never shared with any real website's renderer (site
  isolation's own `RendererPool` mechanism, reused here as a security
  boundary rather than just a crash-isolation one).
- See [`THREAT_MODEL.md`](THREAT_MODEL.md) for the full self-review and its
  prioritized findings.

### Known issues and limitations

- **Not security audited.** Do not rely on this for anonymity or to protect
  sensitive activity.
- `account.txt` is owner-only permissioned, but still holds the recovery code
  in plaintext (it has to be, for the browser to read it back at startup).
- The renderer sandbox on macOS and Windows is real code but has never
  actually run on either real OS.
- On Windows specifically, `file://` support's safety currently rests
  entirely on process/application-level design (routing to one dedicated
  process, that process never getting a `--allow-local-files` flag unless
  it's the one `LOCAL_FILES_SITE` process) rather than on any OS-level
  enforcement: Windows has no Job-Object or mitigation-policy equivalent of
  Landlock's broadened read rule or its network-access denial, so a bug in
  that process-routing logic would not be caught by a second, independent
  kernel-level layer the way it would on Linux or macOS.
- The IPC boundary has not been fuzzed.
- `sync-server` speaks plain HTTP, listens on all interfaces, has no request size
  limit, and its per-IP rate limiter does not understand reverse proxies.
- There is no `Content-Type` or charset handling; response bytes are treated
  as UTF-8 regardless of what the server declared.
- IndexedDB has no indexes, cursors, key ranges, or cross-connection
  `versionchange` event, and its keys are limited to strings and numbers.
- The cross-tab `storage` event can leave another tab's rendered view stale
  until that tab's own next message, a real consequence of the strict
  lockstep IPC protocol - see `ARCHITECTURE.md`.
- No iframes, WebRTC, Canvas/WebGL, `<textarea>`, `multipart/form-data`
  (file upload) forms, `<picture>`/`srcset`, ARIA, or `font-family` support.
  Many modern JavaScript-heavy sites will render empty or broken.
- Update checking reports a failure until `RELEASES_REPO` in
  `renderer/src/update_check.rs` is set to the real repository.
- Only Linux is built and tested on every push and pull request; macOS and
  Windows are only built and tested natively when a release tag is pushed.
