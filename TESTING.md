# Testing

How to test Abyssal Browser locally and on GitHub: the automated suite, what CI
runs, a manual smoke-test checklist for the parts a unit test cannot cover, and
troubleshooting for the failures you are most likely to hit first.

## Contents

- [Quick reference](#quick-reference)
- [What is tested](#what-is-tested)
- [What the tests need](#what-the-tests-need)
- [Continuous integration](#continuous-integration)
- [Testing remotely](#testing-remotely)
- [Manual smoke tests](#manual-smoke-tests)
- [Testing the sync server](#testing-the-sync-server)
- [Testing the sandbox](#testing-the-sandbox)
- [Not tested yet](#not-tested-yet)
- [Troubleshooting](#troubleshooting)
- [Writing tests](#writing-tests)

## Quick reference

```bash
cargo build --workspace                 # required first: builds abyssal-renderer too
cargo test --workspace                  # everything (needs internet, see below)
cargo test --workspace --exclude abyssal   # everything except the app crate (no internet needed)
cargo test -p layout                    # one crate
cargo test -p renderer script::         # tests matching a path filter
cargo test -- --nocapture               # show println!/eprintln! output
cargo test --workspace --release        # what the release workflow runs

cargo fmt --all -- --check              # formatting (CI enforces this)
cargo clippy --workspace --all-targets  # lints
cargo audit                             # dependency advisories (cargo install cargo-audit --locked)
```

## What is tested

There are roughly 740 unit and integration tests across the workspace (counted
as `#[test]` occurrences, so treat the numbers as approximate).

| Crate | Approx. tests | What they cover |
| --- | --- | --- |
| `renderer` | 258 | Script engine (including `localStorage`, IndexedDB, cross-tab storage events), DOM APIs, event dispatch, focus and inputs, image/audio/PDF decoding, downloads, devtools snapshots, update-check parsing, full-page pipeline |
| `layout` | 122 | Block, inline, box model, margin collapsing, flex, grid, floats, positioning, hit-testing, input geometry |
| `app` | 118 | Tabs, history, address bar, settings, bookmarks, downloads, userscripts, renderer pool and site isolation, accessibility tree, media playback state |
| `css` | 75 | Tokenizing, selectors, specificity, cascade, inheritance, inline styles, themes |
| `network` | 37 | DoH parsing, filtering, redirect-hop blocking, partitioned cookie jar (including real `Cookie`/`Set-Cookie` wiring), disk cache |
| `render` | 28 | Painting, alpha blending, images, find highlighting, focus ring |
| `ipc` | 23 | Framing, size limits, message round trips, `LayoutBox` over the wire |
| `storage` | 17 | Serialization, merge semantics, history cap |
| `account` | 16 | Key derivation, encryption, tamper detection, BIP-39, owner-only file permissions |
| `sync` | 11 | Push/pull, conflicts, auth, file store, backups and restore |
| `privacy` | 10 | Blocklist, partition keys, letterboxing, header normalization |
| `text` | 8 | Wrapping and metrics |
| `sync-server` | 6 | Rate limiter and lockout |
| `dom`, `html` | 4 each | Tree operations and HTML parsing |

## What the tests need

| Requirement | Which tests | Notes |
| --- | --- | --- |
| Built `abyssal-renderer` binary | `app` | `app` spawns it as a subprocess and finds it next to the test binary's `target/{debug,release}` directory. Run `cargo build --workspace` first. CI does this for you |
| Outbound internet access | `app` | Several tests make real fetches (through real DoH and TLS) to `example.com`, `example.org`, and `example.net`, to verify site isolation with real renderer processes. DoH goes to `1.1.1.1` / `1.0.0.1` on port 443 |
| A display or GPU | none | Tests never open a window. `Browser::new` and `navigate` do not touch `render::window`, which is why real-renderer tests can run headless |
| Linux Landlock support | `app` (indirectly) | The spawned renderer applies its sandbox on startup. On older kernels it degrades with a warning instead of failing |
| An audio device | none | Playback state is tested without opening a device |

The other crates are designed to be hermetic, using fake fetchers and in-memory
data, so `cargo test --workspace --exclude abyssal` works offline. Tests use
isolated temporary data directories (`Browser::new_with_data_dir`) and will not
touch your real browser profile.

## Continuous integration

Two workflows live in `.github/workflows/`.

**`ci.yml`** runs on pushes and pull requests to `main` or `master`, and can be
started by hand (`workflow_dispatch`):

| Job | What it does |
| --- | --- |
| `rustfmt` | `cargo fmt --all -- --check` |
| `build + test` | Installs system libraries, then `cargo build --workspace --all-targets`, `cargo test --workspace`, and `cargo clippy --workspace --all-targets` |
| `cargo audit` | `cargo audit --deny warnings` against the RustSec advisory database |

**`release.yml`** runs on `v*.*.*` tags (or by hand with a tag input). It
builds and runs the test suite against the release build natively on four
runners - Linux x86_64, Windows x86_64, and macOS on both a real Intel and a
real Apple Silicon runner - and packages one archive per platform (Linux gets
`abyssal`, `abyssal-renderer`, `sync-server`, and the desktop-integration
files from `packaging/linux/`; Windows gets `abyssal.exe`/`abyssal-
renderer.exe`; each macOS runner produces a real `.app` bundle via
`packaging/macos/build_app.sh`), then publishes all of them to a single
GitHub pre-release. See [`packaging/README.md`](packaging/README.md) for
what each platform's package actually contains.

### What to expect on the first run

A brand-new repository is likely to hit one or more of these on its first CI run.
None of them mean the project is broken:

- **Missing ALSA headers.** The audio output crate (`cpal`) links `libasound` on
  Linux. If the build fails in `alsa-sys` with a pkg-config error, add
  `libasound2-dev` to the `apt-get install` line in both workflows.
- **`cargo audit --deny warnings` fails.** This treats any advisory, including
  "unmaintained" and "yanked" warnings, as an error. Read the report. Fix the
  advisory by updating the dependency where possible, or document and explicitly
  ignore a specific advisory that has no fix (`cargo audit --ignore RUSTSEC-...`,
  or an `audit.toml`) with a written justification.
- **`rustfmt` fails.** Run `cargo fmt --all` locally and commit the result.
- **Renderer killed by the sandbox.** See
  [Troubleshooting](#troubleshooting). The seccomp allowlist was derived on one
  machine, and a hosted runner has a different environment.
- **Network flakiness.** The real-fetch tests depend on the internet and on
  Cloudflare's DoH being reachable from the runner.

Clippy currently reports warnings without failing the job. Keep it clean anyway.

## Testing remotely

Once the repository is on GitHub, CI is your remote test machine.

With the [GitHub CLI](https://cli.github.com):

```bash
gh workflow run ci.yml               # start CI by hand on the current branch
gh run list --workflow ci.yml        # recent runs
gh run watch                         # follow a run live
gh run view --log-failed             # only the failing steps' logs
gh run download                      # fetch artifacts
```

To test on another machine or a fresh VM, the loop is:

```bash
sudo apt install libx11-dev libxkbcommon-dev libwayland-dev pkg-config \
                 libasound2-dev libgl1-mesa-dev
git clone https://github.com/AbyssalOath/abyssal-browser.git && cd abyssal-browser
cargo build --workspace && cargo test --workspace
```

The **automated suite needs no display**, so it runs fine over SSH or in a
container. The **GUI needs a display and a working Vulkan driver.** On a headless
Linux box, a virtual X server plus a software Vulkan driver
(`mesa-vulkan-drivers` includes lavapipe) is worth trying for a smoke run, for
example `xvfb-run cargo run -p abyssal`. Expect it to be slow, and use
`vulkaninfo` to confirm a Vulkan device is visible first. This is a best-effort
setup and is not part of CI.

To test the **release pipeline** without publishing, run the `Release` workflow
by hand from the Actions tab (`workflow_dispatch`) with a tag such as `v0.0.0-test`
and download the artifact. The `publish` job only runs for real tag pushes.

## Manual smoke tests

Unit tests cannot cover the window, GPU, input, and audio paths. Before a release,
or after touching `render`, `app`, or `layout`, run through this by hand. Run the
binary from a terminal so you can see its messages.

```bash
cargo build --workspace
cargo run -p abyssal
```

**Startup and rendering**

- [ ] The built-in demo page opens with no network, and the window title says
      "Abyssal Browser".
- [ ] `cargo run -p abyssal -- https://example.com` loads and renders the page.
- [ ] Resizing the window re-lays out and repaints (letterboxed) without freezing.
- [ ] Moving the mouse around for 30 seconds does not spike CPU, GPU, or memory.
- [ ] `light` and `dark` themes both render legibly (`set theme light`).

**Navigation**

- [ ] Clicking a link navigates. Mouse-wheel scrolling works.
- [ ] Typing a URL in the address bar and pressing Enter navigates. `Esc` cancels.
- [ ] Typing a bare domain such as `example.org` assumes https.
- [ ] Back and forward work (`Alt+Left`, `Alt+Right`, and the `<` `>` buttons) and
      restore scroll position.
- [ ] `Ctrl+T`, `Ctrl+W`, `Ctrl+Tab`, `Ctrl+Shift+Tab` manage tabs. Closing the
      last tab does nothing.
- [ ] Two tabs on different sites keep independent pages, scroll, and history.

**Features**

- [ ] `Ctrl+F` highlights matches. `Enter` and `Shift+Enter` cycle, and `Esc`
      closes it.
- [ ] `F12` opens DevTools. `console.log` output appears in the Console, and an
      expression typed in the Console runs against the page. The Elements tab
      shows the DOM, selecting a node shows its box model, and pick mode
      highlights the element on the page.
- [ ] A page with a text input accepts typing, cursor movement, and backspace.
      Checkboxes and radios toggle. Pressing Enter in a GET **and** a POST form
      submits it (a POST needs a server that echoes the body back, such as
      `https://httpbin.org/post`, to confirm the body actually arrived).
- [ ] `Tab` and `Shift+Tab` move a visible focus ring across links, buttons, and
      inputs. `Enter` activates the focused element.
- [ ] The toolbar's back/forward/reload/bookmark/account buttons are visible
      and clickable (not just their keyboard-shortcut equivalents).
- [ ] `bookmark`, then `bookmarks`, lists the page. `history` and `settings` open
      their pages, and the clear-history link on the history page empties it.
- [ ] `account` (or the account button) shows a real account ID and recovery
      code, created automatically with no setup step.
- [ ] A page that calls `localStorage.setItem`/`localStorage.foo = "x"` and
      reloads still has the value afterward (persisted to disk), and the same
      key is visible from a second tab on the same origin. A page that opens
      an IndexedDB database, creates an object store, and puts/gets a record
      round-trips the value.
- [ ] Clicking an `<a download>` link saves a file to your Downloads folder, and
      `about:downloads` lists it. A second download of the same name becomes
      `name (1).ext`.
- [ ] An `<audio controls>` element plays sound, and its play/pause/seek/mute
      controls respond. Audio keeps playing when you switch to another tab.
- [ ] A URL that serves a PDF shows a text-only reader view with a heading per
      page.
- [ ] A `.js` file in `<data dir>/userscripts/` with a matching `// @match` line
      runs on that page.

**Privacy**

- [ ] A page embedding a third-party tracker (or a known ad domain) does not load
      it. Check the terminal output and the DevTools console.
- [ ] With `set fingerprint-resistance strict`, resizing the window changes the
      content area in fixed steps rather than continuously.
- [ ] Tracking parameters such as `utm_source` and `fbclid` are stripped from
      requested URLs.
- [ ] A page that sets a cookie (`https://httpbin.org/cookies/set/name/value`)
      still sends it back on a later request to the same site (check with
      `https://httpbin.org/cookies`), and a second, unrelated site never sees
      it.
- [ ] With DoH unreachable (block `1.1.1.1` on port 443 with a firewall rule), a
      fetch **fails** rather than falling back to plaintext DNS.

**Accessibility** (optional but valuable)

- [ ] With Orca (Linux), NVDA (Windows), or VoiceOver (macOS) running, the
      screen reader announces links, headings, and buttons on a simple page.

**Renderer isolation**

- [ ] With two tabs on different sites open, `ps` (or Task Manager) shows one
      `abyssal-renderer` process per site, and closing a tab's last site removes
      its process.
- [ ] Killing a renderer process (`kill <pid>`) does not take down the app. The
      tab recovers on the next navigation.

## Testing the sync server

Start a server with a throwaway data directory:

```bash
ABYSSAL_SYNC_DATA_DIR=/tmp/abyssal-sync-test cargo run -p sync-server
```

In another terminal, exercise the API directly. The auth secret must be exactly
64 hex characters.

```bash
SECRET=$(openssl rand -hex 32)
URL=http://localhost:7878/accounts/test-account

# First push (expected version 0) creates the account. Expect 200 and body "1".
curl -i -X PUT "$URL" -H "Authorization: Bearer $SECRET" -H "X-Expected-Version: 0" --data-binary 'hello'

# Pull. Expect 200, body "hello", and an X-Version: 1 header.
curl -i "$URL" -H "Authorization: Bearer $SECRET"

# Stale push. Expect 409 with the server's version in the body.
curl -i -X PUT "$URL" -H "Authorization: Bearer $SECRET" -H "X-Expected-Version: 0" --data-binary 'stale'

# Wrong secret. Expect 401.
curl -i "$URL" -H "Authorization: Bearer $(openssl rand -hex 32)"

# Unknown account. Expect 404.
curl -i http://localhost:7878/accounts/nope -H "Authorization: Bearer $SECRET"

# Backups and restore (server can be stopped or running).
ABYSSAL_SYNC_DATA_DIR=/tmp/abyssal-sync-test cargo run -p sync-server -- --list-backups test-account
ABYSSAL_SYNC_DATA_DIR=/tmp/abyssal-sync-test cargo run -p sync-server -- --restore test-account 1
```

To confirm rate limiting, send more than 30 requests in a minute from one address
and expect `429` with a `Retry-After` header. Ten wrong-secret attempts against
one account lock that account out for 15 minutes.

For an end-to-end check with the browser, run the server, then in the browser use
`bookmark` to add a bookmark. It pushes ciphertext automatically. Confirm the
file in the server's data directory is not readable as plaintext. To exercise
multi-device merging in the browser, use two data directories that share an
account file.

## Testing the sandbox

The sandbox is Linux only. Confirm the kernel supports it:

```bash
uname -r                                            # Landlock network rules need 6.7+
cat /sys/kernel/security/lsm | tr ',' '\n' | grep landlock
```

If Landlock is missing or old, the renderer prints a warning at startup and runs
with whatever subset the kernel supports.

The automated tests cover the sandbox only indirectly, because the real-renderer
tests in `app` spawn a sandboxed process and perform real fetches. To check that
the seccomp filter is genuinely enforced, or to re-derive the allowlist after
adding a code path that does new I/O, follow the methodology in the doc comment at
the top of `renderer/src/sandbox.rs` (`ALLOWED_SYSCALLS`). In outline:

1. Trace the real renderer through a representative workload with `strace`, for
   example `strace -ff -o /tmp/trace target/debug/abyssal https://example.com`,
   then find the trace file belonging to the `abyssal-renderer` child.
2. Collect the set of syscalls it actually made, across more than one run and more
   than one kind of page.
3. Compare that set with `ALLOWED_SYSCALLS`.
4. To prove enforcement, temporarily remove one used syscall from the list and
   confirm the renderer dies with `SIGSYS` on the next operation that needs it.
   Then restore it.

To verify the memory/CPU resource limits (`sandbox::resource_limits` on
Linux/macOS, the Job Object's memory/CPU fields on Windows) are genuinely
enforced, not just successfully *set* (a `setrlimit`/`SetInformationJobObject`
call can report success without the OS actually honoring it, in some
container/sandbox environments), start the real binary with its stdin held
open so it doesn't exit immediately, and read the kernel's own accounting
back:

```bash
cargo build -p renderer
mkfifo /tmp/renderer-stdin
( exec 3<>/tmp/renderer-stdin; ./target/debug/abyssal-renderer /tmp/renderer-cache <&3 & echo $! >/tmp/renderer.pid; wait ) &
sleep 1
cat /proc/$(cat /tmp/renderer.pid)/limits | grep -E "Max address space|Max cpu time"
kill "$(cat /tmp/renderer.pid)"
rm -f /tmp/renderer-stdin /tmp/renderer.pid
```

`Max address space` and `Max cpu time` should show the real configured
values (not `unlimited`) for both the soft and hard columns — this is
Linux-only (macOS has no direct `/proc/<pid>/limits` equivalent; Windows'
Job Object limits are queryable via `QueryInformationJobObject`, not
covered here). Don't use `/dev/null` as stdin for this check: the renderer
reads its IPC protocol from stdin and exits immediately on EOF, which races
with reading `/proc/<pid>/limits` afterward and can read a since-reused PID
instead of the real renderer's.

## Not tested yet

Known gaps in test coverage. Contributions here are especially welcome.

- **Fuzzing.** There are no fuzz targets. The IPC deserialization boundary
  (`ipc`), the HTML/CSS/JS paths, and `sync-server`'s request parsing are the
  highest-value candidates. `cargo-fuzz` is a good fit.
- **macOS and Windows on every push/PR.** `ci.yml` only runs on Linux, so a
  regression specific to macOS or Windows is only caught when a tag is
  pushed and `release.yml` builds and tests natively there (see
  [Platform support](README.md#platform-support)). There is no CI job on
  either platform for ordinary pull requests.
- **The macOS and Windows renderer sandbox.** Both have real sandbox code
  (Seatbelt on macOS, a Job Object plus process mitigation policies on
  Windows), but neither has ever actually run - see
  [Testing the sandbox](#testing-the-sandbox) for why this is Linux-only in
  practice, and [`THREAT_MODEL.md`](THREAT_MODEL.md) for the full caveat.
- **A sandboxed-renderer end-to-end job** that fails loudly if the seccomp
  allowlist is out of date for the CI runner's environment.
- **Load testing** of `sync-server`.
- **Visual regression.** There are pixel-level unit tests for painting, but no
  screenshot comparison of real pages.
- **Accessibility with real assistive technology** is manual only.

## Troubleshooting

**"the abyssal-renderer binary was not found"**
Run `cargo build --workspace` (or `cargo build -p renderer`). `cargo run -p abyssal`
does not build the renderer, because there is no Cargo dependency between the two.

**Link error mentioning `alsa`, `asound`, or `pkg-config`**
Install `libasound2-dev` and `pkg-config`. On other distros, install the ALSA
development package.

**Link error mentioning X11, xkbcommon, or Wayland**
Install `libx11-dev libxkbcommon-dev libwayland-dev`.

**Window fails to open with an adapter panic (`request_adapter` returned `None`)**
No usable Vulkan device. Install `mesa-vulkan-drivers vulkan-tools` and run
`vulkaninfo`, which should print your GPU.

**`app` tests fail offline or behind a strict firewall**
They need internet access, including DoH to `1.1.1.1`/`1.0.0.1` on port 443. The
browser fails closed if DoH is unreachable. Use
`cargo test --workspace --exclude abyssal` to skip them.

**The renderer dies with `SIGSYS` ("Bad system call"), or a page or test fails right
when the renderer starts fetching**
The seccomp allowlist is missing a syscall that your libc or kernel needs. Look
for `type=1326` (seccomp) lines with a `syscall=` number in `dmesg` or
`journalctl -k` if audit logging is enabled, or trace the renderer with `strace`.
Add the syscall only after confirming it is a legitimate part of the renderer's
work, per [Testing the sandbox](#testing-the-sandbox). This is the most likely
failure when moving to a different distro or a CI runner.

**"Landlock ... not fully enforced" warning**
Your kernel is older than 6.7 or has Landlock disabled. The renderer still runs,
with fewer restrictions. This is expected on older systems.

**`cargo audit` fails in CI**
See [What to expect on the first run](#what-to-expect-on-the-first-run).

**`abyssal-data/` or `sync-server-data/` appeared in the working tree**
Those are runtime data directories and are ignored by `.gitignore`. Real browser
data lives in your OS user data directory, not in the repository. Never commit
either directory, since they can contain recovery codes.

**Tests pass locally but a real page renders blank**
Expected for JavaScript-framework sites. Try a plain static HTML page first. See
the module docs for what the CSS, layout, and script layers support.

## Writing tests

- Put unit tests in a `#[cfg(test)] mod tests` at the bottom of the file they
  cover. Add a regression test with every bug fix.
- Use the fake fetchers and in-memory stores that already exist rather than the
  network, unless the point of the test is a real end-to-end path.
- Tests in `app` must use `Browser::new_with_data_dir` with a temporary
  directory so they never read or write your real profile.
- For layout and render tests, build a small DOM and stylesheet and assert on
  the resulting boxes or pixels, following the existing tests in `layout` and
  `render`.
- For anything that parses untrusted input, include malformed and oversized
  cases.
- Keep tests deterministic. Avoid sleeping for time to pass and avoid depending on
  the ordering of other tests.
