# Contributing to Abyssal Browser

Thanks for your interest. Abyssal Browser is a small, personal, experimental
project, so please keep expectations modest: reviews and replies are best
effort, and some ideas will be declined because they conflict with the project's
privacy and security rules (below). Reading this whole file first will save
everyone time.

## Contents

- [Before you start](#before-you-start)
- [Project rules](#project-rules)
- [Development setup](#development-setup)
- [Making a change](#making-a-change)
- [Code style](#code-style)
- [Documentation expectations](#documentation-expectations)
- [Adding or changing dependencies](#adding-or-changing-dependencies)
- [Changes that touch security boundaries](#changes-that-touch-security-boundaries)
- [Pull request checklist](#pull-request-checklist)
- [Reporting bugs and requesting features](#reporting-bugs-and-requesting-features)
- [Releasing](#releasing)
- [Licensing](#licensing)

## Before you start

- **Security issues do not go in public issues.** Follow
  [`SECURITY.md`](SECURITY.md).
- **For anything larger than a small fix, open an issue first** so we can agree
  on the approach. This is especially true for anything touching the renderer,
  IPC, sandbox, account, or sync code.
- Skim [`ARCHITECTURE.md`](ARCHITECTURE.md) and the `//!` module doc at the top
  of the crate you are changing. Those docs list what is implemented, what is
  deliberately left out, and what the next steps are. Some gaps are on purpose.

## Project rules

These are constraints on the project, not preferences. A change that breaks one
will not be merged, however useful it is otherwise.

1. **No telemetry.** No analytics, crash reporting, usage tracking, phone-home,
   or "anonymous statistics", and no opt-out switch that implies one exists.
2. **Do not weaken the process split.** `app` must not depend on `network` or
   link an HTTP client. Anything that fetches or parses untrusted bytes belongs
   in `renderer`. No IPC message may carry the recovery code, derived keys, or
   decrypted user data to the renderer.
3. **Keep `account` and `sync` independent.** `sync` only handles opaque
   ciphertext and an account ID string. It must not gain the ability to decrypt.
4. **Prefer memory-safe dependencies on the untrusted-content path.** Do not add
   a C or C++ library to parse untrusted input (HTML, CSS, JS, images, audio,
   video, PDFs, fonts) if a mature pure-Rust option exists. If you believe there
   is no alternative, make the case in an issue first.
5. **Fail closed.** Privacy features should fail by not doing the risky thing
   (for example, DoH failure fails the fetch), not by silently degrading.
6. **Keep privacy defaults in `privacy`.** Do not scatter fingerprinting or
   tracking policy across other crates.
7. **Be honest.** Do not describe something as secure, private, or complete in a
   doc, comment, PR title, or release note unless it is. State limits where you
   introduce them.

## Development setup

Requirements: a recent stable Rust toolchain with `rustfmt` and `clippy`.

On Debian or Ubuntu, install the system libraries the GUI, GPU, and audio crates
link against:

```bash
sudo apt install libx11-dev libxkbcommon-dev libwayland-dev pkg-config \
                 libasound2-dev libgl1-mesa-dev
sudo apt install mesa-vulkan-drivers vulkan-tools
```

Then:

```bash
git clone https://github.com/AbyssalOath/abyssal-browser.git
cd abyssal-browser
cargo build --workspace     # builds abyssal AND abyssal-renderer
cargo test --workspace
cargo run -p abyssal
```

You must build the whole workspace (or at least `-p renderer`) before running or
testing `app`, because `app` spawns `abyssal-renderer` as a subprocess and finds
it next to its own executable. See [`TESTING.md`](TESTING.md) for details,
including which tests need network access.

Handy commands:

```bash
cargo test -p layout                 # one crate's tests
cargo test -p renderer script::      # tests whose path matches a filter
cargo run -p abyssal -- https://example.com
cargo run -p sync-server             # local sync server on :7878
```

## Making a change

1. Fork the repository and create a branch from `main`
   (`fix/short-description` or `feat/short-description`).
2. Make focused commits. One logical change per pull request is much easier to
   review than a bundle.
3. Add or update tests (see below).
4. Run the same checks CI runs:

   ```bash
   cargo fmt --all -- --check
   cargo build --workspace --all-targets
   cargo test --workspace
   cargo clippy --workspace --all-targets
   ```

5. Update the docs that your change makes stale (see the next sections).
6. Open a pull request against `main` and fill in the template.

Every crate has unit tests, and most behavior changes should come with one. If
you fix a bug, add a test that fails without the fix. For rendering changes, a
small test that builds a DOM and stylesheet and asserts on the resulting layout
or pixels is the usual pattern. For end-to-end behavior, see the real-renderer
tests in `app/src/main.rs`, which use `Browser::new_with_data_dir` so tests never
touch your real browser data.

## Code style

- Format with `rustfmt` using the default configuration. CI enforces
  `cargo fmt --all -- --check`.
- Keep `cargo clippy --workspace --all-targets` clean. Do not add blanket
  `#[allow]` attributes without a comment explaining why.
- Prefer clear names and small functions over cleverness. Explain **why**, not
  what, in comments. This codebase leans heavily on doc comments that record
  design tradeoffs, and that habit is welcome.
- Avoid `unsafe`. If it is unavoidable, isolate it, document the invariants, and
  mention it in the PR description.
- Do not use `unwrap()` or `expect()` on data that comes from the network, from
  a renderer reply, or from disk. Those are untrusted or fallible inputs.
- Failure philosophy for content: log and skip (a failed image renders as
  nothing) rather than crashing the tab.
- **High-frequency events** (mouse moves, scrolling) must not trigger GPU work by
  default. See the note in `render::window` and `ARCHITECTURE.md`.

## Documentation expectations

- Each crate's `//!` module doc is authoritative for that crate. If you add,
  remove, or change behavior, update it in the same pull request: what is
  implemented, what is deliberately left out, and the next steps.
- Update [`ARCHITECTURE.md`](ARCHITECTURE.md) if you change a boundary, the
  message protocol, the data on disk, or the sync API.
- Update [`THREAT_MODEL.md`](THREAT_MODEL.md) if you add attack surface (a new
  parser, a new IPC message, a new file the app writes, a new network endpoint)
  or close a listed gap.
- Add a line under `## [Unreleased]` in [`CHANGELOG.md`](CHANGELOG.md) for
  anything user-visible.
- If you change a user-facing behavior, keyboard shortcut, or command, update the
  tables in [`README.md`](README.md).

## Adding or changing dependencies

Dependencies are supply-chain risk, and this project is a privacy tool. Before
adding one:

1. Is it needed? Could a small amount of code replace it?
2. Is it pure Rust? If it lands on the untrusted-content path (anything in
   `renderer`, `html`, `css`, `layout`, `network`), a C or C++ dependency needs
   a very strong justification.
3. Enable only the features you need (`default-features = false`).
4. Check that it is maintained, widely used, and has no open advisories.
   `cargo audit` runs in CI and must pass.
5. Note what it adds in the PR description, and in `THREAT_MODEL.md` if it
   parses untrusted input.

`Cargo.lock` is committed on purpose because this workspace ships executables.
Commit lockfile changes together with the `Cargo.toml` change that caused them.
Some dependencies are pinned exactly (for example `accesskit` and
`accesskit_winit`, to stay compatible with winit 0.29). Read the comment in the
relevant `Cargo.toml` before bumping them.

## Changes that touch security boundaries

Take extra care, and expect closer review, when a change touches:

- `renderer/src/sandbox.rs` (Landlock rules, the seccomp allowlist)
- the `ipc` crate (new message types, new fields, size limits)
- `account`, `sync`, or `sync-server`
- anything that writes files (`account.txt`, `*.enc`, downloads, cache)
- the blocklist, partitioning, or fingerprinting logic in `privacy` or `network`

Specific rules:

- **Sandbox and seccomp.** If your change makes the renderer do a new kind of I/O
  (a new dependency that opens files or sockets, a new fetch path), it may need a
  syscall that is not on `ALLOWED_SYSCALLS`. The failure mode is the renderer
  dying with `SIGSYS` on that operation. Re-run the tracing methodology described
  in that module's doc comment against the new path and update the list, and say
  so in the PR. Never widen the allowlist without evidence for each syscall.
- **IPC.** New fields must not carry secrets to the renderer. Keep replies
  bounded and keep the protocol lockstep. Add round-trip tests.
- **Crypto.** Do not roll your own primitives or change parameters casually. Any
  change to key derivation, nonce handling, or the sync auth secret needs a
  written rationale in the PR.
- **New parsers on untrusted input** must run in the renderer, and should have
  size or time bounds and tests with malformed input.

## Pull request checklist

The PR template repeats this. In short:

- [ ] It follows the [project rules](#project-rules)
- [ ] `cargo fmt`, `cargo build`, `cargo test`, and `cargo clippy` pass locally
- [ ] Tests added or updated
- [ ] Module docs, `ARCHITECTURE.md`, `THREAT_MODEL.md`, `README.md`, and
      `CHANGELOG.md` updated where relevant
- [ ] No secrets, personal data, or local paths committed
- [ ] Dependency changes are justified

## Reporting bugs and requesting features

Use GitHub Issues. For a bug, please include:

- What you did, what you expected, and what happened instead.
- The commit or tag, your OS and version, and (for sandbox problems) your kernel
  version.
- The page or a minimal HTML reproduction. Simple static pages are the realistic
  target. Modern JavaScript-framework sites are known not to work.
- Terminal output. Run the binary from a terminal so you can see its messages.

For feature requests, check the module docs and `ARCHITECTURE.md` first. Many
missing features (iframes, `font-family`, video frames, an auto-updater) are
deliberate omissions with written reasons.

## Releasing

For maintainers.

1. **First release only:** set `RELEASES_REPO` in
   `renderer/src/update_check.rs` to the real `owner/name` (it is `None` until
   then, so update checks report a failure).
2. Bump the version in `app/Cargo.toml` (the update check compares against
   `app`'s `CARGO_PKG_VERSION`) and, for consistency, the other crates.
3. Move the `## [Unreleased]` entries in `CHANGELOG.md` under a new dated version
   heading.
4. Make sure `cargo test --workspace --release` and CI are green.
5. Tag and push: `git tag v0.1.0 && git push origin v0.1.0`.
6. The `Release` workflow builds and tests `abyssal`, `abyssal-renderer`, and
   `sync-server` natively on four runners - Linux x86_64, Windows x86_64, and
   macOS Intel and Apple Silicon - and publishes one archive per platform to a
   single GitHub pre-release with generated notes (`abyssal-browser-linux-
   x86_64.tar.gz`, `abyssal-browser-windows-x86_64.zip`, `abyssal-browser-
   macos-x86_64.zip`, `abyssal-browser-macos-arm64.zip`). Every release before
   a stable, audited 1.0 is deliberately marked as a pre-release. To test the
   workflow itself without publishing, see
   [`TESTING.md`](TESTING.md#testing-remotely).

Release binaries are not signed, and there is no reproducible-build setup yet.
Say so in the release notes.

## Licensing

The project's own code is licensed under the GNU Affero General Public
License v3.0 (AGPLv3) - see [`LICENSE`](LICENSE). By sending a contribution
you agree it will be distributed under that same license. If you want to
contribute code under different terms, open an issue to discuss it first.
Bundled third-party assets keep their own licenses. See the last section of
[`README.md`](README.md).
