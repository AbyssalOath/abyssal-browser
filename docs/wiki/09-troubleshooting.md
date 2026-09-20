# 09. Troubleshooting

`TESTING.md`'s own "Troubleshooting" section is the quick-reference version
of most of this -- short, symptom-to-fix. This page is the narrative
companion: the same problems, explained in more depth, plus a few real
lessons learned while building this project that aren't written down
anywhere else yet.

## "the abyssal-renderer binary was not found"

`cargo run -p abyssal` does **not** build `abyssal-renderer` for you --
there's no Cargo dependency between the `app` and `renderer` packages (see
`01-process-model-and-ipc.md` for why they're separate binaries at all).
Run `cargo build --workspace` (or at minimum `cargo build -p renderer`)
first. `app` checks for the binary eagerly at startup specifically so this
fails with an actionable message immediately, rather than on your first
real navigation.

## Link errors mentioning ALSA/asound, X11/xkbcommon/Wayland

System library dependencies for `cpal` (audio) and `winit`/`wgpu`
(windowing/GPU), not a Rust problem. On Debian/Ubuntu:

```bash
sudo apt install libx11-dev libxkbcommon-dev libwayland-dev pkg-config \
                 libasound2-dev libgl1-mesa-dev
```

## Window fails to open with an adapter panic (`request_adapter` returned `None`)

No usable Vulkan device found. Install `mesa-vulkan-drivers vulkan-tools`
and run `vulkaninfo` -- it should print your GPU's name. If it doesn't,
that's the real problem to fix (a driver issue), not something in this
codebase.

## The renderer dies with `SIGSYS` ("Bad system call")

The seccomp allowlist (`renderer::sandbox::linux::ALLOWED_SYSCALLS`) is
missing a syscall your libc/kernel/a new code path actually needs. Look
for `type=1326` lines with a `syscall=` number in `dmesg`/`journalctl -k`
if audit logging is enabled, or trace the renderer directly with `strace`.
This is genuinely the most likely failure the first time you run this on
a new distro or a new CI runner -- see `07-sandboxing.md` for the real
methodology to re-derive the list, and never just add a syscall because a
crash mentions it without confirming it's legitimate.

## "Landlock ... not fully enforced" warning

Your kernel is older than 6.7 (or has Landlock disabled). The renderer
still runs, with fewer restrictions -- this is expected on older systems,
not a bug, and `renderer::sandbox::linux::apply` deliberately never
refuses to start over it.

## `app` tests fail offline or behind a strict firewall

Several tests make real fetches (`example.com`, `example.org`,
`httpbin.org`) through real DoH and TLS -- this is deliberate (see
`08-rust-patterns-glossary.md`'s note on when this codebase reaches for a
real network test vs. a fake fetcher). DoH itself goes to
`1.1.1.1`/`1.0.0.1` on port 443, and the whole fetch fails closed if that's
unreachable -- which is correct behavior, not a bug, if you're testing that
specific failure mode. Otherwise use
`cargo test --workspace --exclude abyssal` to skip everything that needs a
network.

## Cross-compilation for macOS/Windows type-checking hits a wall

`cargo check -p renderer --target x86_64-apple-darwin` (or
`--target x86_64-pc-windows-gnu`) is the normal way to catch real API
mistakes in platform-specific code without real hardware -- but the FULL
crate often can't finish, because `reqwest`'s TLS stack pulls in
`aws-lc-sys`, which needs a real C cross-compiler (`clang` targeting
Darwin, or `x86_64-w64-mingw32-gcc` for Windows) that a normal dev
machine/CI runner usually doesn't have installed. You'll see an error like
`failed to run custom build command for aws-lc-sys` or
`failed to find tool "x86_64-w64-mingw32-gcc"`.

**The real workaround, used throughout this project's own sandboxing
work**: if the code you actually need to check is small and has few
dependencies of its own (a new function in `sandbox.rs`, say), copy just
that code into an isolated scratch crate (in your scratchpad directory,
never inside this repo) whose `Cargo.toml` only lists the specific
dependency it needs (`libc`, or `windows-sys` with the right feature list --
copy the exact feature list from `renderer/Cargo.toml`'s own
`[target.'cfg(...)'.dependencies]` section). `libc`/`windows-sys`
themselves are pure Rust bindings with no C compilation step, so a scratch
crate depending on only those builds cleanly cross-platform even in an
environment that can't build the real `renderer` crate for that target.
This proves the code type-checks correctly without proving anything about
the rest of the crate -- good enough for "did I get this FFI signature
right," not a substitute for testing the whole thing on Linux.

## A resource-limit or sandbox check seems to pass but isn't real

`setrlimit`/`SetInformationJobObject` returning success does NOT prove the
OS is actually enforcing the limit -- some sandboxed/virtualized/containerized
environments (including, in one real case during this project's own
development, whatever this exact coding environment runs inside)
silently accept the call without applying it. The real check reads the
limit back from the kernel's own accounting after the fact
(`/proc/<pid>/limits` on Linux). If you get a suspicious result, don't
assume it's wrong -- first check whether you raced a process's own exit
(see the next entry).

## A `/proc/<pid>/limits`-style check gives an unexpected result

If you spawn a short-lived process, capture its PID, then read
`/proc/<pid>/...` shortly after, there's a real race: if the process has
already exited by the time you read it, the PID can have been **reused**
by an unrelated, completely different process by the time your read
happens, and you'll silently get *that* process's real (probably
unrestricted) limits instead of an error. This actually happened once
during this project's own `setrlimit` verification work -- feeding the
renderer's stdin from `/dev/null` let it hit EOF and exit almost
immediately, and a `/proc` read a moment later picked up a reused PID
showing "unlimited." The fix: keep the process alive on purpose while you
check it -- feed its stdin from an open pipe (`mkfifo`, or just don't close
the write end) instead of `/dev/null`, confirm with `ps -p <pid>` that it's
really still your process, then check.

## `abyssal-data/` or `sync-server-data/` appeared in your working tree

Runtime data directories, ignored by `.gitignore`. Real browser data lives
in your OS's standard per-user directory, never in the repository. Never
commit either -- `abyssal-data/` in particular can contain a real recovery
code.

## Tests pass locally but a real page renders blank or badly wrong

Expected for anything JS-framework-heavy -- this rendering engine's CSS/
layout/JS surface is real but deliberately narrow (see `02-*.md` and
`03-*.md` for exactly what's covered). Try a plain static HTML page first
to confirm the basics work, then check the relevant crate's own module doc
for what's explicitly out of scope before assuming it's a bug.

## `cargo audit` fails in CI

Treats any advisory (including "unmaintained"/"yanked" warnings) as an
error. Read the actual report: update the flagged dependency if a fix
exists, or document and explicitly ignore a specific advisory that has no
fix, with a written reason -- never just silence it blind.
