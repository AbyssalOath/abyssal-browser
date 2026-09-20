# 07. Sandboxing

All of this lives in `renderer/src/sandbox.rs`. Read its top-of-file `//!`
doc comment first -- it's long, but it's the honest, up-to-date account of
what's real and what's real-but-unverified across all three platforms, and
this page is a narrative companion to it, not a replacement.

## The honest confidence gradient

This matters enough to say up front: **Linux's sandbox has actually run, a
lot, on real hardware, exercised continuously by this project's own real
test suite. macOS's and Windows's have not** -- they were written and
cross-type-checked (`cargo check --target x86_64-apple-darwin` /
`--target x86_64-pc-windows-gnu`) without ever running on the real OS,
because there's no Mac or Windows machine in this project's development
loop. Treat them as a real, meaningful reduction in attack surface, not as
tested-and-proven the way Linux's is. If you ever get real hardware, the
single highest-value thing to do with it is re-derive both from a real
trace the way Linux's already was.

## Linux: Landlock + seccomp-bpf, in that order

Two layers, applied in a specific order for a specific reason.

**Landlock** (via the `landlock` crate, targeting ABI V4 specifically --
`linux::TARGET_ABI`) restricts *what the process can touch*: read-only
access to the OS's real TLS trust store paths (`/etc/ssl`, `/etc/pki`, plus
whatever `SSL_CERT_FILE`/`SSL_CERT_DIR` name -- `read_only_cert_paths`, with
a real symlink-resolution pass, `walk_symlinks`, because at least one real
distro -- Arch -- ships its actual cert bundle as a symlink to somewhere
Landlock's path-based rules wouldn't otherwise cover), read/write on
*only* its own cache directory, and outbound TCP to ports 80/443 only
(no `BindTcp` rule at all, so it can never listen on anything). On a
kernel with only partial Landlock support, `apply` logs a warning and
continues with whatever subset that kernel supports -- it never refuses to
start the renderer over it.

**seccomp-bpf** (via `seccompiler`, in the `seccomp` submodule) restricts
*which syscalls the process may make at all* -- currently a 55-entry
allowlist (`ALLOWED_SYSCALLS`), everything else killing the process outright.
This is the piece Landlock alone can't provide: Landlock says nothing about
`ptrace`, `mount`, `reboot`, or an arbitrary `ioctl` -- all still permitted
by Landlock alone.

**Why this order matters, specifically**: once a seccomp filter is
installed, it can only ever be *narrowed* further within that process, never
widened again. So anything Landlock itself still needs to do its own setup
has to happen before seccomp locks the rest down -- hence Landlock first,
`resource_limits::apply()` second (see below -- `setrlimit` is itself a
syscall), seccomp last.

### How the allowlist was actually derived

Not guessed. `strace -ff` against a real, representative workload (a real
DoH lookup, a real HTTPS fetch, a cache read/write, a second host, a real
`Tick`, a real `Click`), then compared against the list. Enforcement was
proven, not assumed: a used syscall was temporarily removed and the
renderer was confirmed to die with a real `SIGSYS` on its next operation
needing it, then restored.

Two things landed in this crate *after* that original trace without
triggering a re-trace, deliberately: `layout::flex`/`layout::grid` and
CSS's inline `style="..."` support, both pure in-memory computation with
provably no I/O of their own (verified by reading the code, since it's this
crate's own Rust, not a third-party black box). `renderer::images` DID get
an actual re-trace (a genuinely new I/O path -- a second kind of fetch, a
new decode dependency) against a real, complex page
(`en.wikipedia.org`'s actual homepage) -- every syscall it made was already
on the list. That result is *why* the "pure computation needs no re-trace"
reasoning above is trusted rather than just hoped: it's independent
empirical confirmation the theory holds in this specific codebase.

**The lesson for future you**: if you add a genuinely new kind of I/O (a
new dependency that opens files/sockets, a new fetch path), that's the
trigger to re-run the real trace. If you add pure computation over bytes
already fetched by an existing, already-traced path, reasoning about it is
accepted -- but say so explicitly in a comment, the way every existing
instance of this does, so the next person can tell "measured" from
"reasoned about."

Two real, concrete syscalls that got added to the allowlist *after* the
original trace, both found via real repro rather than guessed: `SYS_clock_gettime`
and `SYS_fchmod` (the latter for the old file-based cookie-persistence
code's `set_permissions` call -- since removed when persistence moved to
`app`, but the syscall stayed in the allowlist; nothing currently forces
it back out, and it's harmless to leave allowed).

## Resource limits: `sandbox::resource_limits`

A cheap, portable backstop independent of everything above -- Landlock and
seccomp say nothing about *how much* of anything a process may use, only
*which* paths/syscalls. On Linux and macOS this is real `setrlimit`
(`RLIMIT_AS` capping virtual memory at 1.5 GiB, `RLIMIT_CPU` capping
cumulative CPU time at 30 minutes), applied via a small macro
(`set_limit!`) rather than a plain function -- `RLIMIT_AS`/`RLIMIT_CPU` are
typed differently per platform (`u32` on glibc, `c_int` on Darwin), so a
function with one fixed parameter type literally can't compile against
both. On Windows, the same numbers apply via the existing Job Object's
`JOB_OBJECT_LIMIT_PROCESS_MEMORY`/`PROCESS_TIME` fields (same Job Object
that already caps this process to a single active child -- see below).

**The one honest wrinkle worth remembering**: `RLIMIT_CPU` counts
*cumulative* CPU time since the process started, not wall-clock time and
not reset per navigation or per message. A single `RendererPool` process
can live across many navigations on the same site for an entire browsing
session. 30 minutes is chosen generously specifically because of that --
ordinary browsing spends the overwhelming majority of its time idle
between real script/layout work, so this is meant to catch a genuinely
pathological runaway (a native Rust bug outside `script::RuntimeLimits`'s
own reach -- that one only bounds JS loop iterations/recursion, not native
code) rather than ever fire during real, if heavy, legitimate use. A true
per-operation watchdog would need a fundamentally different design
(re-arming the limit around each message, or a wall-clock timeout thread)
-- not built here, deliberately, as the cheap/coarse version instead.

This was empirically verified, not just "should work": the real
`abyssal-renderer` binary was spawned directly and its actual
`/proc/<pid>/limits` was read back, confirming the kernel really enforces
the configured values (a `setrlimit` call reporting success doesn't
automatically prove enforcement -- some sandboxed/virtualized environments
silently no-op it).

## macOS: Seatbelt

A real SBPL (Sandbox Profile Language) string, applied via the private-but-
stable `sandbox_init`/`sandbox_free_error` FFI (`libsystem_sandbox.dylib`,
always present on real macOS -- not in the public `libc` crate since it's
Apple-private, hence the raw `extern "C"` block in `macos::`). Restricts
filesystem the same way Landlock does (read-only baseline system paths,
read/write on the cache dir only) and outbound network to ports 80/443
only.

**The one deliberately-not-yet-closed gap**: `mach-lookup` (every Mach IPC
service the process can reach) is left completely unrestricted. Real TLS
certificate verification on macOS goes through `Security.framework`
(`SecTrust`), which talks to system daemons like `trustd` over Mach IPC
rather than reading flat cert files the way Linux does -- naming the exact
service set that needs is exactly the kind of thing this project normally
derives from a real trace, and there's no Mac here to run one on. This is
explicitly flagged as the single highest-value next step for macOS
specifically, once real hardware exists.

## Windows: Job Object + mitigation policies

Deliberately does NOT attempt AppContainer (the real Chrome/Edge-grade
mechanism) -- that needs a container profile, capability SIDs, and
`UpdateProcThreadAttribute` calls from the *parent* at process creation, a
much larger surface to get right blind. What's here instead is several
independently-simple, well-documented Win32 mechanisms, each failing loudly
on its own if denied rather than silently partially applying:

- A Job Object the process puts itself into, capped to a single active
  process (so it can never successfully spawn a child) and killed if the
  job handle itself ever closes -- plus (see above) the real memory/CPU
  limit fields on that same Job Object.
- `ProcessDynamicCodePolicy` -- safe because Boa is a pure Rust tree-walking
  interpreter with no JIT.
- `ProcessSystemCallDisablePolicy` -- blocks ALL of `win32k.sys` (the entire
  GUI/USER/GDI syscall surface); safe because this process creates no
  windows and does no GDI drawing (confirmed by its own `Cargo.toml` never
  pulling in `winit`/`wgpu`/`render` -- all real UI/GPU work happens in
  `app` instead).
- `ProcessExtensionPointDisablePolicy` / `ProcessImageLoadPolicy` --
  standard, narrow hardening (no legacy global hooks, no loading a DLL
  from a network path or with a low integrity label).
- `ProcessChildProcessPolicy` (`NoChildProcessCreation`) -- belt-and-suspenders
  with the Job Object's own single-process cap, since the two mechanisms
  fail independently.

Deliberately skips `ProcessSignaturePolicy` (Microsoft-signed-only module
loading) -- real third-party AV/EDR hooking DLLs, common on real consumer
and corporate machines alike, often aren't Microsoft-signed and would
legitimately need to load here; enforcing this blind with no real Windows
machine to notice a resulting "renderer silently fails to start" regression
was judged a worse trade than leaving it out.

## `file://` support: one process gets the opposite trade

Everything above assumes a renderer process's job is to fetch REMOTE bytes
over the network and touch almost nothing on disk. `file://` support (see
`app::site_for_url`, `app::LOCAL_FILES_SITE`, and `network::FilteringFetcher
::enable_local_file_access`) needed the exact opposite of that for exactly
one process, and the interesting part is how the rest of this module's
existing machinery made that safe to add rather than needing a whole new
mechanism.

**The problem this had to avoid**: real browsers restrict `file://`
specifically because a malicious remote page can construct a clickable
`<a href="file:///home/you/.ssh/id_rsa">` link. Without isolation, clicking
it would read (and, if that process still had network access, exfiltrate) an
arbitrary local file through the SAME renderer process that was rendering
the malicious remote page. This project has no iframes and no general
cross-origin script navigation, but that one clickable-link path is real
regardless, so the fix had to be structural.

**The fix reuses site isolation as a security boundary, not just a crash
one.** `site_for_url` routes every `file://` URL, whatever its actual path,
to one fixed site key (`LOCAL_FILES_SITE`) instead of the real per-eTLD+1
key a normal URL gets. That means `RendererPool` -- the exact same mechanism
that already gives `example.com` and `evil.example` their own separate
processes -- spawns exactly ONE process for every local file any tab ever
opens, and that process is never, under any circumstances, the same process
a real website's tab uses.

**Only that one process is ever spawned with `--allow-local-files`
(`renderer/src/main.rs`), and it changes two sandbox rules together, never
one without the other**:

- Linux (`linux::build_and_restrict`): instead of the usual narrow
  `cache_dir`-only Landlock rule, it adds ONE root-scoped `PathBeneath` rule
  (`PathFd::new("/")`) -- real, broad, read access to anything the OS user
  account can read, matching what the user explicitly chose over Chrome/
  Firefox's own default scope. And it skips the `NetPort`/`ConnectTcp` rule
  loop entirely -- no rule granting outbound access to ports 80/443 at all,
  which for Landlock (an allowlist mechanism -- nothing not explicitly
  granted is permitted) means no network access, period.
- macOS (`macos::build_profile`): the same trade in SBPL -- an unrestricted
  `(allow file-read* (subpath "/"))` line instead of the narrow `cache_dir`
  one, and the two `(allow network-outbound ...)` lines for ports 80/443 are
  left out of the profile string entirely rather than narrowed.

**Why giving up network access is what makes broad read access safe**: even
a fully compromised dedicated `file://` process -- Boa engine bug, a
`renderer` parsing bug, anything -- has no socket to exfiltrate what it
reads through. The two changes are a package deal for exactly this reason;
granting one without the other would defeat the point.

**`FilteringFetcher` gates this too, at the one chokepoint every fetch
already goes through.** `allow_local_files` (set once, at process startup,
by `enable_local_file_access`) is checked in `fetch_in_context_with_body`
before ANY `file://` URL is served -- and since navigation, images,
stylesheets, external scripts, and a page's own `fetch()` all flow through
that same function, this one flag covers every one of them without each
needing its own check. An ordinary website's renderer process never calls
`enable_local_file_access`, so a `file://` fetch attempted from within a
malicious page's own script -- not just a clicked link -- is rejected before
ever touching disk, proven directly in `network`'s own test suite
(`a_file_url_is_rejected_when_local_file_access_is_not_enabled` and its
siblings).

**Windows** gets the flag threaded through for signature consistency
(`windows::apply`/`other::apply` both now take the same `local_file_access:
bool` parameter every platform's `apply` does), but it's a documented no-op
there: none of the existing Job Object/mitigation-policy hardening is a
filesystem- or network-access control to begin with, so there is nothing to
toggle. On Windows, correctness rests entirely on `app`'s own process-
routing logic -- see this page's own "honest confidence gradient" section
above, which applies here with an extra edge: even Linux's own kernel-level
guarantee doesn't exist yet on that platform for this specific feature.

## Verifying any of this yourself

`TESTING.md`'s "Testing the sandbox" section has the actual commands. In
short: trace with `strace -ff`, compare against `ALLOWED_SYSCALLS`, and to
prove enforcement rather than just coverage, temporarily delete one used
entry and confirm a real `SIGSYS` kill on the next operation that needs it.
For the resource limits specifically, spawn the real binary with its stdin
held open (not `/dev/null` -- it exits on EOF almost immediately, which
races with reading `/proc/<pid>/limits` afterward) and read
`/proc/<pid>/limits` back directly.
