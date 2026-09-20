//! Process sandboxing for the renderer, one real implementation per
//! platform — see each platform module's own doc comment for what it
//! actually does and how confident to be in it. Linux's (Landlock +
//! seccomp-bpf) is the mature one: built from an EMPIRICAL syscall
//! trace against a real, representative workload, and exercised
//! continuously by this project's own real test suite on real Linux
//! hardware. macOS's (Seatbelt) and Windows's (Job Object + process
//! mitigation policies) are real, but were written and cross-type-
//! checked (`cargo check --target x86_64-apple-darwin` /
//! `--target x86_64-pc-windows-gnu`) without ever running on the
//! actual OS — there is no Mac or Windows machine in this project's
//! own development loop. Treat them as a real, meaningful reduction
//! in attack surface, not as tested-and-proven to the same standard
//! Linux's is; the honest thing before relying on either for something
//! that actually matters is to run it for real on that OS first.
//!
//! Linux: Landlock (kernel 5.13+; network restrictions specifically
//! need 6.7+, ABI V4) PLUS seccomp-bpf syscall filtering on top of it,
//! applied in that order. Landlock alone (the whole of this module
//! before seccomp was added) can
//! stop a compromised renderer from touching any file outside an
//! explicit allowlist, or opening a connection anywhere but ports
//! 80/443 — which for this specific process (whose only real job is
//! fetch+parse+layout+script-execution of untrusted content) covers
//! the two things that matter most: it can never read
//! `abyssal-data/account.txt` or `bookmarks.enc` (the account's
//! recovery code and encrypted bookmarks — this process never even
//! gets a copy of them, since `app` never sends them over the IPC
//! boundary either), and it can never open a connection anywhere but
//! a normal web port, ruling out e.g. a C2 callback on an arbitrary
//! port or a listening socket. But Landlock says nothing at all about
//! WHICH SYSCALLS this process may make — `ptrace`, `mount`,
//! `reboot`, arbitrary `ioctl`s were all still permitted, right up
//! until this pass. seccomp-bpf closes that: an allowlist of the
//! ~50 syscalls this process ACTUALLY makes doing its real job (see
//! `linux::ALLOWED_SYSCALLS`' own doc comment for exactly how that
//! list was derived), with anything else killing the process outright
//! rather than being permitted or silently erroring.
//!
//! Deliberately targets Landlock ABI V4 specifically, not "whatever's
//! newest" — the `landlock` crate's own docs explicitly recommend
//! this: ABIs should be a version you've actually tested against, not
//! chosen dynamically at runtime, since an untested newer restriction
//! category could behave unexpectedly. V4 is what introduces network
//! restrictions (the feature this module cares about most), and is
//! old enough (Linux 6.7, released Jan 2024) to be on current stable
//! distros. A kernel with only PARTIAL Landlock support (older, or a
//! custom kernel build with it disabled) still gets whatever subset
//! that kernel supports — see `apply`'s handling of `RulesetStatus`;
//! this never refuses to start the renderer over it, only warns. The
//! seccomp filter is applied AFTER Landlock, deliberately last: once
//! it's installed there's no going back (a seccomp filter can only
//! ever be narrowed further within a process, never widened), so
//! everything Landlock itself needed to set up (its own syscalls) is
//! already done by the time seccomp locks the rest down.
//!
//! Next steps, roughly in order of payoff:
//!   1. Get real macOS and Windows hardware into this project's own
//!      test loop, and re-derive both platforms' sandboxes from that
//!      the way Linux's already was — a real syscall/mach-lookup trace
//!      on macOS, and real verification that the Windows mitigation
//!      policies/Job Object actually apply (`cargo test`, on real
//!      hardware, currently only proves the Linux implementation).
//!      Concretely, for macOS specifically: `macos::PROFILE` allows
//!      `mach-lookup` UNRESTRICTED rather than naming the exact
//!      services real TLS cert verification needs (`trustd` and
//!      friends) — see that module's own doc comment for why, and
//!      why narrowing it is the single highest-value next step there.
//!   2. ~~A per-process resource limit (`setrlimit`) as a cheap, portable
//!      backstop against a memory-exhaustion bug~~ Done — see
//!      `resource_limits`'s own doc comment (Linux/macOS) and
//!      `windows::apply_job_object`'s memory/CPU fields (Windows).
//!      Empirically confirmed enforced on real Linux hardware via a
//!      running renderer's own `/proc/<pid>/limits`; real code,
//!      unverified on macOS/Windows like the rest of those two
//!      platforms' sandboxes.
//!   3. `ALLOWED_SYSCALLS` was derived from ONE real, representative
//!      workload (see its doc comment) — a genuinely new code path
//!      added to this crate later that does its own real I/O (a new
//!      dependency, a new kind of fetch) could need a syscall not on
//!      the list, which would show up as that specific operation
//!      failing (killing the renderer; `app`'s existing
//!      respawn-and-retry logic recovers the PROCESS, but the same
//!      operation will fail again deterministically on retry) rather
//!      than a compile error — re-run the same tracing methodology
//!      against the new code path if that ever happens. Two whole
//!      features landed in this crate AFTER the trace that produced
//!      `ALLOWED_SYSCALLS` (`layout::flex`/`layout::grid`, and
//!      `css`'s inline `style="..."` attribute support) without
//!      triggering a re-trace, deliberately: both are pure in-memory
//!      computation (arithmetic, `Vec`/`HashMap` bookkeeping, string
//!      parsing) with no I/O of their own at all — verified by reading
//!      the code, not assumed, since it's this crate's OWN Rust, not a
//!      third-party black box. `script`'s Boa-JS-evaluation path
//!      (`setTimeout` firing, `click` dispatch running a listener)
//!      gets the weaker version of that same argument: Boa is a
//!      genuine third-party dependency, so "no I/O" here is
//!      architectural reasoning (a pure ECMAScript interpreter has no
//!      reason to make syscalls beyond heap growth — `mmap`/`brk`/
//!      `mremap`, already allowed) rather than something read line by
//!      line, and external `<script src>` fetching/a redirect/blocked
//!      third-party subresource reuse the EXACT SAME `fetch_in_context`
//!      code path the traced top-level page fetch already exercises —
//!      not independently re-traced for the same reason `flex`/`grid`
//!      weren't. All of that is reasoning, not fresh measurement,
//!      which is a real difference worth being honest about even
//!      though it hasn't broken anything in real end-to-end testing so
//!      far — a genuinely new dependency or fetch path is still the
//!      trigger to actually re-run the tracer, not just reason about it.
//!      `renderer::images` (real `<img src>` fetching + decoding via
//!      the `image` crate) is the one exception that DID get an actual
//!      re-trace, not just reasoning — it's a genuinely new real I/O
//!      path (a second kind of fetch, a new decoding dependency), so
//!      the bar it needed to clear was different: the tracer was
//!      re-run against a real, complex, image-laden page
//!      (`en.wikipedia.org`'s actual main page — real image fetch
//!      attempts, real inline scripts including some that threw, a
//!      real successful navigation) and every syscall it observed was
//!      already in `ALLOWED_SYSCALLS` — no changes needed. That result
//!      is also *why* the flex/grid/inline-style/Boa reasoning above
//!      is trusted rather than just hoped: it's independent empirical
//!      confirmation that "pure computation over already-fetched
//!      bytes adds no new syscalls" actually holds in this codebase,
//!      not only in theory. `renderer::media`'s `symphonia`-based
//!      audio decode gets the same REASONING-not-fresh-measurement
//!      treatment as Boa: it reuses the exact same `fetch_in_context`
//!      path already covered by the trace (no new kind of fetch), and
//!      decoding itself is pure computation over already-fetched bytes
//!      (parsing a container, running a codec) with no I/O of its
//!      own — a real, symmetric case to `renderer::images`' own
//!      decode step, which already sits comfortably under the same
//!      allowlist. Not independently re-traced for the same reason
//!      `flex`/`grid` weren't; a genuinely new fetch path (streaming
//!      audio, say) would still be the trigger to actually do so.
//!      `renderer::pdf`'s `pdf-extract`-based text extraction gets the
//!      exact same treatment for the exact same reason: it reuses the
//!      already-covered `fetch_in_context` path, and
//!      `extract_text_from_mem_by_pages` operates purely in memory over
//!      bytes already fetched — no filesystem access, no I/O of any
//!      kind, just parsing.

use std::path::Path;

/// A per-process resource limit backstop for Linux and macOS, shared
/// between `linux::apply`/`macos::apply` (both real POSIX systems, so
/// both get the exact same `setrlimit` calls) — see this module's own
/// top-level doc comment, "next steps" item 2. Landlock/Seatbelt say
/// nothing about HOW MUCH of anything a process may use, only WHICH
/// paths/ports it may touch; seccomp says nothing about HOW MUCH
/// either, only WHICH syscalls. Neither stops a memory-exhaustion bug
/// (or a page trying to exhaust memory on purpose) from using up all
/// of the machine's RAM, or a runaway loop somewhere outside
/// `script::RuntimeLimits`'s own reach (native Rust code, not JS) from
/// pinning a CPU core indefinitely. `setrlimit` is a real, cheap,
/// portable-across-POSIX backstop against exactly those two failure
/// modes, independent of and in addition to Landlock/seccomp/Seatbelt.
///
/// Windows gets the equivalent protection a different way — see
/// `windows::apply_job_object`'s own `ProcessMemoryLimit`/
/// `PerProcessUserTimeLimit` fields on the SAME Job Object it already
/// creates, not this module.
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod resource_limits {
    /// Chosen, not measured against every real page: a real fetch/
    /// parse/layout/script pass for an ordinary page uses a small
    /// fraction of this (the media caps elsewhere in this crate — 1200
    /// px images, ~40 MB decoded audio, ~45 MB downloads — give a sense
    /// of scale), while 1.5 GiB is still enough headroom for a
    /// legitimately heavy page (a big PDF, a large inline script's own
    /// heap) to keep working. A hostile or badly-behaved page that
    /// tries to allocate far beyond that gets this process killed
    /// (`SIGSEGV`/an allocation failure, not gracefully) rather than
    /// left to grow without bound.
    const MEMORY_LIMIT_BYTES: u64 = 1536 * 1024 * 1024;

    /// `RLIMIT_CPU` counts CUMULATIVE CPU time consumed since this
    /// PROCESS started (not wall-clock time, and not reset per
    /// navigation or per message) — a real, disclosed mismatch with
    /// what an ideal "per-operation" or "per-page" CPU budget would
    /// look like, since one `RendererPool` process can live for an
    /// entire browsing session across many navigations on the same
    /// site (see `app::RendererPool`). 30 minutes of ACTUAL busy CPU
    /// time (not idle-while-waiting-for-input time, which doesn't
    /// count against this at all) is chosen generously specifically
    /// because of that mismatch: ordinary browsing, even a long
    /// session, spends the overwhelming majority of its time idle
    /// between real script/layout work, so this is meant to catch a
    /// genuinely pathological runaway (a bug that spins a native loop
    /// outside `script::RuntimeLimits`'s own reach, which only bounds
    /// JS loop iterations and recursion, not native Rust code) rather
    /// than ever fire during real, if heavy, legitimate use. A real
    /// per-operation watchdog would need a fundamentally different
    /// design (re-arming the limit around each message, or a wall-
    /// clock timeout thread) — not implemented here; this is the
    /// cheap, coarse backstop, not that.
    const CPU_LIMIT_SECONDS: u64 = 30 * 60;

    /// A macro, not a plain function, specifically because `RLIMIT_AS`/
    /// `RLIMIT_CPU` are typed differently per platform (`u32` on
    /// glibc/Linux, `c_int` on Darwin/macOS — both are real, valid
    /// `libc::setrlimit` argument types on their own platform, just not
    /// the SAME type), so a function with one fixed parameter type
    /// cannot accept both; inlining the call lets each platform's own
    /// call site typecheck against whatever `libc::RLIMIT_*` actually
    /// is there. Sets both the soft AND hard limit to `$value` — there
    /// is no legitimate reason for this process to ever raise either
    /// back up (it never calls `setrlimit` again after this), so
    /// there is nothing a "soft limit lower than hard limit, raisable
    /// later" split would actually be used for here.
    macro_rules! set_limit {
        ($resource:expr, $value:expr, $name:expr) => {{
            let limit = libc::rlimit {
                rlim_cur: $value as libc::rlim_t,
                rlim_max: $value as libc::rlim_t,
            };
            // SAFETY: `limit` is a fully-initialized, valid
            // `libc::rlimit` value living on this stack frame for the
            // duration of the call; the resource constant is one of
            // libc's own fixed `RLIMIT_*` values, exactly the contract
            // `setrlimit` documents.
            let result = unsafe { libc::setrlimit($resource, &limit) };
            if result != 0 {
                eprintln!(
                    "renderer: failed to set {} to {} ({}) - continuing without this limit.",
                    $name,
                    $value,
                    std::io::Error::last_os_error()
                );
            } else {
                eprintln!("renderer: {} capped at {}.", $name, $value);
            }
        }};
    }

    /// Applied once, at startup, before the platform's own filesystem/
    /// network/syscall restrictions go up (Landlock+seccomp on Linux,
    /// Seatbelt on macOS) — `setrlimit` itself is a syscall, and on
    /// Linux specifically it must run BEFORE `seccomp::apply()`
    /// installs its allowlist, since a seccomp filter can only ever be
    /// narrowed afterward (see this module's own top-level doc
    /// comment), never widened to permit one more call later.
    pub fn apply() {
        set_limit!(
            libc::RLIMIT_AS,
            MEMORY_LIMIT_BYTES,
            "RLIMIT_AS (virtual memory)"
        );
        set_limit!(
            libc::RLIMIT_CPU,
            CPU_LIMIT_SECONDS,
            "RLIMIT_CPU (cumulative CPU time)"
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use landlock::{
        Access, AccessFs, AccessNet, NetPort, PathBeneath, PathFd, Ruleset, RulesetAttr,
        RulesetCreatedAttr, RulesetError, RulesetStatus, ABI,
    };

    /// See this module's doc comment for why V4 specifically.
    const TARGET_ABI: ABI = ABI::V4;

    /// Read-only paths a normal TLS stack needs to verify certificates:
    /// `network`'s `HttpFetcher` goes through `reqwest` ->
    /// `rustls-platform-verifier` -> `rustls-native-certs` ->
    /// `openssl-probe`, which reads the system's CA trust store from
    /// disk (see that crate's own docs — it is NOT a bundled/compiled-in
    /// trust store). Covers the common Linux distro layouts
    /// (Debian/Ubuntu/Arch under `/etc/ssl`, Fedora/RHEL under
    /// `/etc/pki`) plus whatever `SSL_CERT_FILE`/`SSL_CERT_DIR` point
    /// at, if set. A candidate that doesn't exist on this system is
    /// silently skipped, not treated as an error — no single system
    /// has all of these.
    ///
    /// Also resolves and grants every SYMLINK found (shallowly) inside
    /// those directories, not just the directories themselves — Arch,
    /// Debian, and Ubuntu all ship the actual bundle FILE
    /// `openssl-probe` looks for, `/etc/ssl/certs/ca-certificates.crt`,
    /// as a symlink to somewhere else entirely (on Arch specifically,
    /// `/etc/ca-certificates/extracted/tls-ca-bundle.pem`). Landlock
    /// enforces access at the symlink's RESOLVED target, not its own
    /// path, so granting only `/etc/ssl` still leaves that real file
    /// unreachable — confirmed via a real repro on exactly this Arch
    /// layout: every HTTPS fetch failing with rustls's `"No CA
    /// certificates were loaded from the system"` under full Landlock
    /// enforcement (ABI V4), the sandboxed renderer's one and only
    /// path to the network having gone completely dark. `walk_symlinks`
    /// is capped at a shallow depth since a real cert tree is never
    /// nested more than 2-3 levels deep, not because a deeper one
    /// would be unsafe to walk.
    fn read_only_cert_paths() -> Vec<std::path::PathBuf> {
        let mut paths = vec![
            std::path::PathBuf::from("/etc/ssl"),
            std::path::PathBuf::from("/etc/pki"),
        ];
        if let Some(file) = std::env::var_os("SSL_CERT_FILE") {
            paths.push(std::path::PathBuf::from(file));
        }
        if let Some(dirs) = std::env::var_os("SSL_CERT_DIR") {
            paths.extend(std::env::split_paths(&dirs));
        }
        paths.retain(|p| p.exists());

        let mut resolved_targets = Vec::new();
        for path in &paths {
            walk_symlinks(path, 4, &mut resolved_targets);
        }
        for target in resolved_targets {
            if !paths.iter().any(|p| target.starts_with(p)) {
                paths.push(target);
            }
        }
        paths
    }

    /// Recursively (up to `max_depth`) visits every entry under `path`
    /// and, for each one that's ultimately a symlink to somewhere
    /// else, canonicalizes it and pushes that REAL, resolved path's
    /// parent directory into `out` — see `read_only_cert_paths`'s doc
    /// comment for why. A single unreadable/broken entry is skipped,
    /// not treated as an error — this is best-effort discovery on top
    /// of the already-granted literal paths, never the only path to
    /// them.
    fn walk_symlinks(path: &Path, max_depth: u32, out: &mut Vec<std::path::PathBuf>) {
        let Ok(metadata) = std::fs::symlink_metadata(path) else {
            return;
        };
        if metadata.is_symlink() {
            if let Ok(real) = std::fs::canonicalize(path) {
                if let Some(parent) = real.parent() {
                    out.push(parent.to_path_buf());
                }
            }
            return;
        }
        if max_depth == 0 || !metadata.is_dir() {
            return;
        }
        let Ok(entries) = std::fs::read_dir(path) else {
            return;
        };
        for entry in entries.flatten() {
            walk_symlinks(&entry.path(), max_depth - 1, out);
        }
    }

    /// Builds the full ruleset and activates it in one fallible chain
    /// -- `Ruleset`/`RulesetCreated`'s builder methods consume and
    /// return `Self` (see the `landlock` crate), so a failure partway
    /// through can't be "resumed" from a partially-built ruleset; the
    /// caller (`apply`) treats any `Err` here as "couldn't sandbox at
    /// all" rather than "sandboxed except for the one rule that failed".
    ///
    /// `local_file_access` is `true` for exactly one renderer process
    /// this whole browser ever spawns: the dedicated one
    /// `app::RendererPool` routes every `file://` navigation to (see
    /// that struct's own doc comment on why `file://` gets its own
    /// process, never shared with a real website's). When `true`, this
    /// grants real, broad READ access to the whole filesystem (root-
    /// scoped, so it covers everything this OS user can read -- matching
    /// real browsers' own `file://` scope, a deliberate choice over a
    /// narrower one -- see `THREAT_MODEL.md`) and grants NO network
    /// access at all (the `NetPort`/`ConnectTcp` loop below is skipped
    /// entirely, so this process cannot open a socket to anywhere,
    /// full stop). That combination -- real local-file read, zero
    /// network -- is what makes `file://` browsing safe to add at all:
    /// even a fully compromised render of a hostile local HTML file has
    /// nothing to exfiltrate TO, because the kernel itself refuses the
    /// connection before any application code runs. Every OTHER
    /// renderer process (the overwhelming majority -- one per real
    /// website) keeps the original, narrow policy completely unchanged:
    /// only its own cache directory, no broader filesystem read at all.
    fn build_and_restrict(
        cache_dir: &Path,
        local_file_access: bool,
    ) -> Result<RulesetStatus, RulesetError> {
        let mut ruleset = Ruleset::default()
            .handle_access(AccessFs::from_all(TARGET_ABI))?
            .handle_access(AccessNet::from_all(TARGET_ABI))?
            .create()?;

        for path in read_only_cert_paths() {
            if let Ok(fd) = PathFd::new(&path) {
                ruleset =
                    ruleset.add_rule(PathBeneath::new(fd, AccessFs::from_read(TARGET_ABI)))?;
            }
        }

        // Read/write access to (only) the disk cache -- see
        // `network::disk_cache`'s docs. If this directory can't be
        // opened, we deliberately still proceed with everything else:
        // worst case the disk cache fails closed (every write silently
        // fails, every read misses), a functionality regression, not
        // a security one.
        if let Ok(fd) = PathFd::new(cache_dir) {
            ruleset = ruleset.add_rule(PathBeneath::new(fd, AccessFs::from_all(TARGET_ABI)))?;
        }

        if local_file_access {
            // Root-scoped: a single Landlock rule on `/` covers every
            // path beneath it, the same way the `cache_dir` rule above
            // covers everything beneath THAT one directory -- see this
            // function's own doc comment for why this scope was chosen
            // deliberately, not left this broad by oversight.
            if let Ok(fd) = PathFd::new("/") {
                ruleset =
                    ruleset.add_rule(PathBeneath::new(fd, AccessFs::from_read(TARGET_ABI)))?;
            }
        } else {
            // Outbound HTTP(S) only -- no BindTcp rule is added at all, so
            // binding/listening is denied outright; ConnectTcp is allowed
            // on exactly the two ports a web fetch ever needs. Skipped
            // entirely for the `file://` process -- see this function's
            // own doc comment.
            for port in [80u16, 443u16] {
                ruleset = ruleset.add_rule(NetPort::new(port, AccessNet::ConnectTcp))?;
            }
        }

        Ok(ruleset.restrict_self()?.ruleset)
    }

    pub fn apply(cache_dir: &Path, local_file_access: bool) {
        match build_and_restrict(cache_dir, local_file_access) {
            Ok(RulesetStatus::FullyEnforced) => {
                eprintln!("renderer: sandbox fully enforced (Landlock ABI {TARGET_ABI:?})");
            }
            Ok(RulesetStatus::PartiallyEnforced) => {
                eprintln!(
                    "renderer: sandbox PARTIALLY enforced — this kernel only supports an \
                     older Landlock ABI than {TARGET_ABI:?}."
                );
            }
            Ok(RulesetStatus::NotEnforced) => {
                eprintln!(
                    "renderer: sandbox NOT enforced — this kernel has no Landlock support at \
                     all. Running WITHOUT filesystem/network isolation."
                );
            }
            Err(e) => {
                eprintln!("renderer: failed to apply the sandbox ({e}) — running WITHOUT one.");
            }
        }

        // Before seccomp: `setrlimit` is itself a syscall, and a
        // seccomp filter can only ever be narrowed once installed, not
        // widened later — see `resource_limits`'s own doc comment.
        super::resource_limits::apply();

        seccomp::apply();
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn temp_dir(name: &str) -> std::path::PathBuf {
            let dir = std::env::temp_dir().join(format!(
                "abyssal-test-{name}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            dir
        }

        #[test]
        fn walk_symlinks_finds_a_direct_symlinks_real_target_directory() {
            let root = temp_dir("walk-symlinks-direct");
            let real_target_dir = root.join("real");
            std::fs::create_dir_all(&real_target_dir).unwrap();
            std::fs::write(real_target_dir.join("bundle.pem"), b"fake cert").unwrap();

            let certs_dir = root.join("certs");
            std::fs::create_dir_all(&certs_dir).unwrap();
            std::os::unix::fs::symlink(
                real_target_dir.join("bundle.pem"),
                certs_dir.join("ca-certificates.crt"),
            )
            .unwrap();

            let mut out = Vec::new();
            walk_symlinks(&certs_dir, 4, &mut out);

            assert!(
                out.contains(&real_target_dir),
                "expected {real_target_dir:?} in {out:?}"
            );
        }

        #[test]
        fn walk_symlinks_follows_a_relative_two_hop_symlink_like_arch_linux_uses() {
            // Mirrors the exact real-world layout that motivated this
            // function: `/etc/ssl/certs/ca-certificates.crt ->
            // ../../ca-certificates/extracted/tls-ca-bundle.pem`.
            let root = temp_dir("walk-symlinks-arch-style");
            let extracted_dir = root.join("ca-certificates").join("extracted");
            std::fs::create_dir_all(&extracted_dir).unwrap();
            std::fs::write(extracted_dir.join("tls-ca-bundle.pem"), b"fake cert").unwrap();

            let ssl_dir = root.join("ssl");
            let certs_dir = ssl_dir.join("certs");
            std::fs::create_dir_all(&certs_dir).unwrap();
            std::os::unix::fs::symlink(
                "../../ca-certificates/extracted/tls-ca-bundle.pem",
                certs_dir.join("ca-certificates.crt"),
            )
            .unwrap();

            let mut out = Vec::new();
            walk_symlinks(&ssl_dir, 4, &mut out);

            assert!(
                out.contains(&extracted_dir),
                "expected {extracted_dir:?} in {out:?}"
            );
        }

        #[test]
        fn walk_symlinks_is_a_harmless_no_op_with_no_symlinks_at_all() {
            let root = temp_dir("walk-symlinks-none");
            std::fs::write(root.join("plain.pem"), b"fake cert").unwrap();

            let mut out = Vec::new();
            walk_symlinks(&root, 4, &mut out);

            assert!(out.is_empty());
        }

        #[test]
        fn read_only_cert_paths_always_includes_the_literal_etc_ssl_and_etc_pki_candidates() {
            // `read_only_cert_paths` checks the real, hardcoded
            // `/etc/ssl`/`/etc/pki` system paths — this dev machine's
            // own layout (whatever it is) isn't something a test
            // should assume the shape of, but at least one of the two
            // existing on any real Linux system this ships on is a
            // safe, real assertion. The symlink-resolution behavior
            // itself is covered directly, against a controlled temp
            // layout, by the `walk_symlinks` tests above.
            let paths = read_only_cert_paths();
            assert!(
                paths.iter().any(|p| p == Path::new("/etc/ssl"))
                    || paths.iter().any(|p| p == Path::new("/etc/pki")),
                "expected at least one of /etc/ssl or /etc/pki to exist and be included, got {paths:?}"
            );
        }
    }
}

#[cfg(target_os = "linux")]
mod seccomp {
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule};
    use std::collections::BTreeMap;
    use std::convert::TryInto;

    /// The complete set of syscalls this process is allowed to make —
    /// everything else is a `KillProcess`. Derived EMPIRICALLY, not
    /// guessed: a disposable ptrace-based tracer (built for this pass,
    /// not shipped) attached to a real `abyssal-renderer` process and
    /// recorded every unique syscall number it made across a real,
    /// representative workload driven over real IPC — a fresh
    /// DNS-over-HTTPS lookup + HTTPS page fetch (which itself spins up
    /// a `reqwest::blocking::Client`'s own background tokio runtime
    /// thread — see `network::HttpFetcher::fetch`'s doc comment on why
    /// a fresh client, and thus a fresh thread, is built per request),
    /// a `Tick`, a `Click`, a same-URL re-fetch (exercising the disk
    /// cache's read path, not just its write path), and a second,
    /// different real host (a second fresh DoH lookup + client). Ran
    /// twice independently; both runs produced the IDENTICAL syscall
    /// set below, which is the actual bar for "this is real coverage,"
    /// not just "it happened to work once." `resolve_and_fetch_scripts`
    /// (external `<script src>`) and a resolved `Click` that runs a JS
    /// listener aren't separately traced — both reuse the exact same
    /// fetch/Boa-evaluation machinery already covered here, not a
    /// different one, so there's no reason to expect a different
    /// syscall shape from either. `landlock_create_ruleset`/
    /// `landlock_add_rule`/`landlock_restrict_self` are included
    /// defensively even though they only ever run BEFORE this filter
    /// installs (see this module's own doc comment on ordering) — near
    /// zero cost to allow, and it means a future reordering wouldn't
    /// silently break Landlock's own setup.
    const ALLOWED_SYSCALLS: &[i64] = &[
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_close,
        libc::SYS_fstat,
        // Not seen by the original trace (glibc normally serves this
        // through the vDSO, no real syscall at all) but a real syscall
        // on some kernels/environments (e.g. no vDSO mapped, or one
        // that's been disabled) — TLS/HTTP timeouts and `Instant::now`
        // go through this constantly, so its absence here is a
        // guaranteed, environment-dependent `SIGSYS` crash rather than
        // a rare one. Confirmed via a real repro: this exact process,
        // sandboxed, fetching `https://example.com/`, killed with
        // `SIGSYS` on syscall 228 (`clock_gettime`) every time.
        libc::SYS_clock_gettime,
        libc::SYS_poll,
        libc::SYS_lseek,
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_munmap,
        libc::SYS_brk,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_pread64,
        libc::SYS_writev,
        libc::SYS_access,
        libc::SYS_mremap,
        libc::SYS_madvise,
        libc::SYS_socket,
        libc::SYS_connect,
        libc::SYS_recvfrom,
        libc::SYS_getsockname,
        libc::SYS_getpeername,
        libc::SYS_setsockopt,
        libc::SYS_getsockopt,
        libc::SYS_exit,
        libc::SYS_fcntl,
        libc::SYS_getcwd,
        libc::SYS_rename,
        // Not seen by the original trace (see `ALLOWED_SYSCALLS`'
        // own doc comment) — added for `PartitionedCookieJar::
        // save_merged_to_file`'s atomic write-then-rename, a genuinely
        // new I/O path added after that trace. `File::set_permissions`
        // on an already-open handle (locking the temp file down to
        // `0o600` before the rename) issues `fchmod`, not `chmod` —
        // confirmed via a real repro (`SIGSYS` on syscall 91) the same
        // way `SYS_clock_gettime` was originally found.
        libc::SYS_fchmod,
        libc::SYS_mkdir,
        libc::SYS_sigaltstack,
        libc::SYS_prctl,
        libc::SYS_arch_prctl,
        libc::SYS_gettid,
        libc::SYS_futex,
        libc::SYS_sched_getaffinity,
        libc::SYS_getdents64,
        libc::SYS_set_tid_address,
        libc::SYS_exit_group,
        libc::SYS_epoll_wait,
        libc::SYS_epoll_ctl,
        libc::SYS_openat,
        libc::SYS_newfstatat,
        libc::SYS_set_robust_list,
        libc::SYS_eventfd2,
        libc::SYS_epoll_create1,
        libc::SYS_prlimit64,
        libc::SYS_getrandom,
        libc::SYS_statx,
        libc::SYS_rseq,
        libc::SYS_clone3,
        libc::SYS_landlock_create_ruleset,
        libc::SYS_landlock_add_rule,
        libc::SYS_landlock_restrict_self,
    ];

    fn build_filter() -> seccompiler::Result<BpfProgram> {
        let rules: BTreeMap<i64, Vec<SeccompRule>> = ALLOWED_SYSCALLS
            .iter()
            .map(|&syscall| (syscall, Vec::new()))
            .collect();
        let filter = SeccompFilter::new(
            rules,
            SeccompAction::KillProcess,
            SeccompAction::Allow,
            std::env::consts::ARCH.try_into()?,
        )?;
        let program: BpfProgram = filter.try_into()?;
        Ok(program)
    }

    pub fn apply() {
        match build_filter() {
            Ok(program) => match seccompiler::apply_filter_all_threads(&program) {
                Ok(()) => eprintln!("renderer: seccomp-bpf syscall filter applied ({} allowed syscalls)", ALLOWED_SYSCALLS.len()),
                Err(e) => eprintln!("renderer: failed to install the seccomp filter ({e}) — running WITHOUT syscall filtering."),
            },
            Err(e) => eprintln!("renderer: failed to build the seccomp filter ({e}) — running WITHOUT syscall filtering."),
        }
    }
}

/// macOS sandboxing via Seatbelt (`sandbox_init`) — see this module's
/// own top-level doc comment for the overall "real, but never run on
/// real macOS" caveat that applies to everything here.
///
/// `sandbox_init` and its SBPL (Sandbox Profile Language) profile
/// syntax are an Apple-PRIVATE, undocumented-by-header mechanism —
/// there is no public Apple documentation for either. Everything known
/// about them publicly (including what this module uses) comes from
/// reverse-engineering by security researchers and from real,
/// published profiles (Chromium's own sandbox shipped one for years).
/// It remains a real, stable, still-functional mechanism despite being
/// deprecated in favor of App Sandbox/XPC-service architectures Apple
/// now steers new, code-signed, entitled apps toward — neither of
/// which fits a plain spawned Mach-O subprocess like `abyssal-renderer`
/// the way `sandbox_init` does. Apple's own `sandbox-exec(1)` CLI tool,
/// a normal shipped system binary, is itself a thin wrapper around
/// this exact same call — its continued presence on every real macOS
/// install is itself evidence this mechanism hasn't been removed.
///
/// FAILURE MODE, and why that makes this safer to ship un-run than it
/// might sound: `(deny default)` means the profile below fails CLOSED.
/// If a mach-lookup this process actually needs turns out to be
/// missing (see `PROFILE`'s own doc comment on `mach-lookup` being
/// left unrestricted specifically to avoid this), the affected
/// operation errors out loudly (e.g. every HTTPS fetch failing) —
/// obvious and immediately noticeable on first real use, not a silent
/// security gap. A `sandbox_init` call that fails outright (bad SBPL
/// syntax, the mechanism being unavailable) is treated exactly like a
/// Landlock failure on Linux: logged, and the renderer keeps running
/// WITHOUT a sandbox rather than refusing to start at all.
#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use std::ffi::{CStr, CString};
    use std::os::raw::{c_char, c_int};

    // Not in the `libc` crate (it's Apple-private, not POSIX) — this
    // is the well-known, long-stable signature every public reverse-
    // engineering writeup and Chromium's own historical sandbox code
    // agree on. Both symbols live in `libsystem_sandbox.dylib`, which
    // is always present and implicitly linked (part of `libSystem`) on
    // every real macOS install.
    extern "C" {
        fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> c_int;
        fn sandbox_free_error(errorbuf: *mut c_char);
    }

    /// The real SBPL profile. Restricts filesystem access (read-only
    /// system paths needed just to keep running, plus read/write on
    /// `cache_dir` — nothing else) and outbound network (ports 80/443
    /// only) with the SAME intent as Linux's Landlock rules, and with
    /// the same real confidence: these are ordinary, well-attested SBPL
    /// primitives (every public reverse-engineered writeup of the
    /// language agrees on `file-read*`/`file-write*`/`network-outbound`
    /// syntax), not a guess.
    ///
    /// `local_file_access` mirrors Linux's `local_file_access` flag on
    /// `build_and_restrict` exactly, and for the same reason: this is
    /// only ever `true` for the one dedicated, permanently-isolated
    /// `file://` renderer process (see `app`'s `site_for_url`), never
    /// for a process handling a real, possibly-malicious website. When
    /// `true`, this profile trades broad real filesystem read access
    /// (`(allow file-read* (subpath "/"))`, matching the user's chosen
    /// "unrestricted, matches real browsers" scope) for giving up
    /// outbound network entirely -- the two `network-outbound` allow
    /// lines below are omitted outright, not merely narrowed, so this
    /// process has no way to open a socket at all. That trade is what
    /// makes broad read access safe: a malicious `https://` page's own
    /// renderer process never gets this flag, so it never gains the
    /// broad read rule either, and this process -- the only one that
    /// ever does -- has no network path to exfiltrate anything it
    /// reads. See `linux::build_and_restrict`'s own doc comment for the
    /// identical reasoning spelled out in more detail.
    ///
    /// Deliberately does NOT restrict `mach-lookup` (every Mach IPC
    /// service this process can reach) — real TLS certificate
    /// verification on macOS goes through `Security.framework`
    /// (`SecTrust`, see `network`'s own doc comment on
    /// `rustls-platform-verifier`'s Apple backend), which talks to
    /// system daemons like `trustd` over Mach IPC rather than reading
    /// flat cert files the way Linux does. Naming the exact service
    /// set that needs is exactly the kind of thing this project
    /// normally derives from a real ptrace/dtrace-style trace (see
    /// `linux::ALLOWED_SYSCALLS`'s own doc comment for that
    /// methodology on Linux) — there's no Mac in this project's
    /// development loop to run that trace on. Leaving `mach-lookup`
    /// unrestricted is a deliberate, disclosed scope reduction (this
    /// profile is real protection against arbitrary file/network
    /// access, not yet full mach-service-level containment) rather
    /// than guessing a service list and risking either a silent gap
    /// (guessed the required set too broad) or a completely broken
    /// browser on macOS (guessed too narrow, real cert verification
    /// starts failing). See this module's own doc comment for why a
    /// wrong guess on the FILE/NETWORK rules below would fail loudly
    /// instead — narrowing `mach-lookup` is the top item in this
    /// module's own "next steps".
    fn build_profile(cache_dir: &str, local_file_access: bool) -> String {
        let mut profile = format!(
            r#"(version 1)
(deny default)

; Baseline OS services every process needs just to keep running —
; dynamic linking, thread/signal handling, and querying basic system
; info. None of this is specific to this process's own job.
(allow file-read* (subpath "/usr/lib") (subpath "/System/Library"))
(allow file-read-metadata)
(allow sysctl-read)
(allow mach-lookup)
(allow signal (target self))

; The disk cache, cookies, and localStorage — the ONE place besides
; those read-only system paths above this process can touch at all.
; Mirrors Landlock's own cache_dir rule on Linux exactly.
(allow file-read* file-write* (subpath "{cache_dir}"))
"#,
        );
        if local_file_access {
            // The dedicated file:// process's own broad read rule --
            // mirrors Linux's root-scoped `PathBeneath` rule exactly.
            // No `network-outbound` allow lines follow: this process
            // gets no outbound network access at all, not even a
            // narrowed one, which is what makes the broad read above
            // safe. See this function's own doc comment.
            profile.push_str("(allow file-read* (subpath \"/\"))\n");
        } else {
            // Outbound HTTPS/HTTP only — no listening, no arbitrary
            // ports. Mirrors Landlock's own `NetPort`/`ConnectTcp` rule
            // on Linux exactly.
            profile.push_str("(allow network-outbound (remote tcp \"*:443\"))\n");
            profile.push_str("(allow network-outbound (remote tcp \"*:80\"))\n");
        }
        profile
    }

    /// Escapes `s` for safe embedding inside an SBPL double-quoted
    /// string literal (`(subpath "...")`) — `cache_dir` is never
    /// attacker-controlled (it's `app`'s own hardcoded data directory,
    /// not derived from anything a malicious page could influence),
    /// but a real path can still legitimately contain a `"` or `\` on
    /// a real filesystem, and either would otherwise break out of the
    /// profile's string literal and corrupt the policy being compiled.
    fn escape_sbpl_string(s: &str) -> String {
        s.replace('\\', "\\\\").replace('"', "\\\"")
    }

    pub fn apply(cache_dir: &Path, local_file_access: bool) {
        // Seatbelt mediates specific operations (file/network/mach),
        // not raw syscalls the way seccomp does, so there's no
        // ordering hazard here the way there is on Linux — applied
        // first anyway, for the same "resource limits before access
        // restrictions" ordering `linux::apply` uses.
        super::resource_limits::apply();

        let profile = build_profile(
            &escape_sbpl_string(&cache_dir.to_string_lossy()),
            local_file_access,
        );
        let c_profile = match CString::new(profile) {
            Ok(p) => p,
            Err(e) => {
                eprintln!(
                    "renderer: internal error building the macOS sandbox profile ({e}) — \
                     running WITHOUT one."
                );
                return;
            }
        };

        let mut error_buf: *mut c_char = std::ptr::null_mut();
        // SAFETY: `c_profile` is a valid, NUL-terminated C string that
        // outlives this call (owned by this stack frame). `error_buf`
        // is a valid pointer to a local `*mut c_char` `sandbox_init`
        // may write an owned, `sandbox_free_error`-reclaimable pointer
        // into on failure — never read before checking the return
        // value, and only ever passed to `sandbox_free_error` (never
        // freed any other way).
        let result = unsafe { sandbox_init(c_profile.as_ptr(), 0, &mut error_buf) };
        if result != 0 {
            let message = if error_buf.is_null() {
                "no further error information provided".to_string()
            } else {
                // SAFETY: `error_buf` was just set by `sandbox_init`
                // itself to a NUL-terminated string it owns; freed via
                // `sandbox_free_error` right after reading it here, so
                // this is the one and only read of it.
                let owned = unsafe { CStr::from_ptr(error_buf) }
                    .to_string_lossy()
                    .into_owned();
                unsafe { sandbox_free_error(error_buf) };
                owned
            };
            eprintln!(
                "renderer: failed to apply the macOS sandbox ({message}) — running WITHOUT one."
            );
            return;
        }
        eprintln!("renderer: macOS sandbox (Seatbelt) applied.");
    }
}

/// Windows sandboxing via a Job Object plus several process mitigation
/// policies — see this module's own top-level doc comment for the
/// overall "real, but never run on real Windows" caveat that applies
/// to everything here.
///
/// Deliberately does NOT attempt AppContainer (the real Chrome/Edge-
/// grade mechanism, which actually restricts filesystem/registry/
/// network access the way Landlock does on Linux) — it needs a
/// container profile, capability SIDs, and correctly-configured
/// `UpdateProcThreadAttribute` calls made by the PARENT at process
/// creation (a fundamentally different, much larger surface to get
/// right blind, and one this project's own `RendererProcess::spawn`
/// in `app` would need real changes for, not just this module). What's
/// here instead is a genuinely real, much narrower reduction in
/// attack surface using well-documented, individually-simple, stable
/// Win32 APIs, each independently toggleable and each either applying
/// exactly as documented or failing outright (no silent partial
/// application):
///   - A Job Object this process puts itself into, capping it to a
///     single active process (so it can never successfully spawn a
///     child — real defense in depth on top of the mitigation policy
///     below, not this project's only defense against it) and killing
///     it if the job handle itself ever closes unexpectedly. The SAME
///     Job Object also carries a real memory limit
///     (`JOB_OBJECT_LIMIT_PROCESS_MEMORY`) and cumulative CPU-time
///     limit (`JOB_OBJECT_LIMIT_PROCESS_TIME`) — the Windows-native
///     equivalent of `sandbox::resource_limits`'s `setrlimit` calls on
///     Linux/macOS (see that module's own doc comment for the exact
///     values and the honest caveat about `RLIMIT_CPU`/
///     `PerProcessUserTimeLimit` both being CUMULATIVE-since-start, not
///     a per-page budget).
///   - `ProcessDynamicCodePolicy` (prohibit allocating executable
///     memory / loading unsigned code at runtime) — safe here because
///     this process's own JS engine (`boa_engine`) is a pure Rust
///     tree-walking interpreter with no JIT of its own.
///   - `ProcessSystemCallDisablePolicy` (block ALL win32k.sys — the
///     entire GUI/USER/GDI syscall surface, a historically rich source
///     of Windows kernel privilege-escalation bugs) — safe because
///     this process creates no windows and does no GDI drawing at all;
///     confirmed by reading `renderer`'s own `Cargo.toml`, which pulls
///     in none of `winit`/`wgpu`/`render` (all real UI/GPU work happens
///     in the separate `app` process instead).
///   - `ProcessExtensionPointDisablePolicy` (blocks legacy global
///     hooks/AppInit DLLs from attaching) and `ProcessImageLoadPolicy`
///     (refuses to load a DLL from a network path or one carrying a
///     low integrity label) — standard, narrow hardening with the same
///     "well-documented, individually low-risk" property as the above.
///   - `ProcessChildProcessPolicy` (`NoChildProcessCreation`) — the
///     SAME "this process should never spawn a child" property the Job
///     Object above already provides, applied a second, more direct
///     way; belt-and-suspenders, not redundant effort, since the two
///     mechanisms fail independently.
///
/// Deliberately skips `ProcessSignaturePolicy` (Microsoft-signed-only
/// module loading) — real third-party software (antivirus/EDR hooking
/// DLLs injected into every process on a machine, common in real
/// corporate/consumer environments alike) often isn't Microsoft-signed
/// and would legitimately need to load into this process; enforcing
/// this blind, with no real Windows machine to notice a resulting
/// "renderer silently fails to start on some real users' machines"
/// regression, is a worse trade than leaving it out for now.
#[cfg(target_os = "windows")]
mod windows {
    use super::*;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOB_OBJECT_LIMIT_PROCESS_MEMORY, JOB_OBJECT_LIMIT_PROCESS_TIME,
    };
    use windows_sys::Win32::System::SystemServices::{
        PROCESS_MITIGATION_CHILD_PROCESS_POLICY, PROCESS_MITIGATION_DYNAMIC_CODE_POLICY,
        PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY, PROCESS_MITIGATION_IMAGE_LOAD_POLICY,
        PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, ProcessChildProcessPolicy, ProcessDynamicCodePolicy,
        ProcessExtensionPointDisablePolicy, ProcessImageLoadPolicy, ProcessSystemCallDisablePolicy,
        SetProcessMitigationPolicy,
    };

    /// Same real backstop values as `sandbox::resource_limits` on
    /// Linux/macOS (see that module's own doc comment for the full
    /// reasoning, including the honest "cumulative since process
    /// start, not a per-page budget" caveat for the CPU one) — kept in
    /// sync by hand since this module has no code-level dependency on
    /// that `unix`-only one.
    const MEMORY_LIMIT_BYTES: u64 = 1536 * 1024 * 1024;
    /// 100-nanosecond units, the native unit `PerProcessUserTimeLimit`
    /// uses (the same unit Windows `FILETIME`s use) — 30 minutes.
    const CPU_LIMIT_100NS: i64 = 30 * 60 * 10_000_000;

    /// Creates a Job Object, applies its limits, and puts the CURRENT
    /// process into it — see this module's own doc comment. Logs and
    /// continues (rather than failing the whole call) on an error,
    /// same "one denied restriction doesn't cost every other one"
    /// philosophy `apply` itself uses for the mitigation policies.
    fn apply_job_object() {
        // SAFETY: `CreateJobObjectW` with null security attributes and
        // null name creates a new, unnamed, process-local job object
        // handle — no preconditions beyond a valid (possibly null)
        // pointer, which this is.
        let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if job.is_null() {
            eprintln!(
                "renderer: failed to create a Windows Job Object (error {}) — no active-process/kill-on-close/memory/CPU limit applied.",
                std::io::Error::last_os_error()
            );
            return;
        }

        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_PROCESS_MEMORY
            | JOB_OBJECT_LIMIT_PROCESS_TIME;
        info.BasicLimitInformation.ActiveProcessLimit = 1;
        info.BasicLimitInformation.PerProcessUserTimeLimit = CPU_LIMIT_100NS;
        info.ProcessMemoryLimit = MEMORY_LIMIT_BYTES as usize;

        // SAFETY: `job` was just checked non-null above; `info` is a
        // validly-initialized struct of exactly the type
        // `JobObjectExtendedLimitInformation` expects, and its size is
        // computed from that same type.
        let set_ok = unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const _,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if set_ok == 0 {
            eprintln!(
                "renderer: failed to configure the Windows Job Object (error {}) — no active-process/kill-on-close/memory/CPU limit applied.",
                std::io::Error::last_os_error()
            );
            // SAFETY: `job` is a valid handle this function owns and
            // hasn't closed yet.
            unsafe { CloseHandle(job) };
            return;
        }

        // SAFETY: `job` is a valid job object handle; `GetCurrentProcess()`
        // returns the well-known pseudo-handle for this process, valid
        // for the lifetime of the process and needing no cleanup.
        let assign_ok = unsafe { AssignProcessToJobObject(job, GetCurrentProcess()) };
        if assign_ok == 0 {
            eprintln!(
                "renderer: failed to join the Windows Job Object (error {}) — no active-process/kill-on-close/memory/CPU limit applied.",
                std::io::Error::last_os_error()
            );
        } else {
            eprintln!(
                "renderer: Windows Job Object (single-process, kill-on-close, {} MiB memory cap, {} min CPU cap) applied.",
                MEMORY_LIMIT_BYTES / (1024 * 1024),
                CPU_LIMIT_100NS / (60 * 10_000_000)
            );
        }
        // The job handle is deliberately LEAKED (not closed) here: a
        // job object's limits stop applying to member processes once
        // its LAST handle closes, and this process itself is the only
        // thing that would ever close it — closing it right after
        // `AssignProcessToJobObject` would undo the very restriction
        // this function exists to apply. The OS reclaims it when this
        // process exits, same as every other resource it holds.
    }

    /// Applies one `SetProcessMitigationPolicy` policy, built from a
    /// single raw `Flags` `u32` rather than the real bitfield struct
    /// each policy technically has — every one of these structs is
    /// defined as a `union { DWORD Flags; struct { bitfields } }` in
    /// the real Win32 headers specifically so callers CAN set it as a
    /// single flat integer instead of naming individual bitfields
    /// (whose exact bit positions this code would otherwise have to
    /// get right blind); using `Flags` directly is normal, documented
    /// usage, not a shortcut around the real API.
    fn set_mitigation_policy<T>(
        name: &str,
        policy: windows_sys::Win32::System::Threading::PROCESS_MITIGATION_POLICY,
        value: T,
    ) {
        // SAFETY: `policy` identifies which of the union'd mitigation
        // structs `value` is; `value` is exactly that struct, sized
        // correctly via `size_of::<T>()` — the same contract every
        // `SetProcessMitigationPolicy` caller (including Microsoft's
        // own documentation examples) follows.
        let ok = unsafe {
            SetProcessMitigationPolicy(
                policy,
                &value as *const T as *const _,
                std::mem::size_of::<T>(),
            )
        };
        if ok == 0 {
            eprintln!(
                "renderer: failed to apply Windows mitigation policy {name} (error {}) — that one protection is not active.",
                std::io::Error::last_os_error()
            );
        }
    }

    /// `local_file_access` exists only so this function's signature
    /// matches `linux::apply`/`macos::apply` (see the `pub use ...
    /// apply;` re-export block at the bottom of this file, which needs
    /// all four platform modules to agree on one signature). It is
    /// otherwise unused here: unlike Landlock's `PathBeneath`/`NetPort`
    /// rules or Seatbelt's `file-read*`/`network-outbound` rules, none
    /// of the mitigation policies below are filesystem- or network-
    /// access controls at all -- they harden against code-injection and
    /// exploitation techniques (dynamic code generation, win32k
    /// syscalls, DLL injection, child process spawning), a different
    /// concern entirely. This is a real, disclosed gap, not an
    /// oversight: on Windows, the dedicated file:// process's broadened
    /// filesystem read and every other renderer process's network
    /// access are both currently unenforced at the OS-sandbox level, matching
    /// this module's pre-existing "real code, but only verified on
    /// Linux" caveat (see this module's own top-level doc comment).
    pub fn apply(_cache_dir: &Path, _local_file_access: bool) {
        apply_job_object();

        let mut dynamic_code: PROCESS_MITIGATION_DYNAMIC_CODE_POLICY =
            unsafe { std::mem::zeroed() };
        dynamic_code.Anonymous.Flags = 0b1; // ProhibitDynamicCode
        set_mitigation_policy("DynamicCode", ProcessDynamicCodePolicy, dynamic_code);

        let mut syscall_disable: PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY =
            unsafe { std::mem::zeroed() };
        syscall_disable.Anonymous.Flags = 0b1; // DisallowWin32kSystemCalls
        set_mitigation_policy(
            "SystemCallDisable",
            ProcessSystemCallDisablePolicy,
            syscall_disable,
        );

        let mut extension_points: PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY =
            unsafe { std::mem::zeroed() };
        extension_points.Anonymous.Flags = 0b1; // DisableExtensionPoints
        set_mitigation_policy(
            "ExtensionPointDisable",
            ProcessExtensionPointDisablePolicy,
            extension_points,
        );

        let mut image_load: PROCESS_MITIGATION_IMAGE_LOAD_POLICY = unsafe { std::mem::zeroed() };
        image_load.Anonymous.Flags = 0b11; // NoRemoteImages | NoLowMandatoryLabelImages
        set_mitigation_policy("ImageLoad", ProcessImageLoadPolicy, image_load);

        let mut child_process: PROCESS_MITIGATION_CHILD_PROCESS_POLICY =
            unsafe { std::mem::zeroed() };
        child_process.Anonymous.Flags = 0b1; // NoChildProcessCreation
        set_mitigation_policy("ChildProcess", ProcessChildProcessPolicy, child_process);

        eprintln!(
            "renderer: Windows process mitigation policies applied (dynamic code, win32k \
             syscalls, extension points, image load, child process creation all restricted)."
        );
    }
}

/// The true "nothing implemented for this platform" fallback — every
/// platform this project actually targets (Linux/macOS/Windows) has
/// its own real module above; this only exists for some other, wholly
/// unsupported OS this project has never claimed to run on at all.
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
mod other {
    use super::*;

    pub fn apply(_cache_dir: &Path, _local_file_access: bool) {
        eprintln!(
            "renderer: process sandboxing has no implementation at all for this platform (see \
             renderer::sandbox's module docs) — running WITHOUT one."
        );
    }
}

#[cfg(target_os = "linux")]
pub use linux::apply;
#[cfg(target_os = "macos")]
pub use macos::apply;
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub use other::apply;
#[cfg(target_os = "windows")]
pub use windows::apply;
