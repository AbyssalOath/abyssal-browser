//! Embeds `assets/icon.ico` into the Windows `.exe` as its real, native
//! icon resource — the ONLY thing this build script does. Linux's/
//! macOS's own icons come from entirely separate mechanisms (a
//! `.desktop` file + installed icon for Linux, an `.app` bundle's
//! `Info.plist`/`.icns` for macOS — see `packaging/`), neither of
//! which involves compiling anything, so this script has nothing to
//! do on those platforms at all.
//!
//! Uses `winresource` (a maintained `winres` fork) to drive the real
//! platform resource compiler — MSVC's `rc.exe` (auto-located via the
//! Windows Registry) or MinGW's `windres` (via `%PATH%`) — exactly the
//! way `winresource`'s own docs recommend. A failure to embed the icon
//! (resource compiler not found, `assets/icon.ico` missing, ...) is
//! reported as a build WARNING, not a build failure: the icon is
//! purely cosmetic, and refusing to build the whole browser over a
//! missing decoration would be a worse failure mode than a plain
//! window/taskbar icon.
//!
//! Deliberately checks `CARGO_CFG_TARGET_OS` (an env var reflecting
//! the REAL compilation target) rather than relying only on
//! `#[cfg(target_os = "windows")]` (which reflects the HOST rustc
//! compiles this very build script for/runs it on — the two differ
//! when cross-compiling) — matching `winresource`'s own documented
//! usage pattern. The `#[cfg(target_os = "windows")]` gate around the
//! function body is still needed too, separately: it's what makes this
//! file compile at all on a non-Windows HOST, where the `winresource`
//! crate isn't even pulled in as a dependency (see this crate's own
//! Cargo.toml — it's listed under `[target.'cfg(windows)'.build-dependencies]`).
//! Net effect: this only actually embeds an icon when building
//! NATIVELY on Windows (host == target) — the workflow this project's
//! own packaging docs assume; cross-compiling a Windows binary from a
//! different host would need a real fix to this file, not just a
//! different invocation.

fn main() {
    #[cfg(target_os = "windows")]
    embed_windows_icon();
}

#[cfg(target_os = "windows")]
fn embed_windows_icon() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let mut resource = winresource::WindowsResource::new();
    resource.set_icon("assets/icon.ico");
    if let Err(e) = resource.compile() {
        println!("cargo:warning=could not embed the Windows icon resource: {e}");
    }
}
