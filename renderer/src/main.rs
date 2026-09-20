//! The renderer binary's entry point. Deliberately thin — all the real
//! logic lives in `renderer`'s `lib.rs` (testable without a real
//! subprocess/pipes) and `sandbox.rs`; this just wires stdin/stdout to
//! `renderer::serve` after applying the sandbox.
//!
//! Usage: `abyssal-renderer <cache-dir> [--allow-local-files]` --
//! spawned by `app`, never run directly by a user. `<cache-dir>` is the
//! one filesystem location this process is allowed to read/write (see
//! `sandbox::apply`); `app` passes its own `CACHE_DIR` constant here.
//! `--allow-local-files`, when present, is what makes this the ONE
//! dedicated `file://` process (see `app`'s `site_for_url`): it both
//! grants the sandbox broad real filesystem read access AND removes
//! this process's own outbound network access entirely (see
//! `sandbox::apply`'s own doc comments for why those two changes are
//! made together, never one without the other), and separately opts
//! `FilteringFetcher` itself into serving `file://` fetches at all
//! (`enable_local_file_access` below). `app` never passes this flag
//! when spawning a renderer for a real website.

fn main() {
    let mut args = std::env::args().skip(1);
    let cache_dir = args.next().unwrap_or_else(|| {
        eprintln!("usage: abyssal-renderer <cache-dir> [--allow-local-files]");
        std::process::exit(2);
    });
    let allow_local_files = args.next().as_deref() == Some("--allow-local-files");
    let cache_dir = std::path::PathBuf::from(cache_dir);
    if let Err(e) = std::fs::create_dir_all(&cache_dir) {
        eprintln!("renderer: failed to create cache dir {cache_dir:?}: {e} — continuing, the disk cache will fail closed.");
    }

    // Loaded/built from bytes compiled into this binary (`include_bytes!`/
    // `include_str!`) — no runtime file access needed for either, so
    // it's fine (and simplest) to do this before the sandbox goes up,
    // even though neither actually depends on that ordering.
    let font = text::load_default_font();
    let blocklist = privacy::Blocklist::with_seed_list();

    // From here on, this process can only reach the cache directory,
    // read-only system CA certificate paths, and outbound TCP on ports
    // 80/443 — unless `allow_local_files` is set, in which case it's
    // the opposite: broad real filesystem read access and NO network
    // access at all. See sandbox.rs's own module docs for exactly what
    // either mode does and doesn't protect against.
    renderer::sandbox::apply(&cache_dir, allow_local_files);

    let http_fetcher = network::HttpFetcher::new(blocklist.clone());
    let mut fetcher = network::FilteringFetcher::new(http_fetcher, blocklist);
    if allow_local_files {
        fetcher.enable_local_file_access();
    }
    if let Err(e) = fetcher.enable_disk_cache(&cache_dir) {
        eprintln!(
            "renderer: failed to open disk cache at {cache_dir:?}: {e} — continuing without one."
        );
    }

    // Cookies/`localStorage`/IndexedDB are no longer loaded from or
    // written to disk by this process at all — `app` (the privileged
    // process, which holds the account's encryption key this
    // sandboxed process never receives) now owns encrypting and
    // persisting all three, over the SAME IPC channel every other
    // reply already crosses. This process's own copy starts empty and
    // gets seeded from `ipc::RenderRequest::initial_cookies`/
    // `initial_local_storage`/`initial_indexed_db` on the first real
    // `Navigate` `app` sends (see `RendererState::
    // seed_storage_from_request`), and reports any change back via
    // `ipc::ServerMessage::updated_cookies`/`updated_local_storage`/
    // `updated_indexed_db` (see `RendererState::
    // reported_cookies_if_changed` and its two siblings) — see
    // `ipc::ServerMessage`'s own doc comment for the full reasoning.
    let mut state = renderer::RendererState::new(fetcher, font);

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();
    renderer::serve(&mut reader, &mut writer, &mut state);
}
