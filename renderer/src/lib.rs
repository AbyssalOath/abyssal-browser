//! `renderer` — the sandboxed child process that does everything
//! touching UNTRUSTED, attacker-influenced content on `app`'s behalf:
//! the real network fetch (DNS-over-HTTPS + TLS + HTTP, via
//! `network::HttpFetcher`/`FilteringFetcher` — unchanged from before
//! this crate existed), HTML parsing, CSS, layout, and now script
//! execution (see `script`'s module docs). It hands back a fully
//! laid-out `layout::LayoutBox` tree (see `ipc`'s module docs for why
//! layout happens here rather than in `app`) plus the page's title,
//! over a length-prefixed JSON protocol on its own stdin/stdout (see
//! `ipc::{read_message, write_message}`).
//!
//! `app` (the main process) never hands this process the account's
//! recovery code, derived keys, or decrypted bookmarks/settings —
//! there's simply no field in `ipc::RenderRequest` for any of that —
//! and `main.rs` applies `sandbox::apply` (Landlock, Linux-only for
//! now) before the first request is ever read, so even a memory-safety
//! bug triggered by a malicious page can't read the account/bookmarks
//! files on disk or open a connection anywhere but a normal web port.
//! See `sandbox`'s own module docs for exactly what that does and
//! doesn't cover.
//!
//! The `FilteringFetcher` this process builds owns its OWN
//! `PartitionedCookieJar` and disk cache (see `network`'s docs) —
//! `app` never sees either. Both persist to disk now, inside the SAME
//! `cache_dir` this process already has Landlock read/write access to
//! (see `RendererState::enable_cookie_persistence`) — a deliberate,
//! scoped exception to "`app` never sees this," not an oversight: the
//! disk cache holds only already-public fetched web content, and a
//! cookie is exactly as sensitive as the login session it represents,
//! neither of which is the account/bookmark secrets this process is
//! actually barred from (there's still no field in `ipc::RenderRequest`
//! for any of those, and nothing here changes that). Persisting
//! cookies is what makes staying logged into a site survive an idle
//! tab's renderer process being evicted, or the browser restarting —
//! before this, either silently logged you out of everything.

pub mod devtools;
pub mod download;
pub mod images;
pub mod indexed_db;
pub mod local_storage;
pub mod media;
pub mod page_signals;
pub mod pdf;
pub mod sandbox;
pub mod script;
pub mod stylesheets;
pub mod update_check;

use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::rc::Rc;

use network::{Fetcher, FilteringFetcher, PartitionedCookieJar};

/// Fetches and parses a page, running any scripts (inline or, now,
/// external — see `script::resolve_and_fetch_scripts`) it contains,
/// and returns the resulting `script::Session` — a live Boa `Context` +
/// DOM that `RendererState` keeps around afterward, addressed by the
/// tab that requested it (see `ipc`'s module docs on why sessions now
/// persist rather than being one-shot). Doesn't lay out or extract a
/// title itself; `RendererState::handle_message` does that from the
/// returned `Session` so the SAME code path (`Session::relayout`) is
/// used for both a fresh `Navigate` and a later `Tick`.
///
/// `fetcher` is shared (`Rc<RefCell<..>>`), not owned outright, because
/// the `Session` this returns needs its OWN long-lived handle to the
/// SAME fetcher — see `script`'s module docs on `fetch()` — so a
/// page's script can keep making real, blocklist-checked requests long
/// after this function returns, through the exact same cookie jar/
/// disk cache every other request on this tab uses. Each individual
/// borrow here (one per call below) is scoped to a single statement —
/// see those calls' own inline comments — specifically so it's
/// released before `Session::new` runs the page's initial scripts,
/// which might themselves call `fetch()` and need to borrow this same
/// `RefCell` again.
fn navigate<F: Fetcher + Clone + Send + 'static>(
    request: &ipc::RenderRequest,
    fetcher: &Rc<RefCell<FilteringFetcher<F>>>,
    local_storage: &Rc<RefCell<local_storage::LocalStorageStore>>,
    indexed_db: &Rc<RefCell<indexed_db::IndexedDbStore>>,
) -> Result<script::Session, String> {
    let response = fetcher
        .borrow_mut()
        .fetch_in_context_with_body(
            &request.url,
            request.top_level_host.as_deref(),
            request.body.as_deref(),
        )
        .map_err(|e| format!("{e:?}"))?;

    let theme = css::Theme::parse(&request.theme).unwrap_or_default();

    // A real PDF is detected from the fetched bytes themselves (see
    // `pdf::looks_like_pdf`'s own doc comment on why, not any URL
    // suffix or header) and takes a completely separate path: a
    // synthetic, script-free, stylesheet-free, image-free document
    // built from the PDF's own real extracted text — see `pdf`'s
    // module docs for the full "reader mode, not real rendering"
    // story. Userscripts are the ONE thing still applied uniformly to
    // every navigation, PDFs included — see `ipc::RenderRequest::
    // user_scripts`'s own doc comment.
    if pdf::looks_like_pdf(&response.body) {
        let document = pdf::build_document(&response.body)?;
        return Ok(script::Session::new_with_shared_storage(
            document,
            &request.user_scripts,
            request.canvas_width,
            theme,
            HashMap::new(),
            HashMap::new(),
            Rc::clone(fetcher),
            request.url.clone(),
            HashMap::new(),
            HashMap::new(),
            Rc::clone(local_storage),
            Rc::clone(indexed_db),
        ));
    }

    // Lossy, not `Result`-returning: a malformed/mislabeled page body
    // should degrade to replacement characters, not fail the whole
    // navigation outright — `response.body` is raw bytes now (see
    // `network::Response`'s doc comment) since this same fetch path
    // also carries real image bytes.
    let document = html::parse(&String::from_utf8_lossy(&response.body));

    // Scripts run BEFORE the caller lays anything out, so that a
    // script mutating `document.title` or an element's
    // `textContent`/`classList` during the initial pass is reflected
    // in what `app` actually receives — see `script`'s module docs
    // for exactly what that execution model does and doesn't cover.
    let scripts = script::extract_scripts(&document);
    let mut sources =
        script::resolve_and_fetch_scripts(&scripts, &request.url, &mut fetcher.borrow_mut());
    // Userscripts run AFTER the page's own scripts — see
    // `ipc::RenderRequest::user_scripts`'s own doc comment on why
    // that's the only timing this crate supports, and why `app` (not
    // this sandboxed process) is what already filtered these down to
    // the ones that actually apply here.
    sources.extend(request.user_scripts.iter().cloned());

    // Images don't depend on script execution at all (this DOM surface
    // has no `createElement`/`appendChild` from script — see `script`'s
    // own module docs — so the set of `<img>` elements is fixed once
    // parsing is done), but extracting them AFTER scripts run costs
    // nothing and keeps this function's own ordering simple to reason
    // about top to bottom.
    let image_sources = images::extract_image_sources(&document);
    let decoded_images =
        images::resolve_and_fetch_images(&image_sources, &request.url, &mut fetcher.borrow_mut());

    // Same independence from script execution as images (see above) —
    // this DOM surface has no way for a script to add a NEW `<link>`
    // element either, so the set of stylesheet links is also fixed
    // once parsing is done.
    let stylesheet_links = stylesheets::extract_stylesheet_links(&document);
    let external_css = stylesheets::resolve_and_fetch_stylesheets(
        &stylesheet_links,
        &request.url,
        &mut fetcher.borrow_mut(),
    );

    // Same independence from script execution as images/stylesheets
    // above — no script API exists to add a new `<audio>`/`<video>` or
    // change an existing one's `src` (see `layout::MediaContent`'s own
    // doc comment on why there's no scripting surface here at all yet).
    // Needs `decoded_images` (already resolved above) to attach a
    // `<video poster>` from the SAME map a plain `<img>` would use —
    // see `media::resolve_and_decode_media`'s own doc comment.
    let media_sources = media::extract_media_sources(&document);
    let (media_assets, decoded_audio) = media::resolve_and_decode_media(
        &media_sources,
        &request.url,
        &decoded_images,
        &mut fetcher.borrow_mut(),
    );

    Ok(script::Session::new_with_shared_storage(
        document,
        &sources,
        request.canvas_width,
        theme,
        decoded_images,
        external_css,
        Rc::clone(fetcher),
        request.url.clone(),
        media_assets,
        decoded_audio,
        Rc::clone(local_storage),
        Rc::clone(indexed_db),
    ))
}

/// Builds a `RenderSuccess` from a `Session`'s CURRENT state — shared
/// by every `handle_message` arm that can produce one (`Navigate`,
/// `Tick`, `Click`) so the three don't each re-derive
/// layout/title/wake-up from `Session` slightly differently.
fn render_success(session: &script::Session, font: &text::Font) -> ipc::RenderSuccess {
    ipc::RenderSuccess {
        layout_tree: session.relayout(font),
        title: session.title(),
        next_wake_in_millis: session.next_wake_in_millis(),
        // Only ever `true` for a `Click` reply — see the `Click` arm
        // below, which overwrites this after calling this helper.
        default_prevented: false,
        // Only ever `Some` for a `TextInput(Enter)` or `Click` reply
        // — see those arms below, which overwrite these two after
        // calling this helper.
        submit_url: None,
        submit_body: None,
        // Drained (not cloned) here — see `Session::drain_console_messages`'s
        // own doc comment. Every code path that builds a `RenderSuccess`
        // goes through this one helper, so there's exactly one place
        // that ever needs to remember to do this.
        console_messages: session.drain_console_messages(),
        page_signals: session.page_signals(),
    }
}

/// Everything this process retains ACROSS messages: the fetcher (its
/// cookie jar and disk cache persist across navigations and across
/// tabs — see this crate's module docs on why that's a deliberate
/// simplification), the loaded font, and each open tab's live
/// `script::Session` — a Boa `Context` + DOM that survives from the
/// initial `Navigate` through any later `Tick`s, until the tab
/// navigates again or is closed (see `ipc::ClientMessageKind`'s doc
/// comments for exactly when each of those drops a session).
pub struct RendererState<F: Fetcher + Clone + Send + 'static> {
    /// Shared (not owned outright) specifically so a page's own script
    /// can hold a long-lived handle to this SAME fetcher too — see
    /// `navigate`'s doc comment and `script`'s module docs on `fetch()`.
    fetcher: Rc<RefCell<FilteringFetcher<F>>>,
    /// Shared across every tab in this process the same way `fetcher`
    /// is, and for the same reason: two tabs on the same origin need
    /// to see the same `localStorage`, live — see
    /// `script::Session::new_with_shared_storage`'s own doc comment.
    local_storage: Rc<RefCell<local_storage::LocalStorageStore>>,
    /// Same sharing reasoning as `local_storage`, for IndexedDB.
    indexed_db: Rc<RefCell<indexed_db::IndexedDbStore>>,
    font: text::Font,
    tabs: HashMap<ipc::TabId, script::Session>,
    /// This store's own `version()` as of the last `ServerMessage` that
    /// reported it (see `reported_cookies_if_changed`) — NOT "as of the
    /// last disk write": this process never writes cookies/
    /// `localStorage`/IndexedDB to disk itself any more. `app` does
    /// that now, with the account's own encryption key, which this
    /// sandboxed, untrusted-content-facing process never receives (see
    /// `ipc::ServerMessage`'s own doc comment for the full reasoning).
    /// This field only exists so an unchanged store doesn't get
    /// re-serialized and re-sent on every single reply.
    last_reported_cookie_version: u64,
    last_reported_local_storage_version: u64,
    last_reported_indexed_db_version: u64,
}

impl<F: Fetcher + Clone + Send + 'static> RendererState<F> {
    pub fn new(fetcher: FilteringFetcher<F>, font: text::Font) -> Self {
        RendererState {
            fetcher: Rc::new(RefCell::new(fetcher)),
            local_storage: Rc::new(RefCell::new(local_storage::LocalStorageStore::default())),
            indexed_db: Rc::new(RefCell::new(indexed_db::IndexedDbStore::default())),
            font,
            tabs: HashMap::new(),
            last_reported_cookie_version: 0,
            last_reported_local_storage_version: 0,
            last_reported_indexed_db_version: 0,
        }
    }

    /// Dispatches one `ClientMessage` to the right handler and wraps
    /// the result back up with the same `tab_id` it came in with.
    pub fn handle_message(&mut self, message: &ipc::ClientMessage) -> ipc::ServerMessage {
        let kind = match &message.kind {
            ipc::ClientMessageKind::Navigate(request) => {
                self.seed_storage_from_request(request);
                match navigate(
                    request,
                    &self.fetcher,
                    &self.local_storage,
                    &self.indexed_db,
                ) {
                    Ok(session) => {
                        let success = render_success(&session, &self.font);
                        self.tabs.insert(message.tab_id, session);
                        ipc::ServerMessageKind::Rendered(success)
                    }
                    Err(e) => {
                        // A failed navigation replaces whatever this tab
                        // was showing before — there's nothing left to
                        // keep a stale session around for.
                        self.tabs.remove(&message.tab_id);
                        ipc::ServerMessageKind::Error(e)
                    }
                }
            }
            ipc::ClientMessageKind::CloseTab => {
                self.tabs.remove(&message.tab_id);
                ipc::ServerMessageKind::Closed
            }
            ipc::ClientMessageKind::Tick => match self.tabs.get_mut(&message.tab_id) {
                Some(session) => {
                    if session.tick() {
                        ipc::ServerMessageKind::Rendered(render_success(session, &self.font))
                    } else {
                        ipc::ServerMessageKind::Unchanged {
                            next_wake_in_millis: session.next_wake_in_millis(),
                        }
                    }
                }
                // A stale wake-up racing a tab close (or a tab that
                // never navigated) is an expected, harmless timing
                // window — see `ipc::ClientMessageKind::Tick`'s doc
                // comment — not a protocol error.
                None => ipc::ServerMessageKind::Unchanged {
                    next_wake_in_millis: None,
                },
            },
            ipc::ClientMessageKind::Click { dom_node_id } => {
                match self.tabs.get_mut(&message.tab_id) {
                    Some(session) => {
                        let outcome = session.dispatch_click(*dom_node_id);
                        if outcome.resolved {
                            let mut success = render_success(session, &self.font);
                            success.default_prevented = outcome.default_prevented;
                            success.submit_url = outcome.submit_url;
                            success.submit_body = outcome.submit_body;
                            ipc::ServerMessageKind::Rendered(success)
                        } else {
                            // The node id didn't resolve in this session's
                            // CURRENT DOM — see `ipc::ClientMessageKind::
                            // Click`'s doc comment on why that's an
                            // expected race, not an error. Nothing actually
                            // dispatched, so `default_prevented` couldn't
                            // possibly be true — no field needed here.
                            ipc::ServerMessageKind::Unchanged {
                                next_wake_in_millis: session.next_wake_in_millis(),
                            }
                        }
                    }
                    None => ipc::ServerMessageKind::Unchanged {
                        next_wake_in_millis: None,
                    },
                }
            }
            ipc::ClientMessageKind::Focus {
                dom_node_id,
                click_x,
            } => match self.tabs.get_mut(&message.tab_id) {
                Some(session) => {
                    if session.focus(*dom_node_id, *click_x, &self.font) {
                        ipc::ServerMessageKind::Rendered(render_success(session, &self.font))
                    } else {
                        // Not a live, text-editable input right now —
                        // see `ipc::ClientMessageKind::Focus`'s doc
                        // comment on why that's an expected race, not
                        // an error.
                        ipc::ServerMessageKind::Unchanged {
                            next_wake_in_millis: session.next_wake_in_millis(),
                        }
                    }
                }
                None => ipc::ServerMessageKind::Unchanged {
                    next_wake_in_millis: None,
                },
            },
            ipc::ClientMessageKind::Blur => match self.tabs.get_mut(&message.tab_id) {
                Some(session) => {
                    session.blur();
                    ipc::ServerMessageKind::Rendered(render_success(session, &self.font))
                }
                None => ipc::ServerMessageKind::Unchanged {
                    next_wake_in_millis: None,
                },
            },
            ipc::ClientMessageKind::TextInput(action) => {
                match self.tabs.get_mut(&message.tab_id) {
                    Some(session) => {
                        let outcome = session.handle_text_input(*action);
                        if outcome.resolved {
                            let mut success = render_success(session, &self.font);
                            success.submit_url = outcome.submit_url;
                            success.submit_body = outcome.submit_body;
                            ipc::ServerMessageKind::Rendered(success)
                        } else {
                            // Nothing focused right now — see
                            // `ipc::ClientMessageKind::TextInput`'s doc
                            // comment on why that's an expected race,
                            // not an error.
                            ipc::ServerMessageKind::Unchanged {
                                next_wake_in_millis: session.next_wake_in_millis(),
                            }
                        }
                    }
                    None => ipc::ServerMessageKind::Unchanged {
                        next_wake_in_millis: None,
                    },
                }
            }
            ipc::ClientMessageKind::CheckForUpdate { current_version } => {
                // Not tab-scoped at all (see this variant's own doc
                // comment) — `self.tabs` is never touched here, unlike
                // every other arm above.
                let outcome = {
                    let mut fetcher = self.fetcher.borrow_mut();
                    update_check::check_for_update(&mut fetcher, current_version)
                };
                ipc::ServerMessageKind::UpdateCheckResult(outcome)
            }
            ipc::ClientMessageKind::Download {
                url,
                top_level_host,
            } => {
                // Also not tab-scoped (see `ipc::ClientMessageKind::
                // Download`'s doc comment) — a download doesn't touch
                // any tab's `script::Session`, just the shared fetcher
                // every other request in this process already uses.
                let outcome = {
                    let mut fetcher = self.fetcher.borrow_mut();
                    download::download(&mut fetcher, url, top_level_host.as_deref())
                };
                ipc::ServerMessageKind::DownloadResult(outcome)
            }
            ipc::ClientMessageKind::FetchAudioPcm { dom_node_id } => {
                let outcome = match self.tabs.get(&message.tab_id) {
                    Some(session) => match session.fetch_audio_pcm(*dom_node_id) {
                        Some(audio) => ipc::AudioPcmOutcome::Ready(ipc::AudioPcmData::new(
                            &audio.samples,
                            audio.sample_rate,
                            audio.channels,
                        )),
                        None => ipc::AudioPcmOutcome::Failed(
                            "no decoded audio is available for this element".to_string(),
                        ),
                    },
                    None => {
                        ipc::AudioPcmOutcome::Failed("no live session for this tab".to_string())
                    }
                };
                ipc::ServerMessageKind::AudioPcmResult(outcome)
            }
            ipc::ClientMessageKind::UpdateMediaPlayback {
                dom_node_id,
                playing,
                muted,
                current_time_secs,
            } => match self.tabs.get_mut(&message.tab_id) {
                Some(session) => {
                    if session.update_media_playback(
                        *dom_node_id,
                        *playing,
                        *muted,
                        *current_time_secs,
                    ) {
                        ipc::ServerMessageKind::Rendered(render_success(session, &self.font))
                    } else {
                        // `dom_node_id` isn't a known media element in
                        // this session's CURRENT DOM — an expected race
                        // (e.g. a stale update racing a navigation away
                        // from the page), not a protocol error.
                        ipc::ServerMessageKind::Unchanged {
                            next_wake_in_millis: session.next_wake_in_millis(),
                        }
                    }
                }
                None => ipc::ServerMessageKind::Unchanged {
                    next_wake_in_millis: None,
                },
            },
            ipc::ClientMessageKind::EvalConsoleExpression { code } => {
                match self.tabs.get_mut(&message.tab_id) {
                    Some(session) => {
                        session.eval_console_expression(code);
                        ipc::ServerMessageKind::Rendered(render_success(session, &self.font))
                    }
                    // No live session to eval against — an expected
                    // race (e.g. the DevTools console was still open
                    // when the tab was closed), not a protocol error.
                    None => ipc::ServerMessageKind::Unchanged {
                        next_wake_in_millis: None,
                    },
                }
            }
            ipc::ClientMessageKind::FetchDomSnapshot => {
                let outcome = match self.tabs.get(&message.tab_id) {
                    Some(session) => ipc::DomSnapshotOutcome::Ready(session.dom_snapshot()),
                    None => ipc::DomSnapshotOutcome::Unavailable,
                };
                ipc::ServerMessageKind::DomSnapshotResult(outcome)
            }
            ipc::ClientMessageKind::MoveKeyboardFocus { direction } => {
                match self.tabs.get_mut(&message.tab_id) {
                    Some(session) => {
                        session.move_keyboard_focus(*direction);
                        ipc::ServerMessageKind::Rendered(render_success(session, &self.font))
                    }
                    None => ipc::ServerMessageKind::Unchanged {
                        next_wake_in_millis: None,
                    },
                }
            }
            ipc::ClientMessageKind::ActivateFocused => match self.tabs.get_mut(&message.tab_id) {
                Some(session) => {
                    let outcome = session.activate_focused();
                    if outcome.resolved {
                        let mut success = render_success(session, &self.font);
                        success.default_prevented = outcome.default_prevented;
                        ipc::ServerMessageKind::Rendered(success)
                    } else {
                        ipc::ServerMessageKind::Unchanged {
                            next_wake_in_millis: session.next_wake_in_millis(),
                        }
                    }
                }
                None => ipc::ServerMessageKind::Unchanged {
                    next_wake_in_millis: None,
                },
            },
            ipc::ClientMessageKind::FocusNode { dom_node_id } => {
                match self.tabs.get_mut(&message.tab_id) {
                    Some(session) => {
                        if session.focus_node(*dom_node_id) {
                            ipc::ServerMessageKind::Rendered(render_success(session, &self.font))
                        } else {
                            ipc::ServerMessageKind::Unchanged {
                                next_wake_in_millis: session.next_wake_in_millis(),
                            }
                        }
                    }
                    None => ipc::ServerMessageKind::Unchanged {
                        next_wake_in_millis: None,
                    },
                }
            }
        };
        self.dispatch_pending_storage_events(message.tab_id);
        ipc::ServerMessage {
            tab_id: message.tab_id,
            kind,
            updated_cookies: self.reported_cookies_if_changed(),
            updated_local_storage: self.reported_local_storage_if_changed(),
            updated_indexed_db: self.reported_indexed_db_if_changed(),
        }
    }

    /// Merges `request`'s `initial_cookies`/`initial_local_storage`/
    /// `initial_indexed_db` (see those fields' own doc comments on
    /// `ipc::RenderRequest`) into this process's shared stores, if
    /// present. `app::RendererProcess::render` only ever sends these on
    /// the very first `Navigate` a freshly-spawned process receives,
    /// but this MERGES rather than blindly replacing regardless (via
    /// each store's own real `merge_into`, the same method
    /// `reported_*_if_changed`'s `app`-side counterpart used to call
    /// directly on a shared on-disk file before this process stopped
    /// touching that file at all): an unexpected repeat (a bug on
    /// `app`'s side, or a stale message racing a respawn) can then only
    /// ADD data, never silently discard whatever this process's own
    /// tabs already wrote since it started.
    fn seed_storage_from_request(&mut self, request: &ipc::RenderRequest) {
        if let Some(bytes) = &request.initial_cookies {
            if let Some(seeded) = PartitionedCookieJar::from_bytes(bytes) {
                let mut fetcher = self.fetcher.borrow_mut();
                seeded.merge_into(&mut fetcher.cookies);
            }
        }
        if let Some(bytes) = &request.initial_local_storage {
            if let Some(seeded) = local_storage::LocalStorageStore::from_bytes(bytes) {
                seeded.merge_into(&mut self.local_storage.borrow_mut());
            }
        }
        if let Some(bytes) = &request.initial_indexed_db {
            if let Some(seeded) = indexed_db::IndexedDbStore::from_bytes(bytes) {
                seeded.merge_into(&mut self.indexed_db.borrow_mut());
            }
        }
    }

    /// Drains whichever `StorageChange`s `source_tab_id`'s own session
    /// just queued up (see `script::Session::drain_storage_events`) and
    /// fires a real `storage` event (`script::Session::
    /// fire_storage_event`) into every OTHER live tab in this SAME
    /// renderer process whose origin matches — real cross-tab
    /// `localStorage` notification, for same-origin tabs, the way real
    /// browsers do it. Deliberately called BEFORE `maybe_persist_*`
    /// (though it doesn't touch either file itself) simply so it runs
    /// right alongside the other "things a message's script execution
    /// might have caused" bookkeeping, at the same single tail point
    /// every message kind already funnels through.
    ///
    /// Two tabs on the same origin are always in the SAME renderer
    /// process (`app::RendererPool` pools by site — see its own doc
    /// comment), so `self.tabs` is exactly the right, and only, set of
    /// sessions that could possibly need this; there's no cross-process
    /// case to handle here at all.
    fn dispatch_pending_storage_events(&mut self, source_tab_id: ipc::TabId) {
        let changes = match self.tabs.get_mut(&source_tab_id) {
            Some(session) => session.drain_storage_events(),
            None => return,
        };
        if changes.is_empty() {
            return;
        }
        for (tab_id, session) in self.tabs.iter_mut() {
            if *tab_id == source_tab_id {
                continue;
            }
            for change in &changes {
                if session.origin() == change.origin {
                    session.fire_storage_event(change);
                }
            }
        }
    }

    /// Returns this process's cookie jar as real bytes
    /// (`PartitionedCookieJar::to_bytes`) iff it actually changed since
    /// the last reply that reported it, `None` otherwise — called from
    /// `handle_message`'s tail on EVERY message (see that method), not
    /// gated behind any opt-in the way the old file-writing version of
    /// this was, since attaching an extra field to an in-memory struct
    /// this process was already about to return has no disk-I/O cost to
    /// avoid. `app::RendererProcess::try_send` is what actually turns
    /// a `Some` here into a real encrypted disk write — see
    /// `ipc::ServerMessage`'s own doc comment for the full reasoning on
    /// why THAT has to happen in `app`, not here. A no-op (just a
    /// version-counter comparison, no serialization) for the common
    /// case of a message that never touched a cookie at all — e.g. the
    /// frequent, otherwise unrelated `Tick` a playing media element's
    /// progress bar update sends every 250ms (see `app`'s own
    /// `MEDIA_PROGRESS_TICK_INTERVAL`).
    fn reported_cookies_if_changed(&mut self) -> Option<Vec<u8>> {
        let fetcher = self.fetcher.borrow();
        let current_version = fetcher.cookies.version();
        if current_version == self.last_reported_cookie_version {
            return None;
        }
        self.last_reported_cookie_version = current_version;
        Some(fetcher.cookies.to_bytes())
    }

    /// Same shape as `reported_cookies_if_changed`, for `localStorage`.
    fn reported_local_storage_if_changed(&mut self) -> Option<Vec<u8>> {
        let store = self.local_storage.borrow();
        let current_version = store.version();
        if current_version == self.last_reported_local_storage_version {
            return None;
        }
        self.last_reported_local_storage_version = current_version;
        Some(store.to_bytes())
    }

    /// Same shape as `reported_cookies_if_changed`, for IndexedDB.
    fn reported_indexed_db_if_changed(&mut self) -> Option<Vec<u8>> {
        let store = self.indexed_db.borrow();
        let current_version = store.version();
        if current_version == self.last_reported_indexed_db_version {
            return None;
        }
        self.last_reported_indexed_db_version = current_version;
        Some(store.to_bytes())
    }

    #[cfg(test)]
    fn is_tab_open(&self, tab_id: ipc::TabId) -> bool {
        self.tabs.contains_key(&tab_id)
    }

    #[cfg(test)]
    fn open_tab_count(&self) -> usize {
        self.tabs.len()
    }
}

/// The main loop: read one `ClientMessage`, handle it, write back one
/// `ServerMessage`, repeat — until the reader hits EOF (the parent
/// process closed its end, i.e. `app` exited or is shutting this
/// renderer down) or a write fails (the parent went away). Either one
/// just ends the loop cleanly; there's nothing left to serve. Strictly
/// lockstep (see `ipc`'s module docs on why) — this never writes
/// unless it just read, and never reads again until it's written back.
pub fn serve<R: Read, W: Write, F: Fetcher + Clone + Send + 'static>(
    reader: &mut R,
    writer: &mut W,
    state: &mut RendererState<F>,
) {
    loop {
        let message: ipc::ClientMessage = match ipc::read_message(reader) {
            Ok(msg) => msg,
            Err(_) => return,
        };
        let response = state.handle_message(&message);
        if ipc::write_message(writer, &response).is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use network::FakeFetcher;
    use privacy::Blocklist;
    use std::io::Cursor;

    fn request(url: &str) -> ipc::RenderRequest {
        ipc::RenderRequest {
            url: url.to_string(),
            body: None,
            top_level_host: None,
            canvas_width: 800.0,
            theme: "dark".to_string(),
            user_scripts: Vec::new(),
            initial_cookies: None,
            initial_local_storage: None,
            initial_indexed_db: None,
        }
    }

    fn navigate_msg(tab_id: u64, url: &str) -> ipc::ClientMessage {
        ipc::ClientMessage {
            tab_id: ipc::TabId(tab_id),
            kind: ipc::ClientMessageKind::Navigate(request(url)),
        }
    }

    fn navigate_msg_with_user_scripts(
        tab_id: u64,
        url: &str,
        user_scripts: Vec<String>,
    ) -> ipc::ClientMessage {
        let mut req = request(url);
        req.user_scripts = user_scripts;
        ipc::ClientMessage {
            tab_id: ipc::TabId(tab_id),
            kind: ipc::ClientMessageKind::Navigate(req),
        }
    }

    fn close_tab(tab_id: u64) -> ipc::ClientMessage {
        ipc::ClientMessage {
            tab_id: ipc::TabId(tab_id),
            kind: ipc::ClientMessageKind::CloseTab,
        }
    }

    fn tick(tab_id: u64) -> ipc::ClientMessage {
        ipc::ClientMessage {
            tab_id: ipc::TabId(tab_id),
            kind: ipc::ClientMessageKind::Tick,
        }
    }

    fn click(tab_id: u64, dom_node_id: dom::NodeId) -> ipc::ClientMessage {
        ipc::ClientMessage {
            tab_id: ipc::TabId(tab_id),
            kind: ipc::ClientMessageKind::Click { dom_node_id },
        }
    }

    fn focus_msg(tab_id: u64, dom_node_id: dom::NodeId, click_x: f32) -> ipc::ClientMessage {
        ipc::ClientMessage {
            tab_id: ipc::TabId(tab_id),
            kind: ipc::ClientMessageKind::Focus {
                dom_node_id,
                click_x,
            },
        }
    }

    fn text_input_msg(tab_id: u64, action: ipc::TextInputAction) -> ipc::ClientMessage {
        ipc::ClientMessage {
            tab_id: ipc::TabId(tab_id),
            kind: ipc::ClientMessageKind::TextInput(action),
        }
    }

    fn fetch_audio_pcm_msg(tab_id: u64, dom_node_id: dom::NodeId) -> ipc::ClientMessage {
        ipc::ClientMessage {
            tab_id: ipc::TabId(tab_id),
            kind: ipc::ClientMessageKind::FetchAudioPcm { dom_node_id },
        }
    }

    fn update_media_playback_msg(
        tab_id: u64,
        dom_node_id: dom::NodeId,
        playing: bool,
        muted: bool,
        current_time_secs: f32,
    ) -> ipc::ClientMessage {
        ipc::ClientMessage {
            tab_id: ipc::TabId(tab_id),
            kind: ipc::ClientMessageKind::UpdateMediaPlayback {
                dom_node_id,
                playing,
                muted,
                current_time_secs,
            },
        }
    }

    fn eval_console_msg(tab_id: u64, code: &str) -> ipc::ClientMessage {
        ipc::ClientMessage {
            tab_id: ipc::TabId(tab_id),
            kind: ipc::ClientMessageKind::EvalConsoleExpression {
                code: code.to_string(),
            },
        }
    }

    fn fetch_dom_snapshot_msg(tab_id: u64) -> ipc::ClientMessage {
        ipc::ClientMessage {
            tab_id: ipc::TabId(tab_id),
            kind: ipc::ClientMessageKind::FetchDomSnapshot,
        }
    }

    fn move_keyboard_focus_msg(tab_id: u64, direction: ipc::FocusDirection) -> ipc::ClientMessage {
        ipc::ClientMessage {
            tab_id: ipc::TabId(tab_id),
            kind: ipc::ClientMessageKind::MoveKeyboardFocus { direction },
        }
    }

    fn activate_focused_msg(tab_id: u64) -> ipc::ClientMessage {
        ipc::ClientMessage {
            tab_id: ipc::TabId(tab_id),
            kind: ipc::ClientMessageKind::ActivateFocused,
        }
    }

    fn focus_node_msg(tab_id: u64, dom_node_id: dom::NodeId) -> ipc::ClientMessage {
        ipc::ClientMessage {
            tab_id: ipc::TabId(tab_id),
            kind: ipc::ClientMessageKind::FocusNode { dom_node_id },
        }
    }

    /// A tiny, real, valid WAV file — same construction
    /// `media::tests::tiny_wav` uses, duplicated here rather than
    /// shared across modules for something this small and self-
    /// contained (matching `images::tests::tiny_red_png`'s own
    /// precedent of a locally-built fixture per test module).
    fn tiny_wav() -> Vec<u8> {
        let samples: [i16; 4] = [500, -500, 1000, -1000];
        let data_bytes: Vec<u8> = samples.iter().flat_map(|s| s.to_le_bytes()).collect();
        let sample_rate: u32 = 8000;
        let channels: u16 = 1;
        let bits_per_sample: u16 = 16;
        let byte_rate = sample_rate * channels as u32 * (bits_per_sample as u32 / 8);
        let block_align = channels * (bits_per_sample / 8);

        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"RIFF");
        bytes.extend_from_slice(&(36 + data_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(b"WAVE");
        bytes.extend_from_slice(b"fmt ");
        bytes.extend_from_slice(&16u32.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&channels.to_le_bytes());
        bytes.extend_from_slice(&sample_rate.to_le_bytes());
        bytes.extend_from_slice(&byte_rate.to_le_bytes());
        bytes.extend_from_slice(&block_align.to_le_bytes());
        bytes.extend_from_slice(&bits_per_sample.to_le_bytes());
        bytes.extend_from_slice(b"data");
        bytes.extend_from_slice(&(data_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&data_bytes);
        bytes
    }

    fn find_element_box<'a>(
        node: &'a layout::LayoutBox,
        tag_name: &str,
    ) -> Option<&'a layout::LayoutBox> {
        if matches!(&node.node_type, dom::NodeType::Element(el) if el.tag_name == tag_name) {
            return Some(node);
        }
        node.children
            .iter()
            .find_map(|child| find_element_box(child, tag_name))
    }

    fn state_with(fake: FakeFetcher) -> RendererState<FakeFetcher> {
        RendererState::new(
            FilteringFetcher::new(fake, Blocklist::with_seed_list()),
            text::load_default_font(),
        )
    }

    fn collect_all_text(node: &layout::LayoutBox) -> String {
        let mut out = String::new();
        if let Some(text) = &node.text {
            out.push_str(&text.raw);
            out.push(' ');
        }
        for child in &node.children {
            out.push_str(&collect_all_text(child));
        }
        out
    }

    #[test]
    fn handle_message_navigate_returns_a_laid_out_tree_with_the_page_title() {
        let mut fake = FakeFetcher::new();
        fake.register(
            "https://example.com/",
            "<html><head><title>Hello</title></head><body><p>Hi there</p></body></html>",
        );
        let mut state = state_with(fake);

        let response = state.handle_message(&navigate_msg(1, "https://example.com/"));
        match response.kind {
            ipc::ServerMessageKind::Rendered(success) => {
                assert_eq!(success.title, Some("Hello".to_string()));
                assert!(
                    success.layout_tree.rect.width > 0.0,
                    "a laid-out tree should have real geometry"
                );
            }
            ipc::ServerMessageKind::Error(e) => panic!("expected success, got: {e}"),
            _ => panic!("expected Rendered"),
        }
    }

    /// A real, full-page flexbox test through the ACTUAL production
    /// pipeline (`html::parse` real HTML5 parsing -> `css` real
    /// stylesheet parsing/cascade -> `layout::build_layout_tree` +
    /// `layout::layout`, exactly what a genuine `Navigate` runs) rather
    /// than `layout`'s own unit tests, which build DOM trees by hand
    /// and never exercise `html::parse`'s `<style>`-block handling or
    /// `class` attribute parsing at all.
    #[test]
    fn handle_message_navigate_lays_out_a_real_flexbox_page_end_to_end() {
        let mut fake = FakeFetcher::new();
        fake.register(
            "https://example.com/",
            r#"<html><head><style>
                .row { display: flex; justify-content: space-between; }
            </style></head><body>
                <div class="row">
                    <div>Left</div>
                    <div>Right</div>
                </div>
            </body></html>"#,
        );
        let mut state = state_with(fake);

        let response = state.handle_message(&navigate_msg(1, "https://example.com/"));
        let layout_tree = match response.kind {
            ipc::ServerMessageKind::Rendered(success) => success.layout_tree,
            ipc::ServerMessageKind::Error(e) => panic!("expected success, got: {e}"),
            _ => panic!("expected Rendered"),
        };

        let row =
            find_element_by_class(&layout_tree, "row").expect("the flex row should be in the tree");
        // The tree still literally contains whitespace-only text nodes
        // from the source's own indentation between the two <div>s
        // (real HTML parsing behavior, not a bug) — only the two real
        // element children are flex items; see `layout::flex`'s own
        // module docs on why those text nodes are skipped during
        // layout rather than removed from the tree outright.
        let elements: Vec<_> = row
            .children
            .iter()
            .filter(|c| matches!(&c.node_type, dom::NodeType::Element(_)))
            .collect();
        assert_eq!(
            elements.len(),
            2,
            "exactly two real <div> flex items, ignoring whitespace text nodes"
        );
        let (left, right) = (elements[0], elements[1]);
        assert_eq!(
            left.rect.y, right.rect.y,
            "flex row children should share one line, not stack"
        );
        assert!(
            right.rect.x > left.rect.x + left.rect.width,
            "justify-content: space-between should push the second item toward the far edge, not right after the first"
        );
    }

    /// End-to-end proof that `<link rel="stylesheet">` is fetched AND
    /// applied through the real production pipeline (`navigate` ->
    /// `stylesheets::resolve_and_fetch_stylesheets` ->
    /// `css::extract_author_stylesheet_with_external` ->
    /// `Session::relayout`), not just unit-tested in isolation within
    /// `stylesheets`'s own module.
    #[test]
    fn handle_message_navigate_applies_a_real_external_stylesheet_end_to_end() {
        let mut fake = FakeFetcher::new();
        fake.register(
            "https://example.com/",
            r#"<html><head><link rel="stylesheet" href="/style.css"></head>
               <body><p class="alert">Hi</p></body></html>"#,
        );
        fake.register(
            "https://example.com/style.css",
            ".alert { color: #ff0000; }",
        );
        let mut state = state_with(fake);

        let response = state.handle_message(&navigate_msg(1, "https://example.com/"));
        let layout_tree = match response.kind {
            ipc::ServerMessageKind::Rendered(success) => success.layout_tree,
            ipc::ServerMessageKind::Error(e) => panic!("expected success, got: {e}"),
            _ => panic!("expected Rendered"),
        };

        let p = find_element_box(&layout_tree, "p").expect("the <p> should be in the tree");
        assert_eq!(
            p.style.properties.get("color").map(String::as_str),
            Some("#ff0000"),
            "the external stylesheet's rule should have been fetched and applied"
        );
    }

    #[test]
    fn handle_message_navigate_skips_a_blocked_third_party_stylesheet() {
        let mut fake = FakeFetcher::new();
        fake.register(
            "https://news.example.com/",
            r#"<html><head><link rel="stylesheet" href="http://g.doubleclick.net/style.css"></head>
               <body><p class="alert">Hi</p></body></html>"#,
        );
        fake.register(
            "http://g.doubleclick.net/style.css",
            ".alert { color: #ff0000; }",
        );
        let mut state = state_with(fake);

        let response = state.handle_message(&navigate_msg(1, "https://news.example.com/"));
        let layout_tree = match response.kind {
            ipc::ServerMessageKind::Rendered(success) => success.layout_tree,
            ipc::ServerMessageKind::Error(e) => panic!("expected success, got: {e}"),
            _ => panic!("expected Rendered"),
        };

        let p = find_element_box(&layout_tree, "p").expect("the <p> should be in the tree");
        assert_ne!(
            p.style.properties.get("color").map(String::as_str),
            Some("#ff0000"),
            "a third-party stylesheet should have been blocked, not applied \
             (the color should still be whatever the UA stylesheet inherited down, not red)"
        );
    }

    fn find_element_by_class<'a>(
        node: &'a layout::LayoutBox,
        class_name: &str,
    ) -> Option<&'a layout::LayoutBox> {
        let matches_class = matches!(
            &node.node_type,
            dom::NodeType::Element(el) if el.attributes.get("class").is_some_and(|c| c.split_whitespace().any(|c| c == class_name))
        );
        if matches_class {
            return Some(node);
        }
        node.children
            .iter()
            .find_map(|child| find_element_by_class(child, class_name))
    }

    /// The other tests either exercise `script::run_scripts`/`Session`
    /// directly (bypassing `navigate`/`handle_message` entirely) or
    /// exercise `handle_message` on a page with no script at all —
    /// neither actually proves the real production wiring (extract
    /// scripts, run them, THEN extract the title and lay out) is
    /// correct end to end. This does: a script mutates `document.title`
    /// AND an element's `textContent`, and both mutations must show up
    /// in what `handle_message` — the actual function `main.rs`'s
    /// `serve` loop calls — hands back.
    #[test]
    fn handle_message_navigate_decodes_real_audio_and_fetch_audio_pcm_returns_it() {
        let mut fake = FakeFetcher::new();
        fake.register(
            "https://example.com/",
            r#"<html><body><audio id="a" src="song.wav" controls></audio></body></html>"#,
        );
        fake.register_bytes("https://example.com/song.wav", tiny_wav());
        let mut state = state_with(fake);

        let response = state.handle_message(&navigate_msg(1, "https://example.com/"));
        let layout_tree = match response.kind {
            ipc::ServerMessageKind::Rendered(success) => success.layout_tree,
            _ => panic!("expected Rendered"),
        };
        let audio_box =
            find_element_box(&layout_tree, "audio").expect("audio should be in the tree");
        let media = audio_box.media.as_ref().expect("should have media content");
        assert!(
            media.duration_secs > 0.0,
            "the audio track should have decoded with a real duration"
        );
        let dom_node_id = audio_box.dom_node_id;

        let response = state.handle_message(&fetch_audio_pcm_msg(1, dom_node_id));
        match response.kind {
            ipc::ServerMessageKind::AudioPcmResult(ipc::AudioPcmOutcome::Ready(data)) => {
                assert_eq!(data.samples().unwrap(), vec![500, -500, 1000, -1000]);
                assert_eq!(data.sample_rate, 8000);
                assert_eq!(data.channels, 1);
            }
            _ => panic!("expected AudioPcmResult(Ready(..)), got something else"),
        }
    }

    #[test]
    fn fetch_audio_pcm_for_an_element_with_no_decoded_audio_reports_failure() {
        let mut fake = FakeFetcher::new();
        fake.register(
            "https://example.com/",
            r#"<html><body><audio id="a" controls></audio></body></html>"#,
        );
        let mut state = state_with(fake);

        let response = state.handle_message(&navigate_msg(1, "https://example.com/"));
        let layout_tree = match response.kind {
            ipc::ServerMessageKind::Rendered(success) => success.layout_tree,
            _ => panic!("expected Rendered"),
        };
        let audio_box = find_element_box(&layout_tree, "audio").unwrap();
        let dom_node_id = audio_box.dom_node_id;

        let response = state.handle_message(&fetch_audio_pcm_msg(1, dom_node_id));
        assert!(matches!(
            response.kind,
            ipc::ServerMessageKind::AudioPcmResult(ipc::AudioPcmOutcome::Failed(_))
        ));
    }

    #[test]
    fn update_media_playback_is_reflected_in_the_next_render() {
        let mut fake = FakeFetcher::new();
        fake.register(
            "https://example.com/",
            r#"<html><body><audio id="a" src="song.wav" controls></audio></body></html>"#,
        );
        fake.register_bytes("https://example.com/song.wav", tiny_wav());
        let mut state = state_with(fake);

        let response = state.handle_message(&navigate_msg(1, "https://example.com/"));
        let layout_tree = match response.kind {
            ipc::ServerMessageKind::Rendered(success) => success.layout_tree,
            _ => panic!("expected Rendered"),
        };
        let dom_node_id = find_element_box(&layout_tree, "audio").unwrap().dom_node_id;

        let response =
            state.handle_message(&update_media_playback_msg(1, dom_node_id, true, false, 0.2));
        match response.kind {
            ipc::ServerMessageKind::Rendered(success) => {
                let media = find_element_box(&success.layout_tree, "audio")
                    .unwrap()
                    .media
                    .as_ref()
                    .unwrap();
                assert!(media.playing);
                assert_eq!(media.current_time_secs, 0.2);
            }
            _ => panic!("expected Rendered"),
        }
    }

    #[test]
    fn update_media_playback_for_an_unresolvable_node_id_is_unchanged_not_an_error() {
        let mut fake = FakeFetcher::new();
        fake.register("https://example.com/", "<html><body></body></html>");
        let mut state = state_with(fake);
        state.handle_message(&navigate_msg(1, "https://example.com/"));

        let response = state.handle_message(&update_media_playback_msg(
            1,
            dom::NodeId(999_999),
            true,
            false,
            0.0,
        ));
        assert!(matches!(
            response.kind,
            ipc::ServerMessageKind::Unchanged { .. }
        ));
    }

    #[test]
    fn handle_message_reflects_script_mutations_in_the_final_title_and_layout() {
        let mut fake = FakeFetcher::new();
        fake.register(
            "https://example.com/",
            r#"<html><head><title>Before</title></head><body>
                <p id="greeting">old text</p>
                <script>
                    document.title = "Mutated By Script";
                    document.getElementById('greeting').textContent = "new text from script";
                </script>
            </body></html>"#,
        );
        let mut state = state_with(fake);

        let response = state.handle_message(&navigate_msg(1, "https://example.com/"));
        match response.kind {
            ipc::ServerMessageKind::Rendered(success) => {
                assert_eq!(success.title, Some("Mutated By Script".to_string()));
                // The mutated text has to actually reach the LAYOUT
                // TREE `app` receives — not just the DOM this process
                // keeps to itself — since that tree is the only thing
                // that crosses the IPC boundary (see `ipc`'s module docs).
                let rendered_text = collect_all_text(&success.layout_tree);
                assert!(
                    rendered_text.contains("new text from script"),
                    "expected the script's textContent mutation in the rendered output, got: {rendered_text:?}"
                );
                assert!(
                    !rendered_text.contains("old text"),
                    "the original text should have been replaced, not just appended alongside"
                );
            }
            ipc::ServerMessageKind::Error(e) => panic!("expected success, got: {e}"),
            _ => panic!("expected Rendered"),
        }
    }

    #[test]
    fn handle_message_navigate_captures_a_real_console_log_call() {
        let mut fake = FakeFetcher::new();
        fake.register(
            "https://example.com/",
            r#"<html><body><script>console.log("hello", 42);</script></body></html>"#,
        );
        let mut state = state_with(fake);

        let response = state.handle_message(&navigate_msg(1, "https://example.com/"));
        match response.kind {
            ipc::ServerMessageKind::Rendered(success) => {
                assert_eq!(success.console_messages.len(), 1);
                assert_eq!(success.console_messages[0].level, ipc::ConsoleLevel::Log);
                assert_eq!(success.console_messages[0].text, "hello 42");
            }
            ipc::ServerMessageKind::Error(e) => panic!("expected success, got: {e}"),
            _ => panic!("expected Rendered"),
        }
    }

    #[test]
    fn handle_message_navigate_renders_a_real_pdf_as_reader_mode_text() {
        let mut fake = FakeFetcher::new();
        fake.register_bytes(
            "https://example.com/doc.pdf",
            pdf::tiny_one_page_pdf_for_tests(),
        );
        let mut state = state_with(fake);

        let response = state.handle_message(&navigate_msg(1, "https://example.com/doc.pdf"));
        match response.kind {
            ipc::ServerMessageKind::Rendered(success) => {
                let rendered_text = collect_all_text(&success.layout_tree);
                assert!(
                    rendered_text.contains("Hello PDF"),
                    "expected the PDF's real extracted text, got: {rendered_text:?}"
                );
                assert!(
                    rendered_text.contains("Page 1"),
                    "expected a real per-page heading"
                );
            }
            ipc::ServerMessageKind::Error(e) => panic!("expected success, got: {e}"),
            _ => panic!("expected Rendered"),
        }
    }

    #[test]
    fn handle_message_navigate_reports_a_malformed_pdf_as_a_real_error() {
        let mut fake = FakeFetcher::new();
        fake.register_bytes(
            "https://example.com/broken.pdf",
            b"%PDF-1.4\nnot a real pdf structure at all".to_vec(),
        );
        let mut state = state_with(fake);

        let response = state.handle_message(&navigate_msg(1, "https://example.com/broken.pdf"));
        assert!(matches!(response.kind, ipc::ServerMessageKind::Error(_)));
    }

    #[test]
    fn handle_message_navigate_runs_a_matching_userscript_after_the_pages_own_scripts() {
        let mut fake = FakeFetcher::new();
        fake.register(
            "https://example.com/",
            r#"<html><head><title>Before</title></head><body>
                <script>document.title = "page script ran";</script>
            </body></html>"#,
        );
        let mut state = state_with(fake);

        let response = state.handle_message(&navigate_msg_with_user_scripts(
            1,
            "https://example.com/",
            vec!["document.title = document.title + ' + userscript ran';".to_string()],
        ));
        match response.kind {
            ipc::ServerMessageKind::Rendered(success) => {
                assert_eq!(
                    success.title,
                    Some("page script ran + userscript ran".to_string()),
                    "the userscript should have run AFTER the page's own script, seeing its effect"
                );
            }
            ipc::ServerMessageKind::Error(e) => panic!("expected success, got: {e}"),
            _ => panic!("expected Rendered"),
        }
    }

    #[test]
    fn handle_message_navigate_with_no_user_scripts_is_unaffected() {
        let mut fake = FakeFetcher::new();
        fake.register(
            "https://example.com/",
            "<html><head><title>Plain</title></head><body></body></html>",
        );
        let mut state = state_with(fake);

        let response = state.handle_message(&navigate_msg(1, "https://example.com/"));
        match response.kind {
            ipc::ServerMessageKind::Rendered(success) => {
                assert_eq!(success.title, Some("Plain".to_string()));
            }
            ipc::ServerMessageKind::Error(e) => panic!("expected success, got: {e}"),
            _ => panic!("expected Rendered"),
        }
    }

    #[test]
    fn handle_message_navigate_distinguishes_warn_and_error_console_levels() {
        let mut fake = FakeFetcher::new();
        fake.register(
            "https://example.com/",
            r#"<html><body><script>
                console.warn("careful");
                console.error("broken");
            </script></body></html>"#,
        );
        let mut state = state_with(fake);

        let response = state.handle_message(&navigate_msg(1, "https://example.com/"));
        match response.kind {
            ipc::ServerMessageKind::Rendered(success) => {
                assert_eq!(success.console_messages.len(), 2);
                assert_eq!(success.console_messages[0].level, ipc::ConsoleLevel::Warn);
                assert_eq!(success.console_messages[1].level, ipc::ConsoleLevel::Error);
            }
            ipc::ServerMessageKind::Error(e) => panic!("expected success, got: {e}"),
            _ => panic!("expected Rendered"),
        }
    }

    #[test]
    fn eval_console_expression_echoes_the_input_and_its_result() {
        let mut fake = FakeFetcher::new();
        fake.register("https://example.com/", "<html><body></body></html>");
        let mut state = state_with(fake);
        state.handle_message(&navigate_msg(1, "https://example.com/"));

        let response = state.handle_message(&eval_console_msg(1, "1 + 2"));
        match response.kind {
            ipc::ServerMessageKind::Rendered(success) => {
                assert_eq!(success.console_messages.len(), 2);
                assert_eq!(success.console_messages[0].text, "> 1 + 2");
                assert_eq!(success.console_messages[1].text, "3");
                assert_eq!(success.console_messages[1].level, ipc::ConsoleLevel::Log);
            }
            ipc::ServerMessageKind::Error(e) => panic!("expected success, got: {e}"),
            _ => panic!("expected Rendered"),
        }
    }

    #[test]
    fn eval_console_expression_reports_a_thrown_error_at_error_level() {
        let mut fake = FakeFetcher::new();
        fake.register("https://example.com/", "<html><body></body></html>");
        let mut state = state_with(fake);
        state.handle_message(&navigate_msg(1, "https://example.com/"));

        let response = state.handle_message(&eval_console_msg(1, "nonexistentThing.foo"));
        match response.kind {
            ipc::ServerMessageKind::Rendered(success) => {
                assert_eq!(success.console_messages.len(), 2);
                assert_eq!(success.console_messages[1].level, ipc::ConsoleLevel::Error);
            }
            ipc::ServerMessageKind::Error(e) => panic!("expected success, got: {e}"),
            _ => panic!("expected Rendered"),
        }
    }

    #[test]
    fn eval_console_expression_mutations_are_reflected_in_the_layout_tree() {
        let mut fake = FakeFetcher::new();
        fake.register(
            "https://example.com/",
            r#"<html><body><p id="x">before</p></body></html>"#,
        );
        let mut state = state_with(fake);
        state.handle_message(&navigate_msg(1, "https://example.com/"));

        let response = state.handle_message(&eval_console_msg(
            1,
            "document.getElementById('x').textContent = 'after';",
        ));
        match response.kind {
            ipc::ServerMessageKind::Rendered(success) => {
                let rendered_text = collect_all_text(&success.layout_tree);
                assert!(rendered_text.contains("after"));
                assert!(!rendered_text.contains("before"));
            }
            ipc::ServerMessageKind::Error(e) => panic!("expected success, got: {e}"),
            _ => panic!("expected Rendered"),
        }
    }

    #[test]
    fn eval_console_expression_on_an_unknown_tab_is_unchanged_not_an_error() {
        let mut state = state_with(FakeFetcher::new());
        let response = state.handle_message(&eval_console_msg(99, "1"));
        assert!(matches!(
            response.kind,
            ipc::ServerMessageKind::Unchanged { .. }
        ));
    }

    #[test]
    fn fetch_dom_snapshot_includes_a_script_element_the_layout_tree_would_have_dropped() {
        let mut fake = FakeFetcher::new();
        fake.register(
            "https://example.com/",
            r#"<html><head><script>1;</script></head><body><p>hi</p></body></html>"#,
        );
        let mut state = state_with(fake);
        state.handle_message(&navigate_msg(1, "https://example.com/"));

        let response = state.handle_message(&fetch_dom_snapshot_msg(1));
        match response.kind {
            ipc::ServerMessageKind::DomSnapshotResult(ipc::DomSnapshotOutcome::Ready(root)) => {
                let has_script = contains_tag(&root, "script");
                assert!(
                    has_script,
                    "the DOM snapshot should include <script>, unlike the painted layout tree"
                );
            }
            ipc::ServerMessageKind::DomSnapshotResult(ipc::DomSnapshotOutcome::Unavailable) => {
                panic!("expected DomSnapshotResult(Ready(_)), got Unavailable")
            }
            _ => panic!("expected DomSnapshotResult(Ready(_))"),
        }
    }

    fn contains_tag(node: &ipc::DomNode, tag: &str) -> bool {
        if let ipc::DomNodeKind::Element { tag_name, .. } = &node.kind {
            if tag_name == tag {
                return true;
            }
        }
        node.children.iter().any(|c| contains_tag(c, tag))
    }

    #[test]
    fn fetch_dom_snapshot_on_an_unknown_tab_reports_unavailable() {
        let mut state = state_with(FakeFetcher::new());
        let response = state.handle_message(&fetch_dom_snapshot_msg(99));
        assert!(matches!(
            response.kind,
            ipc::ServerMessageKind::DomSnapshotResult(ipc::DomSnapshotOutcome::Unavailable)
        ));
    }

    #[test]
    fn move_keyboard_focus_next_lands_on_the_first_real_focusable_element() {
        let mut fake = FakeFetcher::new();
        fake.register(
            "https://example.com/",
            r#"<html><body><a href="/x" id="link">go</a></body></html>"#,
        );
        let mut state = state_with(fake);
        state.handle_message(&navigate_msg(1, "https://example.com/"));

        let response = state.handle_message(&move_keyboard_focus_msg(1, ipc::FocusDirection::Next));
        match response.kind {
            ipc::ServerMessageKind::Rendered(success) => {
                let link_box = find_element_box(&success.layout_tree, "a")
                    .expect("the link should be in the layout tree");
                assert!(link_box.focused, "the link should now show as focused");
            }
            ipc::ServerMessageKind::Error(e) => panic!("expected success, got: {e}"),
            _ => panic!("expected Rendered"),
        }
    }

    #[test]
    fn move_keyboard_focus_on_an_unknown_tab_is_unchanged_not_an_error() {
        let mut state = state_with(FakeFetcher::new());
        let response =
            state.handle_message(&move_keyboard_focus_msg(99, ipc::FocusDirection::Next));
        assert!(matches!(
            response.kind,
            ipc::ServerMessageKind::Unchanged { .. }
        ));
    }

    #[test]
    fn activate_focused_after_moving_focus_dispatches_a_real_click() {
        let mut fake = FakeFetcher::new();
        fake.register(
            "https://example.com/",
            r#"<html><head><title>Before</title></head><body>
                <button id="btn">go</button>
                <script>
                    document.getElementById('btn').addEventListener('click', function() {
                        document.title = 'activated';
                    });
                </script>
            </body></html>"#,
        );
        let mut state = state_with(fake);
        state.handle_message(&navigate_msg(1, "https://example.com/"));
        state.handle_message(&move_keyboard_focus_msg(1, ipc::FocusDirection::Next));

        let response = state.handle_message(&activate_focused_msg(1));
        match response.kind {
            ipc::ServerMessageKind::Rendered(success) => {
                assert_eq!(success.title, Some("activated".to_string()));
            }
            ipc::ServerMessageKind::Error(e) => panic!("expected success, got: {e}"),
            _ => panic!("expected Rendered"),
        }
    }

    #[test]
    fn activate_focused_with_nothing_focused_is_unchanged_not_an_error() {
        let mut fake = FakeFetcher::new();
        fake.register(
            "https://example.com/",
            "<html><body><button>go</button></body></html>",
        );
        let mut state = state_with(fake);
        state.handle_message(&navigate_msg(1, "https://example.com/"));

        let response = state.handle_message(&activate_focused_msg(1));
        assert!(matches!(
            response.kind,
            ipc::ServerMessageKind::Unchanged { .. }
        ));
    }

    #[test]
    fn focus_node_directly_focuses_a_real_element_by_id() {
        let mut fake = FakeFetcher::new();
        fake.register(
            "https://example.com/",
            r#"<html><body><a href="/x" id="link">go</a></body></html>"#,
        );
        let mut state = state_with(fake);
        state.handle_message(&navigate_msg(1, "https://example.com/"));
        let link_id = state
            .tabs
            .get(&ipc::TabId(1))
            .and_then(|session| {
                find_element_box(&session.relayout(&text::load_default_font()), "a")
                    .map(|b| b.dom_node_id)
            })
            .expect("the link should be in the layout tree");

        let response = state.handle_message(&focus_node_msg(1, link_id));
        match response.kind {
            ipc::ServerMessageKind::Rendered(success) => {
                let link_box =
                    find_element_box(&success.layout_tree, "a").expect("link should be present");
                assert!(link_box.focused);
            }
            ipc::ServerMessageKind::Error(e) => panic!("expected success, got: {e}"),
            _ => panic!("expected Rendered"),
        }
    }

    #[test]
    fn focus_node_on_an_unknown_tab_is_unchanged_not_an_error() {
        let mut state = state_with(FakeFetcher::new());
        let response = state.handle_message(&focus_node_msg(99, dom::NodeId(1)));
        assert!(matches!(
            response.kind,
            ipc::ServerMessageKind::Unchanged { .. }
        ));
    }

    #[test]
    fn handle_message_navigate_reports_a_fetch_failure_as_an_error() {
        let fake = FakeFetcher::new(); // nothing registered
        let mut state = state_with(fake);

        let response = state.handle_message(&navigate_msg(1, "https://never-registered.example/"));
        assert!(matches!(response.kind, ipc::ServerMessageKind::Error(_)));
        assert!(!state.is_tab_open(ipc::TabId(1)));
    }

    #[test]
    fn handle_message_navigate_reports_a_blocked_request_as_an_error() {
        let mut fake = FakeFetcher::new();
        fake.register("http://g.doubleclick.net/pixel", "tracking pixel");
        let mut state = state_with(fake);

        let mut blocked_request = request("http://g.doubleclick.net/pixel");
        blocked_request.top_level_host = Some("news.example.com".to_string());
        let response = state.handle_message(&ipc::ClientMessage {
            tab_id: ipc::TabId(1),
            kind: ipc::ClientMessageKind::Navigate(blocked_request),
        });

        assert!(
            matches!(response.kind, ipc::ServerMessageKind::Error(_)),
            "a third-party tracker request should have been blocked"
        );
    }

    #[test]
    fn handle_message_navigate_marks_the_tab_open_and_returns_rendered() {
        let mut fake = FakeFetcher::new();
        fake.register("https://example.com/", "<html><body>hi</body></html>");
        let mut state = state_with(fake);

        let response = state.handle_message(&navigate_msg(1, "https://example.com/"));

        assert_eq!(response.tab_id, ipc::TabId(1));
        assert!(matches!(response.kind, ipc::ServerMessageKind::Rendered(_)));
        assert!(state.is_tab_open(ipc::TabId(1)));
    }

    #[test]
    fn a_set_cookie_response_is_reported_on_the_server_message_after_navigating() {
        // Cookies are no longer written to disk by this process at all
        // (see `RendererState::reported_cookies_if_changed`'s own doc
        // comment) — `app` does that now, with the account's own
        // encryption key. This just checks the REPORTING half: real,
        // parseable bytes show up on the reply exactly when the cookie
        // jar actually changed.
        let mut fake = FakeFetcher::new();
        fake.register_with_set_cookie(
            "https://example.com/",
            "<html><body>hi</body></html>",
            &["session=abc123; Path=/; HttpOnly"],
        );
        let mut state = state_with(fake);

        let response = state.handle_message(&navigate_msg(1, "https://example.com/"));

        let reported = response
            .updated_cookies
            .expect("a real Set-Cookie should be reported");
        let jar = network::PartitionedCookieJar::from_bytes(&reported).unwrap();
        let key = privacy::StoragePartitionKey {
            top_level_site: "example.com".to_string(),
            resource_host: "example.com".to_string(),
        };
        assert_eq!(
            jar.cookie_header_for(&key),
            Some("session=abc123".to_string())
        );
    }

    #[test]
    fn a_message_that_never_touches_a_cookie_does_not_report_an_update() {
        let mut fake = FakeFetcher::new();
        fake.register("https://example.com/", "<html><body>hi</body></html>");
        let mut state = state_with(fake);

        let response = state.handle_message(&navigate_msg(1, "https://example.com/"));

        assert!(
            response.updated_cookies.is_none(),
            "a response with no Set-Cookie at all shouldn't report a change"
        );
    }

    #[test]
    fn initial_cookies_on_a_navigate_request_seed_this_processs_cookie_jar() {
        // Mirrors what `app::RendererProcess::render` does on the very
        // first `Navigate` to a freshly-spawned process: decrypt
        // whatever was on disk from a PREVIOUS run and attach it as
        // real bytes on the request, so a page that set a cookie last
        // time is still logged in this time.
        let mut seed_jar = network::PartitionedCookieJar::default();
        seed_jar.set(
            privacy::StoragePartitionKey {
                top_level_site: "example.com".to_string(),
                resource_host: "example.com".to_string(),
            },
            "session",
            "from-a-previous-run",
        );

        let mut fake = FakeFetcher::new();
        fake.register("https://example.com/", "<html><body>hi</body></html>");
        let mut state = state_with(fake);

        let mut req = request("https://example.com/");
        req.initial_cookies = Some(seed_jar.to_bytes());
        let message = ipc::ClientMessage {
            tab_id: ipc::TabId(1),
            kind: ipc::ClientMessageKind::Navigate(req),
        };
        state.handle_message(&message);

        let key = privacy::StoragePartitionKey {
            top_level_site: "example.com".to_string(),
            resource_host: "example.com".to_string(),
        };
        assert_eq!(
            state.fetcher.borrow().cookies.cookie_header_for(&key),
            Some("session=from-a-previous-run".to_string())
        );
    }

    #[test]
    fn local_storage_set_on_one_tab_is_visible_from_another_tab_on_the_same_origin() {
        // Two DIFFERENT tabs (ids 1 and 2), same renderer process (one
        // `RendererState` — matching real `app::RendererPool` behavior
        // for two tabs on the same site), both navigated to the same
        // origin. `localStorage` is shared LIVE across them, the way
        // real browser tabs share it — see
        // `script::Session::new_with_local_storage`'s own doc comment.
        let mut fake = FakeFetcher::new();
        fake.register(
            "https://example.com/a",
            r#"<html><head><title>A</title></head><body>
                <script>localStorage.setItem('shared', 'from-tab-1');</script>
            </body></html>"#,
        );
        fake.register(
            "https://example.com/b",
            r#"<html><head><title>B</title></head></html>"#,
        );
        let mut state = state_with(fake);

        state.handle_message(&navigate_msg(1, "https://example.com/a"));
        let response = state.handle_message(&navigate_msg(2, "https://example.com/b"));

        let layout_tree = match response.kind {
            ipc::ServerMessageKind::Rendered(success) => success.layout_tree,
            _ => panic!("expected Rendered"),
        };
        // Tab 2 never set this itself — if it reads it back, the two
        // tabs are genuinely sharing one live store, not each getting
        // its own.
        let _ = layout_tree; // (title/layout aren't what's under test here)
        assert_eq!(
            state
                .local_storage
                .borrow()
                .get("https://example.com", "shared"),
            Some("from-tab-1".to_string())
        );
    }

    #[test]
    fn local_storage_set_on_one_tab_fires_a_real_storage_event_on_another_same_origin_tab() {
        // Tab 2 registers a real `window.addEventListener('storage', ...)`
        // listener FIRST (matching a real multi-tab scenario: the other
        // tab is already open when this one writes). Tab 1 then sets a
        // key — tab 2's own live JS `Context` should observe a real
        // `StorageEvent`-shaped object, with no message ever sent to
        // tab 2 itself. See `script::Session::fire_storage_event`'s own
        // doc comment for why direct field access (rather than a
        // `FetchDomSnapshot`/`Tick` message) is how this test proves
        // the JS side effect actually happened right away, without
        // relying on `app` observing it too.
        let mut fake = FakeFetcher::new();
        fake.register(
            "https://example.com/a",
            r#"<html><head><title>A</title></head></html>"#,
        );
        fake.register(
            "https://example.com/b",
            r#"<html><head><title>B</title></head><body>
                <script>
                    window.addEventListener('storage', function (e) {
                        document.title = 'storage:' + e.key + ':' + e.oldValue + ':' + e.newValue;
                    });
                </script>
            </body></html>"#,
        );
        let mut state = state_with(fake);

        state.handle_message(&navigate_msg(2, "https://example.com/b"));
        state.handle_message(&navigate_msg(1, "https://example.com/a"));

        // Tab 1's own navigation ran no script that touches
        // `localStorage` yet — tab 2 shouldn't have heard anything.
        assert_eq!(
            state.tabs.get(&ipc::TabId(2)).unwrap().title(),
            Some("B".to_string())
        );

        state.handle_message(&ipc::ClientMessage {
            tab_id: ipc::TabId(1),
            kind: ipc::ClientMessageKind::EvalConsoleExpression {
                code: "localStorage.setItem('theme', 'dark')".to_string(),
            },
        });

        assert_eq!(
            state.tabs.get(&ipc::TabId(2)).unwrap().title(),
            Some("storage:theme:null:dark".to_string())
        );
    }

    #[test]
    fn local_storage_set_on_one_tab_does_not_fire_a_storage_event_on_itself() {
        let mut fake = FakeFetcher::new();
        fake.register(
            "https://example.com/a",
            r#"<html><head><title>A</title></head><body>
                <script>
                    window.addEventListener('storage', function (e) {
                        document.title = 'should-not-fire';
                    });
                </script>
            </body></html>"#,
        );
        let mut state = state_with(fake);
        state.handle_message(&navigate_msg(1, "https://example.com/a"));

        state.handle_message(&ipc::ClientMessage {
            tab_id: ipc::TabId(1),
            kind: ipc::ClientMessageKind::EvalConsoleExpression {
                code: "localStorage.setItem('k', 'v')".to_string(),
            },
        });

        assert_eq!(
            state.tabs.get(&ipc::TabId(1)).unwrap().title(),
            Some("A".to_string())
        );
    }

    #[test]
    fn local_storage_set_on_one_tab_does_not_fire_a_storage_event_on_a_different_origin_tab() {
        let mut fake = FakeFetcher::new();
        fake.register(
            "https://example.com/a",
            r#"<html><head><title>A</title></head></html>"#,
        );
        fake.register(
            "https://other.example/b",
            r#"<html><head><title>B</title></head><body>
                <script>
                    window.addEventListener('storage', function (e) {
                        document.title = 'should-not-fire';
                    });
                </script>
            </body></html>"#,
        );
        let mut state = state_with(fake);
        state.handle_message(&navigate_msg(2, "https://other.example/b"));
        state.handle_message(&navigate_msg(1, "https://example.com/a"));

        state.handle_message(&ipc::ClientMessage {
            tab_id: ipc::TabId(1),
            kind: ipc::ClientMessageKind::EvalConsoleExpression {
                code: "localStorage.setItem('k', 'v')".to_string(),
            },
        });

        assert_eq!(
            state.tabs.get(&ipc::TabId(2)).unwrap().title(),
            Some("B".to_string())
        );
    }

    #[test]
    fn local_storage_changes_are_reported_on_the_server_message_after_navigating() {
        let mut fake = FakeFetcher::new();
        fake.register(
            "https://example.com/",
            r#"<html><body><script>localStorage.setItem('k', 'v');</script></body></html>"#,
        );
        let mut state = state_with(fake);

        let response = state.handle_message(&navigate_msg(1, "https://example.com/"));

        let reported = response
            .updated_local_storage
            .expect("a real localStorage.setItem should be reported");
        let store = local_storage::LocalStorageStore::from_bytes(&reported).unwrap();
        assert_eq!(store.get("https://example.com", "k"), Some("v".to_string()));
    }

    #[test]
    fn a_message_that_never_touches_local_storage_does_not_report_an_update() {
        let mut fake = FakeFetcher::new();
        fake.register("https://example.com/", "<html><body>hi</body></html>");
        let mut state = state_with(fake);

        let response = state.handle_message(&navigate_msg(1, "https://example.com/"));

        assert!(
            response.updated_local_storage.is_none(),
            "a page that never touches localStorage shouldn't report a change"
        );
    }

    #[test]
    fn initial_local_storage_on_a_navigate_request_seeds_this_processs_store() {
        let mut seed_store = local_storage::LocalStorageStore::default();
        seed_store
            .set(
                "https://example.com",
                "k".to_string(),
                "from-a-previous-run".to_string(),
            )
            .unwrap();

        let mut fake = FakeFetcher::new();
        fake.register("https://example.com/", "<html><body>hi</body></html>");
        let mut state = state_with(fake);

        let mut req = request("https://example.com/");
        req.initial_local_storage = Some(seed_store.to_bytes());
        let message = ipc::ClientMessage {
            tab_id: ipc::TabId(1),
            kind: ipc::ClientMessageKind::Navigate(req),
        };
        state.handle_message(&message);

        assert_eq!(
            state.local_storage.borrow().get("https://example.com", "k"),
            Some("from-a-previous-run".to_string())
        );
    }

    #[test]
    fn indexed_db_put_on_one_tab_is_visible_from_another_tab_on_the_same_origin() {
        let mut fake = FakeFetcher::new();
        fake.register(
            "https://example.com/a",
            r#"<html><head><title>A</title></head><body>
                <script>
                    var req = indexedDB.open('mydb', 1);
                    req.onupgradeneeded = function () { req.result.createObjectStore('things'); };
                    req.onsuccess = function () {
                        req.result.transaction('things', 'readwrite').objectStore('things').put('from-tab-1', 'shared');
                    };
                </script>
            </body></html>"#,
        );
        fake.register(
            "https://example.com/b",
            r#"<html><head><title>B</title></head></html>"#,
        );
        let mut state = state_with(fake);

        state.handle_message(&navigate_msg(1, "https://example.com/a"));
        state.handle_message(&navigate_msg(2, "https://example.com/b"));

        assert_eq!(
            state
                .indexed_db
                .borrow()
                .get(
                    "https://example.com",
                    "mydb",
                    "things",
                    &serde_json::Value::from("shared")
                )
                .unwrap(),
            Some(serde_json::Value::from("from-tab-1"))
        );
    }

    #[test]
    fn indexed_db_changes_are_reported_on_the_server_message_after_navigating() {
        let mut fake = FakeFetcher::new();
        fake.register(
            "https://example.com/",
            r#"<html><body><script>
                var req = indexedDB.open('mydb', 1);
                req.onupgradeneeded = function () { req.result.createObjectStore('things'); };
                req.onsuccess = function () {
                    req.result.transaction('things', 'readwrite').objectStore('things').put('v', 'k');
                };
            </script></body></html>"#,
        );
        let mut state = state_with(fake);

        let response = state.handle_message(&navigate_msg(1, "https://example.com/"));

        let reported = response
            .updated_indexed_db
            .expect("a real IndexedDB put should be reported");
        let store = indexed_db::IndexedDbStore::from_bytes(&reported).unwrap();
        assert_eq!(
            store
                .get(
                    "https://example.com",
                    "mydb",
                    "things",
                    &serde_json::Value::from("k")
                )
                .unwrap(),
            Some(serde_json::Value::from("v"))
        );
    }

    #[test]
    fn a_message_that_never_touches_indexed_db_does_not_report_an_update() {
        let mut fake = FakeFetcher::new();
        fake.register("https://example.com/", "<html><body>hi</body></html>");
        let mut state = state_with(fake);

        let response = state.handle_message(&navigate_msg(1, "https://example.com/"));

        assert!(
            response.updated_indexed_db.is_none(),
            "a page that never touches IndexedDB shouldn't report a change"
        );
    }

    #[test]
    fn initial_indexed_db_on_a_navigate_request_seeds_this_processs_store() {
        let mut seed_store = indexed_db::IndexedDbStore::default();
        seed_store.open("https://example.com", "mydb", None);
        seed_store
            .create_object_store("https://example.com", "mydb", "things", None, false)
            .unwrap();
        seed_store
            .put(
                "https://example.com",
                "mydb",
                "things",
                serde_json::Value::from("from-a-previous-run"),
                Some(serde_json::Value::from("k")),
                false,
            )
            .unwrap();

        let mut fake = FakeFetcher::new();
        fake.register("https://example.com/", "<html><body>hi</body></html>");
        let mut state = state_with(fake);

        let mut req = request("https://example.com/");
        req.initial_indexed_db = Some(seed_store.to_bytes());
        let message = ipc::ClientMessage {
            tab_id: ipc::TabId(1),
            kind: ipc::ClientMessageKind::Navigate(req),
        };
        state.handle_message(&message);

        assert_eq!(
            state
                .indexed_db
                .borrow()
                .get(
                    "https://example.com",
                    "mydb",
                    "things",
                    &serde_json::Value::from("k")
                )
                .unwrap(),
            Some(serde_json::Value::from("from-a-previous-run"))
        );
    }

    #[test]
    fn handle_message_close_tab_removes_it_and_acknowledges() {
        let mut fake = FakeFetcher::new();
        fake.register("https://example.com/", "<html><body>hi</body></html>");
        let mut state = state_with(fake);

        state.handle_message(&navigate_msg(1, "https://example.com/"));
        assert!(state.is_tab_open(ipc::TabId(1)));

        let response = state.handle_message(&close_tab(1));
        assert_eq!(response.tab_id, ipc::TabId(1));
        assert!(matches!(response.kind, ipc::ServerMessageKind::Closed));
        assert!(!state.is_tab_open(ipc::TabId(1)));
    }

    #[test]
    fn tabs_are_tracked_independently() {
        let mut fake = FakeFetcher::new();
        fake.register("https://a.example/", "<html><body>a</body></html>");
        fake.register("https://b.example/", "<html><body>b</body></html>");
        let mut state = state_with(fake);

        state.handle_message(&navigate_msg(1, "https://a.example/"));
        state.handle_message(&navigate_msg(2, "https://b.example/"));
        assert_eq!(state.open_tab_count(), 2);

        // Closing tab 1 must not affect tab 2's tracked state.
        state.handle_message(&close_tab(1));
        assert!(!state.is_tab_open(ipc::TabId(1)));
        assert!(state.is_tab_open(ipc::TabId(2)));
        assert_eq!(state.open_tab_count(), 1);
    }

    #[test]
    fn closing_an_unknown_tab_id_is_a_harmless_no_op() {
        let mut state = state_with(FakeFetcher::new());
        let response = state.handle_message(&close_tab(999));
        assert!(matches!(response.kind, ipc::ServerMessageKind::Closed));
        assert_eq!(state.open_tab_count(), 0);
    }

    #[test]
    fn tick_on_an_unknown_tab_is_unchanged_with_no_wake_up_rather_than_an_error() {
        let mut state = state_with(FakeFetcher::new());
        let response = state.handle_message(&tick(999));
        match response.kind {
            ipc::ServerMessageKind::Unchanged {
                next_wake_in_millis,
            } => assert_eq!(next_wake_in_millis, None),
            _ => panic!("expected Unchanged"),
        }
    }

    #[test]
    fn handle_message_click_runs_a_registered_listener_and_returns_rendered() {
        let mut fake = FakeFetcher::new();
        fake.register(
            "https://example.com/",
            r#"<html><head><title>Before</title></head><body>
                <button id="btn">Click</button>
                <script>
                    document.getElementById('btn').addEventListener('click', function() {
                        document.title = 'clicked';
                    });
                </script>
            </body></html>"#,
        );
        let mut state = state_with(fake);

        let response = state.handle_message(&navigate_msg(1, "https://example.com/"));
        let layout_tree = match response.kind {
            ipc::ServerMessageKind::Rendered(success) => success.layout_tree,
            _ => panic!("expected Rendered"),
        };

        // Find the button's node id the same way `app` would — off the
        // `LayoutBox` snapshot it already received, not by reaching
        // into the renderer's live session.
        let button_box =
            find_element_box(&layout_tree, "button").expect("button should be in the tree");
        let dom_node_id = button_box.dom_node_id;

        let response = state.handle_message(&click(1, dom_node_id));
        match response.kind {
            ipc::ServerMessageKind::Rendered(success) => {
                assert_eq!(success.title, Some("clicked".to_string()));
                assert!(
                    !success.default_prevented,
                    "this listener never calls preventDefault"
                );
            }
            _ => panic!("expected Rendered"),
        }
    }

    #[test]
    fn handle_message_click_reports_default_prevented_when_a_listener_calls_it() {
        let mut fake = FakeFetcher::new();
        fake.register(
            "https://example.com/",
            r#"<html><body>
                <button id="btn">Click</button>
                <script>
                    document.getElementById('btn').addEventListener('click', function(event) {
                        event.preventDefault();
                    });
                </script>
            </body></html>"#,
        );
        let mut state = state_with(fake);

        let response = state.handle_message(&navigate_msg(1, "https://example.com/"));
        let layout_tree = match response.kind {
            ipc::ServerMessageKind::Rendered(success) => success.layout_tree,
            _ => panic!("expected Rendered"),
        };
        let dom_node_id = find_element_box(&layout_tree, "button")
            .unwrap()
            .dom_node_id;

        let response = state.handle_message(&click(1, dom_node_id));
        match response.kind {
            ipc::ServerMessageKind::Rendered(success) => assert!(success.default_prevented),
            _ => panic!("expected Rendered"),
        }
    }

    /// End-to-end proof that `Focus`/`TextInput` reach a real
    /// `<input>` through the full `RendererState::handle_message` path
    /// (not just `Session`'s own methods directly) — mirrors
    /// `handle_message_click_runs_a_registered_listener_and_returns_rendered`
    /// closely, for the same reason.
    #[test]
    fn handle_message_focus_and_type_updates_the_rendered_value() {
        let mut fake = FakeFetcher::new();
        fake.register(
            "https://example.com/",
            r#"<html><body><input id="q" value="h"></body></html>"#,
        );
        let mut state = state_with(fake);

        let response = state.handle_message(&navigate_msg(1, "https://example.com/"));
        let layout_tree = match response.kind {
            ipc::ServerMessageKind::Rendered(success) => success.layout_tree,
            _ => panic!("expected Rendered"),
        };
        let input_box =
            find_element_box(&layout_tree, "input").expect("input should be in the tree");
        let dom_node_id = input_box.dom_node_id;

        let response = state.handle_message(&focus_msg(1, dom_node_id, 10_000.0));
        assert!(matches!(response.kind, ipc::ServerMessageKind::Rendered(_)));

        let response =
            state.handle_message(&text_input_msg(1, ipc::TextInputAction::InsertChar('i')));
        match response.kind {
            ipc::ServerMessageKind::Rendered(success) => {
                let input_box =
                    find_element_box(&success.layout_tree, "input").expect("still there");
                assert_eq!(
                    input_box.text_input.as_ref().unwrap().value,
                    "hi",
                    "typing after Focus should have inserted at the end"
                );
            }
            _ => panic!("expected Rendered"),
        }
    }

    #[test]
    fn handle_message_enter_reports_a_real_submit_url() {
        let mut fake = FakeFetcher::new();
        fake.register(
            "https://example.com/",
            r#"<html><body><form action="/search"><input id="q" name="term" value="cats"></form></body></html>"#,
        );
        let mut state = state_with(fake);

        let response = state.handle_message(&navigate_msg(1, "https://example.com/"));
        let layout_tree = match response.kind {
            ipc::ServerMessageKind::Rendered(success) => success.layout_tree,
            _ => panic!("expected Rendered"),
        };
        let dom_node_id = find_element_box(&layout_tree, "input").unwrap().dom_node_id;

        state.handle_message(&focus_msg(1, dom_node_id, 0.0));
        let response = state.handle_message(&text_input_msg(1, ipc::TextInputAction::Enter));
        match response.kind {
            ipc::ServerMessageKind::Rendered(success) => {
                assert_eq!(
                    success.submit_url.as_deref(),
                    Some("https://example.com/search?term=cats")
                );
            }
            _ => panic!("expected Rendered"),
        }
    }

    #[test]
    fn handle_message_click_on_a_submit_button_reports_a_real_post_submission() {
        let mut fake = FakeFetcher::new();
        fake.register(
            "https://example.com/",
            r#"<html><body><form action="/login" method="post">
                <input name="username" value="alice">
                <button type="submit" id="go">Log in</button>
            </form></body></html>"#,
        );
        let mut state = state_with(fake);

        let response = state.handle_message(&navigate_msg(1, "https://example.com/"));
        let layout_tree = match response.kind {
            ipc::ServerMessageKind::Rendered(success) => success.layout_tree,
            _ => panic!("expected Rendered"),
        };
        let dom_node_id = find_element_box(&layout_tree, "button")
            .unwrap()
            .dom_node_id;

        let response = state.handle_message(&click(1, dom_node_id));
        match response.kind {
            ipc::ServerMessageKind::Rendered(success) => {
                assert_eq!(
                    success.submit_url.as_deref(),
                    Some("https://example.com/login")
                );
                assert_eq!(success.submit_body, Some(b"username=alice".to_vec()));
            }
            _ => panic!("expected Rendered"),
        }
    }

    #[test]
    fn handle_message_click_on_a_plain_button_type_reports_no_submission() {
        let mut fake = FakeFetcher::new();
        fake.register(
            "https://example.com/",
            r#"<html><body><form action="/login" method="post">
                <input name="username" value="alice">
                <button type="button" id="not-a-submit">Not a submit</button>
            </form></body></html>"#,
        );
        let mut state = state_with(fake);

        let response = state.handle_message(&navigate_msg(1, "https://example.com/"));
        let layout_tree = match response.kind {
            ipc::ServerMessageKind::Rendered(success) => success.layout_tree,
            _ => panic!("expected Rendered"),
        };
        let dom_node_id = find_element_box(&layout_tree, "button")
            .unwrap()
            .dom_node_id;

        let response = state.handle_message(&click(1, dom_node_id));
        match response.kind {
            ipc::ServerMessageKind::Rendered(success) => {
                assert_eq!(success.submit_url, None);
                assert_eq!(success.submit_body, None);
            }
            _ => panic!("expected Rendered"),
        }
    }

    #[test]
    fn focus_on_an_unknown_tab_is_unchanged_with_no_wake_up_rather_than_an_error() {
        let mut state = state_with(FakeFetcher::new());
        let response = state.handle_message(&focus_msg(999, dom::NodeId(1), 0.0));
        match response.kind {
            ipc::ServerMessageKind::Unchanged {
                next_wake_in_millis,
            } => assert_eq!(next_wake_in_millis, None),
            _ => panic!("expected Unchanged"),
        }
    }

    #[test]
    fn text_input_with_nothing_focused_is_unchanged_rather_than_an_error() {
        let mut fake = FakeFetcher::new();
        fake.register(
            "https://example.com/",
            r#"<html><body><input id="q" value=""></body></html>"#,
        );
        let mut state = state_with(fake);
        state.handle_message(&navigate_msg(1, "https://example.com/"));

        let response =
            state.handle_message(&text_input_msg(1, ipc::TextInputAction::InsertChar('x')));
        assert!(matches!(
            response.kind,
            ipc::ServerMessageKind::Unchanged { .. }
        ));
    }

    #[test]
    fn click_on_an_unknown_tab_is_unchanged_with_no_wake_up_rather_than_an_error() {
        let mut state = state_with(FakeFetcher::new());
        let response = state.handle_message(&click(999, dom::NodeId(1)));
        match response.kind {
            ipc::ServerMessageKind::Unchanged {
                next_wake_in_millis,
            } => assert_eq!(next_wake_in_millis, None),
            _ => panic!("expected Unchanged"),
        }
    }

    #[test]
    fn click_with_an_unresolvable_node_id_on_a_live_tab_is_unchanged_not_an_error() {
        let mut fake = FakeFetcher::new();
        fake.register(
            "https://example.com/",
            "<html><body><p>hi</p></body></html>",
        );
        let mut state = state_with(fake);
        state.handle_message(&navigate_msg(1, "https://example.com/"));

        // A node id that never existed in this tab's current DOM at
        // all (as opposed to one that existed on a PREVIOUS page — see
        // `a_fresh_navigate_replaces_the_previous_sessions_pending_timers`
        // for that angle) — the same "expected race, not a protocol
        // bug" contract as an unknown tab id.
        let response = state.handle_message(&click(1, dom::NodeId(u64::MAX)));
        assert!(matches!(
            response.kind,
            ipc::ServerMessageKind::Unchanged { .. }
        ));
    }

    #[test]
    fn tick_before_a_pending_timer_is_due_reports_unchanged_but_keeps_the_wake_up_armed() {
        let mut fake = FakeFetcher::new();
        fake.register(
            "https://example.com/",
            r#"<html><head><title>Start</title></head><body>
                <script>setTimeout(function() { document.title = 'fired'; }, 10000); </script>
            </body></html>"#,
        );
        let mut state = state_with(fake);
        state.handle_message(&navigate_msg(1, "https://example.com/"));

        let response = state.handle_message(&tick(1));
        match response.kind {
            ipc::ServerMessageKind::Unchanged {
                next_wake_in_millis,
            } => assert!(next_wake_in_millis.is_some()),
            _ => panic!("expected Unchanged"),
        }
    }

    #[test]
    fn tick_after_a_timer_fires_returns_rendered_with_the_mutation() {
        let mut fake = FakeFetcher::new();
        fake.register(
            "https://example.com/",
            r#"<html><head><title>Start</title></head><body>
                <script>setTimeout(function() { document.title = 'fired'; }, 10); </script>
            </body></html>"#,
        );
        let mut state = state_with(fake);
        state.handle_message(&navigate_msg(1, "https://example.com/"));

        std::thread::sleep(std::time::Duration::from_millis(30));
        let response = state.handle_message(&tick(1));
        match response.kind {
            ipc::ServerMessageKind::Rendered(success) => {
                assert_eq!(success.title, Some("fired".to_string()));
                assert_eq!(success.next_wake_in_millis, None);
            }
            _ => panic!("expected Rendered"),
        }
    }

    #[test]
    fn a_fresh_navigate_replaces_the_previous_sessions_pending_timers() {
        let mut fake = FakeFetcher::new();
        fake.register(
            "https://a.example/",
            r#"<html><head><title>A</title></head><body>
                <script>setTimeout(function() { document.title = 'A fired'; }, 10); </script>
            </body></html>"#,
        );
        fake.register(
            "https://b.example/",
            "<html><head><title>B</title></head><body></body></html>",
        );
        let mut state = state_with(fake);

        state.handle_message(&navigate_msg(1, "https://a.example/"));
        state.handle_message(&navigate_msg(1, "https://b.example/"));

        std::thread::sleep(std::time::Duration::from_millis(30));
        let response = state.handle_message(&tick(1));
        // The old page's timer must not resurrect the old title on the
        // new page — a fresh Navigate should have dropped that session.
        assert!(matches!(
            response.kind,
            ipc::ServerMessageKind::Unchanged { .. }
        ));
    }

    #[test]
    fn serve_handles_multiple_tab_scoped_messages_over_one_connection_then_stops_at_eof() {
        let mut fake = FakeFetcher::new();
        fake.register("https://a.example/", "<html><body>a</body></html>");
        fake.register("https://b.example/", "<html><body>b</body></html>");
        let mut state = state_with(fake);

        let mut request_bytes = Vec::new();
        ipc::write_message(&mut request_bytes, &navigate_msg(1, "https://a.example/")).unwrap();
        ipc::write_message(&mut request_bytes, &navigate_msg(2, "https://b.example/")).unwrap();
        ipc::write_message(&mut request_bytes, &close_tab(1)).unwrap();
        // No further message follows — `serve` should see EOF on the
        // next read attempt and return cleanly rather than hanging.

        let mut reader = Cursor::new(request_bytes);
        let mut response_bytes = Vec::new();
        serve(&mut reader, &mut response_bytes, &mut state);

        assert!(!state.is_tab_open(ipc::TabId(1)));
        assert!(state.is_tab_open(ipc::TabId(2)));

        let mut response_reader = Cursor::new(response_bytes);
        let first: ipc::ServerMessage = ipc::read_message(&mut response_reader).unwrap();
        assert_eq!(first.tab_id, ipc::TabId(1));
        assert!(matches!(first.kind, ipc::ServerMessageKind::Rendered(_)));

        let second: ipc::ServerMessage = ipc::read_message(&mut response_reader).unwrap();
        assert_eq!(second.tab_id, ipc::TabId(2));
        assert!(matches!(second.kind, ipc::ServerMessageKind::Rendered(_)));

        let third: ipc::ServerMessage = ipc::read_message(&mut response_reader).unwrap();
        assert_eq!(third.tab_id, ipc::TabId(1));
        assert!(matches!(third.kind, ipc::ServerMessageKind::Closed));
    }
}
