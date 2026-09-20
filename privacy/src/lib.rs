//! `privacy` — the policy engine behind "anonymity browser."
//!
//! This crate has no opinion on *how* requests are made (that's
//! `network`'s job) — it only answers policy questions:
//!   - should this request be blocked? (`Blocklist::is_blocked`)
//!   - what headers should leave the machine? (`normalize_headers`)
//!   - what storage partition does this belong to?
//!     (`StoragePartitionKey::for_request`)
//!   - what window size should the OS report? (`letterbox`)
//!
//! Splitting it out like this means `network` (and later, a settings
//! UI) can consult one place for "what does private mode mean here,"
//! and it's testable without any actual sockets.
//!
//! Scope of this stub, and what's NOT implemented yet:
//!   - **Blocklist** is real now: the `adblock` crate plus bundled
//!     EasyList/EasyPrivacy snapshots, matched by host AND path (see
//!     `Blocklist::is_blocked`) — a manual `extra_blocked_hosts` set is
//!     checked alongside it for ad hoc additions.
//!   - **Storage partitioning** computes a real eTLD+1 via the Public
//!     Suffix List (see `registrable_domain`), not a naive "just the
//!     host as-is" — `example.co.uk` partitions on `example.co.uk`,
//!     not `co.uk`.
//!   - **Fingerprint resistance** covers window-size letterboxing and
//!     header/timezone/locale normalization only. Canvas/WebGL/Audio
//!     readback noise, font-enumeration limits, and JS-exposed
//!     `navigator.*` spoofing all require a JS engine to hook into —
//!     flagged as future work, not missing by accident.
//!   - **WebRTC and other high-leak-risk Web APIs** don't exist yet
//!     either (no JS engine to expose them through), but
//!     `default_web_api_policy()` records the decision now: WebRTC
//!     disabled outright by default (it can reveal real IP addresses
//!     even through a VPN/Tor — this is a leak vector, not a
//!     fingerprinting one), geolocation and battery/sensor APIs
//!     disabled, Canvas/WebGL/AudioContext restricted once they exist.
//!   - **No telemetry, ever, by design**: this codebase has no
//!     analytics/crash-reporting/usage-tracking call sites, and none
//!     should be added — that's a project-level constraint, not
//!     something toggled off in settings. `sync` is the one thing
//!     that leaves the device, and only when the user creates an
//!     account and only as opaque ciphertext (see the `account`/`sync`
//!     crate docs).
//!
//! Next steps, roughly in order of payoff:
//!   1. `is_third_party` (and therefore `should_block`) is host-based
//!      only — it has no notion of same-site-but-different-scheme or
//!      of a resource embedded via a redirect chain that CHANGES
//!      top-level context mid-flight (rare, but not impossible).
//!   2. Once `render`/a JS engine exists: Canvas/WebGL noise, font
//!      allowlist, `navigator.*` spoofing to match the letterboxed
//!      "everyone looks the same" identity.

use adblock::{lists::ParseOptions, request::Request, Engine, FilterSet};
use std::collections::HashSet;
use std::sync::Arc;

/// A single origin's request context, as seen by the privacy policy:
/// where the resource lives, and what page embedded it. Third-party
/// checks and storage partitioning both key off `request_host`/
/// `top_level_host`; `Blocklist::is_blocked` additionally needs
/// `request_path`, since real tracker lists increasingly ship
/// path-specific rules (a tracker living at a specific path on an
/// otherwise-legitimate, unblockable domain), not just domain-anchored
/// ones.
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// The host actually being requested, e.g. "ads.example.com".
    pub request_host: String,
    /// The path (plus query string, if any) of the resource being
    /// requested, e.g. "/ads/banner.js" — always starting with `/`.
    /// Callers that only have a bare hostname (no real request in
    /// hand) should pass `"/"` rather than guessing.
    pub request_path: String,
    /// The host in the address bar, e.g. "news.example.com".
    /// `None` for a top-level navigation (the request *is* the page).
    pub top_level_host: Option<String>,
}

impl RequestContext {
    pub fn is_third_party(&self) -> bool {
        match &self.top_level_host {
            Some(top) => top != &self.request_host,
            None => false,
        }
    }
}

/// Bundled EasyList + EasyPrivacy snapshots, compiled into the binary
/// via `include_str!` so blocking works fully offline with no runtime
/// fetch of the lists (fetching a blocklist over the network on every
/// startup is itself a small tracking-adjacent signal, plus adds
/// latency/a failure mode). Refresh by re-downloading the two URLs
/// above into `privacy/assets/` and rebuilding.
const EASYLIST: &str = include_str!("../assets/easylist.txt");
const EASYPRIVACY: &str = include_str!("../assets/easyprivacy.txt");

/// Real EasyList/EasyPrivacy matching via the `adblock` crate.
pub struct Blocklist {
    engine: Arc<Engine>,
    /// Manual additions beyond the loaded lists (e.g. `block()` below) —
    /// checked first, cheaply, alongside the real engine.
    extra_blocked_hosts: HashSet<String>,
}

impl Default for Blocklist {
    fn default() -> Self {
        Blocklist {
            engine: Arc::new(Engine::default()),
            extra_blocked_hosts: HashSet::new(),
        }
    }
}

impl Clone for Blocklist {
    fn clone(&self) -> Self {
        Blocklist {
            engine: Arc::clone(&self.engine),
            extra_blocked_hosts: self.extra_blocked_hosts.clone(),
        }
    }
}

impl std::fmt::Debug for Blocklist {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Blocklist").finish_non_exhaustive()
    }
}

impl Blocklist {
    pub fn new() -> Self {
        Self::default()
    }

    /// Real EasyList + EasyPrivacy, loaded from the bundled snapshot.
    pub fn with_seed_list() -> Self {
        let mut filter_set = FilterSet::new(false);
        filter_set.add_filter_list(EASYLIST.to_string(), ParseOptions::default());
        filter_set.add_filter_list(EASYPRIVACY.to_string(), ParseOptions::default());
        Blocklist {
            engine: Arc::new(Engine::new_with_filter_set(filter_set)),
            extra_blocked_hosts: HashSet::new(),
        }
    }

    /// Builds a blocklist from arbitrary filter-list text (Adblock Plus/
    /// uBlock syntax) instead of the bundled EasyList/EasyPrivacy
    /// snapshot. Mainly for tests that need one specific, stable rule to
    /// assert against, rather than depending on whatever happens to be
    /// in the bundled lists (which can be refreshed independently of
    /// this code) at any given time.
    pub fn from_filter_text(text: &str) -> Self {
        let mut filter_set = FilterSet::new(false);
        filter_set.add_filter_list(text.to_string(), ParseOptions::default());
        Blocklist {
            engine: Arc::new(Engine::new_with_filter_set(filter_set)),
            extra_blocked_hosts: HashSet::new(),
        }
    }

    pub fn block(&mut self, host: &str) {
        self.extra_blocked_hosts.insert(host.to_lowercase());
    }

    /// Checks `host` + `path` against both the manual block-list and
    /// the real EasyList/EasyPrivacy engine. `path` matters: real
    /// tracker lists increasingly ship path-specific rules (a tracker
    /// living at a specific path on an otherwise-legitimate,
    /// unblockable domain — a bare-hostname check can never catch
    /// that), not just domain-anchored ones like `||doubleclick.net^`.
    /// Callers with no real path in hand (e.g. checking a bare
    /// hostname with no actual request) should pass `"/"`.
    pub fn is_blocked(&self, host: &str, path: &str) -> bool {
        let host = host.to_lowercase();
        if self.extra_blocked_hosts.contains(&host) {
            return true;
        }
        let path = if path.starts_with('/') { path } else { "/" };
        let target_url = format!("https://{host}{path}");
        // Always evaluated as an unrelated THIRD-PARTY subresource load: this
        // method only ever gets called after something upstream (e.g.
        // `privacy::should_block`) has already decided the request is
        // third-party, and most EasyList/EasyPrivacy tracker rules are
        // scoped to third-party + non-document types (script/xhr/image) —
        // the previous same-origin "document" check matched almost nothing.
        const PLACEHOLDER_SOURCE: &str = "https://a-different-site.com/";
        match Request::new(&target_url, PLACEHOLDER_SOURCE, "script", "GET") {
            Ok(request) => self.engine.check_network_request(&request).should_block(),
            Err(_) => false,
        }
    }
}

/// Decide whether a request should be blocked outright. Third-party
/// requests to a blocklisted host/path are blocked; first-party
/// requests are always allowed through this check (first-party
/// tracking is a storage-partitioning problem, not a blocklist
/// problem).
pub fn should_block(ctx: &RequestContext, blocklist: &Blocklist) -> bool {
    ctx.is_third_party() && blocklist.is_blocked(&ctx.request_host, &ctx.request_path)
}

/// Storage (cookies, localStorage, cache) is keyed by BOTH the
/// resource's own host AND the top-level site that embedded it, so
/// `tracker.com` storage set while browsing `siteA.com` is invisible
/// to `tracker.com` embedded on `siteB.com`. This is the "Total
/// Cookie Protection" / storage-partitioning model.
///
/// TODO: `top_level_site` should be an eTLD+1 computed via the Public
/// Suffix List, not a raw host — see module docs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StoragePartitionKey {
    pub top_level_site: String,
    pub resource_host: String,
}

impl StoragePartitionKey {
    pub fn for_request(ctx: &RequestContext) -> Self {
        StoragePartitionKey {
            top_level_site: ctx
                .top_level_host
                .as_deref()
                .map(registrable_domain)
                .unwrap_or_else(|| registrable_domain(&ctx.request_host)),
            resource_host: ctx.request_host.clone(),
        }
    }
}

/// The eTLD+1 for `host` via the real Public Suffix List. Falls back
/// to the host as-is for things that aren't real registrable domains
/// (bare IPs, `localhost`, a host that's itself just a public suffix).
///
/// `pub` (not just crate-internal) because `app` uses this same
/// registrable-domain notion of "site" to decide which sandboxed
/// renderer PROCESS a tab's page belongs to (see `app`'s
/// `RendererPool`/site-isolation doc comments) — the same boundary
/// that already governs storage partitioning and third-party
/// classification here, reused rather than reinvented for process
/// isolation specifically.
pub fn registrable_domain(host: &str) -> String {
    let bare_host = host.split(':').next().unwrap_or(host);
    addr::parse_domain_name(bare_host)
        .ok()
        .and_then(|d| d.root().map(str::to_string))
        .unwrap_or_else(|| bare_host.to_string())
}

/// A fixed, non-unique header set. Every user of this browser sends
/// the same `User-Agent`/`Accept-Language` — the goal (straight out
/// of the Tor Browser / Mullvad Browser playbook) is that no single
/// user's headers stand out from anyone else's.
///
/// TODO: this needs to be updated in lockstep across all users when
/// the "real" version changes, or the frozen UA itself becomes a
/// fingerprint (this is why Tor Browser ships UA updates on a slow,
/// coordinated schedule rather than per-build).
pub fn normalize_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
        ),
        ("Accept-Language", "en-US,en;q=0.5"),
        // TODO: strip/omit Referer cross-origin instead of sending
        // the full referring URL; at minimum trim to origin-only.
    ]
}

/// Strip common cross-site tracking parameters from a URL's query
/// string before it's fetched or stored in history/bookmarks.
/// TODO: this is a fixed prefix list; a real implementation should
/// pull from a maintained list (e.g. Brave's "query filter" list)
/// since trackers invent new param names constantly.
pub fn strip_tracking_params(url: &str) -> String {
    const TRACKING_PREFIXES: &[&str] = &["utm_", "fbclid", "gclid", "msclkid", "mc_eid"];

    let Some((base, query)) = url.split_once('?') else {
        return url.to_string();
    };

    let kept: Vec<&str> = query
        .split('&')
        .filter(|pair| {
            let key = pair.split('=').next().unwrap_or("");
            !TRACKING_PREFIXES
                .iter()
                .any(|prefix| key.starts_with(prefix))
        })
        .collect();

    if kept.is_empty() {
        base.to_string()
    } else {
        format!("{base}?{}", kept.join("&"))
    }
}

/// Round a window size down to fixed buckets so window dimensions
/// can't be used as a fingerprinting signal — the same "letterboxing"
/// technique Tor Browser / Mullvad Browser use: the content area is
/// padded/pillarboxed to the nearest bucket rather than exactly
/// filling whatever size the user resized the window to.
pub fn letterbox(width: u32, height: u32) -> (u32, u32) {
    const BUCKET: u32 = 100;
    let round_down = |v: u32| (v / BUCKET).max(1) * BUCKET;
    (round_down(width), round_down(height))
}

/// How aggressively window-size fingerprint resistance is applied —
/// exposed as a real settings-UI choice (`app`'s "Fingerprint
/// resistance" setting) rather than baked in, because it's a genuine,
/// honest tradeoff rather than a strictly-better/worse toggle:
/// `Strict` (the default, matching Tor Browser/Mullvad Browser) makes
/// every user's window report one of a small number of fixed sizes,
/// at the cost of visible letterboxing bars whenever the window
/// doesn't land on a bucket exactly; `Standard` reports the real size
/// (e.g. for someone who wants pixel-exact screenshots and knowingly
/// accepts that window size becomes a fingerprinting signal again).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FingerprintResistanceLevel {
    #[default]
    Strict,
    Standard,
}

impl FingerprintResistanceLevel {
    /// Canonical lowercase name — what a settings UI stores/displays;
    /// `parse` is its exact inverse.
    pub fn as_str(self) -> &'static str {
        match self {
            FingerprintResistanceLevel::Strict => "strict",
            FingerprintResistanceLevel::Standard => "standard",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "strict" => Some(FingerprintResistanceLevel::Strict),
            "standard" => Some(FingerprintResistanceLevel::Standard),
            _ => None,
        }
    }

    /// Applies this level's policy to a raw, real window size: `Strict`
    /// letterboxes it (see `letterbox`); `Standard` passes it through
    /// unchanged. This is the one call site `app` needs — callers
    /// never have to branch on the level themselves.
    pub fn resolve_window_size(self, width: u32, height: u32) -> (u32, u32) {
        match self {
            FingerprintResistanceLevel::Strict => letterbox(width, height),
            FingerprintResistanceLevel::Standard => (width, height),
        }
    }
}

/// A fixed timezone/locale identity, matching the header normalization
/// above. Real OS timezone/locale are high-entropy fingerprint
/// signals; a JS-facing `Intl`/`Date` implementation should report
/// this instead of the host OS's actual settings.
pub const SPOOFED_TIMEZONE: &str = "UTC";
pub const SPOOFED_LOCALE: &str = "en-US";

/// How a given Web API should behave once one exists to enforce this
/// against. There is no JS engine or WebRTC stack in this scaffold
/// yet (see the `javascript`/`webapis` milestones in the README) — this
/// enum and `default_web_api_policy()` exist so the *decision* is made
/// and documented now, rather than left as an unstated assumption that
/// whoever adds WebRTC later has to rediscover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiAccess {
    /// Fully disabled — the API is not exposed to script at all.
    Disabled,
    /// Exposed, but restricted to reduce fingerprinting/leak surface
    /// (see the per-API notes in `default_web_api_policy`).
    Restricted,
}

/// The default policy for high-risk Web APIs, keyed by API name.
///
/// **WebRTC is the important one here.** WebRTC's ICE candidate
/// gathering can reveal a user's real local/public IP address even
/// through a VPN or Tor, by design — it's one of the most well-known
/// deanonymization vectors in browsers, independent of cookies or
/// fingerprinting entirely. Mullvad Browser and Tor Browser both
/// disable WebRTC outright rather than trying to "sanitize" it, and
/// that's the default here too: `Restricted` mode (relay-only
/// candidates, no host/srflx candidates) is documented as an option
/// for a future "allow video calls" toggle, but `Disabled` is what
/// ships by default.
///
/// Also disabled by default: precise geolocation (rarely needed, high
/// signal), and battery/sensor APIs (classic low-value, high-entropy
/// fingerprint vectors — Firefox itself removed the Battery Status API
/// for exactly this reason).
pub fn default_web_api_policy() -> Vec<(&'static str, ApiAccess)> {
    vec![
        ("webrtc", ApiAccess::Disabled),
        ("geolocation", ApiAccess::Disabled),
        ("battery_status", ApiAccess::Disabled),
        ("ambient_light_sensor", ApiAccess::Disabled),
        // Canvas/WebGL/AudioContext stay *available* (real pages need
        // them) but are `Restricted`: readback should be noised, per
        // the module docs' "Canvas/WebGL/Audio readback noise" TODO.
        ("canvas_readback", ApiAccess::Restricted),
        ("webgl_readback", ApiAccess::Restricted),
        ("audio_context", ApiAccess::Restricted),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_third_party_tracker_but_not_first_party() {
        let blocklist = Blocklist::with_seed_list();

        let third_party = RequestContext {
            request_host: "g.doubleclick.net".to_string(),
            request_path: "/".to_string(),
            top_level_host: Some("news.example.com".to_string()),
        };
        assert!(should_block(&third_party, &blocklist));

        let first_party = RequestContext {
            request_host: "news.example.com".to_string(),
            request_path: "/".to_string(),
            top_level_host: Some("news.example.com".to_string()),
        };
        assert!(!should_block(&first_party, &blocklist));
    }

    #[test]
    fn partitions_same_tracker_by_embedding_site() {
        let ctx_a = RequestContext {
            request_host: "tracker.com".to_string(),
            request_path: "/".to_string(),
            top_level_host: Some("siteA.com".to_string()),
        };
        let ctx_b = RequestContext {
            request_host: "tracker.com".to_string(),
            request_path: "/".to_string(),
            top_level_host: Some("siteB.com".to_string()),
        };
        assert_ne!(
            StoragePartitionKey::for_request(&ctx_a),
            StoragePartitionKey::for_request(&ctx_b)
        );
    }

    #[test]
    fn strips_tracking_params_but_keeps_the_rest() {
        let cleaned = strip_tracking_params(
            "https://example.com/page?id=42&utm_source=newsletter&fbclid=abc",
        );
        assert_eq!(cleaned, "https://example.com/page?id=42");
    }

    #[test]
    fn letterboxes_window_size_to_fixed_buckets() {
        assert_eq!(letterbox(1437, 892), (1400, 800));
        assert_eq!(letterbox(1440, 900), (1400, 900));
    }

    #[test]
    fn fingerprint_resistance_level_as_str_and_parse_round_trip() {
        assert_eq!(
            FingerprintResistanceLevel::parse(FingerprintResistanceLevel::Strict.as_str()),
            Some(FingerprintResistanceLevel::Strict)
        );
        assert_eq!(
            FingerprintResistanceLevel::parse(FingerprintResistanceLevel::Standard.as_str()),
            Some(FingerprintResistanceLevel::Standard)
        );
        assert_eq!(FingerprintResistanceLevel::parse("bogus"), None);
    }

    #[test]
    fn strict_resistance_letterboxes_but_standard_passes_the_real_size_through() {
        assert_eq!(
            FingerprintResistanceLevel::Strict.resolve_window_size(1437, 892),
            (1400, 800)
        );
        assert_eq!(
            FingerprintResistanceLevel::Standard.resolve_window_size(1437, 892),
            (1437, 892)
        );
    }

    #[test]
    fn webrtc_is_disabled_by_default() {
        let policy = default_web_api_policy();
        let webrtc = policy.iter().find(|(name, _)| *name == "webrtc");
        assert_eq!(webrtc.map(|(_, access)| *access), Some(ApiAccess::Disabled));
    }

    #[test]
    fn computes_the_correct_etld_plus_one_for_a_multi_part_public_suffix() {
        let ctx = RequestContext {
            request_host: "shop.example.co.uk".to_string(),
            request_path: "/".to_string(),
            top_level_host: Some("shop.example.co.uk".to_string()),
        };
        assert_eq!(
            StoragePartitionKey::for_request(&ctx).top_level_site,
            "example.co.uk"
        );
    }

    #[test]
    fn is_blocked_matches_a_path_specific_rule_not_just_the_bare_host() {
        // A path-anchored rule (the same shape real EasyList rules use
        // for a tracker living at a specific path on an otherwise-
        // legitimate domain) — proves `path` actually reaches the
        // matching engine instead of being silently ignored, which a
        // bare-hostname-only check (the old signature) could never do.
        let blocklist = Blocklist::from_filter_text("||example.com/ads/tracker.js\n");

        assert!(blocklist.is_blocked("example.com", "/ads/tracker.js"));
        assert!(!blocklist.is_blocked("example.com", "/harmless/page.html"));
    }

    #[test]
    fn should_block_passes_the_real_request_path_through() {
        let blocklist = Blocklist::from_filter_text("||example.com/ads/tracker.js\n");

        let blocked_path = RequestContext {
            request_host: "example.com".to_string(),
            request_path: "/ads/tracker.js".to_string(),
            top_level_host: Some("news.example.org".to_string()),
        };
        assert!(should_block(&blocked_path, &blocklist));

        let harmless_path = RequestContext {
            request_host: "example.com".to_string(),
            request_path: "/harmless/page.html".to_string(),
            top_level_host: Some("news.example.org".to_string()),
        };
        assert!(!should_block(&harmless_path, &blocklist));
    }
}
