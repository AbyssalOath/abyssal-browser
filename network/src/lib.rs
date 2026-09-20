//! `network` — fetches resources (pages, stylesheets, images, ...).
//!
//! Real HTTP now: `HttpFetcher` wraps `reqwest::blocking::Client` for
//! actual DNS/TLS/HTTP(1.1+2) requests, and now resolves hostnames via
//! DNS-over-HTTPS instead of the OS's plaintext resolver (see
//! `HttpFetcher::resolve_via_doh`) — plain DNS is famously
//! unencrypted, so without this, every hostname visited leaks to
//! whoever's watching the network (an ISP, a coffee-shop Wi-Fi
//! operator, a compromised router) even though the HTTPS request that
//! follows is itself encrypted. It sits behind the same privacy
//! plumbing as always:
//!   - `FilteringFetcher`: wraps any `Fetcher` and consults
//!     `privacy::should_block` before letting a request through —
//!     third-party requests to a blocklisted host/path never leave
//!     this layer.
//!   - `HttpFetcher` itself also checks every REDIRECT hop the same
//!     way (see its docs) — `FilteringFetcher` only ever sees the
//!     initial URL, so without this a tracker could sneak in via a 3xx
//!     chain `FilteringFetcher` never inspects. Both the initial
//!     request and every redirect hop use the exact same
//!     `privacy::should_block` call with the exact same top-level-host
//!     context, so a redirect to the requesting site's OWN subdomain
//!     is correctly treated as first-party rather than blocked outright.
//!   - `PartitionedCookieJar`: stores cookies keyed by
//!     `privacy::StoragePartitionKey` (top-level site + resource
//!     host), not just by host — so the same tracker embedded on two
//!     different sites can't correlate a user across them via cookies.
//!     Real now, wired through `FilteringFetcher::fetch_in_context`:
//!     `cookie_header_for` supplies the outgoing `Cookie` header,
//!     every `Set-Cookie` in the response is stored back via
//!     `store_set_cookie`. Persisted to disk now too, but not by this
//!     crate or by `renderer` — the sandboxed renderer process reports
//!     its own real, plaintext `to_bytes()` back to `app` over the
//!     existing IPC channel (`ipc::ServerMessage::updated_cookies`),
//!     and `app` (the only process that ever holds the account's
//!     encryption key) is what actually encrypts and writes
//!     `cookies.enc`, and decrypts and seeds a freshly-spawned
//!     renderer from it (`ipc::RenderRequest::initial_cookies`) — see
//!     those two fields' own doc comments for the full reasoning. In
//!     the small window before that first reply, cookies are
//!     in-memory only inside whichever renderer process handles a
//!     given site.
//!   - `disk_cache::DiskCache`: an on-disk response cache, partitioned
//!     by the SAME `StoragePartitionKey` the cookie jar uses — an
//!     unpartitioned cache would itself be a cross-site tracking
//!     side-channel (see that module's docs). Opt-in via
//!     `FilteringFetcher::enable_disk_cache`; only caches responses
//!     that explicitly opt in via `Cache-Control: max-age=N`.
//!   - Every fetch goes through `privacy::normalize_headers` (fixed,
//!     non-unique `User-Agent`/`Accept-Language` — see `HttpFetcher::new`)
//!     and `privacy::strip_tracking_params` (via
//!     `FilteringFetcher::fetch_in_context`).
//!
//! DNS-over-HTTPS specifics (see `HttpFetcher::resolve_via_doh`):
//! queries Cloudflare's JSON DoH API (`cloudflare-dns.com/dns-query`)
//! over HTTPS. To reach that hostname AT ALL without a chicken-and-egg
//! dependency on the very plaintext DNS this feature exists to avoid,
//! the DoH server's own hostname is pinned to a hardcoded, well-known
//! IP (`1.1.1.1`/`1.0.0.1`) — every DoH client does this same
//! bootstrap trick. Once the target hostname's IP comes back from
//! that query, it's used to override reqwest's own resolution for
//! that hostname via `ClientBuilder::resolve` (a real reqwest builder
//! method, not a fake stand-in) — so the ACTUAL page/resource request
//! that follows also never touches the OS's plaintext resolver.
//!
//! Deliberately fails CLOSED: if the DoH lookup itself fails (network
//! issue reaching Cloudflare, malformed response, no A record), the
//! whole fetch fails rather than silently falling back to plaintext
//! DNS. That's a privacy-over-availability tradeoff worth being
//! explicit about — a real product might want a user-facing setting
//! for "fail open" instead, trading some privacy for reliability, but
//! failing closed is the honest default for something called a
//! privacy browser.
//!
//! Next steps, roughly in order of payoff:
//!   1. `PartitionedCookieJar` has no `SameSite`/`Secure`/`HttpOnly`/
//!      expiry handling at all — every cookie is treated as a plain
//!      session-lifetime name=value pair regardless of what its
//!      `Set-Cookie` attributes actually said.
//!   2. Respect `Content-Type`/charset instead of assuming UTF-8.
//!   3. `disk_cache::DiskCache` has no size limit/eviction and no
//!      ETag/`Vary` revalidation — see that module's own docs for
//!      exactly what "not a full RFC 7234 cache" means here.

mod disk_cache;

use std::cell::RefCell;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use std::time::Instant;

use disk_cache::DiskCache;
use privacy::{should_block, Blocklist, RequestContext, StoragePartitionKey};

#[derive(Debug)]
pub enum FetchError {
    NotFound(String),
    Blocked(String),
    /// A transport-level failure: DNS-over-HTTPS lookup failure, TLS/
    /// certificate errors, timeouts, connection refused, etc. The
    /// `String` is a human-readable message (often `reqwest`'s own
    /// error text) — not parsed into finer-grained variants yet (see
    /// module docs' TODO list for the general shape of what's still
    /// missing).
    Network(String),
}

pub struct Response {
    pub status: u16,
    /// Raw response bytes — NOT assumed to be UTF-8 text, since this
    /// is also how image bytes cross this boundary (see `renderer`'s
    /// image-decoding pipeline). A caller that needs text (HTML, JS)
    /// converts explicitly at the point of use (`String::from_utf8_lossy`
    /// — lossy, not `Result`-returning, since a malformed/mislabeled
    /// text response should degrade to replacement characters rather
    /// than fail the whole fetch outright).
    pub body: Vec<u8>,
    pub set_cookies: Vec<String>,
    /// The response's own `Cache-Control` header value, verbatim, if
    /// present — `FilteringFetcher::fetch_in_context` is what actually
    /// decides whether/how long to cache from this (see
    /// `disk_cache::parse_max_age`); this crate's fetchers just carry
    /// the header through unparsed.
    pub cache_control: Option<String>,
}

/// Anything that can turn a URL into a `Response`. `FakeFetcher` (for
/// tests) and `HttpFetcher` (real HTTP) both implement this, so
/// `FilteringFetcher` and everything upstream of it never needs to
/// know which one it's holding. `top_level_host` is threaded all the
/// way down here (not just to `FilteringFetcher::fetch_in_context`) so
/// `HttpFetcher` can apply the exact same first-party/third-party
/// logic to redirect hops that `FilteringFetcher` applies to the
/// initial request — see `HttpFetcher::fetch`'s doc comment.
pub trait Fetcher {
    /// `body` is `Some` only for a POST form submission (see
    /// `FilteringFetcher::fetch_in_context_with_body`) — its bytes are
    /// sent as the request body with `Content-Type:
    /// application/x-www-form-urlencoded`, the one encoding real HTML
    /// forms use by default and the only one this crate builds (no
    /// `multipart/form-data`, so a real file-upload `<form>` still
    /// won't work — see `renderer::script::Session::
    /// build_form_submission`'s own doc comment). `None` is an
    /// ordinary GET, the case that existed before this parameter did.
    fn fetch(
        &self,
        url: &str,
        top_level_host: Option<&str>,
        cookie_header: Option<&str>,
        body: Option<&[u8]>,
    ) -> Result<Response, FetchError>;
}

/// A registered fake response: a body plus an optional `Cache-Control`
/// value, so tests can exercise `DiskCache` wiring (which reads that
/// header) without a real network round trip.
#[derive(Clone)]
struct FakeResponse {
    body: Vec<u8>,
    cache_control: Option<String>,
    set_cookies: Vec<String>,
}

/// An in-memory "fetcher" for tests and early development — register
/// fixed responses instead of hitting the network. `Clone` (like
/// `HttpFetcher`'s own) is what lets `renderer::images` give each of
/// its concurrent image-fetching worker threads an independent copy —
/// see `FilteringFetcher::clone_for_concurrent_use`'s own doc comment.
#[derive(Default, Clone)]
pub struct FakeFetcher {
    responses: HashMap<String, FakeResponse>,
    /// Every `fetch` call's `(url, body)`, in order — lets a test
    /// assert what was ACTUALLY sent (e.g. a POST form's real
    /// URL-encoded body) rather than only what came back. `RefCell`
    /// because `Fetcher::fetch` takes `&self`, matching `HttpFetcher`'s
    /// own real, unavoidable interior mutability need (its DNS cache).
    requests: RefCell<Vec<(String, Option<Vec<u8>>)>>,
}

impl FakeFetcher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, url: &str, body: &str) {
        self.responses.insert(
            url.to_string(),
            FakeResponse {
                body: body.as_bytes().to_vec(),
                cache_control: None,
                set_cookies: Vec::new(),
            },
        );
    }

    /// Same as `register`, but for raw (possibly non-UTF-8) bytes — a
    /// real decoded image's fake fetch response, for instance, where
    /// `register`'s `&str` parameter simply couldn't hold the bytes at
    /// all.
    pub fn register_bytes(&mut self, url: &str, body: Vec<u8>) {
        self.responses.insert(
            url.to_string(),
            FakeResponse {
                body,
                cache_control: None,
                set_cookies: Vec::new(),
            },
        );
    }

    /// Same as `register`, but also sets a `Cache-Control` value on the
    /// fake response — for tests that need to exercise `DiskCache`
    /// wiring, which only ever caches a response that explicitly opts
    /// in via this header (see `disk_cache::parse_max_age`).
    pub fn register_with_cache_control(&mut self, url: &str, body: &str, cache_control: &str) {
        self.responses.insert(
            url.to_string(),
            FakeResponse {
                body: body.as_bytes().to_vec(),
                cache_control: Some(cache_control.to_string()),
                set_cookies: Vec::new(),
            },
        );
    }

    /// Same as `register`, but also attaches one or more raw
    /// `Set-Cookie` header values to the fake response — for tests
    /// that need to exercise `PartitionedCookieJar` wiring (see
    /// `FilteringFetcher::fetch_in_context`) without a real server.
    pub fn register_with_set_cookie(&mut self, url: &str, body: &str, set_cookies: &[&str]) {
        self.responses.insert(
            url.to_string(),
            FakeResponse {
                body: body.as_bytes().to_vec(),
                cache_control: None,
                set_cookies: set_cookies.iter().map(|s| s.to_string()).collect(),
            },
        );
    }

    /// The body of the MOST RECENT `fetch` call to `url` (`None` if
    /// that call's own `body` was `None` — an ordinary GET — or if
    /// `url` was never fetched at all) — see `requests`'s own doc
    /// comment.
    pub fn last_request_body(&self, url: &str) -> Option<Vec<u8>> {
        self.requests
            .borrow()
            .iter()
            .rev()
            .find(|(u, _)| u == url)
            .and_then(|(_, body)| body.clone())
    }
}

impl Fetcher for FakeFetcher {
    fn fetch(
        &self,
        url: &str,
        _top_level_host: Option<&str>,
        _cookie_header: Option<&str>,
        body: Option<&[u8]>,
    ) -> Result<Response, FetchError> {
        self.requests
            .borrow_mut()
            .push((url.to_string(), body.map(|b| b.to_vec())));
        self.responses
            .get(url)
            .map(|r| Response {
                status: 200,
                body: r.body.clone(),
                set_cookies: r.set_cookies.clone(),
                cache_control: r.cache_control.clone(),
            })
            .ok_or_else(|| FetchError::NotFound(url.to_string()))
    }
}

/// Hostname of Cloudflare's DNS-over-HTTPS resolver.
const DOH_RESOLVER_HOST: &str = "cloudflare-dns.com";
/// Hardcoded, well-known IPs for the DoH resolver itself — see module
/// docs for why this bootstrap step can't itself go through DNS.
const DOH_RESOLVER_IPS: &[&str] = &["1.1.1.1", "1.0.0.1"];

/// A real HTTP client, backed by `reqwest::blocking::Client` (TLS via
/// rustls, HTTP/1.1+2 all handled by reqwest — see this crate's
/// Cargo.toml). `blocking` keeps this synchronous, matching the
/// `Fetcher` trait — no async runtime threaded through `app`. DNS goes
/// through `resolve_via_doh` instead of the OS resolver — see module
/// docs.
///
/// `Clone` (cheap: `reqwest::blocking::Client` is internally `Arc`-based
/// and designed to be cloned/shared, and every other field is a plain
/// value or a small cache) is what lets `renderer::images` give each of
/// its concurrent image-fetching worker threads an independent copy —
/// see `FilteringFetcher::clone_for_concurrent_use`'s own doc comment
/// for why a CLONE, not a shared reference: `dns_cache`'s `RefCell`
/// makes plain `&HttpFetcher` unsound to access from more than one
/// thread at once, so each thread gets its own owned instance (and so
/// its own, separately-warmed DNS cache) instead.
#[derive(Clone)]
pub struct HttpFetcher {
    headers: reqwest::header::HeaderMap,
    redirect_blocklist: Blocklist,
    doh_client: reqwest::blocking::Client,
    /// DoH answers cached by their own TTL, so a page with many
    /// same-host resources doesn't re-query Cloudflare on every single
    /// fetch. `RefCell` because `Fetcher::fetch` takes `&self`, not
    /// `&mut self`, and this cache is purely an internal optimization,
    /// not part of the fetcher's externally-visible behavior.
    dns_cache: RefCell<HashMap<String, CachedDnsAnswer>>,
}

#[derive(Clone)]
struct CachedDnsAnswer {
    ip: IpAddr,
    expires_at: Instant,
}

impl HttpFetcher {
    /// `redirect_blocklist` is consulted on every redirect hop, not
    /// just the initial URL — `FilteringFetcher::fetch_in_context`
    /// only ever sees the URL it was asked to fetch, so without this,
    /// a tracker could sit behind a 3xx redirect chain and never be
    /// checked at all. Each hop is judged via `redirect_should_block`,
    /// which applies the SAME first-party/third-party (and path-aware)
    /// logic `FilteringFetcher` applies to the initial request — a
    /// redirect to the requesting site's own subdomain is correctly
    /// treated as first-party, not blocked outright.
    pub fn new(redirect_blocklist: Blocklist) -> Self {
        let headers = build_normalized_headers();

        let mut doh_builder = reqwest::blocking::Client::builder()
            .default_headers(headers.clone())
            .timeout(Duration::from_secs(10));
        for ip in DOH_RESOLVER_IPS {
            if let Ok(addr) = ip.parse::<IpAddr>() {
                // Port 0 means "use whatever port the URL/scheme
                // implies" (443 for https here) — see reqwest's own
                // doc comment on `resolve`/`resolve_to_addrs`.
                doh_builder = doh_builder.resolve(DOH_RESOLVER_HOST, SocketAddr::new(addr, 0));
            }
        }
        let doh_client = doh_builder
            .build()
            .expect("building the DoH client with static configuration should never fail");

        HttpFetcher {
            headers,
            redirect_blocklist,
            doh_client,
            dns_cache: RefCell::new(HashMap::new()),
        }
    }

    /// Resolves `hostname` via DNS-over-HTTPS, trying an A record
    /// first and falling back to AAAA (IPv6) if there's no A record —
    /// this is what makes IPv6-only sites work at all, not just
    /// dual-stack ones. Caches the answer by its own DNS TTL so a page
    /// with many same-host resources doesn't re-query Cloudflare every
    /// single fetch. Still fails closed overall (see module docs) if
    /// NEITHER record type resolves.
    fn resolve_via_doh(&self, hostname: &str) -> Result<IpAddr, FetchError> {
        if let Some(cached) = self.dns_cache.borrow().get(hostname) {
            if cached.expires_at > Instant::now() {
                return Ok(cached.ip);
            }
        }

        let (ip, ttl_secs) = self
            .query_doh(hostname, "A")
            .or_else(|_| self.query_doh(hostname, "AAAA"))?;

        self.dns_cache.borrow_mut().insert(
            hostname.to_string(),
            CachedDnsAnswer {
                ip,
                expires_at: Instant::now() + Duration::from_secs(ttl_secs.max(1)),
            },
        );
        Ok(ip)
    }

    fn query_doh(&self, hostname: &str, record_type: &str) -> Result<(IpAddr, u64), FetchError> {
        let url =
            format!("https://{DOH_RESOLVER_HOST}/dns-query?name={hostname}&type={record_type}");
        let resp = self
            .doh_client
            .get(&url)
            .header("Accept", "application/dns-json")
            .send()
            .map_err(|e| {
                FetchError::Network(format!(
                    "DoH {record_type} query for {hostname} failed: {e}"
                ))
            })?;

        let body = resp
            .text()
            .map_err(|e| FetchError::Network(format!("DoH response read failed: {e}")))?;

        parse_first_answer(&body, record_type).ok_or_else(|| {
            FetchError::Network(format!(
                "DoH lookup for {hostname} returned no usable {record_type} record"
            ))
        })
    }
}

/// Pure parsing logic pulled out of `query_doh` so it's testable
/// without a real network call. `record_type` is `"A"` (DNS type 1) or
/// `"AAAA"` (DNS type 28) — returns that record's address and TTL
/// (seconds), if present.
fn parse_first_answer(body: &str, record_type: &str) -> Option<(IpAddr, u64)> {
    let type_code = match record_type {
        "A" => 1,
        "AAAA" => 28,
        _ => return None,
    };
    let json: serde_json::Value = serde_json::from_str(body).ok()?;
    let answer = json
        .get("Answer")?
        .as_array()?
        .iter()
        .find(|answer| answer.get("type").and_then(|t| t.as_i64()) == Some(type_code))?;
    let ip = answer.get("data")?.as_str()?.parse::<IpAddr>().ok()?;
    let ttl = answer.get("TTL").and_then(|t| t.as_u64()).unwrap_or(60);
    Some((ip, ttl))
}

fn build_normalized_headers() -> reqwest::header::HeaderMap {
    let mut headers = reqwest::header::HeaderMap::new();
    for (name, value) in privacy::normalize_headers() {
        if let (Ok(header_name), Ok(header_value)) = (
            reqwest::header::HeaderName::from_bytes(name.as_bytes()),
            reqwest::header::HeaderValue::from_str(value),
        ) {
            headers.insert(header_name, header_value);
        }
    }
    headers
}

/// A hard cap on how many redirect hops `HttpFetcher::fetch` will
/// follow in one request — matches common real-browser limits (Firefox
/// caps at 20; this is intentionally stricter) and exists purely to
/// bound a malicious/broken redirect chain, not to be hit in practice.
const MAX_REDIRECTS: u8 = 10;

impl Fetcher for HttpFetcher {
    fn fetch(
        &self,
        url: &str,
        top_level_host: Option<&str>,
        cookie_header: Option<&str>,
        body: Option<&[u8]>,
    ) -> Result<Response, FetchError> {
        // Redirects are followed MANUALLY, one hop at a time, rather
        // than handing reqwest a `redirect::Policy` and letting it
        // follow automatically — `.resolve(...)` below only pins DNS
        // for THIS hop's own host. A `reqwest::redirect::Policy` that
        // just returns follow/stop gives no way to also pin a NEW
        // resolved IP for whatever host the next hop lands on, so an
        // automatically-followed cross-host redirect (extremely
        // common in practice — bare domain to `www.`, `http` to
        // `https`, a CDN host, ...) would fall through to reqwest's
        // default resolver (hyper-util's `GaiResolver`, real
        // `getaddrinfo(3)`/system DNS) for that host. That's both a
        // real privacy leak (this crate's whole point is that DNS
        // queries go over DoH, never the OS resolver — see module
        // docs) AND, inside `renderer`'s sandboxed process, a hard
        // crash: `getaddrinfo`'s own syscalls aren't in
        // `sandbox::linux::ALLOWED_SYSCALLS` (that allowlist was
        // built around this crate's real, intended syscall footprint,
        // which was never supposed to include the system resolver at
        // all), so the process is killed with `SIGSYS` — confirmed via
        // a real crash reproduction against `https://iana.org/domains/example`
        // (redirects to `https://www.iana.org/domains/example`), which
        // is exactly what surfaced this as "renderer unavailable...
        // failed to fill whole buffer" on basically any real site that
        // redirects at all. Resolving every hop's host via
        // `resolve_via_doh` (same cached-by-TTL path a same-host
        // request already uses) keeps every hop first-party-checked,
        // DoH-resolved, and inside the sandbox's real syscall budget.
        let mut current_url = url.to_string();
        // Downgraded to `None` on a 301/302/303 hop (see below) —
        // `current_body.is_some()` is what actually decides GET vs.
        // POST for each hop's OWN request, not the original `body`
        // parameter, so a redirect away from a POST correctly stops
        // resending it.
        let mut current_body: Option<Vec<u8>> = body.map(<[u8]>::to_vec);
        let top_level_host_owned = top_level_host.map(str::to_string);
        // Accumulated across EVERY hop, not just the final response —
        // a `Set-Cookie` on a 3xx redirect hop itself is a completely
        // ordinary, common pattern (a login endpoint that sets a
        // session cookie on the SAME response that redirects to the
        // now-authenticated page), and dropping it here would silently
        // break exactly the flow `PartitionedCookieJar`'s persistence
        // exists to support. Order matches request order, so a later
        // hop's `Set-Cookie` for the same name naturally wins once
        // `PartitionedCookieJar::store_set_cookie` applies them in
        // order (last write to a `HashMap` entry wins).
        let mut accumulated_set_cookies: Vec<String> = Vec::new();

        for _ in 0..MAX_REDIRECTS {
            let hostname = strip_port(&extract_host(&current_url)).to_string();
            let resolved_ip = self.resolve_via_doh(&hostname)?;

            // Rebuilt per hop (see the `doh_client` field's doc
            // comment for why): `.resolve` is a builder-time-only
            // setting, so a fresh client is needed to pin EACH hop's
            // own resolved IP.
            let client = reqwest::blocking::Client::builder()
                .default_headers(self.headers.clone())
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(15))
                .resolve(&hostname, SocketAddr::new(resolved_ip, 0))
                .build()
                .map_err(|e| {
                    FetchError::Network(format!("building the HTTP client failed: {e}"))
                })?;

            let mut request = match &current_body {
                Some(bytes) => client
                    .post(&current_url)
                    .header(
                        reqwest::header::CONTENT_TYPE,
                        "application/x-www-form-urlencoded",
                    )
                    .body(bytes.clone()),
                None => client.get(&current_url),
            };
            if let Some(cookie_value) = cookie_header {
                request = request.header("Cookie", cookie_value);
            }
            let resp = request
                .send()
                .map_err(|e| FetchError::Network(e.to_string()))?;

            if resp.status().is_redirection() {
                accumulated_set_cookies.extend(
                    resp.headers()
                        .get_all(reqwest::header::SET_COOKIE)
                        .iter()
                        .filter_map(|v| v.to_str().ok().map(str::to_string)),
                );

                // Real browser semantics: a 301/302/303 redirect off a
                // POST re-fetches the target as a GET, dropping the
                // body — only 307/308 preserve the original method AND
                // body. Without this, a login endpoint's POST-then-
                // redirect-to-dashboard flow would incorrectly re-POST
                // the login form's own body at the dashboard URL.
                let status = resp.status().as_u16();
                if current_body.is_some() && !matches!(status, 307 | 308) {
                    current_body = None;
                }

                let location = resp
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| {
                        FetchError::Network(format!(
                            "redirect from {current_url} had no (or a non-UTF-8) Location header"
                        ))
                    })?;
                let next_url = reqwest::Url::parse(&current_url)
                    .and_then(|base| base.join(location))
                    .map_err(|e| {
                        FetchError::Network(format!(
                            "could not resolve redirect Location {location:?}: {e}"
                        ))
                    })?;

                if redirect_should_block(&next_url, &top_level_host_owned, &self.redirect_blocklist)
                {
                    return Err(FetchError::Blocked(next_url.to_string()));
                }
                current_url = next_url.to_string();
                continue;
            }

            accumulated_set_cookies.extend(
                resp.headers()
                    .get_all(reqwest::header::SET_COOKIE)
                    .iter()
                    .filter_map(|v| v.to_str().ok().map(str::to_string)),
            );
            let set_cookies = accumulated_set_cookies;
            let cache_control = resp
                .headers()
                .get(reqwest::header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);

            let status = resp.status().as_u16();
            let body = resp
                .bytes()
                .map_err(|e| FetchError::Network(e.to_string()))?
                .to_vec();
            return Ok(Response {
                status,
                body,
                set_cookies,
                cache_control,
            });
        }

        Err(FetchError::Network(format!(
            "too many redirects ({MAX_REDIRECTS}) fetching {url}"
        )))
    }
}

/// Decides whether a REDIRECT HOP should be blocked, using the exact
/// same `privacy::should_block` call (and therefore the exact same
/// first-party/third-party + path-aware logic) `FilteringFetcher`
/// applies to the initial request — pulled out as its own pure
/// function (no network I/O) so it's unit-testable without needing a
/// real redirecting server. `top_level_host` is whatever the ORIGINAL
/// request was given; every hop in one redirect chain is judged
/// against that same top-level context, not re-derived per hop.
fn redirect_should_block(
    url: &reqwest::Url,
    top_level_host: &Option<String>,
    blocklist: &Blocklist,
) -> bool {
    let host = url.host_str().unwrap_or("").to_lowercase();
    let path = url.path();
    let ctx = RequestContext {
        request_host: host,
        request_path: if path.is_empty() {
            "/".to_string()
        } else {
            path.to_string()
        },
        top_level_host: top_level_host.clone(),
    };
    should_block(&ctx, blocklist)
}

/// Wraps any `Fetcher` and applies privacy policy before delegating:
/// strips tracking params, blocks third-party tracker hosts/paths, and
/// (via `PartitionedCookieJar`) keeps cookie storage isolated per
/// top-level site. This is the layer `app` should actually hold onto
/// — not a bare `FakeFetcher`/`HttpFetcher` — so policy is enforced
/// in exactly one place regardless of which transport is underneath.
pub struct FilteringFetcher<F: Fetcher> {
    inner: F,
    blocklist: Blocklist,
    pub cookies: PartitionedCookieJar,
    /// `None` until `enable_disk_cache` is called — caching is opt-in
    /// so plain unit tests (constructing a `FilteringFetcher` around a
    /// `FakeFetcher`) never touch the filesystem unless they ask to.
    cache: Option<DiskCache>,
    /// `false` unless `enable_local_file_access` was called -- see that
    /// method's own doc comment. Gates ALL `file://` handling in this
    /// fetcher: with this `false` (every renderer process except the
    /// one dedicated to `file://` browsing -- see `app::RendererPool`'s
    /// own docs on the dedicated site bucket), a `file://` URL is
    /// rejected the same way any other unreachable URL is, regardless
    /// of where the request originated (a typed URL, a clicked link, an
    /// `<img src>`, a page's own `fetch()` call) -- this is what stops a
    /// malicious REMOTE page's script from ever reading a local file
    /// through this same, shared fetch path just because SOME renderer
    /// process somewhere has local-file access enabled.
    allow_local_files: bool,
}

impl<F: Fetcher> FilteringFetcher<F> {
    pub fn new(inner: F, blocklist: Blocklist) -> Self {
        FilteringFetcher {
            inner,
            blocklist,
            cookies: PartitionedCookieJar::default(),
            cache: None,
            allow_local_files: false,
        }
    }

    /// Opts this ONE fetcher instance into real `file://` URL support --
    /// called exactly once, from `abyssal-renderer`'s own `main`, and
    /// ONLY for the single dedicated renderer process `app::RendererPool`
    /// spawns for `file://` navigation (see that struct's own doc
    /// comment on why `file://` gets its own process, never sharing one
    /// with any real website). That process's OWN sandbox profile also
    /// has no outbound network access at all (see `renderer::sandbox`'s
    /// own module docs) -- so even though this flag technically also
    /// permits an ordinary `https://` fetch to keep working from that
    /// same process, there is nothing for it to reach: the OS itself
    /// refuses the connection before this code ever runs.
    pub fn enable_local_file_access(&mut self) {
        self.allow_local_files = true;
    }

    /// A fresh, independent `FilteringFetcher` for use on ANOTHER
    /// THREAD — same blocklist and a snapshot of the current cookie
    /// jar (so a request needing an already-set cookie still sees it),
    /// but DELIBERATELY without the disk cache: `DiskCache` isn't
    /// designed for concurrent access from multiple threads at once,
    /// and giving every worker its own on-disk connection would risk
    /// exactly that. `renderer::images`' concurrent image-fetching path
    /// is the one place this exists for — real, sequential fetches
    /// everywhere else keep using the ORIGINAL fetcher (and its real
    /// disk cache) unchanged. A clone's own cookie jar is a one-way
    /// snapshot, not linked back to the original — a `Set-Cookie` an
    /// image response happens to send is real, but only visible to
    /// requests made through THAT SAME clone for the rest of this
    /// batch, not written back to the tab's real, ongoing session.
    pub fn clone_for_concurrent_use(&self) -> Self
    where
        F: Clone,
    {
        FilteringFetcher {
            inner: self.inner.clone(),
            blocklist: self.blocklist.clone(),
            cookies: self.cookies.clone(),
            cache: None,
            // Inherited, not reset to `false`: this clone stays inside
            // the SAME process/sandbox as the original (see this
            // method's own doc comment — it exists for concurrent
            // image-fetching worker threads within one renderer, not
            // for crossing any trust boundary), so a page's local
            // `<img src="file://...">` references keep working through
            // the concurrent path too when the dedicated `file://`
            // process is the one doing the fetching.
            allow_local_files: self.allow_local_files,
        }
    }

    /// Turns on the on-disk response cache, rooted at `cache_dir` (see
    /// `disk_cache`'s module docs for what it does and doesn't cache).
    /// Fails only if the directory can't be created.
    pub fn enable_disk_cache(
        &mut self,
        cache_dir: impl AsRef<std::path::Path>,
    ) -> std::io::Result<()> {
        self.cache = Some(DiskCache::open(cache_dir)?);
        Ok(())
    }

    /// Ordinary GET fetch — see `fetch_in_context_with_body` (which
    /// this is a thin wrapper around) for the real implementation and
    /// the POST case.
    pub fn fetch_in_context(
        &mut self,
        url: &str,
        top_level_host: Option<&str>,
    ) -> Result<Response, FetchError> {
        self.fetch_in_context_with_body(url, top_level_host, None)
    }

    /// Like `fetch_in_context`, but `body` (when `Some`) sends a real
    /// POST instead of a GET — see `Fetcher::fetch`'s own doc comment
    /// for the encoding this assumes. A POST response is never read
    /// from or written to the disk cache: caching by URL alone would
    /// be wrong the moment two different POST bodies to the same URL
    /// produce different results (a search form and a login form can
    /// both point `action` at the same endpoint), and real HTTP
    /// semantics don't treat a POST as cacheable by default the way a
    /// GET is anyway.
    pub fn fetch_in_context_with_body(
        &mut self,
        url: &str,
        top_level_host: Option<&str>,
        body: Option<&[u8]>,
    ) -> Result<Response, FetchError> {
        // Handled entirely separately from everything below: a `file://`
        // URL has no host to blocklist-check, no cookies, and nothing
        // worth disk-caching (reading a local file again is already
        // instant) -- see `local_file_response`'s own doc comment for the
        // real security reasoning behind gating this on
        // `self.allow_local_files`.
        if url.starts_with("file://") {
            return self.local_file_response(url);
        }

        let cleaned_url = privacy::strip_tracking_params(url);
        let request_host = extract_host(&cleaned_url);
        let request_path = extract_path(&cleaned_url);
        let ctx = RequestContext {
            request_host: request_host.clone(),
            request_path,
            top_level_host: top_level_host.map(str::to_string),
        };
        if should_block(&ctx, &self.blocklist) {
            return Err(FetchError::Blocked(request_host));
        }

        let partition_key = StoragePartitionKey::for_request(&ctx);
        let is_post = body.is_some();

        if !is_post {
            if let Some(cache) = &self.cache {
                if let Some((status, body)) = cache.get(&partition_key, &cleaned_url) {
                    return Ok(Response {
                        status,
                        body,
                        set_cookies: Vec::new(),
                        cache_control: None,
                    });
                }
            }
        }

        let cookie_header = self.cookies.cookie_header_for(&partition_key);
        let response =
            self.inner
                .fetch(&cleaned_url, top_level_host, cookie_header.as_deref(), body)?;
        for raw_set_cookie in &response.set_cookies {
            self.cookies
                .store_set_cookie(partition_key.clone(), raw_set_cookie);
        }

        if !is_post {
            if let Some(cache) = &self.cache {
                if response.status == 200 {
                    if let Some(max_age) = response
                        .cache_control
                        .as_deref()
                        .and_then(disk_cache::parse_max_age)
                    {
                        cache.put(
                            &partition_key,
                            &cleaned_url,
                            response.status,
                            &response.body,
                            max_age,
                        );
                    }
                }
            }
        }

        Ok(response)
    }

    /// The whole real `file://` implementation, gated on
    /// `self.allow_local_files` -- see that field's own doc comment for
    /// why this MUST stay behind that flag rather than being reachable
    /// unconditionally: without the gate, a malicious REMOTE `https://`
    /// page's own `fetch('file:///home/you/.ssh/id_rsa')` would succeed
    /// through this exact same code path, in any ordinary renderer
    /// process, and that process still has real internet access to
    /// exfiltrate whatever it just read. With the gate, only the one
    /// dedicated, network-less renderer process `app::RendererPool`
    /// spawns for `file://` browsing ever sets it.
    ///
    /// No blocklist check, no cookies, no disk cache -- none of those
    /// concepts apply to a local file. `url::Url::to_file_path` is what
    /// does the real, correct `file://` -> filesystem-path conversion
    /// (percent-decoding included) rather than hand-rolling it the way
    /// `extract_host`/`extract_path` do for the (bounded, "good enough
    /// to key a hashmap") ordinary case.
    fn local_file_response(&self, url: &str) -> Result<Response, FetchError> {
        if !self.allow_local_files {
            return Err(FetchError::Network(
                "file:// access is not enabled for this renderer process".to_string(),
            ));
        }
        let parsed = url::Url::parse(url)
            .map_err(|e| FetchError::NotFound(format!("malformed file:// URL {url:?}: {e}")))?;
        let path = parsed
            .to_file_path()
            .map_err(|()| FetchError::NotFound(format!("not a valid local file path: {url:?}")))?;
        let body = std::fs::read(&path)
            .map_err(|e| FetchError::NotFound(format!("{}: {e}", path.display())))?;
        Ok(Response {
            status: 200,
            body,
            set_cookies: Vec::new(),
            cache_control: None,
        })
    }
}

/// A naive `scheme://host/...` host extractor. No IDNA/punycode
/// normalization, no IPv6 bracket parsing. Includes a trailing `:port`
/// if present in the URL — use `strip_port` on the result if a bare
/// hostname is needed (e.g. for `HttpFetcher`'s DNS override, which
/// must match reqwest's own bare-hostname lookup key exactly).
/// TODO: reach for the `url` crate for real URL parsing once this
/// stops being "just enough to key a hashmap."
fn extract_host(url: &str) -> String {
    url.split("://")
        .nth(1)
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or("")
        .to_lowercase()
}

/// The path (plus query string, if any) of `url`, always starting with
/// `/` — the counterpart to `extract_host`, needed so
/// `Blocklist::is_blocked` can see more than a bare hostname (see
/// `privacy::RequestContext::request_path`). Same narrow scope as
/// `extract_host`: no percent-decoding, no normalization.
fn extract_path(url: &str) -> String {
    let after_scheme = url.split("://").nth(1).unwrap_or(url);
    match after_scheme.find('/') {
        Some(idx) => after_scheme[idx..].to_string(),
        None => "/".to_string(),
    }
}

/// Strips a trailing `:port` from a host string (as returned by
/// `extract_host`). Doesn't handle IPv6 literal hosts (`[::1]:8080`)
/// — same narrow scope as `extract_host` itself.
fn strip_port(host: &str) -> &str {
    host.split(':').next().unwrap_or(host)
}

/// Cookie storage keyed by `privacy::StoragePartitionKey` instead of
/// just by host — this is the mechanism behind "Total Cookie
/// Protection": the same tracker domain gets a *different* cookie jar
/// per top-level site that embeds it, so it can't use a cookie to
/// recognize the same user across unrelated sites.
///
/// TODO: this only models cookies. LocalStorage, IndexedDB, and the
/// HTTP cache all need the same partitioning treatment and currently
/// have none.
#[derive(Debug, Default, Clone)]
pub struct PartitionedCookieJar {
    jar: HashMap<StoragePartitionKey, HashMap<String, String>>,
    /// Bumped by every real mutation (`set`) — lets a caller cheaply
    /// answer "did anything actually change since I last persisted
    /// this?" (see `renderer::RendererState`'s use of this) without
    /// re-serializing/diffing the whole jar on every single message.
    version: u64,
}

impl PartitionedCookieJar {
    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn set(&mut self, key: StoragePartitionKey, name: &str, value: &str) {
        self.jar
            .entry(key)
            .or_default()
            .insert(name.to_string(), value.to_string());
        self.version += 1;
    }

    pub fn get(&self, key: &StoragePartitionKey, name: &str) -> Option<&str> {
        self.jar.get(key)?.get(name).map(String::as_str)
    }

    pub fn cookie_header_for(&self, key: &StoragePartitionKey) -> Option<String> {
        let cookies = self.jar.get(key)?;
        if cookies.is_empty() {
            return None;
        }
        Some(
            cookies
                .iter()
                .map(|(n, v)| format!("{n}={v}"))
                .collect::<Vec<_>>()
                .join("; "),
        )
    }

    pub fn store_set_cookie(&mut self, key: StoragePartitionKey, raw_set_cookie: &str) {
        let name_value = raw_set_cookie
            .split(';')
            .next()
            .unwrap_or(raw_set_cookie)
            .trim();
        if let Some((name, value)) = name_value.split_once('=') {
            self.set(key, name.trim(), value.trim());
        }
    }

    /// Real JSON serialization via `serde_json::Value` (hand-built,
    /// not `#[derive(Serialize)]` — this crate only depends on
    /// `serde_json`, not plain `serde`, and `StoragePartitionKey`'s
    /// two fields are already `pub`, so a derive would add a
    /// dependency for no real benefit here) — an array of
    /// `{top_level_site, resource_host, cookies}` objects, one per
    /// partition. Mirrors `storage::SyncPayload::to_bytes`'s own
    /// "real JSON, not a hand-rolled delimited format" reasoning.
    pub fn to_bytes(&self) -> Vec<u8> {
        let entries: Vec<serde_json::Value> = self
            .jar
            .iter()
            .map(|(key, cookies)| {
                serde_json::json!({
                    "top_level_site": key.top_level_site,
                    "resource_host": key.resource_host,
                    "cookies": cookies,
                })
            })
            .collect();
        serde_json::to_vec(&entries).unwrap_or_default()
    }

    /// The `to_bytes` inverse. An entry missing a required field, or
    /// with a non-string cookie value, is skipped rather than failing
    /// the whole load — one malformed partition (e.g. hand-edited, or
    /// from some future format change) shouldn't cost every other
    /// site's cookies too. Malformed/unreadable `bytes` overall (not
    /// valid JSON at all) is the one case that gives up entirely,
    /// same as `storage::SyncPayload::from_bytes`.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let entries: Vec<serde_json::Value> = serde_json::from_slice(bytes).ok()?;
        let mut jar = HashMap::new();
        for entry in &entries {
            let (Some(top_level_site), Some(resource_host), Some(cookies_obj)) = (
                entry.get("top_level_site").and_then(|v| v.as_str()),
                entry.get("resource_host").and_then(|v| v.as_str()),
                entry.get("cookies").and_then(|v| v.as_object()),
            ) else {
                continue;
            };
            let cookies: HashMap<String, String> = cookies_obj
                .iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect();
            jar.insert(
                StoragePartitionKey {
                    top_level_site: top_level_site.to_string(),
                    resource_host: resource_host.to_string(),
                },
                cookies,
            );
        }
        Some(PartitionedCookieJar { jar, version: 0 })
    }

    /// Overwrites, into `on_disk`, every partition THIS jar has an
    /// entry for — leaving any partition this jar has no opinion on
    /// untouched. This is what lets several concurrent, independent
    /// renderer PROCESSES (one per site — see `app::RendererPool`'s
    /// own docs) each report cookies (see `ipc::ServerMessage::
    /// updated_cookies`) toward the ONE shared, `app`-owned
    /// `cookies.enc` without a later report from a DIFFERENT site's
    /// process clobbering an earlier one's cookies for a site it never
    /// even talked to: every renderer process only ever creates
    /// partition keys whose `top_level_site` is the one site it
    /// renders, so two processes' own partition sets never overlap in
    /// practice. `app` itself can't call this real, typed method
    /// directly (it must never depend on this crate — see
    /// `ARCHITECTURE.md`); `app::merge_persisted_json` reimplements
    /// the same semantics generically, over raw JSON, using this
    /// method's own real behavior as the reference.
    pub fn merge_into(&self, on_disk: &mut Self) {
        for (key, cookies) in &self.jar {
            on_disk.jar.insert(key.clone(), cookies.clone());
        }
        on_disk.version += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_fetcher_returns_registered_body() {
        let mut fetcher = FakeFetcher::new();
        fetcher.register("http://example.com", "<html></html>");
        let resp = fetcher
            .fetch("http://example.com", None, None, None)
            .unwrap();
        assert_eq!(resp.body, b"<html></html>".to_vec());
    }

    #[test]
    fn filtering_fetcher_blocks_third_party_trackers() {
        let mut fake = FakeFetcher::new();
        fake.register("http://g.doubleclick.net/pixel", "tracking pixel");
        let mut filtering = FilteringFetcher::new(fake, Blocklist::with_seed_list());

        let result =
            filtering.fetch_in_context("http://g.doubleclick.net/pixel", Some("news.example.com"));
        assert!(matches!(result, Err(FetchError::Blocked(_))));
    }

    #[test]
    fn filtering_fetcher_allows_first_party_requests() {
        let mut fake = FakeFetcher::new();
        fake.register("http://news.example.com/", "<html></html>");
        let mut filtering = FilteringFetcher::new(fake, Blocklist::with_seed_list());

        let result =
            filtering.fetch_in_context("http://news.example.com/", Some("news.example.com"));
        assert!(result.is_ok());
    }

    #[test]
    fn a_file_url_is_rejected_when_local_file_access_is_not_enabled() {
        let dir = std::env::temp_dir().join(format!(
            "abyssal-test-file-url-disabled-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("real.html");
        std::fs::write(&path, "<html><body>hi</body></html>").unwrap();

        // The critical negative case: an ORDINARY fetcher (the shape
        // every real website's own renderer process uses) must refuse a
        // `file://` URL even though the real file genuinely exists on
        // disk and is genuinely readable by this OS user -- proving the
        // gate, not just that a missing file fails.
        let fake = FakeFetcher::new();
        let mut filtering = FilteringFetcher::new(fake, Blocklist::with_seed_list());
        let url = format!("file://{}", path.display());

        let result = filtering.fetch_in_context(&url, None);

        assert!(
            matches!(result, Err(FetchError::Network(_))),
            "expected a rejection (Err(Network(_)))"
        );
    }

    #[test]
    fn a_file_url_reads_the_real_file_once_local_file_access_is_enabled() {
        let dir = std::env::temp_dir().join(format!(
            "abyssal-test-file-url-enabled-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("real.html");
        std::fs::write(&path, "<html><body>real local content</body></html>").unwrap();

        let fake = FakeFetcher::new();
        let mut filtering = FilteringFetcher::new(fake, Blocklist::with_seed_list());
        filtering.enable_local_file_access();
        let url = format!("file://{}", path.display());

        let response = filtering.fetch_in_context(&url, None).unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(
            String::from_utf8(response.body).unwrap(),
            "<html><body>real local content</body></html>"
        );
    }

    #[test]
    fn a_missing_file_url_reports_not_found_even_when_enabled() {
        let missing = std::env::temp_dir().join("abyssal-test-file-url-does-not-exist.html");
        let fake = FakeFetcher::new();
        let mut filtering = FilteringFetcher::new(fake, Blocklist::with_seed_list());
        filtering.enable_local_file_access();
        let url = format!("file://{}", missing.display());

        let result = filtering.fetch_in_context(&url, None);

        assert!(matches!(result, Err(FetchError::NotFound(_))));
    }

    #[test]
    fn local_file_access_does_not_go_through_the_blocklist_or_cookie_jar() {
        // A file:// request has no real host, so it must never be
        // treated as first/third-party or checked against the
        // blocklist -- confirmed here by fetching a real file whose own
        // "host" component (if extract_host's ordinary parsing applied)
        // would be nonsensical, and confirming it still succeeds.
        let dir = std::env::temp_dir().join(format!(
            "abyssal-test-file-url-no-blocklist-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("page.html");
        std::fs::write(&path, "local").unwrap();

        let fake = FakeFetcher::new();
        let mut filtering = FilteringFetcher::new(fake, Blocklist::with_seed_list());
        filtering.enable_local_file_access();
        let url = format!("file://{}", path.display());

        // top_level_host intentionally omitted/irrelevant for file://.
        let result = filtering.fetch_in_context(&url, Some("some-remote-site.example"));
        assert!(result.is_ok());
        assert!(
            filtering
                .cookies
                .cookie_header_for(&StoragePartitionKey {
                    top_level_site: "some-remote-site.example".to_string(),
                    resource_host: String::new(),
                })
                .is_none(),
            "a file:// fetch must never populate the cookie jar"
        );
    }

    #[test]
    fn fetch_in_context_with_body_sends_a_real_post_body_to_the_inner_fetcher() {
        let mut fake = FakeFetcher::new();
        fake.register("http://example.com/login", "logged in");
        let mut filtering = FilteringFetcher::new(fake, Blocklist::with_seed_list());

        let result = filtering.fetch_in_context_with_body(
            "http://example.com/login",
            None,
            Some(b"username=alice&password=hunter2"),
        );

        assert!(result.is_ok());
        assert_eq!(
            filtering
                .inner
                .last_request_body("http://example.com/login"),
            Some(b"username=alice&password=hunter2".to_vec())
        );
    }

    #[test]
    fn fetch_in_context_without_a_body_sends_none_to_the_inner_fetcher() {
        let mut fake = FakeFetcher::new();
        fake.register("http://example.com/", "<html></html>");
        let mut filtering = FilteringFetcher::new(fake, Blocklist::with_seed_list());

        filtering
            .fetch_in_context("http://example.com/", None)
            .unwrap();

        assert_eq!(
            filtering.inner.last_request_body("http://example.com/"),
            None
        );
    }

    #[test]
    fn a_post_response_is_never_read_from_or_written_to_the_disk_cache() {
        let dir = std::env::temp_dir().join(format!(
            "abyssal-test-post-no-cache-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut fake = FakeFetcher::new();
        fake.register_with_cache_control(
            "http://example.com/submit",
            "first response",
            "max-age=3600",
        );
        let mut filtering = FilteringFetcher::new(fake, Blocklist::with_seed_list());
        filtering.enable_disk_cache(&dir).unwrap();

        let first = filtering
            .fetch_in_context_with_body("http://example.com/submit", None, Some(b"a=1"))
            .unwrap();
        assert_eq!(first.body, b"first response");

        // A DIFFERENT POST body to the same URL must reach the fetcher
        // again, not be served from a cache keyed only on the URL —
        // if this were wrongly cached, changing the registered
        // response below would never be observed.
        filtering
            .inner
            .register("http://example.com/submit", "second response");
        let second = filtering
            .fetch_in_context_with_body("http://example.com/submit", None, Some(b"a=2"))
            .unwrap();
        assert_eq!(second.body, b"second response");
    }

    #[test]
    fn filtering_fetcher_strips_tracking_params_before_lookup() {
        let mut fake = FakeFetcher::new();
        fake.register("http://example.com/page", "clean page");
        let mut filtering = FilteringFetcher::new(fake, Blocklist::with_seed_list());

        let result = filtering.fetch_in_context("http://example.com/page?utm_source=email", None);
        assert!(result.is_ok());
    }

    #[test]
    fn cookie_jar_partitions_same_host_by_top_level_site() {
        let mut jar = PartitionedCookieJar::default();
        let key_a = StoragePartitionKey {
            top_level_site: "siteA.com".to_string(),
            resource_host: "tracker.com".to_string(),
        };
        let key_b = StoragePartitionKey {
            top_level_site: "siteB.com".to_string(),
            resource_host: "tracker.com".to_string(),
        };

        jar.set(key_a.clone(), "id", "user-on-site-a");
        assert_eq!(jar.get(&key_a, "id"), Some("user-on-site-a"));
        assert_eq!(jar.get(&key_b, "id"), None);
    }

    #[test]
    fn http_fetcher_builds_without_making_any_network_call() {
        // Deliberately doesn't hit the network — just confirms the
        // client(s) build successfully with our header/redirect-policy/
        // DoH-override configuration. Real fetches against
        // `HttpFetcher` (which now require actually reaching
        // Cloudflare's DoH endpoint) aren't covered by this crate's
        // automated tests, since that would make the test suite
        // depend on network access.
        let _fetcher = HttpFetcher::new(Blocklist::with_seed_list());
    }

    #[test]
    fn strip_port_removes_a_trailing_port() {
        assert_eq!(strip_port("example.com:8080"), "example.com");
        assert_eq!(strip_port("example.com"), "example.com");
    }

    #[test]
    fn parses_an_a_record_out_of_a_real_shaped_doh_response() {
        let body = r#"{
            "Status": 0,
            "Answer": [
                { "name": "example.com.", "type": 5, "TTL": 300, "data": "cname.example.net." },
                { "name": "cname.example.net.", "type": 1, "TTL": 60, "data": "93.184.216.34" }
            ]
        }"#;
        let (ip, ttl) = parse_first_answer(body, "A").expect("should find the A record");
        assert_eq!(ip, "93.184.216.34".parse::<IpAddr>().unwrap());
        assert_eq!(ttl, 60);
    }

    #[test]
    fn returns_none_when_there_is_no_a_record() {
        let body = r#"{ "Status": 0, "Answer": [] }"#;
        assert_eq!(parse_first_answer(body, "A"), None);
    }

    #[test]
    fn returns_none_for_malformed_json() {
        assert_eq!(parse_first_answer("not json at all", "A"), None);
    }

    #[test]
    fn cookie_jar_serializes_a_cookie_header_and_parses_set_cookie() {
        let mut jar = PartitionedCookieJar::default();
        let key = StoragePartitionKey {
            top_level_site: "example.com".to_string(),
            resource_host: "example.com".to_string(),
        };
        assert_eq!(jar.cookie_header_for(&key), None);
        jar.store_set_cookie(key.clone(), "session=abc123; Path=/; HttpOnly");
        assert_eq!(
            jar.cookie_header_for(&key),
            Some("session=abc123".to_string())
        );
    }

    #[test]
    fn a_real_mutation_bumps_the_version_but_a_lookup_does_not() {
        let mut jar = PartitionedCookieJar::default();
        let key = StoragePartitionKey {
            top_level_site: "example.com".to_string(),
            resource_host: "example.com".to_string(),
        };
        assert_eq!(jar.version(), 0);
        jar.set(key.clone(), "a", "1");
        assert_eq!(jar.version(), 1);
        let _ = jar.cookie_header_for(&key);
        let _ = jar.get(&key, "a");
        assert_eq!(jar.version(), 1, "a read-only lookup shouldn't bump it");
    }

    #[test]
    fn cookies_round_trip_through_bytes() {
        let mut jar = PartitionedCookieJar::default();
        let key = StoragePartitionKey {
            top_level_site: "example.com".to_string(),
            resource_host: "example.com".to_string(),
        };
        jar.set(key.clone(), "session", "abc123");

        let restored = PartitionedCookieJar::from_bytes(&jar.to_bytes()).unwrap();
        assert_eq!(
            restored.cookie_header_for(&key),
            Some("session=abc123".to_string())
        );
    }

    #[test]
    fn from_bytes_is_none_for_garbage() {
        assert!(PartitionedCookieJar::from_bytes(b"not json at all").is_none());
    }

    #[test]
    fn merge_into_overwrites_only_the_partitions_it_has_an_opinion_on() {
        // Mirrors what `app::merge_persisted_json` now does generically
        // over raw JSON (see that function's own doc comment for why
        // `app` can't call this real, typed method directly) — this
        // test covers the real thing directly: renderer process A
        // (siteA.com) and renderer process B (siteB.com) each only
        // ever create partition keys for their own site, so merging
        // B's jar into A's on-disk state must not clobber A's cookies.
        let key_a = StoragePartitionKey {
            top_level_site: "siteA.com".to_string(),
            resource_host: "siteA.com".to_string(),
        };
        let key_b = StoragePartitionKey {
            top_level_site: "siteB.com".to_string(),
            resource_host: "siteB.com".to_string(),
        };

        let mut on_disk = PartitionedCookieJar::default();
        on_disk.set(key_a.clone(), "session", "aaa");

        let mut jar_b = PartitionedCookieJar::default();
        jar_b.set(key_b.clone(), "session", "bbb");
        jar_b.merge_into(&mut on_disk);

        assert_eq!(
            on_disk.cookie_header_for(&key_a),
            Some("session=aaa".to_string())
        );
        assert_eq!(
            on_disk.cookie_header_for(&key_b),
            Some("session=bbb".to_string())
        );
    }

    #[test]
    fn falls_back_to_an_aaaa_record_when_there_is_no_a_record() {
        let body = r#"{
            "Status": 0,
            "Answer": [
                { "name": "example.com.", "type": 28, "TTL": 120, "data": "2606:2800:220:1:248:1893:25c8:1946" }
            ]
        }"#;
        let (ip, ttl) = parse_first_answer(body, "AAAA").expect("should find the AAAA record");
        assert!(ip.is_ipv6());
        assert_eq!(ttl, 120);
    }

    #[test]
    fn redirect_should_block_treats_a_same_site_subdomain_as_first_party() {
        // The exact bug this fix closes: a redirect hop to the
        // requesting site's OWN subdomain must NOT be blocked just
        // because that hostname happens to appear on a list — it's
        // first-party relative to the page that's redirecting, same
        // as `privacy::should_block` would already treat it if this
        // were the initial request rather than a redirect hop.
        let blocklist = Blocklist::from_filter_text("||news.example.com^\n");
        let url = reqwest::Url::parse("https://news.example.com/live").unwrap();
        let top_level_host = Some("news.example.com".to_string());

        assert!(!redirect_should_block(&url, &top_level_host, &blocklist));
    }

    #[test]
    fn redirect_should_block_blocks_a_genuine_third_party_hop() {
        let blocklist = Blocklist::with_seed_list();
        let url = reqwest::Url::parse("https://g.doubleclick.net/pixel").unwrap();
        let top_level_host = Some("news.example.com".to_string());

        assert!(redirect_should_block(&url, &top_level_host, &blocklist));
    }

    #[test]
    fn redirect_should_block_respects_a_path_specific_rule() {
        let blocklist = Blocklist::from_filter_text("||cdn.example.com/ads/tracker.js\n");
        let top_level_host = Some("news.example.org".to_string());

        let blocked = reqwest::Url::parse("https://cdn.example.com/ads/tracker.js").unwrap();
        assert!(redirect_should_block(&blocked, &top_level_host, &blocklist));

        let harmless = reqwest::Url::parse("https://cdn.example.com/lib/jquery.js").unwrap();
        assert!(!redirect_should_block(
            &harmless,
            &top_level_host,
            &blocklist
        ));
    }

    #[test]
    fn redirect_should_block_never_blocks_a_top_level_navigation() {
        // `top_level_host: None` means "this IS the top-level
        // navigation" — there's no separate embedding context, so
        // there's no third party to speak of, matching
        // `privacy::RequestContext::is_third_party`'s own semantics.
        let blocklist = Blocklist::with_seed_list();
        let url = reqwest::Url::parse("https://g.doubleclick.net/").unwrap();

        assert!(!redirect_should_block(&url, &None, &blocklist));
    }

    #[test]
    fn extract_path_returns_the_path_and_query() {
        assert_eq!(extract_path("https://example.com/a/b?x=1"), "/a/b?x=1");
        assert_eq!(extract_path("https://example.com"), "/");
        assert_eq!(extract_path("https://example.com/"), "/");
    }

    /// A directory under the OS temp dir, unique per test (PID + an
    /// incrementing counter), cleaned up when the returned guard drops
    /// — same pattern `disk_cache`'s own tests and `sync`'s tests use.
    struct TempDir(std::path::PathBuf);
    impl TempDir {
        fn new(label: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "abyssal-fetcher-cache-test-{label}-{}-{n}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).unwrap();
            TempDir(path)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn filtering_fetcher_serves_a_cacheable_response_from_disk_on_the_second_fetch() {
        let dir = TempDir::new("hit");
        let mut fake = FakeFetcher::new();
        fake.register_with_cache_control("http://example.com/", "first response", "max-age=3600");
        let mut filtering = FilteringFetcher::new(fake, Blocklist::with_seed_list());
        filtering.enable_disk_cache(&dir.0).unwrap();

        let first = filtering
            .fetch_in_context("http://example.com/", None)
            .unwrap();
        assert_eq!(first.body, b"first response".to_vec());

        // Swap out the underlying fetcher's registered response —
        // proving a second identical fetch comes back from the CACHE,
        // not from `inner.fetch` again, since `FakeFetcher` no longer
        // has this URL registered under its new content.
        let mut fake_again = FakeFetcher::new();
        fake_again.register("http://example.com/", "SHOULD NEVER BE SEEN");
        let mut filtering_reopened = FilteringFetcher::new(fake_again, Blocklist::with_seed_list());
        filtering_reopened.enable_disk_cache(&dir.0).unwrap();

        let second = filtering_reopened
            .fetch_in_context("http://example.com/", None)
            .unwrap();
        assert_eq!(second.body, b"first response".to_vec(), "a cached, non-expired response should be served without touching the underlying fetcher");
    }

    #[test]
    fn filtering_fetcher_never_caches_a_response_with_no_cache_control() {
        let dir = TempDir::new("no-cache-control");
        let mut fake = FakeFetcher::new();
        fake.register("http://example.com/", "uncacheable");
        let mut filtering = FilteringFetcher::new(fake, Blocklist::with_seed_list());
        filtering.enable_disk_cache(&dir.0).unwrap();

        filtering
            .fetch_in_context("http://example.com/", None)
            .unwrap();

        // No Cache-Control at all means "don't cache" (conservative
        // default — see `disk_cache::parse_max_age`), so a fresh
        // `FilteringFetcher` pointed at the same cache directory but a
        // DIFFERENT underlying fetcher must NOT find anything cached.
        let fake_without_registration = FakeFetcher::new();
        let mut filtering_reopened =
            FilteringFetcher::new(fake_without_registration, Blocklist::with_seed_list());
        filtering_reopened.enable_disk_cache(&dir.0).unwrap();
        let result = filtering_reopened.fetch_in_context("http://example.com/", None);
        assert!(
            matches!(result, Err(FetchError::NotFound(_))),
            "should miss the cache and fall through to the (empty) underlying fetcher"
        );
    }

    #[test]
    fn filtering_fetcher_cache_is_partitioned_by_top_level_site() {
        let dir = TempDir::new("partitioned-fetch");
        let mut fake = FakeFetcher::new();
        fake.register_with_cache_control(
            "http://cdn.example.com/lib.js",
            "from site A",
            "max-age=3600",
        );
        let mut filtering = FilteringFetcher::new(fake, Blocklist::with_seed_list());
        filtering.enable_disk_cache(&dir.0).unwrap();
        filtering
            .fetch_in_context("http://cdn.example.com/lib.js", Some("siteA.com"))
            .unwrap();

        // Same resource, same cache directory, but embedded on a
        // DIFFERENT top-level site — must miss, not return site A's
        // cached copy (the actual privacy property partitioning
        // exists to provide — see `disk_cache`'s module docs).
        let mut fake_b = FakeFetcher::new();
        fake_b.register_with_cache_control(
            "http://cdn.example.com/lib.js",
            "from site B",
            "max-age=3600",
        );
        let mut filtering_b = FilteringFetcher::new(fake_b, Blocklist::with_seed_list());
        filtering_b.enable_disk_cache(&dir.0).unwrap();
        let result = filtering_b
            .fetch_in_context("http://cdn.example.com/lib.js", Some("siteB.com"))
            .unwrap();
        assert_eq!(
            result.body,
            b"from site B".to_vec(),
            "site B must get its own fetch, not site A's cached response"
        );
    }

    #[test]
    fn clone_for_concurrent_use_snapshots_cookies_but_drops_the_disk_cache() {
        let dir = TempDir::new("clone-for-concurrent-use");
        let fake = FakeFetcher::new();
        let mut filtering = FilteringFetcher::new(fake, Blocklist::with_seed_list());
        filtering.enable_disk_cache(&dir.0).unwrap();

        let key = StoragePartitionKey {
            top_level_site: "example.com".to_string(),
            resource_host: "example.com".to_string(),
        };
        filtering.cookies.set(key.clone(), "id", "before-clone");

        let clone = filtering.clone_for_concurrent_use();
        assert_eq!(
            clone.cookies.get(&key, "id"),
            Some("before-clone"),
            "the clone should start with a snapshot of the original's cookies"
        );
        assert!(
            clone.cache.is_none(),
            "a concurrent-use clone must never carry a disk cache, since DiskCache isn't safe for concurrent multi-thread access"
        );

        // The clone's cookie jar is a one-way snapshot: changes made
        // through the clone (as a concurrent image-fetch worker would)
        // must not be visible back on the original fetcher.
        let mut clone = clone;
        clone.cookies.set(key.clone(), "id", "after-clone");
        assert_eq!(
            filtering.cookies.get(&key, "id"),
            Some("before-clone"),
            "the original fetcher must be unaffected by cookies set through a clone"
        );
    }

    #[test]
    fn clone_for_concurrent_use_still_enforces_the_same_blocklist() {
        let mut fake = FakeFetcher::new();
        fake.register("http://example.com/", "allowed");
        let filtering = FilteringFetcher::new(fake, Blocklist::with_seed_list());

        let mut clone = filtering.clone_for_concurrent_use();
        let result = clone.fetch_in_context("http://example.com/", None);
        assert!(
            result.is_ok(),
            "a concurrent-use clone should still be a real, working FilteringFetcher"
        );
    }
}
