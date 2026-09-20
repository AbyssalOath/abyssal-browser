# 04. Network and Privacy

This file covers the `network` and `privacy` crates: everything about how
Abyssal Browser actually reaches the real internet, and everything about how
it tries not to leak who you are while doing it.

The short version of the relationship between the two crates: `privacy` is a
pure policy engine with no sockets in it at all (it can be unit tested with
zero network access) - it only answers questions like "should this be
blocked?" and "which storage partition does this belong to?". `network` is
where the actual HTTP happens, and it consults `privacy` before, during, and
after every real request. Neither crate knows anything about JavaScript, the
DOM, or encryption - those live in `renderer` and `account`/`app`
respectively (see `01-process-model-and-ipc.md`, `03-javascript-engine.md`,
and `05-account-storage-sync.md`).

## The `Fetcher` trait and why it exists

Everything in `network` that does real work is built against one trait:

```rust
pub trait Fetcher {
    fn fetch(&self, url: &str, top_level_host: Option<&str>,
             cookie_header: Option<&str>, body: Option<&[u8]>)
        -> Result<Response, FetchError>;
}
```

Two real implementations exist: `HttpFetcher` (real DNS/TLS/HTTP) and
`FakeFetcher` (an in-memory map of registered responses, used everywhere in
tests). Everything upstream - `FilteringFetcher`, and everything in
`renderer` that fetches things - is generic over `F: Fetcher`, so it never
needs to know or care which one it's holding. This is the same pattern you'll
see repeated all over this codebase: define a small trait, write a fake
implementation early, and keep the real implementation swappable. It's also
why so many tests in this codebase can run with zero network access and zero
flakiness - `FakeFetcher::register("https://example.com/", "<html>...")`
gives you a fully deterministic, instant "server."

`body: Option<&[u8]>` on `fetch` exists for one reason: real POST form
submissions. When it's `Some`, the bytes are sent as
`application/x-www-form-urlencoded` - the one encoding real HTML forms use by
default, and the only one this codebase builds. There's no `multipart/
form-data` support, so a real file-upload `<form>` still won't work (see
`renderer::script::Session::build_form_submission` for where the actual
encoding happens, on the renderer side).

## `HttpFetcher`: the real HTTP client

`HttpFetcher` wraps `reqwest::blocking::Client`. "Blocking" matters here -
there's no async runtime anywhere in `app` or `network`. Everything in this
whole codebase that looks synchronous (fetch a page, wait for the response,
move on) actually IS synchronous at the Rust level; the "async-feeling" parts
you see in JavaScript (`fetch()`, promises) are a Boa-side illusion built on
top of a fetch that already fully completed before the JS promise is even
constructed - see `03-javascript-engine.md` for that trick.

### DNS-over-HTTPS, and why it's tricky to bootstrap

Plain DNS is unencrypted. Even if the actual page load happens over HTTPS,
the *hostname lookup* that happens first leaks in the clear to anyone
watching the network (an ISP, a coffee-shop Wi-Fi operator, a compromised
router). `HttpFetcher::resolve_via_doh` fixes this by resolving hostnames
through Cloudflare's DoH JSON API (`cloudflare-dns.com/dns-query`) instead of
the OS resolver.

There's a real chicken-and-egg problem here: to reach
`cloudflare-dns.com` over HTTPS, you need to resolve ITS hostname first -
and if you use plain DNS for that one lookup, you've just leaked the fact
that you're about to make encrypted DNS queries (not usually sensitive on its
own, but it defeats the purpose if literally every DoH client needs to leak
one plaintext lookup to bootstrap). The fix every real DoH client uses,
including this one: hardcode Cloudflare's own well-known IPs (`1.1.1.1`,
`1.0.0.1`) and pin them via `reqwest::ClientBuilder::resolve` so the DoH
client itself never touches DNS at all.

Once a real answer comes back (an A record, falling back to AAAA for
IPv6-only sites), `resolve_via_doh` also uses `.resolve()` to pin that
result for the ACTUAL page/resource fetch that follows - so the "real"
request never touches the OS resolver either. Answers are cached by their own
real DNS TTL (`dns_cache`, a `RefCell<HashMap<...>>` since `Fetcher::fetch`
only gets `&self`) so a page with fifty same-host resources doesn't hit
Cloudflare fifty times.

**This fails closed.** If the DoH lookup itself fails - Cloudflare
unreachable, malformed response, genuinely no A or AAAA record - the whole
fetch fails. It never silently falls back to the OS's plaintext resolver.
That's a real, deliberate privacy-over-availability tradeoff: a "privacy
browser" that quietly degrades to leaking your DNS queries the moment
Cloudflare has a bad day isn't actually private, it just feels private.

### Redirects are followed by hand, one hop at a time

This is one of the more interesting pieces of code in this crate, and there's
a real bug story behind why it works the way it does. `HttpFetcher::fetch`
does NOT hand `reqwest` a `redirect::Policy` and let it auto-follow. It loops
manually, up to `MAX_REDIRECTS` (10) hops, and for EACH hop:

1. Resolves that hop's hostname via the same `resolve_via_doh` path (cached
   by TTL, same as the top-level fetch).
2. Builds a **fresh** `reqwest::Client` with `.resolve()` pinned to THAT
   hop's IP (a client's `.resolve()` is builder-time-only, so a genuinely new
   client is needed per hop).
3. Re-checks the redirect target against the blocklist
   (`redirect_should_block`) using the SAME first-party/third-party logic the
   initial request used, with the SAME `top_level_host` context throughout
   the whole chain (not re-derived per hop).
4. Accumulates any `Set-Cookie` headers from EVERY hop, not just the final
   response - a login endpoint that sets a session cookie on the same
   response that redirects to the dashboard is an extremely common real
   pattern, and dropping that cookie would silently break login.
5. Downgrades a POST to a GET on 301/302/303 (dropping the body), but
   preserves method+body on 307/308 - this matches what real browsers do,
   and without it, a login form's POST body would get replayed against
   whatever the redirect target happens to be.

**Why manual, not automatic?** The doc comment on `Fetcher::fetch` explains
the real incident: `reqwest`'s own automatic redirect following uses its
default resolver (hyper-util's `GaiResolver`, i.e. real `getaddrinfo(3)`,
i.e. the OS resolver) for any host the `.resolve()` override doesn't
explicitly cover - and since `.resolve()` only ever pins the INITIAL host,
any cross-host redirect (extremely common - bare domain to `www.`, `http` to
`https`, a CDN) would silently fall through to plain OS DNS. That's a real
privacy leak (this crate's entire point is "DNS never goes to the OS
resolver"). It's also a hard crash inside the sandboxed renderer process:
`getaddrinfo`'s own syscalls were never in
`renderer::sandbox::linux::ALLOWED_SYSCALLS` (that allowlist was built by
tracing this crate's REAL, intended syscall footprint, which was never
supposed to include the OS resolver at all), so the renderer gets killed with
`SIGSYS` the moment it tries. This was confirmed with a real repro against
`https://iana.org/domains/example` (which redirects to
`https://www.iana.org/domains/example`) - it manifested as "renderer
unavailable... failed to fill whole buffer" on basically any real site that
redirects at all, which is to say: almost every real site. If you're ever
debugging a mysterious renderer crash on a specific URL, "does it redirect,
and does the redirect target's syscalls match what's expected" is a real
thing to check - see `10-troubleshooting.md`.

### Request building and headers

Every `HttpFetcher` is built with `privacy::normalize_headers()` baked into
its default headers - a fixed, non-unique `User-Agent`/`Accept-Language`
(see the privacy section below for why "non-unique" is the actual goal, not
"looks real").

## `FilteringFetcher`: the policy layer everything actually uses

`HttpFetcher` alone has no idea what a blocklist is. `FilteringFetcher<F:
Fetcher>` is the thing that actually enforces privacy policy, and it's the
type `app`'s renderer processes actually hold (never a bare `HttpFetcher`) -
see `01-process-model-and-ipc.md` for how `renderer::navigate` threads it
through. It wraps any `Fetcher` and, on every `fetch_in_context`/
`fetch_in_context_with_body` call:

1. Strips tracking query parameters (`privacy::strip_tracking_params`) before
   anything else touches the URL.
2. Builds a `privacy::RequestContext` and checks `privacy::should_block` -
   a THIRD-PARTY request to a blocklisted host/path is refused outright with
   `FetchError::Blocked`, before it ever reaches the underlying fetcher.
3. Computes a `privacy::StoragePartitionKey` for this request (top-level
   site + resource host - see below) and, for a GET with the disk cache
   enabled, checks the cache FIRST. A cache hit skips the real fetch
   entirely.
4. Looks up the outgoing `Cookie` header for this partition
   (`cookies.cookie_header_for`) and passes it down to the real fetch.
5. After a real fetch, stores every `Set-Cookie` the response carried
   (`cookies.store_set_cookie`, partitioned by the SAME key).
6. For a cacheable GET (status 200, a real `Cache-Control: max-age=N`), writes
   the response into the disk cache.

**POST responses are never read from or written to the disk cache**, on
purpose - caching by URL alone is wrong the instant two different POST
bodies to the SAME URL produce different results (a search form and a login
form both commonly point `action` at the same endpoint), and real HTTP
semantics don't treat POST as cacheable by default anyway.

### `clone_for_concurrent_use`

`renderer::images` fetches multiple `<img>` sources concurrently on separate
worker threads (see `02-dom-html-css-layout-render.md`), and `DiskCache`
isn't safe for concurrent access from more than one thread at once. Rather
than adding locking, each worker thread gets its OWN `FilteringFetcher` via
`clone_for_concurrent_use`: same blocklist, a one-way SNAPSHOT of the current
cookie jar (so an already-set cookie is visible), but `cache: None` always -
that clone simply never touches the disk cache at all. Cookies a clone
happens to receive (an image response setting one, unusual but possible)
are visible to other requests through that SAME clone for the rest of the
batch, but never written back to the tab's real, ongoing session. This is a
one-way, cheap trick for a narrow, specific need (concurrent image fetching)
- it is not a general "thread-safe fetcher" story.

## `PartitionedCookieJar`

Cookies are keyed by `StoragePartitionKey { top_level_site, resource_host }`,
not just by host. This is the "Total Cookie Protection" model real privacy
browsers use: the SAME tracker domain embedded on two different sites gets a
DIFFERENT cookie jar per site, so it can't read a cookie set while you were
on site A back when you're on site B, even though it's technically the same
tracker.example.com in both cases.

The jar itself is a plain `HashMap<StoragePartitionKey, HashMap<String,
String>>` plus a `version: u64` counter bumped on every real mutation
(`set`). That counter exists purely so a caller can cheaply answer "did
anything actually change since I last reported this?" without re-serializing
or diffing the whole jar - see `renderer::RendererState::
reported_cookies_if_changed` in `01-process-model-and-ipc.md`, and the whole
encrypted-persistence story in that same file. **This crate does not persist
anything to disk itself, and never encrypts anything** - `to_bytes`/
`from_bytes`/`merge_into` exist so a renderer process can report its own
plaintext bytes up to `app` over IPC, and `app` (the only process holding the
account's encryption key) does the actual encrypt/merge/write. If you're
looking for where `cookies.enc` gets written, it's not in this crate at all
- it's `app::persist_encrypted_merge` in `app/src/main.rs`.

`merge_into` deserves a specific mention because the SAME pattern shows up
three times in this codebase (cookies, `localStorage`, IndexedDB - see
`03-javascript-engine.md`): it overwrites, into `on_disk`, every partition
THIS jar has an opinion on, leaving every other partition alone. This is what
makes it safe for several independent renderer PROCESSES (one per site) to
each report their own state without one process's report clobbering
another's - every renderer process only ever creates partition keys for the
ONE site it renders, so two processes' partition sets never actually overlap
in practice, even though nothing enforces that at the type level.

`store_set_cookie` is deliberately minimal: it parses `name=value` out of the
first `;`-delimited segment of a raw `Set-Cookie` header and throws the rest
away. There is **no `SameSite`/`Secure`/`HttpOnly`/expiry handling at all** -
every cookie is treated as a plain session-lifetime name=value pair
regardless of what its real attributes said. This is the single most-cited
"known gap" for this crate across the project's own docs (see
`THREAT_MODEL.md`) - if you're ever debugging "why does this cookie behave
differently than in a real browser," this is almost certainly why.

## `disk_cache::DiskCache`

A real on-disk HTTP response cache, partitioned by the SAME
`StoragePartitionKey` the cookie jar uses. This partitioning matters for a
subtler reason than cookies do: an UNpartitioned cache is itself a
timing-based tracking side-channel - a tracker embedded on two different
sites could measure "was this resource already cached" (faster = cached) to
infer whether you'd separately visited the OTHER site that also embeds it,
without ever needing a cookie at all.

Each cache entry lives in its own flat file, named by
`SHA-256(top_level_site || \0 || resource_host || \0 || url)` - hashing the
partition key together with the URL (not either alone) is what makes the
partitioning real: the exact same URL embedded on two different top-level
sites hashes to two completely different files. It also sidesteps any
path-traversal concern from an arbitrary URL string landing in a filename,
the same reasoning `sync::FileSyncServer` uses for hashing account IDs (see
`05-account-storage-sync.md`).

**Deliberately conservative about what gets cached at all**: only a response
that EXPLICITLY opts in via a real `Cache-Control: max-age=N` header
(`disk_cache::parse_max_age`) is ever written. No guessed default TTL, and
`no-store`/`no-cache` are honored outright. Writes go through a real
temp-file-then-rename (same "can't leave a half-written file behind on a
crash/kill" reasoning as `write_secret_file` in `app` and
`sync::FileSyncServer::write_blob`).

This is explicitly **not a full RFC 7234 cache**: no ETag/`If-None-Match`
revalidation, no `Vary` handling, and no size limit or eviction. An expired
entry just sits on disk, inert, until something eventually overwrites it via
a fresh `put` - it's never proactively swept, because there's no "clear
browsing data" feature yet to hook a sweep into. If you ever add one, this is
where it'd need to plug in.

## `privacy`: the policy layer with no sockets

Everything in `privacy` is a pure function or a pure data structure - no
`network` type appears anywhere in this crate's own signatures, and it can be
fully unit tested with zero I/O. That separation is deliberate: it's what
lets a future settings UI (or this study guide!) reason about "what does
private mode mean here" in one place, and it's why `network`'s own module
docs describe this crate as the thing it "consults."

### The blocklist itself

`Blocklist` wraps the real `adblock` crate (the same engine used by real ad
blockers), loaded from two bundled snapshots -
`privacy/assets/easylist.txt` and `easyprivacy.txt`, compiled into the
binary via `include_str!` so blocking works fully offline with no runtime
fetch (fetching a blocklist over the network on every startup would itself
be a small tracking-adjacent signal, on top of adding latency and a failure
mode). `Blocklist::is_blocked(host, path)` checks BOTH a manual
`extra_blocked_hosts` set (cheap, checked first) and the real engine - `path`
matters because real tracker lists increasingly ship path-specific rules (a
tracker sitting at one specific path on an otherwise-legitimate,
unblockable domain), not just whole-domain rules.

`should_block(ctx, blocklist)` is the actual policy decision, and it's
narrower than "is this on the blocklist": **first-party requests are ALWAYS
allowed through this check**, even if the exact host happens to be on a
list. `ctx.is_third_party()` is what decides that (`top_level_host` differs
from `request_host`, or `top_level_host` is `None` meaning "this request IS
the top-level navigation"). The reasoning: first-party tracking (a site
tracking its own visitors on itself) is a storage-partitioning problem, not
a blocklist problem - blocking it outright would break the site itself,
which isn't what a blocklist is for.

### Storage partitioning and `registrable_domain`

`StoragePartitionKey::for_request` builds the same key the cookie jar and
disk cache both use, keying `top_level_site` on a REAL eTLD+1 (effective
top-level-domain-plus-one) via `registrable_domain`, not a naive "just use
the host as typed." This matters concretely: `shop.example.co.uk` needs to
partition on `example.co.uk`, not `co.uk` (which would incorrectly lump
together every unrelated site on that public suffix) and not
`shop.example.co.uk` (which would incorrectly split `shop.example.co.uk` and
`checkout.example.co.uk` into separate partitions even though they're the
same real site). `registrable_domain` uses the `addr` crate's real Public
Suffix List parsing for this, falling back to the host as-is for things that
aren't real registrable domains at all (a bare IP, `localhost`).

**This same function is reused by `app` for an entirely different purpose**:
deciding which sandboxed renderer PROCESS a tab belongs to (`app`'s
`RendererPool`/site-isolation logic - see `01-process-model-and-ipc.md`).
That's not a coincidence or convenience reuse - it's the same real notion of
"site" that already governs storage partitioning and third-party
classification, deliberately reused rather than reinvented for process
isolation. If you ever need to change what "site" means in this browser,
this is the one function to change, and the blast radius includes both
privacy semantics and process isolation.

### Fingerprint resistance: what's real vs. what's aspirational

This is a place where the module doc comment is very explicit about scope,
and it's worth reading literally:

- **Real today**: window-size letterboxing (`letterbox`/
  `FingerprintResistanceLevel`) and header/timezone/locale normalization
  (`normalize_headers`, `SPOOFED_TIMEZONE`, `SPOOFED_LOCALE`).
- **Not implemented yet**: Canvas/WebGL/AudioContext readback noise,
  font-enumeration limits, JS-exposed `navigator.*` spoofing. These all
  require hooking into the JS engine to intercept the actual API calls a
  page's script would make, which didn't exist when this crate was first
  written and still only partially exists now (see `03-javascript-engine.md`
  for what Boa integration actually covers).

`letterbox(width, height)` rounds a window size DOWN to 100px buckets -
`1437x892` becomes `1400x800`. The idea (straight out of the Tor
Browser/Mullvad Browser playbook): if everyone's window reports one of a
small number of fixed sizes, no single user's exact window dimensions stand
out as a fingerprinting signal. `FingerprintResistanceLevel` exposes this as
a real, honest user choice rather than something silently baked in - `Strict`
(the default) letterboxes; `Standard` reports the real size, for someone who
explicitly wants pixel-exact rendering and knowingly accepts the
fingerprinting tradeoff. This is wired up as a real settings-UI toggle in
`app` (`set fingerprint-resistance strict|standard` - see
`06-app-ui-and-window.md`).

### `default_web_api_policy()`: a decision recorded before there's code to enforce it

This is a slightly unusual pattern worth calling out on its own, because it's
a good example of this codebase's "write down decisions now, even before
there's code to enforce them" philosophy. `default_web_api_policy()` returns
a table of API name to `ApiAccess::{Disabled, Restricted}` - WebRTC,
geolocation, and battery/sensor APIs disabled outright; Canvas/WebGL/
AudioContext marked `Restricted` (available, but should be noised once
there's a readback path to noise). **None of these APIs are actually exposed
to script yet** - there's no WebRTC stack, no geolocation API, nothing. The
point of this table existing anyway is that WHOEVER adds one of these APIs
later has one place that already recorded the decision, instead of having to
rediscover "should WebRTC be on by default" from scratch and possibly get it
wrong. WebRTC specifically gets the most detailed reasoning in the doc
comment: ICE candidate gathering can reveal your real IP address even
through a VPN or Tor, independent of cookies or fingerprinting entirely -
that's a deanonymization vector, not just a privacy nicety, which is why it's
`Disabled` rather than `Restricted`.

## Gotchas and things that are easy to get wrong

- **`extract_host`/`extract_path`/`strip_port` in `network` are naive
  string-splitting, not real URL parsing.** No IDNA/punycode normalization,
  no IPv6 bracket handling. There's a `TODO` in the code to eventually use
  the real `url` crate here (which IS already a dependency of `network`'s
  own transitive deps via `reqwest`) - if you're debugging weird behavior
  with unusual URLs (IPv6 literals, internationalized domains), this is a
  likely culprit.
- **`is_third_party()` is host-based only.** It has no notion of "same site,
  different scheme" and no handling of a redirect chain that changes
  top-level context mid-flight. This is called out explicitly as `privacy`'s
  own top "next step."
- **The disk cache and cookie jar both silently degrade to "nothing
  persisted" if their respective opt-in methods are never called** -
  `FilteringFetcher::enable_disk_cache` and (on the `app` side)
  `RendererProcess`'s seeding logic. A plain unit test building a
  `FilteringFetcher` around a `FakeFetcher` never touches the filesystem
  unless it explicitly asks to - this is intentional (keeps most tests fast
  and hermetic), but it means a test asserting cache/cookie behavior has to
  remember to opt in first, or it'll pass for the wrong reason (nothing
  happened at all).
- **`FakeFetcher::last_request_body` only returns the MOST RECENT request to
  a given URL.** If a test fetches the same URL twice with different bodies
  and only checks `last_request_body`, it's only really testing the second
  call.
- **The blocklist's `Request::new(...)` call always uses a fixed placeholder
  source (`https://a-different-site.com/`) and always claims resource type
  `"script"`.** This is deliberate - `is_blocked` is only ever called after
  something upstream has already decided the request is third-party, and
  most EasyList/EasyPrivacy rules are scoped to third-party, non-document
  resource types. But it means this crate can't currently express "this
  exact request type matters" (e.g. treating an image differently from a
  script) - everything gets checked as if it were a third-party script load.

## Where to look next

- `01-process-model-and-ipc.md` - how a fetched page's cookies/storage
  actually end up encrypted on disk (spoiler: not in this crate).
- `03-javascript-engine.md` - the synchronous-but-promise-wrapped `fetch()`
  trick, and how `localStorage`/IndexedDB use the exact same
  `merge_into`/version-counter pattern cookies do here.
- `06-app-ui-and-window.md` - where `FingerprintResistanceLevel`/blocklist
  settings actually get surfaced to the user.
- `THREAT_MODEL.md` (repo root) - the maintained, audit-oriented list of
  known gaps in this crate (no `SameSite`/`Secure`/`HttpOnly`, no
  `Content-Type`/charset handling, host-based `is_third_party`, etc.) - this
  wiki file explains HOW things work; that file tracks what's still missing
  and why it matters for security specifically.
