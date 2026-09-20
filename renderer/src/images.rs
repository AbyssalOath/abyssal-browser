//! `<img src="...">` fetching and decoding — real, but deliberately
//! scoped down, matching this crate's own established pattern for
//! external `<script src>` (see `script`'s module docs, which this
//! mirrors closely): resolve each `src` against the page's own URL,
//! fetch it through the SAME blocklist-checking, cache-aware,
//! third-party-aware `FilteringFetcher` any other subresource uses (a
//! third-party tracking pixel gets blocked exactly like a third-party
//! tracking script would), then decode it — inside THIS sandboxed
//! process, never in `app` (see `layout::ImageContent`'s doc comment
//! for why that split matters: it's what keeps an image-decoding
//! dependency, a classic source of real memory-corruption bugs when
//! parsing attacker-controlled bytes, out of the privileged process
//! entirely). Decoding itself is via the `image` crate with only
//! pure-Rust codecs enabled (`png`, `zune-jpeg`, `gif`, `bmp` — no
//! default features, no C dependency anywhere in that dependency
//! tree — see this crate's own Cargo.toml) — the same "memory safety
//! over raw feature count" reasoning `renderer/src/script.rs` gives
//! for choosing Boa over V8/QuickJS applies here too, for exactly the
//! same class of untrusted input.
//!
//! Scope, deliberately narrow:
//!   - Only `<img src="...">` — no `<picture>`/`srcset` (responsive
//!     image selection), no lazy-loading, no `object-fit`.
//!   - A failed fetch, a blocked (third-party tracker) request, or a
//!     failed decode all just mean that `<img>` never gets a
//!     `layout::ImageContent` at all — `layout` then renders it as an
//!     ordinary empty inline box (see that crate's own docs), not a
//!     real browser's "broken image" icon. Silent-but-logged, matching
//!     `resolve_and_fetch_scripts`'s own failure philosophy.
//!   - Every decoded image is downscaled (preserving aspect ratio) to
//!     at most `MAX_IMAGE_DIMENSION` on its longer side BEFORE it ever
//!     crosses the `app`<->`renderer` IPC boundary — see that
//!     constant's own doc comment for why.
//!
//! **Fetched CONCURRENTLY, not one at a time.** A real, image-heavy
//! page can easily reference several dozen images; each fetch is a
//! real network round trip (DNS, TCP, TLS, request, response), and
//! doing them strictly in sequence is the dominant cost of loading
//! such a page in practice — confirmed against a real, ordinary
//! (if unusually image-heavy) real-world site, where sequential
//! fetching of 39 images took over 80 real seconds end to end, versus
//! a few seconds once parallelized. `resolve_and_fetch_images` splits
//! the list across a small, bounded pool of real OS threads (see
//! `MAX_CONCURRENT_IMAGE_FETCHES`) — the same order of concurrency a
//! real browser already uses per origin. Each thread gets its own
//! INDEPENDENT clone of the fetcher (see `FilteringFetcher::
//! clone_for_concurrent_use`'s own doc comment for exactly what that
//! does and doesn't preserve — notably, no disk-cache access from the
//! parallel workers) rather than sharing one mutable fetcher across
//! threads, which this crate's `Rc<RefCell<..>>`-based fetcher
//! plumbing elsewhere is deliberately NOT built to support.

use std::collections::HashMap;
use std::sync::mpsc;

use network::{Fetcher, FilteringFetcher};

/// A bounded worker-thread count for concurrent image fetching — real
/// browsers commonly cap concurrent connections per origin around this
/// same order of magnitude (historically 6 for HTTP/1.1 keep-alive),
/// so this isn't an aggressive outlier that would be unusually likely
/// to trip a server's own rate limiting. Also caps how many independent
/// fetcher clones (and so how many separately-cold DNS caches, cookie
/// jar snapshots, ...) a single navigation ever creates at once,
/// regardless of how many images a page actually has.
const MAX_CONCURRENT_IMAGE_FETCHES: usize = 6;

/// A hard cap on the LONGER side of a decoded image, applied before it
/// crosses the `app`<->`renderer` IPC boundary at all — see
/// `layout::ImageContent`'s doc comment for the general reasoning: an
/// uncompressed RGBA8 bitmap is often many times the size of the
/// compressed bytes it was decoded from (a modest 1920x1080 photo
/// alone is ~8MB uncompressed). Bounds any ONE image; see
/// `MAX_TOTAL_IMAGE_PIXEL_BYTES` for the cap across a whole page's
/// worth of them, since this alone was NOT enough in practice — a real
/// image-heavy page with three dozen large photos, each independently
/// within this cap, still added up to a message many times over
/// `ipc::MAX_MESSAGE_LEN`. 1200px is generous for anything this
/// browser's own layout (no explicit `width`/`height` CSS properties —
/// see `layout`'s module docs) would ever actually display at.
const MAX_IMAGE_DIMENSION: u32 = 1200;

/// A hard cap on the SUM of every decoded image's raw pixel bytes on
/// one page — `MAX_IMAGE_DIMENSION` alone bounds a single image, but a
/// real page can embed dozens of them, and `layout::ImageContent`'s
/// `pixels` crosses the wire as a plain JSON array of numbers (no
/// base64/binary framing), which measured at roughly 2.6x the raw byte
/// count for real photo content. Confirmed against a real site (39
/// images, each already at the `MAX_IMAGE_DIMENSION` cap): total raw
/// pixel bytes alone came to ~214 MiB, serializing to a ~552 MiB
/// message — `serve` correctly REFUSES to ever write a message over
/// `ipc::MAX_MESSAGE_LEN` (64 MiB), so without a total-page budget too,
/// `navigate` would successfully fetch and decode everything only to
/// have the whole navigation still fail at the very last step. 12 MiB
/// raw leaves roughly 40 MiB of serialized headroom (12 MiB * ~2.6x
/// expansion ≈ 31 MiB) inside the 64 MiB budget for the rest of a real
/// page's layout tree (text, boxes, CSS) on top of it. Once spent,
/// remaining images are dropped the same silent-but-logged way a
/// failed fetch/decode already is — see the aggregation loop below.
const MAX_TOTAL_IMAGE_PIXEL_BYTES: usize = 12 * 1024 * 1024;

/// Collects every `<img src="...">` element's (node id, unresolved
/// src) pair, in document order — mirrors `script::extract_scripts`'s
/// own shape and reasoning closely. Also collects a `<video
/// poster="...">`'s poster, keyed by the VIDEO's own node id (not a
/// separate one) — `renderer::media` looks it up the same way
/// `layout::build_layout_tree_with_media` expects a video's poster to
/// arrive, reusing this entire fetch/decode pipeline rather than
/// building a second one for what's still just an image underneath.
pub fn extract_image_sources(document: &dom::NodeRef) -> Vec<(dom::NodeId, String)> {
    let mut sources = Vec::new();
    collect_image_sources(document, &mut sources);
    sources
}

fn collect_image_sources(node: &dom::NodeRef, out: &mut Vec<(dom::NodeId, String)>) {
    let (src, children) = {
        let node_ref = node.borrow();
        match &node_ref.node_type {
            dom::NodeType::Element(el) if el.tag_name == "img" => {
                (el.attributes.get("src").cloned(), node_ref.children.clone())
            }
            dom::NodeType::Element(el) if el.tag_name == "video" => (
                el.attributes.get("poster").cloned(),
                node_ref.children.clone(),
            ),
            _ => (None, node_ref.children.clone()),
        }
    };
    if let Some(src) = src {
        out.push((node.borrow().id, src));
    }
    // `<img>` is a void HTML element in practice (html5ever's parser
    // never gives it real children), but recursing regardless is
    // harmless and defensive rather than assuming that.
    for child in &children {
        collect_image_sources(child, out);
    }
}

/// Resolves every `(node id, src)` pair against `page_url` and
/// fetches + decodes each one, CONCURRENTLY (see this module's own
/// doc comment on why) — otherwise mirrors
/// `script::resolve_and_fetch_scripts`'s own third-party/failure-
/// handling story closely (including the same "can't even determine
/// the page's own host — skip everything rather than risk
/// misjudging first/third-party" fallback).
pub fn resolve_and_fetch_images<F: Fetcher + Clone + Send>(
    sources: &[(dom::NodeId, String)],
    page_url: &str,
    fetcher: &mut FilteringFetcher<F>,
) -> HashMap<dom::NodeId, layout::ImageContent> {
    let mut images = HashMap::new();
    if sources.is_empty() {
        return images;
    }

    let page_host = match url::Url::parse(page_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
    {
        Some(host) => host,
        None => {
            eprintln!(
                "renderer: could not determine the page's own host from {page_url:?} — skipping all \
                 images on this page rather than risk misjudging first/third-party."
            );
            return images;
        }
    };

    // Resolving each `src` against `page_url` is cheap, pure string
    // work (no I/O) — done up front, sequentially, so every worker
    // thread below only ever deals with already-resolved, absolute
    // URLs, never `page_url`/relative-resolution logic of its own.
    let mut resolved: Vec<(dom::NodeId, String)> = Vec::with_capacity(sources.len());
    for (node_id, src) in sources {
        match url::Url::parse(page_url).and_then(|base| base.join(src)) {
            Ok(resolved_url) => resolved.push((*node_id, resolved_url.to_string())),
            Err(_) => eprintln!(
                "renderer: could not resolve image src {src:?} against page URL {page_url:?} (skipping)"
            ),
        }
    }
    if resolved.is_empty() {
        return images;
    }

    // Bounded, even-ish chunks across at most `MAX_CONCURRENT_IMAGE_FETCHES`
    // real OS threads — see this module's own doc comment. `thread::scope`
    // (not a detached `thread::spawn`) is what lets each worker borrow
    // `page_host`/`resolved` directly instead of needing `'static` +
    // its own owned copy of everything, and guarantees every worker
    // has finished (successfully or not) before this function returns.
    let chunk_size = resolved.len().div_ceil(MAX_CONCURRENT_IMAGE_FETCHES).max(1);
    let (results_tx, results_rx) = mpsc::channel();
    std::thread::scope(|scope| {
        for chunk in resolved.chunks(chunk_size) {
            let mut worker_fetcher = fetcher.clone_for_concurrent_use();
            let page_host = page_host.as_str();
            let results_tx = results_tx.clone();
            scope.spawn(move || {
                for (node_id, resolved_url) in chunk {
                    let outcome =
                        fetch_and_decode_one(&mut worker_fetcher, resolved_url, page_host);
                    // The receiving end only ever stops listening if
                    // this whole function has already returned, which
                    // can't happen while `scope` is still waiting on
                    // this very thread — a dropped receiver here isn't
                    // a real scenario this needs to handle.
                    let _ = results_tx.send((*node_id, outcome));
                }
            });
        }
    });
    // Dropped so the loop below ends once every worker's own sender
    // clone (and this original) has gone out of scope — `scope` above
    // already guarantees every worker thread (and so every sender
    // clone it held) has finished by this point regardless.
    drop(results_tx);

    // A running budget on TOTAL decoded pixel bytes across every image
    // on this page — see `MAX_TOTAL_IMAGE_PIXEL_BYTES`'s own doc
    // comment for why this exists at all: `MAX_IMAGE_DIMENSION` alone
    // bounds a single image, but a real image-heavy page (dozens of
    // large photos) can still add up to a serialized IPC message many
    // times over `ipc::MAX_MESSAGE_LEN`, which — confirmed against a
    // real site with 39 large images — made `navigate` succeed at
    // FETCHING and DECODING everything, only to fail to ever hand the
    // result back to `app` at all (`serve` refuses to write a message
    // over the limit). Once the budget's spent, later images (in
    // whatever order their worker chunk happened to finish) are
    // dropped the same silent-but-logged way a failed fetch/decode
    // already is — a page that's over budget shows SOME of its images
    // rather than none, and never any indication beyond `<img>`'s
    // usual empty-box fallback either way.
    let mut total_pixel_bytes: usize = 0;
    let mut skipped_over_budget = 0usize;
    for (node_id, outcome) in results_rx {
        match outcome {
            Ok(content) => {
                if total_pixel_bytes + content.pixels.len() > MAX_TOTAL_IMAGE_PIXEL_BYTES {
                    skipped_over_budget += 1;
                    continue;
                }
                total_pixel_bytes += content.pixels.len();
                images.insert(node_id, content);
            }
            Err(e) => eprintln!("renderer: {e} (skipping)"),
        }
    }
    if skipped_over_budget > 0 {
        eprintln!(
            "renderer: {skipped_over_budget} image(s) skipped — this page's total decoded image \
             size exceeded the {MAX_TOTAL_IMAGE_PIXEL_BYTES}-byte per-page budget"
        );
    }
    images
}

/// One worker thread's own unit of work: fetch (through ITS OWN
/// fetcher clone) then decode a single already-resolved image URL.
fn fetch_and_decode_one<F: Fetcher>(
    fetcher: &mut FilteringFetcher<F>,
    resolved_url: &str,
    page_host: &str,
) -> Result<layout::ImageContent, String> {
    let response = fetcher
        .fetch_in_context(resolved_url, Some(page_host))
        .map_err(|e| format!("failed to fetch image {resolved_url:?}: {e:?}"))?;
    decode_and_downscale(&response.body)
        .map_err(|e| format!("failed to decode image {resolved_url:?}: {e}"))
}

/// Decodes raw (PNG/JPEG/GIF/BMP) bytes into RGBA8, downscaling first
/// if needed — see `MAX_IMAGE_DIMENSION`'s doc comment. `image::load_from_memory`
/// sniffs the format from the bytes themselves rather than trusting a
/// `Content-Type` header (which this crate doesn't even carry through
/// `network::Response` today) or the URL's extension — the only sound
/// approach for attacker-controlled bytes.
fn decode_and_downscale(bytes: &[u8]) -> Result<layout::ImageContent, String> {
    let decoded = image::load_from_memory(bytes).map_err(|e| e.to_string())?;
    let decoded = if decoded.width() > MAX_IMAGE_DIMENSION || decoded.height() > MAX_IMAGE_DIMENSION
    {
        decoded.resize(
            MAX_IMAGE_DIMENSION,
            MAX_IMAGE_DIMENSION,
            image::imageops::FilterType::Triangle,
        )
    } else {
        decoded
    };
    let rgba = decoded.to_rgba8();
    let (width, height) = rgba.dimensions();
    Ok(layout::ImageContent {
        width,
        height,
        pixels: rgba.into_raw(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(html: &str) -> dom::NodeRef {
        html::parse(html)
    }

    /// A tiny (1x1, red) real, valid PNG — hand-encoded rather than
    /// pulled from a file, so these tests have no external fixture to
    /// keep in sync. Produced once via the real `image` crate and
    /// hardcoded here as bytes (see the doc comment on why: a test
    /// fixture this small is easier to embed than to load from disk,
    /// and it's exercised through the exact same `image::load_from_memory`
    /// production code path either way).
    fn tiny_red_png() -> Vec<u8> {
        let img = image::RgbaImage::from_pixel(1, 1, image::Rgba([255, 0, 0, 255]));
        let mut bytes = Vec::new();
        image::DynamicImage::ImageRgba8(img)
            .write_to(
                &mut std::io::Cursor::new(&mut bytes),
                image::ImageFormat::Png,
            )
            .expect("encoding a 1x1 PNG for tests should never fail");
        bytes
    }

    #[test]
    fn extract_image_sources_finds_img_elements_with_a_src() {
        let document =
            parse(r#"<html><body><img src="a.png"><p>text</p><img src="b.jpg"></body></html>"#);
        let sources = extract_image_sources(&document);
        assert_eq!(sources.len(), 2);
        assert_eq!(sources[0].1, "a.png");
        assert_eq!(sources[1].1, "b.jpg");
    }

    #[test]
    fn extract_image_sources_ignores_an_img_with_no_src_attribute() {
        let document = parse("<html><body><img></body></html>");
        assert!(extract_image_sources(&document).is_empty());
    }

    #[test]
    fn resolve_and_fetch_images_decodes_a_real_fetched_image() {
        let mut fake = network::FakeFetcher::new();
        fake.register_bytes("https://example.com/a.png", tiny_red_png());
        let mut fetcher =
            network::FilteringFetcher::new(fake, privacy::Blocklist::with_seed_list());

        let sources = vec![(dom::NodeId(1), "/a.png".to_string())];
        let images =
            resolve_and_fetch_images(&sources, "https://example.com/index.html", &mut fetcher);

        let image = images
            .get(&dom::NodeId(1))
            .expect("the image should have decoded successfully");
        assert_eq!((image.width, image.height), (1, 1));
        assert_eq!(
            image.pixels,
            vec![255, 0, 0, 255],
            "should decode to a single opaque red RGBA8 pixel"
        );
    }

    #[test]
    fn resolve_and_fetch_images_skips_a_blocked_third_party_image() {
        let mut fake = network::FakeFetcher::new();
        fake.register_bytes("http://g.doubleclick.net/pixel.png", tiny_red_png());
        let mut fetcher =
            network::FilteringFetcher::new(fake, privacy::Blocklist::with_seed_list());

        let sources = vec![(
            dom::NodeId(1),
            "http://g.doubleclick.net/pixel.png".to_string(),
        )];
        let images = resolve_and_fetch_images(&sources, "https://news.example.com/", &mut fetcher);

        assert!(
            images.is_empty(),
            "a third-party tracking pixel should be blocked, not decoded"
        );
    }

    #[test]
    fn resolve_and_fetch_images_skips_an_image_that_fails_to_fetch() {
        let fake = network::FakeFetcher::new(); // nothing registered
        let mut fetcher =
            network::FilteringFetcher::new(fake, privacy::Blocklist::with_seed_list());

        let sources = vec![(
            dom::NodeId(1),
            "https://example.com/missing.png".to_string(),
        )];
        let images = resolve_and_fetch_images(&sources, "https://example.com/", &mut fetcher);
        assert!(images.is_empty());
    }

    #[test]
    fn resolve_and_fetch_images_skips_bytes_that_are_not_a_real_image() {
        let mut fake = network::FakeFetcher::new();
        fake.register("https://example.com/fake.png", "not actually a png");
        let mut fetcher =
            network::FilteringFetcher::new(fake, privacy::Blocklist::with_seed_list());

        let sources = vec![(dom::NodeId(1), "/fake.png".to_string())];
        let images =
            resolve_and_fetch_images(&sources, "https://example.com/index.html", &mut fetcher);
        assert!(
            images.is_empty(),
            "malformed image bytes should be skipped, not panic or produce garbage pixels"
        );
    }

    /// A real, valid, solid-color PNG at a given size — used (unlike
    /// `tiny_red_png`) where a test needs a REAL, non-trivial pixel
    /// byte count to exercise `MAX_TOTAL_IMAGE_PIXEL_BYTES`.
    fn solid_png(width: u32, height: u32) -> Vec<u8> {
        let img = image::RgbaImage::from_pixel(width, height, image::Rgba([0, 0, 255, 255]));
        let mut bytes = Vec::new();
        image::DynamicImage::ImageRgba8(img)
            .write_to(
                &mut std::io::Cursor::new(&mut bytes),
                image::ImageFormat::Png,
            )
            .expect("encoding a solid PNG for tests should never fail");
        bytes
    }

    #[test]
    fn resolve_and_fetch_images_stops_once_the_total_pixel_byte_budget_is_spent() {
        // Each decoded image is 600x600x4 = 1,440,000 raw pixel bytes —
        // with `MAX_TOTAL_IMAGE_PIXEL_BYTES` == 12 MiB, that's room for
        // exactly 8 of them (11,520,000 bytes) before a 9th would push
        // the running total over budget and get skipped, the same
        // silent-but-logged way a failed fetch/decode already is. 12
        // offered images (more than the 8 that fit) proves the rest are
        // genuinely DROPPED, not merely deferred.
        const IMAGE_PIXEL_BYTES: usize = 600 * 600 * 4;
        let images_that_fit = MAX_TOTAL_IMAGE_PIXEL_BYTES / IMAGE_PIXEL_BYTES;
        assert_eq!(
            images_that_fit, 8,
            "this test's own arithmetic assumption about the current budget/image-size ratio"
        );

        let mut fake = network::FakeFetcher::new();
        let offered = 12;
        let mut sources = Vec::with_capacity(offered);
        for i in 0..offered {
            let url = format!("https://example.com/{i}.png");
            fake.register_bytes(&url, solid_png(600, 600));
            sources.push((dom::NodeId(i as u64), format!("/{i}.png")));
        }
        let mut fetcher =
            network::FilteringFetcher::new(fake, privacy::Blocklist::with_seed_list());

        let images =
            resolve_and_fetch_images(&sources, "https://example.com/index.html", &mut fetcher);

        assert_eq!(
            images.len(),
            images_that_fit,
            "only as many images as fit within the total pixel-byte budget should come back"
        );
        let total_bytes: usize = images.values().map(|img| img.pixels.len()).sum();
        assert!(
            total_bytes <= MAX_TOTAL_IMAGE_PIXEL_BYTES,
            "the running total across every returned image must never exceed the budget"
        );
    }

    #[test]
    fn resolve_and_fetch_images_decodes_every_image_across_more_than_one_worker_chunk() {
        // 14 images with `MAX_CONCURRENT_IMAGE_FETCHES` == 6 genuinely
        // exercises the multi-thread/multi-chunk path (three chunks of
        // <=6 each), not just the single-worker case every other test
        // above covers.
        let mut fake = network::FakeFetcher::new();
        let image_count = 14;
        let mut sources = Vec::with_capacity(image_count);
        for i in 0..image_count {
            let url = format!("https://example.com/{i}.png");
            fake.register_bytes(&url, tiny_red_png());
            sources.push((dom::NodeId(i as u64), format!("/{i}.png")));
        }
        let mut fetcher =
            network::FilteringFetcher::new(fake, privacy::Blocklist::with_seed_list());

        let images =
            resolve_and_fetch_images(&sources, "https://example.com/index.html", &mut fetcher);

        assert_eq!(
            images.len(),
            image_count,
            "every image across every worker chunk should decode successfully"
        );
        for i in 0..image_count {
            let image = images
                .get(&dom::NodeId(i as u64))
                .unwrap_or_else(|| panic!("image {i} should have decoded"));
            assert_eq!((image.width, image.height), (1, 1));
            assert_eq!(image.pixels, vec![255, 0, 0, 255]);
        }
    }

    #[test]
    fn decode_and_downscale_shrinks_an_oversized_image_but_keeps_aspect_ratio() {
        let img = image::RgbaImage::from_pixel(3000, 1500, image::Rgba([0, 255, 0, 255]));
        let mut bytes = Vec::new();
        image::DynamicImage::ImageRgba8(img)
            .write_to(
                &mut std::io::Cursor::new(&mut bytes),
                image::ImageFormat::Png,
            )
            .unwrap();

        let content = decode_and_downscale(&bytes).unwrap();
        assert!(content.width <= MAX_IMAGE_DIMENSION);
        assert!(content.height <= MAX_IMAGE_DIMENSION);
        // 3000x1500 is a real 2:1 aspect ratio — resizing to fit within
        // a 1200x1200 box while preserving it should land at 1200x600.
        assert_eq!((content.width, content.height), (1200, 600));
    }
}
