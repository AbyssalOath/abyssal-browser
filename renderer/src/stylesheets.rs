//! `<link rel="stylesheet" href="...">` fetching — real now, mirroring
//! this crate's own established pattern for external `<script src>`
//! and `<img src>` (see `script`'s and `images`' module docs, which
//! this closely follows): resolve each `href` against the page's own
//! URL, fetch it through the SAME blocklist-checking, cache-aware,
//! third-party-aware `FilteringFetcher` any other subresource uses (a
//! third-party stylesheet — rare in practice, but not impossible — is
//! blocked exactly like a third-party tracking script or pixel would
//! be), and hand back the raw CSS text keyed by the `<link>` element's
//! `dom::NodeId` so `css::extract_author_stylesheet_with_external` can
//! splice it in at the right point in document order.
//!
//! Unlike images, there's no decoding step here at all — CSS is parsed
//! (by the `css` crate, not this one) as plain text, not attacker-
//! controlled binary that needs a memory-safety-sensitive decoder. The
//! parse itself still happens against untrusted bytes, but `css`'s own
//! hand-rolled parser has no unsafe code and simply produces fewer/
//! wrong rules on malformed input rather than anything memory-unsafe
//! (see that crate's own module docs).
//!
//! Scope, deliberately narrow:
//!   - No `@import` inside a fetched stylesheet (a stylesheet that
//!     itself pulls in another external file via `@import` gets
//!     nothing from that second file) — `css`'s parser has no at-rule
//!     support at all yet (see its own module docs).
//!   - No `media` attribute / `@media` handling — a
//!     `<link media="print">` stylesheet is fetched and applied
//!     unconditionally, same as an unconditional one.
//!   - A failed fetch, a blocked (third-party) request, or bytes that
//!     don't decode as valid UTF-8 (lossily replaced rather than
//!     rejected — matching how `renderer::navigate` already treats the
//!     main page body) just mean that `<link>` contributes nothing,
//!     the same silent-but-logged failure philosophy `images`/`script`
//!     already establish.

use std::collections::HashMap;

use network::{Fetcher, FilteringFetcher};

/// Collects every `<link rel="stylesheet" href="...">` element's
/// (node id, unresolved href) pair, in document order — mirrors
/// `images::extract_image_sources`'s own shape and reasoning closely.
pub fn extract_stylesheet_links(document: &dom::NodeRef) -> Vec<(dom::NodeId, String)> {
    let mut links = Vec::new();
    collect_stylesheet_links(document, &mut links);
    links
}

fn collect_stylesheet_links(node: &dom::NodeRef, out: &mut Vec<(dom::NodeId, String)>) {
    let (href, children) = {
        let node_ref = node.borrow();
        match &node_ref.node_type {
            dom::NodeType::Element(el) if el.tag_name == "link" && is_stylesheet_rel(el) => (
                el.attributes.get("href").cloned(),
                node_ref.children.clone(),
            ),
            _ => (None, node_ref.children.clone()),
        }
    };
    if let Some(href) = href {
        out.push((node.borrow().id, href));
    }
    // `<link>` is a void HTML element in practice, but recursing
    // regardless is harmless and defensive, matching `images`'s own
    // treatment of `<img>`.
    for child in &children {
        collect_stylesheet_links(child, out);
    }
}

fn is_stylesheet_rel(el: &dom::Element) -> bool {
    el.attributes.get("rel").is_some_and(|rel| {
        rel.split_whitespace()
            .any(|tok| tok.eq_ignore_ascii_case("stylesheet"))
    })
}

/// Resolves every `(node id, href)` pair against `page_url` and fetches
/// each one — see this module's own doc comment for the full third-
/// party/failure-handling story, which mirrors
/// `images::resolve_and_fetch_images` closely (including the same
/// "can't even determine the page's own host — skip everything rather
/// than risk misjudging first/third-party" fallback).
pub fn resolve_and_fetch_stylesheets<F: Fetcher>(
    links: &[(dom::NodeId, String)],
    page_url: &str,
    fetcher: &mut FilteringFetcher<F>,
) -> HashMap<dom::NodeId, String> {
    let mut stylesheets = HashMap::new();
    if links.is_empty() {
        return stylesheets;
    }

    let page_host = match url::Url::parse(page_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
    {
        Some(host) => host,
        None => {
            eprintln!(
                "renderer: could not determine the page's own host from {page_url:?} — skipping all \
                 external stylesheets on this page rather than risk misjudging first/third-party."
            );
            return stylesheets;
        }
    };

    for (node_id, href) in links {
        let Some(resolved_url) = url::Url::parse(page_url)
            .and_then(|base| base.join(href))
            .ok()
            .map(|u| u.to_string())
        else {
            eprintln!(
                "renderer: could not resolve stylesheet href {href:?} against page URL {page_url:?} (skipping)"
            );
            continue;
        };
        let response = match fetcher.fetch_in_context(&resolved_url, Some(&page_host)) {
            Ok(response) => response,
            Err(e) => {
                eprintln!(
                    "renderer: failed to fetch stylesheet {resolved_url:?}: {e:?} (skipping)"
                );
                continue;
            }
        };
        let css_text = String::from_utf8_lossy(&response.body).into_owned();
        stylesheets.insert(*node_id, css_text);
    }
    stylesheets
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(html: &str) -> dom::NodeRef {
        html::parse(html)
    }

    #[test]
    fn extract_stylesheet_links_finds_link_rel_stylesheet_elements() {
        let document = parse(
            r#"<html><head>
                <link rel="stylesheet" href="a.css">
                <link rel="icon" href="favicon.ico">
                <link rel="stylesheet" href="b.css">
            </head><body></body></html>"#,
        );
        let links = extract_stylesheet_links(&document);
        assert_eq!(links.len(), 2);
        assert_eq!(links[0].1, "a.css");
        assert_eq!(links[1].1, "b.css");
    }

    #[test]
    fn extract_stylesheet_links_matches_a_multi_token_rel_attribute() {
        let document =
            parse(r#"<html><head><link rel="preload stylesheet" href="a.css"></head></html>"#);
        let links = extract_stylesheet_links(&document);
        assert_eq!(links.len(), 1);
    }

    #[test]
    fn extract_stylesheet_links_ignores_a_link_with_no_href() {
        let document = parse(r#"<html><head><link rel="stylesheet"></head></html>"#);
        assert!(extract_stylesheet_links(&document).is_empty());
    }

    #[test]
    fn resolve_and_fetch_stylesheets_fetches_real_css_text() {
        let mut fake = network::FakeFetcher::new();
        fake.register("https://example.com/style.css", "p { color: red; }");
        let mut fetcher =
            network::FilteringFetcher::new(fake, privacy::Blocklist::with_seed_list());

        let links = vec![(dom::NodeId(1), "/style.css".to_string())];
        let sheets =
            resolve_and_fetch_stylesheets(&links, "https://example.com/index.html", &mut fetcher);

        assert_eq!(
            sheets.get(&dom::NodeId(1)).map(String::as_str),
            Some("p { color: red; }")
        );
    }

    #[test]
    fn resolve_and_fetch_stylesheets_skips_a_blocked_third_party_stylesheet() {
        let mut fake = network::FakeFetcher::new();
        fake.register("http://g.doubleclick.net/evil.css", "body { color: red; }");
        let mut fetcher =
            network::FilteringFetcher::new(fake, privacy::Blocklist::with_seed_list());

        let links = vec![(
            dom::NodeId(1),
            "http://g.doubleclick.net/evil.css".to_string(),
        )];
        let sheets =
            resolve_and_fetch_stylesheets(&links, "https://news.example.com/", &mut fetcher);
        assert!(sheets.is_empty());
    }

    #[test]
    fn resolve_and_fetch_stylesheets_skips_one_that_fails_to_fetch() {
        let fake = network::FakeFetcher::new(); // nothing registered
        let mut fetcher =
            network::FilteringFetcher::new(fake, privacy::Blocklist::with_seed_list());

        let links = vec![(
            dom::NodeId(1),
            "https://example.com/missing.css".to_string(),
        )];
        let sheets = resolve_and_fetch_stylesheets(&links, "https://example.com/", &mut fetcher);
        assert!(sheets.is_empty());
    }
}
