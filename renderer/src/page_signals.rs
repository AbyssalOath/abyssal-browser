//! Small, local-only "transparency" signals about a fetched page —
//! whether it uses JavaScript at all, and how many of its links look
//! like affiliate/tracked-referral links. Computed fresh from the live
//! DOM on every `RenderSuccess` (see `crate::render_success`), never
//! cached from `Navigate` time alone, so a script that mutates the DOM
//! afterward is still reflected. See `ipc::PageSignals`'s own doc
//! comment for what `app` does with the result — this module only ever
//! computes it, never acts on it.
//!
//! This is deliberately a read-only pass with no effect on fetching,
//! parsing, or rendering: it exists purely to inform a badge in `app`'s
//! chrome, not to filter or alter anything about the page itself.

/// Known affiliate-network redirect/link-shortener domains. Not
/// exhaustive — new affiliate networks (and rebrands of old ones)
/// appear constantly — but each of these is a domain whose ENTIRE
/// purpose is redirecting through an affiliate/referral link, so a
/// substring match here has essentially no false-positive risk (unlike
/// a query-parameter heuristic, which can coincidentally collide with
/// an unrelated site's own unrelated `ref=`/`tag=` parameter).
const AFFILIATE_DOMAINS: &[&str] = &[
    "amzn.to",
    "go.skimresources.com",
    "redirect.viglink.com",
    "shareasale.com",
    "linksynergy.com",
    "awin1.com",
    "prf.hn",
    "sjv.io",
    "anrdoezrs.net",
    "dpbolvw.net",
    "jdoqocy.com",
    "kqzyfj.com",
    "tkqlhce.com",
    "rstyle.me",
    "shopstyle.it",
    "ojrq.net",
    "avantlink.com",
    "pjatr.com",
    "sovrn.co",
];

/// Query-string parameter names strongly associated with affiliate
/// tracking (Amazon's own `tag=`, Impact Radius's `irclickid=`, etc.).
/// Checked as a bare `key=` substring rather than real query parsing —
/// good enough for a best-effort badge, and avoids pulling in a URL
/// parser for something this scoped. Kept deliberately short: a
/// generic `ref=`/`source=` would flag a huge number of ordinary
/// internal-navigation links that have nothing to do with affiliate
/// programs, which would make the badge noisy enough to ignore.
const AFFILIATE_QUERY_PARAMS: &[&str] = &[
    "tag=",
    "affid=",
    "aff_id=",
    "irclickid=",
    "ascsubtag=",
    "smid=",
];

/// A link is also counted as affiliate when it explicitly says so via
/// `rel="sponsored"` — the value search engines' own guidelines ask
/// paid/affiliate links to use, so a page that follows that convention
/// is trusted at its word rather than pattern-matched.
fn has_sponsored_rel(attributes: &std::collections::HashMap<String, String>) -> bool {
    attributes.get("rel").is_some_and(|rel| {
        rel.split_whitespace()
            .any(|tok| tok.eq_ignore_ascii_case("sponsored"))
    })
}

/// Heuristic-only: matches a known affiliate redirector domain or a
/// known affiliate tracking query parameter, case-insensitively over
/// the raw href text. Known blind spots, left as-is rather than
/// over-engineered for a badge: relative/obfuscated redirect chains
/// this can't see through, and any affiliate network not in
/// `AFFILIATE_DOMAINS`/`AFFILIATE_QUERY_PARAMS` above.
fn is_affiliate_href(href: &str) -> bool {
    let lower = href.to_ascii_lowercase();
    AFFILIATE_DOMAINS.iter().any(|d| lower.contains(d))
        || AFFILIATE_QUERY_PARAMS.iter().any(|p| lower.contains(p))
}

/// Walks the live DOM once, computing both signals in a single pass.
pub fn compute(document: &dom::NodeRef) -> ipc::PageSignals {
    let mut uses_javascript = false;
    let mut affiliate_link_count = 0usize;
    walk(document, &mut uses_javascript, &mut affiliate_link_count);
    ipc::PageSignals {
        uses_javascript,
        affiliate_link_count,
    }
}

fn walk(node: &dom::NodeRef, uses_javascript: &mut bool, affiliate_link_count: &mut usize) {
    let node_ref = node.borrow();
    if let dom::NodeType::Element(el) = &node_ref.node_type {
        if el.tag_name.eq_ignore_ascii_case("script") {
            *uses_javascript = true;
        } else if el.tag_name.eq_ignore_ascii_case("a") {
            let looks_affiliate = el
                .attributes
                .get("href")
                .is_some_and(|href| is_affiliate_href(href))
                || has_sponsored_rel(&el.attributes);
            if looks_affiliate {
                *affiliate_link_count += 1;
            }
        }
    }
    for child in &node_ref.children {
        walk(child, uses_javascript, affiliate_link_count);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(html: &str) -> dom::NodeRef {
        html::parse(html)
    }

    #[test]
    fn detects_an_inline_script() {
        let doc = parse("<html><body><script>1;</script></body></html>");
        let signals = compute(&doc);
        assert!(signals.uses_javascript);
        assert_eq!(signals.affiliate_link_count, 0);
    }

    #[test]
    fn detects_an_external_script_tag_even_if_unresolved() {
        let doc = parse(r#"<html><body><script src="/app.js"></script></body></html>"#);
        assert!(compute(&doc).uses_javascript);
    }

    #[test]
    fn a_page_with_no_script_tag_reports_no_javascript() {
        let doc = parse("<html><body><p>hi</p></body></html>");
        assert!(!compute(&doc).uses_javascript);
    }

    #[test]
    fn counts_a_known_affiliate_domain_link() {
        let doc = parse(r#"<html><body><a href="https://amzn.to/abc123">deal</a></body></html>"#);
        assert_eq!(compute(&doc).affiliate_link_count, 1);
    }

    #[test]
    fn counts_a_link_with_an_affiliate_tracking_param() {
        let doc = parse(
            r#"<html><body><a href="https://example.com/product?tag=mysite-20">buy</a></body></html>"#,
        );
        assert_eq!(compute(&doc).affiliate_link_count, 1);
    }

    #[test]
    fn counts_a_link_marked_rel_sponsored_regardless_of_its_href() {
        let doc = parse(
            r#"<html><body><a href="https://example.com/x" rel="sponsored">ad</a></body></html>"#,
        );
        assert_eq!(compute(&doc).affiliate_link_count, 1);
    }

    #[test]
    fn an_ordinary_link_is_not_counted() {
        let doc =
            parse(r#"<html><body><a href="https://example.com/about">About</a></body></html>"#);
        assert_eq!(compute(&doc).affiliate_link_count, 0);
    }

    #[test]
    fn counts_multiple_affiliate_links_across_the_page() {
        let doc = parse(
            r#"<html><body>
                <a href="https://amzn.to/1">a</a>
                <a href="https://example.com/about">b</a>
                <a href="https://example.com/x?irclickid=abc">c</a>
            </body></html>"#,
        );
        assert_eq!(compute(&doc).affiliate_link_count, 2);
    }
}
