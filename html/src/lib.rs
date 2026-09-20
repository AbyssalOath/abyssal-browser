//! `html` — turns raw HTML text into a `dom::Node` tree.
//!
//! Real HTML5 parsing now: tokenization and tree construction (every
//! insertion mode, error recovery, implied tags — the parts that make
//! HTML parsing "hundreds of pages of spec" rather than a simple
//! grammar) are fully delegated to `html5ever`, the same parser
//! Servo/Firefox use. This crate's own code is just a thin adapter:
//! html5ever parses into `rcdom::RcDom` (a vendored copy of
//! html5ever's own reference DOM implementation — see that module's
//! doc comment for why it's vendored rather than a dependency), and
//! `convert()` below walks that tree once to build our own
//! `dom::Node` tree from it.
//!
//! Why convert rather than implement `TreeSink` directly against
//! `dom::Node`: html5ever's `TreeSink::elem_name` needs to return a
//! borrowed, namespace-qualified `ExpandedName` during parsing, which
//! means the DOM type driving the parse needs to store a real
//! `markup5ever::QualName` per element. Our `dom::Element` deliberately
//! only stores a plain `tag_name: String` (see dom's module docs —
//! it's meant to stay dependency-light). Parsing into html5ever's own
//! RcDom first and converting afterward avoids that tension entirely:
//! the genuinely hard part (spec-compliant parsing) is still 100%
//! html5ever's work, and this crate only does simple data-structure
//! transcoding.
//!
//! What's NOT carried over from the parsed tree:
//!   - Doctype and ProcessingInstruction nodes are dropped (`convert`
//!     returns `None` for them) — nothing downstream (css/layout/
//!     render) does anything with a doctype yet.
//!   - Namespaces are ignored entirely (`name.local` only, no
//!     `name.ns`) — fine for plain HTML, wrong the moment embedded
//!     SVG/MathML (which use different namespaces) needs distinct
//!     handling.
//!   - html5ever's parse errors (`RcDom.errors`) are discarded rather
//!     than surfaced anywhere — useful for a future "view page
//!     source with parse warnings" feature, not wired up yet.
//!
//! Next steps, roughly in order of payoff:
//!   1. Surface `RcDom.errors` somewhere (at minimum, a debug log) —
//!      currently silent even in cases a page is meaningfully broken.
//!   2. Namespace-aware handling once SVG/MathML embedding matters.
//!   3. Streaming parse (via `read_from` against a real byte stream as
//!      it arrives over the network) instead of parsing a fully
//!      buffered `String`, once that matters for perceived load time.

mod rcdom;

use dom::NodeRef;
use html5ever::parse_document;
use html5ever::tendril::TendrilSink;
use rcdom::{Handle, NodeData, RcDom};

pub fn parse(input: &str) -> NodeRef {
    let parsed = parse_document(RcDom::default(), Default::default())
        .from_utf8()
        .read_from(&mut input.as_bytes())
        .expect("parsing from an in-memory byte slice should never actually fail");

    convert(&parsed.document).expect("the document root always converts to a dom::Node")
}

/// Recursively convert an html5ever `RcDom` tree into our own
/// `dom::Node` tree. Returns `None` for node kinds we don't model
/// (Doctype, ProcessingInstruction) — see module docs.
fn convert(handle: &Handle) -> Option<NodeRef> {
    let converted = match &handle.data {
        NodeData::Document => dom::Node::new_document(),

        NodeData::Element { name, attrs, .. } => {
            let element = dom::Node::new_element(name.local.as_ref());
            {
                let mut node_mut = element.borrow_mut();
                if let dom::NodeType::Element(el) = &mut node_mut.node_type {
                    for attr in attrs.borrow().iter() {
                        el.attributes
                            .insert(attr.name.local.to_string(), attr.value.to_string());
                    }
                }
            }
            element
        }

        NodeData::Text { contents } => dom::Node::new_text(&contents.borrow()),

        NodeData::Comment { contents } => dom::Node::new_comment(contents),

        NodeData::Doctype { .. } | NodeData::ProcessingInstruction { .. } => return None,
    };

    for child in handle.children.borrow().iter() {
        if let Some(converted_child) = convert(child) {
            dom::append_child(&converted, converted_child);
        }
    }

    Some(converted)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Finds a direct child element by tag name. `<html>`'s children
    /// are `[<head>, <body>]` once html5ever implies both — indexing
    /// `children[0]` to mean "body" is exactly the bug that made two
    /// of the tests below silently start asserting against `<head>`
    /// (always empty) instead of `<body>`.
    fn child_element(node: &NodeRef, tag_name: &str) -> NodeRef {
        node.borrow()
            .children
            .iter()
            .find(|c| matches!(&c.borrow().node_type, dom::NodeType::Element(e) if e.tag_name == tag_name))
            .unwrap_or_else(|| panic!("expected a <{tag_name}> child"))
            .clone()
    }

    #[test]
    fn parses_a_trivial_document() {
        let document = parse("<html><body><p>hi</p></body></html>");
        assert_eq!(document.borrow().children.len(), 1); // just <html>
    }

    #[test]
    fn auto_closes_an_unclosed_paragraph_per_spec_instead_of_nesting_it() {
        // Per the HTML5 spec, an open <p> is implicitly closed when
        // another <p> start tag appears — real browsers render this
        // as two SIBLING paragraphs, never nested. Our old naive
        // tokenizer had no such rule and would have nested the second
        // <p> inside the first; html5ever gets this right.
        let document = parse("<body><p>one<p>two</body>");
        let html = child_element(&document, "html");
        let body = child_element(&html, "body");
        let p_count = body
            .borrow()
            .children
            .iter()
            .filter(
                |c| matches!(&c.borrow().node_type, dom::NodeType::Element(e) if e.tag_name == "p"),
            )
            .count();
        assert_eq!(
            p_count, 2,
            "expected two sibling <p> elements, not one nested inside the other"
        );
    }

    #[test]
    fn extracts_element_attributes() {
        // The old naive tokenizer discarded all attributes outright.
        let document =
            parse(r#"<html><body><div class="card highlighted" id="main"></div></body></html>"#);
        let html = child_element(&document, "html");
        let body = child_element(&html, "body");
        let div = child_element(&body, "div");

        let div_ref = div.borrow();
        let dom::NodeType::Element(el) = &div_ref.node_type else {
            panic!("expected an element");
        };
        assert_eq!(el.attributes.get("id").map(String::as_str), Some("main"));
        assert_eq!(
            el.attributes.get("class").map(String::as_str),
            Some("card highlighted")
        );
    }

    #[test]
    fn implies_missing_head_and_body_like_a_real_browser() {
        // No <head>/<body> at all — html5ever should still produce a
        // well-formed tree with both implied, per spec.
        let document = parse("<html><p>just a paragraph</p></html>");
        let html = &document.borrow().children[0];
        let tag_names: Vec<String> = html
            .borrow()
            .children
            .iter()
            .filter_map(|c| match &c.borrow().node_type {
                dom::NodeType::Element(e) => Some(e.tag_name.clone()),
                _ => None,
            })
            .collect();
        assert!(tag_names.contains(&"head".to_string()));
        assert!(tag_names.contains(&"body".to_string()));
    }
}
