//! DOM tree snapshots for `app`'s DevTools Elements panel — see
//! `ipc::ClientMessageKind::FetchDomSnapshot`'s own doc comment for why
//! this is a separate tree from `layout::build_layout_tree` (that one
//! exists to be PAINTED, so it silently drops `display: none` content
//! — including every `<head>`/`<script>`/`<style>` element — entirely;
//! a DOM inspector needs the real, complete structure regardless of
//! what's visible).
//!
//! This module does no filtering and no truncation: it walks the WHOLE
//! live tree, however large, into an owned `ipc::DomNode` tree that
//! then crosses the IPC boundary as one message. That's a deliberate,
//! documented tradeoff matching `FetchDomSnapshot`'s own "fetched once
//! per DevTools open/refresh, not after every render" design — for an
//! enormous real-world page this could in principle approach
//! `ipc::MAX_MESSAGE_LEN`, but there's no cap here the way
//! `renderer::media`/`renderer::download` have one for fetched bytes,
//! since truncating a DEBUGGING tool's own view of the page would just
//! be confusing (an inspector that silently hides part of the DOM is
//! worse than one that's occasionally slow to open on a huge page).

use dom::{NodeRef, NodeType};

/// Walks `node` and every descendant into an owned `ipc::DomNode` tree.
pub fn build_dom_snapshot(node: &NodeRef) -> ipc::DomNode {
    let borrowed = node.borrow();
    let kind = match &borrowed.node_type {
        NodeType::Document => ipc::DomNodeKind::Document,
        NodeType::Element(el) => {
            let mut attributes: Vec<(String, String)> = el
                .attributes
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            attributes.sort_by(|a, b| a.0.cmp(&b.0));
            ipc::DomNodeKind::Element {
                tag_name: el.tag_name.clone(),
                attributes,
            }
        }
        NodeType::Text(text) => ipc::DomNodeKind::Text(text.clone()),
        NodeType::Comment(text) => ipc::DomNodeKind::Comment(text.clone()),
    };
    let children = borrowed.children.iter().map(build_dom_snapshot).collect();
    ipc::DomNode {
        node_id: borrowed.id,
        kind,
        children,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_dom_snapshot_captures_document_element_text_and_comment_nodes() {
        let document = dom::Node::new_document();
        let div = dom::Node::new_element("div");
        dom::append_child(&div, dom::Node::new_text("hello"));
        dom::append_child(&div, dom::Node::new_comment("a note"));
        dom::append_child(&document, div);

        let snapshot = build_dom_snapshot(&document);

        assert!(matches!(snapshot.kind, ipc::DomNodeKind::Document));
        assert_eq!(snapshot.children.len(), 1);
        let div_snapshot = &snapshot.children[0];
        match &div_snapshot.kind {
            ipc::DomNodeKind::Element {
                tag_name,
                attributes,
            } => {
                assert_eq!(tag_name, "div");
                assert!(attributes.is_empty());
            }
            _ => panic!("expected an Element"),
        }
        assert_eq!(div_snapshot.children.len(), 2);
        assert!(matches!(
            &div_snapshot.children[0].kind,
            ipc::DomNodeKind::Text(t) if t == "hello"
        ));
        assert!(matches!(
            &div_snapshot.children[1].kind,
            ipc::DomNodeKind::Comment(t) if t == "a note"
        ));
    }

    #[test]
    fn build_dom_snapshot_includes_display_none_elements_unlike_the_layout_tree() {
        // The whole reason this module exists rather than reusing
        // `layout::build_layout_tree`: a real DOM inspector must show
        // `<script>`/`<head>` content, which the layout tree drops.
        let document = dom::Node::new_document();
        let script = dom::Node::new_element("script");
        dom::append_child(&script, dom::Node::new_text("console.log(1)"));
        dom::append_child(&document, script);

        let snapshot = build_dom_snapshot(&document);

        assert_eq!(snapshot.children.len(), 1);
        match &snapshot.children[0].kind {
            ipc::DomNodeKind::Element { tag_name, .. } => assert_eq!(tag_name, "script"),
            _ => panic!("expected an Element"),
        }
    }

    #[test]
    fn build_dom_snapshot_sorts_attributes_by_name_for_determinism() {
        let document = dom::Node::new_document();
        let el = dom::Node::new_element("input");
        {
            let mut borrowed = el.borrow_mut();
            if let NodeType::Element(element) = &mut borrowed.node_type {
                element
                    .attributes
                    .insert("type".to_string(), "text".to_string());
                element.attributes.insert("id".to_string(), "x".to_string());
                element
                    .attributes
                    .insert("class".to_string(), "y".to_string());
            }
        }
        dom::append_child(&document, el);

        let snapshot = build_dom_snapshot(&document);
        match &snapshot.children[0].kind {
            ipc::DomNodeKind::Element { attributes, .. } => {
                let names: Vec<&str> = attributes.iter().map(|(k, _)| k.as_str()).collect();
                assert_eq!(names, vec!["class", "id", "type"]);
            }
            _ => panic!("expected an Element"),
        }
    }

    #[test]
    fn build_dom_snapshot_preserves_stable_dom_node_ids() {
        let document = dom::Node::new_document();
        let div = dom::Node::new_element("div");
        let div_id = div.borrow().id;
        dom::append_child(&document, div);

        let snapshot = build_dom_snapshot(&document);
        assert_eq!(snapshot.children[0].node_id, div_id);
    }
}
