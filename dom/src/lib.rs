//! `dom` — the shared tree structure every other subsystem talks to.
//!
//! The `html` crate builds this tree. The `css` crate walks it to
//! compute styles. The `layout` crate walks it (plus computed styles)
//! to produce a box tree. The `render` crate paints the box tree.
//!
//! Keep this crate boring and stable — it's the load-bearing wall.
//! Prefer `Rc<RefCell<Node>>` for parent/child links to start; if you
//! outgrow it, an arena (`Vec<Node>` + index-based ids, like Servo's
//! `NodeId`) scales much better but is more work up front.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::{Rc, Weak};
use std::sync::atomic::{AtomicU64, Ordering};

pub type NodeRef = Rc<RefCell<Node>>;
pub type WeakNodeRef = Weak<RefCell<Node>>;

/// A stable identity for one DOM node, assigned once at construction
/// (see `next_node_id`) and never reused — this is what lets
/// `layout::LayoutBox` carry a reference back to the live node it was
/// built from (see that crate's `dom_node_id` field) instead of only
/// ever cloning the node's DATA out, the way `build_layout_tree`
/// otherwise has to (a `LayoutBox` crosses the `app`<->`renderer` IPC
/// boundary as a plain snapshot — see `ipc`'s module docs — so it can
/// never hold a real `NodeRef` itself). Monotonic and process-global
/// rather than derived from the node's own memory address (e.g.
/// `Rc::as_ptr`) specifically to avoid an ABA hazard: if an id were
/// tied to an allocation's address, a node dropped mid-session (e.g.
/// `renderer::script`'s `set_text_content` replacing a text child)
/// could free memory the allocator later reuses for an unrelated new
/// node, making a stale id from an old `LayoutBox` silently resolve to
/// the WRONG live node instead of correctly failing to resolve at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct NodeId(pub u64);

/// Starts at 1 (not 0) purely so `NodeId(0)` reads unambiguously as
/// "never assigned" in any future code that wants a sentinel — nothing
/// today actually relies on that, but it costs nothing to keep true.
static NEXT_NODE_ID: AtomicU64 = AtomicU64::new(1);

fn next_node_id() -> NodeId {
    NodeId(NEXT_NODE_ID.fetch_add(1, Ordering::Relaxed))
}

/// A single node in the DOM tree.
///
/// TODO: this is deliberately minimal. A real DOM also needs at least:
/// - `CharacterData` operations (splitText, appendData, ...) for Text
/// - mutation observers
/// - namespace-aware tag/attribute names (for SVG/MathML embedding)
pub struct Node {
    pub id: NodeId,
    pub node_type: NodeType,
    pub parent: Option<WeakNodeRef>,
    pub children: Vec<NodeRef>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum NodeType {
    Document,
    Element(Element),
    Text(String),
    Comment(String),
}

/// An element node: a tag name plus its attributes.
///
/// TODO: attribute values should probably be `Rc<str>` or interned
/// strings once you care about memory — every "class" and "div" in a
/// large page is currently a fresh heap allocation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Element {
    pub tag_name: String,
    pub attributes: HashMap<String, String>,
}

impl Node {
    pub fn new_document() -> NodeRef {
        Rc::new(RefCell::new(Node {
            id: next_node_id(),
            node_type: NodeType::Document,
            parent: None,
            children: Vec::new(),
        }))
    }

    pub fn new_element(tag_name: &str) -> NodeRef {
        Rc::new(RefCell::new(Node {
            id: next_node_id(),
            node_type: NodeType::Element(Element {
                tag_name: tag_name.to_string(),
                attributes: HashMap::new(),
            }),
            parent: None,
            children: Vec::new(),
        }))
    }

    pub fn new_text(data: &str) -> NodeRef {
        Rc::new(RefCell::new(Node {
            id: next_node_id(),
            node_type: NodeType::Text(data.to_string()),
            parent: None,
            children: Vec::new(),
        }))
    }

    pub fn new_comment(data: &str) -> NodeRef {
        Rc::new(RefCell::new(Node {
            id: next_node_id(),
            node_type: NodeType::Comment(data.to_string()),
            parent: None,
            children: Vec::new(),
        }))
    }
}

/// Append `child` to `parent`, wiring up the back-pointer. Real DOM
/// move semantics: if `child` already has a parent (anywhere — the
/// same `parent` or a different one), it's removed from that parent's
/// children first, so a node can never end up listed under two
/// parents at once. `html`'s own tree builder only ever calls this
/// with brand-new, never-yet-attached nodes (so the removal path is
/// simply a no-op there), but a JS-facing `appendChild` (see
/// `renderer::script`) needs the real move behavior — re-appending an
/// element that's already elsewhere in the tree is a completely
/// ordinary, spec-required thing to do from script.
pub fn append_child(parent: &NodeRef, child: NodeRef) {
    if let Some(old_parent) = child.borrow().parent.as_ref().and_then(Weak::upgrade) {
        old_parent
            .borrow_mut()
            .children
            .retain(|c| !Rc::ptr_eq(c, &child));
    }
    child.borrow_mut().parent = Some(Rc::downgrade(parent));
    parent.borrow_mut().children.push(child);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_a_tiny_tree() {
        let document = Node::new_document();
        let html = Node::new_element("html");
        let text = Node::new_text("hello");

        append_child(&html, text);
        append_child(&document, html);

        assert_eq!(document.borrow().children.len(), 1);
    }

    #[test]
    fn every_new_node_gets_a_distinct_id() {
        let a = Node::new_element("div");
        let b = Node::new_element("div");
        let c = Node::new_text("hi");
        assert_ne!(a.borrow().id, b.borrow().id);
        assert_ne!(b.borrow().id, c.borrow().id);
    }

    #[test]
    fn appending_an_already_attached_node_moves_it_rather_than_duplicating_it() {
        let old_parent = Node::new_element("div");
        let new_parent = Node::new_element("section");
        let child = Node::new_element("span");

        append_child(&old_parent, child.clone());
        assert_eq!(old_parent.borrow().children.len(), 1);

        append_child(&new_parent, child.clone());
        assert_eq!(
            old_parent.borrow().children.len(),
            0,
            "the child should have been removed from its old parent"
        );
        assert_eq!(new_parent.borrow().children.len(), 1);
        assert!(Rc::ptr_eq(
            child
                .borrow()
                .parent
                .as_ref()
                .unwrap()
                .upgrade()
                .as_ref()
                .unwrap(),
            &new_parent
        ));
    }

    #[test]
    fn re_appending_a_child_to_the_same_parent_does_not_duplicate_it() {
        let parent = Node::new_element("div");
        let child = Node::new_element("span");
        append_child(&parent, child.clone());
        append_child(&parent, child.clone());
        assert_eq!(parent.borrow().children.len(), 1);
    }
}
