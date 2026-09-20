//! Builds a real `accesskit::TreeUpdate` describing the active tab's
//! current page — see `render::window`'s own module docs for why the
//! actual tree-BUILDING logic lives here in `app` rather than in
//! `render` (which deliberately knows nothing about DOM/layout
//! semantics, only pixels — see that crate's own module docs on that
//! boundary). `render::window::run_window`'s `accesskit_winit::Adapter`
//! is what actually exposes whatever this module builds to a real OS
//! assistive technology: Orca via AT-SPI on Linux, NVDA/JAWS via UIA on
//! Windows, VoiceOver via NSAccessibility on macOS.
//!
//! **Node ids**: `dom::NodeId` and `accesskit::NodeId` are both plain
//! `u64` wrappers, so this module maps between them by VALUE
//! (`accesskit::NodeId(dom_node_id.0)`) — no separate lookup table
//! needed in either direction.
//!
//! **Coordinates**: every node's `bounds` are real ON-SCREEN pixel
//! coordinates (accounting for the chrome height above the page and
//! the active tab's current scroll offset), not the raw layout-tree
//! space `layout::LayoutBox::rect` is in — a real assistive technology
//! needs this to draw its own on-screen highlight or follow it with a
//! magnifier, not just to reason about the page's internal structure.
//!
//! **Rebuilt from scratch every frame**, not incrementally — simpler,
//! and `accesskit_winit::Adapter::update_if_active` already makes
//! actually USING the result free unless a real assistive technology
//! is attached and listening (see that method's own doc comment), so
//! the cost of building it in the first place is the only real
//! overhead, and it's the same order of magnitude of work as
//! `layout::layout` itself already redoes every frame regardless.
//!
//! **Role/name mapping is deliberately not exhaustive**: real ARIA
//! roles/labels (`role="..."`, `aria-label`, `aria-hidden`, live
//! regions) aren't read at all — every element gets a role purely from
//! its OWN tag name/content-type (a link, a button, a checkbox, a
//! heading, a paragraph, or a generic container), which already
//! carries real, useful structure and labeling to an assistive
//! technology, but stops short of full ARIA support. A documented
//! scope cut, matching this project's other "real but not exhaustive"
//! choices, not an oversight.

use accesskit::{
    Action, Checked, Node as AccessibilityNode, NodeBuilder, NodeClassSet,
    NodeId as AccessibilityNodeId, Rect as AccessibilityRect, Role, Tree, TreeUpdate,
};

/// Builds a complete tree update for one page — the only entry point
/// this module exposes. `content_offset_y` converts `layout::LayoutBox::rect`
/// (page-content space) into real on-screen y coordinates — pass
/// `chrome_height - scroll_y` (x needs no such adjustment: this
/// browser has no horizontal scrolling at all).
pub fn build_tree_update(
    layout_tree: &layout::LayoutBox,
    keyboard_focus: Option<dom::NodeId>,
    content_offset_y: f32,
) -> TreeUpdate {
    let mut classes = NodeClassSet::lock_global();
    let mut nodes = Vec::new();
    let root_id = build_node(layout_tree, content_offset_y, &mut nodes, &mut classes);

    // `TreeUpdate::focus` must always resolve to a node that's actually
    // IN `nodes` (see that field's own doc comment: "must be set to
    // the root" when nothing more specific has focus) — a stale
    // `keyboard_focus` id from a page mutation this tree hasn't caught
    // up to yet falls back to the root rather than pointing at nothing.
    let focus_id = keyboard_focus
        .filter(|id| layout::find_box_by_dom_node_id(layout_tree, *id).is_some())
        .map(|id| AccessibilityNodeId(id.0))
        .unwrap_or(root_id);

    TreeUpdate {
        nodes,
        tree: Some(Tree::new(root_id)),
        focus: focus_id,
    }
}

/// Recursively builds `b` and every descendant worth exposing,
/// appending each `(id, node)` pair to `nodes` in post-order (a
/// child's own entry is always pushed before its parent's, since the
/// parent's `Node` must already list the child's id in its own
/// `children` by the time IT gets pushed) and returning `b`'s own id
/// so its caller (its real parent, or `build_tree_update` for the
/// root) can reference it.
fn build_node(
    b: &layout::LayoutBox,
    content_offset_y: f32,
    nodes: &mut Vec<(AccessibilityNodeId, AccessibilityNode)>,
    classes: &mut NodeClassSet,
) -> AccessibilityNodeId {
    let id = AccessibilityNodeId(b.dom_node_id.0);
    let (role, name) = role_and_name(b);
    let mut builder = NodeBuilder::new(role);
    if let Some(name) = name {
        if !name.is_empty() {
            builder.set_name(name);
        }
    }
    builder.set_bounds(AccessibilityRect::new(
        b.rect.x as f64,
        (b.rect.y + content_offset_y) as f64,
        (b.rect.x + b.rect.width) as f64,
        (b.rect.y + content_offset_y + b.rect.height) as f64,
    ));

    if let Some(checkable) = &b.checkable_input {
        builder.set_checked(if checkable.checked {
            Checked::True
        } else {
            Checked::False
        });
    }
    if matches!(
        role,
        Role::Link | Role::Button | Role::CheckBox | Role::RadioButton
    ) {
        builder.add_action(Action::Default);
    }
    if is_keyboard_focusable(b) {
        builder.add_action(Action::Focus);
    }
    if let (Role::Heading, dom::NodeType::Element(el)) = (role, &b.node_type) {
        if let Some(level) = heading_level(&el.tag_name) {
            builder.set_hierarchical_level(level);
        }
    }

    let children: Vec<AccessibilityNodeId> = b
        .children
        .iter()
        .filter(|child| !should_omit(child))
        .map(|child| build_node(child, content_offset_y, nodes, classes))
        .collect();
    if !children.is_empty() {
        builder.set_children(children);
    }

    let node = builder.build(classes);
    nodes.push((id, node));
    id
}

/// Whitespace-only text nodes (the pure formatting whitespace between
/// sibling tags in real, human-written HTML) carry nothing worth
/// announcing and would just be noise in the tree — this is the ONLY
/// thing this module ever fully drops rather than representing as a
/// (possibly unlabeled) `GenericContainer`. Safe to check without
/// recursing: a text node is always a leaf.
fn should_omit(b: &layout::LayoutBox) -> bool {
    matches!(&b.node_type, dom::NodeType::Text(t) if t.trim().is_empty())
}

fn is_keyboard_focusable(b: &layout::LayoutBox) -> bool {
    matches!(&b.node_type, dom::NodeType::Element(el) if layout::is_keyboard_focusable(el))
}

fn heading_level(tag_name: &str) -> Option<usize> {
    match tag_name {
        "h1" => Some(1),
        "h2" => Some(2),
        "h3" => Some(3),
        "h4" => Some(4),
        "h5" => Some(5),
        "h6" => Some(6),
        _ => None,
    }
}

/// Concatenates every descendant text node's raw text, whitespace-
/// trimmed and single-space-joined — a link/button's own accessible
/// NAME (real screen readers announce "link, <name>" rather than
/// separately reading each of the link's own child text nodes), not
/// used for anything else.
fn label_text(b: &layout::LayoutBox) -> String {
    let mut out = String::new();
    collect_label_text(b, &mut out);
    out.trim().to_string()
}

fn collect_label_text(b: &layout::LayoutBox, out: &mut String) {
    if let Some(text) = &b.text {
        let trimmed = text.raw.trim();
        if !trimmed.is_empty() {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(trimmed);
        }
    }
    for child in &b.children {
        collect_label_text(child, out);
    }
}

/// Maps a `LayoutBox` to its accessible role and (if any) name — see
/// this module's own doc comment on why this mapping is real but
/// deliberately not exhaustive (no ARIA `role`/`aria-label` support).
fn role_and_name(b: &layout::LayoutBox) -> (Role, Option<String>) {
    if let Some(input) = &b.text_input {
        return (Role::TextInput, Some(input.value.clone()));
    }
    if let Some(checkable) = &b.checkable_input {
        let role = match checkable.kind {
            layout::CheckableKind::Checkbox => Role::CheckBox,
            layout::CheckableKind::Radio => Role::RadioButton,
        };
        return (role, None);
    }
    match &b.node_type {
        dom::NodeType::Document => (Role::Document, None),
        dom::NodeType::Comment(_) => (Role::GenericContainer, None),
        dom::NodeType::Text(text) => {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                (Role::GenericContainer, None)
            } else {
                (Role::StaticText, Some(trimmed.to_string()))
            }
        }
        dom::NodeType::Element(el) => match el.tag_name.as_str() {
            "a" if el.attributes.contains_key("href") => (Role::Link, Some(label_text(b))),
            "button" => (Role::Button, Some(label_text(b))),
            "img" => (Role::Image, el.attributes.get("alt").cloned()),
            "p" => (Role::Paragraph, None),
            "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => (Role::Heading, None),
            _ => (Role::GenericContainer, None),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout_tree_for(html: &str) -> layout::LayoutBox {
        let document = html::parse(html);
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let font = text::load_default_font();
        let mut tree = layout::build_layout_tree(&document, &stylesheet);
        layout::layout(&mut tree, 800.0, &font);
        tree
    }

    fn find_by_role(
        nodes: &[(AccessibilityNodeId, AccessibilityNode)],
        role: Role,
    ) -> Option<&AccessibilityNode> {
        nodes.iter().map(|(_, n)| n).find(|n| n.role() == role)
    }

    #[test]
    fn root_node_is_a_real_document() {
        let tree = layout_tree_for("<html><body><p>hi</p></body></html>");
        let update = build_tree_update(&tree, None, 0.0);
        let root = update
            .nodes
            .iter()
            .find(|(id, _)| *id == update.tree.as_ref().unwrap().root)
            .map(|(_, n)| n)
            .unwrap();
        assert_eq!(root.role(), Role::Document);
    }

    #[test]
    fn a_link_gets_a_real_link_role_and_its_text_as_its_name() {
        let tree = layout_tree_for(r#"<html><body><a href="/x">click me</a></body></html>"#);
        let update = build_tree_update(&tree, None, 0.0);
        let link = find_by_role(&update.nodes, Role::Link).expect("expected a Link node");
        assert_eq!(link.name(), Some("click me"));
        assert!(link.supports_action(Action::Default));
    }

    #[test]
    fn a_link_with_no_href_is_not_given_the_link_role() {
        let tree = layout_tree_for("<html><body><a>not a real link</a></body></html>");
        let update = build_tree_update(&tree, None, 0.0);
        assert!(find_by_role(&update.nodes, Role::Link).is_none());
    }

    #[test]
    fn a_checkbox_reports_its_real_checked_state() {
        let tree = layout_tree_for(r#"<html><body><input type="checkbox" checked></body></html>"#);
        let update = build_tree_update(&tree, None, 0.0);
        let checkbox = find_by_role(&update.nodes, Role::CheckBox).expect("expected a CheckBox");
        assert_eq!(checkbox.checked(), Some(Checked::True));
    }

    #[test]
    fn an_unchecked_checkbox_reports_false() {
        let tree = layout_tree_for(r#"<html><body><input type="checkbox"></body></html>"#);
        let update = build_tree_update(&tree, None, 0.0);
        let checkbox = find_by_role(&update.nodes, Role::CheckBox).expect("expected a CheckBox");
        assert_eq!(checkbox.checked(), Some(Checked::False));
    }

    #[test]
    fn a_text_input_reports_its_real_current_value_as_its_name() {
        let tree = layout_tree_for(r#"<html><body><input value="hello"></body></html>"#);
        let update = build_tree_update(&tree, None, 0.0);
        let input = find_by_role(&update.nodes, Role::TextInput).expect("expected a TextInput");
        assert_eq!(input.name(), Some("hello"));
    }

    #[test]
    fn real_text_becomes_static_text_with_its_own_content_as_its_name() {
        let tree = layout_tree_for("<html><body><p>hello world</p></body></html>");
        let update = build_tree_update(&tree, None, 0.0);
        let text = find_by_role(&update.nodes, Role::StaticText).expect("expected StaticText");
        assert_eq!(text.name(), Some("hello world"));
    }

    #[test]
    fn whitespace_only_text_is_omitted_entirely() {
        let tree = layout_tree_for("<html><body><div>   </div></body></html>");
        let update = build_tree_update(&tree, None, 0.0);
        assert!(
            find_by_role(&update.nodes, Role::StaticText).is_none(),
            "a whitespace-only text node shouldn't produce any node at all"
        );
    }

    #[test]
    fn headings_get_a_real_heading_role_and_level() {
        let tree = layout_tree_for("<html><body><h2>Section</h2></body></html>");
        let update = build_tree_update(&tree, None, 0.0);
        let heading = find_by_role(&update.nodes, Role::Heading).expect("expected a Heading");
        assert_eq!(heading.hierarchical_level(), Some(2));
    }

    #[test]
    fn a_button_is_focusable_and_supports_the_default_action() {
        let tree = layout_tree_for("<html><body><button>go</button></body></html>");
        let update = build_tree_update(&tree, None, 0.0);
        let button = find_by_role(&update.nodes, Role::Button).expect("expected a Button");
        assert!(button.supports_action(Action::Default));
        assert!(button.supports_action(Action::Focus));
    }

    #[test]
    fn a_plain_div_is_not_focusable() {
        let tree = layout_tree_for("<html><body><div>x</div></body></html>");
        let update = build_tree_update(&tree, None, 0.0);
        let container =
            find_by_role(&update.nodes, Role::GenericContainer).expect("expected a container");
        assert!(!container.supports_action(Action::Focus));
    }

    #[test]
    fn bounds_are_shifted_by_the_given_content_offset() {
        let tree = layout_tree_for("<html><body><p>hi</p></body></html>");
        let unshifted = build_tree_update(&tree, None, 0.0);
        let shifted = build_tree_update(&tree, None, 60.0);

        let unshifted_p = find_by_role(&unshifted.nodes, Role::Paragraph).unwrap();
        let shifted_p = find_by_role(&shifted.nodes, Role::Paragraph).unwrap();
        let unshifted_bounds = unshifted_p.bounds().unwrap();
        let shifted_bounds = shifted_p.bounds().unwrap();

        assert!((shifted_bounds.y0 - unshifted_bounds.y0 - 60.0).abs() < 0.01);
        assert_eq!(shifted_bounds.x0, unshifted_bounds.x0, "x is never offset");
    }

    #[test]
    fn focus_falls_back_to_the_root_when_the_given_node_id_is_not_in_the_tree() {
        let tree = layout_tree_for("<html><body><p>hi</p></body></html>");
        let update = build_tree_update(&tree, Some(dom::NodeId(999_999)), 0.0);
        assert_eq!(update.focus, update.tree.unwrap().root);
    }

    #[test]
    fn focus_resolves_to_a_real_focused_node_when_it_exists() {
        let document = html::parse(r#"<html><body><a href="/x">go</a></body></html>"#);
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let font = text::load_default_font();
        let mut tree = layout::build_layout_tree(&document, &stylesheet);
        layout::layout(&mut tree, 800.0, &font);
        let link_id = tree.children[0].children[0].dom_node_id;

        let update = build_tree_update(&tree, Some(link_id), 0.0);
        assert_eq!(update.focus, AccessibilityNodeId(link_id.0));
    }
}
