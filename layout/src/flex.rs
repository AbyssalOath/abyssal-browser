//! `display: flex` layout — real, but deliberately scoped down from
//! the full spec algorithm. See this module's two entry points'
//! doc comments (`layout_flex_row`/`layout_flex_column`) for exactly
//! what's covered on each axis; the short version is: `flex-direction:
//! row` gets the real algorithm (basis/grow/shrink resolution,
//! wrapping into multiple lines, `justify-content` spacing,
//! `align-items` cross-axis alignment/stretch), while `column` gets a
//! deliberately simpler one, because this codebase's box model has no
//! notion of an explicit container HEIGHT anywhere (see `layout`'s own
//! module docs) — a column flex container's main axis (height) is
//! therefore always unbounded/content-driven, so there is never a
//! finite amount of free space to grow into or a deficit to shrink
//! against. `column` mode still does something real and useful
//! (`gap`-spaced vertical stacking with real `align-items` alignment
//! along the cross axis, which IS bounded — the container's width),
//! just not full grow/shrink/wrap/justify-content.
//!
//! Both directions reuse `layout_box` (the crate's ordinary block/
//! inline layout entry point) to lay out each item's own CONTENT once
//! its main-axis size has been resolved — flex items can be arbitrary
//! nested content (text, blocks, nested flex/grid containers) for
//! free, since `layout_box` dispatches back into this module for any
//! descendant that itself has `display: flex`.
//!
//! Known gap shared by both directions: an item whose own `display` is
//! `inline` (e.g. a bare `<span>` used directly as a flex item, with
//! no display override) is NOT "blockified" the way real CSS requires
//! — `layout_box`'s shrink-to-fit sizing for `Display::Inline` still
//! applies, so such an item won't stretch/grow/shrink correctly. Every
//! ordinary element (anything `Block` by default, which is everything
//! except the fixed `INLINE_TAGS` list in `css`) is unaffected.

use crate::{intrinsic_width, is_whitespace_only_text, layout_box, LayoutBox};
use css::{AlignItems, FlexWrap, JustifyContent};
use text::Font;

/// This item's flex basis — explicit `flex-basis`, or (for `auto`) an
/// approximation of its natural/preferred main size: `intrinsic_width`
/// for the main axis being width (row), or its natural height for the
/// main axis being height (column) — discovered by actually laying it
/// out once, at the full cross-axis size, purely to measure how tall
/// its content naturally comes out (see `layout_flex_column`, the only
/// caller that needs the height case).
fn resolve_basis_width(item: &LayoutBox, font: &Font) -> f32 {
    item.style
        .flex_basis()
        .unwrap_or_else(|| intrinsic_width(item, font))
}

/// Lays out `container`'s children as a `flex-direction: row` (the
/// default) flex formatting context. See this module's doc comment
/// for overall scope. Returns the consumed content height so the
/// caller (`layout_box`) can size the container itself.
pub(crate) fn layout_flex_row(
    container: &mut LayoutBox,
    content_x: f32,
    content_y: f32,
    content_width: f32,
    font: &Font,
) -> f32 {
    let style = &container.style;
    let wrap = style.flex_wrap();
    let justify = style.justify_content();
    let align = style.align_items();
    let row_gap = style.row_gap();
    let column_gap = style.column_gap();

    if container.children.is_empty() {
        return 0.0;
    }

    // Each item's basis (border-box main size before grow/shrink) plus
    // its own margins — computed once, up front, since basis doesn't
    // depend on which line an item lands in.
    let bases: Vec<f32> = container
        .children
        .iter()
        .map(|item| resolve_basis_width(item, font))
        .collect();

    // Greedily pack items into lines: `NoWrap` is just one line
    // containing everything, regardless of overflow (matching this
    // codebase's general "let it overflow rather than clip/error"
    // philosophy elsewhere — see `layout`'s own module docs on
    // over-long single words). Whitespace-only text children (see
    // `is_whitespace_only_text`) are skipped entirely — they never
    // become their own line and never get laid out at all, matching
    // real CSS dropping them before flex items are even generated.
    let mut lines: Vec<Vec<usize>> = vec![Vec::new()];
    let mut line_used_main = 0.0f32;
    for (i, item) in container.children.iter().enumerate() {
        if is_whitespace_only_text(item) {
            continue;
        }
        let outer_basis = bases[i] + item.margin.horizontal();
        let gap_before = if lines.last().unwrap().is_empty() {
            0.0
        } else {
            column_gap
        };
        let would_use = line_used_main + gap_before + outer_basis;
        let fits = would_use <= content_width || lines.last().unwrap().is_empty();
        if wrap == FlexWrap::Wrap && !fits && !lines.last().unwrap().is_empty() {
            lines.push(Vec::new());
            line_used_main = outer_basis;
        } else {
            line_used_main = would_use;
        }
        lines.last_mut().unwrap().push(i);
    }

    let mut cursor_y = content_y;
    for line in &lines {
        let line_height = layout_flex_line_row(
            container,
            line,
            &bases,
            content_x,
            cursor_y,
            content_width,
            column_gap,
            justify,
            align,
            font,
        );
        cursor_y += line_height + row_gap;
    }
    // The trailing `row_gap` added after the last line was never
    // actually needed (there's no line after it).
    if !lines.is_empty() {
        cursor_y -= row_gap;
    }

    cursor_y - content_y
}

#[allow(clippy::too_many_arguments)]
fn layout_flex_line_row(
    container: &mut LayoutBox,
    line: &[usize],
    bases: &[f32],
    content_x: f32,
    line_y: f32,
    content_width: f32,
    column_gap: f32,
    justify: JustifyContent,
    align: AlignItems,
    font: &Font,
) -> f32 {
    let n = line.len();
    let total_grow: f32 = line
        .iter()
        .map(|&i| container.children[i].style.flex_grow())
        .sum();
    let total_shrink_weight: f32 = line
        .iter()
        .map(|&i| container.children[i].style.flex_shrink() * bases[i])
        .sum();

    let gaps_total = column_gap * (n.saturating_sub(1)) as f32;
    let used_main: f32 = line
        .iter()
        .map(|&i| bases[i] + container.children[i].margin.horizontal())
        .sum::<f32>()
        + gaps_total;
    let free_space = content_width - used_main;

    // Resolve each item's final main size (border-box width) from its
    // basis, distributing `free_space` by `flex-grow` (if there's
    // extra room) or the deficit by `flex-shrink * basis` (if there's
    // not) — a real, single-pass proportional distribution; the full
    // spec's multi-pass min/max-violation resolution isn't implemented
    // (see this module's doc comment).
    let mut resolved_main = vec![0.0f32; n];
    for (slot, &i) in line.iter().enumerate() {
        let basis = bases[i];
        resolved_main[slot] = if free_space > 0.0 && total_grow > 0.0 {
            let grow = container.children[i].style.flex_grow();
            basis + free_space * (grow / total_grow)
        } else if free_space < 0.0 && total_shrink_weight > 0.0 {
            let weight = container.children[i].style.flex_shrink() * basis;
            (basis + free_space * (weight / total_shrink_weight)).max(0.0)
        } else {
            basis
        };
    }

    // Leftover space AFTER grow/shrink resolution (zero unless neither
    // grow nor shrink applied — e.g. every item has `flex-grow: 0` and
    // there's extra room) is what `justify-content` distributes.
    let leftover = (content_width - (resolved_main.iter().sum::<f32>() + gaps_total)).max(0.0);
    let (lead, between_extra) = match justify {
        JustifyContent::FlexStart => (0.0, 0.0),
        JustifyContent::FlexEnd => (leftover, 0.0),
        JustifyContent::Center => (leftover / 2.0, 0.0),
        JustifyContent::SpaceBetween if n > 1 => (0.0, leftover / (n - 1) as f32),
        JustifyContent::SpaceBetween => (0.0, 0.0),
        JustifyContent::SpaceAround => (leftover / (n as f32 + 1.0), leftover / (n as f32 + 1.0)),
    };

    // First pass: lay out every item at its resolved main size to
    // discover its NATURAL cross size (height) — needed before
    // `align-items: stretch` can know what the line's height even is.
    let mut cursor_x = content_x + lead;
    let mut natural_heights = vec![0.0f32; n];
    let mut item_x = vec![0.0f32; n];
    for (slot, &i) in line.iter().enumerate() {
        let item = &mut container.children[i];
        item_x[slot] = cursor_x;
        // `focus` (see `layout_box`'s own doc comment) is always `None`
        // for flex items — a documented scope limit: a focused
        // `<input>` inside a flex container still renders its value
        // correctly, just without a visible cursor. See that doc
        // comment for the reasoning.
        layout_box(
            item,
            cursor_x,
            line_y,
            resolved_main[slot] + item.margin.horizontal(),
            font,
            true,
            None,
        );
        natural_heights[slot] = item.rect.height + item.margin.vertical();
        cursor_x += resolved_main[slot] + item.margin.horizontal() + column_gap + between_extra;
    }

    let line_height = natural_heights.iter().cloned().fold(0.0f32, f32::max);

    // Second pass: cross-axis (vertical) alignment within the line —
    // reposition (and, for `stretch`, resize) each item now that the
    // line's real height is known.
    for (slot, &i) in line.iter().enumerate() {
        let item = &mut container.children[i];
        let extra = (line_height - natural_heights[slot]).max(0.0);
        let offset_y = match align {
            AlignItems::FlexStart | AlignItems::Stretch => 0.0,
            AlignItems::FlexEnd => extra,
            AlignItems::Center => extra / 2.0,
        };
        item.rect.y = line_y + item.margin.top + offset_y;
        if align == AlignItems::Stretch {
            item.rect.height = (line_height - item.margin.vertical()).max(0.0);
        }
    }

    line_height
}

/// Lays out `container`'s children as a `flex-direction: column` flex
/// formatting context. See this module's doc comment for why this is
/// a deliberately simpler algorithm than the row case: no bounded main
/// axis (height) exists anywhere in this box model, so grow/shrink/
/// wrap/justify-content have nothing to distribute — items simply
/// stack top-to-bottom with real `gap` spacing and real `align-items`
/// alignment/stretch along the (bounded) cross axis, width.
pub(crate) fn layout_flex_column(
    container: &mut LayoutBox,
    content_x: f32,
    content_y: f32,
    content_width: f32,
    font: &Font,
) -> f32 {
    let style = &container.style;
    let align = style.align_items();
    let row_gap = style.row_gap();

    let mut cursor_y = content_y;
    let mut first = true;
    let child_count = container.children.len();
    for i in 0..child_count {
        if is_whitespace_only_text(&container.children[i]) {
            continue;
        }
        if !first {
            cursor_y += row_gap;
        }
        first = false;

        let (natural_width, item_available_width) = {
            let item = &container.children[i];
            if align == AlignItems::Stretch {
                (content_width, content_width)
            } else {
                // Shrink-to-fit along the cross axis, same treatment
                // `layout_box` gives an ordinary `display: inline` box
                // — capped at the container's own width.
                (
                    intrinsic_width(item, font).min(content_width),
                    content_width,
                )
            }
        };

        let item = &mut container.children[i];
        // See the row-direction branch above for why `focus` is always
        // `None` here.
        layout_box(
            item,
            content_x,
            cursor_y,
            item_available_width,
            font,
            true,
            None,
        );
        if align != AlignItems::Stretch {
            item.rect.width = natural_width;
        }
        let offset_x = match align {
            AlignItems::FlexStart | AlignItems::Stretch => 0.0,
            AlignItems::FlexEnd => {
                (content_width - natural_width - item.margin.horizontal()).max(0.0)
            }
            AlignItems::Center => {
                ((content_width - natural_width - item.margin.horizontal()) / 2.0).max(0.0)
            }
        };
        item.rect.x = content_x + item.margin.left + offset_x;

        cursor_y = item.rect.y + item.rect.height;
    }

    cursor_y - content_y
}

#[cfg(test)]
mod tests {
    use crate::{build_layout_tree, layout};

    /// Builds `count` `<div>` children of a `<div id="flex">` flex
    /// container, laid out against `width` — the shape every test
    /// below needs, differing only in the container's own declarations
    /// and each child's.
    fn layout_flex_container(
        container_css: &str,
        child_css: &[&str],
        width: f32,
    ) -> Vec<crate::LayoutBox> {
        let stylesheet = css::parse_stylesheet(&format!(
            ".flex {{ display: flex; {container_css} }} {}",
            child_css
                .iter()
                .enumerate()
                .map(|(i, css)| format!(".item{i} {{ {css} }}"))
                .collect::<Vec<_>>()
                .join(" ")
        ));
        let document = dom::Node::new_document();
        let flex = dom::Node::new_element("div");
        if let dom::NodeType::Element(el) = &mut flex.borrow_mut().node_type {
            el.attributes
                .insert("class".to_string(), "flex".to_string());
        }
        for i in 0..child_css.len() {
            let item = dom::Node::new_element("div");
            if let dom::NodeType::Element(el) = &mut item.borrow_mut().node_type {
                el.attributes
                    .insert("class".to_string(), format!("item{i}"));
            }
            dom::append_child(&item, dom::Node::new_text("x"));
            dom::append_child(&flex, item);
        }
        dom::append_child(&document, flex);

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, width, &font);
        tree.children.remove(0).children
    }

    #[test]
    fn row_direction_packs_items_side_by_side_at_their_natural_widths() {
        let items = layout_flex_container("", &["", ""], 400.0);
        // Both items are plain text content ("x") with no explicit
        // basis — they sit side by side, the second starting right
        // after the first's natural width, not stacked full-width the
        // way ordinary block children would.
        assert_eq!(items[0].rect.x, 0.0);
        assert!(
            items[1].rect.x > items[0].rect.x,
            "the second item should start after the first, not stack below it"
        );
        assert_eq!(
            items[0].rect.y, items[1].rect.y,
            "row-direction items share the same line"
        );
    }

    #[test]
    fn flex_grow_distributes_extra_space_proportionally() {
        let items = layout_flex_container(
            "",
            &[
                "flex-basis: 50px; flex-grow: 1;",
                "flex-basis: 50px; flex-grow: 3;",
            ],
            250.0,
        );
        // Used: 100px basis, 150px free. grow-1 gets 1/4, grow-3 gets 3/4.
        assert!(
            (items[0].rect.width - 87.5).abs() < 0.01,
            "50 + 150*(1/4) = 87.5, got {}",
            items[0].rect.width
        );
        assert!(
            (items[1].rect.width - 162.5).abs() < 0.01,
            "50 + 150*(3/4) = 162.5, got {}",
            items[1].rect.width
        );
    }

    #[test]
    fn no_grow_factor_means_no_extra_width_even_with_free_space() {
        let items = layout_flex_container("", &["flex-basis: 50px;", "flex-basis: 50px;"], 300.0);
        assert_eq!(items[0].rect.width, 50.0);
        assert_eq!(items[1].rect.width, 50.0);
    }

    #[test]
    fn flex_shrink_distributes_a_deficit_proportionally_by_basis_weighted_shrink() {
        let items = layout_flex_container(
            "",
            &[
                "flex-basis: 200px; flex-shrink: 1;",
                "flex-basis: 200px; flex-shrink: 1;",
            ],
            300.0,
        );
        // Deficit of 100px, both weight 200*1=200, split evenly: -50 each.
        assert!((items[0].rect.width - 150.0).abs() < 0.01);
        assert!((items[1].rect.width - 150.0).abs() < 0.01);
    }

    #[test]
    fn flex_shrink_zero_keeps_an_item_at_its_basis_even_when_the_line_overflows() {
        let items = layout_flex_container(
            "",
            &[
                "flex-basis: 200px; flex-shrink: 0;",
                "flex-basis: 200px; flex-shrink: 1;",
            ],
            300.0,
        );
        assert_eq!(
            items[0].rect.width, 200.0,
            "flex-shrink: 0 must never shrink"
        );
    }

    #[test]
    fn justify_content_center_centers_the_line_when_no_grow_is_set() {
        let items = layout_flex_container(
            "justify-content: center;",
            &["flex-basis: 50px;", "flex-basis: 50px;"],
            300.0,
        );
        // Total content 100px in a 300px line -> 100px leading space.
        assert!(
            (items[0].rect.x - 100.0).abs() < 0.01,
            "expected 100px leading space, got x={}",
            items[0].rect.x
        );
    }

    #[test]
    fn justify_content_space_between_puts_all_extra_space_between_items_not_at_the_edges() {
        let items = layout_flex_container(
            "justify-content: space-between;",
            &[
                "flex-basis: 50px;",
                "flex-basis: 50px;",
                "flex-basis: 50px;",
            ],
            300.0,
        );
        assert_eq!(items[0].rect.x, 0.0, "no leading space with space-between");
        // 300 - 150 = 150 leftover, split into 2 gaps of 75 each.
        assert!(
            (items[1].rect.x - 125.0).abs() < 0.01,
            "50 + 75 = 125, got {}",
            items[1].rect.x
        );
    }

    #[test]
    fn align_items_stretch_is_the_default_and_fills_the_line_height() {
        // Give "tall" a second, block-level child so its natural
        // height is genuinely bigger than "short"'s single text line
        // — otherwise both items would already end up the same height
        // with no stretching involved, and the test would prove nothing.
        let stylesheet = css::parse_stylesheet(
            ".flex { display: flex; } .tall { flex-basis: 50px; } .short { flex-basis: 50px; }",
        );
        let document = dom::Node::new_document();
        let flex = dom::Node::new_element("div");
        if let dom::NodeType::Element(el) = &mut flex.borrow_mut().node_type {
            el.attributes
                .insert("class".to_string(), "flex".to_string());
        }
        let tall = dom::Node::new_element("div");
        if let dom::NodeType::Element(el) = &mut tall.borrow_mut().node_type {
            el.attributes
                .insert("class".to_string(), "tall".to_string());
        }
        dom::append_child(&tall, dom::Node::new_text("line one"));
        dom::append_child(&tall, dom::Node::new_element("br"));
        let short = dom::Node::new_element("div");
        if let dom::NodeType::Element(el) = &mut short.borrow_mut().node_type {
            el.attributes
                .insert("class".to_string(), "short".to_string());
        }
        dom::append_child(&short, dom::Node::new_text("x"));
        dom::append_child(&flex, tall);
        dom::append_child(&flex, short);
        dom::append_child(&document, flex);

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 400.0, &font);
        let items = &tree.children[0].children;

        // "tall" and "short" have very different NATURAL content
        // heights (one has an extra block-level child, the other is a
        // single text line) — under the real default, `align-items:
        // stretch`, both end up reporting the SAME final height
        // anyway: "short" grew to fill the line "tall" established.
        assert_eq!(
            items[0].rect.height, items[1].rect.height,
            "stretch (the default) should equalize both items' heights"
        );
    }

    #[test]
    fn align_items_flex_start_does_not_stretch_shorter_items() {
        let stylesheet = css::parse_stylesheet(
            ".flex { display: flex; align-items: flex-start; } .tall { flex-basis: 50px; } .short { flex-basis: 50px; }",
        );
        let document = dom::Node::new_document();
        let flex = dom::Node::new_element("div");
        if let dom::NodeType::Element(el) = &mut flex.borrow_mut().node_type {
            el.attributes
                .insert("class".to_string(), "flex".to_string());
        }
        let tall = dom::Node::new_element("div");
        if let dom::NodeType::Element(el) = &mut tall.borrow_mut().node_type {
            el.attributes
                .insert("class".to_string(), "tall".to_string());
        }
        dom::append_child(&tall, dom::Node::new_text("line one"));
        dom::append_child(&tall, dom::Node::new_element("br"));
        let short = dom::Node::new_element("div");
        if let dom::NodeType::Element(el) = &mut short.borrow_mut().node_type {
            el.attributes
                .insert("class".to_string(), "short".to_string());
        }
        dom::append_child(&short, dom::Node::new_text("x"));
        dom::append_child(&flex, tall);
        dom::append_child(&flex, short);
        dom::append_child(&document, flex);

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 400.0, &font);
        let items = &tree.children[0].children;
        assert!(
            items[0].rect.height >= items[1].rect.height,
            "the taller item should keep its own natural height"
        );
        assert!(
            items[1].rect.height < items[0].rect.height,
            "the shorter item must NOT be stretched under align-items: flex-start"
        );
    }

    #[test]
    fn wrap_starts_a_new_line_when_items_no_longer_fit() {
        let items = layout_flex_container(
            "flex-wrap: wrap;",
            &[
                "flex-basis: 150px; flex-shrink: 0;",
                "flex-basis: 150px; flex-shrink: 0;",
                "flex-basis: 150px; flex-shrink: 0;",
            ],
            300.0,
        );
        assert_eq!(
            items[0].rect.y, items[1].rect.y,
            "first two items fit on the first line"
        );
        assert!(
            items[2].rect.y > items[0].rect.y,
            "the third item should wrap onto a second line"
        );
    }

    #[test]
    fn nowrap_keeps_everything_on_one_line_even_when_it_overflows() {
        let items = layout_flex_container(
            "",
            &[
                "flex-basis: 200px; flex-shrink: 0;",
                "flex-basis: 200px; flex-shrink: 0;",
            ],
            300.0,
        );
        assert_eq!(
            items[0].rect.y, items[1].rect.y,
            "nowrap must never start a second line"
        );
    }

    #[test]
    fn gap_adds_real_spacing_between_items_on_the_same_line() {
        let items = layout_flex_container(
            "gap: 20px;",
            &["flex-basis: 50px;", "flex-basis: 50px;"],
            300.0,
        );
        assert!((items[1].rect.x - (items[0].rect.x + 50.0 + 20.0)).abs() < 0.01);
    }

    #[test]
    fn column_direction_stacks_items_vertically_with_gap() {
        let items = layout_flex_container("flex-direction: column; gap: 10px;", &["", ""], 200.0);
        assert_eq!(
            items[0].rect.x, items[1].rect.x,
            "column items share the same x by default (stretch)"
        );
        assert!(
            items[1].rect.y > items[0].rect.y,
            "the second item should stack below the first"
        );
        assert!((items[1].rect.y - (items[0].rect.y + items[0].rect.height + 10.0)).abs() < 0.01);
    }

    #[test]
    fn column_direction_align_items_center_centers_narrower_items_horizontally() {
        let items = layout_flex_container(
            "flex-direction: column; align-items: center;",
            &["display: inline;", "display: inline;"],
            200.0,
        );
        // Shrink-to-fit content ("x") is much narrower than 200px —
        // centered items should NOT start at x=0.
        assert!(
            items[0].rect.x > 0.0,
            "a centered, narrower-than-container item should be offset from the left edge"
        );
    }
}
