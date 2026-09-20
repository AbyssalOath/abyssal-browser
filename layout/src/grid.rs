//! `display: grid` layout — real, but deliberately scoped down. See
//! `css::ComputedStyle::grid_template_columns`/`grid_template_rows`'s
//! own doc comment for what a track can be (`<px>`, `<N>fr`, or
//! `repeat()`  — nothing else: no percentages, no `minmax()`). This
//! module adds the rest of the scope limits:
//!   - **Placement**: an item names a region either by
//!     `grid-area: <name>` (matching a `grid-template-areas` name —
//!     see `css::ComputedStyle::grid_area`'s doc comment) or by
//!     `grid-column`/`grid-row: span <N>` (occupies `N` tracks in that
//!     axis while still being auto-placed); everything else
//!     auto-places into the next free cell, row-major. Real CSS's
//!     4-part explicit line-number placement (`grid-column: 2 / 4`,
//!     or a bare line number) isn't implemented — falls back to
//!     ordinary auto-placement (span 1), same as an unset value (see
//!     `css::ComputedStyle::grid_column_span`'s doc comment).
//!   - **Row sizing**: an explicit `Fixed` row track is honored; a row
//!     with no explicit track (the common case — `grid-template-rows`
//!     is usually left unset, letting rows size to content) gets the
//!     max natural height of whatever SINGLE-ROW item landed in it,
//!     discovered the same way `flex`'s row-direction line-height is
//!     (lay out the item at its column's width first, then read back
//!     its natural height). A row-SPANNING item does NOT grow the rows
//!     it spans to fit its own content — it's positioned and stretched
//!     to whatever height those rows already resolved to from their
//!     own single-row items, which can leave a spanning item's content
//!     overflowing its box. A `Fraction` (`fr`) ROW track has nothing
//!     bounded to take a fraction OF — same root cause as `flex`'s own
//!     column-direction limitation (see that module's docs): this box
//!     model has no notion of an explicit container height — so a
//!     fractional row track just falls back to content-driven sizing
//!     too, same as an unset one.
//!   - Every item stretches to fill its cell's (or spanned cells')
//!     resolved height (the same `align-items: stretch` default `flex`
//!     uses) — `align-items` itself isn't read here at all yet; that's
//!     a real gap, not a deliberate non-default choice.

use crate::{is_whitespace_only_text, layout_box, LayoutBox};
use css::GridTrack;
use std::collections::HashSet;
use text::Font;

/// Resolves each track to a concrete pixel size — see this module's
/// doc comment on what a track can be. `Fixed` tracks keep their own
/// size; the space left after subtracting every `Fixed` track and
/// every gap is split among `Fraction` tracks proportionally to their
/// own `fr` value (a `2fr` track gets twice a `1fr` track's share) —
/// the same proportional-distribution idea `flex`'s own grow/shrink
/// resolution uses, just simpler since there's no basis/deficit case
/// to consider (a track's OWN size, unlike a flex item's, is never a
/// starting point grow/shrink adjusts).
fn resolve_tracks(tracks: &[GridTrack], available: f32, gap: f32) -> Vec<f32> {
    let n = tracks.len();
    let gaps_total = gap * n.saturating_sub(1) as f32;
    let fixed_total: f32 = tracks
        .iter()
        .filter_map(|t| {
            if let GridTrack::Fixed(px) = t {
                Some(*px)
            } else {
                None
            }
        })
        .sum();
    let fraction_total: f32 = tracks
        .iter()
        .filter_map(|t| {
            if let GridTrack::Fraction(fr) = t {
                Some(*fr)
            } else {
                None
            }
        })
        .sum();
    let remaining = (available - gaps_total - fixed_total).max(0.0);
    tracks
        .iter()
        .map(|t| match t {
            GridTrack::Fixed(px) => *px,
            GridTrack::Fraction(fr) => {
                if fraction_total > 0.0 {
                    remaining * (fr / fraction_total)
                } else {
                    0.0
                }
            }
        })
        .collect()
}

/// One item's resolved cell(s), 0-based — either from a matching
/// `grid-area` name or from auto-placement (see `place_items`).
struct Placement {
    child_idx: usize,
    row: usize,
    col: usize,
    row_span: usize,
    col_span: usize,
}

/// A named area's bounding box (0-based, `row`/`col` the top-left
/// corner) — computed as the min/max extent of every cell that names
/// it in `grid-template-areas`, so a name spanning a real rectangle of
/// cells (e.g. `"header header"` twice in a row) resolves to one
/// region covering all of them, matching real CSS. Real CSS requires
/// every named area to actually BE a rectangle; a malformed
/// (non-rectangular) one here just silently resolves to its bounding
/// box instead of being rejected, same fallback philosophy as the rest
/// of this crate.
fn resolve_named_areas(
    areas: &[Vec<String>],
) -> std::collections::HashMap<String, (usize, usize, usize, usize)> {
    let mut bounds: std::collections::HashMap<String, (usize, usize, usize, usize)> =
        std::collections::HashMap::new();
    for (r, row) in areas.iter().enumerate() {
        for (c, name) in row.iter().enumerate() {
            if name.is_empty() || name == "." {
                continue;
            }
            bounds
                .entry(name.clone())
                .and_modify(|(min_r, min_c, max_r, max_c)| {
                    *min_r = (*min_r).min(r);
                    *min_c = (*min_c).min(c);
                    *max_r = (*max_r).max(r);
                    *max_c = (*max_c).max(c);
                })
                .or_insert((r, c, r, c));
        }
    }
    bounds
        .into_iter()
        .map(|(name, (min_r, min_c, max_r, max_c))| {
            (name, (min_r, min_c, max_r - min_r + 1, max_c - min_c + 1))
        })
        .collect()
}

/// Places every real item (whitespace-only text already filtered out
/// by the caller) into a cell or cells: `grid-area`-named items go to
/// their resolved bounding box; everything else auto-places into the
/// next free cell(s) — row-major, honoring `span <N>` — skipping any
/// cell a named area already claims (real CSS carves those regions
/// out of the auto-placement flow regardless of whether an item ever
/// actually uses that name).
fn place_items(
    item_indices: &[usize],
    children: &[LayoutBox],
    n_cols: usize,
    named_areas: &std::collections::HashMap<String, (usize, usize, usize, usize)>,
) -> Vec<Placement> {
    let mut occupied: HashSet<(usize, usize)> = HashSet::new();
    for &(row, col, row_span, col_span) in named_areas.values() {
        for r in row..row + row_span {
            for c in col..col + col_span {
                occupied.insert((r, c));
            }
        }
    }

    let mut placements = Vec::with_capacity(item_indices.len());
    let mut cursor_row = 0usize;
    let mut cursor_col = 0usize;
    for &child_idx in item_indices {
        let style = &children[child_idx].style;
        if let Some((row, col, row_span, col_span)) = style
            .grid_area()
            .and_then(|name| named_areas.get(&name).copied())
        {
            placements.push(Placement {
                child_idx,
                row,
                col,
                row_span,
                col_span,
            });
            continue;
        }

        let col_span = style.grid_column_span().clamp(1, n_cols.max(1));
        let row_span = style.grid_row_span().max(1);
        loop {
            if cursor_col + col_span > n_cols {
                cursor_col = 0;
                cursor_row += 1;
                continue;
            }
            let fits = (cursor_row..cursor_row + row_span)
                .all(|r| (cursor_col..cursor_col + col_span).all(|c| !occupied.contains(&(r, c))));
            if !fits {
                cursor_col += 1;
                continue;
            }
            for r in cursor_row..cursor_row + row_span {
                for c in cursor_col..cursor_col + col_span {
                    occupied.insert((r, c));
                }
            }
            placements.push(Placement {
                child_idx,
                row: cursor_row,
                col: cursor_col,
                row_span,
                col_span,
            });
            cursor_col += col_span;
            break;
        }
    }
    placements
}

/// Lays out `container`'s children into a grid — see this module's own
/// doc comment for exactly what's covered. Returns the consumed
/// content height so the caller (`layout_box`) can size the container
/// itself.
pub(crate) fn layout_grid(
    container: &mut LayoutBox,
    content_x: f32,
    content_y: f32,
    content_width: f32,
    font: &Font,
) -> f32 {
    let item_indices: Vec<usize> = container
        .children
        .iter()
        .enumerate()
        .filter(|(_, c)| !is_whitespace_only_text(c))
        .map(|(i, _)| i)
        .collect();
    if item_indices.is_empty() {
        return 0.0;
    }

    let style = &container.style;
    let column_gap = style.column_gap();
    let row_gap = style.row_gap();
    let row_tracks = style.grid_template_rows();
    let mut columns = style.grid_template_columns();
    let areas = style.grid_template_areas();
    let named_areas = resolve_named_areas(&areas);

    // The column count is whichever is larger: explicit tracks, or
    // the widest `grid-template-areas` row — padding any shortfall
    // with `1fr` tracks (a graceful default, same reasoning as the
    // "no explicit columns at all" fallback below).
    let areas_cols = areas.iter().map(Vec::len).max().unwrap_or(0);
    let mut n_cols = columns.len().max(areas_cols).max(1);
    if columns.is_empty() {
        // No explicit columns at all — degrade to a single column
        // (items just stack top to bottom), a graceful fallback rather
        // than an empty/zero-width grid. `grid-template-areas` (if
        // any) already widened `n_cols` above; this only fires when
        // there's truly nothing to size columns from.
        n_cols = n_cols.max(1);
    }
    while columns.len() < n_cols {
        columns.push(GridTrack::Fraction(1.0));
    }

    let placements = place_items(&item_indices, &container.children, n_cols, &named_areas);
    let n_rows = placements
        .iter()
        .map(|p| p.row + p.row_span)
        .max()
        .unwrap_or(0)
        .max(areas.len());
    if n_rows == 0 {
        return 0.0;
    }

    let col_widths = resolve_tracks(&columns, content_width, column_gap);
    let mut col_x = vec![0.0f32; n_cols];
    let mut cursor_x = content_x;
    for (c, width) in col_widths.iter().enumerate() {
        col_x[c] = cursor_x;
        cursor_x += width + column_gap;
    }

    /// This item's full spanned width (its own tracks' widths plus the
    /// gaps strictly between them — never around the outside, same as
    /// `flex`'s own gap treatment).
    fn spanned_width(col_widths: &[f32], col: usize, col_span: usize, column_gap: f32) -> f32 {
        col_widths[col..col + col_span].iter().sum::<f32>()
            + column_gap * col_span.saturating_sub(1) as f32
    }

    // First pass: lay out every SINGLE-ROW-SPAN item now, at its full
    // spanned width, purely to discover its natural height — needed
    // before an "auto" row's height is even knowable. Row-spanning
    // items are deliberately skipped here (see this module's own doc
    // comment on why they don't grow the rows they span) and laid out
    // for the first time in the second pass below instead.
    let mut row_heights = vec![0.0f32; n_rows];
    for placement in &placements {
        if placement.row_span != 1 {
            continue;
        }
        let width = spanned_width(&col_widths, placement.col, placement.col_span, column_gap);
        let item = &mut container.children[placement.child_idx];
        // `focus` (see `layout_box`'s own doc comment) is always
        // `None` for grid items — same documented scope limit as
        // `flex`'s own item-layout calls.
        layout_box(
            item,
            col_x[placement.col],
            content_y,
            width + item.margin.horizontal(),
            font,
            true,
            None,
        );
        let natural_height = item.rect.height + item.margin.vertical();
        row_heights[placement.row] = row_heights[placement.row].max(natural_height);
    }
    for (r, row_height) in row_heights.iter_mut().enumerate() {
        if let Some(GridTrack::Fixed(px)) = row_tracks.get(r) {
            *row_height = *px;
        }
    }

    let mut row_y = vec![0.0f32; n_rows];
    let mut cursor_y = content_y;
    for (r, height) in row_heights.iter().enumerate() {
        row_y[r] = cursor_y;
        cursor_y += height + row_gap;
    }

    // Second pass: every item gets its FINAL position; a row-spanning
    // item is laid out for the first time here (now that the rows it
    // spans are sized), everything else is simply repositioned/stretched.
    for placement in &placements {
        let width = spanned_width(&col_widths, placement.col, placement.col_span, column_gap);
        let cell_height = row_heights[placement.row..placement.row + placement.row_span]
            .iter()
            .sum::<f32>()
            + row_gap * placement.row_span.saturating_sub(1) as f32;
        let item = &mut container.children[placement.child_idx];
        if placement.row_span != 1 {
            layout_box(
                item,
                col_x[placement.col],
                row_y[placement.row],
                width + item.margin.horizontal(),
                font,
                true,
                None,
            );
        }
        item.rect.y = row_y[placement.row] + item.margin.top;
        item.rect.height = (cell_height - item.margin.vertical()).max(0.0);
    }

    let total_row_height: f32 =
        row_heights.iter().sum::<f32>() + row_gap * n_rows.saturating_sub(1) as f32;
    total_row_height
}

#[cfg(test)]
mod tests {
    use crate::{build_layout_tree, layout};

    fn layout_grid_container(
        container_css: &str,
        item_count: usize,
        width: f32,
    ) -> Vec<crate::LayoutBox> {
        let stylesheet =
            css::parse_stylesheet(&format!(".grid {{ display: grid; {container_css} }}"));
        let document = dom::Node::new_document();
        let grid = dom::Node::new_element("div");
        if let dom::NodeType::Element(el) = &mut grid.borrow_mut().node_type {
            el.attributes
                .insert("class".to_string(), "grid".to_string());
        }
        for _ in 0..item_count {
            let item = dom::Node::new_element("div");
            dom::append_child(&item, dom::Node::new_text("x"));
            dom::append_child(&grid, item);
        }
        dom::append_child(&document, grid);

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, width, &font);
        tree.children.remove(0).children
    }

    /// Builds a grid container with explicit per-item CSS (via
    /// per-item classes `item0`, `item1`, ...) rather than uniform
    /// items — needed for span/grid-area tests, where different items
    /// need different declarations.
    fn layout_grid_container_with_items(
        container_css: &str,
        item_css: &[&str],
        width: f32,
    ) -> Vec<crate::LayoutBox> {
        let item_rules = item_css
            .iter()
            .enumerate()
            .map(|(i, css)| format!(".item{i} {{ {css} }}"))
            .collect::<Vec<_>>()
            .join(" ");
        let stylesheet = css::parse_stylesheet(&format!(
            ".grid {{ display: grid; {container_css} }} {item_rules}"
        ));
        let document = dom::Node::new_document();
        let grid = dom::Node::new_element("div");
        if let dom::NodeType::Element(el) = &mut grid.borrow_mut().node_type {
            el.attributes
                .insert("class".to_string(), "grid".to_string());
        }
        for i in 0..item_css.len() {
            let item = dom::Node::new_element("div");
            if let dom::NodeType::Element(el) = &mut item.borrow_mut().node_type {
                el.attributes
                    .insert("class".to_string(), format!("item{i}"));
            }
            dom::append_child(&item, dom::Node::new_text("x"));
            dom::append_child(&grid, item);
        }
        dom::append_child(&document, grid);

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, width, &font);
        tree.children.remove(0).children
    }

    #[test]
    fn fixed_columns_place_items_at_the_right_x_offsets() {
        let items = layout_grid_container("grid-template-columns: 100px 100px;", 4, 400.0);
        assert_eq!(items[0].rect.x, 0.0);
        assert_eq!(items[1].rect.x, 100.0);
        assert_eq!(
            items[2].rect.x, 0.0,
            "the third item should wrap to a new row, back to column 0"
        );
        assert_eq!(items[3].rect.x, 100.0);
    }

    #[test]
    fn auto_placement_wraps_to_a_new_row_after_filling_the_columns() {
        let items = layout_grid_container("grid-template-columns: 50px 50px;", 3, 400.0);
        assert_eq!(
            items[0].rect.y, items[1].rect.y,
            "the first two items share row 0"
        );
        assert!(
            items[2].rect.y > items[0].rect.y,
            "the third item should be on row 1"
        );
    }

    #[test]
    fn fr_columns_split_available_width_proportionally() {
        let items = layout_grid_container("grid-template-columns: 1fr 3fr;", 2, 400.0);
        assert!(
            (items[0].rect.width - 100.0).abs() < 0.01,
            "1fr of 4 total = 1/4 of 400 = 100, got {}",
            items[0].rect.width
        );
        assert!(
            (items[1].rect.width - 300.0).abs() < 0.01,
            "3fr of 4 total = 3/4 of 400 = 300, got {}",
            items[1].rect.width
        );
    }

    #[test]
    fn mixed_fixed_and_fr_columns_give_fr_tracks_the_leftover_space() {
        let items = layout_grid_container("grid-template-columns: 100px 1fr;", 2, 400.0);
        assert_eq!(items[0].rect.width, 100.0);
        assert!(
            (items[1].rect.width - 300.0).abs() < 0.01,
            "1fr gets everything left after the fixed 100px track, got {}",
            items[1].rect.width
        );
    }

    #[test]
    fn repeat_expands_into_the_right_number_of_equal_columns() {
        let items = layout_grid_container("grid-template-columns: repeat(4, 1fr);", 4, 400.0);
        for item in &items {
            assert!((item.rect.width - 100.0).abs() < 0.01);
        }
        assert_eq!(items[1].rect.x, 100.0);
        assert_eq!(items[2].rect.x, 200.0);
        assert_eq!(items[3].rect.x, 300.0);
    }

    #[test]
    fn column_gap_and_row_gap_add_real_spacing() {
        let items = layout_grid_container("grid-template-columns: 50px 50px; gap: 10px;", 4, 400.0);
        assert!(
            (items[1].rect.x - (items[0].rect.x + 50.0 + 10.0)).abs() < 0.01,
            "column-gap between columns"
        );
        assert!(
            items[2].rect.y > items[0].rect.y + items[0].rect.height,
            "row-gap should leave a real gap below row 0"
        );
    }

    #[test]
    fn no_grid_template_columns_falls_back_to_a_single_column() {
        let items = layout_grid_container("", 3, 400.0);
        for item in &items {
            assert_eq!(item.rect.x, 0.0);
        }
        assert!(
            items[1].rect.y > items[0].rect.y,
            "items should still stack, one per row"
        );
        assert!(items[2].rect.y > items[1].rect.y);
    }

    #[test]
    fn items_in_the_same_row_stretch_to_that_rows_tallest_items_height() {
        let stylesheet =
            css::parse_stylesheet(".grid { display: grid; grid-template-columns: 100px 100px; }");
        let document = dom::Node::new_document();
        let grid = dom::Node::new_element("div");
        if let dom::NodeType::Element(el) = &mut grid.borrow_mut().node_type {
            el.attributes
                .insert("class".to_string(), "grid".to_string());
        }
        let tall = dom::Node::new_element("div");
        dom::append_child(&tall, dom::Node::new_text("line one"));
        dom::append_child(&tall, dom::Node::new_element("br"));
        let short = dom::Node::new_element("div");
        dom::append_child(&short, dom::Node::new_text("x"));
        dom::append_child(&grid, tall);
        dom::append_child(&grid, short);
        dom::append_child(&document, grid);

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 400.0, &font);
        let items = &tree.children[0].children;
        assert_eq!(items[0].rect.height, items[1].rect.height);
    }

    #[test]
    fn explicit_fixed_row_track_is_honored_over_content_height() {
        let items = layout_grid_container(
            "grid-template-columns: 100px; grid-template-rows: 80px;",
            1,
            400.0,
        );
        assert_eq!(items[0].rect.height, 80.0);
    }

    #[test]
    fn grid_column_span_makes_an_item_occupy_multiple_columns() {
        let items = layout_grid_container_with_items(
            "grid-template-columns: repeat(4, 1fr);",
            &["grid-column: span 2;", "", ""],
            400.0,
        );
        assert!(
            (items[0].rect.width - 200.0).abs() < 0.01,
            "spanning 2 of 4 equal 100px columns = 200px, got {}",
            items[0].rect.width
        );
        // item 1 auto-places right after item 0's span (columns 2,3 taken by item0 -> item1 lands at column 2).
        assert_eq!(items[1].rect.x, 200.0);
        assert_eq!(items[2].rect.x, 300.0);
    }

    #[test]
    fn grid_row_span_makes_an_item_taller_by_spanning_multiple_rows() {
        let items = layout_grid_container_with_items(
            "grid-template-columns: 100px 100px; grid-template-rows: 50px 50px;",
            &["grid-row: span 2;", "", ""],
            400.0,
        );
        // item0 spans rows 0-1 (100px total); item1 and item2 each take one row.
        assert!(
            (items[0].rect.height - 100.0).abs() < 0.01,
            "spanning 2 rows of 50px = 100px, got {}",
            items[0].rect.height
        );
        assert_eq!(items[0].rect.x, 0.0);
        assert_eq!(
            items[1].rect.x, 100.0,
            "item1 auto-places at column 1 (column 0 is taken by the spanning item0)"
        );
    }

    #[test]
    fn grid_area_places_an_item_at_its_named_regions_bounding_box() {
        let items = layout_grid_container_with_items(
            r#"grid-template-columns: 100px 100px; grid-template-areas: "header header" "side main";"#,
            &["grid-area: header;", "grid-area: side;", "grid-area: main;"],
            400.0,
        );
        // "header" spans both columns on row 0.
        assert_eq!(items[0].rect.x, 0.0);
        assert!(
            (items[0].rect.width - 200.0).abs() < 0.01,
            "header spans both 100px columns = 200px, got {}",
            items[0].rect.width
        );
        // "side" is row 1, column 0; "main" is row 1, column 1.
        assert_eq!(items[1].rect.x, 0.0);
        assert_eq!(items[2].rect.x, 100.0);
        assert_eq!(items[1].rect.y, items[2].rect.y);
        assert!(
            items[1].rect.y > items[0].rect.y,
            "the named-area row should come after the header row"
        );
    }

    #[test]
    fn auto_placed_items_skip_cells_already_claimed_by_a_named_area() {
        let items = layout_grid_container_with_items(
            r#"grid-template-columns: 100px 100px; grid-template-areas: "header header";"#,
            &["grid-area: header;", ""],
            400.0,
        );
        // Row 0 is entirely claimed by "header" — the unnamed second
        // item must NOT land in row 0 at all, even though there'd
        // otherwise be room; it should be pushed to row 1.
        assert!(
            items[1].rect.y > items[0].rect.y,
            "the auto-placed item must not overlap the named header area"
        );
    }
}
