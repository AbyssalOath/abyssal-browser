//! Parses margin/border/padding out of a `ComputedStyle`'s stringly
//! typed property bag. This lives here (not in `css`) because `css`
//! deliberately keeps `ComputedStyle` as an untyped `HashMap<String,
//! String>` for now (see its module docs) — the numeric box-model
//! values only need to exist as `f32`s once something actually lays
//! boxes out, which is here.

use css::ComputedStyle;

/// Four-sided spacing: used for both `margin` and `padding` (widths
/// only), and for `border` (widths — color is tracked separately on
/// `LayoutBox`, since a single set of `EdgeSizes` has nowhere to put
/// it).
#[derive(Debug, Clone, Copy, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct EdgeSizes {
    pub top: f32,
    pub right: f32,
    pub bottom: f32,
    pub left: f32,
}

impl EdgeSizes {
    pub fn horizontal(&self) -> f32 {
        self.left + self.right
    }

    pub fn vertical(&self) -> f32 {
        self.top + self.bottom
    }
}

/// Parses a CSS length. Only bare numbers (`"0"`) and `px` lengths
/// (`"12px"`) are understood — no `%`, `em`, `rem`, `vw`/`vh`, or
/// `auto` yet. Anything unparseable resolves to `0.0` rather than
/// panicking, since a stub-quality parser will see malformed/
/// unsupported values on real pages constantly.
fn parse_length(value: &str) -> f32 {
    value
        .trim()
        .trim_end_matches("px")
        .trim()
        .parse::<f32>()
        .unwrap_or(0.0)
}

/// Expands the standard CSS 1/2/3/4-value shorthand syntax
/// (`margin: 10px`, `margin: 10px 20px`, ...) into four resolved
/// sides. An empty or unparseable value list resolves to all zeros.
fn parse_shorthand(value: &str) -> EdgeSizes {
    let parts: Vec<f32> = value.split_whitespace().map(parse_length).collect();
    match parts.as_slice() {
        [all] => EdgeSizes {
            top: *all,
            right: *all,
            bottom: *all,
            left: *all,
        },
        [vertical, horizontal] => EdgeSizes {
            top: *vertical,
            bottom: *vertical,
            right: *horizontal,
            left: *horizontal,
        },
        [top, horizontal, bottom] => EdgeSizes {
            top: *top,
            right: *horizontal,
            left: *horizontal,
            bottom: *bottom,
        },
        [top, right, bottom, left] => EdgeSizes {
            top: *top,
            right: *right,
            bottom: *bottom,
            left: *left,
        },
        _ => EdgeSizes::default(),
    }
}

/// Resolves `margin` or `padding` for a computed style: starts from
/// the shorthand (if present), then lets any of the four longhands
/// (`{prefix}-top` etc.) override individual sides — matching real
/// CSS cascade behavior for shorthand-vs-longhand within a single
/// declaration block.
pub fn resolve_edges(style: &ComputedStyle, prefix: &str) -> EdgeSizes {
    let mut edges = style
        .properties
        .get(prefix)
        .map(|v| parse_shorthand(v))
        .unwrap_or_default();

    if let Some(v) = style.properties.get(&format!("{prefix}-top")) {
        edges.top = parse_length(v);
    }
    if let Some(v) = style.properties.get(&format!("{prefix}-right")) {
        edges.right = parse_length(v);
    }
    if let Some(v) = style.properties.get(&format!("{prefix}-bottom")) {
        edges.bottom = parse_length(v);
    }
    if let Some(v) = style.properties.get(&format!("{prefix}-left")) {
        edges.left = parse_length(v);
    }

    edges
}

/// Resolves a single uniform border width + optional color. Reads, in
/// order: the `border` shorthand (`"1px solid #ffffff"` — the style
/// keyword is skipped, any token starting with `#` is taken as the
/// color, any token ending in `px` as the width), then lets
/// `border-width`/`border-color` longhands override individual parts.
///
/// TODO (see module docs at the crate root): this is uniform on all
/// four sides — no `border-top-width`, no per-side color, no
/// `rgb()`/named colors.
pub fn resolve_border(style: &ComputedStyle) -> (EdgeSizes, Option<String>) {
    let mut width = 0.0;
    let mut color = None;

    if let Some(shorthand) = style.properties.get("border") {
        for token in shorthand.split_whitespace() {
            if let Some(hex) = token.strip_prefix('#') {
                color = Some(format!("#{hex}"));
            } else if token.ends_with("px") {
                width = parse_length(token);
            }
            // Anything else (e.g. `solid`, `dashed`) is a border-style
            // keyword we don't render differently yet — skip it.
        }
    }

    if let Some(v) = style.properties.get("border-width") {
        width = parse_length(v);
    }
    if let Some(v) = style.properties.get("border-color") {
        color = Some(v.clone());
    }

    let edges = EdgeSizes {
        top: width,
        right: width,
        bottom: width,
        left: width,
    };

    (edges, color)
}

/// A resolved `width`/`height`-family value: either an absolute length
/// in `px` or a percentage of some basis the caller supplies (see
/// `resolve`). `box-sizing` is always `content-box` in this crate (see
/// module docs), so every one of these always refers to the CONTENT
/// box, never the border box — a caller adds border/padding back on
/// top itself, the same way it already does for the implicit
/// (non-explicit-width) sizing path.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Sizing {
    Length(f32),
    Percent(f32),
}

impl Sizing {
    pub fn resolve(self, basis: f32) -> f32 {
        match self {
            Sizing::Length(px) => px,
            Sizing::Percent(pct) => basis * pct / 100.0,
        }
    }
}

/// Parses a bare CSS length (`px` or unitless) or percentage. `auto`
/// (explicitly, or anything else unrecognized) resolves to `None` —
/// "nothing set, fall back to this box's normal sizing," matching
/// every other property in this crate's fallback-on-unparseable
/// philosophy.
fn parse_sizing(value: &str) -> Option<Sizing> {
    let v = value.trim();
    if v.eq_ignore_ascii_case("auto") {
        return None;
    }
    if let Some(pct) = v.strip_suffix('%') {
        return pct.trim().parse::<f32>().ok().map(Sizing::Percent);
    }
    v.strip_suffix("px")
        .unwrap_or(v)
        .trim()
        .parse::<f32>()
        .ok()
        .map(Sizing::Length)
}

/// `width`/`min-width`/`max-width` — percentages are meaningful here
/// (resolved against the containing block's available width, which
/// this crate always has a concrete number for by the time it's
/// needed — see `layout::layout_box`), so both `Length` and `Percent`
/// are supported.
pub fn resolve_width(style: &ComputedStyle) -> Option<Sizing> {
    style.properties.get("width").and_then(|v| parse_sizing(v))
}

pub fn resolve_min_width(style: &ComputedStyle) -> Option<Sizing> {
    style
        .properties
        .get("min-width")
        .and_then(|v| parse_sizing(v))
}

pub fn resolve_max_width(style: &ComputedStyle) -> Option<Sizing> {
    style
        .properties
        .get("max-width")
        .and_then(|v| parse_sizing(v))
}

/// `height`/`min-height`/`max-height` — deliberately `Length`-only
/// (a percentage is silently ignored, same treatment as `auto`): a
/// percentage height is only meaningful in real CSS when the
/// containing block itself has a definite (non-content-derived)
/// height, which most boxes in this crate's block-layout model don't
/// (see `layout`'s own module docs — heights are normally derived
/// bottom-up from content, not imposed top-down), so resolving one
/// against, say, the box's own not-yet-known natural height would
/// just be inventing a number rather than implementing the real rule.
pub fn resolve_height(style: &ComputedStyle) -> Option<f32> {
    length_only(style.properties.get("height"))
}

pub fn resolve_min_height(style: &ComputedStyle) -> Option<f32> {
    length_only(style.properties.get("min-height"))
}

pub fn resolve_max_height(style: &ComputedStyle) -> Option<f32> {
    length_only(style.properties.get("max-height"))
}

fn length_only(value: Option<&String>) -> Option<f32> {
    match value.and_then(|v| parse_sizing(v)) {
        Some(Sizing::Length(px)) => Some(px),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn style_with(props: &[(&str, &str)]) -> ComputedStyle {
        let mut properties = HashMap::new();
        for (k, v) in props {
            properties.insert(k.to_string(), v.to_string());
        }
        ComputedStyle { properties }
    }

    #[test]
    fn single_value_shorthand_applies_to_all_sides() {
        let style = style_with(&[("margin", "10px")]);
        let edges = resolve_edges(&style, "margin");
        assert_eq!(
            edges,
            EdgeSizes {
                top: 10.0,
                right: 10.0,
                bottom: 10.0,
                left: 10.0
            }
        );
    }

    #[test]
    fn two_value_shorthand_is_vertical_then_horizontal() {
        let style = style_with(&[("padding", "5px 20px")]);
        let edges = resolve_edges(&style, "padding");
        assert_eq!(
            edges,
            EdgeSizes {
                top: 5.0,
                right: 20.0,
                bottom: 5.0,
                left: 20.0
            }
        );
    }

    #[test]
    fn four_value_shorthand_is_top_right_bottom_left() {
        let style = style_with(&[("margin", "1px 2px 3px 4px")]);
        let edges = resolve_edges(&style, "margin");
        assert_eq!(
            edges,
            EdgeSizes {
                top: 1.0,
                right: 2.0,
                bottom: 3.0,
                left: 4.0
            }
        );
    }

    #[test]
    fn longhand_overrides_shorthand_for_one_side() {
        let style = style_with(&[("margin", "10px"), ("margin-left", "40px")]);
        let edges = resolve_edges(&style, "margin");
        assert_eq!(
            edges,
            EdgeSizes {
                top: 10.0,
                right: 10.0,
                bottom: 10.0,
                left: 40.0
            }
        );
    }

    #[test]
    fn border_shorthand_extracts_width_and_color_ignoring_style_keyword() {
        let style = style_with(&[("border", "2px solid #ff00ff")]);
        let (edges, color) = resolve_border(&style);
        assert_eq!(
            edges,
            EdgeSizes {
                top: 2.0,
                right: 2.0,
                bottom: 2.0,
                left: 2.0
            }
        );
        assert_eq!(color.as_deref(), Some("#ff00ff"));
    }

    #[test]
    fn border_longhands_override_shorthand() {
        let style = style_with(&[
            ("border", "2px solid #ff00ff"),
            ("border-width", "5px"),
            ("border-color", "#00ff00"),
        ]);
        let (edges, color) = resolve_border(&style);
        assert_eq!(
            edges,
            EdgeSizes {
                top: 5.0,
                right: 5.0,
                bottom: 5.0,
                left: 5.0
            }
        );
        assert_eq!(color.as_deref(), Some("#00ff00"));
    }

    #[test]
    fn missing_properties_resolve_to_zero() {
        let style = style_with(&[]);
        assert_eq!(resolve_edges(&style, "margin"), EdgeSizes::default());
        let (edges, color) = resolve_border(&style);
        assert_eq!(edges, EdgeSizes::default());
        assert!(color.is_none());
    }

    #[test]
    fn width_parses_px_and_percent() {
        let px = style_with(&[("width", "200px")]);
        assert_eq!(resolve_width(&px), Some(Sizing::Length(200.0)));

        let pct = style_with(&[("width", "50%")]);
        assert_eq!(resolve_width(&pct), Some(Sizing::Percent(50.0)));
        assert_eq!(resolve_width(&pct).unwrap().resolve(400.0), 200.0);
    }

    #[test]
    fn width_auto_or_unset_resolves_to_none() {
        assert_eq!(resolve_width(&style_with(&[("width", "auto")])), None);
        assert_eq!(resolve_width(&style_with(&[])), None);
    }

    #[test]
    fn unitless_width_is_treated_as_px() {
        assert_eq!(
            resolve_width(&style_with(&[("width", "150")])),
            Some(Sizing::Length(150.0))
        );
    }

    #[test]
    fn min_and_max_width_parse_independently() {
        let style = style_with(&[("min-width", "100px"), ("max-width", "80%")]);
        assert_eq!(resolve_min_width(&style), Some(Sizing::Length(100.0)));
        assert_eq!(resolve_max_width(&style), Some(Sizing::Percent(80.0)));
    }

    #[test]
    fn height_only_accepts_lengths_not_percentages() {
        let style = style_with(&[("height", "300px")]);
        assert_eq!(resolve_height(&style), Some(300.0));

        let pct_style = style_with(&[("height", "50%")]);
        assert_eq!(
            resolve_height(&pct_style),
            None,
            "a percentage height should be ignored, not resolved against a made-up basis"
        );
    }

    #[test]
    fn min_max_height_also_length_only() {
        let style = style_with(&[("min-height", "50px"), ("max-height", "10%")]);
        assert_eq!(resolve_min_height(&style), Some(50.0));
        assert_eq!(resolve_max_height(&style), None);
    }
}
