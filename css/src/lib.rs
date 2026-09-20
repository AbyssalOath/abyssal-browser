//! `css` — parses stylesheets and resolves computed styles per DOM node.
//!
//! Scope of this stub:
//!   - selectors: real now — tag, `#id`, `.class`, `[attr]`/`[attr=v]`/
//!     `[attr~=v]`/`[attr|=v]`/`[attr^=v]`/`[attr$=v]`/`[attr*=v]`,
//!     the universal `*`, combinators (` ` descendant, `>` child, `+`
//!     adjacent-sibling, `~` general-sibling), comma-separated selector
//!     lists (`h1, h2 { ... }`), and structural pseudo-classes
//!     (`:first-child`, `:last-child`, `:only-child`, `:first-of-type`,
//!     `:last-of-type`, `:nth-child(An+B)`, `:nth-of-type(An+B)`,
//!     `:not(...)`, `:root`, `:empty`, `:link`). See `SimpleSelector`
//!     for the full list and `Selector`/`Combinator` for how compound
//!     selectors chain together.
//!   - deliberately excluded: pseudo-*elements* (`::before`, a whole
//!     different, content-generating concept this crate doesn't have a
//!     render-tree hook for at all), and any pseudo-class that needs
//!     *interaction* state — `:hover`/`:focus`/`:active` parse (so a
//!     stylesheet using them doesn't break) but never match, and
//!     `:visited` isn't even parsed as a distinct case (falls through
//!     with every other unrecognized pseudo-class to "selector fails
//!     to parse, rule dropped"). `:hover`'s omission is a real,
//!     temporary limitation (`render::window`'s mouse-move handler
//!     does no work at all today — see its own module docs on the GPU-
//!     exhaustion bug that caused that — so there's no live cursor
//!     position to test against yet). `:visited`'s omission is
//!     deliberate and permanent: real browsers already tightly
//!     restrict what `:visited` can style specifically because it's a
//!     known history-sniffing side channel, and the simplest way to
//!     close that channel entirely is to never distinguish visited
//!     from unvisited in the first place.
//!   - specificity: real (see `Specificity`), the same `(id, class,
//!     type)` triple the CSS spec itself uses — `id_count` is nonzero
//!     now that `#id` selectors exist. Declarations from every
//!     matching rule are gathered and sorted by `(specificity, source
//!     order)` before being applied, so a higher-specificity rule
//!     earlier in a stylesheet correctly beats a lower-specificity
//!     rule later in it — not just "last rule wins."
//!   - inheritance: real now for a fixed list of properties
//!     (`INHERITED_PROPERTIES`) — `compute_style` takes the parent's
//!     already-computed style and falls back to it for any
//!     inheritable property this node didn't set itself. Still not
//!     "real" in the sense of deriving inheritability from a full CSS
//!     property table; it's a curated list of the common inheritable
//!     properties (matching the CSS spec's own designation of which
//!     ones inherit).
//!   - the cascade's "origin" concept (user agent / user / author
//!     stylesheets, `!important`) is entirely absent — `Stylesheet::extend`
//!     approximates "author beats user-agent" via source order, which
//!     works because our UA stylesheet only ever uses tag selectors
//!     (see `user_agent_stylesheet`), but isn't the real origin-based
//!     cascade.
//!
//! Next steps, roughly in order of payoff:
//!   1. Real cascade origins (user-agent vs. author vs. `!important`)
//!      instead of approximating "author wins" via source order.
//!   2. Wire up `:hover` for real once `render::window` grows a live
//!      cursor position it's safe to recompute style/layout from (see
//!      that crate's own module docs on why mouse-move is inert today).
//!   3. Shorthand property expansion (`margin: 1px 2px` -> four longhands).

use dom::{NodeRef, NodeType};
use std::collections::HashMap;
use std::rc::Rc;

#[derive(Debug, Clone)]
pub struct Declaration {
    pub property: String,
    pub value: String,
}

/// One non-combinator selector fragment — everything that can appear
/// glued directly onto a tag with no whitespace (`div.foo#bar[baz]`).
/// A `CompoundSelector` is an implicit AND of these.
#[derive(Debug, Clone)]
pub enum SimpleSelector {
    Universal,
    Tag(String),
    Id(String),
    Class(String),
    Attribute(AttributeSelector),
    PseudoClass(PseudoClass),
}

#[derive(Debug, Clone)]
pub struct AttributeSelector {
    pub name: String,
    pub match_kind: AttrMatch,
}

/// The operator inside `[attr<op>value]` — `Exists` for a bare
/// `[attr]`. Matches the real CSS attribute-selector operators except
/// case-insensitive matching (`[attr=value i]`), which isn't parsed.
#[derive(Debug, Clone)]
pub enum AttrMatch {
    Exists,
    Equals(String),
    /// `~=`: value is a whitespace-separated list containing this word.
    Includes(String),
    /// `|=`: value equals this, or starts with `this-`.
    DashMatch(String),
    /// `^=`: value starts with this (non-empty).
    PrefixMatch(String),
    /// `$=`: value ends with this (non-empty).
    SuffixMatch(String),
    /// `*=`: value contains this (non-empty).
    SubstringMatch(String),
}

/// An `An+B` expression, as used by `:nth-child()`/`:nth-of-type()` —
/// `odd` parses to `{a: 2, b: 1}`, `even` to `{a: 2, b: 0}`. A node at
/// 1-based sibling position `p` matches when `p == a*n + b` for some
/// integer `n >= 0` (see `nth_matches`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct NthExpr {
    pub a: i32,
    pub b: i32,
}

/// Structural/interactive pseudo-classes. See module docs for which
/// ones are deliberately never-matching stand-ins (`Hover`/`Focus`)
/// versus deliberately entirely unparsed (`:visited`).
#[derive(Debug, Clone)]
pub enum PseudoClass {
    FirstChild,
    LastChild,
    OnlyChild,
    FirstOfType,
    LastOfType,
    NthChild(NthExpr),
    NthOfType(NthExpr),
    Not(Box<CompoundSelector>),
    Root,
    Empty,
    /// Any `<a>`/`<area>` with an `href` — real CSS distinguishes
    /// `:link` (unvisited) from `:visited`, a distinction this crate
    /// deliberately never makes (see module docs), so this matches
    /// every hyperlink regardless of visit state.
    Link,
    /// Parses, never matches — see module docs.
    Hover,
    /// Parses, never matches — see module docs.
    Focus,
}

/// One `tag#id.class[attr]:pseudo` chunk with no combinator inside it
/// — every `SimpleSelector` in `simple_selectors` must match (AND).
#[derive(Debug, Clone, Default)]
pub struct CompoundSelector {
    pub simple_selectors: Vec<SimpleSelector>,
}

/// The relationship between two adjacent compound selectors in a
/// chain (`div > p`, `h1 ~ p`, `li + li`, or plain whitespace for
/// `Descendant`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Combinator {
    /// `a b` — `b` is any descendant of `a`, at any depth.
    Descendant,
    /// `a > b` — `b` is a direct child of `a`.
    Child,
    /// `a + b` — `b` is the element immediately following `a` among
    /// its siblings (ignoring text/comment nodes).
    NextSibling,
    /// `a ~ b` — `b` is any later sibling of `a`.
    SubsequentSibling,
}

/// A full selector: one compound selector (`first`), optionally
/// followed by more compounds each joined by a `Combinator`, read
/// left-to-right the same way CSS source reads (`first` is the
/// outermost/leftmost part, the LAST entry of `rest` is the part that
/// must match the actual target element).
#[derive(Debug, Clone)]
pub struct Selector {
    pub first: CompoundSelector,
    pub rest: Vec<(Combinator, CompoundSelector)>,
}

/// A selector's specificity, modeled as the same `(id, class, type)`
/// triple the CSS spec itself uses — compared lexicographically via
/// the derived `Ord` (id most significant, type least), exactly
/// matching spec precedence. Attribute selectors and (non-`:not`)
/// pseudo-classes count at the `class` level, matching the real spec;
/// `:not(...)`'s own specificity is that of its argument, also
/// matching spec (a "free" negation would otherwise let `:not(#id)`
/// dodge `#id`'s real weight).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Specificity {
    id_count: u32,
    class_count: u32,
    type_count: u32,
}

impl std::ops::AddAssign for Specificity {
    fn add_assign(&mut self, other: Specificity) {
        self.id_count += other.id_count;
        self.class_count += other.class_count;
        self.type_count += other.type_count;
    }
}

impl CompoundSelector {
    fn specificity(&self) -> Specificity {
        let mut total = Specificity::default();
        for simple in &self.simple_selectors {
            total += match simple {
                SimpleSelector::Universal => Specificity::default(),
                SimpleSelector::Tag(_) => Specificity {
                    type_count: 1,
                    ..Default::default()
                },
                SimpleSelector::Id(_) => Specificity {
                    id_count: 1,
                    ..Default::default()
                },
                SimpleSelector::Class(_) | SimpleSelector::Attribute(_) => Specificity {
                    class_count: 1,
                    ..Default::default()
                },
                SimpleSelector::PseudoClass(PseudoClass::Not(inner)) => inner.specificity(),
                SimpleSelector::PseudoClass(_) => Specificity {
                    class_count: 1,
                    ..Default::default()
                },
            };
        }
        total
    }
}

impl Selector {
    pub fn specificity(&self) -> Specificity {
        let mut total = self.first.specificity();
        for (_, compound) in &self.rest {
            total += compound.specificity();
        }
        total
    }

    /// The chain flattened into `(incoming combinator, compound)`
    /// pairs in source order — `first`'s slot always has `None`, since
    /// nothing precedes it. Shared by matching (`selector_matches`)
    /// rather than duplicating the `first`-then-`rest` walk twice.
    fn flatten(&self) -> Vec<(Option<Combinator>, &CompoundSelector)> {
        let mut chain = Vec::with_capacity(self.rest.len() + 1);
        chain.push((None, &self.first));
        chain.extend(self.rest.iter().map(|(c, s)| (Some(*c), s)));
        chain
    }
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub selector: Selector,
    pub declarations: Vec<Declaration>,
}

#[derive(Debug, Default)]
pub struct Stylesheet {
    pub rules: Vec<Rule>,
}

/// The root font size real browsers default `<html>` to absent any
/// stylesheet saying otherwise — what an unset "font-size" ultimately
/// bottoms out at once inheritance runs out of ancestors. See
/// `resolve_font_size`/`compute_style`.
const DEFAULT_FONT_SIZE_PX: f32 = 16.0;

/// Computed style for one element: just a property->value bag for now.
/// TODO: this should eventually be a typed struct (`display: Display`,
/// `color: Color`, ...) rather than stringly-typed values — you'll
/// want that before layout can reason about e.g. box model numbers.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct ComputedStyle {
    pub properties: HashMap<String, String>,
}

/// How a box participates in layout. This is the one property pulled
/// out of the otherwise-stringly-typed `ComputedStyle` bag into a real
/// enum, because `layout` needs to branch on it directly (block vs.
/// inline vs. flex vs. grid formatting, or skip the box entirely)
/// rather than string-matching at every call site.
///
/// TODO: `inline-block`, `table*`, and friends are still unimplemented
/// — anything other than `none`/`inline`/`flex`/`grid` resolves to
/// `Block`, matching real CSS's fallback behavior for unrecognized
/// values but not (yet) covering these other real display modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Display {
    Block,
    Inline,
    Flex,
    Grid,
    None,
}

impl ComputedStyle {
    /// Resolves the `display` property. Defaults to `Block` — every
    /// element is block-level unless a stylesheet (typically the
    /// user-agent stylesheet, see `user_agent_stylesheet`) says
    /// otherwise, which is also what happens for any unrecognized
    /// value rather than erroring.
    pub fn display(&self) -> Display {
        match self.properties.get("display").map(String::as_str) {
            Some("none") => Display::None,
            Some("inline") => Display::Inline,
            Some("flex") => Display::Flex,
            Some("grid") => Display::Grid,
            _ => Display::Block,
        }
    }

    /// This node's resolved font size, in pixels. `compute_style`
    /// (see `resolve_font_size`, which it calls) already normalizes
    /// "font-size" to a plain `"Npx"` string for every node — this
    /// just parses that back out, with a fallback for the case where
    /// something bypassed `compute_style` entirely (e.g. a
    /// hand-built `ComputedStyle` in a test) rather than for any real
    /// runtime path.
    pub fn font_size(&self) -> f32 {
        self.properties
            .get("font-size")
            .and_then(|v| v.strip_suffix("px"))
            .and_then(|n| n.parse::<f32>().ok())
            .unwrap_or(DEFAULT_FONT_SIZE_PX)
    }
}

/// A box's positioning scheme — `layout::apply_positioning` is what
/// actually acts on this (this crate only parses it); see that
/// function's own doc comment for the full story on what each variant
/// does and doesn't cover (in particular `Fixed`'s scoped-down
/// "anchors to the page, not the live viewport" behavior).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Position {
    #[default]
    Static,
    Relative,
    Absolute,
    Fixed,
}

impl ComputedStyle {
    /// Defaults to `Static` — every element stays in normal flow
    /// unless told otherwise, same fallback-on-unrecognized-value
    /// philosophy as `display()`.
    pub fn position(&self) -> Position {
        match self.properties.get("position").map(String::as_str) {
            Some("relative") => Position::Relative,
            Some("absolute") => Position::Absolute,
            Some("fixed") => Position::Fixed,
            _ => Position::Static,
        }
    }

    /// `top`/`right`/`bottom`/`left` — deliberately `px`-length-only
    /// (no percentage support, unlike `width`'s own offset-adjacent
    /// properties in `layout::box_model`): a percentage offset here
    /// resolves against the containing block's size, but "containing
    /// block" for `position: absolute` specifically depends on
    /// walking up to the nearest positioned ancestor, and getting that
    /// resolution subtly wrong would silently mis-place an element
    /// rather than just under-supporting it — `None` (the same
    /// treatment as `auto`/unset) is safer than a wrong number. Reuses
    /// this same crate's own `parse_length` (see the `gap`/flex-basis
    /// parsing above), which already treats an unparseable value as
    /// `None` rather than `0.0`, so this needs no extra handling for
    /// `"auto"` specifically.
    pub fn top(&self) -> Option<f32> {
        self.properties.get("top").and_then(|v| parse_length(v))
    }
    pub fn right(&self) -> Option<f32> {
        self.properties.get("right").and_then(|v| parse_length(v))
    }
    pub fn bottom(&self) -> Option<f32> {
        self.properties.get("bottom").and_then(|v| parse_length(v))
    }
    pub fn left(&self) -> Option<f32> {
        self.properties.get("left").and_then(|v| parse_length(v))
    }
}

/// `float` — see `layout`'s own module docs for what actually acts on
/// this (this crate only parses it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Float {
    #[default]
    None,
    Left,
    Right,
}

/// `clear` — pushes a box down past any active float(s) on the given
/// side(s). `Both` is the common real-world "clearfix" value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Clear {
    #[default]
    None,
    Left,
    Right,
    Both,
}

impl ComputedStyle {
    pub fn float(&self) -> Float {
        match self.properties.get("float").map(String::as_str) {
            Some("left") => Float::Left,
            Some("right") => Float::Right,
            _ => Float::None,
        }
    }

    pub fn clear(&self) -> Clear {
        match self.properties.get("clear").map(String::as_str) {
            Some("left") => Clear::Left,
            Some("right") => Clear::Right,
            Some("both") => Clear::Both,
            _ => Clear::None,
        }
    }
}

/// The main-axis direction of a `display: flex` container. `RowReverse`/
/// `ColumnReverse` aren't implemented — an unrecognized or reversed
/// value falls back to `Row`, same fallback-to-default philosophy as
/// `Display`'s own unrecognized-value handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlexDirection {
    Row,
    Column,
}

/// Whether a `display: flex` container wraps overflowing items onto
/// additional lines. `WrapReverse` isn't implemented — falls back to
/// `NoWrap`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlexWrap {
    NoWrap,
    Wrap,
}

/// How a flex/grid container distributes extra space along the main
/// axis. `SpaceEvenly` isn't implemented — falls back to `FlexStart`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JustifyContent {
    FlexStart,
    FlexEnd,
    Center,
    SpaceBetween,
    SpaceAround,
}

/// How a flex/grid container aligns items along the cross axis.
/// `Baseline` isn't implemented — falls back to `Stretch`, the real
/// CSS default for `align-items`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlignItems {
    FlexStart,
    FlexEnd,
    Center,
    Stretch,
}

impl ComputedStyle {
    pub fn flex_direction(&self) -> FlexDirection {
        match self.properties.get("flex-direction").map(String::as_str) {
            Some("column") | Some("column-reverse") => FlexDirection::Column,
            _ => FlexDirection::Row,
        }
    }

    pub fn flex_wrap(&self) -> FlexWrap {
        match self.properties.get("flex-wrap").map(String::as_str) {
            Some("wrap") | Some("wrap-reverse") => FlexWrap::Wrap,
            _ => FlexWrap::NoWrap,
        }
    }

    pub fn justify_content(&self) -> JustifyContent {
        match self.properties.get("justify-content").map(String::as_str) {
            Some("flex-end") => JustifyContent::FlexEnd,
            Some("center") => JustifyContent::Center,
            Some("space-between") => JustifyContent::SpaceBetween,
            Some("space-around") => JustifyContent::SpaceAround,
            _ => JustifyContent::FlexStart,
        }
    }

    /// Real CSS default is `Stretch`, not `FlexStart` — matched here
    /// deliberately (see `AlignItems`'s own doc comment).
    pub fn align_items(&self) -> AlignItems {
        match self.properties.get("align-items").map(String::as_str) {
            Some("flex-start") => AlignItems::FlexStart,
            Some("flex-end") => AlignItems::FlexEnd,
            Some("center") => AlignItems::Center,
            _ => AlignItems::Stretch,
        }
    }

    /// `flex-grow` — how eagerly this item claims extra space along
    /// the main axis, relative to its siblings' own grow factors.
    /// Real CSS default is `0` (don't grow at all).
    pub fn flex_grow(&self) -> f32 {
        self.properties
            .get("flex-grow")
            .and_then(|v| v.trim().parse::<f32>().ok())
            .unwrap_or(0.0)
            .max(0.0)
    }

    /// `flex-shrink` — how eagerly this item gives up space when the
    /// container is too small for everyone's basis size, relative to
    /// siblings. Real CSS default is `1` (shrink is normally ON,
    /// unlike grow), matched here deliberately.
    pub fn flex_shrink(&self) -> f32 {
        self.properties
            .get("flex-shrink")
            .and_then(|v| v.trim().parse::<f32>().ok())
            .unwrap_or(1.0)
            .max(0.0)
    }

    /// `flex-basis` — this item's starting main-axis size before
    /// grow/shrink redistribute space. `None` means `auto` (fall back
    /// to the item's own natural/available size, same as an ordinary
    /// block/inline box would resolve to) — real CSS also supports
    /// `content` and percentage bases; neither is implemented, both
    /// fall back to `auto` the same as an unset/unrecognized value.
    pub fn flex_basis(&self) -> Option<f32> {
        let raw = self.properties.get("flex-basis")?;
        let trimmed = raw.trim();
        if trimmed == "auto" {
            return None;
        }
        trimmed
            .strip_suffix("px")
            .unwrap_or(trimmed)
            .trim()
            .parse()
            .ok()
    }

    /// The `gap`/`row-gap`/`column-gap` shorthand-and-longhands family
    /// — `gap` sets both axes at once (real CSS shorthand order is
    /// `row-gap column-gap`; a single value sets both), and the two
    /// longhands each override just their own axis, matching how
    /// `box_model`'s margin/padding shorthand-vs-longhand precedence
    /// already works elsewhere in this codebase.
    pub fn row_gap(&self) -> f32 {
        self.gap_longhand("row-gap")
            .or_else(|| self.gap_shorthand().map(|(row, _)| row))
            .unwrap_or(0.0)
    }

    pub fn column_gap(&self) -> f32 {
        self.gap_longhand("column-gap")
            .or_else(|| self.gap_shorthand().map(|(_, col)| col))
            .unwrap_or(0.0)
    }

    fn gap_longhand(&self, property: &str) -> Option<f32> {
        let raw = self.properties.get(property)?;
        parse_length(raw)
    }

    fn gap_shorthand(&self) -> Option<(f32, f32)> {
        let raw = self.properties.get("gap")?;
        let mut parts = raw.split_whitespace().filter_map(parse_length);
        let row = parts.next()?;
        let column = parts.next().unwrap_or(row);
        Some((row, column))
    }

    /// `grid-template-columns`/`grid-template-rows` — a space-separated
    /// list of track sizes, each either a fixed length (`100px`), a
    /// flexible `<N>fr` share of whatever space is left after every
    /// fixed track is subtracted, or `repeat(<count>, <pattern>)`
    /// (expanded inline — `repeat(3, 1fr)` becomes three separate
    /// `1fr` tracks; `<pattern>` can itself be more than one track,
    /// e.g. `repeat(2, 100px 1fr)`, repeating the whole pattern
    /// `<count>` times). Real CSS also supports percentages, `auto`,
    /// `minmax()`, and nested/`auto-fill`/`auto-fit` repeats — none of
    /// that is implemented; an unparseable track is dropped rather
    /// than erroring, same fallback philosophy as everything else in
    /// this stringly-typed style bag.
    pub fn grid_template_columns(&self) -> Vec<GridTrack> {
        parse_grid_tracks(
            self.properties
                .get("grid-template-columns")
                .map(String::as_str)
                .unwrap_or(""),
        )
    }

    pub fn grid_template_rows(&self) -> Vec<GridTrack> {
        parse_grid_tracks(
            self.properties
                .get("grid-template-rows")
                .map(String::as_str)
                .unwrap_or(""),
        )
    }

    /// `grid-template-areas` — each quoted string is one grid ROW,
    /// each whitespace-separated token within it one cell's area name
    /// (`.` conventionally means "no area," same as real CSS, though
    /// nothing here treats it specially beyond it simply never
    /// matching a real `grid-area` value). Real CSS requires every
    /// named area's cells to form a single rectangle and every row
    /// string to have the same number of tokens — neither is
    /// validated here; `layout::grid` just takes the bounding box of
    /// wherever a name actually appears, which happens to produce the
    /// same result for well-formed input and something merely
    /// "reasonable rather than spec-correct" for malformed input,
    /// consistent with this stringly-typed bag's fallback philosophy
    /// elsewhere.
    pub fn grid_template_areas(&self) -> Vec<Vec<String>> {
        match self.properties.get("grid-template-areas") {
            Some(raw) => parse_grid_template_areas(raw),
            None => Vec::new(),
        }
    }

    /// `grid-area` on a grid ITEM — only the simple `grid-area: <name>`
    /// form (matching a `grid-template-areas` name) is supported;
    /// `None` for anything else (including real CSS's 4-part
    /// `row-start / col-start / row-end / col-end` line-number form,
    /// or a bare line number), which callers treat as "auto-place this
    /// item normally" rather than guessing at a numeric placement.
    pub fn grid_area(&self) -> Option<String> {
        let raw = self.properties.get("grid-area")?.trim();
        if raw.is_empty()
            || raw.contains('/')
            || raw.chars().next().is_some_and(|c| c.is_ascii_digit())
        {
            return None;
        }
        Some(raw.to_string())
    }

    /// `grid-column`/`grid-row` on a grid ITEM — only the `span <N>`
    /// form is read, returning how many tracks (minimum 1) this item
    /// should occupy in that axis while still being auto-placed (or
    /// named-area-placed, if `grid_area` also resolved — see
    /// `layout::grid`'s own doc comment for how the two interact). A
    /// bare line number or the 2-part `<start> / <end>` explicit-line
    /// form isn't implemented — falls back to `1`, i.e. "no special
    /// span," same as an unset value.
    pub fn grid_column_span(&self) -> usize {
        parse_grid_span(self.properties.get("grid-column").map(String::as_str))
    }

    pub fn grid_row_span(&self) -> usize {
        parse_grid_span(self.properties.get("grid-row").map(String::as_str))
    }
}

/// One track (`grid-template-columns`/`-rows`) — see that accessor's
/// doc comment for scope.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum GridTrack {
    Fixed(f32),
    Fraction(f32),
}

fn parse_grid_tracks(raw: &str) -> Vec<GridTrack> {
    let mut tracks = Vec::new();
    for token in split_top_level_tokens(raw) {
        if let Some(inner) = token
            .strip_prefix("repeat(")
            .and_then(|s| s.strip_suffix(')'))
        {
            if let Some((count_str, pattern)) = inner.split_once(',') {
                if let Ok(count) = count_str.trim().parse::<usize>() {
                    let pattern_tracks = parse_grid_tracks(pattern.trim());
                    for _ in 0..count {
                        tracks.extend(pattern_tracks.iter().copied());
                    }
                }
            }
            continue;
        }
        if let Some(fr) = token.strip_suffix("fr") {
            if let Ok(v) = fr.trim().parse::<f32>() {
                tracks.push(GridTrack::Fraction(v));
                continue;
            }
        }
        if let Some(px) = parse_length(token) {
            tracks.push(GridTrack::Fixed(px));
        }
    }
    tracks
}

/// Splits `raw` on whitespace, EXCEPT inside a `(...)` group — so
/// `repeat(2, 100px 1fr) 50px` splits into `["repeat(2, 100px 1fr)",
/// "50px"]`, not four separately-broken pieces. A plain
/// `split_whitespace()` (what this crate's other track/gap parsing
/// uses) can't handle `repeat()`'s own internal spaces and comma at
/// all — this is the one place that needs to be paren-aware.
fn split_top_level_tokens(raw: &str) -> Vec<&str> {
    let mut tokens = Vec::new();
    let mut depth = 0i32;
    let mut start: Option<usize> = None;
    for (i, ch) in raw.char_indices() {
        match ch {
            '(' => {
                depth += 1;
                start.get_or_insert(i);
            }
            ')' => {
                depth -= 1;
            }
            c if c.is_whitespace() && depth == 0 => {
                if let Some(s) = start.take() {
                    tokens.push(&raw[s..i]);
                }
            }
            _ => {
                start.get_or_insert(i);
            }
        }
    }
    if let Some(s) = start {
        tokens.push(&raw[s..]);
    }
    tokens
}

/// See `ComputedStyle::grid_template_areas`'s doc comment.
fn parse_grid_template_areas(raw: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut in_quotes = false;
    let mut start = 0;
    for (i, ch) in raw.char_indices() {
        if ch != '"' {
            continue;
        }
        if in_quotes {
            rows.push(
                raw[start..i]
                    .split_whitespace()
                    .map(str::to_string)
                    .collect(),
            );
            in_quotes = false;
        } else {
            in_quotes = true;
            start = i + '"'.len_utf8();
        }
    }
    rows
}

/// See `ComputedStyle::grid_column_span`/`grid_row_span`'s doc comment.
fn parse_grid_span(raw: Option<&str>) -> usize {
    let Some(raw) = raw else { return 1 };
    match raw.trim().strip_prefix("span") {
        Some(rest) => rest
            .trim()
            .parse::<usize>()
            .ok()
            .filter(|&n| n > 0)
            .unwrap_or(1),
        None => 1,
    }
}

/// Resolves ONE node's "font-size" against its parent's already-
/// resolved pixel size — `px` (absolute), `em`/bare numbers
/// (multiples of `parent_px`), and `%` (percentage of `parent_px`)
/// are the units that actually matter for font-size in practice; a
/// handful of the CSS spec's absolute/relative keywords are supported
/// too since UA stylesheets and older sites both still use them.
/// `specified` is `None` when this node didn't set (or inherit — see
/// `compute_style`) a "font-size" at all, which simply keeps the
/// parent's size unchanged, same as real CSS inheritance; an
/// unparseable value falls back to the parent's size the same way
/// every other unrecognized value in this stringly-typed style bag
/// does (see e.g. `display()`'s own doc comment).
fn resolve_font_size(specified: Option<&str>, parent_px: f32) -> f32 {
    let Some(raw) = specified else {
        return parent_px;
    };
    let trimmed = raw.trim();
    if let Some(pct) = trimmed.strip_suffix('%') {
        return pct
            .trim()
            .parse::<f32>()
            .map(|p| parent_px * p / 100.0)
            .unwrap_or(parent_px);
    }
    if let Some(em) = trimmed.strip_suffix("em") {
        return em
            .trim()
            .parse::<f32>()
            .map(|multiplier| parent_px * multiplier)
            .unwrap_or(parent_px);
    }
    if let Some(px) = trimmed.strip_suffix("px") {
        return px.trim().parse::<f32>().unwrap_or(parent_px);
    }
    match trimmed {
        "smaller" => return parent_px / 1.2,
        "larger" => return parent_px * 1.2,
        "xx-small" => return DEFAULT_FONT_SIZE_PX * 0.6,
        "x-small" => return DEFAULT_FONT_SIZE_PX * 0.75,
        "small" => return DEFAULT_FONT_SIZE_PX * 0.89,
        "medium" => return DEFAULT_FONT_SIZE_PX,
        "large" => return DEFAULT_FONT_SIZE_PX * 1.2,
        "x-large" => return DEFAULT_FONT_SIZE_PX * 1.5,
        "xx-large" => return DEFAULT_FONT_SIZE_PX * 2.0,
        _ => {}
    }
    // A bare number with no unit at all (non-standard for real CSS,
    // but cheap to accept and matches this stub's existing
    // lenient-parsing philosophy elsewhere, e.g. `parse_length` below).
    trimmed.parse::<f32>().unwrap_or(parent_px)
}

/// A bare CSS length in `px` (or unitless — treated the same way this
/// stub already treats every other unitless number) — shared by the
/// `gap`/grid-track parsing above. Doesn't support any other unit
/// (`em`, `%`, ...); an unparseable value is simply absent, same
/// fallback-to-default philosophy as the rest of this stringly-typed
/// style bag.
fn parse_length(raw: &str) -> Option<f32> {
    let trimmed = raw.trim();
    trimmed
        .strip_suffix("px")
        .unwrap_or(trimmed)
        .trim()
        .parse()
        .ok()
}

/// Extremely small stylesheet parser. No at-rules (@media, @import),
/// no comments-inside-values edge cases, no error recovery.
///
/// A selector list (`h1, h2 { ... }`) becomes one `Rule` per
/// comma-separated selector that parses successfully — each gets its
/// own (cloned) copy of the block's declarations, so the cascade sees
/// them as independent rules with independent specificity, matching
/// real CSS (a selector list is pure shorthand for repeating the same
/// declaration block against each selector). A selector in the list
/// that fails to parse is dropped silently; the others still apply.
pub fn parse_stylesheet(input: &str) -> Stylesheet {
    let mut rules = Vec::new();
    let mut rest = input;

    while let Some(open) = rest.find('{') {
        let selector_list_str = rest[..open].trim();
        let close = match rest[open..].find('}') {
            Some(c) => open + c,
            None => break, // malformed input; a real parser recovers here
        };
        let body = &rest[open + 1..close];
        let declarations = parse_declarations(body);

        for selector_str in split_top_level(selector_list_str, ',') {
            if let Some(selector) = parse_selector(selector_str) {
                rules.push(Rule {
                    selector,
                    declarations: declarations.clone(),
                });
            }
        }

        rest = &rest[close + 1..];
    }

    Stylesheet { rules }
}

/// Splits `s` on top-level occurrences of `separator` — never inside
/// a `[...]` or `(...)` group, which is what lets `[attr=","]` (an
/// attribute value containing the separator) or `:not(a, b)`-shaped
/// input pass through a single token unsplit. Empty pieces are
/// dropped; a wholly-empty or whitespace-only `s` yields no pieces at
/// all (used for both selector-list commas and combinator-spacing).
fn split_top_level(s: &str, separator: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    for (i, ch) in s.char_indices() {
        match ch {
            '[' | '(' => depth += 1,
            ']' | ')' => depth -= 1,
            c if c == separator && depth == 0 => {
                let piece = s[start..i].trim();
                if !piece.is_empty() {
                    parts.push(piece);
                }
                start = i + separator.len_utf8();
            }
            _ => {}
        }
    }
    let last = s[start..].trim();
    if !last.is_empty() {
        parts.push(last);
    }
    parts
}

/// Parses one (non-comma-list) selector chain: a compound selector,
/// optionally followed by more compounds each joined by a combinator.
/// An explicit combinator character (`>`, `+`, `~`) may or may not
/// have surrounding whitespace (`div>p` and `div > p` both parse the
/// same); bare whitespace with no explicit character is the implicit
/// `Descendant` combinator.
fn parse_selector(s: &str) -> Option<Selector> {
    let spaced = pad_combinators(s);
    let mut tokens = split_top_level_whitespace(&spaced).into_iter();

    let first = parse_compound_selector(tokens.next()?)?;
    let mut rest = Vec::new();
    let mut pending_combinator: Option<Combinator> = None;

    for token in tokens {
        match token {
            ">" => pending_combinator = Some(Combinator::Child),
            "+" => pending_combinator = Some(Combinator::NextSibling),
            "~" => pending_combinator = Some(Combinator::SubsequentSibling),
            _ => {
                let combinator = pending_combinator.take().unwrap_or(Combinator::Descendant);
                rest.push((combinator, parse_compound_selector(token)?));
            }
        }
    }

    Some(Selector { first, rest })
}

/// Surrounds every top-level `>`/`+`/`~` with spaces so a later
/// `split_whitespace()` yields them as their own tokens — e.g.
/// `"div>p"` becomes `"div > p"`. Left untouched inside `[...]`/`(...)`
/// so an attribute value or `:not()` argument containing one of these
/// characters is never mistaken for a combinator.
fn pad_combinators(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut depth = 0i32;
    for ch in s.chars() {
        match ch {
            '[' | '(' => {
                depth += 1;
                out.push(ch);
            }
            ']' | ')' => {
                depth -= 1;
                out.push(ch);
            }
            '>' | '+' | '~' if depth == 0 => {
                out.push(' ');
                out.push(ch);
                out.push(' ');
            }
            _ => out.push(ch),
        }
    }
    out
}

/// Splits `s` on whitespace, except inside a `[...]` or `(...)` group
/// — so an attribute selector's quoted value (`[data-x="a b"]`) or a
/// `:not(...)` argument survives as one token instead of being torn
/// apart at the space inside it, the same concern `split_top_level`
/// handles for commas.
fn split_top_level_whitespace(s: &str) -> Vec<&str> {
    let mut tokens = Vec::new();
    let mut depth = 0i32;
    let mut start: Option<usize> = None;
    for (i, ch) in s.char_indices() {
        match ch {
            '[' | '(' => {
                depth += 1;
                start.get_or_insert(i);
            }
            ']' | ')' => {
                depth -= 1;
            }
            c if c.is_whitespace() && depth == 0 => {
                if let Some(st) = start.take() {
                    tokens.push(&s[st..i]);
                }
            }
            _ => {
                start.get_or_insert(i);
            }
        }
    }
    if let Some(st) = start {
        tokens.push(&s[st..]);
    }
    tokens
}

fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '-' || c == '_'
}

/// Finds the index of the `close` matching the `open` at `chars[start]`
/// (which must itself be `open`), respecting nesting — used for both
/// `[...]` and `(...)`.
fn find_matching_bracket(chars: &[char], start: usize, open: char, close: char) -> Option<usize> {
    let mut depth = 0i32;
    for (i, &ch) in chars.iter().enumerate().skip(start) {
        if ch == open {
            depth += 1;
        } else if ch == close {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
    }
    None
}

/// Parses one compound selector — a tag/universal (if present, must
/// come first) followed by any number of `#id`/`.class`/`[attr]`/
/// `:pseudo` pieces in any order, with no whitespace between any of
/// them. Returns `None` for anything that doesn't parse cleanly
/// (unbalanced brackets, an unrecognized pseudo-class, a `::`
/// pseudo-element) rather than guessing — see `parse_stylesheet`'s
/// doc comment on how a failure here affects the surrounding rule.
fn parse_compound_selector(s: &str) -> Option<CompoundSelector> {
    let chars: Vec<char> = s.chars().collect();
    let mut simple = Vec::new();
    let mut i = 0;

    if i < chars.len() && (chars[i].is_alphabetic() || chars[i] == '*') {
        if chars[i] == '*' {
            simple.push(SimpleSelector::Universal);
            i += 1;
        } else {
            let start = i;
            while i < chars.len() && is_ident_char(chars[i]) {
                i += 1;
            }
            let tag: String = chars[start..i].iter().collect();
            simple.push(SimpleSelector::Tag(tag.to_lowercase()));
        }
    }

    while i < chars.len() {
        match chars[i] {
            '.' => {
                i += 1;
                let start = i;
                while i < chars.len() && is_ident_char(chars[i]) {
                    i += 1;
                }
                if start == i {
                    return None;
                }
                simple.push(SimpleSelector::Class(chars[start..i].iter().collect()));
            }
            '#' => {
                i += 1;
                let start = i;
                while i < chars.len() && is_ident_char(chars[i]) {
                    i += 1;
                }
                if start == i {
                    return None;
                }
                simple.push(SimpleSelector::Id(chars[start..i].iter().collect()));
            }
            '[' => {
                let close = find_matching_bracket(&chars, i, '[', ']')?;
                let inner: String = chars[i + 1..close].iter().collect();
                simple.push(parse_attribute_selector(&inner)?);
                i = close + 1;
            }
            ':' => {
                let mut j = i + 1;
                if j < chars.len() && chars[j] == ':' {
                    // A `::pseudo-element` — a different, content-
                    // generating concept this crate has no render-tree
                    // hook for at all (see module docs); bail out
                    // rather than silently ignoring just the `::` part,
                    // since matching the bare name would be wrong.
                    return None;
                }
                let name_start = j;
                while j < chars.len() && is_ident_char(chars[j]) {
                    j += 1;
                }
                let name: String = chars[name_start..j]
                    .iter()
                    .collect::<String>()
                    .to_lowercase();
                if j < chars.len() && chars[j] == '(' {
                    let close = find_matching_bracket(&chars, j, '(', ')')?;
                    let arg: String = chars[j + 1..close].iter().collect();
                    simple.push(parse_functional_pseudo_class(&name, arg.trim())?);
                    i = close + 1;
                } else {
                    simple.push(parse_pseudo_class(&name)?);
                    i = j;
                }
            }
            _ => return None,
        }
    }

    if simple.is_empty() {
        None
    } else {
        Some(CompoundSelector {
            simple_selectors: simple,
        })
    }
}

fn unquote(s: &str) -> String {
    let s = s.trim();
    let bytes = s.as_bytes();
    if bytes.len() >= 2
        && ((bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\''))
    {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

/// One `[attr<op>value]` operator string paired with the `AttrMatch`
/// variant constructor it selects — see `parse_attribute_selector`'s
/// own `OPERATORS` table.
type AttrOperator = (&'static str, fn(String) -> AttrMatch);

/// Parses the inside of `[...]` — see `AttrMatch` for the operators
/// understood. Multi-character operators are checked before the
/// bare `=` they each contain, so `[a~=b]` isn't mis-split as `[a` `~`
/// `=b]`.
fn parse_attribute_selector(inner: &str) -> Option<SimpleSelector> {
    const OPERATORS: &[AttrOperator] = &[
        ("~=", AttrMatch::Includes),
        ("|=", AttrMatch::DashMatch),
        ("^=", AttrMatch::PrefixMatch),
        ("$=", AttrMatch::SuffixMatch),
        ("*=", AttrMatch::SubstringMatch),
        ("=", AttrMatch::Equals),
    ];
    for (op, ctor) in OPERATORS {
        if let Some(idx) = inner.find(op) {
            let name = inner[..idx].trim();
            if name.is_empty() {
                return None;
            }
            let value = unquote(inner[idx + op.len()..].trim());
            return Some(SimpleSelector::Attribute(AttributeSelector {
                name: name.to_lowercase(),
                match_kind: ctor(value),
            }));
        }
    }
    let name = inner.trim();
    if name.is_empty() {
        return None;
    }
    Some(SimpleSelector::Attribute(AttributeSelector {
        name: name.to_lowercase(),
        match_kind: AttrMatch::Exists,
    }))
}

fn parse_pseudo_class(name: &str) -> Option<SimpleSelector> {
    let pc = match name {
        "first-child" => PseudoClass::FirstChild,
        "last-child" => PseudoClass::LastChild,
        "only-child" => PseudoClass::OnlyChild,
        "first-of-type" => PseudoClass::FirstOfType,
        "last-of-type" => PseudoClass::LastOfType,
        "root" => PseudoClass::Root,
        "empty" => PseudoClass::Empty,
        "link" => PseudoClass::Link,
        "hover" => PseudoClass::Hover,
        "focus" => PseudoClass::Focus,
        _ => return None,
    };
    Some(SimpleSelector::PseudoClass(pc))
}

fn parse_functional_pseudo_class(name: &str, arg: &str) -> Option<SimpleSelector> {
    let pc = match name {
        "nth-child" => PseudoClass::NthChild(parse_nth(arg)?),
        "nth-of-type" => PseudoClass::NthOfType(parse_nth(arg)?),
        "not" => PseudoClass::Not(Box::new(parse_compound_selector(arg)?)),
        _ => return None,
    };
    Some(SimpleSelector::PseudoClass(pc))
}

/// Parses an `An+B` expression (`"odd"`, `"even"`, `"3"`, `"2n+1"`,
/// `"-n+3"`, ...) — see `NthExpr`'s doc comment for the matching rule.
fn parse_nth(raw: &str) -> Option<NthExpr> {
    let s: String = raw
        .trim()
        .to_lowercase()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    if s == "odd" {
        return Some(NthExpr { a: 2, b: 1 });
    }
    if s == "even" {
        return Some(NthExpr { a: 2, b: 0 });
    }
    match s.find('n') {
        Some(pos) => {
            let a = match &s[..pos] {
                "" => 1,
                "-" => -1,
                other => other.parse().ok()?,
            };
            let rest = &s[pos + 1..];
            let b = if rest.is_empty() {
                0
            } else {
                rest.parse().ok()?
            };
            Some(NthExpr { a, b })
        }
        None => Some(NthExpr {
            a: 0,
            b: s.parse().ok()?,
        }),
    }
}

/// Whether 1-based sibling position `position` satisfies `expr`: real
/// CSS considers `position = a*n + b` for `n = 0, 1, 2, ...`, so a
/// match exists exactly when `(position - b)` is evenly divisible by
/// `a` with a non-negative quotient (or, when `a == 0`, exactly when
/// `position == b`).
fn nth_matches(expr: NthExpr, position: i32) -> bool {
    if expr.a == 0 {
        return position == expr.b;
    }
    let diff = position - expr.b;
    diff % expr.a == 0 && diff / expr.a >= 0
}

fn parse_declarations(body: &str) -> Vec<Declaration> {
    body.split(';')
        .filter_map(|decl| {
            let mut parts = decl.splitn(2, ':');
            let property = parts.next()?.trim();
            let value = parts.next()?.trim();
            if property.is_empty() || value.is_empty() {
                return None;
            }
            Some(Declaration {
                property: property.to_string(),
                value: value.to_string(),
            })
        })
        .collect()
}

/// `node`'s parent, if it has one and the weak link still resolves
/// (it always should for a live, still-attached tree).
fn parent_of(node: &NodeRef) -> Option<NodeRef> {
    node.borrow().parent.as_ref()?.upgrade()
}

/// `node`'s element-type siblings (itself included), in document
/// order — real CSS's `:nth-child`/`:first-child`/etc. all count
/// *element* siblings only, text/comment nodes don't participate.
/// `None` if `node` has no parent at all (a document root).
fn element_siblings(node: &NodeRef) -> Option<Vec<NodeRef>> {
    let parent = parent_of(node)?;
    let siblings = parent
        .borrow()
        .children
        .iter()
        .filter(|c| matches!(c.borrow().node_type, NodeType::Element(_)))
        .cloned()
        .collect();
    Some(siblings)
}

fn tag_name_of(node: &NodeRef) -> Option<String> {
    match &node.borrow().node_type {
        NodeType::Element(el) => Some(el.tag_name.clone()),
        _ => None,
    }
}

fn attribute_matches(attr: &AttributeSelector, el: &dom::Element) -> bool {
    let Some(value) = el.attributes.get(&attr.name) else {
        return false;
    };
    match &attr.match_kind {
        AttrMatch::Exists => true,
        AttrMatch::Equals(v) => value == v,
        AttrMatch::Includes(v) => value.split_whitespace().any(|w| w == v),
        AttrMatch::DashMatch(v) => value == v || value.starts_with(&format!("{v}-")),
        AttrMatch::PrefixMatch(v) => !v.is_empty() && value.starts_with(v.as_str()),
        AttrMatch::SuffixMatch(v) => !v.is_empty() && value.ends_with(v.as_str()),
        AttrMatch::SubstringMatch(v) => !v.is_empty() && value.contains(v.as_str()),
    }
}

fn pseudo_class_matches(pc: &PseudoClass, node: &NodeRef) -> bool {
    match pc {
        PseudoClass::Root => {
            parent_of(node).is_some_and(|p| matches!(p.borrow().node_type, NodeType::Document))
        }
        PseudoClass::Empty => node
            .borrow()
            .children
            .iter()
            .all(|c| match &c.borrow().node_type {
                NodeType::Text(t) => t.is_empty(),
                NodeType::Element(_) => false,
                _ => true,
            }),
        PseudoClass::Link => {
            matches!(&node.borrow().node_type, NodeType::Element(el) if (el.tag_name == "a" || el.tag_name == "area") && el.attributes.contains_key("href"))
        }
        PseudoClass::Hover | PseudoClass::Focus => false, // see module docs
        PseudoClass::FirstChild => {
            element_siblings(node).and_then(|sibs| sibs.iter().position(|s| Rc::ptr_eq(s, node)))
                == Some(0)
        }
        PseudoClass::LastChild => {
            let Some(sibs) = element_siblings(node) else {
                return false;
            };
            !sibs.is_empty()
                && sibs.iter().position(|s| Rc::ptr_eq(s, node)) == Some(sibs.len() - 1)
        }
        PseudoClass::OnlyChild => {
            let Some(sibs) = element_siblings(node) else {
                return false;
            };
            sibs.len() == 1
        }
        PseudoClass::NthChild(expr) => {
            let Some(sibs) = element_siblings(node) else {
                return false;
            };
            match sibs.iter().position(|s| Rc::ptr_eq(s, node)) {
                Some(idx) => nth_matches(*expr, idx as i32 + 1),
                None => false,
            }
        }
        PseudoClass::FirstOfType => match (element_siblings(node), tag_name_of(node)) {
            (Some(sibs), Some(tag)) => sibs
                .iter()
                .find(|s| tag_name_of(s).as_deref() == Some(tag.as_str()))
                .is_some_and(|s| Rc::ptr_eq(s, node)),
            _ => false,
        },
        PseudoClass::LastOfType => match (element_siblings(node), tag_name_of(node)) {
            (Some(sibs), Some(tag)) => sibs
                .iter()
                .rfind(|s| tag_name_of(s).as_deref() == Some(tag.as_str()))
                .is_some_and(|s| Rc::ptr_eq(s, node)),
            _ => false,
        },
        PseudoClass::NthOfType(expr) => match (element_siblings(node), tag_name_of(node)) {
            (Some(sibs), Some(tag)) => {
                let same_type: Vec<&NodeRef> = sibs
                    .iter()
                    .filter(|s| tag_name_of(s).as_deref() == Some(tag.as_str()))
                    .collect();
                match same_type.iter().position(|s| Rc::ptr_eq(s, node)) {
                    Some(idx) => nth_matches(*expr, idx as i32 + 1),
                    None => false,
                }
            }
            _ => false,
        },
        PseudoClass::Not(inner) => !compound_matches(inner, node),
    }
}

fn simple_matches(simple: &SimpleSelector, node: &NodeRef) -> bool {
    match simple {
        SimpleSelector::Universal => true,
        SimpleSelector::Tag(tag) => tag_name_of(node).as_deref() == Some(tag.as_str()),
        SimpleSelector::Id(id) => {
            matches!(&node.borrow().node_type, NodeType::Element(el) if el.attributes.get("id").map(String::as_str) == Some(id.as_str()))
        }
        SimpleSelector::Class(class) => {
            matches!(&node.borrow().node_type, NodeType::Element(el) if el.attributes.get("class").map(|c| c.split_whitespace().any(|c| c == class)).unwrap_or(false))
        }
        SimpleSelector::Attribute(attr) => {
            matches!(&node.borrow().node_type, NodeType::Element(el) if attribute_matches(attr, el))
        }
        SimpleSelector::PseudoClass(pc) => pseudo_class_matches(pc, node),
    }
}

fn compound_matches(compound: &CompoundSelector, node: &NodeRef) -> bool {
    if !matches!(node.borrow().node_type, NodeType::Element(_)) {
        return false;
    }
    compound
        .simple_selectors
        .iter()
        .all(|s| simple_matches(s, node))
}

/// The immediately preceding element sibling of `node` (skipping any
/// text/comment nodes in between), if any — what `+`/`~` combinators
/// walk backward through.
fn previous_element_sibling(node: &NodeRef) -> Option<NodeRef> {
    let parent = parent_of(node)?;
    let parent_ref = parent.borrow();
    let idx = parent_ref
        .children
        .iter()
        .position(|c| Rc::ptr_eq(c, node))?;
    parent_ref.children[..idx]
        .iter()
        .rev()
        .find(|c| matches!(c.borrow().node_type, NodeType::Element(_)))
        .cloned()
}

/// Walks a flattened selector chain backward from `idx` (whose
/// compound is assumed to already match the node it was checked
/// against — see `selector_matches`), verifying every earlier
/// combinator/compound pair against `node`'s ancestors/siblings.
/// `Descendant`/`SubsequentSibling` search every candidate (any
/// ancestor, any earlier sibling) since more than one might satisfy
/// the rest of the chain; `Child`/`NextSibling` have only one
/// candidate to check.
fn matches_from(
    chain: &[(Option<Combinator>, &CompoundSelector)],
    idx: usize,
    node: &NodeRef,
) -> bool {
    if idx == 0 {
        return true;
    }
    let combinator = chain[idx].0.expect("only index 0 has no combinator");
    let earlier_compound = chain[idx - 1].1;
    match combinator {
        Combinator::Child => match parent_of(node) {
            Some(p) => compound_matches(earlier_compound, &p) && matches_from(chain, idx - 1, &p),
            None => false,
        },
        Combinator::Descendant => {
            let mut current = parent_of(node);
            while let Some(p) = current {
                if compound_matches(earlier_compound, &p) && matches_from(chain, idx - 1, &p) {
                    return true;
                }
                current = parent_of(&p);
            }
            false
        }
        Combinator::NextSibling => match previous_element_sibling(node) {
            Some(s) => compound_matches(earlier_compound, &s) && matches_from(chain, idx - 1, &s),
            None => false,
        },
        Combinator::SubsequentSibling => {
            let mut current = previous_element_sibling(node);
            while let Some(s) = current {
                if compound_matches(earlier_compound, &s) && matches_from(chain, idx - 1, &s) {
                    return true;
                }
                current = previous_element_sibling(&s);
            }
            false
        }
    }
}

fn selector_matches(selector: &Selector, node: &NodeRef) -> bool {
    let chain = selector.flatten();
    let last_idx = chain.len() - 1;
    compound_matches(chain[last_idx].1, node) && matches_from(&chain, last_idx, node)
}

/// Parses `selector_text` as a (possibly comma-separated) selector
/// list and reports whether `node` matches ANY of them — a selector
/// list is a logical OR, the same semantics real `querySelector`/
/// `querySelectorAll`/`Element.matches()` all use. Exposed
/// independently of the cascade/`Stylesheet` machinery above for
/// callers that just need "does this one node match this one selector
/// string" — in practice, `renderer::script`'s DOM bindings, which is
/// also where the actual document/subtree WALK that turns this into a
/// real `querySelector(All)` lives (this crate has no DOM traversal of
/// its own beyond what `compute_style`'s cascade already needs).
///
/// A selector that fails to parse contributes `false` rather than an
/// error — matching this crate's established fallback philosophy
/// elsewhere (see `parse_stylesheet`'s own doc comment on a selector
/// list where only some entries parse).
pub fn matches(selector_text: &str, node: &NodeRef) -> bool {
    split_top_level(selector_text, ',')
        .into_iter()
        .filter_map(parse_selector)
        .any(|selector| selector_matches(&selector, node))
}

/// CSS properties that inherit from parent to child when this node
/// doesn't set them itself — a fixed, curated list matching the CSS
/// spec's own designation of which properties inherit (not derived
/// from any general per-property metadata table, since we don't have
/// one). Anything not in this list simply doesn't inherit: an
/// unset-here property is just absent, cascade or no cascade.
const INHERITED_PROPERTIES: &[&str] = &[
    "color",
    "font-family",
    // "font-size" is NOT in this generic list — see `compute_style`'s
    // dedicated resolution step below. A real `em`/`%` font-size has
    // to resolve against the PARENT's already-resolved pixel value at
    // the point it's computed (not copied down as a raw, still-relative
    // string for some later reader to reinterpret against the wrong
    // ancestor), so it needs its own step rather than the generic
    // copy-the-raw-string-down-if-unset handling every other inherited
    // property gets here.
    "font-weight",
    "font-style",
    "line-height",
    "text-align",
    "visibility",
    "cursor",
    "letter-spacing",
    "white-space",
];

/// Compute the style for a single node against a stylesheet.
///
/// `parent_style` is this node's parent's already-computed style (or
/// `None` for a document root) — used to resolve `INHERITED_PROPERTIES`
/// this node doesn't set itself. Passing the SAME node's own style as
/// `parent_style` for its children (rather than re-deriving anything)
/// is how a caller threads inheritance down a tree; see
/// `layout::build_layout_tree` for exactly that pattern.
///
/// Cascade: every matching rule's declarations are gathered, then
/// sorted by `(Specificity, source_order)` before being applied — a
/// higher-specificity rule wins regardless of where it appears in the
/// stylesheet; among equal specificity, later source order wins (both
/// match the real CSS cascade for same-origin, non-`!important`
/// rules — see module docs for what's still missing: real origins and
/// `!important`). An element's own `style="..."` attribute, if any, is
/// applied AFTER every selector-based rule regardless of specificity —
/// matching real CSS, where an inline style beats even an `!important`-free
/// `#id` selector (specificity effectively "wins by construction," not by
/// out-scoring the highest real specificity value).
pub fn compute_style(
    node: &NodeRef,
    stylesheet: &Stylesheet,
    parent_style: Option<&ComputedStyle>,
) -> ComputedStyle {
    let mut matches: Vec<(Specificity, usize, &Declaration)> = Vec::new();
    for (order, rule) in stylesheet.rules.iter().enumerate() {
        if selector_matches(&rule.selector, node) {
            let specificity = rule.selector.specificity();
            for decl in &rule.declarations {
                matches.push((specificity, order, decl));
            }
        }
    }
    // Stable sort ascending by (specificity, source order): applying
    // in this order and overwriting on ties means the last-applied
    // entry for any given property is always the correct cascade
    // winner — highest specificity, then latest source order.
    matches.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

    let mut properties = HashMap::new();
    for (_, _, decl) in matches {
        properties.insert(decl.property.clone(), decl.value.clone());
    }

    if let NodeType::Element(el) = &node.borrow().node_type {
        if let Some(style_attr) = el.attributes.get("style") {
            for decl in parse_declarations(style_attr) {
                properties.insert(decl.property, decl.value);
            }
        }
    }

    if let Some(parent) = parent_style {
        for prop in INHERITED_PROPERTIES {
            if !properties.contains_key(*prop) {
                if let Some(inherited_value) = parent.properties.get(*prop) {
                    properties.insert((*prop).to_string(), inherited_value.clone());
                }
            }
        }
    }

    // Resolves to an absolute pixel value and canonicalizes it back
    // into `properties` as a plain `"Npx"` string — this is what lets
    // a DESCENDANT that also uses `em`/`%` (or no font-size at all)
    // read `parent.properties.get("font-size")` back out as an
    // already-resolved pixel value on the next call, rather than a
    // still-relative string it would have to know how to re-resolve
    // itself. Matches real CSS: `font-size` inherits as the parent's
    // COMPUTED (pixel) value, not its specified (possibly relative)
    // one. Runs for every node, including the root (`parent_style ==
    // None`), which is what makes `DEFAULT_FONT_SIZE_PX` the ultimate
    // fallback an unstyled document bottoms out at.
    let parent_font_size_px = parent_style.map(ComputedStyle::font_size);
    let resolved_font_size = resolve_font_size(
        properties.get("font-size").map(String::as_str),
        parent_font_size_px.unwrap_or(DEFAULT_FONT_SIZE_PX),
    );
    properties.insert("font-size".to_string(), format!("{resolved_font_size}px"));

    ComputedStyle { properties }
}

impl Stylesheet {
    /// Append `other`'s rules after this stylesheet's own rules. Since
    /// `compute_style` applies rules in order and lets later matches
    /// overwrite earlier ones for the same property, appending an
    /// author stylesheet after a user-agent stylesheet gives the
    /// author priority — a rough stand-in for real cascade/specificity
    /// (see the module docs' TODO on that).
    pub fn extend(&mut self, other: Stylesheet) {
        self.rules.extend(other.rules);
    }
}

/// Which color scheme the browser's default (user-agent) stylesheet
/// uses. This is "dark mode" at the architecture level: real browsers
/// ship a default stylesheet regardless of what the page provides,
/// and light/dark mode is largely a matter of which default colors
/// that stylesheet uses. `Dark` is the default here, per product
/// requirement — most privacy browsers (Mullvad Browser, Tor Browser)
/// also default to a dark theme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Theme {
    Light,
    #[default]
    Dark,
}

impl Theme {
    pub fn background_hex(self) -> &'static str {
        match self {
            Theme::Dark => "#121212",
            Theme::Light => "#ffffff",
        }
    }

    pub fn foreground_hex(self) -> &'static str {
        match self {
            Theme::Dark => "#e8e8e8",
            Theme::Light => "#111111",
        }
    }

    /// A form control's own background — deliberately distinct from
    /// the page background (`background_hex`) so a real `<input>` box
    /// still reads as "a control," not as an invisible hole in the
    /// page, the same way it does in a real browser regardless of the
    /// page's own color scheme.
    pub fn input_background_hex(self) -> &'static str {
        match self {
            Theme::Dark => "#2a2a2a",
            Theme::Light => "#ffffff",
        }
    }

    /// A form control's border — see `input_background_hex`'s doc
    /// comment for why this needs its own (theme-aware, but
    /// page-background-independent) color.
    pub fn input_border_hex(self) -> &'static str {
        match self {
            Theme::Dark => "#666666",
            Theme::Light => "#999999",
        }
    }

    /// Canonical lowercase name — what a settings UI stores/displays
    /// and what `parse` reads back. Kept next to `parse` so the two
    /// can never drift apart into accepting/producing different spellings.
    pub fn as_str(self) -> &'static str {
        match self {
            Theme::Dark => "dark",
            Theme::Light => "light",
        }
    }

    /// The inverse of `as_str` — used by settings persistence (a
    /// stored `Settings` string) and a typed `set theme <name>`
    /// command. `None` for anything else, rather than falling back to
    /// a default, so the caller can tell "unset" apart from "typo."
    pub fn parse(name: &str) -> Option<Theme> {
        match name {
            "dark" => Some(Theme::Dark),
            "light" => Some(Theme::Light),
            _ => None,
        }
    }
}

/// Tags whose content is never rendered as page content: metadata
/// (`head`, `title`, `meta`, `link`) and source code (`script`,
/// `style`) that real browsers hide from the render tree entirely
/// rather than flowing as text. `noscript`/`template` are included
/// for the same reason. Previously this lived as a hardcoded list in
/// `layout`; now it's just `display: none` in the user-agent
/// stylesheet like a real browser, so an author stylesheet is free to
/// override it (or hide/show other elements the same way).
const NEVER_RENDERED_TAGS: &[&str] = &[
    "head", "title", "meta", "link", "script", "style", "noscript", "template",
];

/// Common inline-level HTML elements. TODO: this is a fixed list
/// covering the everyday cases (nav links, emphasis, small inline
/// labels) — real HTML has more (e.g. `<button>`, `<select>` are
/// inline-block), none of which are distinguished from plain `inline`
/// here yet. `img` IS included — real HTML's `inline-replaced` isn't a
/// distinct value this crate's `Display` enum has (there's no
/// `InlineBlock` variant at all yet), but `layout`'s own image sizing
/// (never stretching to fill, only ever shrinking to fit — see that
/// crate's `layout_box`) already gives an `<img>` the one behavior
/// that actually matters day to day, so plain `Inline` is close enough
/// not to need a dedicated value yet.
const INLINE_TAGS: &[&str] = &[
    "a", "span", "b", "i", "em", "strong", "small", "code", "label", "abbr", "sub", "sup", "u",
    "s", "mark", "img", "input", "video", "audio",
];

/// The browser's default stylesheet — applied before any page CSS, so
/// author rules (added via `Stylesheet::extend`) can override it.
///
/// `color` is set once, on `html` — real inheritance (see
/// `compute_style`) carries it down to `body`, every element, and
/// every text node from there, the same way a real browser's UA
/// stylesheet does it. This used to repeat the color on every common
/// tag as a workaround before inheritance existed; that workaround is
/// gone now that the real thing is here.
pub fn user_agent_stylesheet(theme: Theme) -> Stylesheet {
    let bg = theme.background_hex();
    let fg = theme.foreground_hex();
    let mut css_text = format!(
        "html {{ background-color: {bg}; color: {fg}; }} \
         body {{ background-color: {bg}; }}"
    );

    for tag in NEVER_RENDERED_TAGS {
        css_text.push_str(&format!(" {tag} {{ display: none; }}"));
    }
    for tag in INLINE_TAGS {
        css_text.push_str(&format!(" {tag} {{ display: inline; }}"));
    }

    // A real form-control box: fixed default size (matching real
    // browsers' own `<input>` UA default, roughly), a visible border
    // and control-specific background/text color (see
    // `input_background_hex`/`input_border_hex`'s own doc comments for
    // why those are distinct from the page's own colors), and enough
    // padding that typed text doesn't touch the border. `width`/
    // `height`/`border`/`padding` are all real, author-overridable CSS
    // properties already (see `layout::box_model`) — this is just the
    // UA-level default, exactly like `display: inline` above.
    let input_bg = theme.input_background_hex();
    let input_border = theme.input_border_hex();
    css_text.push_str(&format!(
        " input {{ width: 150px; height: 22px; border: 1px solid {input_border}; \
           background-color: {input_bg}; color: {fg}; padding: 2px 4px; }}"
    ));

    // A checkbox/radio is a small, roughly-square widget, not a
    // 150px-wide text box — this real ATTRIBUTE selector (see
    // `SimpleSelector::Attribute`) overrides just `width`/`height`/
    // `padding` from the generic `input` rule above; `border`/
    // `background-color`/`color` still come from that same rule
    // (untouched here), via the ordinary per-PROPERTY cascade
    // (`compute_style` merges every matching rule's declarations
    // rather than letting a more specific rule replace a less specific
    // one wholesale) — this rule's higher specificity (an attribute
    // selector counts at the CLASS level, beating the plain `input`
    // type selector — see `Specificity`) is what makes it win for the
    // three properties it actually sets.
    css_text.push_str(
        r#" input[type="checkbox"], input[type="radio"] { width: 16px; height: 16px; padding: 0; }"#,
    );

    // `<audio>` without `controls` is invisible per real HTML semantics
    // (a page is expected to control it entirely via script, which
    // this browser doesn't support — see `layout::MediaContent`'s own
    // doc comment) — matched here the same way the checkbox/radio rule
    // above overrides the generic `input` rule: a higher-specificity
    // attribute selector (`audio[controls]`) beats the bare-type
    // `audio` rule for the one property (`display`) both set. `video`
    // always shows a box (its poster or a placeholder — see
    // `render::paint_media`) regardless of `controls`, matching real
    // browsers.
    css_text.push_str(" audio { display: none; }");
    css_text.push_str(" audio[controls] { display: inline; width: 300px; height: 32px; }");
    css_text.push_str(" video { display: inline; width: 300px; height: 150px; }");

    // Default heading sizes, matching (approximately) every mainstream
    // browser's own UA stylesheet — `em`, so an author who sets a
    // different BODY font-size still gets proportionally-scaled
    // headings rather than these fixed absolute pixel values. Without
    // this, a page with no CSS of its own renders every heading at the
    // same size as its body text (`h1`..`h6` had no UA rule at all
    // before this pass — see `layout`'s own `font_size` support this
    // now feeds into). `font-weight: bold` is real browsers' other
    // heading default, deliberately NOT added here: nothing in
    // `text`/`render` can paint a bold glyph yet (no second font face,
    // no synthetic-bold rendering), so setting it would be a silent
    // no-op rather than a real improvement.
    for (tag, em) in [
        ("h1", 2.0),
        ("h2", 1.5),
        ("h3", 1.17),
        ("h4", 1.0),
        ("h5", 0.83),
        ("h6", 0.67),
    ] {
        css_text.push_str(&format!(" {tag} {{ font-size: {em}em; }}"));
    }

    parse_stylesheet(&css_text)
}

/// Walks `document` for `<style>` elements (in document order) and
/// parses each one's text content as CSS, combining them into a
/// single `Stylesheet` via `Stylesheet::extend` — a later `<style>`
/// block's rules win ties against an earlier one's, matching real CSS
/// cascade behavior for same-origin, non-`!important` rules (see this
/// crate's own module docs on what's still missing there). This is
/// what makes a real page's OWN CSS apply at all, as opposed to only
/// ever getting `user_agent_stylesheet`'s built-in defaults — a
/// caller is expected to build the UA stylesheet first and
/// `.extend()` this one after it, so author rules win, the same
/// pattern `Stylesheet::extend`'s own doc comment already describes.
///
/// Scope, deliberately narrow: only inline `<style>` blocks are read.
/// `<link rel="stylesheet" href="...">` isn't — see
/// `extract_author_stylesheet_with_external` for the version that
/// also splices in already-fetched external stylesheets. Inline
/// `style="..."` attributes on individual elements aren't read either
/// (a real, separate gap from this one — see `layout`'s own module
/// docs' TODO list).
pub fn extract_author_stylesheet(document: &NodeRef) -> Stylesheet {
    extract_author_stylesheet_with_external(document, &HashMap::new())
}

/// Same as `extract_author_stylesheet`, but for each `<link
/// rel="stylesheet" href="...">` element encountered, also looks up
/// that element's `dom::NodeId` in `external_css` and — if present —
/// parses and splices in that (already-fetched) raw CSS text at
/// exactly that point in document order, the same way an inline
/// `<style>` block's rules are spliced in at ITS position. That
/// ordering match matters: real CSS cascade tie-breaking is by
/// SOURCE order, so a `<link>` and a `<style>` block need to interleave
/// correctly relative to each other, not have every external
/// stylesheet's rules appended after every inline one regardless of
/// which the page actually wrote first.
///
/// This crate has no way to fetch anything itself (no network
/// dependency at all — see this crate's own design) — `external_css`
/// is expected to already hold the result of a caller (in practice,
/// `renderer::stylesheets::resolve_and_fetch_stylesheets`) resolving
/// and fetching each `<link>`'s `href` through the real, blocklist-
/// checking, cache-aware fetch path every other subresource uses. A
/// `<link>` whose id isn't in the map (not yet fetched, blocked as a
/// third-party tracker stylesheet, or the fetch/decode simply failed)
/// contributes nothing, matching this crate's established "missing
/// input degrades silently" philosophy elsewhere (see `<img>`'s own
/// failure handling in `layout`/`renderer::images`).
pub fn extract_author_stylesheet_with_external(
    document: &NodeRef,
    external_css: &HashMap<dom::NodeId, String>,
) -> Stylesheet {
    let mut combined = Stylesheet::default();
    collect_style_blocks(document, external_css, &mut combined);
    combined
}

fn collect_style_blocks(
    node: &NodeRef,
    external_css: &HashMap<dom::NodeId, String>,
    combined: &mut Stylesheet,
) {
    let (id, is_style, is_stylesheet_link, children) = {
        let node_ref = node.borrow();
        match &node_ref.node_type {
            NodeType::Element(el) if el.tag_name == "style" => {
                (node_ref.id, true, false, node_ref.children.clone())
            }
            NodeType::Element(el) if el.tag_name == "link" && is_stylesheet_rel(el) => {
                (node_ref.id, false, true, node_ref.children.clone())
            }
            _ => (node_ref.id, false, false, node_ref.children.clone()),
        }
    };
    if is_style {
        // A <style> element's own children are its CSS source text,
        // never further markup to recurse into — same treatment
        // `renderer::script`'s `extract_scripts` gives a `<script>`
        // element's children.
        combined.extend(parse_stylesheet(&style_text_content(node)));
        return;
    }
    if is_stylesheet_link {
        if let Some(css_text) = external_css.get(&id) {
            combined.extend(parse_stylesheet(css_text));
        }
        // A <link> is a void element with no real children either
        // way, but there's nothing to recurse into regardless.
        return;
    }
    for child in &children {
        collect_style_blocks(child, external_css, combined);
    }
}

/// Whether a `<link>` element's `rel` attribute names it as a
/// stylesheet — real HTML lets `rel` hold a space-separated list of
/// tokens (`rel="preload stylesheet"` is valid, if unusual), so this
/// checks token membership rather than exact equality; matching is
/// case-insensitive, matching real HTML's own `rel` keyword handling.
fn is_stylesheet_rel(el: &dom::Element) -> bool {
    el.attributes.get("rel").is_some_and(|rel| {
        rel.split_whitespace()
            .any(|tok| tok.eq_ignore_ascii_case("stylesheet"))
    }) && el.attributes.contains_key("href")
}

/// Concatenates every descendant TEXT node's data, depth-first — the
/// same real `textContent` semantics `renderer::script`'s own
/// (separate, JS-facing) `text_content` helper implements; duplicated
/// rather than shared across crates for a handful of lines that don't
/// warrant a new cross-crate dependency.
fn style_text_content(node: &NodeRef) -> String {
    let (text_value, children) = {
        let node_ref = node.borrow();
        match &node_ref.node_type {
            NodeType::Text(t) => (Some(t.clone()), Vec::new()),
            _ => (None, node_ref.children.clone()),
        }
    };
    match text_value {
        Some(t) => t,
        None => children
            .iter()
            .map(style_text_content)
            .collect::<Vec<_>>()
            .join(""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_simple_rule() {
        let sheet = parse_stylesheet("p { color: red; font-size: 12px; }");
        assert_eq!(sheet.rules.len(), 1);
        assert_eq!(sheet.rules[0].declarations.len(), 2);
    }

    #[test]
    fn theme_as_str_and_parse_round_trip() {
        assert_eq!(Theme::parse(Theme::Dark.as_str()), Some(Theme::Dark));
        assert_eq!(Theme::parse(Theme::Light.as_str()), Some(Theme::Light));
        assert_eq!(Theme::parse("sepia"), None);
    }

    #[test]
    fn theme_defaults_to_dark() {
        assert_eq!(Theme::default(), Theme::Dark);
    }

    #[test]
    fn author_rules_override_user_agent_rules_after_extend() {
        let mut sheet = user_agent_stylesheet(Theme::Dark);
        sheet.extend(parse_stylesheet("p { color: #ff0000; }"));

        let document = dom::Node::new_document();
        let p = dom::Node::new_element("p");
        dom::append_child(&document, p.clone());

        let style = compute_style(&p, &sheet, None);
        assert_eq!(
            style.properties.get("color").map(String::as_str),
            Some("#ff0000")
        );
    }

    #[test]
    fn display_defaults_to_block_when_unset() {
        let style = ComputedStyle::default();
        assert_eq!(style.display(), Display::Block);
    }

    #[test]
    fn position_defaults_to_static_and_parses_every_recognized_value() {
        assert_eq!(style_from("").position(), Position::Static);
        assert_eq!(
            style_from("position: relative;").position(),
            Position::Relative
        );
        assert_eq!(
            style_from("position: absolute;").position(),
            Position::Absolute
        );
        assert_eq!(style_from("position: fixed;").position(), Position::Fixed);
        assert_eq!(
            style_from("position: sticky;").position(),
            Position::Static,
            "an unrecognized value (sticky isn't implemented) should fall back to static"
        );
    }

    #[test]
    fn top_right_bottom_left_parse_as_px_lengths() {
        let style = style_from("top: 10px; right: 20px; bottom: 30px; left: 40px;");
        assert_eq!(style.top(), Some(10.0));
        assert_eq!(style.right(), Some(20.0));
        assert_eq!(style.bottom(), Some(30.0));
        assert_eq!(style.left(), Some(40.0));
    }

    #[test]
    fn top_right_bottom_left_default_to_none_when_unset_or_auto() {
        assert_eq!(style_from("").top(), None);
        assert_eq!(style_from("top: auto;").top(), None);
    }

    #[test]
    fn float_defaults_to_none_and_parses_left_and_right() {
        assert_eq!(style_from("").float(), Float::None);
        assert_eq!(style_from("float: left;").float(), Float::Left);
        assert_eq!(style_from("float: right;").float(), Float::Right);
    }

    #[test]
    fn clear_defaults_to_none_and_parses_every_recognized_value() {
        assert_eq!(style_from("").clear(), Clear::None);
        assert_eq!(style_from("clear: left;").clear(), Clear::Left);
        assert_eq!(style_from("clear: right;").clear(), Clear::Right);
        assert_eq!(style_from("clear: both;").clear(), Clear::Both);
    }

    #[test]
    fn user_agent_stylesheet_hides_head_and_script_content() {
        let sheet = user_agent_stylesheet(Theme::Dark);

        let document = dom::Node::new_document();
        let script = dom::Node::new_element("script");
        dom::append_child(&document, script.clone());

        let style = compute_style(&script, &sheet, None);
        assert_eq!(style.display(), Display::None);
    }

    #[test]
    fn user_agent_stylesheet_makes_anchors_and_spans_inline() {
        let sheet = user_agent_stylesheet(Theme::Dark);

        let document = dom::Node::new_document();
        let a = dom::Node::new_element("a");
        dom::append_child(&document, a.clone());

        let style = compute_style(&a, &sheet, None);
        assert_eq!(style.display(), Display::Inline);
    }

    #[test]
    fn user_agent_stylesheet_gives_input_a_real_default_box() {
        let sheet = user_agent_stylesheet(Theme::Dark);
        let document = dom::Node::new_document();
        let input = dom::Node::new_element("input");
        dom::append_child(&document, input.clone());

        let style = compute_style(&input, &sheet, None);
        assert_eq!(style.display(), Display::Inline);
        assert_eq!(
            style.properties.get("width").map(String::as_str),
            Some("150px")
        );
        assert_eq!(
            style.properties.get("height").map(String::as_str),
            Some("22px")
        );
        assert!(style.properties.contains_key("border"));
        assert_eq!(
            style.properties.get("background-color").map(String::as_str),
            Some(Theme::Dark.input_background_hex())
        );
    }

    #[test]
    fn checkbox_and_radio_inputs_get_a_small_square_box_not_the_text_input_default() {
        let sheet = user_agent_stylesheet(Theme::Dark);
        let document = dom::Node::new_document();

        let checkbox = dom::Node::new_element("input");
        set_attr(&checkbox, "type", "checkbox");
        dom::append_child(&document, checkbox.clone());

        let radio = dom::Node::new_element("input");
        set_attr(&radio, "type", "radio");
        dom::append_child(&document, radio.clone());

        for el in [&checkbox, &radio] {
            let style = compute_style(el, &sheet, None);
            assert_eq!(
                style.properties.get("width").map(String::as_str),
                Some("16px"),
                "should override the generic 150px text-input default"
            );
            assert_eq!(
                style.properties.get("height").map(String::as_str),
                Some("16px")
            );
            assert_eq!(
                style.properties.get("padding").map(String::as_str),
                Some("0")
            );
            // Border/background/color should still come through from
            // the generic `input` rule, untouched by the more specific
            // one — proving this is a real per-property cascade merge,
            // not one rule wholesale replacing the other.
            assert!(style.properties.contains_key("border"));
            assert_eq!(
                style.properties.get("background-color").map(String::as_str),
                Some(Theme::Dark.input_background_hex())
            );
        }
    }

    #[test]
    fn author_stylesheet_can_override_the_user_agent_display_default() {
        let mut sheet = user_agent_stylesheet(Theme::Dark);
        sheet.extend(parse_stylesheet("a { display: block; }"));

        let document = dom::Node::new_document();
        let a = dom::Node::new_element("a");
        dom::append_child(&document, a.clone());

        let style = compute_style(&a, &sheet, None);
        assert_eq!(style.display(), Display::Block);
    }

    #[test]
    fn higher_specificity_wins_regardless_of_source_order() {
        // A class selector (specificity 0,1,0) appears BEFORE a tag
        // selector (0,0,1) in source order — without real specificity,
        // "last rule wins" would incorrectly let the tag selector win
        // just because it's later. Real specificity must let the
        // class selector win instead, matching real CSS.
        let sheet = parse_stylesheet(".highlight { color: #ff0000; } p { color: #00ff00; }");

        let document = dom::Node::new_document();
        let p = dom::Node::new_element("p");
        {
            let mut p_mut = p.borrow_mut();
            if let dom::NodeType::Element(el) = &mut p_mut.node_type {
                el.attributes
                    .insert("class".to_string(), "highlight".to_string());
            }
        }
        dom::append_child(&document, p.clone());

        let style = compute_style(&p, &sheet, None);
        assert_eq!(
            style.properties.get("color").map(String::as_str),
            Some("#ff0000")
        );
    }

    #[test]
    fn equal_specificity_falls_back_to_source_order() {
        let sheet = parse_stylesheet("p { color: #ff0000; } p { color: #00ff00; }");
        let document = dom::Node::new_document();
        let p = dom::Node::new_element("p");
        dom::append_child(&document, p.clone());

        let style = compute_style(&p, &sheet, None);
        assert_eq!(
            style.properties.get("color").map(String::as_str),
            Some("#00ff00"),
            "the later rule should win when specificity is tied"
        );
    }

    #[test]
    fn inheritable_property_falls_back_to_parent_when_unset() {
        let sheet = parse_stylesheet("html { color: #123456; }");
        let document = dom::Node::new_document();
        let html = dom::Node::new_element("html");
        dom::append_child(&document, html.clone());

        let html_style = compute_style(&html, &sheet, None);
        assert_eq!(
            html_style.properties.get("color").map(String::as_str),
            Some("#123456")
        );

        // <p> sets no color of its own — should inherit html's.
        let p = dom::Node::new_element("p");
        let p_style = compute_style(&p, &sheet, Some(&html_style));
        assert_eq!(
            p_style.properties.get("color").map(String::as_str),
            Some("#123456")
        );
    }

    #[test]
    fn an_unset_font_size_defaults_to_16px_at_the_root() {
        let div = dom::Node::new_element("div");
        let style = compute_style(&div, &Stylesheet::default(), None);
        assert_eq!(style.font_size(), 16.0);
    }

    #[test]
    fn a_px_font_size_is_used_as_is() {
        let sheet = parse_stylesheet("p { font-size: 24px; }");
        let p = dom::Node::new_element("p");
        let style = compute_style(&p, &sheet, None);
        assert_eq!(style.font_size(), 24.0);
    }

    #[test]
    fn an_em_font_size_multiplies_the_parents_resolved_size() {
        let sheet = parse_stylesheet("div { font-size: 20px; } span { font-size: 1.5em; }");
        let div = dom::Node::new_element("div");
        let div_style = compute_style(&div, &sheet, None);
        assert_eq!(div_style.font_size(), 20.0);

        let span = dom::Node::new_element("span");
        let span_style = compute_style(&span, &sheet, Some(&div_style));
        assert_eq!(span_style.font_size(), 30.0);
    }

    #[test]
    fn a_percent_font_size_is_a_percentage_of_the_parents_resolved_size() {
        let sheet = parse_stylesheet("div { font-size: 20px; } span { font-size: 50%; }");
        let div = dom::Node::new_element("div");
        let div_style = compute_style(&div, &sheet, None);

        let span = dom::Node::new_element("span");
        let span_style = compute_style(&span, &sheet, Some(&div_style));
        assert_eq!(span_style.font_size(), 10.0);
    }

    #[test]
    fn font_size_inherits_the_parents_resolved_pixel_value_when_unset() {
        let sheet = parse_stylesheet("div { font-size: 20px; }");
        let div = dom::Node::new_element("div");
        let div_style = compute_style(&div, &sheet, None);

        // <span> sets no font-size of its own at all.
        let span = dom::Node::new_element("span");
        let span_style = compute_style(&span, &sheet, Some(&div_style));
        assert_eq!(span_style.font_size(), 20.0);
    }

    #[test]
    fn nested_em_font_sizes_compound_against_each_resolved_ancestor() {
        // Real CSS: each `em` multiplies its OWN parent's already-
        // resolved size, so two nested 1.5em levels compound
        // (16 * 1.5 * 1.5 = 36), not both multiplying the same root.
        let sheet = parse_stylesheet("div { font-size: 1.5em; }");
        let outer = dom::Node::new_element("div");
        let outer_style = compute_style(&outer, &sheet, None);
        assert_eq!(outer_style.font_size(), 24.0);

        let inner = dom::Node::new_element("div");
        let inner_style = compute_style(&inner, &sheet, Some(&outer_style));
        assert_eq!(inner_style.font_size(), 36.0);
    }

    #[test]
    fn heading_tags_get_progressively_smaller_default_sizes() {
        let sheet = user_agent_stylesheet(Theme::Dark);
        let sizes: Vec<f32> = ["h1", "h2", "h3", "h4", "h5", "h6"]
            .iter()
            .map(|tag| {
                let node = dom::Node::new_element(tag);
                compute_style(&node, &sheet, None).font_size()
            })
            .collect();
        for window in sizes.windows(2) {
            assert!(
                window[0] > window[1],
                "expected strictly decreasing heading sizes, got {sizes:?}"
            );
        }
        assert_eq!(sizes[0], 32.0, "h1 should be 2em of the 16px default");
    }

    #[test]
    fn non_inherited_property_does_not_fall_back_to_parent() {
        let sheet = parse_stylesheet("div { background-color: #123456; }");
        let document = dom::Node::new_document();
        let div = dom::Node::new_element("div");
        dom::append_child(&document, div.clone());
        let div_style = compute_style(&div, &sheet, None);

        let p = dom::Node::new_element("p");
        let p_style = compute_style(&p, &sheet, Some(&div_style));
        assert_eq!(
            p_style.properties.get("background-color"),
            None,
            "background-color must not inherit"
        );
    }

    #[test]
    fn a_nodes_own_value_wins_over_an_inherited_one() {
        let sheet = parse_stylesheet("html { color: #123456; } p { color: #abcdef; }");
        let document = dom::Node::new_document();
        let html = dom::Node::new_element("html");
        dom::append_child(&document, html.clone());
        let html_style = compute_style(&html, &sheet, None);

        let p = dom::Node::new_element("p");
        let p_style = compute_style(&p, &sheet, Some(&html_style));
        assert_eq!(
            p_style.properties.get("color").map(String::as_str),
            Some("#abcdef")
        );
    }

    fn style_from(css_text: &str) -> ComputedStyle {
        let mut properties = HashMap::new();
        for decl in parse_declarations(css_text) {
            properties.insert(decl.property, decl.value);
        }
        ComputedStyle { properties }
    }

    #[test]
    fn display_parses_flex_and_grid() {
        assert_eq!(style_from("display: flex;").display(), Display::Flex);
        assert_eq!(style_from("display: grid;").display(), Display::Grid);
    }

    #[test]
    fn flex_direction_defaults_to_row() {
        assert_eq!(style_from("").flex_direction(), FlexDirection::Row);
        assert_eq!(
            style_from("flex-direction: column;").flex_direction(),
            FlexDirection::Column
        );
        assert_eq!(
            style_from("flex-direction: row;").flex_direction(),
            FlexDirection::Row
        );
    }

    #[test]
    fn flex_wrap_defaults_to_nowrap() {
        assert_eq!(style_from("").flex_wrap(), FlexWrap::NoWrap);
        assert_eq!(style_from("flex-wrap: wrap;").flex_wrap(), FlexWrap::Wrap);
    }

    #[test]
    fn justify_content_and_align_items_parse_all_recognized_values() {
        assert_eq!(
            style_from("justify-content: center;").justify_content(),
            JustifyContent::Center
        );
        assert_eq!(
            style_from("justify-content: flex-end;").justify_content(),
            JustifyContent::FlexEnd
        );
        assert_eq!(
            style_from("justify-content: space-between;").justify_content(),
            JustifyContent::SpaceBetween
        );
        assert_eq!(
            style_from("justify-content: space-around;").justify_content(),
            JustifyContent::SpaceAround
        );
        assert_eq!(style_from("").justify_content(), JustifyContent::FlexStart);

        assert_eq!(
            style_from("align-items: center;").align_items(),
            AlignItems::Center
        );
        assert_eq!(
            style_from("align-items: flex-start;").align_items(),
            AlignItems::FlexStart
        );
        assert_eq!(
            style_from("align-items: flex-end;").align_items(),
            AlignItems::FlexEnd
        );
    }

    #[test]
    fn align_items_defaults_to_stretch_not_flex_start() {
        // The real CSS default — easy to get wrong by copying
        // `justify-content`'s own flex-start default.
        assert_eq!(style_from("").align_items(), AlignItems::Stretch);
    }

    #[test]
    fn flex_grow_shrink_and_basis_parse_with_real_defaults() {
        let default = style_from("");
        assert_eq!(default.flex_grow(), 0.0, "real CSS default: don't grow");
        assert_eq!(
            default.flex_shrink(),
            1.0,
            "real CSS default: shrink is on by default"
        );
        assert_eq!(default.flex_basis(), None, "real CSS default: auto");

        let set = style_from("flex-grow: 2; flex-shrink: 0.5; flex-basis: 100px;");
        assert_eq!(set.flex_grow(), 2.0);
        assert_eq!(set.flex_shrink(), 0.5);
        assert_eq!(set.flex_basis(), Some(100.0));

        assert_eq!(style_from("flex-basis: auto;").flex_basis(), None);
    }

    #[test]
    fn negative_grow_and_shrink_clamp_to_zero() {
        assert_eq!(style_from("flex-grow: -5;").flex_grow(), 0.0);
        assert_eq!(style_from("flex-shrink: -5;").flex_shrink(), 0.0);
    }

    #[test]
    fn gap_shorthand_sets_both_axes_and_longhands_override_it() {
        let both = style_from("gap: 10px;");
        assert_eq!(both.row_gap(), 10.0);
        assert_eq!(both.column_gap(), 10.0);

        let two_value = style_from("gap: 10px 20px;");
        assert_eq!(two_value.row_gap(), 10.0);
        assert_eq!(two_value.column_gap(), 20.0);

        let overridden = style_from("gap: 10px; column-gap: 30px;");
        assert_eq!(
            overridden.row_gap(),
            10.0,
            "row-gap should still come from the shorthand"
        );
        assert_eq!(
            overridden.column_gap(),
            30.0,
            "the longhand should win over the shorthand"
        );
    }

    #[test]
    fn grid_template_columns_parses_fixed_and_fr_tracks() {
        let style = style_from("grid-template-columns: 100px 1fr 2fr;");
        assert_eq!(
            style.grid_template_columns(),
            vec![
                GridTrack::Fixed(100.0),
                GridTrack::Fraction(1.0),
                GridTrack::Fraction(2.0)
            ]
        );
    }

    #[test]
    fn grid_template_columns_expands_repeat_of_a_single_track() {
        let style = style_from("grid-template-columns: repeat(3, 1fr);");
        assert_eq!(
            style.grid_template_columns(),
            vec![GridTrack::Fraction(1.0); 3]
        );
    }

    #[test]
    fn grid_template_columns_expands_repeat_of_a_multi_track_pattern() {
        let style = style_from("grid-template-columns: repeat(2, 100px 1fr);");
        assert_eq!(
            style.grid_template_columns(),
            vec![
                GridTrack::Fixed(100.0),
                GridTrack::Fraction(1.0),
                GridTrack::Fixed(100.0),
                GridTrack::Fraction(1.0)
            ]
        );
    }

    #[test]
    fn grid_template_columns_mixes_repeat_with_ordinary_tracks() {
        let style = style_from("grid-template-columns: 50px repeat(2, 1fr) 50px;");
        assert_eq!(
            style.grid_template_columns(),
            vec![
                GridTrack::Fixed(50.0),
                GridTrack::Fraction(1.0),
                GridTrack::Fraction(1.0),
                GridTrack::Fixed(50.0)
            ]
        );
    }

    #[test]
    fn grid_template_areas_parses_quoted_rows_into_a_token_grid() {
        let style = style_from(r#"grid-template-areas: "header header" "sidebar content";"#);
        assert_eq!(
            style.grid_template_areas(),
            vec![
                vec!["header".to_string(), "header".to_string()],
                vec!["sidebar".to_string(), "content".to_string()],
            ]
        );
    }

    #[test]
    fn grid_template_areas_defaults_to_empty_when_unset() {
        assert_eq!(
            style_from("").grid_template_areas(),
            Vec::<Vec<String>>::new()
        );
    }

    #[test]
    fn grid_area_reads_a_simple_name_but_not_numeric_or_slash_forms() {
        assert_eq!(
            style_from("grid-area: header;").grid_area(),
            Some("header".to_string())
        );
        assert_eq!(style_from("grid-area: 1 / 2 / 3 / 4;").grid_area(), None);
        assert_eq!(style_from("grid-area: 2;").grid_area(), None);
        assert_eq!(style_from("").grid_area(), None);
    }

    #[test]
    fn grid_column_and_row_span_read_the_span_keyword_form() {
        assert_eq!(style_from("grid-column: span 2;").grid_column_span(), 2);
        assert_eq!(style_from("grid-row: span 3;").grid_row_span(), 3);
        assert_eq!(
            style_from("").grid_column_span(),
            1,
            "unset defaults to no span"
        );
        assert_eq!(
            style_from("grid-column: 2;").grid_column_span(),
            1,
            "a bare line number isn't implemented, falls back to 1"
        );
    }

    #[test]
    fn grid_template_rows_defaults_to_empty_when_unset() {
        assert_eq!(style_from("").grid_template_rows(), Vec::new());
    }

    #[test]
    fn extract_author_stylesheet_reads_a_style_blocks_rules() {
        let document = dom::Node::new_document();
        let style = dom::Node::new_element("style");
        dom::append_child(&style, dom::Node::new_text("p { color: #ff0000; }"));
        dom::append_child(&document, style);

        let sheet = extract_author_stylesheet(&document);
        let p = dom::Node::new_element("p");
        let computed = compute_style(&p, &sheet, None);
        assert_eq!(
            computed.properties.get("color").map(String::as_str),
            Some("#ff0000")
        );
    }

    #[test]
    fn extract_author_stylesheet_combines_multiple_style_blocks_in_document_order() {
        let document = dom::Node::new_document();
        let first = dom::Node::new_element("style");
        dom::append_child(&first, dom::Node::new_text("p { color: #111111; }"));
        let second = dom::Node::new_element("style");
        dom::append_child(&second, dom::Node::new_text("p { color: #222222; }"));
        dom::append_child(&document, first);
        dom::append_child(&document, second);

        let sheet = extract_author_stylesheet(&document);
        let p = dom::Node::new_element("p");
        let computed = compute_style(&p, &sheet, None);
        assert_eq!(
            computed.properties.get("color").map(String::as_str),
            Some("#222222"),
            "the later <style> block should win ties, matching real cascade source-order behavior"
        );
    }

    #[test]
    fn extract_author_stylesheet_returns_empty_when_the_page_has_no_style_block() {
        let document = dom::Node::new_document();
        let p = dom::Node::new_element("p");
        dom::append_child(&document, p);

        let sheet = extract_author_stylesheet(&document);
        assert!(sheet.rules.is_empty());
    }

    #[test]
    fn author_stylesheet_extends_after_user_agent_so_author_rules_win() {
        let document = dom::Node::new_document();
        let style = dom::Node::new_element("style");
        dom::append_child(&style, dom::Node::new_text("a { display: block; }"));
        dom::append_child(&document, style);

        let mut sheet = user_agent_stylesheet(Theme::Dark);
        sheet.extend(extract_author_stylesheet(&document));

        let a = dom::Node::new_element("a");
        let computed = compute_style(&a, &sheet, None);
        assert_eq!(
            computed.display(),
            Display::Block,
            "the page's own <style> block should override the UA default (inline)"
        );
    }

    fn element_with_style(style: &str) -> NodeRef {
        let el = dom::Node::new_element("div");
        if let dom::NodeType::Element(e) = &mut el.borrow_mut().node_type {
            e.attributes.insert("style".to_string(), style.to_string());
        }
        el
    }

    #[test]
    fn inline_style_attribute_applies_even_with_no_stylesheet_at_all() {
        let div = element_with_style("color: #ff0000;");
        let computed = compute_style(&div, &Stylesheet::default(), None);
        assert_eq!(
            computed.properties.get("color").map(String::as_str),
            Some("#ff0000")
        );
    }

    #[test]
    fn inline_style_attribute_beats_a_matching_class_selector() {
        let sheet = parse_stylesheet(".red { color: #ff0000; }");
        let div = element_with_style("color: #00ff00;");
        if let dom::NodeType::Element(el) = &mut div.borrow_mut().node_type {
            el.attributes.insert("class".to_string(), "red".to_string());
        }

        let computed = compute_style(&div, &sheet, None);
        assert_eq!(
            computed.properties.get("color").map(String::as_str),
            Some("#00ff00"),
            "an inline style must beat a selector-based rule regardless of specificity"
        );
    }

    #[test]
    fn inline_style_attribute_sets_display_flex() {
        let div = element_with_style("display: flex; justify-content: center;");
        let computed = compute_style(&div, &Stylesheet::default(), None);
        assert_eq!(computed.display(), Display::Flex);
        assert_eq!(computed.justify_content(), JustifyContent::Center);
    }

    #[test]
    fn a_missing_style_attribute_is_a_harmless_no_op() {
        let div = dom::Node::new_element("div");
        let computed = compute_style(&div, &Stylesheet::default(), None);
        // `font-size` is always resolved (see `resolve_font_size`'s own
        // doc comment — even an unstyled root node bottoms out at
        // `DEFAULT_FONT_SIZE_PX`), so it's the one property present
        // even with no stylesheet and no `style="..."` attribute at
        // all; nothing else should be.
        assert_eq!(computed.properties.len(), 1);
        assert_eq!(computed.font_size(), 16.0);
    }

    fn set_attr(node: &NodeRef, name: &str, value: &str) {
        if let dom::NodeType::Element(el) = &mut node.borrow_mut().node_type {
            el.attributes.insert(name.to_string(), value.to_string());
        }
    }

    #[test]
    fn id_selector_matches_only_the_element_with_that_id() {
        let sheet = parse_stylesheet("#hero { color: #ff0000; }");
        let document = dom::Node::new_document();
        let div = dom::Node::new_element("div");
        set_attr(&div, "id", "hero");
        dom::append_child(&document, div.clone());
        let other = dom::Node::new_element("div");
        set_attr(&other, "id", "not-hero");
        dom::append_child(&document, other.clone());

        assert_eq!(
            compute_style(&div, &sheet, None).properties.get("color"),
            Some(&"#ff0000".to_string())
        );
        assert_eq!(
            compute_style(&other, &sheet, None).properties.get("color"),
            None
        );
    }

    #[test]
    fn id_selector_outweighs_class_and_type_in_specificity() {
        let sheet = parse_stylesheet(
            "div { color: #000000; } .highlight { color: #00ff00; } #hero { color: #ff0000; }",
        );
        let document = dom::Node::new_document();
        let div = dom::Node::new_element("div");
        set_attr(&div, "id", "hero");
        set_attr(&div, "class", "highlight");
        dom::append_child(&document, div.clone());

        assert_eq!(
            compute_style(&div, &sheet, None).properties.get("color"),
            Some(&"#ff0000".to_string())
        );
    }

    #[test]
    fn universal_selector_matches_every_element() {
        let sheet = parse_stylesheet("* { margin: 0; }");
        let document = dom::Node::new_document();
        let p = dom::Node::new_element("p");
        dom::append_child(&document, p.clone());
        assert_eq!(
            compute_style(&p, &sheet, None).properties.get("margin"),
            Some(&"0".to_string())
        );
    }

    #[test]
    fn attribute_selectors_support_every_operator() {
        let div = dom::Node::new_element("div");
        set_attr(&div, "data-state", "foo bar baz");
        set_attr(&div, "lang", "en-US");

        assert!(parse_stylesheet("[data-state] { color: red; }")
            .rules
            .iter()
            .any(|r| selector_matches(&r.selector, &div)));
        assert!(parse_stylesheet("[data-state~=\"bar\"] { color: red; }")
            .rules
            .iter()
            .any(|r| selector_matches(&r.selector, &div)));
        assert!(parse_stylesheet("[lang|=\"en\"] { color: red; }")
            .rules
            .iter()
            .any(|r| selector_matches(&r.selector, &div)));
        assert!(parse_stylesheet("[data-state^=\"foo\"] { color: red; }")
            .rules
            .iter()
            .any(|r| selector_matches(&r.selector, &div)));
        assert!(parse_stylesheet("[data-state$=\"baz\"] { color: red; }")
            .rules
            .iter()
            .any(|r| selector_matches(&r.selector, &div)));
        assert!(parse_stylesheet("[data-state*=\"r ba\"] { color: red; }")
            .rules
            .iter()
            .any(|r| selector_matches(&r.selector, &div)));
        assert!(!parse_stylesheet("[data-state=\"nope\"] { color: red; }")
            .rules
            .iter()
            .any(|r| selector_matches(&r.selector, &div)));
    }

    #[test]
    fn selector_list_applies_the_same_declarations_to_every_selector() {
        let sheet = parse_stylesheet("h1, h2 { color: #ff0000; }");
        let document = dom::Node::new_document();
        let h1 = dom::Node::new_element("h1");
        let h2 = dom::Node::new_element("h2");
        let p = dom::Node::new_element("p");
        dom::append_child(&document, h1.clone());
        dom::append_child(&document, h2.clone());
        dom::append_child(&document, p.clone());

        assert_eq!(
            compute_style(&h1, &sheet, None).properties.get("color"),
            Some(&"#ff0000".to_string())
        );
        assert_eq!(
            compute_style(&h2, &sheet, None).properties.get("color"),
            Some(&"#ff0000".to_string())
        );
        assert_eq!(
            compute_style(&p, &sheet, None).properties.get("color"),
            None
        );
    }

    fn tree_with(parent_tag: &str, child_tags: &[&str]) -> (NodeRef, Vec<NodeRef>) {
        let parent = dom::Node::new_element(parent_tag);
        let mut children = Vec::new();
        for tag in child_tags {
            let child = dom::Node::new_element(tag);
            dom::append_child(&parent, child.clone());
            children.push(child);
        }
        (parent, children)
    }

    #[test]
    fn descendant_combinator_matches_at_any_depth() {
        let sheet = parse_stylesheet("nav a { color: #ff0000; }");
        let document = dom::Node::new_document();
        let nav = dom::Node::new_element("nav");
        let ul = dom::Node::new_element("ul");
        let a = dom::Node::new_element("a");
        dom::append_child(&ul, a.clone());
        dom::append_child(&nav, ul);
        dom::append_child(&document, nav);

        assert!(sheet
            .rules
            .iter()
            .any(|r| selector_matches(&r.selector, &a)));
    }

    #[test]
    fn child_combinator_does_not_match_a_grandchild() {
        let sheet = parse_stylesheet("nav > a { color: #ff0000; }");
        let nav = dom::Node::new_element("nav");
        let ul = dom::Node::new_element("ul");
        let a = dom::Node::new_element("a");
        dom::append_child(&ul, a.clone());
        dom::append_child(&nav, ul.clone());

        assert!(!sheet
            .rules
            .iter()
            .any(|r| selector_matches(&r.selector, &a)));

        let direct_a = dom::Node::new_element("a");
        dom::append_child(&nav, direct_a.clone());
        assert!(sheet
            .rules
            .iter()
            .any(|r| selector_matches(&r.selector, &direct_a)));
    }

    #[test]
    fn adjacent_sibling_combinator_matches_only_the_immediately_next_element() {
        let sheet = parse_stylesheet("h1 + p { color: #ff0000; }");
        let (_parent, children) = tree_with("article", &["h1", "p", "p"]);
        assert!(sheet
            .rules
            .iter()
            .any(|r| selector_matches(&r.selector, &children[1])));
        assert!(!sheet
            .rules
            .iter()
            .any(|r| selector_matches(&r.selector, &children[2])));
    }

    #[test]
    fn general_sibling_combinator_matches_any_later_sibling() {
        let sheet = parse_stylesheet("h1 ~ p { color: #ff0000; }");
        let (_parent, children) = tree_with("article", &["h1", "span", "p"]);
        assert!(sheet
            .rules
            .iter()
            .any(|r| selector_matches(&r.selector, &children[2])));
    }

    #[test]
    fn first_and_last_child_pseudo_classes() {
        let sheet =
            parse_stylesheet("li:first-child { color: #f00; } li:last-child { color: #0f0; }");
        let (_parent, children) = tree_with("ul", &["li", "li", "li"]);

        assert_eq!(
            compute_style(&children[0], &sheet, None)
                .properties
                .get("color"),
            Some(&"#f00".to_string())
        );
        assert_eq!(
            compute_style(&children[2], &sheet, None)
                .properties
                .get("color"),
            Some(&"#0f0".to_string())
        );
        assert_eq!(
            compute_style(&children[1], &sheet, None)
                .properties
                .get("color"),
            None
        );
    }

    #[test]
    fn only_child_matches_a_lone_element_only() {
        let sheet = parse_stylesheet("li:only-child { color: #f00; }");
        let (_solo_parent, solo) = tree_with("ul", &["li"]);
        let (_multi_parent, multi) = tree_with("ul", &["li", "li"]);

        assert_eq!(
            compute_style(&solo[0], &sheet, None)
                .properties
                .get("color"),
            Some(&"#f00".to_string())
        );
        assert_eq!(
            compute_style(&multi[0], &sheet, None)
                .properties
                .get("color"),
            None
        );
    }

    #[test]
    fn nth_child_matches_odd_even_and_an_plus_b() {
        let sheet = parse_stylesheet("li:nth-child(odd) { color: #f00; }");
        let (_parent, children) = tree_with("ul", &["li", "li", "li", "li"]);
        assert_eq!(
            compute_style(&children[0], &sheet, None)
                .properties
                .get("color"),
            Some(&"#f00".to_string()),
            "1st child is odd"
        );
        assert_eq!(
            compute_style(&children[1], &sheet, None)
                .properties
                .get("color"),
            None,
            "2nd child is even"
        );
        assert_eq!(
            compute_style(&children[2], &sheet, None)
                .properties
                .get("color"),
            Some(&"#f00".to_string()),
            "3rd child is odd"
        );

        let sheet2 = parse_stylesheet("li:nth-child(2n+1) { color: #f00; }");
        assert_eq!(
            compute_style(&children[0], &sheet2, None)
                .properties
                .get("color"),
            Some(&"#f00".to_string())
        );
    }

    #[test]
    fn nth_of_type_counts_only_matching_tag_siblings() {
        let sheet = parse_stylesheet("p:nth-of-type(2) { color: #f00; }");
        let parent = dom::Node::new_element("div");
        let h1 = dom::Node::new_element("h1");
        let p1 = dom::Node::new_element("p");
        let p2 = dom::Node::new_element("p");
        dom::append_child(&parent, h1);
        dom::append_child(&parent, p1.clone());
        dom::append_child(&parent, p2.clone());

        assert_eq!(
            compute_style(&p1, &sheet, None).properties.get("color"),
            None,
            "p1 is the FIRST p, not the second"
        );
        assert_eq!(
            compute_style(&p2, &sheet, None).properties.get("color"),
            Some(&"#f00".to_string()),
            "p2 is the second p sibling, ignoring the h1"
        );
    }

    #[test]
    fn not_pseudo_class_excludes_a_matching_element() {
        let sheet = parse_stylesheet("li:not(.skip) { color: #f00; }");
        let (_parent, children) = tree_with("ul", &["li", "li"]);
        set_attr(&children[1], "class", "skip");

        assert_eq!(
            compute_style(&children[0], &sheet, None)
                .properties
                .get("color"),
            Some(&"#f00".to_string())
        );
        assert_eq!(
            compute_style(&children[1], &sheet, None)
                .properties
                .get("color"),
            None
        );
    }

    #[test]
    fn not_pseudo_class_specificity_is_its_argument_not_free() {
        let sheet = parse_stylesheet("li { color: #000; } li:not(#special) { color: #f00; }");
        let document = dom::Node::new_document();
        let li = dom::Node::new_element("li");
        set_attr(&li, "id", "special");
        dom::append_child(&document, li.clone());

        // `li:not(#special)` doesn't even match `li#special` (it's
        // excluded by the `:not`), so plain `li` should win here —
        // this only proves the parse+match succeeds and doesn't panic
        // on an id-bearing `:not()` argument; the specificity math
        // itself is exercised via `Selector::specificity` directly
        // below in the same test for clarity.
        assert_eq!(
            compute_style(&li, &sheet, None).properties.get("color"),
            Some(&"#000".to_string())
        );

        // `:not(#special)` contributes its argument's specificity (an
        // id, here) on top of `li`'s own type specificity — the same
        // total `li#special` (no negation at all) would produce.
        let with_not = parse_selector("li:not(#special)").unwrap();
        let equivalent = parse_selector("li#special").unwrap();
        assert_eq!(with_not.specificity(), equivalent.specificity());
    }

    #[test]
    fn root_pseudo_class_matches_only_the_document_element() {
        let sheet = parse_stylesheet(":root { color: #f00; }");
        let document = dom::Node::new_document();
        let html = dom::Node::new_element("html");
        let body = dom::Node::new_element("body");
        dom::append_child(&html, body.clone());
        dom::append_child(&document, html.clone());

        assert_eq!(
            compute_style(&html, &sheet, None).properties.get("color"),
            Some(&"#f00".to_string())
        );
        assert_eq!(
            compute_style(&body, &sheet, None).properties.get("color"),
            None
        );
    }

    #[test]
    fn empty_pseudo_class_matches_only_childless_elements() {
        let sheet = parse_stylesheet("div:empty { color: #f00; }");
        let document = dom::Node::new_document();
        let empty_div = dom::Node::new_element("div");
        let full_div = dom::Node::new_element("div");
        dom::append_child(&full_div, dom::Node::new_text("hi"));
        dom::append_child(&document, empty_div.clone());
        dom::append_child(&document, full_div.clone());

        assert_eq!(
            compute_style(&empty_div, &sheet, None)
                .properties
                .get("color"),
            Some(&"#f00".to_string())
        );
        assert_eq!(
            compute_style(&full_div, &sheet, None)
                .properties
                .get("color"),
            None
        );
    }

    #[test]
    fn link_pseudo_class_matches_any_anchor_with_href_regardless_of_visit_state() {
        let sheet = parse_stylesheet("a:link { color: #f00; }");
        let with_href = dom::Node::new_element("a");
        set_attr(&with_href, "href", "https://example.com");
        let without_href = dom::Node::new_element("a");

        assert!(sheet
            .rules
            .iter()
            .any(|r| selector_matches(&r.selector, &with_href)));
        assert!(!sheet
            .rules
            .iter()
            .any(|r| selector_matches(&r.selector, &without_href)));
    }

    #[test]
    fn hover_and_focus_parse_but_never_match() {
        let sheet = parse_stylesheet("a:hover { color: #f00; } input:focus { color: #0f0; }");
        assert_eq!(sheet.rules.len(), 2, "both should still parse");
        let a = dom::Node::new_element("a");
        let input = dom::Node::new_element("input");
        assert!(!sheet
            .rules
            .iter()
            .any(|r| selector_matches(&r.selector, &a)));
        assert!(!sheet
            .rules
            .iter()
            .any(|r| selector_matches(&r.selector, &input)));
    }

    #[test]
    fn pseudo_element_fails_to_parse_and_drops_the_rule() {
        let sheet = parse_stylesheet("p::before { content: \"x\"; } p { color: #f00; }");
        assert_eq!(
            sheet.rules.len(),
            1,
            "the ::before rule should be dropped, the plain p rule kept"
        );
    }

    #[test]
    fn compound_selector_combines_tag_class_and_id() {
        let sheet = parse_stylesheet("div.card#featured { color: #f00; }");
        let document = dom::Node::new_document();
        let div = dom::Node::new_element("div");
        set_attr(&div, "class", "card");
        set_attr(&div, "id", "featured");
        dom::append_child(&document, div.clone());

        assert_eq!(
            compute_style(&div, &sheet, None).properties.get("color"),
            Some(&"#f00".to_string())
        );

        set_attr(&div, "id", "other");
        assert_eq!(
            compute_style(&div, &sheet, None).properties.get("color"),
            None,
            "the id no longer matches, so the whole compound should fail"
        );
    }

    #[test]
    fn matches_reports_true_for_any_selector_in_a_comma_list() {
        let document = dom::Node::new_document();
        let p = dom::Node::new_element("p");
        set_attr(&p, "class", "highlight");
        dom::append_child(&document, p.clone());

        assert!(matches("div, .highlight, span", &p));
        assert!(!matches("div, span", &p));
    }

    #[test]
    fn matches_returns_false_for_an_unparseable_selector_rather_than_panicking() {
        let document = dom::Node::new_document();
        let p = dom::Node::new_element("p");
        dom::append_child(&document, p.clone());
        assert!(!matches("::before", &p));
    }
}
