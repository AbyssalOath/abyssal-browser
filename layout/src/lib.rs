//! `layout` — walks the DOM + computed styles and produces a box tree
//! with concrete geometry (x, y, width, height) that `render` can paint.
//!
//! Scope of this stub: normal-flow **block** layout, a real **inline
//! formatting context** for runs of inline-level content (see
//! `layout_inline_run`), real **inline text layout** for the leaf text
//! nodes (word-wrapping via the `text` crate, with real
//! line-count-based heights), and now real (if deliberately scoped —
//! see `flex`'s and `grid`'s own module docs) **`display: flex`** and
//! **`display: grid`** formatting contexts too. What's still missing:
//! tables and writing modes.
//!
//! **Floats** (`float: left`/`right`, `clear`): real now — a floated
//! child is pulled out of normal block flow (like `position: absolute`
//! — see below — it neither takes space nor participates in margin
//! collapsing) and placed flush against its side's edge of its
//! immediate container, and that SAME container's own direct inline
//! runs wrap their line boxes around it (`line_bounds`/`place_float`).
//! `float` auto-blockifies regardless of `display` (`is_inline_level`
//! special-cases it) — needed because the single most common
//! real-world floated element, `<img>`, is `display: inline` by
//! default in this crate's own UA stylesheet. Deliberately scoped:
//! floats only narrow their OWN immediate container's inline
//! content, not a nested block descendant's (a `<div><img
//! style="float:left"><p>text</p></div>` won't wrap `text` around the
//! image — only content that's a DIRECT sibling of the float, e.g.
//! `<p><img style="float:left">text</p>`, does); same-side floats
//! stack vertically rather than packing side-by-side when they'd both
//! fit on one row (see `place_float`'s own doc comment for why); and a
//! container implicitly contains its floats' full height unconditionally
//! (a deliberate, more-useful-by-default deviation from real CSS's
//! `overflow`/`display: flow-root`-gated containment, which exists
//! mainly to preserve a decades-old backwards-compatibility quirk this
//! crate has no reason to reproduce).
//!
//! **Positioning schemes** (`position: relative`/`absolute`/`fixed`):
//! real now too — see `apply_positioning`'s own doc comment for the
//! full design (a second pass run once over the finished tree,
//! walking the nearest-positioned-ancestor "containing block" down)
//! and for `fixed`'s one deliberately scoped-down piece (it anchors to
//! the page's own root, not a live, scroll-independent viewport — this
//! crate has no independent notion of viewport height at all to anchor
//! against otherwise). Scope, deliberately narrow: only a BLOCK-level
//! child can be taken out of flow this way today — one inside an
//! inline formatting context still consumes inline flow space, since
//! real-world absolute/fixed elements are overwhelmingly authored as
//! `display: block` in practice (dropdowns, modals, badges, banners).
//!
//! Sizing properties: real now — `width`/`min-width`/`max-width`
//! (length OR percentage, resolved against the containing block) and
//! `height`/`min-height`/`max-height` (length only — see
//! `box_model::resolve_height`'s doc comment for why percentage
//! height is deliberately never resolved) all override this crate's
//! otherwise-intrinsic/content-derived sizing, applied uniformly to
//! block boxes, flex/grid containers, AND replaced elements (`<img>`,
//! the one CSS-visible "replaced element" this crate has). Matching
//! real CSS, `width`/`height` have NO effect on a non-replaced INLINE
//! element (a `<span style="width: 200px">` still just shrinks to its
//! content, exactly as before) — see `layout_box`'s
//! `sizing_properties_apply` guard.
//!
//! How text height gets computed, since it's the trickiest part of
//! this crate: `build_layout_tree` stores each text node's *raw*
//! string (font size + inherited color) without wrapping it — wrapping
//! needs an available width, and no width is known until the
//! positioning pass. `layout()` (the positioning pass) does the actual
//! word-wrapping once it knows each box's available width, producing
//! a `PositionedLine` per wrapped line (text + its own absolute paint
//! position — see `TextContent`), and line count × `text::line_height`
//! is what determines a text box's height.
//!
//! Color used to be the one CSS property this crate special-cased as
//! "inherited," threading the nearest ancestor's `color` down to text
//! nodes by hand. That hack is gone: `css::compute_style` now does
//! real inheritance (see its module docs) for a curated list of
//! inheritable properties, `color` included. `build_layout_tree`
//! simply passes each element's own just-computed `ComputedStyle` as
//! the `parent_style` for its children, and a text node's `color`
//! comes out of calling `compute_style` on the text node itself
//! (which never matches a selector directly, so it always falls
//! through to whatever it inherited).
//!
//! Box model: every element box has real `margin`/`border`/`padding`,
//! parsed from `ComputedStyle` (see `box_model.rs`) and applied in
//! `layout_box` below. Scope, deliberately narrow:
//!   - `margin`/`padding` support the standard 1/2/3/4-value
//!     shorthand plus the four `*-top`/`*-right`/`*-bottom`/`*-left`
//!     longhands (longhands win over the shorthand, matching CSS).
//!   - `border` supports a single uniform width + color per box —
//!     `border-width`/`border-color` longhands, or a `border: <width>
//!     <style> <color>` shorthand (the style keyword, e.g. `solid`,
//!     is parsed but ignored — everything paints as a solid stroke).
//!     Per-side border widths/colors/styles are NOT supported yet.
//!   - Margin collapsing is real now, for both adjacent block siblings
//!     AND parent/first-child + parent/last-child (a box with no
//!     border/padding/intervening-line-box separating it from its
//!     first or last child merges margins with that child too, same
//!     as real CSS — see `effective_top_margin`/`effective_bottom_margin`
//!     and `layout_box`'s `is_root` parameter). Recurses through
//!     arbitrarily many levels of nested zero-border/padding boxes.
//!     Scope, deliberately narrow: a box with NO children at all still
//!     gets `DEFAULT_LINE_HEIGHT` real height in this stub (see that
//!     const's docs) rather than true CSS "empty box" zero height, so
//!     self-collapsing empty blocks (a real but rarer CSS behavior)
//!     don't apply here — same reasoning as a genuinely non-empty box
//!     blocking collapse in real CSS.
//!   - Text boxes (the anonymous boxes wrapping DOM text nodes) never
//!     carry their own margin/border/padding — only real elements do.
//!   - `box-sizing` is always `content-box`.
//!
//! `display`: real `display: none`/`inline`/(default)`block` support,
//! read from computed style (see `css::Display`) rather than a
//! hardcoded tag list — `css::user_agent_stylesheet` is what actually
//! assigns `display: none` to metadata/source tags and `display:
//! inline` to common inline elements (`a`, `span`, `em`, ...) by
//! default, the same way a real browser's UA stylesheet does. An
//! author stylesheet can freely override any of it.
//!
//! Inline layout (`layout_inline_run`): a maximal run of consecutive
//! inline-level siblings (text boxes and `display: inline` elements)
//! packs left-to-right and wraps into line boxes, instead of every
//! non-text element getting its own full-width row — and does so at
//! **word granularity**: a text box is split into individual words
//! (`flatten_inline_items`) that pack right up against a sibling
//! inline element and keep flowing on the same line, wrapping only
//! when something genuinely doesn't fit (e.g. `text <a>link</a> more
//! text` lets "more" continue right after the link, wrapping only the
//! words that actually run out of room). Word-splitting recurses into
//! nested inline elements too, arbitrarily deep — `flatten_inline_items`
//! tags every item with a `path` (a chain of child indices) rather
//! than a flat index, so a word three levels of inline nesting deep
//! wraps and flows exactly like one at the top level, and a nested
//! inline element's own `rect` ends up as the bounding box of
//! wherever its content landed (see `layout_inline_run`'s doc comment
//! for the one real caveat: an inline element that itself wraps across
//! more than one line gets a single bounding box spanning all of them,
//! not the several per-line fragments a real browser would generate).
//! Each wrapped line gets its own resolved position (`PositionedLine`)
//! rather than assuming every line of a text box starts at the same
//! x — the first line can start wherever it landed mid-run next to a
//! previous sibling, while later wrapped lines of the *same* text box
//! return to the container's left edge, same as a real paragraph
//! continuing after an inline aside. Scope, deliberately narrow — this
//! is a real inline formatting context but a simplified one:
//!   - Inline-level elements are shrink-to-fit sized (their width is
//!     their content's natural width, not the full container width —
//!     see `intrinsic_width`), matching real CSS's default inline
//!     sizing.
//!   - A word/element that doesn't fit even alone on an empty line is
//!     given the full line width anyway and allowed to wrap/overflow
//!     internally — the same tolerance `text::wrap_text` gives an
//!     overlong single word.
//!   - No anonymous block box synthesis: a run of block-level and
//!     inline-level siblings is simply processed as alternating
//!     block-stacked runs and inline-flowed runs in the order they
//!     appear, which produces the same visual result without needing
//!     to wrap the inline runs in a synthetic box in the tree.
//!   - A purely-whitespace text node between two sibling inline
//!     elements (e.g. the text node real HTML has between
//!     `<a>Login</a> <a>Register</a>` from the source-formatting
//!     space) becomes a collapsible `InlineItem::Space`, so two
//!     adjacent buttons/links still get a real gap even though
//!     neither is itself a `Word`. It collapses to nothing at a line
//!     edge, matching real CSS whitespace collapsing.
//!
//! Next steps, roughly in order of payoff:
//!   1. True per-line fragments for a nested inline element that wraps
//!      across more than one line (see the caveat above) instead of a
//!      single bounding box spanning all of them.
//!   2. Per-side border, `border-box` sizing. (Parent-child margin
//!      collapsing is now done too — see above.)
//!   3. Positioning schemes (relative/absolute/fixed), then floats.
//!      `flex`/`grid`'s own module docs each have their own further
//!      "next steps" beyond this crate-wide list.

mod box_model;
mod flex;
mod grid;

pub use box_model::EdgeSizes;
use box_model::{resolve_border, resolve_edges};

use css::{compute_style, ComputedStyle, Display, Stylesheet};
use dom::{NodeRef, NodeType};
use std::collections::HashMap;
use text::Font;

#[derive(Debug, Clone, Copy, Default, serde::Serialize, serde::Deserialize)]
pub struct Rect {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
}

/// One active `float: left`/`right` box within a single container's
/// block-stacking loop — its border-box `rect` (already placed) plus
/// which side it floated to, so `line_bounds` knows which edge to
/// narrow. See `layout_box`'s "Walk children" section for how these
/// get built up, and its own module docs for this feature's scope.
#[derive(Debug, Clone, Copy)]
struct FloatBox {
    side: css::Float,
    rect: Rect,
}

/// One box in the layout tree, with resolved geometry and a reference
/// back to the style that produced it (render needs both).
///
/// `rect` is the box's **border box**: it includes border and padding
/// but not margin — margin only ever affects *position* (it shifts
/// where the border box sits relative to its container), never the
/// box's own painted size. This matches how CSS defines the box model
/// and is why `render::paint` can fill `rect` directly for the
/// background/border without any extra margin math.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct LayoutBox {
    pub rect: Rect,
    pub style: ComputedStyle,
    pub node_type: NodeType,
    /// The live DOM node this box was built from (see `dom::NodeId`'s
    /// doc comment for why this is a monotonic id rather than a
    /// pointer/address-derived one). This is what lets `app` turn a
    /// click's pixel coordinates into "which DOM node was hit" (see
    /// `hit_test_node`) and hand that back to the renderer's live
    /// `script::Session` for event dispatch — without it, the ONLY
    /// thing crossing the IPC boundary would be this snapshot's own
    /// (cloned) `node_type`/`style`/`rect` data, with no way to refer
    /// back to the original node at all.
    pub dom_node_id: dom::NodeId,
    pub children: Vec<LayoutBox>,
    /// `Some` only for boxes built from a DOM text node. `raw` and
    /// `font_size`/`color_hex` are set at tree-construction time;
    /// `lines` is filled in later, during `layout()`, once an
    /// available width exists to wrap against.
    pub text: Option<TextContent>,
    /// `Some` only for an `<img>` element the renderer successfully
    /// fetched and decoded — see `build_layout_tree_with_images` (the
    /// entry point that can ever populate this; plain `build_layout_tree`
    /// never does) and `ImageContent`'s own doc comment for what's
    /// actually inside.
    pub image: Option<ImageContent>,
    /// `Some` only for a text-editable `<input>` element (see
    /// `is_text_like_input`) — populated by `build_layout_tree_inner`
    /// regardless of whether THIS input currently has focus (`cursor_x`
    /// is what actually varies with focus — see `TextInputContent`'s
    /// own doc comment). `render` paints this box's current value text
    /// (and cursor, if focused) the same way it paints an ordinary text
    /// box, just from a single resolved position rather than wrapped
    /// `PositionedLine`s — see `layout_box`'s `text_input` branch.
    pub text_input: Option<TextInputContent>,
    /// `Some` only for an `<input type="checkbox">`/`<input
    /// type="radio">` (see `checkable_kind`) — populated by
    /// `build_layout_tree_inner` from the element's current `checked`
    /// attribute, exactly like `text_input` is from `value`. `render`
    /// paints the widget's checked/unchecked appearance from this
    /// directly; no cursor/focus concept applies here at all (see
    /// `CheckableInputContent`'s own doc comment on why this is
    /// click-toggled, not typed into).
    pub checkable_input: Option<CheckableInputContent>,
    /// `Some` only for an `<audio>`/`<video>` element with real,
    /// decoded content behind it (see `MediaAsset`'s own doc comment
    /// on what "decoded" means here — no video FRAME decoding exists
    /// in this crate, only audio) — populated by
    /// `build_layout_tree_with_media`, the same "static content,
    /// dynamic state applied afterward" split `text_input` uses.
    /// `render` paints the poster (for `<video>`) and, if `controls`
    /// is set, a real play/pause/seek/mute control bar from this
    /// directly.
    pub media: Option<MediaContent>,
    /// `true` when this box's own DOM node is the one keyboard focus
    /// currently sits on — see `layout_with_focus`'s `focus` parameter.
    /// Unlike `TextInputContent::cursor_x` (only ever resolved for a
    /// text-editable `<input>`), this is set on ANY box whose node
    /// matches, regardless of content type: a focused link, button, or
    /// checkbox all get `focused: true` too, which is what lets
    /// `render::paint` draw a real, visible keyboard-focus ring around
    /// whatever's currently focused rather than only ever a text
    /// cursor. Always `false` for a plain `layout()`/`build_layout_tree`
    /// call (no `focus` argument at all) and for any box inside a flex/
    /// grid container, same documented scope limit `cursor_x` already
    /// has — see `layout_box`'s own doc comment on why.
    pub focused: bool,
    /// Margin, border, and padding widths for this box. Always zero
    /// for text boxes (see crate module docs) — only element boxes
    /// read these from computed style.
    pub margin: EdgeSizes,
    pub border: EdgeSizes,
    pub padding: EdgeSizes,
    /// Border stroke color, if a `border`/`border-color` property
    /// resolved to one. `None` means no border is painted, regardless
    /// of `border`'s widths (a border with zero width paints nothing
    /// anyway, but this also covers "color unset" cleanly).
    pub border_color: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct TextContent {
    pub raw: String,
    pub font_size: f32,
    pub color_hex: String,
    /// Resolved during layout (`layout_box`/`layout_inline_run`):
    /// each wrapped line's text plus its own absolute paint position.
    /// A per-line position (rather than a single box origin + fixed
    /// line height, like a naive uniform-left-margin paragraph) is
    /// what lets a text box's *first* line start wherever it landed
    /// mid-line next to a previous inline sibling, while its *later*
    /// wrapped lines return to the container's left edge — see
    /// `layout_inline_run`. Empty until `layout()` runs.
    pub lines: Vec<PositionedLine>,
}

/// One wrapped line of text, already positioned in absolute
/// coordinates by the layout pass. `render::paint_text` just draws
/// each one where it says, rather than assuming every line in a text
/// box starts at the same x.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PositionedLine {
    pub text: String,
    pub x: f32,
    pub y: f32,
}

/// A text-editable `<input>`'s current on-screen state — real single-
/// line text (no wrapping; a real text input scrolls/clips overflow
/// instead, which this crate doesn't model — see `layout_box`'s
/// `text_input` branch for the honest simplification: text simply
/// isn't clipped, matching this crate's established no-overflow-
/// clipping stance everywhere else), positioned during `layout()` the
/// same way `TextContent`'s lines are, so `render` never needs to
/// re-measure anything.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TextInputContent {
    /// The input's current value (from its `value` DOM attribute —
    /// this crate has no separate "IDL value vs. attribute" concept,
    /// see `renderer::script`'s own doc comment on that simplification).
    pub value: String,
    pub font_size: f32,
    pub color_hex: String,
    /// Absolute paint position of `value`'s text — top-left, same
    /// convention as `PositionedLine`.
    pub text_x: f32,
    pub text_y: f32,
    /// The text cursor's absolute x position, already resolved against
    /// `value`'s own character boundaries (see `text::char_index_for_x`)
    /// — `None` when this input is NOT the currently focused one, which
    /// is the only thing that ever makes this differ between two
    /// otherwise-identical inputs sharing the same value.
    pub cursor_x: Option<f32>,
}

/// An `<input type="checkbox">`/`<input type="radio">`'s current
/// on-screen state. Unlike `TextInputContent`, there's no cursor/focus
/// concept at all here: a checkable input's ONE real interaction is
/// toggling on click (see `renderer::script::Session::dispatch_click`'s
/// own doc comment on where that toggle — and a radio group's "only
/// one checked" behavior — actually happens), not typing, so there's
/// nothing analogous to `cursor_x` to resolve during layout. `render`
/// paints the widget purely from `kind`/`checked` — no text, no
/// position beyond the box's own `rect`.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CheckableInputContent {
    pub kind: CheckableKind,
    /// From the element's current `checked` ATTRIBUTE (presence-based,
    /// matching real HTML) — this crate has no separate "IDL checked
    /// vs. attribute" concept, the same simplification
    /// `TextInputContent::value` already makes for `value`.
    pub checked: bool,
}

/// A successfully fetched-and-decoded `<img>`, ready for `render` to
/// blit directly — no further network/decode work needed on that side
/// of the `app`<->`renderer` IPC boundary (see `ipc`'s module docs on
/// why `renderer` does the whole untrusted-content pipeline, images
/// included). `width`/`height` are the ACTUAL dimensions of `pixels`
/// (post any downscaling the renderer applied before sending — see
/// `renderer`'s image-fetching module for why: an uncompressed
/// full-resolution photo can be many times its own compressed size,
/// and this crosses the same length-prefixed IPC message every other
/// part of a page's layout does), not necessarily the image's
/// original, undecoded dimensions.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ImageContent {
    pub width: u32,
    pub height: u32,
    /// Straight RGBA8, row-major, top row first, exactly
    /// `width * height * 4` bytes — deliberately the simplest possible
    /// format `render::paint` can blit with no further decoding,
    /// rather than shipping compressed bytes across the IPC boundary
    /// and asking `app` to decode them (which would mean linking an
    /// image-decoding dependency into the PRIVILEGED process — exactly
    /// what this whole process split exists to avoid for untrusted
    /// content; see `renderer`'s own module docs).
    pub pixels: Vec<u8>,
}

/// `<audio>` vs `<video>` — the only thing that changes about how
/// `render::paint_media` draws one (a `<video>` shows its poster/a
/// placeholder above the control bar; an `<audio>` is just the bar).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum MediaKind {
    Audio,
    Video,
}

/// The STATIC part of an `<audio>`/`<video>` element's content — known
/// once `renderer::media` finishes fetching/decoding, and unchanging
/// for the rest of that element's life (unlike `MediaPlaybackState`,
/// which changes on every play/pause/seek). Split the same way
/// `ImageContent` (static) and `focus`'s cursor position (dynamic) are
/// for `text_input`.
///
/// **No video frame decoding** — this crate (and `renderer::media`
/// upstream of it) only ever decodes a media file's AUDIO track, never
/// its video frames. There is no pure-Rust decoder for the codecs most
/// real-world `<video>` files actually use (H.264/VP9), and this
/// project avoids C/C++ dependencies for parsing untrusted content
/// (the same reasoning behind choosing Boa over a C JS engine, and the
/// pure-Rust `image` crate for `<img>`). A `<video>` therefore always
/// shows a static image (its `poster`, or a plain placeholder) rather
/// than moving pictures — real audio, real transport controls
/// (play/pause/seek/mute), just no motion.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct MediaAsset {
    pub kind: MediaKind,
    /// Mirrors the HTML `controls` attribute's mere presence — real
    /// browsers only draw a native control surface when it's set
    /// (otherwise a page is expected to build its own via script,
    /// which this crate doesn't support — see this type's own "no
    /// scripting API" scope note below). Kept even when `false` so a
    /// `<video>` with no `controls` still shows its poster/placeholder
    /// (real browsers do too), just with no interactive bar under it.
    pub controls: bool,
    /// Seconds, from the decoded audio track — `0.0` if nothing could
    /// be decoded at all (a missing/unreachable/unsupported `src`, or
    /// a file over `renderer::media`'s size cap). `app`'s controls
    /// treat `0.0` as "nothing to play" and don't respond to clicks.
    pub duration_secs: f32,
    /// A decoded `<video poster="...">` image, if one was given and
    /// successfully fetched/decoded — reuses the exact same
    /// `ImageContent`/fetch-and-decode pipeline `<img>` already goes
    /// through (see `renderer::images`). Always `None` for `<audio>`
    /// (real HTML has no `poster` attribute there).
    pub poster: Option<ImageContent>,
}

/// The DYNAMIC part of an `<audio>`/`<video>` element's state —
/// `app` is the only thing that actually knows this (it owns real
/// playback via `cpal`; see that crate's own module docs), so this
/// crosses the IPC boundary via `ipc::ClientMessageKind::
/// UpdateMediaPlayback` and gets applied to an already-laid-out tree
/// by `apply_media_playback` rather than being computed here.
#[derive(Debug, Clone, Copy, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct MediaPlaybackState {
    pub playing: bool,
    pub muted: bool,
    pub current_time_secs: f32,
}

/// An `<audio>`/`<video>` element's full current on-screen state —
/// `MediaAsset`'s static fields plus whatever `MediaPlaybackState` its
/// node id had at the time `apply_media_playback` last ran (all zeroed/
/// `false` before that ever happens, e.g. on the very first render).
/// **No JS scripting API** — `HTMLMediaElement.play()`/`.pause()`/
/// `.currentTime`/events like `timeupdate` don't exist in this crate's
/// (or `renderer::script`'s) scope; only the native `controls` UI
/// bar's own play/pause/seek/mute clicks (`hit_test_media_control`)
/// can ever change this state. A real, documented follow-up, not an
/// oversight — see this project's README.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct MediaContent {
    pub kind: MediaKind,
    pub controls: bool,
    pub duration_secs: f32,
    pub poster: Option<ImageContent>,
    pub playing: bool,
    pub muted: bool,
    pub current_time_secs: f32,
}

/// Applies each media element's CURRENT `MediaPlaybackState` (keyed by
/// `dom::NodeId`) onto an ALREADY-LAID-OUT tree — deliberately separate
/// from `layout()`/`layout_with_focus` itself (unlike `focus`, which
/// resolves a PIXEL cursor position and so has to run inside the
/// geometry pass), since playback state never affects any box's
/// position or size. A node with no entry in `playback` keeps whatever
/// `MediaContent` already had (all `false`/`0.0` defaults from
/// `build_layout_tree_with_media`, for a page that's never sent an
/// `UpdateMediaPlayback` yet).
pub fn apply_media_playback(
    tree: &mut LayoutBox,
    playback: &HashMap<dom::NodeId, MediaPlaybackState>,
) {
    if let Some(media) = &mut tree.media {
        if let Some(state) = playback.get(&tree.dom_node_id) {
            media.playing = state.playing;
            media.muted = state.muted;
            media.current_time_secs = state.current_time_secs;
        }
    }
    for child in &mut tree.children {
        apply_media_playback(child, playback);
    }
}

/// Real `font-size` CSS support now lives in `css::ComputedStyle::
/// font_size` (`px`/`em`/`%`/a handful of keywords, real inheritance —
/// see that function and `css::compute_style`'s own doc comments) —
/// every `TextContent`/`TextInputContent` gets ITS OWN resolved size
/// from `style.font_size()`, not this constant. What's left here is
/// purely a layout-internal fallback for code that measures text
/// without a specific node's computed style in hand at all (e.g.
/// `layout_inline_run`'s generic inter-word space-width measurement) —
/// not a statement that font-size is unsupported.
pub const DEFAULT_FONT_SIZE: f32 = 16.0;

/// Fallback height for non-text leaf boxes with no children at all
/// (e.g. an empty `<div></div>`, or a future `<br>`/`<img>` stand-in).
/// Text boxes do NOT use this — their height comes from real wrapped
/// line counts, see `layout_box`.
const DEFAULT_LINE_HEIGHT: f32 = 18.0;

pub fn build_layout_tree(node: &NodeRef, stylesheet: &Stylesheet) -> LayoutBox {
    build_layout_tree_with_images(node, stylesheet, &HashMap::new())
}

/// Same as `build_layout_tree`, but attaches `images[node_id]` (if
/// present) to the `LayoutBox` built from that node — the only way an
/// `<img>` ever actually renders as a real decoded image rather than
/// nothing at all. `images` is keyed by `dom::NodeId`, not by URL or
/// tag: the renderer resolves/fetches/decodes each `<img src>` itself
/// (see that crate's own image-fetching module) and hands back exactly
/// this map, already keyed the way this function needs it.
pub fn build_layout_tree_with_images(
    node: &NodeRef,
    stylesheet: &Stylesheet,
    images: &HashMap<dom::NodeId, ImageContent>,
) -> LayoutBox {
    build_layout_tree_with_media(node, stylesheet, images, &HashMap::new())
}

/// Same as `build_layout_tree_with_images`, but also attaches
/// `media[node_id]` (if present) to the `LayoutBox` built from that
/// node — the only way an `<audio>`/`<video>` ever gets real decoded
/// content (see `MediaAsset`'s own doc comment) rather than rendering
/// as an empty box. Keyed by `dom::NodeId`, same convention as
/// `images` — `renderer::media` does the actual fetch/decode and hands
/// back this map already keyed the way this function needs it.
pub fn build_layout_tree_with_media(
    node: &NodeRef,
    stylesheet: &Stylesheet,
    images: &HashMap<dom::NodeId, ImageContent>,
    media: &HashMap<dom::NodeId, MediaAsset>,
) -> LayoutBox {
    // A synthetic root style carrying the theme's default text color,
    // so real inheritance (see css::compute_style) has something to
    // fall back to even above the page's own <html> element — the
    // same role the "initial value" of `color` plays in a real
    // browser's inheritance chain.
    let mut root_style = ComputedStyle::default();
    root_style.properties.insert(
        "color".to_string(),
        css::Theme::default().foreground_hex().to_string(),
    );

    build_layout_tree_inner(node, stylesheet, Some(&root_style), images, media)
        .expect("the document root is never itself a non-rendered element")
}

/// True for an `<input>` element whose `type` attribute (or its
/// absence — `text` is the real HTML default) makes it an ordinary
/// single-line editable text field. Deliberately excludes every other
/// real `<input>` type (`checkbox`, `radio`, `submit`, `button`,
/// `hidden`, `file`, `range`, `color`, `date`, ...) — none of which
/// this crate renders/edits as text at all; a `<textarea>` (real
/// multi-line text input) is ALSO out of scope for now (see this
/// crate's module docs on floats/positioning for the established
/// pattern of scoping a feature to its single most common real-world
/// shape first).
pub fn is_text_like_input(el: &dom::Element) -> bool {
    if el.tag_name != "input" {
        return false;
    }
    match el.attributes.get("type").map(|t| t.to_lowercase()) {
        None => true,
        Some(t) => matches!(
            t.as_str(),
            "text" | "search" | "email" | "url" | "tel" | "password"
        ),
    }
}

/// True for an element real HTML's default (no explicit `tabindex`)
/// keyboard focus order includes: a real link (`<a href="...">` — the
/// same "`href` merely present" notion `hit_test_link` already uses),
/// a `<button>`, or any `<input>` except `type="hidden"`. A `disabled`
/// attribute (any value, including an empty one — its mere presence is
/// what matters, matching real HTML) or an explicit `tabindex="-1"`
/// opts an otherwise-focusable element OUT of the tab order — the one
/// real mechanism for that. An element with none of the above can
/// still opt IN via `tabindex="0"` or higher (real HTML's other real
/// mechanism, commonly used to make a custom ARIA widget keyboard-
/// operable).
///
/// Deliberately does NOT implement positive-`tabindex` REORDERING
/// (real HTML visits every `tabindex="1"` before every `tabindex="2"`
/// before every `tabindex="0"`/naturally-focusable element, regardless
/// of document order) — `renderer::script::Session::focusable_nodes`
/// visits every focusable element in plain document order instead,
/// treating any non-negative `tabindex` the same as `0`. A real,
/// documented scope cut: most real-world pages don't rely on positive
/// tabindex either.
pub fn is_keyboard_focusable(el: &dom::Element) -> bool {
    if el.attributes.contains_key("disabled") {
        return false;
    }
    let tabindex = el
        .attributes
        .get("tabindex")
        .and_then(|v| v.trim().parse::<i32>().ok());
    if tabindex == Some(-1) {
        return false;
    }
    if tabindex.is_some_and(|i| i >= 0) {
        return true;
    }
    match el.tag_name.as_str() {
        "a" => el.attributes.contains_key("href"),
        "button" => true,
        "input" => !matches!(
            el.attributes
                .get("type")
                .map(|t| t.to_lowercase())
                .as_deref(),
            Some("hidden")
        ),
        _ => false,
    }
}

/// Which of the two REAL "checkable" `<input>` types (see
/// `checkable_kind`) — `None` for every other kind of `<input>` (text-
/// like, `submit`/`button`, `hidden`, `file`, `range`, `color`, `date`,
/// ...), none of which this crate models as checkable at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CheckableKind {
    Checkbox,
    Radio,
}

/// `Some` for an `<input type="checkbox">`/`<input type="radio">` —
/// unlike `is_text_like_input`, there's no "absent `type` defaults to
/// this" case (real HTML's default `type` is `text`, not `checkbox`),
/// so this only ever matches an EXPLICIT `type="checkbox"`/`"radio"`.
pub fn checkable_kind(el: &dom::Element) -> Option<CheckableKind> {
    if el.tag_name != "input" {
        return None;
    }
    match el
        .attributes
        .get("type")
        .map(|t| t.to_lowercase())
        .as_deref()
    {
        Some("checkbox") => Some(CheckableKind::Checkbox),
        Some("radio") => Some(CheckableKind::Radio),
        _ => None,
    }
}

/// Returns `None` for any element whose computed `display` resolves
/// to `css::Display::None` — the element AND all its children
/// (including any text nodes, e.g. a `<style>` block's CSS source)
/// are excluded from the layout tree entirely, not just hidden after
/// the fact. This is what keeps `<head>`/`<script>`/`<style>` content
/// off the page: see `css::user_agent_stylesheet`, which assigns them
/// `display: none` by default the same way a real browser's built-in
/// stylesheet does.
fn build_layout_tree_inner(
    node: &NodeRef,
    stylesheet: &Stylesheet,
    parent_style: Option<&ComputedStyle>,
    images: &HashMap<dom::NodeId, ImageContent>,
    media: &HashMap<dom::NodeId, MediaAsset>,
) -> Option<LayoutBox> {
    let style = compute_style(node, stylesheet, parent_style);

    if let NodeType::Element(_) = &node.borrow().node_type {
        if style.display() == Display::None {
            return None;
        }
    }

    let text = match &node.borrow().node_type {
        NodeType::Text(raw) => Some(TextContent {
            raw: raw.clone(),
            font_size: style.font_size(),
            // A text node never matches a selector itself (see
            // `css::selector_matches`), so whatever's in `style` here
            // is entirely inherited from `parent_style` — real
            // inheritance doing exactly the job the old hand-threaded
            // hack used to.
            color_hex: style
                .properties
                .get("color")
                .cloned()
                .unwrap_or_else(|| css::Theme::default().foreground_hex().to_string()),
            lines: Vec::new(), // wrapped later, in layout()
        }),
        _ => None,
    };

    // Text boxes never carry their own box model (see module docs) —
    // only real elements read margin/border/padding off computed
    // style.
    let (margin, padding, border, border_color) = if text.is_some() {
        (
            EdgeSizes::default(),
            EdgeSizes::default(),
            EdgeSizes::default(),
            None,
        )
    } else {
        let (border, border_color) = resolve_border(&style);
        (
            resolve_edges(&style, "margin"),
            resolve_edges(&style, "padding"),
            border,
            border_color,
        )
    };

    let children: Vec<LayoutBox> = node
        .borrow()
        .children
        .iter()
        .filter_map(|child| build_layout_tree_inner(child, stylesheet, Some(&style), images, media))
        .collect();

    // Cloning node_type-ish data out of the Rc<RefCell<Node>> is
    // wasteful; a real layout tree should hold a reference/id back
    // into the DOM instead of copying node data. Left simple here for
    // stub clarity.
    let node_type = match &node.borrow().node_type {
        NodeType::Document => NodeType::Document,
        NodeType::Element(el) => NodeType::Element(dom::Element {
            tag_name: el.tag_name.clone(),
            attributes: el.attributes.clone(),
        }),
        NodeType::Text(t) => NodeType::Text(t.clone()),
        NodeType::Comment(c) => NodeType::Comment(c.clone()),
    };

    let node_id = node.borrow().id;
    let image = images.get(&node_id).cloned();

    // `cursor_x`/`text_x`/`text_y` are all resolved later, in
    // `layout_box` (which is where this node's actual content-box
    // position and `focus` — threaded through the geometry pass
    // separately, the same way `font` is — both become available) —
    // this only decides WHETHER a cursor belongs here at all.
    let text_input = match &node.borrow().node_type {
        NodeType::Element(el) if is_text_like_input(el) => Some(TextInputContent {
            value: el.attributes.get("value").cloned().unwrap_or_default(),
            font_size: style.font_size(),
            color_hex: style
                .properties
                .get("color")
                .cloned()
                .unwrap_or_else(|| css::Theme::default().foreground_hex().to_string()),
            text_x: 0.0,
            text_y: 0.0,
            cursor_x: None,
        }),
        _ => None,
    };

    let checkable_input = match &node.borrow().node_type {
        NodeType::Element(el) => checkable_kind(el).map(|kind| CheckableInputContent {
            kind,
            checked: el.attributes.contains_key("checked"),
        }),
        _ => None,
    };

    let media_content = media.get(&node_id).map(|asset| MediaContent {
        kind: asset.kind,
        controls: asset.controls,
        duration_secs: asset.duration_secs,
        poster: asset.poster.clone(),
        // Dynamic fields — filled in later by `apply_media_playback`
        // against an already-laid-out tree, the same "static content
        // now, dynamic state applied afterward" split `MediaAsset`'s
        // own doc comment describes.
        playing: false,
        muted: false,
        current_time_secs: 0.0,
    });

    Some(LayoutBox {
        rect: Rect::default(),
        style,
        node_type,
        dom_node_id: node_id,
        children,
        text,
        image,
        text_input,
        checkable_input,
        media: media_content,
        focused: false,
        margin,
        border,
        padding,
        border_color,
    })
}

/// Block layout with a real inline formatting context and box model:
/// block-level children stack top-to-bottom at full container width;
/// runs of inline-level children (text boxes and `display: inline`
/// elements) pack left-to-right and wrap into line boxes instead (see
/// `layout_inline_run`). A text box's height comes from wrapping its
/// raw string against its available width and counting lines.
///
/// TODO: no parent-child margin collapsing (adjacent-sibling
/// collapsing is done), no word-level interleaving across inline
/// element boundaries — see module docs.
///
/// After normal-flow layout, applies `position: relative/absolute/
/// fixed` (see `apply_positioning`) as a second pass over the now-
/// finished tree.
pub fn layout(root: &mut LayoutBox, viewport_width: f32, font: &Font) {
    layout_with_focus(root, viewport_width, font, None);
}

/// Same as `layout`, but additionally resolving a text cursor position
/// for whichever `<input>` (if any) currently has focus — see
/// `layout_box`'s own doc comment on the `focus` parameter this
/// threads through, and its documented flex/grid scope limit.
pub fn layout_with_focus(
    root: &mut LayoutBox,
    viewport_width: f32,
    font: &Font,
    focus: Option<(dom::NodeId, usize)>,
) {
    layout_box(root, 0.0, 0.0, viewport_width, font, true, focus);
    // The "viewport" `position: fixed` anchors against — see
    // `apply_positioning`'s doc comment for why this is the PAGE's own
    // final height, not the live browser window's, and why that's a
    // deliberate, documented scope reduction rather than an oversight.
    let viewport = Rect {
        x: 0.0,
        y: 0.0,
        width: viewport_width,
        height: root.rect.height,
    };
    apply_positioning(root, root.rect, viewport);
}

/// Finds the `href` of the `<a>` element (if any) whose rendered box
/// contains the point `(x, y)` — in the SAME un-scrolled coordinate
/// space `layout()` itself produces (the caller is responsible for
/// converting a click position back into that space first, e.g. by
/// adding back whatever scroll offset it's currently displaying with —
/// see `render::paint`'s `scroll_y` for the inverse operation).
///
/// Hit-testing is bounding-rect-based, not pixel/glyph-accurate: a
/// click anywhere inside an anchor's box counts, including in gaps
/// between its words that no actual glyph covers. That's both simpler
/// and more usable — real browsers are similarly generous about link
/// hit-testing rather than requiring a pixel-perfect glyph hit.
///
/// Real anchors can't validly nest (html5ever's parser enforces this
/// per spec — an `<a>` inside another `<a>` gets the outer one closed
/// first), so which one "wins" when boxes overlap essentially never
/// comes up in practice; this returns the last (innermost, in a
/// depth-first walk) match found, which is the more sensible tie-break
/// if it ever did.
/// A clicked `<a>`, resolved at hit-test time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkHit {
    pub href: String,
    /// Mirrors the HTML `download` attribute: `Some(value)` (possibly
    /// an empty string, for a bare `download` attribute with no value —
    /// the attribute's mere PRESENCE is what matters, per the HTML
    /// spec) means the author wants this link's resource saved to
    /// disk rather than navigated to; `None` means a normal navigation.
    /// `app`'s `handle_click` is what actually acts on this.
    pub download: Option<String>,
}

pub fn hit_test_link(tree: &LayoutBox, x: f32, y: f32) -> Option<LinkHit> {
    let mut found = None;
    hit_test_link_inner(tree, x, y, &mut found);
    found
}

fn hit_test_link_inner(b: &LayoutBox, x: f32, y: f32, found: &mut Option<LinkHit>) {
    let hit = x >= b.rect.x
        && x <= b.rect.x + b.rect.width
        && y >= b.rect.y
        && y <= b.rect.y + b.rect.height;
    if !hit {
        return;
    }

    if let NodeType::Element(el) = &b.node_type {
        if el.tag_name == "a" {
            if let Some(href) = el.attributes.get("href") {
                *found = Some(LinkHit {
                    href: href.clone(),
                    download: el.attributes.get("download").cloned(),
                });
            }
        }
    }

    for child in &b.children {
        hit_test_link_inner(child, x, y, found);
    }
}

/// Layout of a media control bar — shared between hit-testing here and
/// `render::paint_media`'s drawing (both live in crates `render`
/// already depends on `layout` from, so this is the one place they
/// can't drift apart: clicking exactly where a button is painted).
/// Left to right: play/pause button, a scrubber that fills the
/// remaining space, a fixed time-text budget, a mute button.
pub const MEDIA_CONTROL_BAR_HEIGHT: f32 = 32.0;
pub const MEDIA_PLAY_BUTTON_WIDTH: f32 = 32.0;
pub const MEDIA_MUTE_BUTTON_WIDTH: f32 = 32.0;
pub const MEDIA_TIME_TEXT_WIDTH: f32 = 70.0;

/// What part of a media control bar a click landed on — see
/// `hit_test_media_control`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MediaControlHit {
    PlayPause,
    ToggleMute,
    /// Landed on the scrubber/progress track, `0.0..=1.0` of the way
    /// across it — `app` multiplies this by `MediaContent::
    /// duration_secs` to get the new `current_time_secs` to seek to.
    Seek(f32),
}

/// Finds which media control (if any) a click at `(x, y)` landed on —
/// the SAME unscrolled layout-tree coordinate space `hit_test_link`/
/// `hit_test_node` use. Only ever matches a box whose `media` has
/// `controls: true` AND a real decoded duration (`duration_secs >
/// 0.0`) — clicking a controls bar with nothing actually playable
/// behind it (a failed fetch, an unsupported format) does nothing,
/// same as a real browser's disabled-looking controls would.
pub fn hit_test_media_control(
    tree: &LayoutBox,
    x: f32,
    y: f32,
) -> Option<(dom::NodeId, MediaControlHit)> {
    let mut found = None;
    hit_test_media_control_inner(tree, x, y, &mut found);
    found
}

fn hit_test_media_control_inner(
    b: &LayoutBox,
    x: f32,
    y: f32,
    found: &mut Option<(dom::NodeId, MediaControlHit)>,
) {
    if let Some(media) = &b.media {
        if media.controls && media.duration_secs > 0.0 {
            if let Some(hit) = hit_test_within_control_bar(b, x, y) {
                *found = Some((b.dom_node_id, hit));
                return; // media elements never nest one another
            }
        }
    }
    for child in &b.children {
        hit_test_media_control_inner(child, x, y, found);
    }
}

/// The control bar always sits flush against the BOTTOM of `b`'s own
/// box (below a `<video>`'s poster, or the whole box for `<audio>`,
/// which is sized to exactly `MEDIA_CONTROL_BAR_HEIGHT` — see
/// `css::user_agent_stylesheet`).
fn media_control_bar_rect(b: &LayoutBox) -> Rect {
    Rect {
        x: b.rect.x,
        y: b.rect.y + b.rect.height - MEDIA_CONTROL_BAR_HEIGHT,
        width: b.rect.width,
        height: MEDIA_CONTROL_BAR_HEIGHT,
    }
}

fn hit_test_within_control_bar(b: &LayoutBox, x: f32, y: f32) -> Option<MediaControlHit> {
    let bar = media_control_bar_rect(b);
    if x < bar.x || x > bar.x + bar.width || y < bar.y || y > bar.y + bar.height {
        return None;
    }

    let play_end = bar.x + MEDIA_PLAY_BUTTON_WIDTH;
    let mute_start = bar.x + bar.width - MEDIA_MUTE_BUTTON_WIDTH;
    let scrubber_end = (mute_start - MEDIA_TIME_TEXT_WIDTH).max(play_end);

    if x < play_end {
        Some(MediaControlHit::PlayPause)
    } else if x >= mute_start {
        Some(MediaControlHit::ToggleMute)
    } else if x < scrubber_end {
        let fraction = ((x - play_end) / (scrubber_end - play_end).max(1.0)).clamp(0.0, 1.0);
        Some(MediaControlHit::Seek(fraction))
    } else {
        None // over the time-text label — no action there
    }
}

/// Finds the `dom::NodeId` of the innermost ELEMENT box (never a text
/// box — see below) whose rendered box contains `(x, y)`, in the same
/// coordinate space `hit_test_link` uses. This is what turns a click's
/// pixel position into "which live DOM node should receive it" (see
/// `renderer::script::Session::dispatch_click`, the eventual consumer
/// of this id on the other side of the IPC boundary).
///
/// Deliberately skips text boxes even when one is the deepest match —
/// a `<button>Save</button>`'s text box sits entirely inside the
/// button's own box, and a real click on the word "Save" should still
/// target the BUTTON (the only thing `addEventListener` can ever be
/// called on in this DOM surface — see `script`'s module docs), not a
/// text node no script has any way to attach a listener to anyway.
/// Text boxes are still walked INTO structurally (they can't have
/// children today, but nothing here assumes that) — they just never
/// win the tie-break themselves.
pub fn hit_test_node(tree: &LayoutBox, x: f32, y: f32) -> Option<dom::NodeId> {
    let mut found = None;
    hit_test_node_inner(tree, x, y, &mut found);
    found
}

fn hit_test_node_inner(b: &LayoutBox, x: f32, y: f32, found: &mut Option<dom::NodeId>) {
    let hit = x >= b.rect.x
        && x <= b.rect.x + b.rect.width
        && y >= b.rect.y
        && y <= b.rect.y + b.rect.height;
    if !hit {
        return;
    }

    if matches!(b.node_type, NodeType::Element(_)) {
        *found = Some(b.dom_node_id);
    }

    for child in &b.children {
        hit_test_node_inner(child, x, y, found);
    }
}

/// Finds the `LayoutBox` built from the DOM node `node_id`, if any is
/// still present in `tree` — the DevTools Elements panel's bridge from
/// "here's a node id from a `ClientMessageKind::FetchDomSnapshot`
/// snapshot" to "here's that element's REAL painted geometry/computed
/// style" (`rect`/`margin`/`border`/`padding`/`style`), without `app`
/// needing any layout-tree-walking logic of its own beyond calling
/// this. Returns `None` for a node that exists in the DOM but not in
/// this tree — `display: none` (including every `<head>`/`<script>`/
/// `<style>` element, see `build_layout_tree_inner`'s own doc comment)
/// and a stale id from before the last re-render both look the same
/// from here: "nothing to show a box model for," not an error.
pub fn find_box_by_dom_node_id(tree: &LayoutBox, node_id: dom::NodeId) -> Option<&LayoutBox> {
    if tree.dom_node_id == node_id {
        return Some(tree);
    }
    tree.children
        .iter()
        .find_map(|child| find_box_by_dom_node_id(child, node_id))
}

/// Finds the `dom::NodeId` of whichever box in `tree` is currently
/// marked `focused` (see that field's own doc comment) — `app`'s
/// bridge from "the renderer just moved keyboard focus somewhere" to
/// "which node, specifically," without `app` needing to track that
/// separately: the layout tree it already received IS the answer.
/// `None` when nothing is focused, which is itself a real, expected
/// outcome (a page with zero focusable elements, or focus explicitly
/// cleared) — not an error.
pub fn find_focused_dom_node_id(tree: &LayoutBox) -> Option<dom::NodeId> {
    if tree.focused {
        return Some(tree.dom_node_id);
    }
    tree.children.iter().find_map(find_focused_dom_node_id)
}

/// True for boxes that participate in an inline formatting context:
/// text boxes always do (they have no `display` of their own — see
/// module docs), and elements do when their computed `display` is
/// `Display::Inline` — UNLESS the element also has `float:
/// left`/`right` set, in which case it's always `false` regardless of
/// `display`. That matches real CSS's "floats are auto-blockified"
/// rule: a floated element always generates a block-level box no
/// matter what `display` said, which matters here because the most
/// common real-world floated element is an `<img>` — `Display::Inline`
/// by default per this crate's own UA stylesheet (see
/// `css::INLINE_TAGS`) — and a floated image needs to reach
/// `layout_box`'s block-stacking loop (where `place_float` actually
/// lives), not get folded into an ordinary inline run.
fn is_inline_level(b: &LayoutBox) -> bool {
    if b.style.float() != css::Float::None {
        return false;
    }
    b.text.is_some() || b.style.display() == Display::Inline
}

/// True for a text box whose raw content is entirely whitespace — the
/// box `build_layout_tree` builds for, e.g., the newline-plus-indent
/// text a real HTML parser leaves between `<div>Left</div>` and
/// `<div>Right</div>` in nicely-formatted source. A flex/grid
/// container's real formatting context should never treat one of
/// these as an actual flex/grid item (real CSS drops it before
/// flex/grid item boxes are even generated) — `flex`/`grid` both
/// filter their children down past this, unlike ordinary block/inline
/// layout, which already has its own separate whitespace-collapsing
/// logic for the inline-formatting-context case (see
/// `InlineItem::Space`) that block-level `layout_box` doesn't need,
/// since a block sibling of a whitespace text node just leaves it as
/// an invisible, unlaid-out (zero-size) box today — harmless there,
/// but flex/grid's OWN item-counting (basis sums, line-wrapping,
/// grid-cell auto-placement) would otherwise be thrown off by
/// whitespace nodes that were never meant to occupy a cell/slot.
pub(crate) fn is_whitespace_only_text(b: &LayoutBox) -> bool {
    b.text.as_ref().is_some_and(|t| t.raw.trim().is_empty())
}

/// The natural, unwrapped **border-box** width of `b` — how wide it
/// would be if laid out on a single line with no width constraint.
/// Used to decide whether an inline box fits on the current line
/// (`layout_inline_run`) and to size shrink-to-fit inline elements
/// (`layout_box`). Does not include `b`'s own margin — callers that
/// need the full space `b` occupies add `b.margin.horizontal()`
/// themselves, matching how margin is handled everywhere else in this
/// crate.
///
/// TODO: this sums every child's natural width regardless of whether
/// they'd actually all fit on one line — a reasonable "maximum content
/// width" approximation, but a real intrinsic-sizing pass would
/// distinguish "min-content" (break at every opportunity) from
/// "max-content" (never break) width, which this doesn't.
fn intrinsic_width(b: &LayoutBox, font: &Font) -> f32 {
    if let Some(image) = &b.image {
        return image.width as f32;
    }
    if let Some(media) = &b.media {
        // Only ever a fallback in practice — `css::user_agent_
        // stylesheet` always sets an explicit `width` for `video`/
        // `audio[controls]`, which `sizing_properties_apply` (below)
        // makes take priority over this. A poster's own width is the
        // more informative fallback when one exists; 300.0 (matching
        // this crate's own UA-stylesheet default) otherwise.
        return media
            .poster
            .as_ref()
            .map(|p| p.width as f32)
            .unwrap_or(300.0);
    }
    if let Some(text) = &b.text {
        return text::measure_text_width(font, &text.raw, text.font_size);
    }
    let children_width: f32 = b
        .children
        .iter()
        .map(|c| intrinsic_width(c, font) + c.margin.horizontal())
        .sum();
    children_width + b.border.horizontal() + b.padding.horizontal()
}

/// The top margin `b` presents to whatever precedes it in its block
/// formatting context (a previous sibling, or `b`'s own parent if `b`
/// is the first in-flow child) — not simply `b.margin.top`, since real
/// CSS lets that margin collapse straight through `b` when nothing
/// blocks it. Recurses through `b`'s first child when `b` has no top
/// border/padding and that child is block-level (a line box always
/// blocks it, matching the spec).
fn effective_top_margin(b: &LayoutBox) -> f32 {
    if b.text.is_some() {
        return 0.0; // text boxes never carry margin
    }
    if b.border.top != 0.0 || b.padding.top != 0.0 {
        return b.margin.top;
    }
    match b.children.first() {
        Some(first) if !is_inline_level(first) => b.margin.top.max(effective_top_margin(first)),
        _ => b.margin.top,
    }
}

/// The bottom-margin mirror of `effective_top_margin` — see its docs.
fn effective_bottom_margin(b: &LayoutBox) -> f32 {
    if b.text.is_some() {
        return 0.0;
    }
    if b.border.bottom != 0.0 || b.padding.bottom != 0.0 {
        return b.margin.bottom;
    }
    match b.children.last() {
        Some(last) if !is_inline_level(last) => b.margin.bottom.max(effective_bottom_margin(last)),
        _ => b.margin.bottom,
    }
}

/// Applies an explicit `height` (if set) on top of
/// `natural_content_height` — whatever this box's own sizing rule
/// otherwise produced (an image's aspect ratio, a block's stacked
/// children, or the flex/grid algorithms' own result) — then clamps
/// with `min-height`/`max-height`. All three are content-height values
/// (`box-sizing: content-box`, the only mode this crate supports);
/// the caller adds border/padding back on top itself, same as the
/// width side (see `layout_box`). Percentage heights never apply here
/// at all — see `box_model::resolve_height`'s own doc comment for why
/// that's a deliberate omission, not an oversight.
fn resolve_content_height(style: &ComputedStyle, natural_content_height: f32) -> f32 {
    let mut height = box_model::resolve_height(style).unwrap_or(natural_content_height);
    if let Some(max_h) = box_model::resolve_max_height(style) {
        height = height.min(max_h);
    }
    if let Some(min_h) = box_model::resolve_min_height(style) {
        height = height.max(min_h);
    }
    height
}

/// Narrows `[content_x, content_x + content_width]` for one line of
/// inline content starting at `y`, based on any active float whose
/// vertical span contains `y` — real `float: left`/`right` text-wrap
/// support (see `layout_box`'s own module-doc section on floats for
/// the full design). Tested at the line's TOP `y` only, not its full
/// eventual height (which isn't known until every word on it has been
/// placed) — a deliberate simplification consistent with this crate's
/// line-by-line (not full-paragraph-lookahead) approach to text
/// layout elsewhere.
fn line_bounds(floats: &[FloatBox], content_x: f32, content_width: f32, y: f32) -> (f32, f32) {
    let mut left = content_x;
    let mut right = content_x + content_width;
    for f in floats {
        if y >= f.rect.y && y < f.rect.y + f.rect.height {
            match f.side {
                css::Float::Left => left = left.max(f.rect.x + f.rect.width),
                css::Float::Right => right = right.min(f.rect.x),
                css::Float::None => {}
            }
        }
    }
    (left, right.max(left))
}

/// Lays out and places one floated child (`float: left`/`right`):
/// resolves its own box (a normal `layout_box` call, so explicit
/// `width`/intrinsic shrink-to-fit sizing all work exactly like an
/// in-flow box would — see that function's own sizing logic) at
/// today's flow position, then repositions it flush against its
/// side's edge of the container.
///
/// Real CSS packs same-side floats next to each other when they both
/// fit on one "row"; this crate simplifies to stacking same-side
/// floats vertically instead (each one below the previous same-side
/// float's bottom edge) — a deliberate scope reduction (see
/// `layout_box`'s module-doc section on floats), since the overwhelmingly
/// common real-world case is a single floated image per paragraph, not
/// a multi-float gallery row (real CSS `display: flex`/`grid`, both
/// already implemented here, are how modern content actually builds
/// that instead).
#[allow(clippy::too_many_arguments)]
fn place_float(
    child: &mut LayoutBox,
    side: css::Float,
    content_x: f32,
    content_width: f32,
    cursor_y: f32,
    font: &Font,
    active_floats: &[FloatBox],
    focus: Option<(dom::NodeId, usize)>,
) -> FloatBox {
    layout_box(
        child,
        content_x,
        cursor_y,
        content_width,
        font,
        false,
        focus,
    );

    let same_side_bottom = active_floats
        .iter()
        .filter(|f| f.side == side)
        .map(|f| f.rect.y + f.rect.height)
        .fold(cursor_y, f32::max);

    let new_x = match side {
        css::Float::Right => content_x + content_width - child.rect.width,
        _ => content_x,
    };
    let dx = new_x - child.rect.x;
    let dy = same_side_bottom - child.rect.y;
    if dx != 0.0 || dy != 0.0 {
        shift_subtree(child, dx, dy);
    }

    FloatBox {
        side,
        rect: child.rect,
    }
}

/// `available_width` is the width of the containing block's *content*
/// area — i.e. the space `b` has to work with before its own margin
/// is subtracted. Block-level boxes fill it (minus their own margin,
/// the standard CSS default); inline-level boxes shrink-to-fit their
/// natural content width instead, capped at whatever's available.
///
/// `focus` is `Some((dom_node_id, cursor_char_index))` when a
/// text-editable `<input>` currently has focus (see
/// `renderer::script::Session`) — threaded through so the `text_input`
/// branch below can tell whether THIS box is the focused one and
/// resolve a real `cursor_x` for it. Only threaded through this
/// crate's own block/inline recursion (this function,
/// `layout_inline_run`, `place_float`) — `flex`/`grid` items always
/// see `None` here (a deliberate, minor scope reduction: an input's
/// VALUE still renders correctly either way, since that doesn't depend
/// on focus at all, just its cursor wouldn't show while focused inside
/// a flex/grid container specifically).
fn layout_box(
    b: &mut LayoutBox,
    x: f32,
    y: f32,
    available_width: f32,
    font: &Font,
    is_root: bool,
    focus: Option<(dom::NodeId, usize)>,
) {
    b.rect.x = x + b.margin.left;
    b.rect.y = y + b.margin.top;
    // Set for EVERY box (not just the `text_input` branch below, which
    // additionally resolves a real `cursor_x`) — see `LayoutBox::focused`'s
    // own doc comment.
    b.focused = matches!(focus, Some((focused_id, _)) if focused_id == b.dom_node_id);

    let fill_width = (available_width - b.margin.horizontal()).max(0.0);
    // An image never stretches to fill its container the way an
    // ordinary block box does, regardless of its own `display` — real
    // CSS's replaced-element sizing (an `<img>` keeps its intrinsic
    // size unless `width`/`height` say otherwise) matters more here
    // than the inline-vs-block distinction.
    let shrinks_to_fit = b.image.is_some()
        || b.text_input.is_some()
        || b.checkable_input.is_some()
        || b.media.is_some()
        || (b.text.is_none() && b.style.display() == Display::Inline);
    let natural_border_box_width = if shrinks_to_fit {
        intrinsic_width(b, font).min(fill_width)
    } else {
        fill_width
    };
    let natural_content_width =
        (natural_border_box_width - b.border.horizontal() - b.padding.horizontal()).max(0.0);

    // An explicit `width` (if set) overrides that natural sizing —
    // real CSS's `box-sizing: content-box` (the only mode this crate
    // supports — see `box_model`'s own module docs), so it sets the
    // CONTENT width directly; border/padding get added back on top to
    // recover the border-box `rect.width` everything else here works
    // in. `min-width`/`max-width` clamp the RESULT either way (explicit
    // or natural), matching real CSS. Deliberately NOT capped to
    // `fill_width` when explicit — real CSS lets an explicit width
    // overflow its container; only the natural shrink-to-fit/fill
    // sizing above is capped.
    // Real CSS ignores `width`/`min-width`/`max-width` on a
    // non-replaced inline element (`<span style="width: 200px">` does
    // nothing) — only block-level boxes and REPLACED elements (here,
    // `<img>`, a text-like `<input>`, and a checkbox/radio `<input>`)
    // ever actually size themselves from these properties. Without
    // `checkable_input.is_some()` here specifically, the UA
    // stylesheet's own `input[type="checkbox"]`/`"radio"` sizing (see
    // `css::user_agent_stylesheet`) would be silently ignored — a
    // checkbox has no image/text/children of its own, so its
    // `intrinsic_width` fallback is just its border+padding, next to
    // nothing.
    let sizing_properties_apply = b.image.is_some()
        || b.text_input.is_some()
        || b.checkable_input.is_some()
        || b.media.is_some()
        || b.style.display() != Display::Inline;
    let mut resolved_content_width = if sizing_properties_apply {
        box_model::resolve_width(&b.style)
            .map(|w| w.resolve(fill_width))
            .unwrap_or(natural_content_width)
    } else {
        natural_content_width
    };
    if sizing_properties_apply {
        if let Some(max_w) = box_model::resolve_max_width(&b.style) {
            resolved_content_width = resolved_content_width.min(max_w.resolve(fill_width));
        }
        if let Some(min_w) = box_model::resolve_min_width(&b.style) {
            resolved_content_width = resolved_content_width.max(min_w.resolve(fill_width));
        }
    }
    b.rect.width = resolved_content_width + b.border.horizontal() + b.padding.horizontal();

    let content_width = (b.rect.width - b.border.horizontal() - b.padding.horizontal()).max(0.0);
    let content_x = b.rect.x + b.border.left + b.padding.left;
    let content_y = b.rect.y + b.border.top + b.padding.top;

    if let Some(image) = &b.image {
        // Height follows from whatever width was actually resolved
        // above (already capped to fit, per `shrinks_to_fit`) so the
        // image's own aspect ratio is always preserved, never
        // distorted — an image box never has children/text to derive
        // height from the normal way.
        let aspect_ratio = if image.width > 0 {
            image.height as f32 / image.width as f32
        } else {
            0.0
        };
        let natural_content_height = content_width * aspect_ratio;
        b.rect.height = resolve_content_height(&b.style, natural_content_height)
            + b.border.vertical()
            + b.padding.vertical();
        return;
    }

    // A text-editable `<input>` — real single-line text (see
    // `TextInputContent`'s own doc comment on why there's no wrapping/
    // clipping), with a resolved cursor position only when `focus`
    // names THIS box's own node. Reached instead of the `text` branch
    // below since an `<input>` is a void element with no text-node
    // children of its own — its displayed content comes entirely from
    // its `value` attribute, resolved into `TextInputContent` back in
    // `build_layout_tree_inner`.
    let dom_node_id = b.dom_node_id;
    if let Some(input) = &mut b.text_input {
        input.text_x = content_x;
        input.text_y = content_y;
        input.cursor_x = focus.and_then(|(focused_id, cursor_char_index)| {
            (focused_id == dom_node_id).then(|| {
                let prefix: String = input.value.chars().take(cursor_char_index).collect();
                content_x + text::measure_text_width(font, &prefix, input.font_size)
            })
        });

        let natural_content_height = text::line_height(font, input.font_size);
        b.rect.height = resolve_content_height(&b.style, natural_content_height)
            + b.border.vertical()
            + b.padding.vertical();
        return;
    }

    if let Some(text) = &mut b.text {
        // Reached only when a text box is laid out outside any inline
        // run (see `layout_inline_run`'s doc comment) — a defensive
        // fallback, e.g. a text box as the `layout()` root. Every line
        // starts at this box's own content edge, since there's no
        // sibling run to have pushed the cursor sideways first.
        let raw_lines = text::wrap_text(font, &text.raw, text.font_size, content_width.max(1.0));
        let line_height = text::line_height(font, text.font_size);
        text.lines = raw_lines
            .into_iter()
            .enumerate()
            .map(|(i, line)| PositionedLine {
                text: line,
                x: content_x,
                y: content_y + i as f32 * line_height,
            })
            .collect();
        b.rect.height = text.lines.len() as f32 * line_height;
        return;
    }

    // `display: flex`/`grid` containers get their own formatting
    // context entirely (see `flex`/`grid`'s own module docs for scope)
    // — dispatched here, before the empty-children fallback below,
    // since an empty flex/grid container's real content height is
    // genuinely zero, not `DEFAULT_LINE_HEIGHT` (that fallback is
    // itself a documented block-layout simplification — see this
    // module's own docs — that flex/grid have no reason to inherit).
    match b.style.display() {
        Display::Flex if b.style.flex_direction() == css::FlexDirection::Column => {
            let content_height =
                flex::layout_flex_column(b, content_x, content_y, content_width, font);
            b.rect.height = resolve_content_height(&b.style, content_height)
                + b.border.vertical()
                + b.padding.vertical();
            return;
        }
        Display::Flex => {
            let content_height =
                flex::layout_flex_row(b, content_x, content_y, content_width, font);
            b.rect.height = resolve_content_height(&b.style, content_height)
                + b.border.vertical()
                + b.padding.vertical();
            return;
        }
        Display::Grid => {
            let content_height = grid::layout_grid(b, content_x, content_y, content_width, font);
            b.rect.height = resolve_content_height(&b.style, content_height)
                + b.border.vertical()
                + b.padding.vertical();
            return;
        }
        _ => {}
    }

    if b.children.is_empty() {
        b.rect.height = resolve_content_height(&b.style, DEFAULT_LINE_HEIGHT)
            + b.border.vertical()
            + b.padding.vertical();
        return;
    }

    // Walk children in source order, processing each maximal run of
    // same-formatting-context siblings together: a run of block-level
    // children stacks full-width top-to-bottom (as before); a run of
    // inline-level children (text boxes and `display: inline`
    // elements) flows left-to-right and wraps into line boxes. This
    // gets the same visual result as synthesizing an anonymous block
    // box around each inline run would, without needing to change the
    // tree shape — see module docs for this approach's scope.
    let mut cursor_y = content_y;
    let mut pending_margin = 0.0f32;
    let mut at_container_start = true;
    // Floats active within THIS container's own block-stacking loop —
    // see this crate's module docs (the "floats" section) for the
    // full design and its scope. Deliberately reset per container:
    // floats here don't propagate their exclusion effect into nested
    // block children's own inline content, only this container's own
    // direct inline runs see them.
    let mut active_floats: Vec<FloatBox> = Vec::new();
    let mut i = 0;
    while i < b.children.len() {
        let inline_run = is_inline_level(&b.children[i]);
        let run_end = b.children[i..]
            .iter()
            .position(|c| is_inline_level(c) != inline_run)
            .map(|offset| i + offset)
            .unwrap_or(b.children.len());

        if inline_run {
            cursor_y += pending_margin;
            pending_margin = 0.0;
            cursor_y += layout_inline_run(
                &mut b.children[i..run_end],
                cursor_y,
                content_x,
                content_width,
                font,
                &active_floats,
                focus,
            );
            at_container_start = false;
        } else {
            for child in &mut b.children[i..run_end] {
                // An out-of-flow child (`position: absolute`/`fixed`)
                // is removed from normal flow entirely — real CSS: it
                // neither takes space nor participates in margin
                // collapsing, so subsequent siblings lay out exactly
                // as if it weren't there at all. It still gets a real
                // `layout_box` call (to resolve its own width/height,
                // and to run its own children's layout) at today's
                // flow position — that becomes its real final
                // position if it has no `top`/`right`/`bottom`/`left`
                // of its own (CSS's "static position" fallback,
                // handled for free this way — see
                // `apply_positioning`'s doc comment), or gets
                // overridden by that second pass if it does.
                //
                // Scope, deliberately narrow: this only excludes
                // out-of-flow children from the BLOCK-stacking loop —
                // one inside a run of INLINE-level siblings (handled
                // by `layout_inline_run` instead) still consumes
                // inline flow space today. Out-of-flow elements are
                // overwhelmingly authored as `display: block` in
                // practice (dropdowns, modals, badges), so this covers
                // the common case.
                if matches!(
                    child.style.position(),
                    css::Position::Absolute | css::Position::Fixed
                ) {
                    layout_box(
                        child,
                        content_x,
                        cursor_y,
                        content_width,
                        font,
                        false,
                        focus,
                    );
                    continue;
                }
                // A `float: left`/`right` child is likewise removed
                // from normal flow (doesn't advance `cursor_y` or
                // participate in margin collapsing) but, unlike
                // absolute/fixed, stays around to narrow subsequent
                // INLINE content in this same container — see
                // `place_float`/`line_bounds`.
                let float_side = child.style.float();
                if float_side != css::Float::None {
                    let placed = place_float(
                        child,
                        float_side,
                        content_x,
                        content_width,
                        cursor_y,
                        font,
                        &active_floats,
                        focus,
                    );
                    active_floats.push(placed);
                    continue;
                }
                // `clear: left/right/both` pushes this box down past
                // any active float(s) on the cleared side(s) before
                // it's placed — real CSS's "clearfix" mechanism.
                let clear = child.style.clear();
                if clear != css::Clear::None {
                    let clear_left = matches!(clear, css::Clear::Left | css::Clear::Both);
                    let clear_right = matches!(clear, css::Clear::Right | css::Clear::Both);
                    let clear_y = active_floats
                        .iter()
                        .filter(|f| {
                            (clear_left && f.side == css::Float::Left)
                                || (clear_right && f.side == css::Float::Right)
                        })
                        .map(|f| f.rect.y + f.rect.height)
                        .fold(cursor_y, f32::max);
                    cursor_y = cursor_y.max(clear_y);
                }
                // `b`'s own top margin already collapsed through this
                // exact chain when `b` itself was placed (see
                // `effective_top_margin`, same eligibility rule,
                // `is_root` included) — so the true first child sits
                // flush at `b`'s content edge instead of collapsing
                // against `pending_margin` normally.
                let collapses_with_container =
                    at_container_start && !is_root && b.border.top == 0.0 && b.padding.top == 0.0;
                let collapsed_gap = if collapses_with_container {
                    0.0
                } else {
                    pending_margin.max(effective_top_margin(child))
                };
                let adjusted_y = cursor_y - child.margin.top + collapsed_gap;
                layout_box(
                    child,
                    content_x,
                    adjusted_y,
                    content_width,
                    font,
                    false,
                    focus,
                );
                cursor_y = child.rect.y + child.rect.height;
                pending_margin = effective_bottom_margin(child);
                at_container_start = false;
            }
        }
        i = run_end;
    }
    // If `b` has no bottom border/padding, the trailing margin from
    // the last child escapes through `b`'s own bottom edge instead of
    // taking up space inside it — mirroring `effective_bottom_margin`'s
    // own eligibility check, since that's what `b`'s next sibling (or
    // parent) will use to find out about this same margin.
    if is_root || b.border.bottom != 0.0 || b.padding.bottom != 0.0 {
        cursor_y += pending_margin;
    }
    // A container implicitly contains its own floats' full height —
    // otherwise a `<div>` holding only a floated child would collapse
    // to (near) zero height, the classic pre-`clearfix` CSS quirk.
    // Containing them by default, unconditionally, rather than only
    // under specific `overflow`/`display: flow-root` triggers (as real
    // CSS spec requires) is a deliberate simplification: it's a
    // strictly more USEFUL default for this crate's purposes than
    // faithfully reproducing a historical footgun.
    if let Some(floats_bottom) = active_floats
        .iter()
        .map(|f| f.rect.y + f.rect.height)
        .reduce(f32::max)
    {
        cursor_y = cursor_y.max(floats_bottom);
    }
    let content_height = cursor_y - content_y;
    b.rect.height = resolve_content_height(&b.style, content_height)
        + b.border.vertical()
        + b.padding.vertical();
}

/// The second layout pass, run once over the whole tree after normal-
/// flow `layout_box` recursion has already finished (called from the
/// top-level `layout()`): applies `position: relative`/`absolute`/
/// `fixed`, walking the tree with the nearest enclosing positioned
/// ancestor's PADDING box as the running `containing_block` (real
/// CSS's own rule for what an absolutely positioned descendant
/// anchors against), and `viewport` (see `layout`'s own doc comment)
/// as the fallback for anything with no positioned ancestor at all, or
/// with `position: fixed` specifically.
///
/// Doing this as a SEPARATE pass over the already-finished tree,
/// rather than threading it through `layout_box` itself, sidesteps a
/// real ordering problem: an out-of-flow box's offset can depend on
/// its containing block's size, but that containing block is often an
/// ANCESTOR whose own final size isn't known until ITS OWN normal-flow
/// children (including this box, laid out at its harmless "static
/// position" placeholder — see `layout_box`'s out-of-flow branch) have
/// all been processed. Re-walking the finished tree afterward means
/// every box's `rect` is already final by the time this runs.
///
/// `position: relative` shifts a box (and, via `shift_subtree`, its
/// entire already-laid-out subtree) from wherever normal flow placed
/// it, WITHOUT affecting where normal flow placed anything else — the
/// real CSS behavior (the space it "would have" taken is preserved).
///
/// `position: absolute`/`fixed` instead REPLACES the box's position
/// outright, computed from `top`/`right`/`bottom`/`left` (each
/// independently — real CSS lets you set only one axis and leave the
/// other at its normal-flow "static position", handled here by simply
/// not moving that axis at all when neither of its two offsets is
/// set). `fixed` is scoped down deliberately: it anchors to the same
/// `viewport` rect `absolute` would if it had no positioned ancestor,
/// which is really "the top of the whole rendered PAGE," not "the
/// live browser window regardless of scroll" — this crate's `layout`
/// has no independent concept of window/viewport height at all (only
/// `viewport_width` is ever threaded in; height is normally derived
/// bottom-up from content, which is exactly why there's no such
/// concept elsewhere in this crate either), and `render::paint`'s
/// `scroll_y` is applied uniformly to every box at PAINT time with no
/// way for this layout pass to exempt one box from it. A real "stays
/// pinned regardless of scroll" `fixed` would need scroll-awareness
/// threaded into `render` itself — a genuinely separate, larger
/// change. Treating `fixed` as "anchor to the page, then scroll away
/// like everything else" is an honest, working approximation in the
/// meantime, not a silent misimplementation.
fn apply_positioning(b: &mut LayoutBox, containing_block: Rect, viewport: Rect) {
    let position = b.style.position();

    let (new_x, new_y) = match position {
        css::Position::Relative => {
            let (dx, dy) = relative_offset(&b.style);
            (b.rect.x + dx, b.rect.y + dy)
        }
        css::Position::Absolute | css::Position::Fixed => {
            let cb = if position == css::Position::Fixed {
                viewport
            } else {
                containing_block
            };
            let (ox, oy) = absolute_offsets(&b.style, b.rect.width, b.rect.height, cb);
            (ox.unwrap_or(b.rect.x), oy.unwrap_or(b.rect.y))
        }
        css::Position::Static => (b.rect.x, b.rect.y),
    };

    let dx = new_x - b.rect.x;
    let dy = new_y - b.rect.y;
    if dx != 0.0 || dy != 0.0 {
        shift_subtree(b, dx, dy);
    }

    // A box establishes a new containing block for ITS OWN descendants
    // exactly when its own position is non-static — matching real
    // CSS's "nearest positioned ancestor" rule.
    let next_containing_block = if position == css::Position::Static {
        containing_block
    } else {
        padding_box(b)
    };
    for child in &mut b.children {
        apply_positioning(child, next_containing_block, viewport);
    }
}

/// `left`/`right` resolve independently of `top`/`bottom` — a box can
/// set only one axis, e.g. `position: relative; top: 10px;` with no
/// `left`/`right` at all, and real CSS leaves the OTHER axis exactly
/// where normal flow put it. `left` wins over `right` when both are
/// set (this crate has no bidi/RTL support anywhere — see `text`'s own
/// module docs — so there's no `direction: rtl` case where the real
/// spec would prefer `right` instead); same for `top` over `bottom`.
fn relative_offset(style: &css::ComputedStyle) -> (f32, f32) {
    let dx = match (style.left(), style.right()) {
        (Some(l), _) => l,
        (None, Some(r)) => -r,
        (None, None) => 0.0,
    };
    let dy = match (style.top(), style.bottom()) {
        (Some(t), _) => t,
        (None, Some(b)) => -b,
        (None, None) => 0.0,
    };
    (dx, dy)
}

/// Resolves an absolutely/fixed positioned box's new (x, y) against
/// `cb` (its containing block), independently per axis — `None` for
/// an axis means "neither offset on that axis was set," which
/// `apply_positioning` takes as "leave that axis at its static-flow
/// position" rather than moving it to `cb`'s own origin. `width`/
/// `height` are the box's own already-resolved size (needed to
/// convert a `right`/`bottom` offset — measured from the containing
/// block's FAR edge — into the box's own near-edge x/y this crate's
/// `rect` is always expressed in).
fn absolute_offsets(
    style: &css::ComputedStyle,
    width: f32,
    height: f32,
    cb: Rect,
) -> (Option<f32>, Option<f32>) {
    let new_x = match (style.left(), style.right()) {
        (Some(left), _) => Some(cb.x + left),
        (None, Some(right)) => Some(cb.x + cb.width - width - right),
        (None, None) => None,
    };
    let new_y = match (style.top(), style.bottom()) {
        (Some(top), _) => Some(cb.y + top),
        (None, Some(bottom)) => Some(cb.y + cb.height - height - bottom),
        (None, None) => None,
    };
    (new_x, new_y)
}

/// The padding-box rect of `b` — `b.rect` minus its own border (this
/// crate's box model always includes border+padding in `rect`, see
/// `LayoutBox`'s own doc comment) — what a positioned box's own
/// descendants anchor against, matching real CSS's containing-block
/// rule for absolutely positioned elements.
fn padding_box(b: &LayoutBox) -> Rect {
    Rect {
        x: b.rect.x + b.border.left,
        y: b.rect.y + b.border.top,
        width: (b.rect.width - b.border.horizontal()).max(0.0),
        height: (b.rect.height - b.border.vertical()).max(0.0),
    }
}

/// Moves `b` (and recursively, every descendant, and every already-
/// resolved text line position) by `(dx, dy)` — the one primitive
/// `apply_positioning` needs: once a box's position changes, its
/// entire already-laid-out subtree has to move WITH it (children's
/// coordinates were resolved as absolute values during normal-flow
/// layout, relative to the OLD position), rather than staying behind.
fn shift_subtree(b: &mut LayoutBox, dx: f32, dy: f32) {
    b.rect.x += dx;
    b.rect.y += dy;
    if let Some(text) = &mut b.text {
        for line in &mut text.lines {
            line.x += dx;
            line.y += dy;
        }
    }
    for child in &mut b.children {
        shift_subtree(child, dx, dy);
    }
}

/// One indivisible unit considered while packing an inline run.
/// `path` is a chain of child indices identifying exactly which
/// `LayoutBox` this item belongs to — possibly several levels of
/// inline nesting deep (e.g. `[1, 0]` means "the run's child at index
/// 1, then ITS child at index 0"). Splitting text down to `Word`s —
/// including text that lives inside a nested `display: inline`
/// element, not just the run's own direct children — is what lets
/// text flow word-by-word through arbitrarily nested inline markup
/// (`text <span><a>click</a> here</span> more text`) instead of
/// stopping at whatever nesting level the run started at. See
/// `flatten_inline_items` for how `path` gets built up, and
/// `child_at_path_mut` for how it's used to write results back.
enum InlineItem {
    Word {
        path: Vec<usize>,
        word: String,
        width: f32,
        font_size: f32,
    },
    Box {
        path: Vec<usize>,
        /// Natural width, own margin included, already capped at the
        /// run's full content width.
        outer_width: f32,
    },
    /// A purely-whitespace text node — e.g. the text node real HTML
    /// gets between `<a>Login</a> <a>Register</a>` from the space in
    /// the source. It carries no visible content of its own (nothing
    /// to paint, no owning child to record a line against), but it's
    /// a real collapsible space in the flow: without this, two inline
    /// *elements* separated only by whitespace in the source pack
    /// directly edge-to-edge with no gap, since neither `Word`
    /// splitting nor `Box` packing otherwise account for the
    /// whitespace between two non-text siblings.
    Space,
}

/// Walks a `path` (as built by `flatten_inline_items`) down through
/// nested `children` to reach the exact `LayoutBox` it identifies.
/// Each step re-borrows before indexing again, which is why this
/// needs to be a loop rather than a single chained expression — the
/// borrow checker is fine with it this way (a common pattern for
/// walking into nested `&mut` trees one level at a time).
fn child_at_path_mut<'a>(children: &'a mut [LayoutBox], path: &[usize]) -> &'a mut LayoutBox {
    let mut node = &mut children[path[0]];
    for &idx in &path[1..] {
        node = &mut node.children[idx];
    }
    node
}

/// Recursively splits a run's children — descending into any nested
/// `display: inline` element's own children too, arbitrarily deep —
/// into `InlineItem`s in source order. A text box with real words
/// becomes one `Word` per whitespace-separated word; a purely
/// whitespace text box becomes one collapsible `Space`
/// (`InlineItem::Space`); anything else (a non-text, non-inline
/// child — e.g. a stray `display: block` element sitting inside
/// inline content, however deep) becomes one atomic `Box`.
fn flatten_inline_items(
    children: &[LayoutBox],
    font: &Font,
    content_width: f32,
) -> Vec<InlineItem> {
    let mut items = Vec::new();
    let mut path = Vec::new();
    flatten_inline_items_into(children, &mut path, font, content_width, &mut items);
    items
}

fn flatten_inline_items_into(
    children: &[LayoutBox],
    path: &mut Vec<usize>,
    font: &Font,
    content_width: f32,
    items: &mut Vec<InlineItem>,
) {
    for (child_index, child) in children.iter().enumerate() {
        path.push(child_index);
        if let Some(text) = &child.text {
            if text.raw.trim().is_empty() {
                if !text.raw.is_empty() {
                    items.push(InlineItem::Space);
                }
            } else {
                for word in text.raw.split_whitespace() {
                    let width = text::measure_text_width(font, word, text.font_size);
                    items.push(InlineItem::Word {
                        path: path.clone(),
                        word: word.to_string(),
                        width,
                        font_size: text.font_size,
                    });
                }
            }
        } else if child.style.display() == Display::Inline && !child.children.is_empty() {
            // Recurse into a nested inline element's own children
            // instead of treating the whole element as one atomic
            // unit — this is what lets text flow word-by-word THROUGH
            // it rather than stopping at its boundary.
            flatten_inline_items_into(&child.children, path, font, content_width, items);
        } else {
            let outer_width =
                (intrinsic_width(child, font) + child.margin.horizontal()).min(content_width);
            items.push(InlineItem::Box {
                path: path.clone(),
                outer_width,
            });
        }
        path.pop();
    }
}

/// Closes out whatever text is currently accumulating for one path
/// (if any) into a finished `PositionedLine` at `cursor_y`, and clears
/// the accumulator. Called whenever a line wraps or the run moves on
/// to a different path, since a given path's contribution to a given
/// visual row can only ever be written once (paths are processed in a
/// single left-to-right pass, never revisited).
fn flush_text_run(
    current_text_path: &mut Option<Vec<usize>>,
    current_line_text: &mut String,
    current_line_start_x: f32,
    cursor_y: f32,
    lines_by_path: &mut HashMap<Vec<usize>, Vec<PositionedLine>>,
) {
    if let Some(path) = current_text_path.take() {
        if !current_line_text.is_empty() {
            lines_by_path.entry(path).or_default().push(PositionedLine {
                text: std::mem::take(current_line_text),
                x: current_line_start_x,
                y: cursor_y,
            });
        }
        current_line_text.clear();
    }
}

/// Every proper prefix of `path`, shortest first — e.g. `[1, 0, 2]`
/// yields `[1]`, then `[1, 0]`. Used to grow the bounding box of every
/// ANCESTOR a leaf item's path passes through (a leaf's immediate
/// parent might itself be a nested inline element that was recursed
/// into, whose own `rect` needs to end up spanning everything placed
/// under it — see the write-back pass in `layout_inline_run`).
fn proper_prefixes(path: &[usize]) -> impl Iterator<Item = &[usize]> {
    (1..path.len()).map(move |len| &path[..len])
}

/// Lays out one maximal run of consecutive inline-level siblings as
/// wrapped horizontal line boxes — a real (if simplified) inline
/// formatting context: text is split into words (`flatten_inline_items`,
/// recursing into nested inline elements too) so it can pack right up
/// against a sibling and keep flowing on the same line, wrapping only
/// when a word or element genuinely doesn't fit. Returns the total
/// height the run consumed, so the caller can advance its own cursor
/// past it exactly like a single block child.
///
/// A word or element that doesn't fit even alone on an empty line
/// still gets the full line width and is allowed to wrap/overflow
/// internally, the same tolerance `text::wrap_text` gives an overlong
/// single word.
///
/// Nested inline elements' own `rect` (e.g. an `<a>` whose text got
/// split word-by-word) is set to the bounding box of everywhere its
/// content landed — if that content wrapped across more than one
/// line, this is a single box spanning all of them, NOT the several
/// per-line fragments a real browser would generate for a wrapped
/// inline element. Good enough for the common case (a short link/span
/// on one line); a multi-line-wrapped inline element's hit-testing/
/// visual bounds would be wrong if this ever mattered for something
/// like click-target sizing.
///
/// `active_floats` (see `layout_box`'s module-doc "floats" section)
/// narrows each line's `[left, right)` bounds via `line_bounds` —
/// empty for a container with no active floats, in which case every
/// line just gets the full `[content_x, content_x + content_width)`
/// exactly as before this feature existed.
fn layout_inline_run(
    children: &mut [LayoutBox],
    start_y: f32,
    content_x: f32,
    content_width: f32,
    font: &Font,
    active_floats: &[FloatBox],
    focus: Option<(dom::NodeId, usize)>,
) -> f32 {
    let items = flatten_inline_items(children, font, content_width);
    let space_width = text::measure_text_width(font, " ", DEFAULT_FONT_SIZE);

    let (initial_left, _) = line_bounds(active_floats, content_x, content_width, start_y);
    let mut cursor_x = initial_left;
    let mut cursor_y = start_y;
    let mut line_has_content = false;
    let mut max_line_height_on_row: f32 = 0.0;

    // The path (if any) currently accumulating words for the line in
    // progress, and the line text/start built up so far.
    let mut current_text_path: Option<Vec<usize>> = None;
    let mut current_line_text = String::new();
    let mut current_line_start_x = initial_left;
    let mut lines_by_path: HashMap<Vec<usize>, Vec<PositionedLine>> = HashMap::new();

    // Bounding box (min_x, min_y, max_x, max_y) for every ANCESTOR
    // path a leaf item was placed under — i.e. every nested inline
    // element that got recursed into rather than treated as an atomic
    // `Box`. Grown as each leaf is placed; written back to those
    // elements' own `rect` after the packing loop.
    let mut bounds_by_ancestor_path: HashMap<Vec<usize>, (f32, f32, f32, f32)> = HashMap::new();
    let mut grow_bounds = |path: &[usize], x0: f32, y0: f32, x1: f32, y1: f32| {
        for prefix in proper_prefixes(path) {
            let entry = bounds_by_ancestor_path
                .entry(prefix.to_vec())
                .or_insert((x0, y0, x1, y1));
            entry.0 = entry.0.min(x0);
            entry.1 = entry.1.min(y0);
            entry.2 = entry.2.max(x1);
            entry.3 = entry.3.max(y1);
        }
    };

    macro_rules! flush {
        () => {
            flush_text_run(
                &mut current_text_path,
                &mut current_line_text,
                current_line_start_x,
                cursor_y,
                &mut lines_by_path,
            )
        };
    }

    for item in items {
        match item {
            InlineItem::Word {
                path,
                word,
                width,
                font_size,
            } => {
                let joining_same_word_run = current_text_path.as_deref() == Some(path.as_slice())
                    && !current_line_text.is_empty();
                let extra = if joining_same_word_run {
                    space_width + width
                } else {
                    width
                };
                let (_, line_right) =
                    line_bounds(active_floats, content_x, content_width, cursor_y);
                let remaining = line_right - cursor_x;

                if line_has_content && extra > remaining {
                    flush!();
                    cursor_y += max_line_height_on_row;
                    cursor_x = line_bounds(active_floats, content_x, content_width, cursor_y).0;
                    max_line_height_on_row = 0.0;
                } else if current_text_path.as_deref() != Some(path.as_slice()) {
                    flush!();
                }

                if current_text_path.as_deref() != Some(path.as_slice()) {
                    current_text_path = Some(path.clone());
                    current_line_start_x = cursor_x;
                    current_line_text.clear();
                }

                let word_start_x = if current_line_text.is_empty() {
                    cursor_x
                } else {
                    current_line_text.push(' ');
                    cursor_x += space_width;
                    cursor_x
                };
                current_line_text.push_str(&word);
                cursor_x += width;
                let line_height = text::line_height(font, font_size);
                max_line_height_on_row = max_line_height_on_row.max(line_height);
                grow_bounds(
                    &path,
                    word_start_x,
                    cursor_y,
                    cursor_x,
                    cursor_y + line_height,
                );
                line_has_content = true;
            }
            InlineItem::Box { path, outer_width } => {
                flush!();
                let remaining =
                    line_bounds(active_floats, content_x, content_width, cursor_y).1 - cursor_x;
                if line_has_content && outer_width > remaining {
                    cursor_y += max_line_height_on_row;
                    cursor_x = line_bounds(active_floats, content_x, content_width, cursor_y).0;
                    max_line_height_on_row = 0.0;
                }

                let available_for_child =
                    line_bounds(active_floats, content_x, content_width, cursor_y).1 - cursor_x;
                layout_box(
                    child_at_path_mut(children, &path),
                    cursor_x,
                    cursor_y,
                    available_for_child,
                    font,
                    false,
                    focus,
                );

                // Re-derive the reference fresh rather than holding
                // one across the `layout_box` call above.
                let (box_y, box_height, box_margin_bottom, box_margin_vertical) = {
                    let child = child_at_path_mut(children, &path);
                    (
                        child.rect.y,
                        child.rect.height,
                        child.margin.bottom,
                        child.margin.vertical(),
                    )
                };

                let used_width = outer_width.min(available_for_child).max(0.0);
                let box_bottom = box_y + box_height + box_margin_bottom;
                grow_bounds(&path, cursor_x, cursor_y, cursor_x + used_width, box_bottom);
                cursor_x += used_width;
                max_line_height_on_row =
                    max_line_height_on_row.max(box_height + box_margin_vertical);
                line_has_content = true;
            }
            InlineItem::Space => {
                // Whitespace always breaks word-joining eligibility
                // (it ends whatever text run was accumulating), and
                // it collapses to nothing at the start of a line —
                // real CSS drops leading/trailing whitespace rather
                // than let it force a wrap or leave a visible gap at
                // the line edge.
                flush!();
                if line_has_content {
                    cursor_x += space_width;
                }
            }
        }
    }
    flush!();
    if line_has_content {
        cursor_y += max_line_height_on_row;
    }

    // Write each text path's accumulated lines and resolved geometry
    // back onto the LayoutBox it belongs to — the word-level
    // equivalent of what `layout_box`'s own text branch does for a
    // standalone text box.
    for (path, lines) in lines_by_path {
        let child = child_at_path_mut(children, &path);
        if let Some(text) = &mut child.text {
            child.rect.x = lines.first().map(|l| l.x).unwrap_or(content_x);
            child.rect.y = lines.first().map(|l| l.y).unwrap_or(start_y);
            child.rect.height = lines.len() as f32 * text::line_height(font, text.font_size);
            child.rect.width = lines
                .iter()
                .map(|l| text::measure_text_width(font, &l.text, text.font_size))
                .fold(0.0, f32::max);
            text.lines = lines;
        }
    }

    // Write back the bounding box of every nested inline element that
    // got recursed into (rather than treated as an atomic `Box`) — see
    // this function's doc comment for the multi-line-wrap caveat.
    for (path, (x0, y0, x1, y1)) in bounds_by_ancestor_path {
        let el = child_at_path_mut(children, &path);
        el.rect.x = x0;
        el.rect.y = y0;
        el.rect.width = (x1 - x0).max(0.0);
        el.rect.height = (y1 - y0).max(0.0);
        // This element was recursed into as inline TEXT content rather
        // than laid out via `layout_box` itself (see this function's
        // own doc comment) — the one other place besides `layout_box`
        // and `place_float` that has to set `LayoutBox::focused`
        // itself, or a focused link/span made of nothing but text
        // (the common case for a real `<a>`) would never get a ring.
        el.focused = matches!(focus, Some((focused_id, _)) if focused_id == el.dom_node_id);
    }

    cursor_y - start_y
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_image(width: u32, height: u32) -> ImageContent {
        ImageContent {
            width,
            height,
            pixels: vec![0u8; (width * height * 4) as usize],
        }
    }

    #[test]
    fn an_image_gets_its_natural_dimensions_when_it_fits() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        let img = dom::Node::new_element("img");
        let img_id = img.borrow().id;
        dom::append_child(&document, img);

        let mut images = HashMap::new();
        images.insert(img_id, fake_image(200, 100));

        let font = text::load_default_font();
        let mut tree = build_layout_tree_with_images(&document, &stylesheet, &images);
        layout(&mut tree, 800.0, &font);

        let img_box = &tree.children[0];
        assert_eq!(img_box.rect.width, 200.0);
        assert_eq!(img_box.rect.height, 100.0);
    }

    #[test]
    fn an_image_wider_than_its_container_shrinks_but_keeps_its_aspect_ratio() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        let img = dom::Node::new_element("img");
        let img_id = img.borrow().id;
        dom::append_child(&document, img);

        let mut images = HashMap::new();
        images.insert(img_id, fake_image(400, 200)); // 2:1 aspect ratio

        let font = text::load_default_font();
        let mut tree = build_layout_tree_with_images(&document, &stylesheet, &images);
        layout(&mut tree, 100.0, &font); // narrower than the image's natural 400px width

        let img_box = &tree.children[0];
        assert_eq!(
            img_box.rect.width, 100.0,
            "should shrink to fit the 100px viewport"
        );
        assert_eq!(
            img_box.rect.height, 50.0,
            "height should scale down to preserve the 2:1 aspect ratio"
        );
    }

    #[test]
    fn an_image_never_stretches_beyond_its_natural_size_even_in_a_wide_container() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        let img = dom::Node::new_element("img");
        let img_id = img.borrow().id;
        dom::append_child(&document, img);

        let mut images = HashMap::new();
        images.insert(img_id, fake_image(50, 50));

        let font = text::load_default_font();
        let mut tree = build_layout_tree_with_images(&document, &stylesheet, &images);
        layout(&mut tree, 800.0, &font);

        let img_box = &tree.children[0];
        assert_eq!(
            img_box.rect.width, 50.0,
            "a small image must not stretch to fill a much wider container"
        );
    }

    #[test]
    fn an_img_element_with_no_matching_decoded_image_has_no_image_content() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        dom::append_child(&document, dom::Node::new_element("img"));

        // Plain `build_layout_tree` (no images map at all) — the
        // common case for every non-renderer caller (e.g. `app`'s
        // locally-built `about:` pages).
        let tree = build_layout_tree(&document, &stylesheet);
        assert!(tree.children[0].image.is_none());
    }

    #[test]
    fn two_images_flow_side_by_side_like_other_inline_content() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        let img1 = dom::Node::new_element("img");
        let img1_id = img1.borrow().id;
        let img2 = dom::Node::new_element("img");
        let img2_id = img2.borrow().id;
        dom::append_child(&document, img1);
        dom::append_child(&document, img2);

        let mut images = HashMap::new();
        images.insert(img1_id, fake_image(50, 50));
        images.insert(img2_id, fake_image(50, 50));

        let font = text::load_default_font();
        let mut tree = build_layout_tree_with_images(&document, &stylesheet, &images);
        layout(&mut tree, 800.0, &font);

        assert_eq!(
            tree.children[0].rect.y, tree.children[1].rect.y,
            "images are inline by default and should share a line"
        );
        assert!(tree.children[1].rect.x > tree.children[0].rect.x);
    }

    #[test]
    fn hit_test_finds_the_href_of_a_clicked_link() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        let p = dom::Node::new_element("p");
        let a = dom::Node::new_element("a");
        {
            let mut a_mut = a.borrow_mut();
            if let dom::NodeType::Element(el) = &mut a_mut.node_type {
                el.attributes
                    .insert("href".to_string(), "/forum".to_string());
            }
        }
        dom::append_child(&a, dom::Node::new_text("Forum"));
        dom::append_child(&p, a);
        dom::append_child(&document, p);

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 400.0, &font);

        let a_box = &tree.children[0].children[0];
        // Click squarely inside the anchor's own resolved box.
        let click_x = a_box.rect.x + 1.0;
        let click_y = a_box.rect.y + 1.0;

        assert_eq!(
            hit_test_link(&tree, click_x, click_y),
            Some(LinkHit {
                href: "/forum".to_string(),
                download: None,
            })
        );
    }

    #[test]
    fn hit_test_returns_none_when_clicking_outside_any_link() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        let p = dom::Node::new_element("p");
        dom::append_child(&p, dom::Node::new_text("no links here"));
        dom::append_child(&document, p);

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 400.0, &font);

        assert_eq!(hit_test_link(&tree, 5.0, 5.0), None);
        // Far outside the page entirely.
        assert_eq!(hit_test_link(&tree, 99999.0, 99999.0), None);
    }

    #[test]
    fn hit_test_reports_a_download_attribute_including_when_it_has_no_value() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        let a = dom::Node::new_element("a");
        {
            let mut a_mut = a.borrow_mut();
            if let dom::NodeType::Element(el) = &mut a_mut.node_type {
                el.attributes
                    .insert("href".to_string(), "/file.zip".to_string());
                el.attributes
                    .insert("download".to_string(), "report.zip".to_string());
            }
        }
        dom::append_child(&a, dom::Node::new_text("Get the file"));
        dom::append_child(&document, a);

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 400.0, &font);

        let a_box = &tree.children[0];
        let hit = hit_test_link(&tree, a_box.rect.x + 1.0, a_box.rect.y + 1.0)
            .expect("should hit the link");
        assert_eq!(hit.href, "/file.zip");
        assert_eq!(hit.download, Some("report.zip".to_string()));
    }

    #[test]
    fn hit_test_reports_no_download_for_an_ordinary_link() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        let a = dom::Node::new_element("a");
        {
            let mut a_mut = a.borrow_mut();
            if let dom::NodeType::Element(el) = &mut a_mut.node_type {
                el.attributes
                    .insert("href".to_string(), "/page".to_string());
            }
        }
        dom::append_child(&a, dom::Node::new_text("Go"));
        dom::append_child(&document, a);

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 400.0, &font);

        let a_box = &tree.children[0];
        let hit = hit_test_link(&tree, a_box.rect.x + 1.0, a_box.rect.y + 1.0)
            .expect("should hit the link");
        assert_eq!(hit.download, None);
    }

    /// Builds an `<audio controls>` element with the given decoded
    /// duration, laid out against a real UA stylesheet — shared by
    /// several `hit_test_media_control` tests below.
    fn layout_single_audio_with_controls(duration_secs: f32) -> (LayoutBox, dom::NodeId) {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        let audio = dom::Node::new_element("audio");
        let audio_id = audio.borrow().id;
        {
            let mut el_mut = audio.borrow_mut();
            if let dom::NodeType::Element(el) = &mut el_mut.node_type {
                el.attributes.insert("controls".to_string(), String::new());
            }
        }
        dom::append_child(&document, audio);

        let mut media = HashMap::new();
        media.insert(
            audio_id,
            MediaAsset {
                kind: MediaKind::Audio,
                controls: true,
                duration_secs,
                poster: None,
            },
        );

        let font = text::load_default_font();
        let mut tree =
            build_layout_tree_with_media(&document, &stylesheet, &HashMap::new(), &media);
        layout(&mut tree, 400.0, &font);
        (tree, audio_id)
    }

    #[test]
    fn hit_test_media_control_identifies_play_pause_scrubber_and_mute_regions() {
        let (tree, audio_id) = layout_single_audio_with_controls(100.0);
        let audio_box = &tree.children[0];
        let bar_y = audio_box.rect.y + 1.0;

        assert_eq!(
            hit_test_media_control(&tree, audio_box.rect.x + 1.0, bar_y),
            Some((audio_id, MediaControlHit::PlayPause))
        );
        assert_eq!(
            hit_test_media_control(&tree, audio_box.rect.x + audio_box.rect.width - 1.0, bar_y),
            Some((audio_id, MediaControlHit::ToggleMute))
        );

        let mid_x = audio_box.rect.x + audio_box.rect.width / 2.0;
        match hit_test_media_control(&tree, mid_x, bar_y) {
            Some((id, MediaControlHit::Seek(fraction))) => {
                assert_eq!(id, audio_id);
                assert!((0.0..=1.0).contains(&fraction));
            }
            other => panic!("expected a Seek hit, got {other:?}"),
        }
    }

    #[test]
    fn hit_test_media_control_seek_fraction_increases_left_to_right() {
        let (tree, _) = layout_single_audio_with_controls(100.0);
        let audio_box = &tree.children[0];
        let bar_y = audio_box.rect.y + 1.0;

        let near_start = audio_box.rect.x + MEDIA_PLAY_BUTTON_WIDTH + 2.0;
        let near_end = audio_box.rect.x + audio_box.rect.width
            - MEDIA_MUTE_BUTTON_WIDTH
            - MEDIA_TIME_TEXT_WIDTH
            - 2.0;

        let Some((_, MediaControlHit::Seek(early))) =
            hit_test_media_control(&tree, near_start, bar_y)
        else {
            panic!("expected a Seek hit near the start");
        };
        let Some((_, MediaControlHit::Seek(late))) = hit_test_media_control(&tree, near_end, bar_y)
        else {
            panic!("expected a Seek hit near the end");
        };
        assert!(late > early);
    }

    #[test]
    fn hit_test_media_control_is_none_outside_the_bar() {
        let (tree, _) = layout_single_audio_with_controls(100.0);
        assert_eq!(hit_test_media_control(&tree, -50.0, -50.0), None);
    }

    #[test]
    fn hit_test_media_control_is_none_without_any_decoded_duration() {
        // `duration_secs: 0.0` — nothing actually decoded (a failed
        // fetch, an unsupported format) — clicking should do nothing,
        // same as a real browser's disabled-looking controls would.
        let (tree, _) = layout_single_audio_with_controls(0.0);
        let audio_box = &tree.children[0];
        assert_eq!(
            hit_test_media_control(&tree, audio_box.rect.x + 1.0, audio_box.rect.y + 1.0),
            None
        );
    }

    #[test]
    fn apply_media_playback_updates_only_the_matching_node() {
        let (mut tree, audio_id) = layout_single_audio_with_controls(100.0);

        let mut playback = HashMap::new();
        playback.insert(
            audio_id,
            MediaPlaybackState {
                playing: true,
                muted: true,
                current_time_secs: 42.0,
            },
        );
        apply_media_playback(&mut tree, &playback);

        let audio_box = &tree.children[0];
        let media = audio_box.media.as_ref().expect("should have media content");
        assert!(media.playing);
        assert!(media.muted);
        assert_eq!(media.current_time_secs, 42.0);
    }

    #[test]
    fn apply_media_playback_leaves_an_untracked_node_at_its_defaults() {
        let (mut tree, _) = layout_single_audio_with_controls(100.0);
        apply_media_playback(&mut tree, &HashMap::new());

        let media = tree.children[0]
            .media
            .as_ref()
            .expect("should have media content");
        assert!(!media.playing);
        assert!(!media.muted);
        assert_eq!(media.current_time_secs, 0.0);
    }

    #[test]
    fn hit_test_node_targets_the_button_even_when_its_own_text_is_the_deepest_box() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        let button = dom::Node::new_element("button");
        let button_id = button.borrow().id;
        dom::append_child(&button, dom::Node::new_text("Save"));
        dom::append_child(&document, button);

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 400.0, &font);

        let text_box = &tree.children[0].children[0];
        assert!(
            text_box.text.is_some(),
            "the deepest box under the button should be its text run"
        );
        let click_x = text_box.rect.x + 1.0;
        let click_y = text_box.rect.y + 1.0;

        // A click that geometrically hits the text run should still
        // resolve to the BUTTON's node id, not the text node's — see
        // `hit_test_node`'s doc comment.
        assert_eq!(hit_test_node(&tree, click_x, click_y), Some(button_id));
    }

    #[test]
    fn hit_test_node_returns_none_outside_any_element() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        let p = dom::Node::new_element("p");
        dom::append_child(&p, dom::Node::new_text("hello"));
        dom::append_child(&document, p);

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 400.0, &font);

        assert_eq!(hit_test_node(&tree, 99999.0, 99999.0), None);
    }

    #[test]
    fn hit_test_node_prefers_the_innermost_of_two_nested_elements() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        let outer = dom::Node::new_element("div");
        let inner = dom::Node::new_element("span");
        let inner_id = inner.borrow().id;
        dom::append_child(&inner, dom::Node::new_text("x"));
        dom::append_child(&outer, inner);
        dom::append_child(&document, outer);

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 400.0, &font);

        let outer_box = &tree.children[0];
        let click_x = outer_box.rect.x + 1.0;
        let click_y = outer_box.rect.y + 1.0;

        assert_eq!(hit_test_node(&tree, click_x, click_y), Some(inner_id));
    }

    #[test]
    fn find_box_by_dom_node_id_locates_a_nested_element() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        let outer = dom::Node::new_element("div");
        let inner = dom::Node::new_element("span");
        let inner_id = inner.borrow().id;
        dom::append_child(&inner, dom::Node::new_text("x"));
        dom::append_child(&outer, inner);
        dom::append_child(&document, outer);

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 400.0, &font);

        let found = find_box_by_dom_node_id(&tree, inner_id).expect("inner span should be found");
        assert_eq!(found.dom_node_id, inner_id);
        assert!(matches!(found.node_type, NodeType::Element(_)));
    }

    #[test]
    fn find_box_by_dom_node_id_returns_none_for_a_display_none_element() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        let script = dom::Node::new_element("script");
        let script_id = script.borrow().id;
        dom::append_child(&document, script);

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 400.0, &font);

        assert!(find_box_by_dom_node_id(&tree, script_id).is_none());
    }

    #[test]
    fn find_focused_dom_node_id_locates_whichever_box_is_marked_focused() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        let first = input_with_value("a");
        let first_id = first.borrow().id;
        let second = input_with_value("b");
        dom::append_child(&document, first);
        dom::append_child(&document, second);

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout_with_focus(&mut tree, 400.0, &font, Some((first_id, 0)));

        assert_eq!(find_focused_dom_node_id(&tree), Some(first_id));
    }

    #[test]
    fn find_focused_dom_node_id_is_none_when_nothing_is_focused() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        dom::append_child(&document, input_with_value("a"));

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 400.0, &font);

        assert_eq!(find_focused_dom_node_id(&tree), None);
    }

    #[test]
    fn stacks_children_vertically() {
        let document = dom::Node::new_document();
        let a = dom::Node::new_element("div");
        let b = dom::Node::new_element("div");
        dom::append_child(&document, a);
        dom::append_child(&document, b);

        let stylesheet = Stylesheet::default();
        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 800.0, &font);

        assert_eq!(tree.children.len(), 2);
        assert!(tree.children[1].rect.y > tree.children[0].rect.y);
    }

    #[test]
    fn text_node_wraps_and_gets_a_multi_line_height() {
        let document = dom::Node::new_document();
        let p = dom::Node::new_element("p");
        let text_node = dom::Node::new_text(
            "this is a fairly long sentence that should wrap across more than one line",
        );
        dom::append_child(&p, text_node);
        dom::append_child(&document, p);

        let stylesheet = Stylesheet::default();
        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 200.0, &font); // narrow width forces wrapping

        let text_box = &tree.children[0].children[0];
        let text_content = text_box.text.as_ref().expect("should be a text box");
        assert!(text_content.lines.len() > 1);
        assert!(text_box.rect.height > DEFAULT_LINE_HEIGHT);
    }

    #[test]
    fn a_font_size_declaration_reaches_the_actual_text_boxs_font_size() {
        let document = dom::Node::new_document();
        let h1 = dom::Node::new_element("h1");
        dom::append_child(&h1, dom::Node::new_text("Big Heading"));
        let p = dom::Node::new_element("p");
        dom::append_child(&p, dom::Node::new_text("Body text"));
        dom::append_child(&document, h1);
        dom::append_child(&document, p);

        let stylesheet = css::parse_stylesheet("h1 { font-size: 32px; }");
        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 800.0, &font);

        let h1_text = tree.children[0].children[0]
            .text
            .as_ref()
            .expect("h1's child should be a text box");
        let p_text = tree.children[1].children[0]
            .text
            .as_ref()
            .expect("p's child should be a text box");
        assert_eq!(h1_text.font_size, 32.0);
        assert_eq!(p_text.font_size, DEFAULT_FONT_SIZE);
    }

    #[test]
    fn color_inherits_from_nearest_ancestor_with_a_color_rule() {
        let stylesheet = css::parse_stylesheet("p { color: #ff0000; }");
        let document = dom::Node::new_document();
        let p = dom::Node::new_element("p");
        let text_node = dom::Node::new_text("hello");
        dom::append_child(&p, text_node);
        dom::append_child(&document, p);

        let tree = build_layout_tree(&document, &stylesheet);
        let text_box = &tree.children[0].children[0];
        assert_eq!(text_box.text.as_ref().unwrap().color_hex, "#ff0000");
    }

    #[test]
    fn margin_offsets_position_but_equal_adjacent_margins_collapse() {
        let stylesheet = css::parse_stylesheet("div { margin: 10px; }");
        let document = dom::Node::new_document();
        let a = dom::Node::new_element("div");
        let b = dom::Node::new_element("div");
        dom::append_child(&document, a);
        dom::append_child(&document, b);

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 800.0, &font);

        let first = &tree.children[0];
        let second = &tree.children[1];
        assert_eq!(first.rect.x, 10.0); // shifted right by its own margin-left
        assert_eq!(first.rect.y, 10.0); // shifted down by its own margin-top
                                        // Adjacent siblings' margins collapse: the gap is max(10, 10)
                                        // = 10, NOT the sum (20) — this is real margin collapsing, not
                                        // the old bug where every box's margin was summed independently.
        assert_eq!(second.rect.y, first.rect.y + first.rect.height + 10.0);
    }

    #[test]
    fn asymmetric_adjacent_margins_collapse_to_the_larger_one() {
        // Equal margins (10 and 10) can't distinguish real collapsing
        // from an accidentally-correct buggy average — asymmetric
        // margins (20 vs 5) can: a real max()-based collapse gives 20,
        // summing gives 25, averaging gives 12.5. Only 20 is correct.
        let stylesheet =
            css::parse_stylesheet(".first { margin-bottom: 20px; } .second { margin-top: 5px; }");
        let document = dom::Node::new_document();
        let a = dom::Node::new_element("div");
        let b = dom::Node::new_element("div");
        {
            let mut a_mut = a.borrow_mut();
            if let dom::NodeType::Element(el) = &mut a_mut.node_type {
                el.attributes
                    .insert("class".to_string(), "first".to_string());
            }
        }
        {
            let mut b_mut = b.borrow_mut();
            if let dom::NodeType::Element(el) = &mut b_mut.node_type {
                el.attributes
                    .insert("class".to_string(), "second".to_string());
            }
        }
        dom::append_child(&document, a);
        dom::append_child(&document, b);

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 800.0, &font);

        let first = &tree.children[0];
        let second = &tree.children[1];
        assert_eq!(second.rect.y, first.rect.y + first.rect.height + 20.0);
    }

    #[test]
    fn parent_and_first_child_top_margins_collapse_when_parent_has_no_border_or_padding() {
        let stylesheet = css::parse_stylesheet("div { margin-top: 10px; } p { margin-top: 40px; }");
        let document = dom::Node::new_document();
        let div = dom::Node::new_element("div");
        let p = dom::Node::new_element("p");
        dom::append_child(&p, dom::Node::new_text("text"));
        dom::append_child(&div, p);
        dom::append_child(&document, div);

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 800.0, &font);

        let div_box = &tree.children[0];
        let p_box = &div_box.children[0];
        assert_eq!(
            div_box.rect.y, 40.0,
            "collapsed margin (max of 10 and 40) is the div's only offset"
        );
        assert_eq!(
            p_box.rect.y, div_box.rect.y,
            "p's margin collapsed into div's — same y"
        );
    }

    #[test]
    fn parent_top_margin_does_not_collapse_through_padding() {
        let stylesheet = css::parse_stylesheet(
            "div { margin-top: 10px; padding-top: 5px; } p { margin-top: 40px; }",
        );
        let document = dom::Node::new_document();
        let div = dom::Node::new_element("div");
        let p = dom::Node::new_element("p");
        dom::append_child(&p, dom::Node::new_text("text"));
        dom::append_child(&div, p);
        dom::append_child(&document, div);

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 800.0, &font);

        let div_box = &tree.children[0];
        let p_box = &div_box.children[0];
        assert_eq!(div_box.rect.y, 10.0);
        assert_eq!(
            p_box.rect.y,
            div_box.rect.y + div_box.border.top + div_box.padding.top + 40.0
        );
    }

    #[test]
    fn an_intervening_inline_run_breaks_margin_adjacency() {
        // Content between two boxes (even a line of text) means their
        // margins are no longer "adjacent" in the CSS sense — the full
        // margin-bottom of the block before it, and the full
        // margin-top of the block after it, should both apply in full,
        // not collapse with each other across the text in between.
        let stylesheet = css::parse_stylesheet("div { margin: 10px; }");
        let document = dom::Node::new_document();
        let a = dom::Node::new_element("div");
        let text_node = dom::Node::new_text("some text");
        let b = dom::Node::new_element("div");
        dom::append_child(&document, a);
        dom::append_child(&document, text_node);
        dom::append_child(&document, b);

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 800.0, &font);

        // Just confirm this doesn't panic and produces a sane
        // (non-collapsed, i.e. bigger than a single 10px margin)
        // overall gap — exact pixel value depends on font metrics for
        // the text line, so we only assert the qualitative shape here.
        let first = &tree.children[0];
        let last = tree.children.last().unwrap();
        assert!(last.rect.y > first.rect.y + first.rect.height + 10.0);
    }

    #[test]
    fn padding_and_border_shrink_available_width_for_children() {
        let stylesheet = css::parse_stylesheet("div { padding: 20px; border: 5px solid #ffffff; }");
        let document = dom::Node::new_document();
        let outer = dom::Node::new_element("div");
        let inner = dom::Node::new_element("div");
        dom::append_child(&outer, inner);
        dom::append_child(&document, outer);

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 200.0, &font);

        let outer_box = &tree.children[0];
        let inner_box = &outer_box.children[0];
        // content starts inset by border (5) + padding (20) on each side
        assert_eq!(inner_box.rect.x, outer_box.rect.x + 25.0);
        // inner box's available width is 200 - 2*(5+20) = 150
        assert_eq!(inner_box.rect.width, 150.0);
    }

    #[test]
    fn border_shorthand_resolves_width_and_color_on_the_box() {
        let stylesheet = css::parse_stylesheet("div { border: 3px solid #ff00ff; }");
        let document = dom::Node::new_document();
        let div = dom::Node::new_element("div");
        dom::append_child(&document, div);

        let tree = build_layout_tree(&document, &stylesheet);
        let box_ = &tree.children[0];
        assert_eq!(box_.border.top, 3.0);
        assert_eq!(box_.border_color.as_deref(), Some("#ff00ff"));
    }

    #[test]
    fn inline_siblings_flow_on_the_same_line_instead_of_stacking() {
        // This is the nav-link case: several `<a>` elements as
        // siblings should sit side-by-side on one line, not each get
        // their own full-width row like block children do.
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        for label in ["Home", "Forum", "Blog"] {
            let a = dom::Node::new_element("a");
            dom::append_child(&a, dom::Node::new_text(label));
            dom::append_child(&document, a);
        }

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 800.0, &font);

        assert_eq!(tree.children.len(), 3);
        // All three sit on the same line: same y, strictly increasing x.
        assert_eq!(tree.children[0].rect.y, tree.children[1].rect.y);
        assert_eq!(tree.children[1].rect.y, tree.children[2].rect.y);
        assert!(tree.children[0].rect.x < tree.children[1].rect.x);
        assert!(tree.children[1].rect.x < tree.children[2].rect.x);
    }

    #[test]
    fn inline_siblings_wrap_to_a_new_line_when_they_dont_fit() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        for label in ["Home", "Forum", "Blog"] {
            let a = dom::Node::new_element("a");
            dom::append_child(&a, dom::Node::new_text(label));
            dom::append_child(&document, a);
        }

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        // "Home" alone is ~32px wide; "Home"+"Forum" together is ~72px.
        // 60px fits "Home" alone but not "Home" followed by "Forum".
        layout(&mut tree, 60.0, &font);

        assert!(
            tree.children[1].rect.y > tree.children[0].rect.y,
            "second link should have wrapped onto a new line"
        );
    }

    #[test]
    fn text_words_flow_onto_the_same_line_as_a_preceding_inline_element() {
        // "Hi <a>Link</a> more words here wrap please" — this is the
        // exact case that used to force the whole trailing text box
        // onto its own new line. Now the first word(s) of the
        // trailing text should share the line with "Link".
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        let p = dom::Node::new_element("p");
        dom::append_child(&p, dom::Node::new_text("Hi"));
        let a = dom::Node::new_element("a");
        dom::append_child(&a, dom::Node::new_text("Link"));
        dom::append_child(&p, a);
        dom::append_child(&p, dom::Node::new_text("more words here wrap please"));
        dom::append_child(&document, p);

        let font = text::load_default_font();
        let hi_w = text::measure_text_width(&font, "Hi", 16.0);
        let link_w = text::measure_text_width(&font, "Link", 16.0);
        let more_w = text::measure_text_width(&font, "more", 16.0);
        let words_w = text::measure_text_width(&font, "words", 16.0);
        let space_w = text::measure_text_width(&font, " ", 16.0);

        // Wide enough for "Hi" + "Link" + "more", too narrow to also
        // fit "words" right after it.
        let content_width = hi_w + link_w + more_w + 1.0;
        assert!(
            content_width < hi_w + link_w + more_w + space_w + words_w,
            "test setup: content_width must not fit \"words\" on the first line too"
        );

        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, content_width, &font);

        let p_box = &tree.children[0];
        let a_box = &p_box.children[1];
        let trailing_text = p_box.children[2].text.as_ref().unwrap();

        assert_eq!(
            trailing_text.lines[0].text, "more",
            "\"more\" should have fit on the same line as \"Link\""
        );
        assert_eq!(
            trailing_text.lines[0].y, a_box.rect.y,
            "\"more\" should be on the same visual row as the link"
        );
        assert_eq!(
            trailing_text.lines[0].x,
            a_box.rect.x + a_box.rect.width,
            "\"more\" should start right where the link ended, not at the container's left edge"
        );
    }

    #[test]
    fn word_level_flow_recurses_into_nested_inline_elements() {
        // <p>Hi <span>click <a>here</a> now</span> more words wrap please</p>
        // "here" lives two levels of inline nesting deep (p > span >
        // a). Real word-level flow should treat it exactly like any
        // other word for wrapping purposes, not as one atomic chunk
        // tied to the whole <span> or the whole <a>.
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        let p = dom::Node::new_element("p");
        dom::append_child(&p, dom::Node::new_text("Hi"));

        let span = dom::Node::new_element("span");
        dom::append_child(&span, dom::Node::new_text("click"));
        let a = dom::Node::new_element("a");
        dom::append_child(&a, dom::Node::new_text("here"));
        dom::append_child(&span, a);
        dom::append_child(&span, dom::Node::new_text("now"));
        dom::append_child(&p, span);

        dom::append_child(&p, dom::Node::new_text("more words wrap please"));
        dom::append_child(&document, p);

        let font = text::load_default_font();
        let hi_w = text::measure_text_width(&font, "Hi", 16.0);
        let click_w = text::measure_text_width(&font, "click", 16.0);
        let here_w = text::measure_text_width(&font, "here", 16.0);
        let now_w = text::measure_text_width(&font, "now", 16.0);
        let more_w = text::measure_text_width(&font, "more", 16.0);
        let words_w = text::measure_text_width(&font, "words", 16.0);
        let space_w = text::measure_text_width(&font, " ", 16.0);

        // Wide enough for "Hi click here now more", too narrow to
        // also fit "words" right after it — forces a wrap exactly
        // after "more".
        let fits_through_more =
            hi_w + space_w + click_w + space_w + here_w + space_w + now_w + space_w + more_w;
        let content_width = fits_through_more + 1.0;
        assert!(
            content_width < fits_through_more + space_w + words_w,
            "test setup: content_width must not fit \"words\" on the first line too"
        );

        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, content_width, &font);

        let p_box = &tree.children[0];
        let span_box = &p_box.children[1];
        let a_box = &span_box.children[1]; // span's children: [text "click", <a>, text "now"]
        let a_text = a_box.children[0].text.as_ref().unwrap();

        // "here" (inside <a>, two levels deep) resolved its own line
        // independently — proof it was split at word granularity
        // rather than treated as one atomic chunk tied to <span> or
        // <a> as a whole.
        assert_eq!(a_text.lines[0].text, "here");

        // The <a> element's own bounding box is sized to just its one
        // word, not stretched to its container's width.
        assert_eq!(a_box.rect.width, here_w);

        // Text after </span> keeps flowing on the same line right
        // after "now" rather than restarting on a fresh line.
        let trailing_text = p_box.children[2].text.as_ref().unwrap();
        assert_eq!(trailing_text.lines[0].text, "more");
    }

    #[test]
    fn a_wrapped_line_of_a_text_box_returns_to_the_containers_left_edge() {
        // Once "more" (packed next to the link) is followed by a word
        // that doesn't fit, the wrap should return to the CONTAINER's
        // left edge — not to wherever the link happened to be — same
        // as a normal paragraph continuing after an inline aside.
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        let p = dom::Node::new_element("p");
        dom::append_child(&p, dom::Node::new_text("Hi"));
        let a = dom::Node::new_element("a");
        dom::append_child(&a, dom::Node::new_text("Link"));
        dom::append_child(&p, a);
        dom::append_child(&p, dom::Node::new_text("more words here wrap please"));
        dom::append_child(&document, p);

        let font = text::load_default_font();
        let hi_w = text::measure_text_width(&font, "Hi", 16.0);
        let link_w = text::measure_text_width(&font, "Link", 16.0);
        let more_w = text::measure_text_width(&font, "more", 16.0);
        let content_width = hi_w + link_w + more_w + 1.0;

        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, content_width, &font);

        let p_box = &tree.children[0];
        let trailing_text = p_box.children[2].text.as_ref().unwrap();

        assert!(
            trailing_text.lines.len() > 1,
            "test setup: trailing text should wrap onto more than one line"
        );
        assert_eq!(
            trailing_text.lines[1].x, p_box.rect.x,
            "the wrapped line should start back at the paragraph's left edge"
        );
        assert!(
            trailing_text.lines[1].y > trailing_text.lines[0].y,
            "the wrapped line should be below the first line"
        );
    }

    #[test]
    fn whitespace_only_text_node_leaves_a_gap_between_two_inline_elements() {
        // This is the exact bug seen in a real fetched page:
        // `<a>Login</a> <a>Register</a>` (a plain space between two
        // sibling links, from the source's own formatting) rendered
        // as "LoginRegister" — the whitespace text node contributed
        // no `Word`, so the two links packed with no gap at all.
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        let login = dom::Node::new_element("a");
        dom::append_child(&login, dom::Node::new_text("Login"));
        dom::append_child(&document, login);
        dom::append_child(&document, dom::Node::new_text(" "));
        let register = dom::Node::new_element("a");
        dom::append_child(&register, dom::Node::new_text("Register"));
        dom::append_child(&document, register);

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 800.0, &font);

        let login_box = &tree.children[0];
        let register_box = &tree.children[2];
        let space_w = text::measure_text_width(&font, " ", 16.0);

        assert_eq!(
            register_box.rect.x,
            login_box.rect.x + login_box.rect.width + space_w,
            "Register should start one space-width after Login ends, not immediately adjacent"
        );
    }

    #[test]
    fn leading_whitespace_on_a_line_collapses_to_nothing() {
        // A whitespace-only text node right at the start of a line
        // (nothing placed yet) shouldn't push the next item inward —
        // real CSS collapses leading whitespace on a line away
        // entirely rather than rendering it as a gap.
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        dom::append_child(&document, dom::Node::new_text(" "));
        let a = dom::Node::new_element("a");
        dom::append_child(&a, dom::Node::new_text("Home"));
        dom::append_child(&document, a);

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 800.0, &font);

        let a_box = &tree.children[1];
        assert_eq!(
            a_box.rect.x, 0.0,
            "leading whitespace on an empty line should collapse to nothing"
        );
    }

    #[test]
    fn inline_element_shrinks_to_its_content_width_instead_of_filling_the_container() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        let a = dom::Node::new_element("a");
        dom::append_child(&a, dom::Node::new_text("Home"));
        dom::append_child(&document, a);

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 800.0, &font);

        assert!(
            tree.children[0].rect.width < 800.0,
            "an inline <a> should shrink to its text's width, not fill the 800px container"
        );
    }

    #[test]
    fn display_none_element_produces_no_layout_box() {
        let stylesheet = css::parse_stylesheet("aside { display: none; }");
        let document = dom::Node::new_document();
        let aside = dom::Node::new_element("aside");
        dom::append_child(&aside, dom::Node::new_text("hidden"));
        dom::append_child(&document, aside);
        let p = dom::Node::new_element("p");
        dom::append_child(&document, p);

        let tree = build_layout_tree(&document, &stylesheet);
        assert_eq!(
            tree.children.len(),
            1,
            "only the <p> should have produced a layout box"
        );
    }

    #[test]
    fn hides_style_and_script_content_from_the_layout_tree() {
        // This is exactly the bug found from a real fetched page: a
        // <style> block's CSS source text was flowing into the page
        // as a giant visible paragraph. Neither <style> nor its text
        // child should produce ANY layout box. `display: none` for
        // these tags now comes from the user-agent stylesheet (see
        // `css::user_agent_stylesheet`), not a hardcoded tag list, so
        // this test needs the real UA stylesheet rather than an empty
        // one to exercise that behavior.
        let document = dom::Node::new_document();

        let style_el = dom::Node::new_element("style");
        dom::append_child(&style_el, dom::Node::new_text("body { color: red; }"));
        dom::append_child(&document, style_el);

        let script_el = dom::Node::new_element("script");
        dom::append_child(&script_el, dom::Node::new_text("console.log('hi');"));
        dom::append_child(&document, script_el);

        let p = dom::Node::new_element("p");
        dom::append_child(&p, dom::Node::new_text("visible text"));
        dom::append_child(&document, p);

        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let tree = build_layout_tree(&document, &stylesheet);

        assert_eq!(
            tree.children.len(),
            1,
            "only the <p> should have produced a layout box"
        );
    }

    fn div_with_style(style: &str) -> dom::NodeRef {
        let div = dom::Node::new_element("div");
        if let dom::NodeType::Element(el) = &mut div.borrow_mut().node_type {
            el.attributes.insert("style".to_string(), style.to_string());
        }
        div
    }

    #[test]
    fn explicit_width_overrides_the_natural_fill_width() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        dom::append_child(&document, div_with_style("width: 200px;"));

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 800.0, &font);

        assert_eq!(tree.children[0].rect.width, 200.0);
    }

    #[test]
    fn percentage_width_resolves_against_the_containing_block() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        dom::append_child(&document, div_with_style("width: 50%;"));

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 800.0, &font);

        assert_eq!(tree.children[0].rect.width, 400.0);
    }

    #[test]
    fn explicit_width_can_overflow_its_container_unlike_natural_sizing() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        dom::append_child(&document, div_with_style("width: 2000px;"));

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 800.0, &font);

        assert_eq!(
            tree.children[0].rect.width, 2000.0,
            "real CSS doesn't clamp an explicit width to the container, unlike auto sizing"
        );
    }

    #[test]
    fn max_width_clamps_an_explicit_width() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        dom::append_child(
            &document,
            div_with_style("width: 2000px; max-width: 500px;"),
        );

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 800.0, &font);

        assert_eq!(tree.children[0].rect.width, 500.0);
    }

    #[test]
    fn min_width_clamps_the_natural_fill_width_upward() {
        // A block child normally fills its container — here the
        // container is narrower than min-width, so min-width should win.
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        dom::append_child(&document, div_with_style("min-width: 900px;"));

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 800.0, &font);

        assert_eq!(tree.children[0].rect.width, 900.0);
    }

    #[test]
    fn width_on_a_non_replaced_inline_element_is_ignored() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        let span = dom::Node::new_element("span");
        if let dom::NodeType::Element(el) = &mut span.borrow_mut().node_type {
            el.attributes
                .insert("style".to_string(), "width: 500px;".to_string());
        }
        dom::append_child(&span, dom::Node::new_text("hi"));
        dom::append_child(&document, span);

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 800.0, &font);

        assert_ne!(
            tree.children[0].rect.width, 500.0,
            "width should have no effect on a non-replaced inline element, matching real CSS"
        );
    }

    #[test]
    fn explicit_height_overrides_the_natural_content_derived_height() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        dom::append_child(&document, div_with_style("height: 400px;"));

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 800.0, &font);

        assert_eq!(tree.children[0].rect.height, 400.0);
    }

    #[test]
    fn percentage_height_is_ignored_falling_back_to_natural_height() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        let empty_div = div_with_style("height: 50%;");
        let plain_div = dom::Node::new_element("div");
        dom::append_child(&document, empty_div);
        dom::append_child(&document, plain_div);

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 800.0, &font);

        assert_eq!(
            tree.children[0].rect.height, tree.children[1].rect.height,
            "a percentage height should be ignored, landing on the same fallback height as an unset one"
        );
    }

    #[test]
    fn min_and_max_height_clamp_an_explicit_height() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        dom::append_child(
            &document,
            div_with_style("height: 1000px; max-height: 300px;"),
        );
        dom::append_child(&document, div_with_style("height: 10px; min-height: 60px;"));

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 800.0, &font);

        assert_eq!(tree.children[0].rect.height, 300.0);
        assert_eq!(tree.children[1].rect.height, 60.0);
    }

    #[test]
    fn explicit_width_and_height_apply_to_a_replaced_image_element() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        let img = dom::Node::new_element("img");
        let img_id = img.borrow().id;
        if let dom::NodeType::Element(el) = &mut img.borrow_mut().node_type {
            el.attributes
                .insert("style".to_string(), "width: 64px;".to_string());
        }
        dom::append_child(&document, img);

        let mut images = HashMap::new();
        images.insert(img_id, fake_image(400, 200));

        let font = text::load_default_font();
        let mut tree = build_layout_tree_with_images(&document, &stylesheet, &images);
        layout(&mut tree, 800.0, &font);

        assert_eq!(
            tree.children[0].rect.width, 64.0,
            "an explicit CSS width should override the image's natural (400px) width"
        );
    }

    #[test]
    fn relative_positioning_offsets_a_box_without_disturbing_its_siblings() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        dom::append_child(
            &document,
            div_with_style("position: relative; top: 10px; left: 20px;"),
        );
        dom::append_child(&document, dom::Node::new_element("div"));

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 800.0, &font);

        let first_natural_y = 0.0; // the root's content edge
        assert_eq!(tree.children[0].rect.x, 20.0);
        assert_eq!(tree.children[0].rect.y, first_natural_y + 10.0);

        // The SECOND child must land exactly where it would have if
        // the first child had never moved — relative positioning must
        // not perturb normal flow for anything else.
        let natural_second_child_y = DEFAULT_LINE_HEIGHT; // first child's un-offset height
        assert_eq!(tree.children[1].rect.y, natural_second_child_y);
        assert_eq!(
            tree.children[1].rect.x, 0.0,
            "an unrelated sibling should not have moved horizontally either"
        );
    }

    #[test]
    fn relative_positioning_shifts_descendants_along_with_their_ancestor() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        let outer = dom::Node::new_element("div");
        if let dom::NodeType::Element(el) = &mut outer.borrow_mut().node_type {
            el.attributes.insert(
                "style".to_string(),
                "position: relative; top: 50px; left: 30px;".to_string(),
            );
        }
        let inner = dom::Node::new_element("div");
        dom::append_child(&outer, inner);
        dom::append_child(&document, outer);

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 800.0, &font);

        let outer_box = &tree.children[0];
        let inner_box = &outer_box.children[0];
        assert_eq!(inner_box.rect.x, outer_box.rect.x);
        assert_eq!(inner_box.rect.y, outer_box.rect.y);
    }

    #[test]
    fn absolutely_positioned_box_is_removed_from_normal_flow() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        dom::append_child(
            &document,
            div_with_style("position: absolute; top: 200px; left: 300px;"),
        );
        dom::append_child(&document, dom::Node::new_element("div"));

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 800.0, &font);

        assert_eq!(tree.children[0].rect.x, 300.0);
        assert_eq!(tree.children[0].rect.y, 200.0);
        // The second (in-flow) child must land at the container's
        // content edge, exactly as if the absolutely positioned first
        // child were not there at all — it must not have consumed any
        // flow space.
        assert_eq!(
            tree.children[1].rect.y, 0.0,
            "an absolutely positioned sibling must not push later in-flow content down"
        );
    }

    #[test]
    fn absolutely_positioned_box_anchors_to_its_nearest_positioned_ancestor() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        let container = dom::Node::new_element("div");
        if let dom::NodeType::Element(el) = &mut container.borrow_mut().node_type {
            el.attributes.insert(
                "style".to_string(),
                "position: relative; width: 500px; height: 300px;".to_string(),
            );
        }
        let popup = dom::Node::new_element("div");
        if let dom::NodeType::Element(el) = &mut popup.borrow_mut().node_type {
            el.attributes.insert(
                "style".to_string(),
                "position: absolute; top: 10px; left: 20px;".to_string(),
            );
        }
        dom::append_child(&container, popup);
        dom::append_child(&document, container);

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 800.0, &font);

        let container_box = &tree.children[0];
        let popup_box = &container_box.children[0];
        assert_eq!(
            popup_box.rect.x,
            container_box.rect.x + 20.0,
            "should anchor to the nearest positioned ancestor, not the viewport"
        );
        assert_eq!(popup_box.rect.y, container_box.rect.y + 10.0);
    }

    #[test]
    fn absolutely_positioned_box_with_right_and_bottom_anchors_from_the_far_edge() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        let container = dom::Node::new_element("div");
        if let dom::NodeType::Element(el) = &mut container.borrow_mut().node_type {
            el.attributes.insert(
                "style".to_string(),
                "position: relative; width: 500px; height: 300px;".to_string(),
            );
        }
        let badge = dom::Node::new_element("div");
        if let dom::NodeType::Element(el) = &mut badge.borrow_mut().node_type {
            el.attributes.insert(
                "style".to_string(),
                "position: absolute; right: 10px; bottom: 5px; width: 40px; height: 20px;"
                    .to_string(),
            );
        }
        dom::append_child(&container, badge);
        dom::append_child(&document, container);

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 800.0, &font);

        let container_box = &tree.children[0];
        let badge_box = &container_box.children[0];
        assert_eq!(badge_box.rect.x, container_box.rect.x + 500.0 - 40.0 - 10.0);
        assert_eq!(badge_box.rect.y, container_box.rect.y + 300.0 - 20.0 - 5.0);
    }

    #[test]
    fn absolutely_positioned_box_with_no_offsets_keeps_its_static_position() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        dom::append_child(&document, div_with_style("position: absolute;"));

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 800.0, &font);

        // No top/right/bottom/left at all — CSS's "static position"
        // fallback should leave it exactly where normal flow would
        // have put an ordinary block box.
        assert_eq!(tree.children[0].rect.x, 0.0);
        assert_eq!(tree.children[0].rect.y, 0.0);
    }

    #[test]
    fn fixed_positioning_anchors_to_the_page_root_even_deep_inside_nested_containers() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        let outer = div_with_style("position: relative;");
        let banner = dom::Node::new_element("div");
        if let dom::NodeType::Element(el) = &mut banner.borrow_mut().node_type {
            el.attributes.insert(
                "style".to_string(),
                "position: fixed; top: 0px; left: 0px;".to_string(),
            );
        }
        dom::append_child(&outer, banner);
        dom::append_child(&document, outer);

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 800.0, &font);

        let banner_box = &tree.children[0].children[0];
        assert_eq!(
            (banner_box.rect.x, banner_box.rect.y),
            (0.0, 0.0),
            "fixed should anchor to the page root, ignoring the intervening relative ancestor"
        );
    }

    #[test]
    fn a_floated_box_is_removed_from_block_flow() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        dom::append_child(
            &document,
            div_with_style("float: left; width: 100px; height: 50px;"),
        );
        dom::append_child(&document, dom::Node::new_element("div"));

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 800.0, &font);

        assert_eq!(tree.children[0].rect.x, 0.0);
        assert_eq!(tree.children[0].rect.y, 0.0);
        assert_eq!(
            tree.children[1].rect.y, 0.0,
            "a floated sibling must not push later in-flow content down"
        );
    }

    #[test]
    fn float_right_places_the_box_at_the_containers_right_edge() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        dom::append_child(
            &document,
            div_with_style("float: right; width: 100px; height: 50px;"),
        );

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 800.0, &font);

        assert_eq!(tree.children[0].rect.x, 700.0);
    }

    #[test]
    fn text_wraps_around_a_left_floated_image() {
        // The realistic structure this feature targets: an image
        // floated INSIDE the same paragraph as the text that should
        // wrap around it (`<p><img style="float:left">text...</p>`) —
        // floats only narrow their OWN immediate container's inline
        // runs (see `layout_box`'s module-doc "floats" section), so a
        // float and the text it affects must be direct siblings.
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        let p = dom::Node::new_element("p");
        let img = dom::Node::new_element("img");
        let img_id = img.borrow().id;
        if let dom::NodeType::Element(el) = &mut img.borrow_mut().node_type {
            el.attributes.insert(
                "style".to_string(),
                "float: left; width: 100px;".to_string(),
            );
        }
        dom::append_child(&p, img);
        dom::append_child(&p, dom::Node::new_text("hello"));
        dom::append_child(&document, p);

        let mut images = HashMap::new();
        images.insert(img_id, fake_image(200, 100)); // 2:1 aspect -> 50px tall at 100px wide

        let font = text::load_default_font();
        let mut tree = build_layout_tree_with_images(&document, &stylesheet, &images);
        layout(&mut tree, 800.0, &font);

        let text_box = &tree.children[0].children[1];
        assert!(
            text_box.text.as_ref().unwrap().lines[0].x >= 100.0,
            "the text's first line should start at or after the float's right edge (100px), \
             got x = {}",
            text_box.text.as_ref().unwrap().lines[0].x
        );
    }

    #[test]
    fn a_wrapped_line_past_the_floats_bottom_is_no_longer_narrowed() {
        // Same immediate-container structure as the wrap-around test
        // above, but the float is short (10px tall) and there's enough
        // text to wrap onto a second line — that second line's `y`
        // should already be past the float's bottom, so only the
        // FIRST line should be narrowed.
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        let p = dom::Node::new_element("p");
        // A plain floated `<div>`, not `<img>` — this test cares about
        // float geometry/narrowing, not the image-specific "explicit
        // width/height only applies to a REPLACED element" rule tested
        // separately (`width_on_a_non_replaced_inline_element_is_ignored`,
        // `explicit_width_and_height_apply_to_a_replaced_image_element`),
        // which would otherwise make an `<img>` with no actually
        // decoded image content behave like a plain non-replaced inline
        // box here (zero intrinsic size) rather than the fixed size
        // this test wants.
        let floated = div_with_style("float: left; width: 100px; height: 10px;");
        dom::append_child(&p, floated);
        dom::append_child(
            &p,
            dom::Node::new_text("one two three four five six seven eight nine ten"),
        );
        dom::append_child(&document, p);

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 250.0, &font);

        let lines = &tree.children[0].children[1].text.as_ref().unwrap().lines;
        assert!(
            lines.len() >= 2,
            "the text should have wrapped onto at least a second line in a 250px container"
        );
        assert!(
            lines[0].x >= 100.0,
            "the first line should be narrowed by the float, got x = {}",
            lines[0].x
        );
        assert_eq!(
            lines.last().unwrap().x,
            0.0,
            "a later wrapped line, past the float's 10px bottom, should not be narrowed"
        );
    }

    #[test]
    fn clear_both_pushes_a_block_below_the_floats_bottom() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        dom::append_child(
            &document,
            div_with_style("float: left; width: 100px; height: 80px;"),
        );
        dom::append_child(&document, div_with_style("clear: both;"));

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 800.0, &font);

        assert_eq!(tree.children[1].rect.y, 80.0);
    }

    #[test]
    fn same_side_floats_stack_vertically_rather_than_overlapping() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        dom::append_child(
            &document,
            div_with_style("float: left; width: 100px; height: 40px;"),
        );
        dom::append_child(
            &document,
            div_with_style("float: left; width: 100px; height: 40px;"),
        );

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 800.0, &font);

        assert_eq!(tree.children[0].rect.y, 0.0);
        assert_eq!(tree.children[1].rect.y, 40.0);
        assert_eq!(tree.children[0].rect.x, tree.children[1].rect.x);
    }

    #[test]
    fn a_container_with_only_floated_children_still_contains_their_height() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        let container = dom::Node::new_element("div");
        let floated = div_with_style("float: left; width: 50px; height: 120px;");
        dom::append_child(&container, floated);
        dom::append_child(&document, container);

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 800.0, &font);

        assert_eq!(
            tree.children[0].rect.height, 120.0,
            "a container holding only a floated child should still contain its full height, \
             not collapse to the empty-box fallback"
        );
    }

    fn input_with_value(value: &str) -> dom::NodeRef {
        let input = dom::Node::new_element("input");
        if let dom::NodeType::Element(el) = &mut input.borrow_mut().node_type {
            el.attributes.insert("value".to_string(), value.to_string());
        }
        input
    }

    #[test]
    fn a_text_input_gets_a_text_input_content_with_its_value() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        dom::append_child(&document, input_with_value("hello"));

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 800.0, &font);

        let input_box = &tree.children[0];
        let content = input_box
            .text_input
            .as_ref()
            .expect("should be a text input");
        assert_eq!(content.value, "hello");
        assert_eq!(
            content.cursor_x, None,
            "not focused, so there should be no cursor"
        );
    }

    #[test]
    fn a_checkbox_input_is_not_treated_as_a_text_input() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        let checkbox = dom::Node::new_element("input");
        if let dom::NodeType::Element(el) = &mut checkbox.borrow_mut().node_type {
            el.attributes
                .insert("type".to_string(), "checkbox".to_string());
        }
        dom::append_child(&document, checkbox);

        let tree = build_layout_tree(&document, &stylesheet);
        assert!(tree.children[0].text_input.is_none());
    }

    #[test]
    fn the_focused_input_gets_a_resolved_cursor_x_others_do_not() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        let first = input_with_value("abc");
        let first_id = first.borrow().id;
        let second = input_with_value("xyz");
        dom::append_child(&document, first);
        dom::append_child(&document, second);

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout_with_focus(&mut tree, 800.0, &font, Some((first_id, 2)));

        let first_box = &tree.children[0];
        let second_box = &tree.children[1];
        assert!(
            first_box.text_input.as_ref().unwrap().cursor_x.is_some(),
            "the focused input should have a resolved cursor position"
        );
        assert!(
            second_box.text_input.as_ref().unwrap().cursor_x.is_none(),
            "an unfocused input must not show a cursor"
        );
        assert!(
            first_box.focused,
            "the focused input's own box should be marked focused, not just its cursor_x"
        );
        assert!(!second_box.focused);
    }

    #[test]
    fn layout_with_focus_marks_a_focused_link_even_though_it_has_no_cursor() {
        // Unlike `cursor_x` (text-input-only), `LayoutBox::focused` is
        // set for ANY focusable element — a link has nothing text-
        // editable about it at all, but keyboard-Tab focus can still
        // land on it and needs a visible ring.
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        let link = dom::Node::new_element("a");
        if let dom::NodeType::Element(el) = &mut link.borrow_mut().node_type {
            el.attributes
                .insert("href".to_string(), "https://example.com".to_string());
        }
        let link_id = link.borrow().id;
        dom::append_child(&link, dom::Node::new_text("click me"));
        dom::append_child(&document, link);

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout_with_focus(&mut tree, 800.0, &font, Some((link_id, 0)));

        assert!(tree.children[0].focused);
    }

    #[test]
    fn plain_layout_never_marks_anything_focused() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        dom::append_child(&document, input_with_value("abc"));

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 800.0, &font);

        assert!(!tree.children[0].focused);
    }

    fn element_with_attrs(tag: &str, attrs: &[(&str, &str)]) -> dom::Element {
        let mut attributes = HashMap::new();
        for (k, v) in attrs {
            attributes.insert(k.to_string(), v.to_string());
        }
        dom::Element {
            tag_name: tag.to_string(),
            attributes,
        }
    }

    #[test]
    fn is_keyboard_focusable_accepts_a_link_with_an_href() {
        assert!(is_keyboard_focusable(&element_with_attrs(
            "a",
            &[("href", "https://example.com")]
        )));
    }

    #[test]
    fn is_keyboard_focusable_rejects_a_link_with_no_href() {
        assert!(!is_keyboard_focusable(&element_with_attrs("a", &[])));
    }

    #[test]
    fn is_keyboard_focusable_accepts_a_button() {
        assert!(is_keyboard_focusable(&element_with_attrs("button", &[])));
    }

    #[test]
    fn is_keyboard_focusable_accepts_ordinary_inputs_but_not_hidden_ones() {
        assert!(is_keyboard_focusable(&element_with_attrs("input", &[])));
        assert!(is_keyboard_focusable(&element_with_attrs(
            "input",
            &[("type", "checkbox")]
        )));
        assert!(!is_keyboard_focusable(&element_with_attrs(
            "input",
            &[("type", "hidden")]
        )));
    }

    #[test]
    fn is_keyboard_focusable_rejects_a_disabled_element_regardless_of_type() {
        assert!(!is_keyboard_focusable(&element_with_attrs(
            "button",
            &[("disabled", "")]
        )));
        assert!(!is_keyboard_focusable(&element_with_attrs(
            "input",
            &[("disabled", "disabled")]
        )));
    }

    #[test]
    fn is_keyboard_focusable_respects_a_negative_tabindex_override() {
        assert!(!is_keyboard_focusable(&element_with_attrs(
            "button",
            &[("tabindex", "-1")]
        )));
        assert!(!is_keyboard_focusable(&element_with_attrs(
            "a",
            &[("href", "https://example.com"), ("tabindex", "-1")]
        )));
    }

    #[test]
    fn is_keyboard_focusable_opts_in_an_otherwise_inert_element_via_tabindex() {
        assert!(is_keyboard_focusable(&element_with_attrs(
            "div",
            &[("tabindex", "0")]
        )));
        assert!(is_keyboard_focusable(&element_with_attrs(
            "span",
            &[("tabindex", "3")]
        )));
    }

    #[test]
    fn is_keyboard_focusable_rejects_a_plain_div_with_no_tabindex() {
        assert!(!is_keyboard_focusable(&element_with_attrs("div", &[])));
    }

    #[test]
    fn cursor_x_advances_past_more_characters() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        let input = input_with_value("hello");
        let input_id = input.borrow().id;
        dom::append_child(&document, input);

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout_with_focus(&mut tree, 800.0, &font, Some((input_id, 0)));
        let cursor_at_start = tree.children[0]
            .text_input
            .as_ref()
            .unwrap()
            .cursor_x
            .unwrap();

        let mut tree2 = build_layout_tree(&document, &stylesheet);
        layout_with_focus(&mut tree2, 800.0, &font, Some((input_id, 3)));
        let cursor_after_three_chars = tree2.children[0]
            .text_input
            .as_ref()
            .unwrap()
            .cursor_x
            .unwrap();

        assert!(
            cursor_after_three_chars > cursor_at_start,
            "the cursor should move right as its character index increases"
        );
    }

    #[test]
    fn a_text_input_gets_its_ua_stylesheet_default_size() {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        dom::append_child(&document, input_with_value(""));

        let font = text::load_default_font();
        let mut tree = build_layout_tree(&document, &stylesheet);
        layout(&mut tree, 800.0, &font);

        // `rect` is the border BOX (see `LayoutBox`'s own doc comment)
        // — the UA stylesheet's `width: 150px`/`height: 22px` set the
        // CONTENT box under `box-sizing: content-box` (this crate's
        // only supported mode), so the border box is larger: +1px
        // border and +4px padding on each side.
        let input_box = &tree.children[0];
        assert_eq!(input_box.rect.width, 150.0 + 2.0 + 8.0);
        assert_eq!(input_box.rect.height, 22.0 + 2.0 + 4.0);
    }
}
