# DOM, HTML, CSS, Layout, and Render

This file covers the "parse a page into pixels" pipeline: `dom` -> `html` -> `css` -> `layout` -> `render`. Everything here runs inside the sandboxed `renderer` process except the final `render` step, which happens back in `app` (it paints the `LayoutBox` snapshot `renderer` hands over the IPC boundary). JavaScript is covered separately in `03-javascript-engine.md`; how `app` wires all this into an actual window is covered in `06-app-ui-and-window.md`.

The short version of the whole pipeline:

```
raw HTML bytes
  -> html::parse            (html5ever -> dom::Node tree)
  -> css::extract_author_stylesheet_with_external + css::user_agent_stylesheet
  -> css::compute_style      (per node, walking the tree once, cascade + inheritance)
  -> layout::build_layout_tree + layout::layout   (dom::Node + ComputedStyle -> LayoutBox tree with real geometry)
  -> render::paint           (LayoutBox tree -> Canvas, an RGBA buffer)
  -> render::window          (Canvas -> a real GPU-presented window)
```

## `dom` -- the shared tree

The smallest crate in this pipeline (203 lines) and deliberately kept that way -- its own module doc calls it "the load-bearing wall" and says to keep it boring and stable. Every other crate in this file either builds this tree (`html`), reads it (`css`, `layout`), or is read alongside it (`render` never touches `dom` directly -- it only sees `layout::LayoutBox`, which carries a clone of the `NodeType` it needs).

The tree itself:

```rust
pub type NodeRef = Rc<RefCell<Node>>;
pub type WeakNodeRef = Weak<RefCell<Node>>;

pub struct Node {
    pub id: NodeId,
    pub node_type: NodeType,
    pub parent: Option<WeakNodeRef>,
    pub children: Vec<NodeRef>,
}

pub enum NodeType {
    Document,
    Element(Element),   // tag_name: String, attributes: HashMap<String, String>
    Text(String),
    Comment(String),
}
```

`Rc<RefCell<Node>>` (not an arena/index-based tree) is a deliberate starting choice, called out in the module doc as something to revisit "if you outgrow it." Parent links are `Weak`, not `Rc` -- if they were strong, every node would keep its own parent alive forever via a reference cycle (parent -> Rc child -> Weak parent would be fine, but the actual pattern here is parent holds `Vec<NodeRef>` of children, and each child holds a *strong* would-be-cyclic back-reference to its parent if `parent` weren't `Weak`). `Weak::upgrade()` is how you get back to a live parent; it returns `None` if the parent has since been dropped.

**`NodeId`** is the one thing worth understanding deeply, because it's the hinge the whole `app`/`renderer` process split turns on. It's a monotonically increasing `u64` (`AtomicU64`, process-global, starts at 1), assigned once per node at construction and *never derived from the node's memory address*. Why that specific choice matters: `layout::LayoutBox` (see below) needs to carry a reference back to "which live DOM node produced this box," but a `LayoutBox` tree is a plain serializable snapshot that crosses the `app`<->`renderer` IPC boundary (see `ipc`'s docs) -- it can never hold a real `Rc<RefCell<Node>>`. If node identity were tied to an allocation's address (e.g. `Rc::as_ptr`), a node freed mid-session (a script replacing a text node's content, say) could have its memory reused by the allocator for an unrelated new node, and a stale `NodeId` from an old `LayoutBox` snapshot would silently resolve to the *wrong* live node instead of just failing to resolve. The monotonic counter closes that hole entirely: an id is either the exact node it was minted for, or it resolves to nothing.

**`append_child(parent, child)`** is the one real mutation primitive, and it implements genuine DOM *move* semantics, not just "add to list": if `child` already has a parent anywhere in the tree, it's removed from that parent's children first. `html`'s own tree builder never needs this (it only ever appends brand-new nodes), but `renderer::script`'s JS-facing `appendChild` binding absolutely does -- re-appending an already-attached element to a new location is completely ordinary, spec-required JS behavior (`document.body.appendChild(existingElement)` moves it). Getting this wrong would leave elements duplicated in two places in the tree.

Two TODOs worth knowing about if you're about to extend this crate: attribute values are plain heap-allocated `String`s (every `class="foo"` on a large page is a fresh allocation -- `Rc<str>`/interning would help before this matters for memory), and there's no `CharacterData` API (`splitText`, `appendData`), no mutation observers, and no namespace-aware tag/attribute names (so embedded SVG/MathML, which use different namespaces, isn't really supported).

## `html` -- HTML5 parsing

Tiny (185 lines) because the actual hard work is entirely delegated to `html5ever`, the same parser Servo and Firefox use. This crate's own code is a thin adapter: `html5ever::parse_document` builds an `rcdom::RcDom` (html5ever's own reference DOM implementation, vendored into `html/src/rcdom.rs` -- see below for why), and `convert()` walks that tree exactly once, recursively, to build the real `dom::Node` tree this codebase actually uses.

**Why vendor `rcdom` instead of depending on it as a crate**: `markup5ever_rcdom` (the crate you'd naively reach for) is an "unofficial" third-party republish of html5ever's own test-only reference DOM -- not something the html5ever maintainers themselves publish and support. Depending on it is a real, if minor, supply-chain smell (see `THREAT_MODEL.md`'s dependencies section, which explicitly calls this out as a "previously flagged" gap that vendoring closed). Vendoring the ~small amount of actual code means this codebase controls exactly what version it's built against with no external maintenance risk.

**Why convert into `dom::Node` rather than implement html5ever's `TreeSink` trait directly against it**: html5ever's `TreeSink::elem_name` needs to return a borrowed, namespace-qualified `ExpandedName` *during* parsing, which means whatever DOM type is driving the parse has to store a real `markup5ever::QualName` per element. `dom::Element` deliberately only stores a plain `tag_name: String` (see `dom`'s own module docs -- staying dependency-light is the point). Parsing into html5ever's own `RcDom` first and converting the finished tree afterward sidesteps that tension completely: html5ever does 100% of the actually-hard spec-compliant parsing work (implied tags, error recovery, every insertion mode -- "hundreds of pages of spec," per the module doc), and this crate only does simple data-structure transcoding once, at the end.

What gets dropped in that conversion (`convert()` returns `None` for these): Doctype and ProcessingInstruction nodes (nothing downstream does anything with a doctype yet), and namespaces entirely (`name.local` only -- fine for plain HTML, wrong for embedded SVG/MathML). html5ever's own parse errors (`RcDom.errors`) are silently discarded too -- a real "view source with parse warnings" feature could use these later, but nothing does today.

The tests here (`extracts_element_attributes`, `auto_closes_an_unclosed_paragraph_per_spec_instead_of_nesting_it`, `implies_missing_head_and_body_like_a_real_browser`) are worth reading if you want a feel for what a *real* HTML5 parser gives you for free versus a naive hand-rolled one -- they're direct regression tests against bugs a simpler tokenizer used to have before this crate switched to html5ever.

## `css` -- parsing, cascade, and computed style

The biggest of the five crates (3144 lines). What's actually implemented is extensive -- read the module's own top-of-file doc comment (`css/src/lib.rs` lines 1-59) for the full, precise list; the summary:

**Selectors** (`SimpleSelector`, `CompoundSelector`, `Selector`, `Combinator`): tag, `#id`, `.class`, the universal `*`, all six real attribute-selector operators (`[attr]`, `=`, `~=`, `|=`, `^=`, `$=`, `*=`), all four combinators (` ` descendant, `>` child, `+` adjacent-sibling, `~` general-sibling), comma-separated selector lists, and the structural pseudo-classes (`:first-child`, `:last-child`, `:only-child`, `:first-of-type`, `:last-of-type`, `:nth-child(An+B)`, `:nth-of-type(An+B)`, `:not(...)`, `:root`, `:empty`, `:link`). `:hover`/`:focus` *parse* (so a stylesheet using them doesn't outright fail) but never *match* -- real, temporary limitation, because `render::window`'s mouse-move handler intentionally does zero work on every move (see the GPU-exhaustion story in the Render section below), so there's no live cursor position anywhere to test a `:hover` rule against yet. `:visited` isn't parsed as a distinct case at all -- this one is deliberate and *permanent*, not a "not implemented yet": `:visited` is a well-known history-sniffing side channel in real browsers (a page can use it to detect which links you've clicked), and simply never distinguishing visited from unvisited closes that channel by construction rather than by careful mitigation.

**Specificity** (`Specificity { id_count, class_count, type_count }`) is the real spec triple, compared lexicographically (id most significant) via a derived `Ord`. Attribute selectors and non-`:not` pseudo-classes count at the "class" level (matching spec); `:not(...)` contributes its *argument's* specificity, not zero -- otherwise `:not(#id)` would dodge `#id`'s real weight, which would be wrong.

**The cascade** (`compute_style`, around line 1554) is where it all comes together, and it's worth reading directly rather than just this summary:

1. Every rule in the stylesheet whose selector matches the node gets every one of its declarations collected into a flat list, tagged with `(specificity, source_order)`.
2. That list is stable-sorted ascending by `(specificity, source_order)`.
3. Declarations are applied *in that sorted order*, each one just overwriting the property in a `HashMap<String, String>` -- so the *last-applied* entry for any given property name is automatically the real cascade winner (highest specificity, then latest source order among ties). This is real per-**property** merging, not per-rule "winner takes all" -- two different rules matching the same element can each win on different properties.
4. An element's own `style="..."` attribute is parsed and applied *after* every selector-based rule, unconditionally -- this is what makes an inline style beat even an `!important`-free `#id` selector, exactly matching real CSS (inline style effectively has infinite specificity by construction, not by out-scoring the highest real value).
5. Inheritance runs next: for a fixed, curated list (`INHERITED_PROPERTIES` -- `color`, `font-family`, `font-weight`, `font-style`, `line-height`, `text-align`, `visibility`, `cursor`, `letter-spacing`, `white-space`) any property this node didn't set itself is copied down from `parent_style`.
6. `font-size` gets its own dedicated resolution step, deliberately *not* folded into the generic inheritance loop above: a relative `em`/`%` font-size has to resolve against the parent's already-**resolved** pixel value, not be copied down as a still-relative string for some later reader to reinterpret against the wrong ancestor. `resolve_font_size` runs for every node including the root (where `parent_style` is `None`), which is what makes `DEFAULT_FONT_SIZE_PX` (16px, matching real browsers' own `<html>` default) the ultimate fallback.

What's explicitly *not* real yet: cascade "origins" (user-agent vs. author vs. `!important`) -- `Stylesheet::extend`'s "author beats user-agent" behavior is only an approximation that happens to work because the UA stylesheet only ever uses plain tag selectors (see below), not a genuine origin-based cascade; and shorthand property expansion beyond what's hand-written for specific properties (`margin`/`padding`/`border` do have real shorthand parsing -- see `layout::box_model` -- but there's no general mechanism).

**`ComputedStyle`** itself is deliberately "stringly typed": `pub properties: HashMap<String, String>`. The module doc flags this as a real TODO ("you'll want a typed struct before layout can reason about box-model numbers") -- `Display` is the one property that *did* get pulled out into a real enum (`Block`/`Inline`/`Flex`/`Grid`/`None`), specifically because `layout` needs to branch on it directly rather than string-match at every call site. Everything else (color, lengths, `position`, `float`, flex/grid properties) is parsed back out of the string bag on demand by small accessor methods on `ComputedStyle` (`font_size()`, `position()`, `top()`, and so on) -- so if you're adding a new CSS property, the pattern is: parse it into the string bag during stylesheet parsing (no change needed, it's already just a string), then add a typed accessor method here for whoever consumes it in `layout`.

**The user-agent stylesheet** (`user_agent_stylesheet(theme)`) is built per-theme (since it bakes in the theme's background/foreground colors directly), and is the *only* place `display: none`/`display: inline` get assigned by default -- `NEVER_RENDERED_TAGS` (script, style, head, meta, etc.) get `display: none`, `INLINE_TAGS` (a, span, em, b, i, ...) get `display: inline`; everything else defaults to `Display::Block`. An author stylesheet can freely override any of this.

**Stylesheet extraction** (`extract_author_stylesheet_with_external`) walks the DOM collecting both inline `<style>` blocks and `<link rel="stylesheet">` content, and -- this is the part worth remembering if you touch it -- splices each one in at the exact tree position it was found, interleaved in real document order. That matters because cascade tie-breaking is by source order, so a `<link>` and a `<style>` block need to interleave correctly relative to each other. This crate has no network access of its own at all (by design -- `css` doesn't even know what a fetch is); `external_css: &HashMap<dom::NodeId, String>` is populated by the caller (`renderer::stylesheets::resolve_and_fetch_stylesheets`, which goes through the same blocklist-checking fetch path as everything else) before this function ever runs. A `<link>` whose id isn't in that map (not yet fetched, blocked as a third-party tracker, or the fetch failed) just contributes nothing -- same "missing input degrades silently" philosophy you'll see throughout this codebase (a failed `<img>` similarly just doesn't render, rather than erroring the whole page).

## `layout` -- DOM + computed style -> concrete geometry

The other very large crate (4127 lines in `lib.rs` alone, plus `box_model.rs`, `flex.rs`, `grid.rs`). This is genuinely the most algorithmically dense part of the whole rendering pipeline, and its own module doc comment (`layout/src/lib.rs`, the first ~175 lines) is worth reading start to finish before changing anything here -- it's unusually precise about exactly which real CSS behaviors are implemented and which are deliberately scoped out, and *why* for each one. What follows is a map, not a replacement for that.

**`LayoutBox`** is the tree this crate produces, and the type that crosses the IPC boundary back to `app` as a plain serializable snapshot:

```rust
pub struct LayoutBox {
    pub rect: Rect,              // the box's BORDER box: includes border+padding, not margin
    pub style: ComputedStyle,
    pub node_type: NodeType,     // a CLONE of the dom::NodeType this box came from
    pub dom_node_id: dom::NodeId,
    pub children: Vec<LayoutBox>,
    pub text: Option<TextContent>,           // Some only for a DOM text node
    pub image: Option<ImageContent>,          // Some only for a successfully decoded <img>
    pub text_input: Option<TextInputContent>, // Some only for a text-editable <input>
    pub checkable_input: Option<CheckableInputContent>, // Some only for checkbox/radio
    // ...plus media content for <audio>/<video>
}
```

`rect` being the **border** box (not including margin) matters for `render`: margin only ever affects *position* (shifting where the border box sits relative to its container), never the box's own painted size -- so `render::paint` can fill `rect` directly for background/border with no extra margin arithmetic. `dom_node_id` is the field that makes hit-testing work at all: `app::Browser::handle_click` uses `layout::hit_test_node(tree, x, y)` to turn pixel coordinates into a `dom::NodeId` *locally*, in the privileged process, using the `LayoutBox` snapshot it already has -- and sends only that id to the renderer over IPC, never raw pixel coordinates. The renderer then walks its own *live* DOM (which it still has, since script sessions persist per-tab) to build the real ancestor chain and dispatch a real three-phase (capture/target/bubble) click event.

**Two-pass structure**: `build_layout_tree` walks the DOM once, computing style per node (threading each node's own just-computed `ComputedStyle` down as `parent_style` for its children -- this is also how inheritance actually gets used, not just computed) and building the box tree with real values for everything that doesn't depend on available width. Text boxes store their *raw*, unwrapped string plus font size and color at this point -- wrapping needs to know how much horizontal space is available, and no width is known until the second pass. `layout()` (`layout_with_focus` underneath) is that second, positioning pass: it walks the already-built tree top-down, resolving each box's actual x/y/width, and *that's* when text actually gets word-wrapped (via `text::wrap_text`) into `PositionedLine`s, one per visual line, each carrying its own absolute paint position (not all assumed to share the text box's own origin -- the first line can start mid-run next to a previous inline sibling, while wrapped continuation lines return to the container's left edge).

**Box model** (`box_model.rs`): real `margin`/`border`/`padding`, parsed out of `ComputedStyle`'s string bag into `EdgeSizes { top, right, bottom, left }`. `margin`/`padding` support the 1/2/3/4-value CSS shorthand plus the four longhands (longhands win, matching real CSS cascade-within-a-property behavior). `border` only supports one uniform width+color for the whole box -- no per-side border styling yet. `box-sizing` is always `content-box`. Real margin collapsing is implemented for both adjacent block siblings *and* parent/first-child and parent/last-child (when there's no border/padding/line-box separating them) -- see `effective_top_margin`/`effective_bottom_margin`.

**Inline formatting** (`layout_inline_run`) packs a maximal run of consecutive inline-level siblings (text + `display: inline` elements) left-to-right at **word granularity** -- a text box gets split into individual words (`flatten_inline_items`) that pack right up against sibling inline elements and keep flowing on the same line, wrapping only the words that actually run out of room (`text <a>link</a> more text` lets "more" continue on the same line as the link). Word-splitting recurses into nested inline elements arbitrarily deep via a `path` (a chain of child indices, not a flat index), so a word three levels of inline nesting deep still wraps and flows correctly. Real caveat worth knowing: an inline element that itself wraps across more than one line gets a *single* bounding box spanning all of them, not the several per-line fragments a real browser generates -- listed as item 1 in this crate's own "next steps."

**Flexbox** (`flex.rs`): `flex-direction: row` gets the real algorithm -- basis/grow/shrink resolution, multi-line wrapping, `justify-content` main-axis spacing, `align-items` cross-axis alignment/stretch. `column` gets something deliberately simpler (gap-spaced stacking with real cross-axis alignment, but no grow/shrink/wrap/justify-content), and the reason is structural, not laziness: this whole box model has no notion of an explicit *container height* anywhere, so a column flex container's main axis (height) is always unbounded/content-driven -- there's never a finite amount of free space to grow into or a deficit to shrink against. Both directions reuse the crate's own ordinary `layout_box` to lay out each item's actual content once its main-axis size is resolved, so flex items can contain arbitrary nested content (including nested flex/grid containers) for free. Known gap: an item with `display: inline` and no override isn't "blockified" the way real CSS requires, so a bare `<span>` used directly as a flex item won't stretch/grow/shrink correctly.

**Grid** (`grid.rs`): tracks can be a fixed px length, `<N>fr`, or `repeat()` -- no percentages, no `minmax()`. Placement is via `grid-area: <name>` (matching `grid-template-areas`) or `grid-row`/`grid-column: span <N>` with auto-placement; the real 4-part explicit line-number syntax (`grid-column: 2 / 4`) isn't implemented and falls back to ordinary auto-placement. Row sizing has the same "no explicit container height" limitation flex's column mode has -- a `fr` row track falls back to content-driven sizing, same as an unset one. Every item stretches to fill its cell by default (`align-items` isn't read at all yet, a real gap rather than a deliberate default).

**Floats**: a floated child (`float: left`/`right`) is pulled out of normal flow (like `position: absolute`) and placed flush against its side's edge; that container's own *direct* inline children wrap around it (`line_bounds`/`place_float`). Scoped narrowly: only the float's immediate container's own inline content wraps around it, not a nested descendant's (`<div><img style="float:left"><p>text</p></div>` won't wrap `text`, but `<p><img style="float:left">text</p>` will, since there `text` is a direct sibling). Same-side floats stack vertically rather than packing side-by-side.

**Positioning** (`apply_positioning`, `position: relative`/`absolute`/`fixed`): a *second* pass run once over the already-finished tree, walking down from the nearest positioned ancestor as each element's "containing block," matching the real CSS algorithm. `fixed` anchors to the page's own final rendered height, not a live, scroll-independent viewport -- this crate has no independent notion of viewport height to anchor against otherwise, a deliberate, documented scope reduction. Only block-level children can be taken out of flow this way (an inline-context child still consumes inline space) -- real-world absolute/fixed elements are overwhelmingly authored as `display: block` anyway (dropdowns, modals, banners).

**Hit-testing** (`hit_test_node`): bounding-rect based, not pixel/glyph-accurate -- a click anywhere inside an anchor's box counts, matching how real browsers are similarly generous. Real anchors can't validly nest per spec (html5ever enforces this during parsing), so which box "wins" on overlap essentially never comes up.

## `render` -- pixels and the window

Two files: `render/src/lib.rs` (painting a `LayoutBox` tree into a CPU-side RGBA `Canvas`) and `render/src/window.rs` (a real OS window via `wgpu`/`winit`, presenting that `Canvas`). `render/src/icons.rs` holds the browser chrome's own hand-drawn vector icons (back/forward/reload/bookmark/account) -- small triangle/polygon vertex lists filled via `Canvas::fill_triangle`/`fill_polygon`, since this crate's `Canvas` has no SVG or path support at all; see that file's own doc comment.

**`Canvas`** is genuinely just `{ width, height, pixels: Vec<u8> }` -- RGBA8, row-major, a stand-in for a real GPU surface. `fill_rect`/`fill_circle`/`set_pixel` (which clips to canvas bounds) are the drawing primitives; text goes through a separate glyph-blitting path (`paint_text`/`paint_text_line`) built on the `text` crate's rasterization, with real per-glyph alpha blending (`blend_pixel`) -- `set_pixel` itself *overwrites* rather than blends, which is fine for opaque box fills but is flagged as not correctly compositing partial-alpha backgrounds.

**What `render` deliberately doesn't do**, per its own module doc: gradients, shadows, general clipping, transparency compositing beyond glyph alpha-blending, true pillarboxing on resize (content stretches to fill the window instead of being letterboxed with bars -- a documented simplification, not a bug, and it's why mouse-coordinate scaling can assume uniform stretch), any GPU-native drawing (the CPU buffer is uploaded as one texture and blitted, not drawn with real GPU primitives), subpixel/LCD antialiasing beyond whatever `fontdue` does internally, text selection/cursors as a general concept (a focused `<input>`'s own cursor is handled specially via `TextInputContent`, not as a general text-selection feature), and horizontal scrolling -- only `scroll_y` exists.

**`window.rs`'s central design boundary**, worth internalizing before touching this file: it knows *nothing* about `dom`/`css`/`html`/`layout` at all -- only `Canvas` and raw input coordinates/keys. Everything about "what does a click actually mean" (hit-testing, navigation, an address bar, scrolling) lives entirely in `app`, which supplies a `handler: FnMut(InputEvent) -> Option<Frame>` closure. That's what keeps this module reusable as a thin windowing+GPU layer instead of accumulating browser-specific logic.

**The real reason `Option<Frame>` (not just `Frame`) matters, concretely**: `InputEvent::MouseMoved` fires on *every pixel* of cursor movement. An earlier version of this codebase did a full texture rebuild on every single one of those -- that's enough multi-megabyte GPU work per second to genuinely exhaust memory and hang the system, not just feel slow. The fix is architectural, not a tuning knob: `handler` returning `None` means "nothing changed, skip the GPU work entirely," and `app`'s own handler *always* returns `None` for `MouseMoved` today (there are no hover effects implemented, which is also *why* `:hover` never matches in `css` -- see above). If you ever add a feature that needs to react to mouse movement (a hover state, a drag), you have to think hard about whether it can avoid triggering `Some(frame)` on every single move event, or you will reintroduce this exact bug. This is called out explicitly as "a hard-won rule" in `ARCHITECTURE.md` too.

Mouse coordinates arrive already converted from physical window pixels into content/canvas pixel space (matching whatever `Canvas` size the last `Frame` contained), so `app` never has to reason about physical-vs-rendered-content scaling itself. Resize events *are* debounced (`RESIZE_DEBOUNCE` -- one relayout+repaint+texture-rebuild per drag, after motion pauses); click/scroll/keyboard events are not, since those are discrete and infrequent by nature.

One environment note worth knowing if you ever see it: a momentary black flash during resize on X11 without a compositing manager (common under window managers like IceWM that don't run one by default) is a platform-level artifact of uncomposited GPU swapchain resizing, not a bug in this codebase -- running a lightweight compositor (`picom`) is the usual fix, and is worth confirming as the cause before chasing a phantom code bug.

**A version-compatibility trap documented directly in the module doc**: wgpu 0.19 expects `raw-window-handle` 0.6, and winit 0.29 needs its `"rwh_06"` feature enabled in `Cargo.toml` to satisfy that. If you ever bump either dependency, re-check they still agree -- this is exactly the kind of thing that silently breaks in a way that's confusing to debug from the symptom alone. Similarly, keyboard handling uses winit 0.29's `KeyEvent`/`keyboard::Key` API shape (`Key::Named(NamedKey::...)` / `Key::Character(...)`), which replaced the older pre-0.29 `VirtualKeyCode` enum -- re-check this if you bump winit again.

## Where to go next

- For how JavaScript mutates this same `dom::Node` tree at runtime (and what DOM API surface script actually gets), see `03-javascript-engine.md`.
- For how `app` turns a `LayoutBox` tree into an actual clickable, scrollable browser window (tabs, the address bar, keyboard shortcuts), see `06-app-ui-and-window.md`.
- For the IPC message shapes that carry a `LayoutBox` tree (and a lot more) between `app` and `renderer`, see `01-process-model-and-ipc.md`.
