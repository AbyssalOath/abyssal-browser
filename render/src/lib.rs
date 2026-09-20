//! `render` — turns a `layout::LayoutBox` tree into pixels.
//!
//! This paints solid-color boxes AND real text (via the `text` crate)
//! into an in-memory RGBA buffer, and `window` (see window.rs) opens
//! a real OS window, displays that buffer via `wgpu`, and translates
//! raw input (mouse/keyboard/resize) into `window::InputEvent`s —
//! including live relayout/repaint on resize, driven by a handler the
//! caller (`app`) supplies (see `window::run_window`'s docs).
//! `paint`'s `scroll_y` parameter shifts everything up by that many
//! pixels before drawing (and `fill_rect`/glyph-blitting already clip
//! to the canvas bounds — see `Canvas::set_pixel`/`blend_pixel`) —
//! that's the entire mechanism behind scrolling: `app` re-paints into
//! the SAME fixed-size viewport `Canvas` with a different `scroll_y`,
//! rather than the canvas itself growing/shrinking with page length.
//! `paint_text_line` paints a single line of raw text directly (no
//! `LayoutBox` involved) — for browser UI chrome like the address bar,
//! which isn't page content and has no reason to go through layout.
//! It does NOT do:
//!   - images, gradients, shadows, clipping, transparency compositing
//!     beyond simple per-glyph alpha blending
//!   - true pillarboxing on resize (the painted content stretches to
//!     fill the window rather than being centered with bars — see
//!     window.rs's module docs)
//!   - GPU-native painting — the CPU buffer is uploaded as a texture
//!     and blitted, not drawn with GPU primitives directly
//!   - subpixel/LCD text antialiasing, hinting beyond whatever
//!     `fontdue` does internally, or text selection/cursors
//!   - horizontal scrolling — only `scroll_y` exists, matching how
//!     real pages usually only scroll vertically at the top level
//!
//! Next steps, roughly in order of payoff:
//!   1. True pillarboxing instead of stretch-to-fill on resize (see
//!      window.rs).
//!   2. Factor `paint_text_line`'s glyph-blitting loop and `paint_text`'s
//!      out of their current near-duplication into one shared helper.
//!   3. Images, then gradients/shadows, then compositing/opacity.
//!   4. Move painting itself onto the GPU once CPU rasterization
//!      becomes the bottleneck.

pub mod icons;
pub mod window;

use layout::LayoutBox;
use text::Font;

#[derive(Debug, Clone, Copy, Default)]
pub struct Color {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: u8,
}

/// The current find-in-page match's highlight — a saturated orange, the
/// same "this one specifically" color real browsers commonly use to
/// distinguish it from every other match.
const FIND_CURRENT_MATCH_COLOR: Color = Color {
    r: 255,
    g: 140,
    b: 0,
    a: 255,
};
/// Every OTHER find-in-page match's highlight — a paler yellow, less
/// visually dominant than the current match's orange.
const FIND_OTHER_MATCH_COLOR: Color = Color {
    r: 255,
    g: 235,
    b: 120,
    a: 255,
};

/// A CPU-side RGBA framebuffer. Stand-in for a real GPU surface.
/// `Clone` is a generically useful capability (e.g. comparing frames,
/// caching one) — NOT how `MouseMoved` avoids unnecessary GPU work.
/// That's handled by `window::run_window`'s handler returning
/// `Option<Frame>` (`None` = do nothing at all) instead — see its doc
/// comment for why that distinction matters a lot in practice.
#[derive(Clone)]
pub struct Canvas {
    pub width: usize,
    pub height: usize,
    pub pixels: Vec<u8>, // RGBA8, row-major
}

impl Canvas {
    /// `background` is the canvas's initial fill — in practice, the
    /// current theme's background color (see `css::Theme`), so that
    /// any area no element explicitly paints over still matches dark
    /// mode instead of defaulting to white.
    pub fn new(width: usize, height: usize, background: Color) -> Self {
        let mut pixels = Vec::with_capacity(width * height * 4);
        for _ in 0..(width * height) {
            pixels.extend_from_slice(&[background.r, background.g, background.b, background.a]);
        }
        Canvas {
            width,
            height,
            pixels,
        }
    }

    fn set_pixel(&mut self, x: usize, y: usize, color: Color) {
        if x >= self.width || y >= self.height {
            return;
        }
        let i = (y * self.width + x) * 4;
        // TODO: this overwrites rather than alpha-blends — fine for
        // opaque box fills, but doesn't compose partial-alpha
        // backgrounds correctly. See `blend_pixel` for the blended path
        // text painting uses.
        self.pixels[i] = color.r;
        self.pixels[i + 1] = color.g;
        self.pixels[i + 2] = color.b;
        self.pixels[i + 3] = color.a;
    }

    /// Fills a solid rectangle. `pub` because browser UI chrome (the
    /// address bar background, and anything similar later) needs this
    /// directly too, not just internal page-content painting.
    pub fn fill_rect(&mut self, x: f32, y: f32, w: f32, h: f32, color: Color) {
        let (x0, y0) = (x.max(0.0) as usize, y.max(0.0) as usize);
        let (x1, y1) = ((x + w).max(0.0) as usize, (y + h).max(0.0) as usize);
        for py in y0..y1 {
            for px in x0..x1 {
                self.set_pixel(px, py, color);
            }
        }
    }

    /// Fills a solid disc — this crate's only non-rectangular shape,
    /// which exists specifically for a checked radio button's own
    /// indicator dot (see `paint_checkable_input`). A per-pixel
    /// distance test over the disc's own bounding box, same "simple
    /// but real" bar this crate's other primitives set rather than a
    /// proper vector rasterizer (no antialiasing at the edge).
    pub fn fill_circle(&mut self, cx: f32, cy: f32, radius: f32, color: Color) {
        if radius <= 0.0 {
            return;
        }
        let x0 = (cx - radius).max(0.0) as usize;
        let x1 = ((cx + radius).ceil().max(0.0) as usize).min(self.width);
        let y0 = (cy - radius).max(0.0) as usize;
        let y1 = ((cy + radius).ceil().max(0.0) as usize).min(self.height);
        let r_squared = radius * radius;
        for py in y0..y1 {
            for px in x0..x1 {
                let dx = px as f32 + 0.5 - cx;
                let dy = py as f32 + 0.5 - cy;
                if dx * dx + dy * dy <= r_squared {
                    self.set_pixel(px, py, color);
                }
            }
        }
    }

    /// Fills an arbitrary triangle — this crate's second non-
    /// rectangular shape (see `fill_circle`), for a media control
    /// bar's "play" icon (see `paint_media`). A per-pixel
    /// sign-of-cross-product test against all three edges (the
    /// standard "point in triangle" test) over the triangle's own
    /// bounding box — no antialiasing at the edges, same "simple but
    /// real" bar `fill_circle` already sets, and correct regardless of
    /// the three points' winding order.
    #[allow(clippy::too_many_arguments)]
    pub fn fill_triangle(
        &mut self,
        x0: f32,
        y0: f32,
        x1: f32,
        y1: f32,
        x2: f32,
        y2: f32,
        color: Color,
    ) {
        let min_x = (x0.min(x1).min(x2).max(0.0)) as usize;
        let max_x = ((x0.max(x1).max(x2)).ceil().max(0.0) as usize).min(self.width);
        let min_y = (y0.min(y1).min(y2).max(0.0)) as usize;
        let max_y = ((y0.max(y1).max(y2)).ceil().max(0.0) as usize).min(self.height);

        // Twice the signed area of the triangle (ax,ay)-(bx,by)-(cx,cy)
        // — its sign tells which side of edge a->b point c falls on.
        let sign = |ax: f32, ay: f32, bx: f32, by: f32, cx: f32, cy: f32| {
            (ax - cx) * (by - cy) - (bx - cx) * (ay - cy)
        };

        for py in min_y..max_y {
            for px in min_x..max_x {
                let (fx, fy) = (px as f32 + 0.5, py as f32 + 0.5);
                let d1 = sign(fx, fy, x0, y0, x1, y1);
                let d2 = sign(fx, fy, x1, y1, x2, y2);
                let d3 = sign(fx, fy, x2, y2, x0, y0);
                let has_neg = d1 < 0.0 || d2 < 0.0 || d3 < 0.0;
                let has_pos = d1 > 0.0 || d2 > 0.0 || d3 > 0.0;
                if !(has_neg && has_pos) {
                    self.set_pixel(px, py, color);
                }
            }
        }
    }

    /// Fills an arbitrary simple polygon that's star-shaped with
    /// respect to its own centroid (every edge visible from the
    /// center — true of every regular/near-regular shape this crate's
    /// `icons` module actually draws, like a 5-pointed star or a
    /// symmetric trapezoid) via fan triangulation: one `fill_triangle`
    /// call per edge, from the centroid to that edge's two vertices.
    /// This is NOT a general polygon fill (a genuinely non-star-shaped
    /// or self-intersecting polygon would paint wrong) — see
    /// `icons`'s own module doc comment for why that restriction is
    /// fine for icon-drawing specifically.
    pub fn fill_polygon(&mut self, points: &[(f32, f32)], color: Color) {
        if points.len() < 3 {
            return;
        }
        let n = points.len() as f32;
        let (sum_x, sum_y) = points
            .iter()
            .fold((0.0, 0.0), |(sx, sy), (x, y)| (sx + x, sy + y));
        let (cx, cy) = (sum_x / n, sum_y / n);
        for i in 0..points.len() {
            let (x0, y0) = points[i];
            let (x1, y1) = points[(i + 1) % points.len()];
            self.fill_triangle(cx, cy, x0, y0, x1, y1, color);
        }
    }

    /// Alpha-blend `color` over the existing pixel at `(x, y)`, scaled
    /// by `coverage` (0-255). This is what glyph rasterization uses —
    /// each glyph bitmap is a coverage mask, not an opaque rectangle.
    ///
    /// TODO: always writes destination alpha as fully opaque (255),
    /// which is fine while the canvas itself is always opaque, but
    /// isn't correct general alpha compositing (no support for a
    /// partially-transparent destination).
    pub fn blend_pixel(&mut self, x: usize, y: usize, color: Color, coverage: u8) {
        if x >= self.width || y >= self.height || coverage == 0 {
            return;
        }
        let i = (y * self.width + x) * 4;
        let a = coverage as f32 / 255.0;
        let inv = 1.0 - a;
        self.pixels[i] = (color.r as f32 * a + self.pixels[i] as f32 * inv).round() as u8;
        self.pixels[i + 1] = (color.g as f32 * a + self.pixels[i + 1] as f32 * inv).round() as u8;
        self.pixels[i + 2] = (color.b as f32 * a + self.pixels[i + 2] as f32 * inv).round() as u8;
        self.pixels[i + 3] = 255;
    }
}

/// Paint a layout tree onto a canvas: fills each box's background (if
/// any), strokes its border (if any), paints its text (if it's a text
/// box), then recurses into children. `scroll_y` shifts everything up
/// by that many pixels before drawing — see module docs for why this
/// is the entire scrolling mechanism.
///
/// Paint order matches CSS: background first, border on top of it
/// (border always paints over the background at the edges it
/// occupies), then content (text), then children — each child can
/// therefore paint over its parent's background/border where they
/// overlap, which is correct: children sit visually above their
/// parent's own box.
pub fn paint(canvas: &mut Canvas, tree: &LayoutBox, font: &Font, scroll_y: f32) {
    paint_with_find(canvas, tree, font, scroll_y, None);
}

/// Describes what find-in-page should highlight — see `paint_with_find`
/// and `find_matches_in_tree`. `query` is matched case-insensitively
/// (ASCII only — see `find_all_matches`'s own doc comment) against each
/// wrapped `layout::PositionedLine`'s own text, so a match split across
/// two visually wrapped lines isn't found: a documented, minor
/// simplification in the same spirit as this crate's other "real but
/// not exhaustive" choices, not a full logical-text search engine.
pub struct FindHighlight<'a> {
    pub query: &'a str,
    /// Which occurrence, in document/paint order (matching
    /// `find_matches_in_tree`'s own order exactly), is the CURRENT
    /// match — painted in a distinct color from every other match, the
    /// same "current vs. other matches" distinction a real browser's
    /// find bar makes.
    pub current_match_index: usize,
}

/// Same as `paint`, but also highlights find-in-page matches when
/// `find` is `Some` — a separate entry point rather than an extra
/// always-present parameter on `paint` itself, so every OTHER caller
/// (there's only one today, `app::Browser::repaint`, but this keeps the
/// common case simple regardless) isn't forced to thread `None`
/// through by hand.
pub fn paint_with_find(
    canvas: &mut Canvas,
    tree: &LayoutBox,
    font: &Font,
    scroll_y: f32,
    find: Option<&FindHighlight>,
) {
    let mut match_counter = 0usize;
    paint_node(canvas, tree, font, scroll_y, find, &mut match_counter);
}

fn paint_node(
    canvas: &mut Canvas,
    tree: &LayoutBox,
    font: &Font,
    scroll_y: f32,
    find: Option<&FindHighlight>,
    match_counter: &mut usize,
) {
    let bg = tree
        .style
        .properties
        .get("background-color")
        .and_then(|v| parse_color(v));

    if let Some(bg) = bg {
        if bg.a > 0 {
            canvas.fill_rect(
                tree.rect.x,
                tree.rect.y - scroll_y,
                tree.rect.width,
                tree.rect.height,
                bg,
            );
        }
    }
    // No explicit background-color: leave the canvas's existing fill
    // in place (already the theme background from `Canvas::new`)
    // rather than painting an opaque white box over it.

    paint_border(canvas, tree, scroll_y);

    if tree.focused {
        paint_focus_ring(canvas, tree.rect, scroll_y);
    }

    if let Some(text) = &tree.text {
        paint_text(canvas, text, font, scroll_y, find, match_counter);
    }
    if let Some(image) = &tree.image {
        paint_image(canvas, tree, image, scroll_y);
    }
    if let Some(input) = &tree.text_input {
        paint_text_input(canvas, input, font, scroll_y);
    }
    if let Some(checkable) = &tree.checkable_input {
        paint_checkable_input(canvas, tree, checkable, scroll_y);
    }
    if let Some(media) = &tree.media {
        paint_media(canvas, tree, media, font, scroll_y);
    }

    for child in &tree.children {
        paint_node(canvas, child, font, scroll_y, find, match_counter);
    }
}

/// All find-in-page matches for `query` across `tree`, in the exact
/// same document/paint order `paint_with_find`'s own highlighting
/// numbers matches in — `app` uses this both for the total match count
/// and to scroll a specific match into view, and relies on this
/// ordering agreeing with `paint_with_find`'s so "match 3 of 12" means
/// the same match in both places. Rects are in the SAME unscrolled
/// layout-tree coordinate space `layout::hit_test_node` uses (not
/// adjusted for `scroll_y`) — same convention as everywhere else a
/// pixel rect crosses this boundary.
pub fn find_matches_in_tree(tree: &LayoutBox, query: &str, font: &Font) -> Vec<MatchRect> {
    let mut matches = Vec::new();
    collect_matches(tree, query, font, &mut matches);
    matches
}

/// A single find-in-page match's on-page rectangle.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MatchRect {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
}

fn collect_matches(tree: &LayoutBox, query: &str, font: &Font, out: &mut Vec<MatchRect>) {
    if let Some(text) = &tree.text {
        let line_height = text::line_height(font, text.font_size);
        for line in &text.lines {
            for (start, end) in find_all_matches(&line.text, query) {
                let x_offset = text::measure_text_width(font, &line.text[..start], text.font_size);
                let width = text::measure_text_width(font, &line.text[start..end], text.font_size);
                out.push(MatchRect {
                    x: line.x + x_offset,
                    y: line.y,
                    width,
                    height: line_height,
                });
            }
        }
    }
    for child in &tree.children {
        collect_matches(child, query, font, out);
    }
}

/// All non-overlapping byte-range occurrences of `needle` in
/// `haystack`, matched ASCII-case-insensitively — non-ASCII bytes must
/// match exactly. This (rather than a full Unicode-aware
/// case-insensitive search) is what keeps a match's byte range
/// trivially safe to slice back out of the original string: ASCII case
/// folding never changes a character's byte length, while a general
/// Unicode lowercase conversion occasionally does (e.g. some ligatures),
/// which would make mapping a match found in a lowercased copy back to
/// a byte range in the original string incorrect in the general case.
/// The cost is imperfect case-folding for non-ASCII text — acceptable
/// for a personal browser's find-in-page, not for a spec-compliant
/// search engine. Empty `needle` matches nothing (an empty query
/// shouldn't highlight the entire page).
fn find_all_matches(haystack: &str, needle: &str) -> Vec<(usize, usize)> {
    if needle.is_empty() {
        return Vec::new();
    }
    let haystack_bytes = haystack.as_bytes();
    let needle_bytes = needle.as_bytes();
    let mut matches = Vec::new();
    let mut start = 0;
    while start + needle_bytes.len() <= haystack_bytes.len() {
        if haystack_bytes[start..start + needle_bytes.len()].eq_ignore_ascii_case(needle_bytes) {
            matches.push((start, start + needle_bytes.len()));
            start += needle_bytes.len();
        } else {
            start += 1;
        }
    }
    matches
}

/// Paints a text-editable `<input>`'s current value as one line of raw
/// text (via `paint_text_line` — the same primitive already used for
/// browser UI chrome like the address bar, since this is single-line,
/// unwrapped text with an already-fully-resolved position, exactly
/// like that use case), plus a thin cursor bar when `cursor_x` is
/// `Some` (i.e. this is the currently focused input — see
/// `layout::TextInputContent`'s own doc comment). The cursor reuses
/// the text's own resolved color (`currentColor`, informally) rather
/// than a separate fixed color, matching how a real cursor is
/// typically drawn.
fn paint_text_input(
    canvas: &mut Canvas,
    input: &layout::TextInputContent,
    font: &Font,
    scroll_y: f32,
) {
    let color = parse_color(&input.color_hex).unwrap_or(Color {
        r: 0,
        g: 0,
        b: 0,
        a: 255,
    });
    paint_text_line(
        canvas,
        input.text_x,
        input.text_y - scroll_y,
        &input.value,
        input.font_size,
        color,
        font,
    );

    if let Some(cursor_x) = input.cursor_x {
        let line_height = text::line_height(font, input.font_size);
        canvas.fill_rect(cursor_x, input.text_y - scroll_y, 1.5, line_height, color);
    }
}

/// Paints an `<input type="checkbox">`/`<input type="radio">`'s
/// checked-state indicator — the box's own border/background (painted
/// generically, before this ever runs — see `paint`'s own ordering)
/// already draws the unchecked appearance, so this only ever adds
/// something when `checked` is true. A checkbox's indicator is a
/// smaller filled square inset from the box's own edges; a radio's is
/// a filled disc (`Canvas::fill_circle`) — the one place this crate
/// paints anything other than rectangles/text/images, specifically
/// because "a checkbox and a radio button look identical" would be a
/// real, confusing regression from every real browser's own rendering.
/// The OUTER box itself still renders as a plain square border either
/// way (see `paint_border`) — a real circular-STROKE outline for radio
/// buttons isn't implemented (this crate has no vector stroke
/// primitive beyond straight rectangle edges), a deliberate, minor,
/// documented simplification rather than a full custom-shape renderer.
fn paint_checkable_input(
    canvas: &mut Canvas,
    b: &LayoutBox,
    checkable: &layout::CheckableInputContent,
    scroll_y: f32,
) {
    if !checkable.checked {
        return;
    }
    let color = parse_color(
        b.style
            .properties
            .get("color")
            .map(String::as_str)
            .unwrap_or("#000000"),
    )
    .unwrap_or(Color {
        r: 0,
        g: 0,
        b: 0,
        a: 255,
    });
    let cx = b.rect.x + b.rect.width / 2.0;
    let cy = b.rect.y - scroll_y + b.rect.height / 2.0;

    match checkable.kind {
        layout::CheckableKind::Radio => {
            let radius = (b.rect.width.min(b.rect.height) / 2.0 - 3.0).max(1.0);
            canvas.fill_circle(cx, cy, radius, color);
        }
        layout::CheckableKind::Checkbox => {
            let inset = 3.0;
            let w = (b.rect.width - inset * 2.0).max(0.0);
            let h = (b.rect.height - inset * 2.0).max(0.0);
            canvas.fill_rect(cx - w / 2.0, cy - h / 2.0, w, h, color);
        }
    }
}

const MEDIA_PLACEHOLDER_COLOR: Color = Color {
    r: 40,
    g: 40,
    b: 40,
    a: 255,
};
const MEDIA_BAR_BACKGROUND: Color = Color {
    r: 20,
    g: 20,
    b: 20,
    a: 255,
};
const MEDIA_ICON_COLOR: Color = Color {
    r: 230,
    g: 230,
    b: 230,
    a: 255,
};
const MEDIA_ICON_COLOR_MUTED: Color = Color {
    r: 120,
    g: 120,
    b: 120,
    a: 255,
};
const MEDIA_TRACK_COLOR: Color = Color {
    r: 70,
    g: 70,
    b: 70,
    a: 255,
};
const MEDIA_PROGRESS_COLOR: Color = Color {
    r: 90,
    g: 150,
    b: 220,
    a: 255,
};
const MEDIA_CONTROL_FONT_SIZE: f32 = 12.0;

/// Paints an `<audio>`/`<video>` element: for `<video>`, its poster
/// (or a plain placeholder if there isn't one — this crate never
/// decodes actual video FRAMES, see `layout::MediaAsset`'s own doc
/// comment) fills the box above the control bar; `<audio>`'s whole
/// box (sized by `css::user_agent_stylesheet` to exactly
/// `layout::MEDIA_CONTROL_BAR_HEIGHT`) IS the bar. The bar itself
/// (play/pause, a scrubber, elapsed/total time, mute) only paints at
/// all when `media.controls` is set, matching real browsers — see
/// `layout::hit_test_media_control`, the click-handling counterpart
/// to this drawing.
fn paint_media(
    canvas: &mut Canvas,
    b: &LayoutBox,
    media: &layout::MediaContent,
    font: &Font,
    scroll_y: f32,
) {
    let y = b.rect.y - scroll_y;
    let visual_height = if media.controls {
        (b.rect.height - layout::MEDIA_CONTROL_BAR_HEIGHT).max(0.0)
    } else {
        b.rect.height
    };

    if media.kind == layout::MediaKind::Video {
        match &media.poster {
            Some(poster) => blit_image(canvas, b.rect.x, y, b.rect.width, visual_height, poster),
            None => canvas.fill_rect(
                b.rect.x,
                y,
                b.rect.width,
                visual_height,
                MEDIA_PLACEHOLDER_COLOR,
            ),
        }
    }

    if !media.controls {
        return;
    }

    let has_source = media.duration_secs > 0.0;
    let icon_color = if has_source {
        MEDIA_ICON_COLOR
    } else {
        MEDIA_ICON_COLOR_MUTED
    };
    let bar_y = y + visual_height;
    canvas.fill_rect(
        b.rect.x,
        bar_y,
        b.rect.width,
        layout::MEDIA_CONTROL_BAR_HEIGHT,
        MEDIA_BAR_BACKGROUND,
    );

    // Play/pause icon, centered in its button's own square.
    let button_cx = b.rect.x + layout::MEDIA_PLAY_BUTTON_WIDTH / 2.0;
    let button_cy = bar_y + layout::MEDIA_CONTROL_BAR_HEIGHT / 2.0;
    if media.playing {
        canvas.fill_rect(button_cx - 6.0, button_cy - 6.0, 4.0, 12.0, icon_color);
        canvas.fill_rect(button_cx + 2.0, button_cy - 6.0, 4.0, 12.0, icon_color);
    } else {
        canvas.fill_triangle(
            button_cx - 5.0,
            button_cy - 7.0,
            button_cx - 5.0,
            button_cy + 7.0,
            button_cx + 7.0,
            button_cy,
            icon_color,
        );
    }

    // Scrubber track + progress fill.
    let mute_start = b.rect.x + b.rect.width - layout::MEDIA_MUTE_BUTTON_WIDTH;
    let scrubber_x = b.rect.x + layout::MEDIA_PLAY_BUTTON_WIDTH;
    let scrubber_end = (mute_start - layout::MEDIA_TIME_TEXT_WIDTH).max(scrubber_x);
    let scrubber_width = (scrubber_end - scrubber_x).max(0.0);
    let track_y = bar_y + layout::MEDIA_CONTROL_BAR_HEIGHT / 2.0 - 2.0;
    canvas.fill_rect(scrubber_x, track_y, scrubber_width, 4.0, MEDIA_TRACK_COLOR);
    if has_source {
        let progress = (media.current_time_secs / media.duration_secs).clamp(0.0, 1.0);
        canvas.fill_rect(
            scrubber_x,
            track_y,
            scrubber_width * progress,
            4.0,
            MEDIA_PROGRESS_COLOR,
        );
    }

    // Elapsed/total time label.
    let label = format!(
        "{}/{}",
        format_media_time(media.current_time_secs),
        format_media_time(media.duration_secs)
    );
    paint_text_line(
        canvas,
        scrubber_end + 4.0,
        bar_y + (layout::MEDIA_CONTROL_BAR_HEIGHT - MEDIA_CONTROL_FONT_SIZE) / 2.0,
        &label,
        MEDIA_CONTROL_FONT_SIZE,
        icon_color,
        font,
    );

    // Mute icon — a plain square rather than a speaker glyph (no
    // guarantee the bundled font covers one), dimmed while muted so
    // its state is still visible at a glance.
    let mute_color = if media.muted {
        MEDIA_ICON_COLOR_MUTED
    } else {
        icon_color
    };
    canvas.fill_rect(mute_start + 10.0, button_cy - 6.0, 12.0, 12.0, mute_color);
}

/// A coarse `M:SS` (or `MM:SS`) label for a media control bar's
/// elapsed/total time — plain arithmetic, same "not worth a real
/// date/time-formatting dependency" reasoning `app::format_relative_time`
/// already uses for its own, unrelated "how long ago" display.
fn format_media_time(seconds: f32) -> String {
    let total_seconds = seconds.max(0.0).round() as u64;
    format!("{}:{:02}", total_seconds / 60, total_seconds % 60)
}

/// Blits a decoded `<img>` into its box's CONTENT area (inside any
/// border/padding, matching how every other box's content paints —
/// see `layout::ImageContent`'s doc comment for why `pixels` is
/// already plain RGBA8, needing no further decoding here), scaling via
/// simple nearest-neighbor sampling if the laid-out size differs from
/// the image's own decoded size (`layout::layout_box`'s aspect-ratio-
/// preserving sizing means it usually does, at least slightly, for any
/// image that didn't land at exactly its natural size). No bilinear/
/// higher-quality filtering — the same "simple but real" bar this
/// crate's glyph rasterization already sets, not a full image scaling
/// algorithm. Reuses `Canvas::blend_pixel` (the same real alpha
/// compositing primitive text painting uses) rather than a separate
/// opaque blit, so a source image with real transparency (a PNG with
/// an alpha channel) composites correctly over whatever's already
/// been painted underneath it instead of punching an opaque hole.
fn paint_image(canvas: &mut Canvas, b: &LayoutBox, image: &layout::ImageContent, scroll_y: f32) {
    let content_x = b.rect.x + b.border.left + b.padding.left;
    let content_y = b.rect.y - scroll_y + b.border.top + b.padding.top;
    let content_width = (b.rect.width - b.border.horizontal() - b.padding.horizontal()).max(0.0);
    let content_height = (b.rect.height - b.border.vertical() - b.padding.vertical()).max(0.0);
    blit_image(
        canvas,
        content_x,
        content_y,
        content_width,
        content_height,
        image,
    );
}

/// Blits `image` into an arbitrary destination rect, scaling via
/// simple nearest-neighbor sampling if the destination size differs
/// from the image's own decoded size. Shared by `paint_image` (an
/// `<img>`'s content box) and `paint_media` (a `<video>`'s poster,
/// which paints into just the visual area ABOVE its control bar, not
/// the whole box) — the actual blit math doesn't care which box
/// shape it's filling.
fn blit_image(
    canvas: &mut Canvas,
    dest_x: f32,
    dest_y: f32,
    dest_width: f32,
    dest_height: f32,
    image: &layout::ImageContent,
) {
    if image.width == 0 || image.height == 0 {
        return;
    }
    let dest_w = dest_width.round() as i64;
    let dest_h = dest_height.round() as i64;
    if dest_w <= 0 || dest_h <= 0 {
        return;
    }

    for dy in 0..dest_h {
        let py = dest_y + dy as f32;
        if py < 0.0 {
            continue;
        }
        let src_y = (((dy as f32 + 0.5) / dest_h as f32) * image.height as f32) as u32;
        let src_y = src_y.min(image.height - 1);
        for dx in 0..dest_w {
            let px = dest_x + dx as f32;
            if px < 0.0 {
                continue;
            }
            let src_x = (((dx as f32 + 0.5) / dest_w as f32) * image.width as f32) as u32;
            let src_x = src_x.min(image.width - 1);
            let src_i = ((src_y * image.width + src_x) * 4) as usize;
            let Some(pixel) = image.pixels.get(src_i..src_i + 4) else {
                continue; // defensive — a well-formed ImageContent never actually hits this
            };
            let (r, g, b_, a) = (pixel[0], pixel[1], pixel[2], pixel[3]);
            canvas.blend_pixel(px as usize, py as usize, Color { r, g, b: b_, a }, a);
        }
    }
}

/// Strokes a box's border as four solid-fill strips along the edges
/// of its border-box `rect`. Only a single uniform width/color is
/// supported (see `layout`'s module docs) — no dashed/dotted styles,
/// no per-side colors, no rounded corners.
fn paint_border(canvas: &mut Canvas, b: &LayoutBox, scroll_y: f32) {
    let Some(color) = b.border_color.as_deref().and_then(parse_color) else {
        return;
    };
    let border = b.border;
    if border.top <= 0.0 && border.right <= 0.0 && border.bottom <= 0.0 && border.left <= 0.0 {
        return;
    }

    let r = b.rect;
    let y = r.y - scroll_y;
    if border.top > 0.0 {
        canvas.fill_rect(r.x, y, r.width, border.top, color);
    }
    if border.bottom > 0.0 {
        canvas.fill_rect(
            r.x,
            y + r.height - border.bottom,
            r.width,
            border.bottom,
            color,
        );
    }
    if border.left > 0.0 {
        canvas.fill_rect(r.x, y, border.left, r.height, color);
    }
    if border.right > 0.0 {
        canvas.fill_rect(
            r.x + r.width - border.right,
            y,
            border.right,
            r.height,
            color,
        );
    }
}

/// A visible ring for keyboard focus (see `LayoutBox::focused`'s own
/// doc comment) — real HTML's default `outline`, which every browser
/// draws OUTSIDE the border box rather than as part of it (so it never
/// shifts layout the way changing a border's width would, and never
/// gets clipped by an element's own background/border painting). Drawn
/// as four thin filled bars rather than a real stroked-rectangle
/// primitive (this crate has none — see `Canvas`'s own doc comments on
/// its "simple but real" primitives), which is visually indistinguishable
/// from one at `FOCUS_RING_THICKNESS`.
const FOCUS_RING_COLOR: Color = Color {
    r: 90,
    g: 160,
    b: 255,
    a: 255,
};
const FOCUS_RING_THICKNESS: f32 = 2.0;

fn paint_focus_ring(canvas: &mut Canvas, rect: layout::Rect, scroll_y: f32) {
    let x = rect.x - FOCUS_RING_THICKNESS;
    let y = rect.y - scroll_y - FOCUS_RING_THICKNESS;
    let w = rect.width + FOCUS_RING_THICKNESS * 2.0;
    let h = rect.height + FOCUS_RING_THICKNESS * 2.0;
    canvas.fill_rect(x, y, w, FOCUS_RING_THICKNESS, FOCUS_RING_COLOR);
    canvas.fill_rect(
        x,
        y + h - FOCUS_RING_THICKNESS,
        w,
        FOCUS_RING_THICKNESS,
        FOCUS_RING_COLOR,
    );
    canvas.fill_rect(x, y, FOCUS_RING_THICKNESS, h, FOCUS_RING_COLOR);
    canvas.fill_rect(
        x + w - FOCUS_RING_THICKNESS,
        y,
        FOCUS_RING_THICKNESS,
        h,
        FOCUS_RING_COLOR,
    );
}

/// Paint each wrapped line of a text box, one glyph at a time. Each
/// line carries its own resolved `(x, y)` (see `layout::PositionedLine`)
/// rather than assuming every line starts at the box's own origin —
/// that's what lets a text box's first line start mid-run next to a
/// previous inline sibling while later wrapped lines return to the
/// container's left edge.
///
/// TODO: baseline placement uses a fixed fudge factor
/// (`line_height * 0.25`) rather than the font's real ascent metric —
/// swap that in once `text` exposes real vertical font metrics (see
/// its module docs).
fn paint_text(
    canvas: &mut Canvas,
    text: &layout::TextContent,
    font: &Font,
    scroll_y: f32,
    find: Option<&FindHighlight>,
    match_counter: &mut usize,
) {
    let color = parse_color(&text.color_hex).unwrap_or(Color {
        r: 0,
        g: 0,
        b: 0,
        a: 255,
    });
    let line_height = text::line_height(font, text.font_size);

    for line in &text.lines {
        // Highlights are drawn BEFORE this line's own glyphs, so they
        // sit visually behind the text rather than painting over it —
        // `Canvas` has no true alpha-blending-under-existing-content
        // primitive, so paint ORDER is what makes this a highlight
        // rather than an opaque bar hiding the match entirely.
        if let Some(find) = find {
            for (start, end) in find_all_matches(&line.text, find.query) {
                let is_current = *match_counter == find.current_match_index;
                *match_counter += 1;

                let x_offset = text::measure_text_width(font, &line.text[..start], text.font_size);
                let width = text::measure_text_width(font, &line.text[start..end], text.font_size);
                let highlight_color = if is_current {
                    FIND_CURRENT_MATCH_COLOR
                } else {
                    FIND_OTHER_MATCH_COLOR
                };
                canvas.fill_rect(
                    line.x + x_offset,
                    line.y - scroll_y,
                    width,
                    line_height,
                    highlight_color,
                );
            }
        }

        let baseline_y = line.y - scroll_y + line_height - line_height * 0.25;
        let mut pen_x = line.x;

        for ch in line.text.chars() {
            let glyph = text::rasterize(font, ch, text.font_size);

            for row in 0..glyph.height {
                for col in 0..glyph.width {
                    let coverage = glyph.coverage[row * glyph.width + col];
                    if coverage == 0 {
                        continue;
                    }
                    let px = pen_x + glyph.xmin as f32 + col as f32;
                    let py = baseline_y - glyph.ymin as f32 - glyph.height as f32 + row as f32;
                    if px < 0.0 || py < 0.0 {
                        continue;
                    }
                    canvas.blend_pixel(px as usize, py as usize, color, coverage);
                }
            }

            pen_x += glyph.advance_width;
        }
    }
}

/// Paints one line of raw text directly at `(x, y)`, with no wrapping
/// and no `LayoutBox` involved — for browser UI chrome (the address
/// bar, and anything similar later), which isn't page content and has
/// no reason to go through layout. `y` is the top of the text, same
/// convention as a `LayoutBox`'s `rect.y` — this function works out
/// its own baseline internally, same fudge-factor approach as
/// `paint_text` (see its own TODO about real font ascent metrics).
///
/// A very long line just runs off the right edge — no truncation/
/// ellipsis, matching the "minimal" scope of the address bar this
/// exists for.
pub fn paint_text_line(
    canvas: &mut Canvas,
    x: f32,
    y: f32,
    text: &str,
    font_size: f32,
    color: Color,
    font: &Font,
) {
    let line_height = text::line_height(font, font_size);
    let baseline_y = y + line_height - line_height * 0.25;
    let mut pen_x = x;

    for ch in text.chars() {
        let glyph = text::rasterize(font, ch, font_size);

        for row in 0..glyph.height {
            for col in 0..glyph.width {
                let coverage = glyph.coverage[row * glyph.width + col];
                if coverage == 0 {
                    continue;
                }
                let px = pen_x + glyph.xmin as f32 + col as f32;
                let py = baseline_y - glyph.ymin as f32 - glyph.height as f32 + row as f32;
                if px < 0.0 || py < 0.0 {
                    continue;
                }
                canvas.blend_pixel(px as usize, py as usize, color, coverage);
            }
        }

        pen_x += glyph.advance_width;
    }
}

/// Small color parser: `#rrggbb` hex only.
/// TODO: named colors (`red`, `steelblue`, ...), `rgb()`/`rgba()`,
/// `hsl()`, and shorthand `#rgb` are all missing.
pub fn parse_color(value: &str) -> Option<Color> {
    let value = value.trim();
    if let Some(hex) = value.strip_prefix('#') {
        if hex.len() == 6 {
            let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
            let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
            let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
            return Some(Color { r, g, b, a: 255 });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hex_color() {
        let c = parse_color("#ff0000").unwrap();
        assert_eq!((c.r, c.g, c.b), (255, 0, 0));
    }

    #[test]
    fn canvas_fills_with_the_given_background() {
        let canvas = Canvas::new(
            2,
            2,
            Color {
                r: 18,
                g: 18,
                b: 18,
                a: 255,
            },
        );
        assert_eq!(&canvas.pixels[0..4], &[18, 18, 18, 255]);
    }

    #[test]
    fn blend_pixel_mixes_toward_the_foreground_color() {
        let mut canvas = Canvas::new(
            1,
            1,
            Color {
                r: 0,
                g: 0,
                b: 0,
                a: 255,
            },
        );
        canvas.blend_pixel(
            0,
            0,
            Color {
                r: 255,
                g: 255,
                b: 255,
                a: 255,
            },
            128,
        );
        // ~50% coverage should land roughly halfway between black and white.
        assert!(canvas.pixels[0] > 100 && canvas.pixels[0] < 155);
    }

    fn layout_single_image(
        width: u32,
        height: u32,
        pixel: [u8; 4],
        viewport_width: f32,
    ) -> layout::LayoutBox {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        let img = dom::Node::new_element("img");
        let img_id = img.borrow().id;
        dom::append_child(&document, img);

        let mut images = std::collections::HashMap::new();
        let pixels = pixel
            .iter()
            .copied()
            .cycle()
            .take((width * height * 4) as usize)
            .collect();
        images.insert(
            img_id,
            layout::ImageContent {
                width,
                height,
                pixels,
            },
        );

        let font = text::load_default_font();
        let mut tree = layout::build_layout_tree_with_images(&document, &stylesheet, &images);
        layout::layout(&mut tree, viewport_width, &font);
        tree
    }

    #[test]
    fn paint_image_blits_an_opaque_color_at_its_natural_size() {
        let tree = layout_single_image(2, 2, [255, 0, 0, 255], 100.0);
        let font = text::load_default_font();
        let mut canvas = Canvas::new(
            100,
            40,
            Color {
                r: 0,
                g: 0,
                b: 0,
                a: 255,
            },
        );
        paint(&mut canvas, &tree, &font, 0.0);

        assert_eq!(
            &canvas.pixels[0..4],
            &[255, 0, 0, 255],
            "the image's own red pixel should have been blitted at its top-left corner"
        );
    }

    #[test]
    fn paint_image_composites_transparency_over_the_existing_background() {
        // Half-transparent red (alpha 128) blitted over an opaque
        // black background — the result should land somewhere between
        // black and red, never fully opaque red (that would mean the
        // alpha channel was ignored) and never unchanged black (that
        // would mean nothing painted at all).
        let tree = layout_single_image(1, 1, [255, 0, 0, 128], 100.0);
        let font = text::load_default_font();
        let mut canvas = Canvas::new(
            100,
            40,
            Color {
                r: 0,
                g: 0,
                b: 0,
                a: 255,
            },
        );
        paint(&mut canvas, &tree, &font, 0.0);

        assert!(
            canvas.pixels[0] > 50 && canvas.pixels[0] < 220,
            "expected a real alpha blend, got red={}",
            canvas.pixels[0]
        );
        assert_eq!(
            canvas.pixels[1], 0,
            "no green channel in the source, so none should appear after blending"
        );
    }

    #[test]
    fn paint_image_still_paints_a_solid_color_when_scaled_down_to_fit() {
        // A 400px-wide image forced to shrink into a 50px viewport —
        // nearest-neighbor scaling of a perfectly uniform source color
        // should still come out as that same solid color everywhere,
        // not garbage or a gap.
        let tree = layout_single_image(400, 200, [0, 255, 0, 255], 50.0);
        assert!(
            tree.children[0].rect.width <= 50.0,
            "sanity check: the image should have actually shrunk"
        );

        let font = text::load_default_font();
        let mut canvas = Canvas::new(
            50,
            40,
            Color {
                r: 0,
                g: 0,
                b: 0,
                a: 255,
            },
        );
        paint(&mut canvas, &tree, &font, 0.0);

        let mid_x = (tree.children[0].rect.width / 2.0) as usize;
        let i = mid_x * 4;
        assert_eq!(
            &canvas.pixels[i..i + 4],
            &[0, 255, 0, 255],
            "the scaled-down image should still be solid green in its middle"
        );
    }

    #[test]
    fn paints_a_border_stroke_at_the_box_edge() {
        let font = text::load_default_font();
        let stylesheet = css::parse_stylesheet("div { border: 2px solid #ff0000; }");
        let document = dom::Node::new_document();
        let div = dom::Node::new_element("div");
        dom::append_child(&document, div);

        let mut tree = layout::build_layout_tree(&document, &stylesheet);
        layout::layout(&mut tree, 100.0, &font);

        let mut canvas = Canvas::new(
            100,
            40,
            Color {
                r: 0,
                g: 0,
                b: 0,
                a: 255,
            },
        );
        paint(&mut canvas, &tree, &font, 0.0);

        // Top-left corner sits inside the 2px border stroke and should
        // now be red rather than the black canvas background.
        assert_eq!(&canvas.pixels[0..4], &[255, 0, 0, 255]);
    }

    #[test]
    fn paints_text_producing_non_background_pixels() {
        let font = text::load_default_font();
        let stylesheet = css::parse_stylesheet("p { color: #ffffff; }");
        let document = dom::Node::new_document();
        let p = dom::Node::new_element("p");
        let text_node = dom::Node::new_text("Hi");
        dom::append_child(&p, text_node);
        dom::append_child(&document, p);

        let mut tree = layout::build_layout_tree(&document, &stylesheet);
        layout::layout(&mut tree, 200.0, &font);

        let mut canvas = Canvas::new(
            200,
            60,
            Color {
                r: 0,
                g: 0,
                b: 0,
                a: 255,
            },
        );
        paint(&mut canvas, &tree, &font, 0.0);

        // At least one pixel should have been lightened by glyph
        // coverage away from the pure-black background.
        let any_lit = canvas.pixels.chunks(4).any(|p| p[0] > 10);
        assert!(
            any_lit,
            "expected at least one non-background pixel after painting text"
        );
    }

    #[test]
    fn scroll_y_shifts_painted_content_upward() {
        let font = text::load_default_font();
        let stylesheet = css::parse_stylesheet("div { background-color: #ffffff; }");
        let document = dom::Node::new_document();
        let div = dom::Node::new_element("div");
        dom::append_child(&document, div);

        let mut tree = layout::build_layout_tree(&document, &stylesheet);
        layout::layout(&mut tree, 50.0, &font);
        // Force a known, nonzero height/position to scroll against.
        tree.children[0].rect.y = 10.0;
        tree.children[0].rect.height = 20.0;

        let mut unscrolled = Canvas::new(
            50,
            50,
            Color {
                r: 0,
                g: 0,
                b: 0,
                a: 255,
            },
        );
        paint(&mut unscrolled, &tree, &font, 0.0);
        // The painted white box's top edge should be at y=10 when unscrolled.
        let row_9 = &unscrolled.pixels[(9 * 50) * 4..(9 * 50) * 4 + 4];
        let row_10 = &unscrolled.pixels[(10 * 50) * 4..(10 * 50) * 4 + 4];
        assert_ne!(
            row_9, row_10,
            "sanity check: row 9 and row 10 should differ before scrolling"
        );

        let mut scrolled = Canvas::new(
            50,
            50,
            Color {
                r: 0,
                g: 0,
                b: 0,
                a: 255,
            },
        );
        paint(&mut scrolled, &tree, &font, 10.0);
        // Scrolled down by 10px, the same box's top edge should now
        // land at y=0 instead of y=10.
        assert_eq!(&scrolled.pixels[0..4], &[255, 255, 255, 255]);
    }

    #[test]
    fn paint_text_line_produces_non_background_pixels() {
        let font = text::load_default_font();
        let mut canvas = Canvas::new(
            200,
            40,
            Color {
                r: 0,
                g: 0,
                b: 0,
                a: 255,
            },
        );
        paint_text_line(
            &mut canvas,
            5.0,
            5.0,
            "Hi",
            16.0,
            Color {
                r: 255,
                g: 255,
                b: 255,
                a: 255,
            },
            &font,
        );

        let any_lit = canvas.pixels.chunks(4).any(|p| p[0] > 10);
        assert!(
            any_lit,
            "expected at least one non-background pixel after paint_text_line"
        );
    }

    fn count_pixels_matching(canvas: &Canvas, color: Color) -> usize {
        canvas
            .pixels
            .chunks(4)
            .filter(|p| p[0] == color.r && p[1] == color.g && p[2] == color.b)
            .count()
    }

    #[test]
    fn paint_draws_a_focus_ring_only_around_a_focused_element() {
        let font = text::load_default_font();
        let background = Color {
            r: 18,
            g: 18,
            b: 18,
            a: 255,
        };

        let mut unfocused_canvas = Canvas::new(300, 100, background);
        paint(
            &mut unfocused_canvas,
            &layout_single_input("hi", None),
            &font,
            0.0,
        );
        assert_eq!(
            count_pixels_matching(&unfocused_canvas, FOCUS_RING_COLOR),
            0,
            "an unfocused input should have no focus ring at all"
        );

        let mut focused_canvas = Canvas::new(300, 100, background);
        paint(
            &mut focused_canvas,
            &layout_single_input("hi", Some((dom::NodeId(0), 0))),
            &font,
            0.0,
        );
        assert!(
            count_pixels_matching(&focused_canvas, FOCUS_RING_COLOR) > 0,
            "a focused input should show a real focus ring"
        );
    }

    fn layout_single_input(value: &str, focus: Option<(dom::NodeId, usize)>) -> layout::LayoutBox {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        let input = dom::Node::new_element("input");
        let input_id = input.borrow().id;
        if let dom::NodeType::Element(el) = &mut input.borrow_mut().node_type {
            el.attributes.insert("value".to_string(), value.to_string());
        }
        dom::append_child(&document, input);

        let font = text::load_default_font();
        let mut tree = layout::build_layout_tree(&document, &stylesheet);
        let focus = focus.map(|(_, idx)| (input_id, idx));
        layout::layout_with_focus(&mut tree, 300.0, &font, focus);
        tree
    }

    #[test]
    fn paint_paints_a_text_inputs_value() {
        let tree = layout_single_input("hello", None);
        let font = text::load_default_font();
        let mut canvas = Canvas::new(
            300,
            100,
            Color {
                r: 18,
                g: 18,
                b: 18,
                a: 255,
            },
        );
        paint(&mut canvas, &tree, &font, 0.0);

        let any_lit = canvas.pixels.chunks(4).any(|p| p[0] > 40 || p[1] > 40);
        assert!(
            any_lit,
            "expected the input's value text to paint some non-background pixels"
        );
    }

    #[test]
    fn paint_draws_a_cursor_only_when_focused() {
        let unfocused = layout_single_input("hi", None);
        let font = text::load_default_font();
        let mut canvas_unfocused = Canvas::new(
            300,
            100,
            Color {
                r: 18,
                g: 18,
                b: 18,
                a: 255,
            },
        );
        paint(&mut canvas_unfocused, &unfocused, &font, 0.0);

        let focused = layout_single_input("hi", Some((dom::NodeId(0), 1)));
        let mut canvas_focused = Canvas::new(
            300,
            100,
            Color {
                r: 18,
                g: 18,
                b: 18,
                a: 255,
            },
        );
        paint(&mut canvas_focused, &focused, &font, 0.0);

        assert_ne!(
            canvas_unfocused.pixels, canvas_focused.pixels,
            "a focused input's cursor bar should paint differently from an unfocused one"
        );
    }

    fn layout_single_checkable(kind: &str, checked: bool) -> layout::LayoutBox {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        let input = dom::Node::new_element("input");
        if let dom::NodeType::Element(el) = &mut input.borrow_mut().node_type {
            el.attributes.insert("type".to_string(), kind.to_string());
            if checked {
                el.attributes.insert("checked".to_string(), String::new());
            }
        }
        dom::append_child(&document, input);

        let font = text::load_default_font();
        let mut tree = layout::build_layout_tree(&document, &stylesheet);
        layout::layout(&mut tree, 300.0, &font);
        tree
    }

    fn blank_canvas() -> Canvas {
        Canvas::new(
            300,
            100,
            Color {
                r: 18,
                g: 18,
                b: 18,
                a: 255,
            },
        )
    }

    #[test]
    fn paint_draws_a_checkbox_indicator_only_when_checked() {
        let font = text::load_default_font();

        let unchecked = layout_single_checkable("checkbox", false);
        let mut canvas_unchecked = blank_canvas();
        paint(&mut canvas_unchecked, &unchecked, &font, 0.0);

        let checked = layout_single_checkable("checkbox", true);
        let mut canvas_checked = blank_canvas();
        paint(&mut canvas_checked, &checked, &font, 0.0);

        assert_ne!(
            canvas_unchecked.pixels, canvas_checked.pixels,
            "a checked checkbox should paint an indicator an unchecked one doesn't have"
        );
    }

    #[test]
    fn paint_draws_a_radio_indicator_only_when_checked() {
        let font = text::load_default_font();

        let unchecked = layout_single_checkable("radio", false);
        let mut canvas_unchecked = blank_canvas();
        paint(&mut canvas_unchecked, &unchecked, &font, 0.0);

        let checked = layout_single_checkable("radio", true);
        let mut canvas_checked = blank_canvas();
        paint(&mut canvas_checked, &checked, &font, 0.0);

        assert_ne!(
            canvas_unchecked.pixels, canvas_checked.pixels,
            "a checked radio should paint a dot an unchecked one doesn't have"
        );
    }

    #[test]
    fn fill_circle_paints_pixels_within_the_radius_and_leaves_the_rest_alone() {
        let mut canvas = Canvas::new(
            10,
            10,
            Color {
                r: 0,
                g: 0,
                b: 0,
                a: 255,
            },
        );
        canvas.fill_circle(
            5.0,
            5.0,
            3.0,
            Color {
                r: 255,
                g: 255,
                b: 255,
                a: 255,
            },
        );
        // Center should be filled; a far corner should still be
        // background.
        let center_idx = (5 * 10 + 5) * 4;
        let corner_idx = 0;
        assert_eq!(canvas.pixels[center_idx], 255);
        assert_eq!(canvas.pixels[corner_idx], 0);
    }

    #[test]
    fn find_all_matches_finds_every_non_overlapping_case_insensitive_occurrence() {
        let matches = find_all_matches("Hello hello HELLO world", "hello");
        assert_eq!(matches, vec![(0, 5), (6, 11), (12, 17)]);
    }

    #[test]
    fn find_all_matches_is_empty_for_an_empty_needle() {
        assert!(find_all_matches("anything", "").is_empty());
    }

    #[test]
    fn find_all_matches_does_not_overlap_matches() {
        // "aa" in "aaaa" should find 2 non-overlapping matches (0..2,
        // 2..4), not 3 overlapping ones.
        assert_eq!(find_all_matches("aaaa", "aa"), vec![(0, 2), (2, 4)]);
    }

    fn layout_single_paragraph(text: &str, viewport_width: f32) -> layout::LayoutBox {
        let font = text::load_default_font();
        let stylesheet = css::parse_stylesheet("p { color: #ffffff; }");
        let document = dom::Node::new_document();
        let p = dom::Node::new_element("p");
        dom::append_child(&p, dom::Node::new_text(text));
        dom::append_child(&document, p);

        let mut tree = layout::build_layout_tree(&document, &stylesheet);
        layout::layout(&mut tree, viewport_width, &font);
        tree
    }

    #[test]
    fn find_matches_in_tree_locates_every_occurrence_in_document_order() {
        let font = text::load_default_font();
        let tree = layout_single_paragraph("cat dog cat", 400.0);

        let matches = find_matches_in_tree(&tree, "cat", &font);
        assert_eq!(matches.len(), 2, "should find both occurrences of \"cat\"");
        // Document order: the first "cat" should be positioned to the
        // left of the second one on the same line.
        assert!(matches[0].x < matches[1].x);
    }

    #[test]
    fn find_matches_in_tree_is_empty_when_the_query_does_not_appear() {
        let font = text::load_default_font();
        let tree = layout_single_paragraph("cat dog", 400.0);
        assert!(find_matches_in_tree(&tree, "zebra", &font).is_empty());
    }

    #[test]
    fn paint_with_find_highlights_the_current_match_differently_from_others() {
        let font = text::load_default_font();
        let tree = layout_single_paragraph("cat dog cat", 400.0);
        let matches = find_matches_in_tree(&tree, "cat", &font);
        assert_eq!(matches.len(), 2);

        let mut canvas = Canvas::new(
            400,
            60,
            Color {
                r: 0,
                g: 0,
                b: 0,
                a: 255,
            },
        );
        paint_with_find(
            &mut canvas,
            &tree,
            &font,
            0.0,
            Some(&FindHighlight {
                query: "cat",
                current_match_index: 0,
            }),
        );

        let first_match = matches[0];
        let second_match = matches[1];
        let pixel_at = |canvas: &Canvas, x: f32, y: f32| -> [u8; 4] {
            let px = x as usize;
            let py = y as usize;
            let i = (py * canvas.width + px) * 4;
            [
                canvas.pixels[i],
                canvas.pixels[i + 1],
                canvas.pixels[i + 2],
                canvas.pixels[i + 3],
            ]
        };

        // A point inside the FIRST match's rect (the current one) should
        // be the "current" highlight color; a point inside the SECOND
        // match's rect (not current) should be the "other" color.
        // Sampled near each rect's top-left, inset slightly to land
        // solidly inside it rather than exactly on a float-rounded edge.
        let first_pixel = pixel_at(&canvas, first_match.x + 1.0, first_match.y + 1.0);
        let second_pixel = pixel_at(&canvas, second_match.x + 1.0, second_match.y + 1.0);
        assert_eq!(
            first_pixel,
            [
                FIND_CURRENT_MATCH_COLOR.r,
                FIND_CURRENT_MATCH_COLOR.g,
                FIND_CURRENT_MATCH_COLOR.b,
                FIND_CURRENT_MATCH_COLOR.a
            ]
        );
        assert_eq!(
            second_pixel,
            [
                FIND_OTHER_MATCH_COLOR.r,
                FIND_OTHER_MATCH_COLOR.g,
                FIND_OTHER_MATCH_COLOR.b,
                FIND_OTHER_MATCH_COLOR.a
            ]
        );
    }

    #[test]
    fn paint_with_find_none_paints_no_highlights() {
        let font = text::load_default_font();
        let tree = layout_single_paragraph("cat dog cat", 400.0);
        let mut canvas = Canvas::new(
            400,
            60,
            Color {
                r: 0,
                g: 0,
                b: 0,
                a: 255,
            },
        );
        paint_with_find(&mut canvas, &tree, &font, 0.0, None);

        let has_highlight_color = canvas
            .pixels
            .as_chunks::<4>()
            .0
            .iter()
            .any(|p| p == &[255, 140, 0, 255] || p == &[255, 235, 120, 255]);
        assert!(
            !has_highlight_color,
            "no find-in-page highlight should appear when find is None"
        );
    }

    #[test]
    fn fill_triangle_paints_inside_but_not_outside_it() {
        let mut canvas = blank_canvas();
        let color = Color {
            r: 255,
            g: 255,
            b: 255,
            a: 255,
        };
        // A triangle with a flat base along y=80 and an apex at (50,20).
        canvas.fill_triangle(10.0, 80.0, 90.0, 80.0, 50.0, 20.0, color);

        let center_idx = (50 * canvas.width + 50) * 4;
        assert_eq!(
            canvas.pixels[center_idx], 255,
            "the triangle's own interior should be filled"
        );

        let corner_idx = 0;
        assert_eq!(
            canvas.pixels[corner_idx], 18,
            "the far top-left corner, well outside the triangle, should be untouched"
        );
    }

    fn layout_single_audio(
        kind: layout::MediaKind,
        controls: bool,
        duration_secs: f32,
    ) -> layout::LayoutBox {
        let stylesheet = css::user_agent_stylesheet(css::Theme::Dark);
        let document = dom::Node::new_document();
        let tag = match kind {
            layout::MediaKind::Audio => "audio",
            layout::MediaKind::Video => "video",
        };
        let el_node = dom::Node::new_element(tag);
        let node_id = el_node.borrow().id;
        if controls {
            if let dom::NodeType::Element(el) = &mut el_node.borrow_mut().node_type {
                el.attributes.insert("controls".to_string(), String::new());
            }
        }
        dom::append_child(&document, el_node);

        let mut media = std::collections::HashMap::new();
        media.insert(
            node_id,
            layout::MediaAsset {
                kind,
                controls,
                duration_secs,
                poster: None,
            },
        );

        let font = text::load_default_font();
        let mut tree = layout::build_layout_tree_with_media(
            &document,
            &stylesheet,
            &std::collections::HashMap::new(),
            &media,
        );
        layout::layout(&mut tree, 400.0, &font);
        tree
    }

    #[test]
    fn paint_media_draws_a_control_bar_only_when_controls_is_set() {
        let font = text::load_default_font();

        let with_controls = layout_single_audio(layout::MediaKind::Audio, true, 100.0);
        let mut canvas_with = blank_canvas();
        paint(&mut canvas_with, &with_controls, &font, 0.0);

        let without_controls = layout_single_audio(layout::MediaKind::Audio, false, 100.0);
        let mut canvas_without = blank_canvas();
        paint(&mut canvas_without, &without_controls, &font, 0.0);

        assert_ne!(
            canvas_with.pixels, canvas_without.pixels,
            "a controls bar should paint something a controls-less audio element doesn't"
        );
    }

    #[test]
    fn paint_media_play_icon_differs_from_pause_icon() {
        let font = text::load_default_font();

        let mut paused = layout_single_audio(layout::MediaKind::Audio, true, 100.0);
        paused.children[0].media.as_mut().unwrap().playing = false;
        let mut canvas_paused = blank_canvas();
        paint(&mut canvas_paused, &paused, &font, 0.0);

        let mut playing = layout_single_audio(layout::MediaKind::Audio, true, 100.0);
        playing.children[0].media.as_mut().unwrap().playing = true;
        let mut canvas_playing = blank_canvas();
        paint(&mut canvas_playing, &playing, &font, 0.0);

        assert_ne!(
            canvas_paused.pixels, canvas_playing.pixels,
            "a play triangle and a pause icon should look visibly different"
        );
    }

    #[test]
    fn paint_media_video_without_a_poster_paints_a_placeholder_not_nothing() {
        let font = text::load_default_font();
        let tree = layout_single_audio(layout::MediaKind::Video, false, 0.0);
        let mut canvas = blank_canvas();
        paint(&mut canvas, &tree, &font, 0.0);

        let video_box = &tree.children[0];
        let px = video_box.rect.x as usize + 2;
        let py = video_box.rect.y as usize + 2;
        let idx = (py * canvas.width + px) * 4;
        assert_eq!(
            [canvas.pixels[idx], canvas.pixels[idx + 1], canvas.pixels[idx + 2]],
            [40, 40, 40],
            "a poster-less video should still paint a visible placeholder, not leave the background showing through"
        );
    }

    #[test]
    fn format_media_time_pads_seconds_to_two_digits() {
        assert_eq!(format_media_time(5.0), "0:05");
        assert_eq!(format_media_time(65.0), "1:05");
        assert_eq!(format_media_time(3661.0), "61:01");
    }
}
