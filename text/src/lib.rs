//! `text` — font loading, measurement, word-wrapping, and glyph
//! rasterization. This is the crate `layout` calls to know how wide
//! text is (so it can wrap lines), and the crate `render` calls to
//! turn characters into actual pixel coverage.
//!
//! Built on `fontdue`, a pure-Rust rasterizer with **no shaping** —
//! it measures/rasterizes one Unicode codepoint at a time, with no
//! kerning pairs, no ligatures, and no complex-script/RTL support.
//! That's a real limitation (an "fi" ligature won't merge, Arabic
//! won't join, kerning will look slightly loose) but it's enough to
//! put real, readable Latin-script words on screen, which is the
//! milestone this unlocks. `cosmic-text` (wrapping `rustybuzz` for
//! real shaping) is the upgrade path once that matters.
//!
//! The bundled font is Inconsolata Regular (SIL Open Font License —
//! see assets/OFL.txt, which must ship alongside the font file per
//! that license). It's monospace, which is a placeholder choice: this
//! crate has no `font-family` support at all yet, so every page uses
//! this one font regardless of what CSS asks for.
//!
//! `line_height` uses the font's own real vertical metrics (ascent +
//! descent + line gap, via `fontdue::Font::horizontal_line_metrics`)
//! now, not a fixed heuristic — falling back to the old `1.3x` estimate
//! only for the (rare, spec-nonconformant) font with no metrics table
//! fontdue can read at all.
//!
//! Next steps, roughly in order of payoff:
//!   1. `font-family`/`@font-face` support — deliberately NOT
//!      implemented, and not merely deferred for lack of time. Two
//!      real reasons: (a) glyph RASTERIZATION happens in the
//!      PRIVILEGED `app` process (`render`+`text`), while all
//!      fetching happens in the sandboxed `renderer` (see this
//!      workspace's top-level README on that split) — a fetched
//!      `@font-face` font's bytes would need a new IPC channel
//!      carrying untrusted font data into the privileged process,
//!      which is exactly the kind of new privileged-process attack
//!      surface this architecture exists to avoid opening casually.
//!      (b) even setting that aside, real browsers' own font-related
//!      fingerprinting surface (which fonts are installed/loaded,
//!      subtle per-font glyph metrics) is a well-known tracking vector
//!      — Tor Browser and Mullvad Browser both limit their own font
//!      set specifically to reduce it. A single, fixed, bundled font
//!      is a real privacy property this crate gets "for free" today;
//!      adding arbitrary web-font loading trades that away for a
//!      cosmetic-only win (this browser's real, harder layout gaps —
//!      floats, positioning, real CSS selectors, external stylesheets
//!      — matter far more to whether a page is USABLE at all). Worth
//!      revisiting if this project ever wants closer visual fidelity
//!      to how a page "should" look, but that's a deliberate tradeoff
//!      to make explicitly, not a default to reach for.
//!   2. Mid-word breaking/hyphenation for words wider than the
//!      available line width (currently: the word just overflows).
//!   3. Swap to `cosmic-text`/`rustybuzz` for real shaping once
//!      non-trivial typography (kerning, ligatures, RTL/complex
//!      scripts) matters.

/// Re-exported so downstream crates (`layout`, `render`) can name the
/// font type without taking a direct dependency on `fontdue` — if
/// this crate's rasterizer is ever swapped out, callers referencing
/// `text::Font` don't need to change.
pub type Font = fontdue::Font;

/// Load the one bundled font. There's no font-file discovery, no
/// system font access, and no fallback chain — this is it.
pub fn load_default_font() -> Font {
    let font_bytes = include_bytes!("../assets/Inconsolata-Regular.ttf") as &[u8];
    fontdue::Font::from_bytes(font_bytes, fontdue::FontSettings::default())
        .expect("the bundled font is compiled into the binary and must always parse")
}

/// A rasterized glyph: pixel dimensions, positioning offsets relative
/// to the pen position, and single-channel (alpha/coverage) pixel
/// data. `render` blends this over the background using the text's
/// computed color.
pub struct GlyphBitmap {
    pub width: usize,
    pub height: usize,
    /// Horizontal offset from the pen position to the bitmap's left
    /// edge (left side bearing).
    pub xmin: i32,
    /// Vertical offset from the baseline to the bitmap's bottom edge.
    pub ymin: i32,
    /// How far to advance the pen after drawing this glyph.
    pub advance_width: f32,
    /// Row-major single-channel coverage (0 = transparent, 255 = fully
    /// covered), `width * height` bytes.
    pub coverage: Vec<u8>,
}

pub fn rasterize(font: &Font, ch: char, px: f32) -> GlyphBitmap {
    let (metrics, coverage) = font.rasterize(ch, px);
    GlyphBitmap {
        width: metrics.width,
        height: metrics.height,
        xmin: metrics.xmin,
        ymin: metrics.ymin,
        advance_width: metrics.advance_width,
        coverage,
    }
}

fn advance_width(font: &Font, ch: char, px: f32) -> f32 {
    font.metrics(ch, px).advance_width
}

pub fn measure_text_width(font: &Font, text: &str, px: f32) -> f32 {
    text.chars().map(|ch| advance_width(font, ch, px)).sum()
}

/// Finds the character index in `text` closest to horizontal offset
/// `target_x` (measuring from the text's own left edge, i.e. `target_x`
/// is already local to wherever the text itself starts painting) — the
/// standard "click position -> text cursor position" mapping any
/// editable text field needs. A click past the midpoint of a
/// character's own advance width rounds to the boundary AFTER it,
/// matching how real text cursors snap to the nearer edge rather than
/// always the character's start. Shared by every editable text field
/// this workspace has — originally duplicated between `app`'s address
/// bar and `renderer::script`'s page `<input>` support before being
/// hoisted here.
pub fn char_index_for_x(font: &Font, text: &str, px: f32, target_x: f32) -> usize {
    let mut acc = 0.0;
    for (i, ch) in text.chars().enumerate() {
        let w = measure_text_width(font, &ch.to_string(), px);
        if target_x < acc + w / 2.0 {
            return i;
        }
        acc += w;
    }
    text.chars().count()
}

/// Converts a character index (as `char_index_for_x` and a text
/// cursor's own position both use) into the byte offset
/// `str::replace_range`/`String::insert` etc. actually need — `s` may
/// contain multi-byte UTF-8 characters, so this is NOT simply
/// `char_idx` itself. `char_idx` at or past the end of `text`'s own
/// character count resolves to `s.len()` (the end), matching how a
/// cursor position is always clamped to a valid boundary by its own
/// caller anyway.
pub fn char_byte_offset(s: &str, char_idx: usize) -> usize {
    s.char_indices()
        .nth(char_idx)
        .map(|(b, _)| b)
        .unwrap_or(s.len())
}

/// Real line height: the font's own vertical metrics (ascent +
/// descent + line gap, via `horizontal_line_metrics`'s
/// `new_line_size`) at this pixel size — what a real browser/text
/// layout engine actually uses, rather than a fixed multiple of font
/// size. Falls back to the old `1.3x` heuristic only if the font has
/// no metrics table fontdue can read at all (defensive; the bundled
/// font always has one, so this fallback is untested-in-practice but
/// cheap insurance against a future font that doesn't).
pub fn line_height(font: &Font, px: f32) -> f32 {
    match font.horizontal_line_metrics(px) {
        Some(metrics) => metrics.new_line_size,
        None => px * 1.3,
    }
}

/// Greedy word-wrap: fit as many whitespace-separated words per line
/// as fit within `max_width`, breaking to a new line when the next
/// word wouldn't fit.
///
/// TODO: a word wider than `max_width` on its own is placed on its
/// own line and allowed to overflow rather than being hyphenated or
/// broken mid-word. Also: this collapses all whitespace runs to a
/// single space, which is correct for normal HTML whitespace handling
/// but would be wrong inside a future `white-space: pre` implementation.
pub fn wrap_text(font: &Font, text: &str, px: f32, max_width: f32) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    let mut current_width = 0.0f32;
    let space_width = advance_width(font, ' ', px);

    for word in text.split_whitespace() {
        let word_width = measure_text_width(font, word, px);
        let would_be_width = if current.is_empty() {
            word_width
        } else {
            current_width + space_width + word_width
        };

        if !current.is_empty() && would_be_width > max_width {
            lines.push(std::mem::take(&mut current));
            current_width = 0.0;
        }

        if !current.is_empty() {
            current.push(' ');
            current_width += space_width;
        }
        current.push_str(word);
        current_width += word_width;
    }

    if !current.is_empty() || lines.is_empty() {
        lines.push(current);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_the_bundled_font_without_panicking() {
        let _font = load_default_font();
    }

    #[test]
    fn longer_text_measures_wider() {
        let font = load_default_font();
        let short = measure_text_width(&font, "hi", 16.0);
        let long = measure_text_width(&font, "hello there friend", 16.0);
        assert!(long > short);
    }

    #[test]
    fn wraps_long_text_into_multiple_lines_at_narrow_width() {
        let font = load_default_font();
        let text = "this is a fairly long sentence that should wrap across several lines";
        let wide = wrap_text(&font, text, 16.0, 2000.0);
        let narrow = wrap_text(&font, text, 16.0, 100.0);
        assert_eq!(wide.len(), 1);
        assert!(narrow.len() > 1);
    }

    #[test]
    fn line_height_grows_with_font_size() {
        let font = load_default_font();
        let small = line_height(&font, 16.0);
        let large = line_height(&font, 32.0);
        assert!(small > 0.0);
        assert!(large > small);
    }

    #[test]
    fn char_index_for_x_finds_the_start_and_end_of_a_string() {
        let font = load_default_font();
        assert_eq!(char_index_for_x(&font, "hello", 16.0, -5.0), 0);
        assert_eq!(char_index_for_x(&font, "hello", 16.0, 100_000.0), 5);
    }

    #[test]
    fn char_index_for_x_snaps_to_the_nearer_character_boundary() {
        let font = load_default_font();
        let full_width = measure_text_width(&font, "ab", 16.0);
        let a_width = measure_text_width(&font, "a", 16.0);
        // Just past the midpoint of 'a' should already round up to
        // index 1 (between 'a' and 'b'), not stay at index 0.
        assert_eq!(char_index_for_x(&font, "ab", 16.0, a_width / 2.0 + 0.1), 1);
        assert_eq!(char_index_for_x(&font, "ab", 16.0, full_width + 1.0), 2);
    }

    #[test]
    fn char_byte_offset_handles_multi_byte_characters() {
        let s = "héllo"; // 'é' is 2 bytes in UTF-8
        assert_eq!(char_byte_offset(s, 0), 0);
        assert_eq!(char_byte_offset(s, 1), 1);
        assert_eq!(char_byte_offset(s, 2), 3, "should skip past the 2-byte 'é'");
        assert_eq!(
            char_byte_offset(s, 100),
            s.len(),
            "out of range clamps to the end"
        );
    }

    #[test]
    fn rasterizing_a_glyph_produces_nonempty_coverage() {
        let font = load_default_font();
        let glyph = rasterize(&font, 'A', 32.0);
        assert!(glyph.width > 0 && glyph.height > 0);
        assert_eq!(glyph.coverage.len(), glyph.width * glyph.height);
    }
}
