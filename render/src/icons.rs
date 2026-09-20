//! Small vector icons for the browser's own chrome (back/forward,
//! reload, bookmark, account) — NOT for page content, which never
//! goes through this module.
//!
//! There's no SVG (or any path/stroke) support anywhere in this
//! crate's dependency tree (see this crate's own module doc comment
//! on what `Canvas` does and doesn't do) — every icon here is instead
//! a short, hand-authored list of vertices in a `[-1, 1]` square,
//! centered on the origin, filled with `Canvas::fill_triangle`/
//! `fill_circle`/`fill_polygon` and only ever scaled/translated at
//! paint time via `to_canvas`. That keeps each icon's shape declared
//! in one readable place (a vertex list) rather than as inline pixel
//! arithmetic, the closest practical equivalent to an SVG path this
//! crate's primitives allow. `fill_polygon`'s fan triangulation
//! requires a shape that's star-shaped w.r.t. its centroid (see its
//! own doc comment) — every shape below satisfies that by construction.

use crate::{Canvas, Color};

/// Maps `points` (each coordinate in `[-1, 1]`) onto a `size`-wide
/// square centered at `(cx, cy)` in canvas pixels.
fn to_canvas(cx: f32, cy: f32, size: f32, points: &[(f32, f32)]) -> Vec<(f32, f32)> {
    let half = size / 2.0;
    points
        .iter()
        .map(|(x, y)| (cx + x * half, cy + y * half))
        .collect()
}

fn fill_triangle_points(canvas: &mut Canvas, p: &[(f32, f32)], color: Color) {
    canvas.fill_triangle(p[0].0, p[0].1, p[1].0, p[1].1, p[2].0, p[2].1, color);
}

/// A solid triangle pointing left — the back-navigation icon.
pub fn paint_back_arrow(canvas: &mut Canvas, cx: f32, cy: f32, size: f32, color: Color) {
    let p = to_canvas(cx, cy, size, &[(0.7, -0.8), (0.7, 0.8), (-0.8, 0.0)]);
    fill_triangle_points(canvas, &p, color);
}

/// A solid triangle pointing right — the forward-navigation icon.
pub fn paint_forward_arrow(canvas: &mut Canvas, cx: f32, cy: f32, size: f32, color: Color) {
    let p = to_canvas(cx, cy, size, &[(-0.7, -0.8), (-0.7, 0.8), (0.8, 0.0)]);
    fill_triangle_points(canvas, &p, color);
}

/// A circular reload arrow: since `Canvas` has no arc/stroke
/// primitive, the ring is approximated the same way `fill_circle`
/// already exists to draw a solid dot — by placing a dense row of
/// small solid circles along ~280° of a larger circle's path — with a
/// triangular arrowhead at one end showing the direction of travel.
pub fn paint_reload_icon(canvas: &mut Canvas, cx: f32, cy: f32, size: f32, color: Color) {
    let radius = size * 0.36;
    let dot_radius = (size * 0.085).max(1.0);
    let start_deg: f32 = -75.0;
    let end_deg: f32 = 205.0;
    let steps = 16;
    for i in 0..=steps {
        let t = i as f32 / steps as f32;
        let angle = (start_deg + (end_deg - start_deg) * t).to_radians();
        let x = cx + radius * angle.cos();
        let y = cy + radius * angle.sin();
        canvas.fill_circle(x, y, dot_radius, color);
    }

    // Arrowhead at the arc's start, pointing back along the arc so the
    // whole shape reads as "circle chasing its own tail."
    let head_angle = start_deg.to_radians();
    let head_x = cx + radius * head_angle.cos();
    let head_y = cy + radius * head_angle.sin();
    let head = to_canvas(
        head_x,
        head_y,
        size * 0.42,
        &[(0.0, -0.9), (0.9, 0.5), (-0.9, 0.5)],
    );
    fill_triangle_points(canvas, &head, color);
}

/// A five-pointed star — the bookmark toggle. Always filled solid;
/// callers signal "bookmarked" vs. "not" purely through `color` (a
/// bright vs. dimmed tone), the same convention `paint_nav_button`
/// already uses for its own enabled/disabled state.
pub fn paint_star(canvas: &mut Canvas, cx: f32, cy: f32, size: f32, color: Color) {
    let mut points = Vec::with_capacity(10);
    for i in 0..10 {
        let angle = std::f32::consts::FRAC_PI_2 + (i as f32) * std::f32::consts::PI / 5.0;
        let r = if i % 2 == 0 { 1.0 } else { 0.45 };
        points.push((r * angle.cos(), -r * angle.sin()));
    }
    let p = to_canvas(cx, cy, size, &points);
    canvas.fill_polygon(&p, color);
}

/// A simple person silhouette (head + shoulders) — the account button.
pub fn paint_account_icon(canvas: &mut Canvas, cx: f32, cy: f32, size: f32, color: Color) {
    canvas.fill_circle(cx, cy - size * 0.18, size * 0.22, color);
    let shoulders = to_canvas(
        cx,
        cy + size * 0.32,
        size,
        &[(-0.55, 0.55), (0.55, 0.55), (0.35, -0.2), (-0.35, -0.2)],
    );
    canvas.fill_polygon(&shoulders, color);
}
