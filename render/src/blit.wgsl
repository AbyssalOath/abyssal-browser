// Fullscreen-triangle blit shader.
//
// Draws a single triangle big enough to cover the whole clip-space
// viewport (no vertex buffer needed — the 3 positions are hardcoded
// and indexed by @builtin(vertex_index)). The fragment shader just
// samples `page_texture` at each pixel's corresponding UV coordinate.
// This is the standard trick for "I just want to blit a texture to
// the screen" without setting up a quad + index buffer.

struct VertexOutput {
    @builtin(position) position: vec4<f32>,
    @location(0) uv: vec2<f32>,
};

@vertex
fn vs_main(@builtin(vertex_index) vertex_index: u32) -> VertexOutput {
    var positions = array<vec2<f32>, 3>(
        vec2<f32>(-1.0, -1.0),
        vec2<f32>(3.0, -1.0),
        vec2<f32>(-1.0, 3.0),
    );

    var out: VertexOutput;
    let pos = positions[vertex_index];
    out.position = vec4<f32>(pos, 0.0, 1.0);

    // Map clip space [-1, 1] to UV [0, 1]. Flip Y: our pixel buffer
    // is top-left origin (row 0 = top of the page) but clip-space Y
    // increases upward, so without the flip the page would render
    // upside down.
    out.uv = vec2<f32>((pos.x + 1.0) * 0.5, 1.0 - (pos.y + 1.0) * 0.5);
    return out;
}

@group(0) @binding(0) var page_texture: texture_2d<f32>;
@group(0) @binding(1) var page_sampler: sampler;

@fragment
fn fs_main(in: VertexOutput) -> @location(0) vec4<f32> {
    return textureSample(page_texture, page_sampler, in.uv);
}
