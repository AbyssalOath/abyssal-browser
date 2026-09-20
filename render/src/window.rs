//! `render::window` — opens a real OS window and displays a `Canvas`
//! using `wgpu`, and translates raw OS input (mouse, keyboard, resize)
//! into a small `InputEvent` enum for the caller to handle.
//!
//! Deliberate design boundary: this module knows nothing about
//! `dom`/`css`/`html`/`layout`'s tree types — it only knows `Canvas`
//! and raw input coordinates/keys. All of "what does a click mean"
//! (hit-testing, navigation, scrolling, an address bar) lives in
//! `app`, which supplies a `handler` closure. That's what keeps this
//! module reusable as a thin GPU+windowing layer rather than growing
//! browser-specific logic into it.
//!
//! `handler: FnMut(InputEvent) -> Option<Frame>` is called once at
//! startup (with a synthetic `Resized` using the window's actual
//! starting size, which MUST return `Some`) and again for every
//! subsequent input event. Returning `None` means "nothing changed,
//! skip the GPU work entirely" — critical for `InputEvent::MouseMoved`
//! specifically, which fires on every pixel of cursor movement; doing
//! a full texture rebuild on every one of those (an earlier version of
//! this function did) is enough multi-megabyte GPU work per second to
//! exhaust memory and hang the system, not just slow the app down.
//! When `handler` returns `Some(frame)`, `frame.canvas` is uploaded as
//! the displayed texture, and `frame.title`, if `Some`, updates the
//! window's titlebar (used for updating the title after navigating to
//! a new page).
//!
//! Mouse coordinates in `InputEvent::MouseMoved`/`MouseClick` are
//! already converted from the window's actual physical pixel space
//! into CONTENT/canvas pixel space — i.e. already scaled to match
//! whatever size `Canvas` the last `Frame` contained — so `app` can
//! compare them directly against its own layout tree's coordinates
//! without needing to know anything about the physical-window-vs-
//! rendered-content distinction itself (see `GpuState`'s
//! `canvas_width`/`canvas_height` tracking and `physical_to_content`).
//!
//! The GPU path itself is still the simplest possible one: the
//! CPU-side `Canvas` is uploaded as a texture, and every frame is
//! that texture blitted to the window via a fullscreen triangle + a
//! trivial fragment shader that samples it (see blit.wgsl). There is:
//!   - no true pillarboxing — if a `Frame`'s `Canvas` has a different
//!     aspect ratio than the window, the texture is stretched to fill
//!     the surface rather than centered with solid bars around it —
//!     flagged as a known simplification, not an oversight. (This
//!     also means mouse coordinate scaling assumes uniform stretch,
//!     not letterboxed bars — consistent with that same
//!     simplification, not a separate bug.)
//!   - no `wgpu`-native painting — `render::paint` still rasterizes
//!     to a CPU buffer first, which is fine at this scale but won't
//!     be once real pages need frequent repaints
//!   - resize IS debounced (see `run_window`'s `RESIZE_DEBOUNCE`) —
//!     only one relayout+repaint+texture-rebuild happens per drag,
//!     after motion pauses, rather than one per intermediate event.
//!     Click/scroll/keyboard events are NOT debounced — every one
//!     calls `handler` immediately, since those are discrete and
//!     infrequent. `MouseMoved` fires constantly (every pixel of
//!     cursor movement) and is called every time too, BUT `handler`
//!     returning `None` for it (as `app` does, since there are no
//!     hover effects) means each call does no GPU work at all — see
//!     `run_window`'s own doc comment for why that distinction is
//!     load-bearing, not cosmetic.
//!
//! A momentary black flash during resize on X11 without a compositing
//! manager (common under window managers like IceWM that don't run
//! one by default) is a platform-level artifact of uncomposited GPU
//! swapchain resizing, not something this module can fix from inside
//! the app — running a lightweight compositor (e.g. `picom`) is the
//! usual remedy, and is worth testing to confirm that's the cause
//! before assuming a code-level bug.
//!
//! Next steps, roughly in order of payoff:
//!   1. True pillarboxing: center the texture in the surface at its
//!      own aspect ratio via `RenderPass::set_viewport`, clearing the
//!      surrounding bars to the theme background, instead of
//!      stretching to fill — and correspondingly stop assuming
//!      uniform-stretch when scaling mouse coordinates.
//!   2. Eventually move painting itself onto the GPU (real draw
//!      calls) instead of CPU-rasterize-then-blit — worth doing once
//!      text rendering is the bottleneck.
//!
//! Version note: wgpu 0.19 expects raw-window-handle 0.6; winit 0.29
//! needs its "rwh_06" feature enabled (see Cargo.toml) to satisfy
//! that. If you bump either dependency, re-check they still agree.
//! Keyboard handling uses winit 0.29's `KeyEvent`/`keyboard::Key` API
//! (`logical_key: Key::Named(NamedKey::...)` / `Key::Character(...)`)
//! — the API winit settled on starting in 0.29, replacing the older
//! pre-0.29 `VirtualKeyCode` enum. If you bump winit, re-check this
//! API shape hasn't moved again.

use std::sync::Arc;

use accesskit::{
    ActionRequest, NodeBuilder, NodeClassSet, NodeId as AccessibilityNodeId, Role, Tree, TreeUpdate,
};
use accesskit_winit::{ActionRequestEvent, Adapter as AccessibilityAdapter};
use winit::{
    dpi::PhysicalSize,
    event::{ElementState, Event, MouseButton, MouseScrollDelta, WindowEvent},
    event_loop::EventLoopBuilder,
    keyboard::{Key, ModifiersState, NamedKey},
    window::WindowBuilder,
};

use crate::Canvas;

/// The one custom user event this window's event loop carries — just
/// AccessKit's own action-request bridge. An assistive technology can
/// call AccessKit's action handler from basically any thread (see
/// `accesskit_winit::Adapter`'s own doc comment); routing it through
/// winit's `EventLoopProxy`/user-event mechanism is what gets it back
/// onto the SAME thread `handler`/the GPU state already run on, rather
/// than this module needing its own locking around them.
enum UserEvent {
    AccessKit(ActionRequestEvent),
}

impl From<ActionRequestEvent> for UserEvent {
    fn from(event: ActionRequestEvent) -> Self {
        UserEvent::AccessKit(event)
    }
}

/// A trivial, single-node tree — the ONLY tree this module ever builds
/// itself. It exists purely to satisfy `accesskit_winit::Adapter::new`'s
/// `source` parameter (a real accessible tree must exist, lazily, from
/// the moment assistive tech first asks — see that method's own doc
/// comment), and is immediately superseded by a real one describing
/// the actual page: `app` builds every REAL tree (see `Frame::
/// accessibility_update`) from data (the DOM/layout tree) this crate
/// deliberately knows nothing about — see this module's own top-level
/// doc comment on that boundary. Whatever AT-visible gap exists between
/// activation and the next real `Frame` is the same order of magnitude
/// as the gap before the first real `Frame::canvas` paints over
/// `GpuState`'s own initial blank surface.
fn placeholder_accessibility_tree() -> TreeUpdate {
    let mut classes = NodeClassSet::new();
    let root_id = AccessibilityNodeId(0);
    let root = NodeBuilder::new(Role::Window).build(&mut classes);
    TreeUpdate {
        nodes: vec![(root_id, root)],
        tree: Some(Tree::new(root_id)),
        focus: root_id,
    }
}

/// Raw, already-decoded RGBA8 pixel data for a window icon — decoding
/// (PNG or otherwise) is deliberately the CALLER's job, not this
/// crate's: `render::window` stays a thin, app-agnostic windowing
/// layer with no idea what an icon file even looks like (the same
/// boundary its own module docs describe for `InputEvent`/`Frame` —
/// this crate knows nothing about DOM/layout, and by the same logic,
/// nothing about image file formats either), so it never depends on an
/// image-decoding crate itself. `width * height * 4` must equal
/// `rgba.len()` (winit's own requirement — see `Icon::from_rgba`) or
/// `run_window` logs a warning and simply runs with no icon rather
/// than panicking over what's purely a cosmetic detail.
pub struct WindowIcon {
    pub rgba: Vec<u8>,
    pub width: u32,
    pub height: u32,
}

/// A raw input event, already translated from winit's types into
/// something `app` can act on without depending on `winit` itself.
#[derive(Debug, Clone)]
pub enum InputEvent {
    /// The window's content area resized to this new (physical) size.
    /// Sent once synthetically at startup with the window's actual
    /// starting size, and again on every real resize (after the same
    /// debounce `run_window` has always applied to resizes).
    Resized {
        width: u32,
        height: u32,
    },
    /// Mouse moved to this position, in CONTENT/canvas pixel space —
    /// see module docs. Not adjusted for any scrolling `app` itself
    /// tracks; `app` decides what (if anything) its own scroll offset
    /// means for hit-testing.
    MouseMoved {
        x: f32,
        y: f32,
    },
    /// Left mouse button pressed, at the position of the most recent
    /// `MouseMoved` (winit's click event itself carries no position).
    MouseClick {
        x: f32,
        y: f32,
    },
    /// Mouse wheel scrolled. Sign/magnitude are OS/device-dependent —
    /// `app` is responsible for picking a sensible scroll-speed
    /// multiplier and clamping its own scroll offset.
    Scroll {
        delta_y: f32,
    },
    /// A character was typed, already resolved through the keyboard
    /// layout (see winit's `KeyEvent::text`) — not a raw key code.
    CharTyped(char),
    Backspace,
    Enter,
    Escape,
    /// Left arrow with no modifier held — moves a text cursor (e.g. in
    /// the address bar) one character left. Distinct from `NavigateBack`
    /// (Alt+Left), which the OS/browser convention reserves for history
    /// navigation regardless of which widget has focus.
    ArrowLeft,
    ArrowRight,
    Home,
    End,
    /// Alt+Left — the standard "go back" keybinding, sent instead of
    /// `ArrowLeft` whenever Alt is held at the time of the keypress.
    NavigateBack,
    /// Alt+Right — the standard "go forward" keybinding.
    NavigateForward,
    /// Ctrl+T — the standard "open a new tab" keybinding.
    NewTab,
    /// Ctrl+W — the standard "close the current tab" keybinding.
    CloseTab,
    /// Ctrl+Tab — the standard "next tab" keybinding.
    NextTab,
    /// Ctrl+Shift+Tab — the standard "previous tab" keybinding.
    PreviousTab,
    /// Ctrl+F — the standard "find in page" keybinding.
    Find,
    /// Shift+Enter — "find previous match," the standard companion to
    /// plain `Enter`'s "find next match" while a find-in-page session
    /// is active. Sent instead of `Enter` whenever Shift is held at
    /// keypress time; harmless outside find-in-page (`app` just treats
    /// it as a no-op there, the same way an unused shortcut elsewhere
    /// would be).
    FindPrevious,
    /// `F12` — the standard "toggle DevTools" keybinding.
    ToggleDevTools,
    /// `Ctrl+R` or `F5` — the standard "reload the current page"
    /// keybinding.
    Reload,
    /// `Ctrl+D` — the standard "bookmark this page" keybinding. Toggles
    /// (see `app::Browser`'s handling): pressed again on an
    /// already-bookmarked page, it un-bookmarks it rather than adding
    /// a second copy.
    ToggleBookmark,
    /// Plain `Tab` (no modifier) — moves keyboard focus to the next
    /// focusable element on the PAGE (or, while a browser-chrome text
    /// field like the address bar/find bar/DevTools console has focus
    /// instead, `app` handles this some other way — see `Browser::
    /// handle_event`'s own `FocusNext` arm). Distinct from `NextTab`
    /// (`Ctrl+Tab`, browser TAB-strip cycling — an entirely different
    /// feature that happens to share a key name).
    FocusNext,
    /// `Shift+Tab` — same as `FocusNext`, backwards.
    FocusPrevious,
    /// A real assistive technology (a screen reader, a switch-access
    /// tool, ...) asked to do something — reused from `accesskit`
    /// wholesale rather than this crate defining its own parallel
    /// action vocabulary, since it's ALREADY exactly the right shape
    /// (a target node id plus an action) and `app` needs the full,
    /// real `accesskit::Action` enum to interpret it correctly anyway.
    /// See `render::window`'s own module docs on the AccessKit
    /// integration this rides on, and `app::Browser`'s own handling
    /// for which `Action`s are actually supported (`Focus`/`Default`
    /// today — an AT requesting anything else is a harmless no-op).
    AccessibilityAction(ActionRequest),
    /// No real input happened — `handler` is being given a chance to
    /// act on a wake-up a PREVIOUS `Frame` asked for via `wake_at`
    /// (e.g. running a due `setTimeout`). Never sent unless a prior
    /// `Frame` requested it; see `Frame::wake_at`'s doc comment.
    Tick,
}

/// What `handler` hands back after processing one `InputEvent`: the
/// pixels to display, optionally a new window title (e.g. after
/// navigating to a page with a different `<title>`), and optionally a
/// future instant to wake up at even with no real input.
pub struct Frame {
    pub canvas: Canvas,
    /// `Some` to update the titlebar this frame; `None` to leave it
    /// exactly as it is (the common case — most events don't change
    /// the page's title).
    pub title: Option<String>,
    /// If `Some`, `handler` will be called again with `InputEvent::Tick`
    /// at approximately this instant, even with no real user input —
    /// the primitive `setTimeout` is built on (see `ipc`'s module
    /// docs): a purely reactive, single-threaded event loop waking
    /// ITSELF at a specific future time via winit's own
    /// `ControlFlow::WaitUntil`, the same mechanism this module already
    /// used for resize debouncing before `Tick` existed — no polling,
    /// no background thread. `None` clears any previously scheduled
    /// wake-up. The caller recomputes this fresh on every `Frame` it
    /// returns (e.g. `app` tracks the earliest pending timer across
    /// every tab, or `None` if nothing is pending anywhere) — this
    /// module never merges or accumulates deadlines across calls
    /// itself, it just acts on whatever the most recent `Frame` said.
    pub wake_at: Option<std::time::Instant>,
    /// A full description of the current page for a real assistive
    /// technology — see this module's own doc comment on the AccessKit
    /// integration. Required (not `Option`) on every `Frame`: `app`
    /// builds one from whatever it already has (the active tab's
    /// layout tree) on every call to its own `frame()` constructor, so
    /// there's no meaningful "nothing changed" case the way there is
    /// for `title`/`wake_at` — unlike a texture re-upload, handing this
    /// to `accesskit_winit::Adapter::update_if_active` costs nothing at
    /// all unless a real AT is actually attached and listening.
    pub accessibility_update: TreeUpdate,
}

struct GpuState {
    surface: wgpu::Surface<'static>,
    device: wgpu::Device,
    queue: wgpu::Queue,
    config: wgpu::SurfaceConfiguration,
    pipeline: wgpu::RenderPipeline,
    bind_group_layout: wgpu::BindGroupLayout,
    sampler: wgpu::Sampler,
    /// `None` until the first `update_texture` call — there's no
    /// valid `Canvas` to build a texture from until `handler` has run
    /// at least once.
    bind_group: Option<wgpu::BindGroup>,
    /// Dimensions of the `Canvas` behind the current texture — used
    /// to scale incoming physical mouse coordinates into content
    /// space (see `physical_to_content`). `(1, 1)` until the first
    /// `update_texture` call; harmless, since no mouse event is
    /// meaningfully positioned before then anyway.
    canvas_width: u32,
    canvas_height: u32,
    window: Arc<winit::window::Window>,
}

impl GpuState {
    async fn new(window: Arc<winit::window::Window>) -> Self {
        let size = window.inner_size();

        let instance = wgpu::Instance::new(wgpu::InstanceDescriptor::default());
        let surface = instance
            .create_surface(window.clone())
            .expect("creating a wgpu surface for the window should succeed");

        let adapter = instance
            .request_adapter(&wgpu::RequestAdapterOptions {
                power_preference: wgpu::PowerPreference::default(),
                compatible_surface: Some(&surface),
                force_fallback_adapter: false,
            })
            .await
            .expect(
                "should find a GPU adapter — if this fails, check your system's \
                 Vulkan/Metal/DX12 drivers are installed and up to date",
            );

        let (device, queue) = adapter
            .request_device(
                &wgpu::DeviceDescriptor {
                    label: Some("browser-device"),
                    required_features: wgpu::Features::empty(),
                    required_limits: wgpu::Limits::default(),
                },
                None,
            )
            .await
            .expect("requesting a logical device from the adapter should succeed");

        let surface_caps = surface.get_capabilities(&adapter);
        let surface_format = surface_caps
            .formats
            .iter()
            .copied()
            .find(|f| f.is_srgb())
            .unwrap_or(surface_caps.formats[0]);

        let config = wgpu::SurfaceConfiguration {
            usage: wgpu::TextureUsages::RENDER_ATTACHMENT,
            format: surface_format,
            width: size.width.max(1),
            height: size.height.max(1),
            present_mode: surface_caps.present_modes[0],
            alpha_mode: surface_caps.alpha_modes[0],
            view_formats: vec![],
            desired_maximum_frame_latency: 2,
        };
        surface.configure(&device, &config);

        let sampler = device.create_sampler(&wgpu::SamplerDescriptor {
            label: Some("page-canvas-sampler"),
            address_mode_u: wgpu::AddressMode::ClampToEdge,
            address_mode_v: wgpu::AddressMode::ClampToEdge,
            address_mode_w: wgpu::AddressMode::ClampToEdge,
            mag_filter: wgpu::FilterMode::Linear,
            min_filter: wgpu::FilterMode::Linear,
            mipmap_filter: wgpu::FilterMode::Nearest,
            ..Default::default()
        });

        let bind_group_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("page-canvas-bind-group-layout"),
            entries: &[
                wgpu::BindGroupLayoutEntry {
                    binding: 0,
                    visibility: wgpu::ShaderStages::FRAGMENT,
                    ty: wgpu::BindingType::Texture {
                        sample_type: wgpu::TextureSampleType::Float { filterable: true },
                        view_dimension: wgpu::TextureViewDimension::D2,
                        multisampled: false,
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 1,
                    visibility: wgpu::ShaderStages::FRAGMENT,
                    ty: wgpu::BindingType::Sampler(wgpu::SamplerBindingType::Filtering),
                    count: None,
                },
            ],
        });

        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("fullscreen-blit-shader"),
            source: wgpu::ShaderSource::Wgsl(include_str!("blit.wgsl").into()),
        });

        let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("blit-pipeline-layout"),
            bind_group_layouts: &[&bind_group_layout],
            push_constant_ranges: &[],
        });

        let pipeline = device.create_render_pipeline(&wgpu::RenderPipelineDescriptor {
            label: Some("blit-pipeline"),
            layout: Some(&pipeline_layout),
            vertex: wgpu::VertexState {
                module: &shader,
                entry_point: "vs_main",
                buffers: &[],
            },
            fragment: Some(wgpu::FragmentState {
                module: &shader,
                entry_point: "fs_main",
                targets: &[Some(wgpu::ColorTargetState {
                    format: config.format,
                    blend: Some(wgpu::BlendState::REPLACE),
                    write_mask: wgpu::ColorWrites::ALL,
                })],
            }),
            primitive: wgpu::PrimitiveState {
                topology: wgpu::PrimitiveTopology::TriangleList,
                ..Default::default()
            },
            depth_stencil: None,
            multisample: wgpu::MultisampleState::default(),
            multiview: None,
        });

        GpuState {
            surface,
            device,
            queue,
            config,
            pipeline,
            bind_group_layout,
            sampler,
            bind_group: None,
            canvas_width: 1,
            canvas_height: 1,
            window,
        }
    }

    /// Reconfigures the swapchain surface to match the window's actual
    /// physical pixel size. Independent of `update_texture` — the
    /// surface is always the real window size; the *texture* (the
    /// painted page content) may be a different, letterboxed size,
    /// and gets stretched to fit (see module docs).
    fn resize(&mut self, new_size: PhysicalSize<u32>) {
        if new_size.width > 0 && new_size.height > 0 {
            self.config.width = new_size.width;
            self.config.height = new_size.height;
            self.surface.configure(&self.device, &self.config);
        }
    }

    /// Upload `canvas` as the GPU texture that gets blitted each
    /// frame, replacing whatever texture (if any) was there before,
    /// and remembers its dimensions for mouse coordinate scaling (see
    /// `physical_to_content`).
    fn update_texture(&mut self, canvas: &Canvas) {
        self.canvas_width = (canvas.width as u32).max(1);
        self.canvas_height = (canvas.height as u32).max(1);

        let texture_size = wgpu::Extent3d {
            width: self.canvas_width,
            height: self.canvas_height,
            depth_or_array_layers: 1,
        };
        let texture = self.device.create_texture(&wgpu::TextureDescriptor {
            label: Some("page-canvas-texture"),
            size: texture_size,
            mip_level_count: 1,
            sample_count: 1,
            dimension: wgpu::TextureDimension::D2,
            format: wgpu::TextureFormat::Rgba8UnormSrgb,
            usage: wgpu::TextureUsages::TEXTURE_BINDING | wgpu::TextureUsages::COPY_DST,
            view_formats: &[],
        });
        self.queue.write_texture(
            wgpu::ImageCopyTexture {
                texture: &texture,
                mip_level: 0,
                origin: wgpu::Origin3d::ZERO,
                aspect: wgpu::TextureAspect::All,
            },
            &canvas.pixels,
            wgpu::ImageDataLayout {
                offset: 0,
                bytes_per_row: Some(4 * canvas.width as u32),
                rows_per_image: Some(canvas.height as u32),
            },
            texture_size,
        );

        let texture_view = texture.create_view(&wgpu::TextureViewDescriptor::default());
        self.bind_group = Some(self.device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("page-canvas-bind-group"),
            layout: &self.bind_group_layout,
            entries: &[
                wgpu::BindGroupEntry {
                    binding: 0,
                    resource: wgpu::BindingResource::TextureView(&texture_view),
                },
                wgpu::BindGroupEntry {
                    binding: 1,
                    resource: wgpu::BindingResource::Sampler(&self.sampler),
                },
            ],
        }));
        // `texture` itself is dropped here, but the bind group and its
        // texture view keep the underlying wgpu resource alive — this
        // matches the standard wgpu pattern of not needing to hold the
        // `Texture` handle once a view into it exists.
    }

    /// Converts a physical-pixel mouse position (as winit reports it,
    /// relative to the actual window) into content/canvas pixel space
    /// — assuming uniform stretch between the two, since that's how
    /// this module currently displays a `Canvas` of a different size
    /// than the window (see module docs' pillarboxing TODO).
    fn physical_to_content(&self, physical_x: f64, physical_y: f64) -> (f32, f32) {
        let scale_x = self.canvas_width as f64 / (self.config.width.max(1) as f64);
        let scale_y = self.canvas_height as f64 / (self.config.height.max(1) as f64);
        ((physical_x * scale_x) as f32, (physical_y * scale_y) as f32)
    }

    fn redraw(&mut self) {
        let Some(bind_group) = &self.bind_group else {
            // No `update_texture` call yet — nothing to draw. Shouldn't
            // happen in practice since `run_window` always populates
            // this before entering the event loop, but this guards
            // against ever presenting garbage instead of panicking.
            return;
        };

        let output = match self.surface.get_current_texture() {
            Ok(frame) => frame,
            Err(wgpu::SurfaceError::Lost | wgpu::SurfaceError::Outdated) => {
                self.surface.configure(&self.device, &self.config);
                return;
            }
            Err(e) => {
                eprintln!("dropped frame: {e:?}");
                return;
            }
        };
        let view = output
            .texture
            .create_view(&wgpu::TextureViewDescriptor::default());

        let mut encoder = self
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("blit-encoder"),
            });
        {
            let mut pass = encoder.begin_render_pass(&wgpu::RenderPassDescriptor {
                label: Some("blit-pass"),
                color_attachments: &[Some(wgpu::RenderPassColorAttachment {
                    view: &view,
                    resolve_target: None,
                    ops: wgpu::Operations {
                        load: wgpu::LoadOp::Clear(wgpu::Color::BLACK),
                        store: wgpu::StoreOp::Store,
                    },
                })],
                depth_stencil_attachment: None,
                timestamp_writes: None,
                occlusion_query_set: None,
            });
            pass.set_pipeline(&self.pipeline);
            pass.set_bind_group(0, bind_group, &[]);
            pass.draw(0..3, 0..1); // fullscreen triangle — no vertex buffer needed
        }
        self.queue.submit(std::iter::once(encoder.finish()));
        output.present();
    }
}

/// Open a window and keep it live: `handler(event)` is called once at
/// startup with a synthetic `InputEvent::Resized` (the window's actual
/// starting size), and again for every subsequent input event.
/// Whatever `Frame` it returns is displayed (and its title applied, if
/// `Some`). Blocks until the window is closed.
///
/// Resize handling is debounced (see `RESIZE_DEBOUNCE`): the cheap
/// swapchain reconfigure (`GpuState::resize`) happens on every single
/// `Resized` event so the surface never mismatches the window, but
/// the expensive part — calling `handler` (a full relayout + text
/// re-rasterization on `app`'s side) plus rebuilding the GPU texture —
/// only runs once, after resize events stop arriving for
/// `RESIZE_DEBOUNCE`. Mouse/keyboard/scroll events are NOT debounced —
/// see module docs for why.
///
/// This is the entry point `app`'s `main.rs` calls once it wants a
/// real, interactive window. `render::window` deliberately has no
/// idea what's inside `handler` — `app` owns the DOM/stylesheet/font/
/// scroll/navigation state and knows how to turn an `InputEvent` into
/// a new `Frame`; this module just displays whatever comes back.
///
/// `handler` returns `Option<Frame>`: `None` means "nothing changed,
/// don't touch the GPU at all" — critically important for
/// `InputEvent::MouseMoved`, which fires extremely often (every pixel
/// of cursor movement) and has no reason to trigger a full texture
/// rebuild if nothing on screen actually changed. An earlier version
/// of this function always did a full GPU texture upload on every
/// `MouseMoved`, which under normal mouse movement meant hundreds of
/// multi-megabyte texture rebuilds per second — enough to exhaust
/// memory and hang the whole system, not just this app. `Option<Frame>`
/// is the fix: only do GPU work when there's an actual reason to.
///
/// Correspondingly, this event loop is purely reactive — it does NOT
/// request a redraw on every loop iteration (no `Event::AboutToWait`
/// handler forcing continuous re-rendering). It only redraws when
/// `apply_frame` runs, i.e. when `handler` returned `Some`. An idle
/// window (nothing happening) uses effectively zero CPU/GPU, which is
/// what a browser sitting on a static page should do.
pub fn run_window(
    initial_title: &str,
    icon: Option<WindowIcon>,
    mut handler: impl FnMut(InputEvent) -> Option<Frame> + 'static,
) {
    const RESIZE_DEBOUNCE: std::time::Duration = std::time::Duration::from_millis(120);

    let event_loop = EventLoopBuilder::<UserEvent>::with_user_event()
        .build()
        .expect("creating the event loop should succeed");
    let mut window_builder = WindowBuilder::new()
        .with_title(initial_title)
        // AccessKit's adapter must be created before the window is
        // ever shown (see `AccessibilityAdapter::new`'s own doc
        // comment) — made invisible here, then shown for real right
        // after the adapter exists, a few lines down.
        .with_visible(false);
    // Sets the window's app id (Wayland) / `WM_CLASS` (X11) to match
    // `packaging/linux/abyssal-browser.desktop`'s own filename — the
    // convention the Desktop Entry Spec expects (see
    // `WindowBuilderExtX11`/`WindowBuilderExtWayland::with_name`'s own
    // doc comments) and what actually lets a Wayland compositor find
    // that `.desktop` file's `Icon=` for this running window at all
    // (Wayland otherwise ignores `with_window_icon` below entirely —
    // see that call's own comment). Both extension traits write the
    // SAME underlying field regardless of which one is actually
    // imported here, so importing only the X11 one still covers a
    // Wayland session correctly at runtime; only `#[cfg(unix)]`
    // platforms have either trait at all (see `winit::platform::x11`'s
    // own `#[cfg(x11_platform)]` gating), and this project's default
    // winit features keep both the `x11`/`wayland` backends compiled
    // in on every one of them.
    #[cfg(any(
        target_os = "linux",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
    ))]
    {
        use winit::platform::x11::WindowBuilderExtX11;
        window_builder = window_builder.with_name("abyssal-browser", "abyssal-browser");
    }
    // Sets the actual WINDOW's icon — real, and immediately visible in
    // the titlebar/taskbar/alt-tab switcher on X11 and many window
    // managers. Wayland compositors largely ignore this call entirely
    // and instead look up an icon from the `.desktop` file matching
    // the app id just set above — see `packaging/linux/`'s own
    // install script, which is what actually installs that file (this
    // call alone isn't enough on Wayland without it). macOS's Dock
    // icon likewise comes from the `.app` bundle's own `Info.plist`/
    // `.icns` (see `packaging/macos/`), not a runtime call like this
    // one at all.
    if let Some(icon) = icon {
        let pixel_count_matches =
            icon.rgba.len() as u64 == icon.width as u64 * icon.height as u64 * 4;
        if pixel_count_matches {
            match winit::window::Icon::from_rgba(icon.rgba, icon.width, icon.height) {
                Ok(winit_icon) => {
                    window_builder = window_builder.with_window_icon(Some(winit_icon));
                }
                Err(e) => {
                    eprintln!("Could not set the window icon (continuing without one): {e}");
                }
            }
        } else {
            eprintln!(
                "Window icon pixel data doesn't match its claimed {}x{} size — continuing without one.",
                icon.width, icon.height
            );
        }
    }
    let window = Arc::new(
        window_builder
            .build(&event_loop)
            .expect("creating the window should succeed"),
    );
    let accessibility_adapter = AccessibilityAdapter::new(
        &window,
        placeholder_accessibility_tree,
        event_loop.create_proxy(),
    );
    window.set_visible(true);

    let mut state = pollster::block_on(GpuState::new(window.clone()));

    let mut last_size = window.inner_size();
    let first_frame = handler(InputEvent::Resized {
        width: last_size.width,
        height: last_size.height,
    })
    .expect(
        "the very first handler call (startup Resized) must return Some(Frame) — \
         there's nothing to display otherwise",
    );
    state.update_texture(&first_frame.canvas);
    if let Some(title) = first_frame.title {
        state.window.set_title(&title);
    }
    // Populated from the very first `Frame` too — a page could
    // conceivably schedule a timer before any real input ever arrives.
    let mut wake_deadline: Option<std::time::Instant> = first_frame.wake_at;
    accessibility_adapter.update_if_active(|| first_frame.accessibility_update);
    state.window.request_redraw();

    // Set once a resize lands and cleared once the debounced repaint
    // for it has run. `None` means "nothing pending". Independent of
    // `wake_deadline` below — both can be pending at once (a resize
    // mid-drag on a page with a live `setTimeout`), so `reschedule`
    // always arms winit's single `ControlFlow::WaitUntil` for whichever
    // of the two is sooner.
    let mut pending_resize: Option<PhysicalSize<u32>> = None;
    let mut resize_deadline: Option<std::time::Instant> = None;
    // Most recent cursor position, in PHYSICAL pixels — winit's click
    // event carries no position of its own, so this is what
    // `MouseInput` uses to build an `InputEvent::MouseClick`.
    let mut last_cursor_physical: (f64, f64) = (0.0, 0.0);
    // Current modifier-key state, updated by `ModifiersChanged` — needed
    // to tell a plain Left/Right arrow (moves a text cursor) apart from
    // Alt+Left/Right (history back/forward), since winit's `KeyEvent`
    // itself carries no modifier info.
    let mut modifiers = ModifiersState::empty();

    let apply_frame = |state: &mut GpuState,
                       adapter: &AccessibilityAdapter,
                       frame: Frame,
                       wake_deadline: &mut Option<std::time::Instant>| {
        state.update_texture(&frame.canvas);
        if let Some(title) = frame.title {
            state.window.set_title(&title);
        }
        *wake_deadline = frame.wake_at;
        // A no-op unless a real assistive technology is actually
        // attached and listening right now — see `Frame::
        // accessibility_update`'s own doc comment.
        adapter.update_if_active(|| frame.accessibility_update);
        state.window.request_redraw();
    };

    // Arms winit's one `ControlFlow::WaitUntil` for whichever of the
    // two independent pending deadlines (resize-debounce, timer wake)
    // comes first, or `ControlFlow::Wait` (no timer at all — the idle,
    // zero-CPU state) if neither is pending.
    let reschedule = |elwt: &winit::event_loop::EventLoopWindowTarget<UserEvent>,
                      resize_deadline: Option<std::time::Instant>,
                      wake_deadline: Option<std::time::Instant>| {
        let next = match (resize_deadline, wake_deadline) {
            (None, None) => None,
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (Some(a), Some(b)) => Some(a.min(b)),
        };
        elwt.set_control_flow(match next {
            Some(deadline) => winit::event_loop::ControlFlow::WaitUntil(deadline),
            None => winit::event_loop::ControlFlow::Wait,
        });
    };

    event_loop
        .run(move |event, elwt| match event {
            Event::NewEvents(winit::event::StartCause::Init) => {
                // The very first `Frame` (built above, before the event
                // loop started) may already have asked for a wake-up —
                // this is the one place that has to account for that,
                // since every other `wake_deadline` update happens
                // inside a handler call the loop itself triggers.
                reschedule(elwt, resize_deadline, wake_deadline);
            }
            Event::NewEvents(winit::event::StartCause::ResumeTimeReached { .. }) => {
                let now = std::time::Instant::now();
                if resize_deadline.is_some_and(|d| now >= d) {
                    resize_deadline = None;
                    if let Some(size) = pending_resize.take() {
                        if let Some(frame) = handler(InputEvent::Resized {
                            width: size.width,
                            height: size.height,
                        }) {
                            apply_frame(
                                &mut state,
                                &accessibility_adapter,
                                frame,
                                &mut wake_deadline,
                            );
                        }
                    }
                }
                if wake_deadline.is_some_and(|d| now >= d) {
                    // Clear it BEFORE calling `handler`, not after —
                    // `handler` (via `apply_frame`) sets it again from
                    // the returned `Frame` if there's still (or again)
                    // something pending; if `handler` returns `None`
                    // (no `setTimeout` was actually due after all, or
                    // it was already handled elsewhere), this correctly
                    // leaves no deadline armed rather than one that
                    // would just refire immediately.
                    wake_deadline = None;
                    if let Some(frame) = handler(InputEvent::Tick) {
                        apply_frame(
                            &mut state,
                            &accessibility_adapter,
                            frame,
                            &mut wake_deadline,
                        );
                    }
                }
                reschedule(elwt, resize_deadline, wake_deadline);
            }
            Event::WindowEvent { window_id, event } if window_id == state.window.id() => {
                // Must run before this module's own handling of the
                // same event — see `AccessibilityAdapter::process_event`'s
                // own doc comment.
                accessibility_adapter.process_event(&state.window, &event);
                match event {
                    WindowEvent::CloseRequested => elwt.exit(),
                    WindowEvent::ModifiersChanged(new_modifiers) => {
                        modifiers = new_modifiers.state();
                    }
                    WindowEvent::Resized(new_size) => {
                        // Cheap: keeps the swapchain matched to the
                        // window's actual size on every event, so
                        // there's no visible mismatch/errors even
                        // before the debounced repaint below lands.
                        state.resize(new_size);

                        if new_size.width > 0 && new_size.height > 0 && new_size != last_size {
                            last_size = new_size;
                            pending_resize = Some(new_size);
                            // (Re)start the debounce countdown. Every
                            // new Resized event before it fires just
                            // pushes the deadline back — the repaint
                            // only actually happens once the drag
                            // pauses for RESIZE_DEBOUNCE.
                            resize_deadline = Some(std::time::Instant::now() + RESIZE_DEBOUNCE);
                            reschedule(elwt, resize_deadline, wake_deadline);
                        }
                    }
                    WindowEvent::CursorMoved { position, .. } => {
                        last_cursor_physical = (position.x, position.y);
                        let (x, y) = state.physical_to_content(position.x, position.y);
                        // Deliberately NOT debounced/throttled beyond
                        // whatever `handler` itself does (see module
                        // docs) — `app`'s handler returns `None` here
                        // since there are no hover effects, so this is
                        // normally a no-op with zero GPU work.
                        if let Some(frame) = handler(InputEvent::MouseMoved { x, y }) {
                            apply_frame(
                                &mut state,
                                &accessibility_adapter,
                                frame,
                                &mut wake_deadline,
                            );
                            reschedule(elwt, resize_deadline, wake_deadline);
                        }
                    }
                    WindowEvent::MouseInput {
                        state: ElementState::Pressed,
                        button: MouseButton::Left,
                        ..
                    } => {
                        let (x, y) = state
                            .physical_to_content(last_cursor_physical.0, last_cursor_physical.1);
                        if let Some(frame) = handler(InputEvent::MouseClick { x, y }) {
                            apply_frame(
                                &mut state,
                                &accessibility_adapter,
                                frame,
                                &mut wake_deadline,
                            );
                            reschedule(elwt, resize_deadline, wake_deadline);
                        }
                    }
                    WindowEvent::MouseWheel { delta, .. } => {
                        // Normalize both delta shapes to a single
                        // pixel-ish magnitude. `LineDelta` is in
                        // "lines" (mice with a notched wheel); 24px
                        // per line is a common, unscientific but
                        // reasonable default matching what several
                        // browsers/toolkits use.
                        let delta_y = match delta {
                            MouseScrollDelta::LineDelta(_, y) => y * 24.0,
                            MouseScrollDelta::PixelDelta(pos) => pos.y as f32,
                        };
                        if let Some(frame) = handler(InputEvent::Scroll { delta_y }) {
                            apply_frame(
                                &mut state,
                                &accessibility_adapter,
                                frame,
                                &mut wake_deadline,
                            );
                            reschedule(elwt, resize_deadline, wake_deadline);
                        }
                    }
                    WindowEvent::KeyboardInput {
                        event: key_event, ..
                    } => {
                        if key_event.state != ElementState::Pressed {
                            return;
                        }
                        let input_event = match key_event.logical_key {
                            // Shift+Enter — "find previous" — checked
                            // before the plain Enter arm below so a
                            // Shift-held Enter never falls through to it.
                            Key::Named(NamedKey::Enter) if modifiers.shift_key() => {
                                Some(InputEvent::FindPrevious)
                            }
                            Key::Named(NamedKey::Enter) => Some(InputEvent::Enter),
                            Key::Named(NamedKey::Backspace) => Some(InputEvent::Backspace),
                            Key::Named(NamedKey::Escape) => Some(InputEvent::Escape),
                            Key::Named(NamedKey::Space) => Some(InputEvent::CharTyped(' ')),
                            Key::Named(NamedKey::ArrowLeft) if modifiers.alt_key() => {
                                Some(InputEvent::NavigateBack)
                            }
                            Key::Named(NamedKey::ArrowRight) if modifiers.alt_key() => {
                                Some(InputEvent::NavigateForward)
                            }
                            Key::Named(NamedKey::ArrowLeft) => Some(InputEvent::ArrowLeft),
                            Key::Named(NamedKey::ArrowRight) => Some(InputEvent::ArrowRight),
                            Key::Named(NamedKey::Home) => Some(InputEvent::Home),
                            Key::Named(NamedKey::End) => Some(InputEvent::End),
                            Key::Named(NamedKey::F12) => Some(InputEvent::ToggleDevTools),
                            Key::Named(NamedKey::F5) => Some(InputEvent::Reload),
                            // Ctrl+Tab / Ctrl+Shift+Tab — tab cycling.
                            // Checked before the plain-character arm
                            // below so Ctrl-held presses never fall
                            // through to it.
                            Key::Named(NamedKey::Tab)
                                if modifiers.control_key() && modifiers.shift_key() =>
                            {
                                Some(InputEvent::PreviousTab)
                            }
                            Key::Named(NamedKey::Tab) if modifiers.control_key() => {
                                Some(InputEvent::NextTab)
                            }
                            // Plain Tab / Shift+Tab — keyboard focus
                            // traversal across the PAGE's own focusable
                            // elements (links, buttons, inputs — see
                            // `ipc::ClientMessageKind::MoveKeyboardFocus`).
                            // Reached only when Ctrl ISN'T held, thanks
                            // to the two guarded arms just above.
                            Key::Named(NamedKey::Tab) if modifiers.shift_key() => {
                                Some(InputEvent::FocusPrevious)
                            }
                            Key::Named(NamedKey::Tab) => Some(InputEvent::FocusNext),
                            // Ctrl+T / Ctrl+W — new/close tab. Matched
                            // by character rather than a `NamedKey`
                            // since winit reports plain letter keys as
                            // `Key::Character`, same as normal typing.
                            Key::Character(ref s)
                                if modifiers.control_key() && s.eq_ignore_ascii_case("t") =>
                            {
                                Some(InputEvent::NewTab)
                            }
                            Key::Character(ref s)
                                if modifiers.control_key() && s.eq_ignore_ascii_case("w") =>
                            {
                                Some(InputEvent::CloseTab)
                            }
                            Key::Character(ref s)
                                if modifiers.control_key() && s.eq_ignore_ascii_case("f") =>
                            {
                                Some(InputEvent::Find)
                            }
                            Key::Character(ref s)
                                if modifiers.control_key() && s.eq_ignore_ascii_case("r") =>
                            {
                                Some(InputEvent::Reload)
                            }
                            Key::Character(ref s)
                                if modifiers.control_key() && s.eq_ignore_ascii_case("d") =>
                            {
                                Some(InputEvent::ToggleBookmark)
                            }
                            // A plain character ONLY counts as typed
                            // text when no Ctrl shortcut matched above
                            // — without this guard, e.g. Ctrl+T would
                            // both open a new tab AND insert a stray
                            // "t" into whatever text field has focus.
                            Key::Character(ref s) if !modifiers.control_key() => {
                                s.chars().next().map(InputEvent::CharTyped)
                            }
                            _ => None,
                        };
                        if let Some(input_event) = input_event {
                            if let Some(frame) = handler(input_event) {
                                apply_frame(
                                    &mut state,
                                    &accessibility_adapter,
                                    frame,
                                    &mut wake_deadline,
                                );
                                reschedule(elwt, resize_deadline, wake_deadline);
                            }
                        }
                    }
                    WindowEvent::RedrawRequested => state.redraw(),
                    _ => {}
                }
            }
            Event::UserEvent(UserEvent::AccessKit(ActionRequestEvent { window_id, request }))
                if window_id == state.window.id() =>
            {
                if let Some(frame) = handler(InputEvent::AccessibilityAction(request)) {
                    apply_frame(
                        &mut state,
                        &accessibility_adapter,
                        frame,
                        &mut wake_deadline,
                    );
                    reschedule(elwt, resize_deadline, wake_deadline);
                }
            }
            _ => {}
        })
        .expect("event loop should run without error");
}
