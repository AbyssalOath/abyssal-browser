# Packaging

How to get a real, launcher/Dock/Start-menu-visible "Abyssal Browser"
on each platform, with the real bundled icon. None of this is required
to just run the browser (`cargo run -p abyssal`) -- it's for daily-use
testing convenience.

Tagging a release (`v*.*.*`) runs all of this automatically for all
three platforms via `.github/workflows/release.yml` -- Linux and
Windows built natively on their own CI runners, macOS built natively
on both a real Intel and a real Apple Silicon runner -- and attaches
the results to the GitHub release. Everything below is for running the
same steps yourself locally.

## Icon source

`assets/icons/abyssal-browser-icon.png` (2048×2048) is the master --
every per-platform icon below (`app/assets/icon.png`, `app/assets/
icon.ico`, `packaging/macos/icon.iconset/*.png`) is resized down from
it, not hand-edited. Regenerate all of them after replacing the master
with Pillow:

```python
from PIL import Image
master = Image.open("assets/icons/abyssal-browser-icon.png").convert("RGBA")
master.resize((256, 256), Image.LANCZOS).save("app/assets/icon.png")
master.resize((256, 256), Image.LANCZOS).save(
    "app/assets/icon.ico",
    sizes=[(s, s) for s in (16, 24, 32, 48, 64, 128, 256)],
)
for name, size in {
    "icon_16x16.png": 16, "icon_16x16@2x.png": 32,
    "icon_32x32.png": 32, "icon_32x32@2x.png": 64,
    "icon_128x128.png": 128, "icon_128x128@2x.png": 256,
    "icon_256x256.png": 256, "icon_256x256@2x.png": 512,
    "icon_512x512.png": 512, "icon_512x512@2x.png": 1024,
}.items():
    master.resize((size, size), Image.LANCZOS).save(
        f"packaging/macos/icon.iconset/{name}"
    )
```

## Linux

```
cargo build --release -p abyssal
./packaging/linux/install.sh
```

Installs a `.desktop` launcher entry and a themed icon under
`~/.local/share/` (no root needed). Re-run the script any time you
rebuild -- it just points at whatever binary it finds under `target/`
(or, if you extracted a downloaded release tarball instead of building
locally, right next to itself -- the same `install.sh` ships inside
that tarball for exactly that case).

The window itself also sets a real X11 `WM_CLASS`/Wayland app id
(`abyssal-browser`, matching this `.desktop` file) -- see
`render::window::run_window`'s own comment on `with_name` for why
that's what actually makes a Wayland compositor find the icon at all
(Wayland otherwise ignores a window's icon set at runtime).

## macOS

```
./packaging/macos/build_app.sh
```

Must be run ON a Mac (it shells out to `iconutil`, part of the Xcode
Command Line Tools, to build a real `.icns` from `icon.iconset/`).
Produces `Abyssal Browser.app` at the repo root -- drag it to
`/Applications`, or just run it in place.

The app is unsigned (no Apple Developer account) and unnotarized, so
Gatekeeper blocks a plain double-click the first time. Right-click →
Open, or `xattr -dr com.apple.quarantine "Abyssal Browser.app"`.

## Windows

Nothing extra to run -- just build normally:

```
cargo build --release -p abyssal
```

`build.rs` embeds `assets/icon.ico` as the `.exe`'s real native icon
resource automatically (via `winresource`, using MSVC's `rc.exe` or
MinGW's `windres`) whenever the target is Windows. Only works building
NATIVELY on Windows -- see `build.rs`'s own doc comment for why cross-
compiling a Windows binary from another OS doesn't currently pick this
up.
