#!/usr/bin/env bash
# Builds a real, real double-clickable "Abyssal Browser.app" bundle —
# must be run ON macOS (it shells out to `iconutil`, a real macOS-only
# tool that ships with every Mac via Xcode Command Line Tools, to
# build a real, correct multi-resolution `.icns` from the plain PNGs
# in icon.iconset/ — deliberately NOT hand-built by this project itself
# the way the Windows `.ico`/Linux `.png` icons are, since Apple's own
# tool is the one thing guaranteed to produce a `.icns` macOS actually
# accepts, and this project has no way to verify a hand-rolled one
# against real macOS at all).
#
# This is a real (if minimal) unsigned app bundle: no code signing, no
# notarization. macOS Gatekeeper will refuse to open it with a plain
# double-click the first time — right-click it and choose "Open" (or
# run `xattr -dr com.apple.quarantine "Abyssal Browser.app"` first) to
# get past that for a build you built yourself. Neither signing nor
# notarization is something this project can do without a real Apple
# Developer account, so it's out of scope here — a real, documented gap,
# not an oversight.

set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "error: this script builds a real macOS .app bundle and must be run on macOS." >&2
    exit 1
fi
if ! command -v iconutil >/dev/null 2>&1; then
    echo "error: iconutil not found — install the Xcode Command Line Tools:" >&2
    echo "       xcode-select --install" >&2
    exit 1
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"

echo "Building the abyssal + abyssal-renderer binaries (release)..."
(cd "$repo_root" && cargo build --release -p abyssal -p renderer)

binary="$repo_root/target/release/abyssal"
if [ ! -x "$binary" ]; then
    echo "error: expected a built binary at $binary" >&2
    exit 1
fi
# `abyssal` spawns this as a SANDBOXED CHILD PROCESS on every real
# navigation (see `app::renderer_binary_path`'s own doc comment) — it
# looks for it as a plain sibling file next to its own executable, so
# it has to actually be IN "Contents/MacOS" alongside `abyssal` itself,
# not just built and left under `target/release/`. Omitting this was a
# real bug: every past build of this script produced an app that
# launched fine but panicked/failed the instant it tried to render its
# first real page, since `renderer_binary_path()` found nothing there.
renderer_binary="$repo_root/target/release/abyssal-renderer"
if [ ! -x "$renderer_binary" ]; then
    echo "error: expected a built binary at $renderer_binary" >&2
    exit 1
fi

app_name="Abyssal Browser.app"
app_dir="$repo_root/$app_name"
contents_dir="$app_dir/Contents"
macos_dir="$contents_dir/MacOS"
resources_dir="$contents_dir/Resources"

echo "Creating $app_name ..."
rm -rf "$app_dir"
mkdir -p "$macos_dir" "$resources_dir"

cp "$binary" "$macos_dir/abyssal"
cp "$renderer_binary" "$macos_dir/abyssal-renderer"

echo "Building icon.icns from icon.iconset via iconutil..."
iconutil -c icns "$script_dir/icon.iconset" -o "$resources_dir/icon.icns"

# Read from the repo's own single source of truth rather than a
# hardcoded string here going stale the moment `VERSION` bumps.
app_version="$(cat "$repo_root/VERSION")"

cat > "$contents_dir/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleName</key>
	<string>Abyssal Browser</string>
	<key>CFBundleDisplayName</key>
	<string>Abyssal Browser</string>
	<key>CFBundleIdentifier</key>
	<string>com.abyssal-browser.app</string>
	<key>CFBundleVersion</key>
	<string>$app_version</string>
	<key>CFBundleShortVersionString</key>
	<string>$app_version</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleExecutable</key>
	<string>abyssal</string>
	<key>CFBundleIconFile</key>
	<string>icon.icns</string>
	<key>LSMinimumSystemVersion</key>
	<string>11.0</string>
	<key>NSHighResolutionCapable</key>
	<true/>
</dict>
</plist>
PLIST

echo "Done: $app_dir"
echo "Gatekeeper will block a plain double-click on an unsigned app the first time —"
echo "right-click it and choose Open, or run:"
echo "  xattr -dr com.apple.quarantine \"$app_dir\""
