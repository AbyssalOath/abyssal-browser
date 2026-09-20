#!/usr/bin/env bash
# Installs a real, real launcher-visible "Abyssal Browser" entry for
# the CURRENT USER ONLY (no root/sudo needed at all) — a `.desktop`
# file plus a proper themed icon, both under the standard XDG user
# directories (~/.local/share/...), which every mainstream Linux
# desktop (GNOME, KDE, XFCE, ...) already searches without any extra
# configuration.
#
# Deliberately NOT a system-wide install (no /usr/share, no root) —
# this is a personal testing setup, not a distro package.
#
# Works from two different layouts, tried in this order:
#   1. A downloaded release tarball, extracted — `abyssal`/
#      `abyssal-renderer`/`icon.png` sit right next to this script
#      itself (see `.github/workflows/release.yml`'s Linux packaging
#      step, which lays a release tarball out exactly this way).
#   2. A real repo checkout with a local build already done —
#      `target/{release,debug}/abyssal`, the original (and still
#      supported) use case below.
#
# What this does NOT do, and why:
#   - Doesn't copy/move the built binary anywhere. `Exec=` in the
#     installed .desktop file points directly at whatever binary this
#     script found (wherever it lives — see above) at the time it ran.
#     Rebuilding (`cargo build --release`) in place, or re-extracting a
#     release tarball to the SAME path, keeps working since the path
#     doesn't change; moving the binary (or the whole repo/extracted
#     folder) would break it — rerun this script after that.
#   - Doesn't set a Wayland icon by itself. Setting the window's own
#     app id to match this file (see `render::window::run_window`'s
#     own comment on `with_name`) is what actually makes a Wayland
#     compositor look up the icon this script installs at all.

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"

# Prefers a release build (what you'd actually want for daily testing)
# but falls back to a debug one so this doesn't force a slow rebuild
# just to try the launcher entry out.
binary=""
for candidate in \
    "$script_dir/abyssal" \
    "$repo_root/target/release/abyssal" \
    "$repo_root/target/debug/abyssal"
do
    if [ -x "$candidate" ]; then
        binary="$candidate"
        break
    fi
done
if [ -z "$binary" ]; then
    echo "error: no 'abyssal' binary found next to this script, or under $repo_root/target/{release,debug}/" >&2
    echo "Build it first: cargo build --release -p abyssal (or without --release)" >&2
    exit 1
fi
echo "Using binary: $binary"

icon_source=""
for candidate in "$script_dir/icon.png" "$repo_root/app/assets/icon.png"; do
    if [ -f "$candidate" ]; then
        icon_source="$candidate"
        break
    fi
done
if [ -z "$icon_source" ]; then
    echo "error: no icon.png found next to this script, or at $repo_root/app/assets/icon.png" >&2
    exit 1
fi

icon_dir="$HOME/.local/share/icons/hicolor/256x256/apps"
applications_dir="$HOME/.local/share/applications"
mkdir -p "$icon_dir" "$applications_dir"

cp "$icon_source" "$icon_dir/abyssal-browser.png"
echo "Installed icon: $icon_dir/abyssal-browser.png"

desktop_dest="$applications_dir/abyssal-browser.desktop"
sed "s|@EXEC_PATH@|$binary|" "$script_dir/abyssal-browser.desktop" > "$desktop_dest"
chmod +x "$desktop_dest"
echo "Installed launcher entry: $desktop_dest"

# Best-effort refreshes — a slightly stale icon/menu cache until the
# next login is harmless, so neither failure (missing tool, whatever)
# should abort the install over what's ultimately a cosmetic delay.
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$applications_dir" 2>/dev/null || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -f "$HOME/.local/share/icons/hicolor" 2>/dev/null || true
fi

echo "Done. \"Abyssal Browser\" should now appear in your application launcher."
echo "If the icon doesn't show up immediately, log out and back in (icon/menu caches refresh then regardless)."
