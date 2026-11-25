#!/bin/bash
# Put the local build into /Applications so the user can find it in
# Launchpad / Spotlight (owner's request, 2026-11-05). A running copy is
# quit first (quit = VPN off, direct network, DESIGN.md §21.5), so this
# must not be run while a test or a needed VPN session is up without
# telling the user. Admin users can write /Applications without sudo.
#
# Usage: scripts/install-app.sh [--open]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/.local-build/AlwaysConnect.app"
DST=/Applications/AlwaysConnect.app
[ -d "$SRC" ] || { echo "build first: scripts/build-local.sh" >&2; exit 1; }
running() { pgrep -f "AlwaysConnect.app/Contents/MacOS/AlwaysConnect" >/dev/null; }
if running; then
    echo "quitting the running AlwaysConnect (VPN off, direct network)"
    # The first quit may not take while a session winds down: ask again,
    # and never replace the bundle under a running App (2026-11-25: the
    # old App kept running from the replaced bundle).
    for attempt in 1 2; do
        osascript -e 'tell application id "com.alwaysconnect.app" to quit' >/dev/null 2>&1 || true
        for _ in $(seq 1 20); do
            running || break
            sleep 1
        done
        running || break
    done
    if running; then
        echo "AlwaysConnect did not quit; nothing replaced" >&2
        exit 1
    fi
fi
rm -rf "$DST"
ditto "$SRC" "$DST"
codesign --verify --strict "$DST"
if [ "$(id -u)" != 0 ] && [ -f "$DST/Contents/Resources/refresh-recovery-shortcut.sh" ]; then
    /bin/bash "$DST/Contents/Resources/refresh-recovery-shortcut.sh" \
        "$DST/Contents/Resources/reset-network.sh" "$HOME/Desktop/AlwaysConnect 恢复网络.command" \
        || echo "桌面恢复脚本未能更新；仍可使用 App 内的「恢复网络」。" >&2
fi
echo "installed $DST"
[ "${1:-}" = "--open" ] && open "$DST"
exit 0
