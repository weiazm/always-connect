#!/bin/bash
# Development install of the privileged Helper, for builds WITHOUT a
# developer team (DESIGN.md §20.11). SMAppService only registers
# daemons from a properly signed App; an ad-hoc build cannot use it,
# so this installs the same daemon the classic way: a root-owned copy
# of the Helper in /Library/PrivilegedHelperTools and a LaunchDaemon
# plist declaring the same Mach service the App connects to.
#
# The installed Helper accepts only the App signed with its own
# certificate (DESIGN.md §36.3); an ad-hoc build accepts no App, so
# sign local builds with scripts/dev-signing-identity.sh. Never use
# alongside an SMAppService-installed Helper (same label).
#
# Usage (as root):
#   sudo scripts/dev-helper.sh install [helper]
#                                         copy the Helper (default: the
#                                         .local-build App's), load daemon.
#                                         The App runs this itself from its
#                                         bundle, behind the macOS admin
#                                         password dialog (DESIGN.md §21.8)
#   sudo scripts/dev-helper.sh uninstall  restore network, unload, remove files
#   sudo scripts/dev-helper.sh recover    restore the local network only:
#                                         routes/DNS from route-state, empty the
#                                         pf anchor, clear held state
#   scripts/dev-helper.sh status          daemon state + held-network files
#   scripts/dev-helper.sh log             follow the daemon log
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
LABEL=com.alwaysconnect.app.helper
BIN=/Library/PrivilegedHelperTools/$LABEL
PLIST=/Library/LaunchDaemons/$LABEL.plist
OCDIR=/Library/PrivilegedHelperTools/AlwaysConnect-openconnect
HYDIR=/Library/PrivilegedHelperTools/AlwaysConnect-hysteria
HYRUN="/Library/Application Support/AlwaysConnect-hysteria"
LOGDIR=/Library/Logs/AlwaysConnect
SUPPORT="/Library/Application Support/AlwaysConnect"
ANCHOR=com.apple/300.AlwaysConnect

need_root() {
    [ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 1; }
}

# >>> service-swap (scripts/service-swap-test.sh runs these with a stub launchctl)
# `launchctl bootout` can return while the old service is still exiting:
# seen when the service itself started this update (DESIGN.md §69.12),
# it took 2 s more. A bootstrap in that window fails with "Operation
# already in progress" and leaves no service at all, so wait until
# launchd has removed it (up to 15 s), and retry the bootstrap.
stop_service() {
    launchctl bootout "system/$LABEL" 2>/dev/null || true
    local i
    for i in $(seq 1 30); do
        launchctl print "system/$LABEL" >/dev/null 2>&1 || return 0
        sleep 0.5
    done
    echo "the old service is still loaded after 15 s" >&2
}

start_service() {
    local i
    for i in $(seq 1 9); do
        launchctl bootstrap system "$PLIST" 2>/dev/null && return 0
        sleep 1
    done
    launchctl bootstrap system "$PLIST"
}

# The swap of the service as a launchd job of its own (DESIGN.md §69.15).
# When the service updates itself after the user's approval, it starts
# this script, and launchd ends everything a service started once that
# service exits: on 2026-11-26 the script died right after stopping the
# old service and the new one was never loaded. The files are installed
# first, with the old service still running; then this job, which no
# service owns, stops the old one and loads the new.
SWAP_LABEL=com.alwaysconnect.app.service-swap
SWAP_PLIST="$SUPPORT/service-swap.plist"
SWAP_SCRIPT="$SUPPORT/service-swap.sh"

inside_service() {
    local pid=$$ i command
    for i in 1 2 3 4 5 6 7 8; do
        pid=$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ')
        [ -n "$pid" ] && [ "$pid" -gt 1 ] 2>/dev/null || return 1
        command=$(ps -o command= -p "$pid" 2>/dev/null)
        case "$command" in "$BIN"|"$BIN "*) return 0 ;; esac
    done
    return 1
}

# Root-private copies only (SUPPORT is root's, 0700): root never runs
# anything from a place others can write.
start_swap_job() {
    launchctl bootout "system/$SWAP_LABEL" 2>/dev/null || true
    cp "$0" "$SWAP_SCRIPT"
    chown root:wheel "$SWAP_SCRIPT"
    chmod 700 "$SWAP_SCRIPT"
    cat > "$SWAP_PLIST" <<SWAPJOB
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$SWAP_LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>$SWAP_SCRIPT</string>
    <string>swap</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>StandardOutPath</key>
  <string>$LOGDIR/service-update.log</string>
  <key>StandardErrorPath</key>
  <string>$LOGDIR/service-update.log</string>
</dict>
</plist>
SWAPJOB
    chown root:wheel "$SWAP_PLIST"
    chmod 644 "$SWAP_PLIST"
    launchctl bootstrap system "$SWAP_PLIST"
}

swap_service() {
    stop_service
    # An older daemon did not take its openconnect down on SIGTERM. HUP:
    # leave without logging the session off, so the App's reconnect can
    # reuse the cookie (DESIGN.md §26.17).
    pkill -HUP -f "^[^ ]*/openconnect .*alwaysconnect-vpnc\.sh" 2>/dev/null || true
    start_service
    # Start it now (no RunAtLoad, DESIGN.md §25.6): a hold the replaced
    # daemon left is adopted and, with no App attached, released after
    # the grace period instead of waiting for the next App launch.
    launchctl kickstart "system/$LABEL" 2>/dev/null || true
}
# <<< service-swap

recover() {
    # Same order as a manual disconnect: routes/DNS, then pf.
    local script="$SUPPORT/alwaysconnect-vpnc.sh"
    if [ -x "$script" ]; then
        ALWAYSCONNECT_ROUTE_STATE_PATH="$SUPPORT/route-state" "$script" restore >/dev/null || true
    fi
    pfctl -a "$ANCHOR" -F rules 2>/dev/null || true
    # The network gate's pf enable reference (DESIGN.md §25.2), so pf is
    # not left enabled on our account.
    local token
    token=$(plutil -extract token raw -o - "$SUPPORT/guard.json" 2>/dev/null || true)
    [ -n "$token" ] && pfctl -X "$token" >/dev/null 2>&1 || true
    rm -f "$SUPPORT/guard.json" "$SUPPORT/pf-state.json" "$SUPPORT/route-state" \
        "$SUPPORT/manual-disconnect"
    # A live but slow service still believes it holds that reference;
    # restart it so its state matches (a stopped one just stays idle).
    if launchctl print "system/$LABEL" >/dev/null 2>&1; then
        launchctl kickstart -k "system/$LABEL" >/dev/null 2>&1 || true
    fi
    echo "local network restored (pf anchor emptied, our pf enable reference released)"
}

case "${1:-}" in
install)
    need_root
    src=${2:-"$ROOT/.local-build/AlwaysConnect.app/Contents/Library/LaunchDaemons/AlwaysConnectHelper"}
    [ -x "$src" ] || { echo "build first: scripts/build-local.sh" >&2; exit 1; }
    # Started by the service itself: install the files now and leave the
    # swap to a job of its own, which outlives the old service.
    from_service=0
    inside_service && from_service=1
    if [ $from_service = 0 ]; then
        stop_service
        pkill -HUP -f "^[^ ]*/openconnect .*alwaysconnect-vpnc\.sh" 2>/dev/null || true
    fi
    mkdir -p /Library/PrivilegedHelperTools "$LOGDIR"
    chmod 700 "$LOGDIR"
    install -o root -g wheel -m 755 "$src" "$BIN"
    # The App's own openconnect (DESIGN.md §27.3), next to the daemon in a
    # root-only place. App-driven installation uses a verified root-owned
    # snapshot (PrivilegedBundle); manual sudo is a deliberate developer action.
    oc="$(cd "$(dirname "$src")/../.." && pwd)/Resources/openconnect"
    if [ -x "$oc/bin/openconnect" ]; then
        rm -rf "$OCDIR"
        cp -R "$oc" "$OCDIR"
        chown -R root:wheel "$OCDIR"
        chmod -R go-w "$OCDIR"
        echo "openconnect: $(head -2 "$OCDIR/VERSIONS" | tail -1)"
    fi
    # The App's own pinned Hysteria2 client (DESIGN.md §七十), root-owned
    # and readable/executable by nobody (never world-writable).
    hy="$(cd "$(dirname "$src")/../.." && pwd)/Resources/hysteria"
    if [ -x "$hy/bin/hysteria" ]; then
        rm -rf "$HYDIR"
        cp -R "$hy" "$HYDIR"
        chown -R root:wheel "$HYDIR"
        chmod -R go-w "$HYDIR"
        chmod 755 "$HYDIR" "$HYDIR/bin" "$HYDIR/bin/hysteria"
        echo "hysteria: $(head -1 "$HYDIR/VERSIONS" 2>/dev/null || echo installed)"
    fi
    # The engine's redacted openconnect output in helper.log is opt-in
    # (DESIGN.md §36.3): it still names the server and the user. Run
    # `sudo ALWAYSCONNECT_DEBUG_CHILD_OUTPUT=1 scripts/dev-helper.sh install`
    # to record a gateway's output shapes; the App's own install leaves it off.
    DEBUG_ENV=""
    if [ "${ALWAYSCONNECT_DEBUG_CHILD_OUTPUT:-}" = 1 ]; then
        DEBUG_ENV='    <key>ALWAYSCONNECT_DEBUG_CHILD_OUTPUT</key>
    <string>1</string>
'
    fi
    # The installed App version (root-private): the service's own update
    # refuses anything older (DESIGN.md §69.11).
    info="$(cd "$(dirname "$src")/../.." && pwd)/Info.plist"
    version=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$info" 2>/dev/null || true)
    mkdir -p "$SUPPORT"
    chmod 700 "$SUPPORT"
    if [ -n "$version" ]; then
        printf '%s\n' "$version" > "$SUPPORT/installed-version"
        chmod 600 "$SUPPORT/installed-version"
    fi
    cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$BIN</string>
    <string>daemon</string>
  </array>
  <key>MachServices</key>
  <dict>
    <key>$LABEL</key>
    <true/>
  </dict>
  <key>EnvironmentVariables</key>
  <dict>
    <!-- This service can update itself after the user's approval (§69.11);
         the App reads this world-readable plist to know it may ask. -->
    <key>ALWAYSCONNECT_SERVICE_UPDATE</key>
    <string>1</string>
$DEBUG_ENV  </dict>
  <key>StandardErrorPath</key>
  <string>$LOGDIR/helper.log</string>
  <key>KeepAlive</key>
  <dict>
    <key>Crashed</key>
    <true/>
  </dict>
</dict>
</plist>
EOF
    chown root:wheel "$PLIST"
    chmod 644 "$PLIST"
    plutil -lint -s "$PLIST"
    if [ $from_service = 1 ]; then
        start_swap_job
        echo "installed; a separate job swaps the service in a moment"
    else
        start_service
        launchctl kickstart "system/$LABEL" 2>/dev/null || true
        echo "installed; log: sudo tail -f $LOGDIR/helper.log"
    fi
    ;;
swap)
    # The job started by an update from the service (start_swap_job).
    need_root
    echo "$(date '+%F %T') swapping the service"
    swap_service || echo "the new service did not load" >&2
    rm -f "$SWAP_PLIST" "$SWAP_SCRIPT"
    # Last: removing this job ends this script.
    launchctl bootout "system/$SWAP_LABEL" 2>/dev/null || true
    ;;
uninstall)
    need_root
    recover
    stop_service
    launchctl bootout "system/$SWAP_LABEL" 2>/dev/null || true
    rm -f "$PLIST" "$BIN" "$SWAP_PLIST" "$SWAP_SCRIPT"
    rm -rf "$OCDIR" "$HYDIR" "$HYRUN"
    echo "uninstalled (log kept in $LOGDIR)"
    ;;
recover)
    need_root
    recover
    ;;
status)
    launchctl print system/$LABEL 2>/dev/null | grep -E "^\s*(state|pid|last exit code) =" || echo "daemon not loaded"
    for f in guard.json pf-state.json route-state; do
        [ -e "$SUPPORT/$f" ] && echo "held: $SUPPORT/$f present" || true
    done
    ;;
log)
    exec sudo tail -f "$LOGDIR/helper.log"
    ;;
*)
    sed -n '2,25p' "$0"
    exit 2
    ;;
esac
