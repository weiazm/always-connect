#!/bin/bash
# dev-helper.sh's service swap (DESIGN.md §69.12) with a stub launchctl:
# the real failure on 2026-11-26 was a bootout that returned while the
# old service still ran for 2 s, a bootstrap refused with "Operation
# already in progress", and no service left at all.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
FAILS=0
check() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; FAILS=$((FAILS + 1)); fi; }

FUNCS=$(sed -n '/^# >>> service-swap/,/^# <<< service-swap/p' "$ROOT/scripts/dev-helper.sh")
[ -n "$FUNCS" ] || { echo "FAIL service-swap block not found"; exit 1; }

# The stub: `print` succeeds while the old service lingers (counted in
# polls); `bootstrap` fails while it lingers or for $REFUSE more tries.
run() {
    LINGER=$1 REFUSE=$2 CALLS="" LOADED=0
    LABEL=com.alwaysconnect.app.helper PLIST=/tmp/none.plist
    sleep() { :; }
    launchctl() {
        CALLS="$CALLS $1"
        case $1 in
            bootout) return 0 ;;
            print) if [ "$LINGER" -gt 0 ]; then LINGER=$((LINGER - 1)); return 0; fi; [ "$LOADED" = 1 ] ;;
            bootstrap)
                if [ "$LINGER" -gt 0 ] || [ "$REFUSE" -gt 0 ]; then
                    REFUSE=$((REFUSE > 0 ? REFUSE - 1 : 0)); echo "Bootstrap failed: 37" >&2; return 37
                fi
                LOADED=1 ;;
        esac
    }
    eval "$FUNCS"
    stop_service 2>/dev/null
    start_service 2>/dev/null
    STATUS=$?
}

run 4 0
check "waits for the old service to go before loading the new one" '[ "$STATUS" = 0 ] && [ "$LOADED" = 1 ]'
check "polled until it was gone" '[ "$(echo "$CALLS" | grep -o print | wc -l | tr -d " ")" = 5 ]'
check "one bootstrap when the old one is gone" '[ "$(echo "$CALLS" | grep -o bootstrap | wc -l | tr -d " ")" = 1 ]'

run 0 3
check "a refused bootstrap is retried" '[ "$STATUS" = 0 ] && [ "$LOADED" = 1 ]'
check "retried exactly until it took" '[ "$(echo "$CALLS" | grep -o bootstrap | wc -l | tr -d " ")" = 4 ]'

run 0 50
check "gives up after ten tries and reports the failure" '[ "$STATUS" != 0 ] && [ "$(echo "$CALLS" | grep -o bootstrap | wc -l | tr -d " ")" = 10 ]'

run 100 0
check "a service that never leaves stops the wait after 30 polls" '[ "$(echo "$CALLS" | grep -o print | wc -l | tr -d " ")" -ge 30 ]'

echo "FAILS=$FAILS"
[ "$FAILS" -eq 0 ]
