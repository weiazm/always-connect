#!/bin/bash
# dev-helper.sh's service swap (DESIGN.md §69.12) with a stub launchctl:
# the real failure on 2026-11-26 was a bootout that returned while the
# old service still ran for 2 s, a bootstrap refused with "Operation
# already in progress", and no service left at all.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
FAILS=0
check() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; FAILS=$((FAILS + 1)); fi; }

SUPPORT=/nonexistent LOGDIR=/nonexistent BIN=/nonexistent
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

# §69.15: started by the service, the install leaves the swap to a job
# of its own (launchd ends everything a service started when it exits).
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
LABEL=com.alwaysconnect.app.helper PLIST=/tmp/none.plist
BIN=/Library/PrivilegedHelperTools/com.alwaysconnect.app.helper
SUPPORT=$WORK LOGDIR=$WORK/logs
CHAIN=""
ps() {  # ps -o ppid=|command= -p PID, from CHAIN "pid:ppid:command;..."
    local field=$2 pid=$4 entry
    IFS=';' read -ra entries <<< "$CHAIN"
    for entry in "${entries[@]}"; do
        IFS=':' read -r p pp cmd <<< "$entry"
        [ "$p" = "$pid" ] || continue
        [ "$field" = "ppid=" ] && echo "$pp" || echo "$cmd"
        return 0
    done
    return 1
}
eval "$FUNCS"
CHAIN="$$:300:/bin/bash script;300:200:/bin/bash -c bootstrap;200:1:$BIN daemon"
check "an install started by the service knows it" 'inside_service'
CHAIN="$$:300:/bin/bash script;300:250:/usr/libexec/security_authtrampoline;250:1:/sbin/launchd"
check "an install from the password dialog does not" '! inside_service'
CHAIN="$$:300:/bin/bash script;300:200:$BIN-other daemon;200:1:/sbin/launchd"
check "a look-alike program name does not count" '! inside_service'

CALLS="" LOADED_JOB=""
chown() { :; }
launchctl() { CALLS="$CALLS $1"; [ "$1" = bootstrap ] && LOADED_JOB=$3; return 0; }
start_swap_job
check "the swap job is loaded from its root-private plist" '[ "$LOADED_JOB" = "$WORK/service-swap.plist" ]'
check "the job runs a root-private copy with the swap command" \
    '[ "$(plutil -extract ProgramArguments.1 raw -o - "$WORK/service-swap.plist")" = "$WORK/service-swap.sh" ] && [ "$(plutil -extract ProgramArguments.2 raw -o - "$WORK/service-swap.plist")" = swap ]'
check "the job starts at once and is not kept alive" \
    '[ "$(plutil -extract RunAtLoad raw -o - "$WORK/service-swap.plist")" = true ] && ! plutil -extract KeepAlive raw -o - "$WORK/service-swap.plist" >/dev/null 2>&1'
check "the copy is the script itself, owner-only" '[ -f "$WORK/service-swap.sh" ] && [ "$(stat -f %Lp "$WORK/service-swap.sh")" = 700 ]'

# The job's own work: old service out, new one in, then started.
LINGER=2 REFUSE=0 CALLS="" LOADED=0
sleep() { :; }
pkill() { :; }
launchctl() {
    CALLS="$CALLS $1"
    case $1 in
        bootout) return 0 ;;
        print) if [ "$LINGER" -gt 0 ]; then LINGER=$((LINGER - 1)); return 0; fi; [ "$LOADED" = 1 ] ;;
        bootstrap) LOADED=1 ;;
        kickstart) return 0 ;;
    esac
}
swap_service 2>/dev/null
check "the swap stops the old service, loads the new and starts it" '[ "$LOADED" = 1 ] && [ "$CALLS" = " bootout print print print bootstrap kickstart" ]'

echo "FAILS=$FAILS"
[ "$FAILS" -eq 0 ]
