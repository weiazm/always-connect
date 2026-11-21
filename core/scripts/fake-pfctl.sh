#!/bin/bash
D=$(dirname "$0")
printf "%s\n" "$*" >> "$D/pfctl.log"
# The rule text of each load, for checks on what a set lets through.
if [ "$3" = "-f" ]; then
    [ "$4" = "-" ] || exit 1
    { echo "=== load"; cat; } >> "$D/pf-rules.log"
fi
if [ "$*" = "-E" ]; then
    n=$(( $(cat "$D/token" 2>/dev/null || echo 0) + 1 )); echo $n > "$D/token"
    echo "Token : 1000$n" >&2
fi
exit 0
