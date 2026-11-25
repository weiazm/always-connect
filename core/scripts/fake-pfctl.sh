#!/bin/bash
D=$(dirname "$0")
printf "%s\n" "$*" >> "$D/pfctl.log"
# The rule text of each load, for checks on what a set lets through.
if [ "$3" = "-f" ]; then
    [ "$4" = "-" ] || exit 1
    cat > "$D/current.rules"
    { echo "=== load"; cat "$D/current.rules"; } >> "$D/pf-rules.log"
fi
if [ "$*" = "-E" ]; then
    n=$(( $(cat "$D/token" 2>/dev/null || echo 0) + 1 )); echo $n > "$D/token"
    echo "Token : 1000$n" >&2
fi
case "$*" in
    '-s info') echo 'Status: Enabled' ;;
    '-s rules') echo 'anchor "com.apple/300.AlwaysConnect" all' ;;
    '-a com.apple/300.AlwaysConnect -s rules') cat "$D/current.rules" ;;
    '-a com.apple/300.AlwaysConnect -F rules') : > "$D/current.rules" ;;
esac
exit 0
