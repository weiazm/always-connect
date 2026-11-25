#!/bin/bash
# Script assertions only: never run the generated privileged bootstrap.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
(cd "$ROOT/core" && cargo build --release --quiet)
swiftc -O -parse-as-library "$ROOT/Sources/Shared/PrivatePipe.swift" "$ROOT/core/target/release/libalwaysconnect_core.a" "$ROOT/Sources/App/AppIdentity.swift" "$ROOT/Sources/App/AdminScript.swift" \
    "$ROOT/Sources/Shared/RootBootstrap.swift" "$ROOT/Sources/App/PrivilegedBundle.swift" "$ROOT/core/scripts/PrivilegedBundleTest.swift" -o "$WORK/test"
"$WORK/test" "$WORK/bootstrap.sh" "$WORK/update.sh" "$WORK/version-check.sh"
bash -n "$WORK/bootstrap.sh"
bash -n "$WORK/update.sh"
echo 'PASS bootstrap shell syntax (not executed)'
# The service's own update (§69.11) refuses older versions: run only the
# version check, on a fake snapshot, never the bootstrap.
for case in "0.2.9 0.2.9 ok" "0.3.0 0.2.9 ok" "0.2.10 0.2.9 ok" "1.0 0.9.9 ok" "0.2.8 0.2.9 stop" "0.2 0.2.1 stop" "x.1 0.2.9 stop" "'' 0.2.9 stop"; do
    set -- $case
    app="$WORK/v/AlwaysConnect.app"; rm -rf "$WORK/v"; mkdir -p "$app/Contents"
    new=${1//\'/}
    if [ -n "$new" ]; then
        /usr/libexec/PlistBuddy -c "Add :CFBundleShortVersionString string $new" "$app/Contents/Info.plist" >/dev/null
    fi
    got=$(app="$app" MIN="$2" bash -c 'set -euo pipefail; source "$0"; echo ok' "$WORK/version-check.sh" 2>/dev/null || echo stop)
    [ "$got" = "$3" ] || { echo "FAIL version check $1 vs $2: $got"; exit 1; }
done
echo 'PASS update refuses older or unreadable versions, takes equal and newer'
# An ad-hoc bundle cannot satisfy the root bootstrap's certificate pin.
APP="$WORK/AlwaysConnect.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
printf 'int main(void){return 0;}' | cc -x c - -o "$APP/Contents/MacOS/AlwaysConnect"
cat >"$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0"?><plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.alwaysconnect.app</string>
<key>CFBundleExecutable</key><string>AlwaysConnect</string>
</dict></plist>
PLIST
echo 'exit 0' >"$APP/Contents/Resources/dev-helper.sh"
codesign --force --sign - "$APP" 2>/dev/null
if codesign --verify --strict --deep -R='certificate leaf = H"0123456789abcdef0123456789abcdef01234567"' "$APP" 2>/dev/null; then
    echo 'FAIL ad-hoc bundle accepted by certificate pin'; exit 1
fi
echo 'PASS ad-hoc snapshot refused by real codesign requirement'
echo 'changed' >>"$APP/Contents/Resources/dev-helper.sh"
if codesign --verify --strict --deep "$APP" 2>/dev/null; then
    echo 'FAIL changed resource accepted'; exit 1
fi
echo 'PASS changed bundled script refused by real codesign verification'
