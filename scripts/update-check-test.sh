#!/bin/bash
# The update check (DESIGN.md §三十三): the App's UpdateChecker and the
# Rust decision against a local server standing in for GitHub's releases
# list. Touches no network beyond 127.0.0.1 and no App preferences
# (a scratch defaults suite). Verification level: CI harness.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
SERVER=""
# The scratch suite's emptied plist file stays behind otherwise.
SUITE_PLIST="$HOME/Library/Preferences/com.alwaysconnect.update-check-test.plist"
trap '[ -n "$SERVER" ] && kill $SERVER 2>/dev/null; defaults delete com.alwaysconnect.update-check-test >/dev/null 2>&1 || true; rm -f "$SUITE_PLIST"; rm -rf "$WORK"' EXIT
(cd "$ROOT/core" && cargo build --release --quiet)
swiftc -O -parse-as-library "$ROOT/Sources/Shared/PrivatePipe.swift" "$ROOT/Sources/App/UpdateChecker.swift" "$ROOT/Sources/App/AppQuit.swift" "$ROOT/core/scripts/UpdateCheckTest.swift" \
    "$ROOT/core/target/release/libalwaysconnect_core.a" -o "$WORK/test" 2>&1 | grep -v "built for newer" || true

mkdir -p "$WORK/www"
rel() { printf '{"tag_name":"%s","html_url":"https://github.com/o/r/releases/tag/%s","draft":%s,"prerelease":%s,"name":"%s","body":"notes","assets":[]}' "$1" "$1" "$2" "$3" "$1"; }
echo "[$(rel v9.0.0 true false),$(rel v0.2.0-beta.1 false true),$(rel v0.1.0 false true)]" > "$WORK/www/releases.json"
echo "[$(rel v0.3.0 false false),$(rel v0.2.0-beta.1 false true),$(rel v0.1.0 false true)]" > "$WORK/www/later.json"
echo '{"message":"Not Found","documentation_url":"https://docs.github.com/rest","status":"404"}' > "$WORK/www/notfound.json"
# Several newer releases at once: the newest is offered, not the next one.
echo "[$(rel v0.9.0 false false),$(rel v0.5.0 false false),$(rel v0.4.0 false false)]" > "$WORK/www/several.json"
# A stand-in for GitHub's ETag: an unchanged list answers 304.
cat > "$WORK/server.py" <<'PY'
import hashlib, http.server, sys
class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        path = self.translate_path(self.path)
        try:
            body = open(path, "rb").read()
        except OSError:
            self.send_error(404); return
        tag = '"' + hashlib.md5(body).hexdigest() + '"'
        with open(sys.argv[3], "a") as log:
            log.write(self.path + " " + ("304" if self.headers.get("If-None-Match") == tag else "200") + "\n")
        if self.headers.get("If-None-Match") == tag:
            self.send_response(304); self.send_header("ETag", tag); self.end_headers(); return
        self.send_response(200); self.send_header("ETag", tag)
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *args): pass
http.server.SimpleHTTPRequestHandler.directory = sys.argv[2]
http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])),
    lambda *a, **k: Handler(*a, directory=sys.argv[2], **k)).serve_forever()
PY

PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
CLOSED=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
python3 "$WORK/server.py" "$PORT" "$WORK/www" "$WORK/requests.log" >"$WORK/server.log" 2>&1 &
SERVER=$!
disown "$SERVER"
for _ in $(seq 1 40); do nc -z 127.0.0.1 "$PORT" 2>/dev/null && break; sleep 0.25; done
AC_REQUEST_LOG="$WORK/requests.log" "$WORK/test" "http://127.0.0.1:$PORT/" "http://127.0.0.1:$CLOSED/releases"
