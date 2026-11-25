#!/bin/bash
# Site-list updates (DESIGN.md §66.30): the App's GeoUpdater against a local
# feed with synthetic releases. Uses a scratch folder and preferences only;
# no network beyond 127.0.0.1, nothing of the user's is read or written.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
SERVER=""
trap '[ -n "$SERVER" ] && { kill "$SERVER" 2>/dev/null; wait "$SERVER" 2>/dev/null || true; }; rm -rf "$WORK"' EXIT
cd "$ROOT"
(cd core && cargo build --release --quiet)

python3 -I - "$WORK/feed" <<'PY'
import hashlib, os, sys
feed = sys.argv[1]
def varint(v):
    out = bytearray()
    while True:
        b = v & 0x7F; v >>= 7
        if v: out.append(b | 0x80)
        else: out.append(b); return bytes(out)
def field(n, payload): return varint(n << 3 | 2) + varint(len(payload)) + payload
def domain(kind, value): return varint(1 << 3) + varint(kind) + field(2, value.encode())
def site(name, domains): return field(1, name.encode()) + b"".join(field(2, d) for d in domains)
def catalogue(extra):
    lists = [site(n, d) for n, d in extra]
    lists += [site("list%04d" % i, [domain(2, "d%d.l%d.example" % (j, i)) for j in range(41)]) for i in range(520)]
    return b"".join(field(1, s) for s in lists)
good = catalogue([("EXAMPLE", [domain(2, "example.com"), domain(3, "www.example.net")])])
other = catalogue([("EXAMPLE", [domain(2, "example.com"), domain(3, "www.example.net")]),
                   ("UNUSED", [domain(2, "unused.example")])])
grown = catalogue([("EXAMPLE", [domain(2, "example.com"), domain(3, "www.example.net"), domain(2, "added.example")])])
def release(tag, dat, digest=None):
    d = os.path.join(feed, "download", tag); os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "dlc.dat"), "wb").write(dat)
    open(os.path.join(d, "dlc.dat.sha256sum"), "w").write((digest or hashlib.sha256(dat).hexdigest()) + "  dlc.dat\n")
release("20261124090120", good)
release("20261125000000", good)              # same content, new tag
release("20261126000000", other, "0" * 64)   # published hash does not match
release("20261127000000", other)             # a list nobody uses changed
release("20261128000000", grown)             # a list the rules use changed
release("20261129000000", b"not a catalogue")
open(os.path.join(feed, "api"), "w").write('{"tag_name":"20261124090120"}')
PY
PORT=$(python3 -I -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
python3 -I -m http.server "$PORT" --bind 127.0.0.1 --directory "$WORK/feed" >/dev/null 2>&1 &
SERVER=$!
for _ in $(seq 50); do curl -fs "http://127.0.0.1:$PORT/api" >/dev/null && break; sleep 0.1; done

sed "s/group\.com\.alwaysconnect\.app/com.example.$(basename "$WORK")/g" Sources/Shared/Models.swift > "$WORK/Models.swift"
sed 's|"/opt/cisco/|"/nonexistent/geo-update-test/|g' Sources/App/CiscoProfiles.swift > "$WORK/CiscoProfiles.swift"
SOURCES=("$WORK/Models.swift" "$WORK/CiscoProfiles.swift")
for file in Sources/App/*.swift Sources/Shared/*.swift; do
    case "$file" in
        */AlwaysConnectApp.swift|*/Models.swift|*/CiscoProfiles.swift) ;;
        *) SOURCES+=("$file") ;;
    esac
done
swiftc -target "$(uname -m)-apple-macos13.0" -parse-as-library -module-name GeoUpdateTest "${SOURCES[@]}" \
    core/scripts/GeoUpdateTest.swift core/target/release/libalwaysconnect_core.a \
    -o "$WORK/GeoUpdateTest" > "$WORK/swift.log" 2>&1 || { cat "$WORK/swift.log"; exit 1; }
ALWAYSCONNECT_GEO_DIR="$WORK/geo" ALWAYSCONNECT_GEO_FEED="http://127.0.0.1:$PORT" "$WORK/GeoUpdateTest" "$WORK/feed"
