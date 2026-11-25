#!/bin/bash
# Egress gate harness (DESIGN.md §66.13, §66.25): real openconnect in
# --script-tun mode against the local test gateway (ocserv-test.sh), with the
# gate program in between. The client side lives in its own network
# namespace, so its traffic can only leave through the gate; the test sites
# sit on a dummy interface on the gateway side. Proves, with hard-coded
# addresses (no DNS at all):
#   - an unprotected site passes without a check;
#   - a protected site is checked first, then passes (probe before request);
#   - a protected site (or subdomain) whose exit country is wrong is refused
#     with a reset and no request reaches the site;
#   - plain HTTP is decided by Host; nameless TCP is checked only within a protected range;
#   - a protected site whose exit cannot be read passes (best effort);
#   - UDP 443 (QUIC) never leaves, other UDP does;
#   - concurrent connections share one check;
#   - with the controller gone, protected connections are refused.
# Linux only, needs root and a running test gateway.
# Usage: sudo core/scripts/gate-harness.sh <path-to-alwaysconnect-gate>
set -euo pipefail
GATE=$(realpath "${1:?usage: gate-harness.sh <alwaysconnect-gate>}")
HERE=$(cd "$(dirname "$0")" && pwd)
PY="$HERE/gate-harness.py"
URL=${AC_TEST_URL:-https://127.0.0.1:4443}
GWCA=${AC_TEST_CA:-/tmp/ocserv-test/ca-cert.pem}
NS=acgate-test
SITE=10.250.0.1
RANGE=10.250.0.2
W=$(mktemp -d /tmp/acgate.XXXXXX)
FAILS=0
PIDS=()

cleanup() {
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
  pkill -f "openconnect.*--script-tun" 2>/dev/null || true
  sleep 1
  ip netns del "$NS" 2>/dev/null || true
  ip link del acgdummy 2>/dev/null || true
}
trap cleanup EXIT

dump() {
  echo "---- openconnect/gate log"; tail -40 "$W/oc.log" || true
  echo "---- controller log"; cat "$W/controller.log" 2>/dev/null || true
  echo "---- site log"; cat "$W/site.log" 2>/dev/null || true
}
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; FAILS=$((FAILS + 1)); }
count() { local c; c=$(grep -c "$1" "$2" 2>/dev/null) || true; echo "${c:-0}"; }   # grep -c exits 1 on zero; a missing log counts 0
nsx() { ip netns exec "$NS" "$@"; }

# Before any interface or route is created, a missing initial policy is fatal.
if VPNFD=0 AC_GATE_CONTROL="$W/absent" "$GATE" </dev/null >"$W/no-control.log" 2>&1; then
  fail "the gate started without an initial policy"
elif grep -q "no initial configuration" "$W/no-control.log"; then
  pass "gate starts only with an initial policy"
else
  fail "the gate did not reject the missing policy"
fi

# Test CA and one site certificate for every test name.
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=Gate Harness CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" -keyout "$W/ca.key" -out "$W/ca.pem" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=protected.test" \
  -keyout "$W/site.key" -out "$W/site.csr" 2>/dev/null
# Full leaf extensions: Python 3.13+ verifies strictly (VERIFY_X509_STRICT)
# and rejects a leaf without an authority key identifier.
cat > "$W/site.ext" <<'EXT'
subjectAltName=DNS:protected.test,DNS:blocked.test,DNS:www.blocked.test,DNS:free.test,DNS:untraced.test
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EXT
openssl x509 -req -in "$W/site.csr" -CA "$W/ca.pem" -CAkey "$W/ca.key" -CAcreateserial \
  -out "$W/site.pem" -days 2 -extfile "$W/site.ext" 2>/dev/null

ip netns add "$NS"
ip -n "$NS" link set lo up
ip link add acgdummy type dummy
ip addr add "$SITE/32" dev acgdummy
ip addr add "$RANGE/32" dev acgdummy
ip link set acgdummy up

python3 -I "$PY" server --ip "$SITE" --range-ip "$RANGE" --cert "$W/site.pem" --key "$W/site.key" \
  --log "$W/site.log" --ready "$W/site.ready" &
PIDS+=($!)
python3 -I "$PY" controller --sock "$W/control.sock" --ns "$NS" --ca "$W/ca.pem" --range-ip "$RANGE" \
  --log "$W/controller.log" --ready "$W/controller.ready" &
CTL=$!
PIDS+=($CTL)
for _ in $(seq 1 50); do [ -e "$W/site.ready" ] && [ -e "$W/controller.ready" ] && break; sleep 0.1; done

printf 'testpass\n' | openconnect --server="$URL" --cafile="$GWCA" --user=testuser \
  --passwd-on-stdin --non-inter --script-tun \
  --script "AC_GATE_CONTROL=$W/control.sock AC_GATE_TUN=linux:acg0:netns=$NS $GATE" \
  > "$W/oc.log" 2>&1 &
PIDS+=($!)

up=0
for _ in $(seq 1 60); do
  if nsx ip -4 addr show acg0 2>/dev/null | grep -q inet; then up=1; break; fi
  sleep 0.5
done
if [ "$up" != 1 ]; then
  echo "gate interface never came up"; dump; exit 1
fi
nsx ip route
CURL=(curl -sS --max-time 8 --cacert "$W/ca.pem")

# 1. Unprotected site: passes, no check.
out=$(nsx "${CURL[@]}" --resolve free.test:443:$SITE https://free.test/ 2>&1 || true)
if [ "$out" = "ok free.test" ] && [ "$(count '"host": "free.test"' "$W/controller.log")" = 0 ]; then
  pass "unprotected site passes without a check"
else fail "unprotected site: '$out'"; fi

# 2. Protected site: one check (probe with the marker), then the request.
out=$(nsx "${CURL[@]}" --resolve protected.test:443:$SITE https://protected.test/ 2>&1 || true)
probe_t=$(python3 -c "import json,sys;print(min([json.loads(l)['t'] for l in open('$W/site.log') if '\"probe\": true' in l and 'protected.test' in l] or [0]))")
req_t=$(python3 -c "import json,sys;print(min([json.loads(l)['t'] for l in open('$W/site.log') if '\"probe\": false' in l and 'protected.test' in l] or [0]))")
if [ "$out" = "ok protected.test" ] && python3 -c "import sys; sys.exit(0 if 0 < $probe_t < $req_t else 1)"; then
  pass "protected site is checked first, then passes"
else fail "protected site: '$out' probe=$probe_t request=$req_t"; fi

# 3. Wrong exit country: refused fast, nothing reaches the site.
for name in blocked.test www.blocked.test; do
  start=$(date +%s.%N)
  if nsx "${CURL[@]}" --resolve $name:443:$SITE https://$name/ >/dev/null 2>&1; then
    fail "$name was let through"
  else
    took=$(python3 -c "print(round($(date +%s.%N) - $start, 2))")
    reqs=$(count "\"kind\": \"tls-request\", \"sni\": \"$name\", \"path\": \"/\"" "$W/site.log")
    if [ "$reqs" = 0 ] && python3 -c "import sys; sys.exit(0 if $took < 5 else 1)"; then
      pass "$name refused in ${took}s, no request reached the site"
    else fail "$name: requests=$reqs took=${took}s"; fi
  fi
done
hs=$(count '"kind": "handshake", "sni": "blocked.test"' "$W/site.log")
probes=$(count '"sni": "blocked.test", "path": "/cdn-cgi/trace", "probe": true' "$W/site.log")
if [ "$hs" = "$probes" ]; then
  pass "only marked probes completed a TLS handshake with the blocked site ($probes)"
else fail "blocked handshakes=$hs probes=$probes"; fi

# 4. Plain HTTP by Host; no name, or no readable exit: best effort, passes.
out=$(nsx curl -sS --max-time 8 --resolve free.test:80:$SITE http://free.test/ 2>&1 || true)
[ "$out" = "ok free.test" ] && pass "plain HTTP to an unprotected host passes" || fail "http free: '$out'"
if nsx curl -sS --max-time 8 --resolve blocked.test:80:$SITE http://blocked.test/ >/dev/null 2>&1; then
  fail "plain HTTP to a blocked host was let through"
elif [ "$(count '"host": "blocked.test"' "$W/site.log")" = 0 ]; then
  pass "plain HTTP to a blocked host is refused by Host"
else fail "plain HTTP request reached the site"; fi
checks=$(count '"kind": "check"' "$W/controller.log")
out=$(nsx python3 -I -c "import socket;s=socket.create_connection(('$SITE',7000),5);s.sendall(b'free ping');print(s.recv(16).decode())" 2>&1 || true)
if [ "$out" = "pong" ] && [ "$(count '"kind": "check"' "$W/controller.log")" = "$checks" ]; then
  pass "a connection that shows no name passes without a check"
else fail "nameless: '$out'"; fi
if nsx python3 -I -c "import socket;s=socket.create_connection(('$RANGE',7000),5);s.settimeout(5);s.sendall(b'protected ping');assert s.recv(16)==b'pong'" >/dev/null 2>&1; then
  fail "a nameless connection in the protected range was let through"
elif [ "$(count '"group": 4, "host": ""' "$W/controller.log")" = 1 ]     && [ "$(count 'protected ping' "$W/site.log")" = 0 ]; then
  pass "nameless TCP in the protected range is checked with an empty host and blocked before payload"
else fail "the protected range did not send an empty-host check, or the payload reached the server"; fi
out=$(nsx "${CURL[@]}" --resolve untraced.test:443:$SITE https://untraced.test/ 2>&1 || true)
if [ "$out" = "ok untraced.test" ] && [ "$(count '"result": "unverified"' "$W/controller.log")" -ge 1 ]; then
  pass "a protected site whose exit cannot be read passes"
else fail "untraced: '$out'"; fi

# 5. QUIC never leaves; other UDP does.
nsx python3 -I -c "
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
for p in (443,9999): s.sendto(b'x',('$SITE',p))"
sleep 1
q=$(count '"port": 443' "$W/site.log"); o=$(count '"port": 9999' "$W/site.log")
[ "$q" = 0 ] && [ "$o" = 1 ] && pass "UDP 443 dropped, other UDP passes" || fail "udp 443=$q 9999=$o"

# 6. Concurrent connections share one check (after the last verdict expired).
sleep 1.5
before=$(count '"group": 1,' "$W/controller.log")
CPIDS=()
for i in 1 2 3 4 5; do nsx "${CURL[@]}" -o /dev/null --resolve protected.test:443:$SITE https://protected.test/ & CPIDS+=($!); done
wait "${CPIDS[@]}" || true   # only the curls: a bare wait would wait for the servers too
after=$(count '"group": 1,' "$W/controller.log")
[ $((after - before)) = 1 ] && pass "5 concurrent connections, 1 check" || fail "concurrent checks: $((after - before))"

# 7. Controller gone: protected connections are refused (fail closed).
kill "$CTL" 2>/dev/null || true
sleep 1.5
if nsx "${CURL[@]}" --resolve protected.test:443:$SITE https://protected.test/ >/dev/null 2>&1; then
  fail "protected site passed without a controller"
else pass "without a controller protected connections are refused"; fi
out=$(nsx "${CURL[@]}" --resolve free.test:443:$SITE https://free.test/ 2>&1 || true)
[ "$out" = "ok free.test" ] && pass "unprotected sites keep working without a controller" || fail "free after controller: '$out'"

echo "---- gate log"; grep 'alwaysconnect-gate' "$W/oc.log" | tail -30 || true
if [ "$FAILS" != 0 ]; then dump; echo "gate harness: $FAILS failure(s)"; exit 1; fi
echo "gate harness: all passed"
