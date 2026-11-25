#!/bin/bash
# Our SOCKS5 client against a reference server (DESIGN.md §69): Dante,
# a widely used open-source implementation of RFC 1928, with username/
# password (RFC 1929) and UDP ASSOCIATE. Linux CI (needs root for the
# server's password check); touches only loopback and a throwaway user.
#
#   sudo apt-get install -y dante-server && scripts/socks5-interop-test.sh
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
USER_NAME=acproxytest
PASSWORD="pw-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
cleanup() {
    [ -n "${PID:-}" ] && sudo kill "$PID" 2>/dev/null || true
    sudo userdel "$USER_NAME" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT
id "$USER_NAME" >/dev/null 2>&1 || sudo useradd -M -s /usr/sbin/nologin "$USER_NAME"
echo "$USER_NAME:$PASSWORD" | sudo chpasswd
cat > "$WORK/danted.conf" <<CONF
logoutput: stderr
internal: 127.0.0.1 port = 11080
external: 127.0.0.1
socksmethod: username
user.privileged: root
user.unprivileged: nobody
client pass { from: 127.0.0.0/8 to: 0.0.0.0/0 }
socks pass { from: 127.0.0.0/8 to: 0.0.0.0/0 command: connect udpassociate }
socks pass { from: 0.0.0.0/0 to: 127.0.0.0/8 command: udpreply }
CONF
DANTED=$(command -v danted || command -v sockd)
sudo "$DANTED" -f "$WORK/danted.conf" > "$WORK/danted.log" 2>&1 &
PID=$!
for _ in $(seq 1 50); do
    (exec 3<>/dev/tcp/127.0.0.1/11080) 2>/dev/null && break
    sleep 0.1
done
cd "$ROOT/core"
if ! AC_SOCKS5_INTEROP=127.0.0.1:11080 AC_SOCKS5_INTEROP_AUTH="$USER_NAME:$PASSWORD" \
    cargo test --lib interop_with_a_reference_socks5_server -- --ignored --nocapture; then
    echo "--- danted log"; tail -40 "$WORK/danted.log"; exit 1
fi
echo "PASS socks5 interop (Dante: username/password, CONNECT by address and name, UDP ASSOCIATE)"
